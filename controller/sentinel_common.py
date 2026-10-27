"""
Detection logic shared by the controller and the analysis scripts.

Nothing in this file imports Ryu, so it can be unit-tested on any machine
(python3 -m unittest discover tests). The controller only wires these pieces
to OpenFlow events.

Stage 1  ArpGuard          dual-cache ARP check (Patrice et al. 2024)
Stage 2  EntropyFilter     per-window entropy + volume z-scores (Puranik et al. 2023)
Stage 3  FEATURES          per-port behavioural features for the classifier
Stage 4  PortGate          k-of-n verdict gate before a port is blocked
"""

from __future__ import annotations

import math
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Configuration (one place, so the report and the code cannot disagree)
# --------------------------------------------------------------------------

WINDOW_SECONDS = 1.0          # length of one detection window
EDGE_PORT_MIN = 10            # host-facing switch ports are numbered >= 10 by the topology
WARMUP_WINDOWS = 40           # benign windows used to learn the entropy baseline
Z_THRESHOLD = 3.0             # |z| above this flags the window for the classifier
ENTROPY_SD_FLOOR = 0.25       # bits; stops a near-constant entropy from exploding z
ARP_PENDING_SECONDS = 5.0     # how long an ARP request "explains" a reply
ARP_BLOCK_COUNT = 3           # malicious ARP packets ...
ARP_BLOCK_WINDOW = 10.0       # ... within this many seconds block the port
GATE_K, GATE_N = 2, 3         # classifier must say "attack" in 2 of the last 3 windows
BLOCK_SECONDS = 20            # hard timeout of an OpenFlow drop rule
ML_ATTACK_PROBA = 0.5         # P(attack) at or above this is an "attack" verdict

# Behavioural features per (switch, ingress port, window).
# No IP or MAC address is a feature: the model must learn behaviour, not identity.
FEATURES = [
    "rx_pps",          # packets/s received on the port (port statistics)
    "rx_Bps",          # bytes/s received on the port
    "mean_pkt_size",   # bytes per packet
    "new_flows",       # packet-ins (new flows) from the port this window
    "uniq_dst_ip",     # distinct destination IPs among new flows
    "uniq_dst_port",   # distinct destination L4 ports among new flows
    "uniq_src_ip",     # distinct source IPs among new flows (spoofing indicator)
    "tcp_frac",        # fraction of new flows that are TCP
    "udp_frac",        # fraction of new flows that are UDP
    "icmp_frac",       # fraction of new flows that are ICMP
    "dst_port_entropy" # entropy (bits) of destination ports among new flows
]


def is_edge_port(port_no: int) -> bool:
    """Host-facing ports. Inter-switch links use ports 1..9 by construction."""
    return EDGE_PORT_MIN <= port_no < 0xFFFFFF00


def entropy(counter: Counter) -> float:
    """Shannon entropy in bits of a frequency table (0 for empty)."""
    n = sum(counter.values())
    if n <= 0:
        return 0.0
    h = 0.0
    for c in counter.values():
        if c > 0:
            p = c / n
            h -= p * math.log2(p)
    return h


# --------------------------------------------------------------------------
# Stage 1: ARP dual-cache
# --------------------------------------------------------------------------

@dataclass
class ArpVerdict:
    malicious: bool
    reason: str = ""
    block: bool = False


class ArpGuard:
    """
    Two caches, as in Patrice et al.:
      * bindings  IP -> MAC, learned from requests and validated replies
      * pending   (requester IP, target IP) -> time of the request
    A reply is malicious if nobody asked for it, if it rebinds a known IP to a
    new MAC, or if one MAC claims several IPs. A port that sends ARP_BLOCK_COUNT
    malicious packets within ARP_BLOCK_WINDOW seconds is blocked.
    """

    def __init__(self):
        self.bindings: dict[str, str] = {}
        self.mac_ips: dict[str, set] = defaultdict(set)
        self.pending: dict[tuple, float] = {}
        self.strikes: dict[tuple, deque] = defaultdict(deque)

    def _expire(self, now: float):
        dead = [k for k, t in self.pending.items() if now - t > ARP_PENDING_SECONDS]
        for k in dead:
            del self.pending[k]

    def _conflict(self, ip: str, mac: str) -> str:
        known = self.bindings.get(ip)
        if known is not None and known != mac:
            return "ip_rebinding"
        others = self.mac_ips.get(mac, set()) - {ip}
        if others:
            return "mac_multiple_ips"
        return ""

    def _learn(self, ip: str, mac: str):
        if ip and ip != "0.0.0.0" and ip not in self.bindings:
            self.bindings[ip] = mac
            self.mac_ips[mac].add(ip)

    def inspect(self, port_key, opcode: int, src_mac: str, src_ip: str,
                dst_ip: str, now: float | None = None) -> ArpVerdict:
        """opcode 1 = request, 2 = reply. port_key identifies the ingress port."""
        now = time.time() if now is None else now
        self._expire(now)

        if opcode == 1:                                  # request
            reason = self._conflict(src_ip, src_mac) if src_ip != "0.0.0.0" else ""
            if not reason:
                self._learn(src_ip, src_mac)
                self.pending[(src_ip, dst_ip)] = now
                return ArpVerdict(False)
        elif opcode == 2:                                # reply
            reason = self._conflict(src_ip, src_mac)
            if not reason and (dst_ip, src_ip) not in self.pending:
                reason = "unsolicited_reply"
            if not reason:
                self._learn(src_ip, src_mac)
                return ArpVerdict(False)
        else:
            return ArpVerdict(False)

        q = self.strikes[port_key]
        q.append(now)
        while q and now - q[0] > ARP_BLOCK_WINDOW:
            q.popleft()
        block = len(q) >= ARP_BLOCK_COUNT
        if block:
            q.clear()
        return ArpVerdict(True, reason, block)


# --------------------------------------------------------------------------
# Stage 2: entropy + volume pre-filter
# --------------------------------------------------------------------------

WINDOW_STATS = ["h_src_ip", "h_dst_ip", "h_dst_port", "new_flows", "edge_pps"]


class EntropyFilter:
    """
    Learns the mean and spread of five window statistics during WARMUP_WINDOWS
    benign windows, then flags any window whose statistic is more than
    Z_THRESHOLD standard deviations away (volumes only flag when they rise).
    """

    def __init__(self, warmup: int = WARMUP_WINDOWS, z: float = Z_THRESHOLD):
        self.warmup = warmup
        self.z = z
        self.hist: dict[str, list] = {k: [] for k in WINDOW_STATS}
        self.mu: dict[str, float] = {}
        self.sd: dict[str, float] = {}

    @property
    def ready(self) -> bool:
        return bool(self.mu)

    def _freeze(self):
        for k, xs in self.hist.items():
            m = sum(xs) / len(xs)
            v = sum((x - m) ** 2 for x in xs) / max(1, len(xs) - 1)
            s = math.sqrt(v)
            if k.startswith("h_"):
                s = max(s, ENTROPY_SD_FLOOR)
            else:                                   # counts: relative + absolute floor
                s = max(s, 0.2 * m, 5.0)
            self.mu[k], self.sd[k] = m, s

    def observe(self, stats: dict) -> tuple[bool, float, str]:
        """Returns (flagged, max |z|, which statistic). Learns while warming up."""
        if not self.ready:
            for k in WINDOW_STATS:
                self.hist[k].append(float(stats[k]))
            if len(self.hist["new_flows"]) >= self.warmup:
                self._freeze()
            return False, 0.0, "warmup"
        best_z, best_k = 0.0, ""
        for k in WINDOW_STATS:
            z = (float(stats[k]) - self.mu[k]) / self.sd[k]
            if not k.startswith("h_"):
                z = max(z, 0.0)                     # only rising volume is suspicious
            if abs(z) > abs(best_z):
                best_z, best_k = z, k
        return abs(best_z) > self.z, best_z, best_k


# --------------------------------------------------------------------------
# Stage 3 inputs: per-port accumulator for one window
# --------------------------------------------------------------------------

@dataclass
class PortWindow:
    new_flows: int = 0
    tcp: int = 0
    syn: int = 0
    udp: int = 0
    icmp: int = 0
    dst_ips: set = field(default_factory=set)
    src_ips: set = field(default_factory=set)
    dst_ports: Counter = field(default_factory=Counter)

    def add_flow(self, proto: int, src_ip: str, dst_ip: str, dst_port: int | None,
                 bare_syn: bool):
        self.new_flows += 1
        self.src_ips.add(src_ip)
        self.dst_ips.add(dst_ip)
        if dst_port is not None:
            self.dst_ports[dst_port] += 1
        if proto == 6:
            self.tcp += 1
            if bare_syn:
                self.syn += 1
        elif proto == 17:
            self.udp += 1
        elif proto == 1:
            self.icmp += 1

    def features(self, rx_pkts: float, rx_bytes: float, seconds: float) -> dict:
        seconds = max(seconds, 1e-6)
        n = self.new_flows
        return {
            "rx_pps": rx_pkts / seconds,
            "rx_Bps": rx_bytes / seconds,
            "mean_pkt_size": (rx_bytes / rx_pkts) if rx_pkts > 0 else 0.0,
            "new_flows": float(n),
            "uniq_dst_ip": float(len(self.dst_ips)),
            "uniq_dst_port": float(len(self.dst_ports)),
            "uniq_src_ip": float(len(self.src_ips)),
            "tcp_frac": (self.tcp / n) if n else 0.0,
            "udp_frac": (self.udp / n) if n else 0.0,
            "icmp_frac": (self.icmp / n) if n else 0.0,
            "dst_port_entropy": entropy(self.dst_ports),
        }


# --------------------------------------------------------------------------
# Stage 4 guard: k-of-n gate per port
# --------------------------------------------------------------------------

class PortGate:
    """A port is blocked only when GATE_K of its last GATE_N classified windows say attack."""

    def __init__(self, k: int = GATE_K, n: int = GATE_N):
        self.k, self.n = k, n
        self.hist: dict = defaultdict(lambda: deque(maxlen=self.n))

    def update(self, port_key, attack: bool) -> bool:
        h = self.hist[port_key]
        h.append(1 if attack else 0)
        if sum(h) >= self.k:
            h.clear()
            return True
        return False
