"""
SDN-IoT Sentinel: the Ryu controller app (OpenFlow 1.3).

    ryu-manager controller/sentinel_controller.py          (or osken-manager)

Environment variables (set by experiments/run_experiment.py):
    SENTINEL_MODE     collect | detect   collect = log features, never block
    SENTINEL_GATING   on | off           on  = ML only on windows the entropy filter flags
                                         off = ML on every active port, every window (baseline)
    SENTINEL_MODEL    path to models/classifier.joblib (detect mode)
    SENTINEL_RUN_DIR  where the CSV logs go
    SENTINEL_WARMUP   benign windows used to learn the entropy baseline

Pipeline per packet / per 1 s window:
    Stage 1  every ARP packet from a host port -> ArpGuard; malicious ARP is dropped,
             3 in 10 s blocks the port
    Stage 2  every window -> entropy of src IP, dst IP, dst port + new-flow and
             packet volume -> z-scores against the warm-up baseline
    Stage 3  flagged window -> classifier on each active host port's features
    Stage 4  2 of 3 attack verdicts -> OpenFlow drop rule on that ingress port
"""

import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sentinel_common as sc  # noqa: E402

try:                                    # Ryu, or its maintained fork os-ken
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                        MAIN_DISPATCHER, set_ev_cls)
    from ryu.lib import hub
    from ryu.lib.packet import arp, ether_types, ethernet, icmp, ipv4, packet, tcp, udp
    from ryu.ofproto import ofproto_v1_3
    BaseApp = app_manager.RyuApp
    FRAMEWORK = "ryu"
except ImportError:
    from os_ken.base import app_manager
    from os_ken.controller import ofp_event
    from os_ken.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                           MAIN_DISPATCHER, set_ev_cls)
    from os_ken.lib import hub
    from os_ken.lib.packet import arp, ether_types, ethernet, icmp, ipv4, packet, tcp, udp
    from os_ken.ofproto import ofproto_v1_3
    BaseApp = app_manager.OSKenApp
    FRAMEWORK = "os-ken"

FLOW_IDLE_TIMEOUT = 10
PRIO_TABLE_MISS, PRIO_FLOW, PRIO_BLOCK = 0, 10, 100


class CsvLog:
    def __init__(self, path, header):
        new = not os.path.exists(path)
        self.f = open(path, "a", newline="")
        self.w = csv.writer(self.f)
        if new:
            self.w.writerow(header)

    def row(self, *values):
        self.w.writerow(values)

    def flush(self):
        self.f.flush()


class SentinelController(BaseApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = os.environ.get("SENTINEL_MODE", "detect")
        self.gating = os.environ.get("SENTINEL_GATING", "on") != "off"
        self.run_dir = os.environ.get("SENTINEL_RUN_DIR", "runs/manual")
        warmup = int(os.environ.get("SENTINEL_WARMUP", sc.WARMUP_WINDOWS))
        os.makedirs(self.run_dir, exist_ok=True)

        self.datapaths = {}
        self.mac_to_port = defaultdict(dict)
        self.arp_guard = sc.ArpGuard()
        self.efilter = sc.EntropyFilter(warmup=warmup)
        self.gate = sc.PortGate()
        self.blocked_until = {}                 # (dpid, port) -> unix time
        self.port_counters, self.prev_counters = {}, {}
        self._new_window()
        self.window_no = 0
        self.packet_ins = 0
        self.traffic_started = False

        self.model, self.benign_idx, self.classes = None, None, []
        model_path = os.environ.get("SENTINEL_MODEL", "")
        if self.mode == "detect" and model_path:
            if os.path.exists(model_path):
                import joblib
                bundle = joblib.load(model_path)
                self.model = bundle["model"]
                self.classes = list(self.model.classes_)
                self.benign_idx = self.classes.index("benign")
                if bundle["features"] != sc.FEATURES:
                    raise SystemExit("model was trained on a different feature list")
            else:
                self.logger.error("SENTINEL_MODEL %s not found: ML stage disabled", model_path)

        d = self.run_dir
        self.log_win = CsvLog(f"{d}/windows.csv", ["ts", "window"] + sc.WINDOW_STATS + [
            "flagged", "z", "z_stat", "active_ports", "ml_rows", "ml_ms", "packet_ins"])
        self.log_feat = CsvLog(f"{d}/features.csv",
                               ["ts", "dpid", "port", "flagged"] + sc.FEATURES)
        self.log_dec = CsvLog(f"{d}/decisions.csv",
                              ["ts", "dpid", "port", "stage", "label", "p_attack", "action"])
        self.log_arp = CsvLog(f"{d}/arp.csv",
                              ["ts", "dpid", "port", "mac", "ip", "reason", "blocked"])
        with open(f"{d}/controller_config.json", "w") as f:
            json.dump({"framework": FRAMEWORK, "mode": self.mode, "gating": self.gating,
                       "model": model_path if self.model is not None else None,
                       "classes": self.classes, "warmup_windows": warmup,
                       "window_s": sc.WINDOW_SECONDS, "z_threshold": sc.Z_THRESHOLD,
                       "gate": [sc.GATE_K, sc.GATE_N], "block_s": sc.BLOCK_SECONDS,
                       "pid": os.getpid()}, f, indent=2)
        self.logger.info("Sentinel (%s): mode=%s gating=%s model=%s", FRAMEWORK, self.mode,
                         self.gating, "yes" if self.model is not None else "no")
        hub.spawn(self._monitor)

    # ------------------------------------------------------------------ helpers

    def _new_window(self):
        self.port_win = defaultdict(sc.PortWindow)
        self.win_src, self.win_dst, self.win_dport = Counter(), Counter(), Counter()

    @staticmethod
    def _add_flow(dp, priority, match, actions, idle=0, hard=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle, hard_timeout=hard))

    def _forward(self, dp, msg, in_port, dst_mac, match=None):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        out_port = self.mac_to_port[dp.id].get(dst_mac, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if match is not None and out_port != ofp.OFPP_FLOOD:
            self._add_flow(dp, PRIO_FLOW, match, actions, idle=FLOW_IDLE_TIMEOUT)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    def _block(self, dpid, port, stage, label, p_attack=""):
        now = time.time()
        if self.blocked_until.get((dpid, port), 0) > now:
            return
        dp = self.datapaths.get(dpid)
        action = "logged"
        if self.mode == "detect" and dp is not None:
            match = dp.ofproto_parser.OFPMatch(in_port=port)
            self._add_flow(dp, PRIO_BLOCK, match, [], hard=sc.BLOCK_SECONDS)
            self.blocked_until[(dpid, port)] = now + sc.BLOCK_SECONDS
            action = f"drop_{sc.BLOCK_SECONDS}s"
            self.logger.warning("BLOCK s%s port %s for %ss: %s (%s)", dpid, port,
                                sc.BLOCK_SECONDS, label, stage)
        self.log_dec.row(f"{now:.3f}", dpid, port, stage, label, p_attack, action)
        self.log_dec.flush()

    # ------------------------------------------------------------- OpenFlow events

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self._add_flow(dp, PRIO_TABLE_MISS, parser.OFPMatch(),
                       [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def _error(self, ev):
        m = ev.msg
        self.logger.error("OpenFlow error from s%s: type=%s code=%s", m.datapath.id, m.type, m.code)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid, in_port = dp.id, msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return
        self.packet_ins += 1
        self.mac_to_port[dpid][eth.src] = in_port
        edge = sc.is_edge_port(in_port)

        # ---- Stage 1: ARP dual-cache
        a = pkt.get_protocol(arp.arp)
        if a is not None:
            if edge:
                v = self.arp_guard.inspect((dpid, in_port), a.opcode, a.src_mac,
                                           a.src_ip, a.dst_ip)
                if v.malicious:
                    self.log_arp.row(f"{time.time():.3f}", dpid, in_port, a.src_mac,
                                     a.src_ip, v.reason, int(v.block))
                    self.log_arp.flush()
                    if v.block:
                        self._block(dpid, in_port, "stage1_arp", "arp_spoofing")
                    if self.mode == "detect":
                        return                  # drop the forged packet
            self._forward(dp, msg, in_port, eth.dst)
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            self._forward(dp, msg, in_port, eth.dst)
            return

        parser = dp.ofproto_parser
        if not edge:
            # Transit traffic between switches: plain MAC forwarding, so each new flow
            # raises exactly one packet-in (at the host's own edge switch).
            self._forward(dp, msg, in_port, eth.dst,
                          match=parser.OFPMatch(in_port=in_port, eth_dst=eth.dst))
            return

        fields = dict(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                      ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=ip.proto)
        dst_port, bare_syn = None, False
        t, u = pkt.get_protocol(tcp.tcp), pkt.get_protocol(udp.udp)
        if t is not None:
            dst_port = t.dst_port
            bare_syn = bool(t.bits & tcp.TCP_SYN) and not (t.bits & tcp.TCP_ACK)
            fields.update(tcp_src=t.src_port, tcp_dst=t.dst_port)
        elif u is not None:
            dst_port = u.dst_port
            fields.update(udp_src=u.src_port, udp_dst=u.dst_port)

        # ---- Stage 2/3 inputs: one new flow from this host port
        self.port_win[(dpid, in_port)].add_flow(ip.proto, ip.src, ip.dst, dst_port, bare_syn)
        self.win_src[ip.src] += 1
        self.win_dst[ip.dst] += 1
        if dst_port is not None:
            self.win_dport[dst_port] += 1

        self._forward(dp, msg, in_port, eth.dst, match=parser.OFPMatch(**fields))

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats(self, ev):
        dpid, now = ev.msg.datapath.id, time.time()
        for st in ev.msg.body:
            if sc.is_edge_port(st.port_no):
                self.port_counters[(dpid, st.port_no)] = (st.rx_packets, st.rx_bytes, now)

    # ------------------------------------------------------------ window loop

    def _monitor(self):
        hub.sleep(1.0)
        nxt = time.time()
        while True:
            nxt += sc.WINDOW_SECONDS
            hub.sleep(max(0.0, nxt - time.time()))
            for dp in list(self.datapaths.values()):
                p = dp.ofproto_parser
                dp.send_msg(p.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY))
            try:
                self._close_window()
            except Exception:                           # never let the loop die
                self.logger.exception("window processing failed")

    def _close_window(self):
        now = time.time()
        port_win, src, dst, dport = self.port_win, self.win_src, self.win_dst, self.win_dport
        self._new_window()
        self.window_no += 1

        deltas = {}
        for key, (pk, by, ts) in self.port_counters.items():
            prev = self.prev_counters.get(key)
            if prev is not None and ts > prev[2]:
                deltas[key] = (max(0, pk - prev[0]), max(0, by - prev[1]), ts - prev[2])
            if prev is None or ts > prev[2]:
                self.prev_counters[key] = (pk, by, ts)

        active = sorted({k for k, d in deltas.items() if d[0] > 0} | set(port_win))
        rows = []
        for key in active:
            pk, by, dt = deltas.get(key, (0, 0, sc.WINDOW_SECONDS))
            feats = port_win.get(key, sc.PortWindow()).features(pk, by, dt)
            rows.append((key, feats))

        stats = {"h_src_ip": sc.entropy(src), "h_dst_ip": sc.entropy(dst),
                 "h_dst_port": sc.entropy(dport),
                 "new_flows": sum(f["new_flows"] for _, f in rows),
                 "edge_pps": sum(f["rx_pps"] for _, f in rows)}
        # The baseline may only learn from benign traffic, so wait until the experiment
        # runner says the IoT devices are running (it creates this file).
        if not self.traffic_started:
            self.traffic_started = os.path.exists(os.path.join(self.run_dir, "traffic_started"))
        if self.traffic_started:
            flagged, z, z_stat = self.efilter.observe(stats)
        else:
            flagged, z, z_stat = False, 0.0, "idle"

        ml_rows, ml_ms = 0, 0.0
        run_ml = (self.mode == "detect" and self.model is not None and self.efilter.ready
                  and rows and (flagged or not self.gating))
        if run_ml:
            cand = [(k, f) for k, f in rows if self.blocked_until.get(k, 0) <= now]
            if cand:
                X = [[f[name] for name in sc.FEATURES] for _, f in cand]
                t0 = time.perf_counter()
                proba = self.model.predict_proba(X)
                ml_ms = (time.perf_counter() - t0) * 1000.0
                ml_rows = len(cand)
                for (key, _), p in zip(cand, proba):
                    p_attack = 1.0 - float(p[self.benign_idx])
                    label = self.classes[int(p.argmax())]
                    attack = p_attack >= sc.ML_ATTACK_PROBA
                    if attack:
                        self.log_dec.row(f"{now:.3f}", key[0], key[1], "stage3_ml", label,
                                         f"{p_attack:.3f}", "verdict")
                    if self.gate.update(key, attack):
                        self._block(key[0], key[1], "stage4_gate", label, f"{p_attack:.3f}")

        ts = f"{now:.3f}"
        self.log_win.row(ts, self.window_no, *[f"{stats[k]:.4f}" for k in sc.WINDOW_STATS],
                         int(flagged), f"{z:.2f}", z_stat, len(rows), ml_rows,
                         f"{ml_ms:.3f}", self.packet_ins)
        for key, f in rows:
            self.log_feat.row(ts, key[0], key[1], int(flagged),
                              *[f"{f[name]:.4f}" for name in sc.FEATURES])
        self.log_win.flush()
        self.log_feat.flush()
        self.log_dec.flush()
