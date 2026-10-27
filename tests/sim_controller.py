"""
Drives sentinel_controller.py without a network: real Ryu packet/OpenFlow libraries,
fake switch connection. Needs Ryu's source on PYTHONPATH (not needed in the VM).

    PYTHONPATH=<ryu src>:<deps> python3 tests/sim_controller.py
"""

import csv
import logging
import os
import random
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "controller"))

# ---- fake the parts of Ryu that need an event loop / live connection
app_manager = types.ModuleType("ryu.base.app_manager")


class RyuApp:
    def __init__(self, *a, **k):
        self.logger = logging.getLogger("sentinel")


app_manager.RyuApp = RyuApp
ofp_event = types.ModuleType("ryu.controller.ofp_event")
for n in ("EventOFPSwitchFeatures", "EventOFPStateChange", "EventOFPErrorMsg",
          "EventOFPPacketIn", "EventOFPPortStatsReply"):
    setattr(ofp_event, n, type(n, (), {}))
handler = types.ModuleType("ryu.controller.handler")
handler.CONFIG_DISPATCHER, handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER = "c", "m", "d"
handler.set_ev_cls = lambda *a, **k: (lambda f: f)
hub = types.ModuleType("ryu.lib.hub")
hub.spawn = lambda *a, **k: None
hub.sleep = lambda s: None
import ryu.base, ryu.controller, ryu.lib  # noqa: E401,E402  (real packages)
sys.modules.update({"ryu.base.app_manager": app_manager, "ryu.controller.ofp_event": ofp_event,
                    "ryu.controller.handler": handler, "ryu.lib.hub": hub})

from ryu.lib.packet import arp, ether_types, ethernet, ipv4, packet, tcp, udp  # noqa: E402
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser  # noqa: E402

import numpy as np  # noqa: E402
import joblib  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
import sentinel_common as sc  # noqa: E402


class FakeDP:
    def __init__(self, dpid):
        self.id = dpid
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
        self.sent = []

    def set_xid(self, msg):
        msg.xid = len(self.sent) + 1

    def send_msg(self, msg):
        self.set_xid(msg)
        msg.serialize()                     # proves the message is well-formed OpenFlow
        self.sent.append(msg)


def pkt_in(dp, port, data):
    msg = types.SimpleNamespace(datapath=dp, match={"in_port": port}, data=data,
                                buffer_id=ofproto_v1_3.OFP_NO_BUFFER)
    return types.SimpleNamespace(msg=msg)


def mac(i):
    return "00:00:00:00:00:%02x" % i


def tcp_syn(src_mac, src_ip, dst_mac, dst_ip, sport, dport, syn=True):
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(dst_mac, src_mac, ether_types.ETH_TYPE_IP))
    p.add_protocol(ipv4.ipv4(src=src_ip, dst=dst_ip, proto=6))
    p.add_protocol(tcp.tcp(src_port=sport, dst_port=dport,
                           bits=tcp.TCP_SYN if syn else tcp.TCP_ACK))
    p.serialize()
    return p.data


def udp_pkt(src_mac, src_ip, dst_mac, dst_ip, sport, dport):
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(dst_mac, src_mac, ether_types.ETH_TYPE_IP))
    p.add_protocol(ipv4.ipv4(src=src_ip, dst=dst_ip, proto=17))
    p.add_protocol(udp.udp(src_port=sport, dst_port=dport))
    p.serialize()
    return p.data


def arp_pkt(op, src_mac, src_ip, dst_mac, dst_ip):
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(dst_mac if op == 2 else "ff:ff:ff:ff:ff:ff", src_mac,
                                     ether_types.ETH_TYPE_ARP))
    p.add_protocol(arp.arp(opcode=op, src_mac=src_mac, src_ip=src_ip,
                           dst_mac=dst_mac if op == 2 else "00:00:00:00:00:00", dst_ip=dst_ip))
    p.serialize()
    return p.data


def stats_reply(dp, counters):
    body = [types.SimpleNamespace(port_no=p, rx_packets=pk, rx_bytes=by)
            for p, (pk, by) in counters.items()]
    return types.SimpleNamespace(msg=types.SimpleNamespace(datapath=dp, body=body))


def make_model(path):
    rng = np.random.default_rng(0)
    benign = np.column_stack([rng.uniform(1, 60, 400), rng.uniform(100, 40000, 400),
                              rng.uniform(60, 900, 400), rng.integers(0, 3, 400),
                              rng.integers(0, 2, 400), rng.integers(0, 3, 400),
                              np.ones(400), rng.uniform(0, 1, 400), rng.uniform(0, 1, 400),
                              np.zeros(400), rng.uniform(0, 1, 400)])
    syn = np.column_stack([rng.uniform(150, 600, 400), rng.uniform(8000, 40000, 400),
                           rng.uniform(54, 70, 400), rng.integers(100, 500, 400),
                           np.ones(400), np.ones(400), rng.integers(100, 500, 400),
                           np.ones(400), np.zeros(400), np.zeros(400), np.zeros(400)])
    m = RandomForestClassifier(n_estimators=20, random_state=0).fit(
        np.vstack([benign, syn]), ["benign"] * 400 + ["syn_flood"] * 400)
    joblib.dump({"model": m, "features": sc.FEATURES}, path)


def rows(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def main():
    logging.basicConfig(level=logging.WARNING)
    run = tempfile.mkdtemp()
    model = os.path.join(run, "m.joblib")
    make_model(model)
    mode = os.environ.get("SIM_MODE", "detect")
    gating = os.environ.get("SIM_GATING", "on")
    os.environ.update(SENTINEL_MODE=mode, SENTINEL_GATING=gating, SENTINEL_RUN_DIR=run,
                      SENTINEL_MODEL=model, SENTINEL_WARMUP="5")
    import time as _time
    import sentinel_controller as ctl

    class Clock:                         # one simulated second per window
        t = 1_000_000.0
        time = staticmethod(lambda: Clock.t)
        perf_counter = staticmethod(_time.perf_counter)
    ctl.time = Clock
    app = ctl.SentinelController()
    dp = FakeDP(2)
    app._switch_features(types.SimpleNamespace(msg=types.SimpleNamespace(datapath=dp)))
    app._state_change(types.SimpleNamespace(datapath=dp, state="m"))
    assert dp.sent[0].priority == 0, "table-miss rule missing"

    SRV = (mac(100), "10.0.0.100", 20)
    hosts = {p: (mac(p), f"10.0.0.{p}", p) for p in (10, 11, 12, 13)}
    # srv announces itself so its port is learned
    app._packet_in(pkt_in(dp, 20, arp_pkt(1, SRV[0], SRV[1], "", "10.0.0.10")))
    # a normal ARP exchange must pass
    app._packet_in(pkt_in(dp, 10, arp_pkt(1, mac(10), "10.0.0.10", "", "10.0.0.100")))
    app._packet_in(pkt_in(dp, 20, arp_pkt(2, SRV[0], SRV[1], mac(10), "10.0.0.10")))
    open(os.path.join(run, "traffic_started"), "w").close()

    cnt = {p: [0, 0] for p in (10, 11, 12, 13, 20)}
    rnd = random.Random(1)

    def window(attack=False, arp_attack=False):
        for p in (10, 11):                                  # benign: a few new TCP flows
            for _ in range(rnd.randint(0, 2)):
                app._packet_in(pkt_in(dp, p, tcp_syn(mac(p), f"10.0.0.{p}", SRV[0], SRV[1],
                                                     rnd.randint(30000, 60000), 8000)))
            pk = rnd.randint(5, 30)
            cnt[p][0] += pk
            cnt[p][1] += pk * rnd.randint(60, 900)
        app._packet_in(pkt_in(dp, 13, udp_pkt(mac(13), "10.0.0.13", SRV[0], SRV[1], 4000, 9000)))
        cnt[13][0] += 30
        cnt[13][1] += 24000
        if attack:                                          # spoofed SYN flood from port 12
            for i in range(300):
                app._packet_in(pkt_in(dp, 12, tcp_syn(mac(12), f"172.{i % 200}.{i % 7}.9",
                                                      SRV[0], SRV[1], 1000 + i, 80)))
            cnt[12][0] += 300
            cnt[12][1] += 300 * 54
        if arp_attack:
            app._packet_in(pkt_in(dp, 11, arp_pkt(2, mac(11), "10.0.0.10", SRV[0], SRV[1])))
        app._port_stats(stats_reply(dp, {p: tuple(v) for p, v in cnt.items()}))
        Clock.t += 1.0
        app._close_window()

    for _ in range(8):
        window()
    for _ in range(3):
        window(attack=True)
    for _ in range(3):
        window(arp_attack=True)

    dec = rows(os.path.join(run, "decisions.csv"))
    blocks = [(int(d["port"]), d["stage"], d["label"]) for d in dec if d["action"].startswith("drop")]
    win = rows(os.path.join(run, "windows.csv"))
    feats = rows(os.path.join(run, "features.csv"))
    drops = [m for m in dp.sent if getattr(m, "priority", None) == 100]
    print("windows:", len(win), " flagged:", sum(int(w["flagged"]) for w in win),
          " ml rows:", sum(int(w["ml_rows"]) for w in win), " feature rows:", len(feats))
    print("blocks:", blocks)
    print("drop FlowMods sent:", [(m.match["in_port"], m.hard_timeout) for m in drops])
    print("arp events:", [(r["port"], r["reason"], r["blocked"]) for r in rows(os.path.join(run, "arp.csv"))])

    if mode == "collect":
        assert not drops, "collect mode must never block"
        assert sum(int(w["ml_rows"]) for w in win) == 0
        print("ALL CHECKS PASSED (collect)")
        return
    if gating == "off":
        after_warmup = [w for w in win if w["z_stat"] not in ("warmup", "idle")]
        assert all(int(w["ml_rows"]) > 0 for w in after_warmup), "baseline mode skipped ML"
    assert (12, "stage4_gate", "syn_flood") in blocks, "SYN flood port not blocked"
    assert (11, "stage1_arp", "arp_spoofing") in blocks, "ARP spoofer not blocked"
    assert not any(p in (10, 13, 20) for p, _, _ in blocks), "benign port blocked"
    assert {m.match["in_port"] for m in drops} == {11, 12}
    if gating == "on":
        assert all(int(w["ml_rows"]) == 0 for w in win if w["flagged"] == "0"), "ML ran ungated"
    print(f"ALL CHECKS PASSED (detect, gating {gating})")


if __name__ == "__main__":
    main()
