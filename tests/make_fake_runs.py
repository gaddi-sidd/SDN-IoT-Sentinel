"""
Fabricate run directories in the controller's exact CSV format, so the training
and evaluation scripts can be tested without Mininet. NOT part of the real
pipeline: the VM produces these files for real.
"""

import csv
import json
import os
import random
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "controller"))
import sentinel_common as sc  # noqa: E402

BENIGN_PORTS = [10, 11, 13]
ATTACKER_PORT = 12


def _w(path, header, rows):
    with open(path, "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(header)
        wr.writerows(rows)


def benign_feats(rnd):
    return {"rx_pps": rnd.uniform(5, 60), "rx_Bps": rnd.uniform(400, 9000),
            "mean_pkt_size": rnd.uniform(60, 400), "new_flows": rnd.randint(0, 3),
            "uniq_dst_ip": 1, "uniq_dst_port": rnd.randint(1, 2), "uniq_src_ip": 1,
            "tcp_frac": rnd.choice([0, 1]), "udp_frac": rnd.choice([0, 1]),
            "icmp_frac": 0, "dst_port_entropy": rnd.uniform(0, 0.5)}


def attack_feats(scenario, rnd):
    f = benign_feats(rnd)
    if scenario in ("syn_flood", "chained"):
        f.update(rx_pps=rnd.uniform(150, 600), new_flows=rnd.randint(150, 400),
                 uniq_src_ip=rnd.randint(150, 400), mean_pkt_size=rnd.uniform(54, 70),
                 tcp_frac=1, udp_frac=0, dst_port_entropy=0, uniq_dst_port=1)
    elif scenario == "udp_flood":
        f.update(rx_pps=rnd.uniform(150, 600), new_flows=rnd.randint(150, 400),
                 uniq_src_ip=rnd.randint(150, 400), udp_frac=1, tcp_frac=0)
    elif scenario == "icmp_flood":
        f.update(rx_pps=rnd.uniform(150, 600), new_flows=rnd.randint(100, 300),
                 icmp_frac=1, tcp_frac=0, udp_frac=0)
    elif scenario == "port_scan":
        f.update(rx_pps=rnd.uniform(60, 200), new_flows=rnd.randint(100, 400),
                 uniq_dst_port=rnd.randint(100, 400), tcp_frac=1,
                 dst_port_entropy=rnd.uniform(6, 9), mean_pkt_size=rnd.uniform(54, 70))
    elif scenario == "lowrate":                    # evasive: looks nearly benign
        f.update(rx_pps=rnd.uniform(40, 70), new_flows=rnd.randint(30, 50),
                 uniq_src_ip=rnd.randint(30, 50), tcp_frac=1)
    return f


def make_run(base, scenario, gating, seed, detect=True, arp=False):
    rnd = random.Random(seed)
    d = os.path.join(base, f"{scenario}_{'detect' if detect else 'collect'}_{gating}_s{seed}")
    os.makedirs(d, exist_ok=True)
    t0 = 1_000_000.0
    baseline, attack_at, attack_dur = 45, 15, 30
    astart, aend = baseline + attack_at, baseline + attack_at + attack_dur
    total = aend + 8 if scenario not in ("benign", "collect") else baseline + attack_dur

    wrows, frows, drows, arows, cpurows = [], [], [], [], []
    gate_hist = []
    for w in range(total):
        ts = t0 + w
        ports = BENIGN_PORTS + ([ATTACKER_PORT] if scenario not in ("benign", "collect") else [])
        in_attack = scenario not in ("benign", "collect") and astart <= w <= aend
        flagged = 0
        row_feats = []
        for p in ports:
            atk = (p == ATTACKER_PORT and in_attack)
            f = attack_feats(scenario, rnd) if atk else benign_feats(rnd)
            row_feats.append((p, f, atk))
            if atk and scenario != "lowrate":
                flagged = 1
        warmup = w < baseline - 5
        ml_rows = 0
        if detect and not warmup:
            do_ml = (flagged or gating == "off")
            if do_ml:
                for p, f, atk in row_feats:
                    ml_rows += 1
                    attack_pred = atk and scenario != "lowrate"
                    if attack_pred:
                        drows.append([f"{ts:.3f}", 2, p, "stage3_ml", scenario, "0.95", "verdict"])
                    gate_hist.append((p, attack_pred))
                    recent = [a for (pp, a) in gate_hist[-3:] if pp == p]
                    if sum(a for pp, a in gate_hist[-6:] if pp == p) >= 2 and attack_pred:
                        drows.append([f"{ts:.3f}", 2, p, "stage4_gate", scenario, "0.95",
                                      "drop_20s"])
        for p, f, atk in row_feats:
            frows.append([f"{ts:.3f}", 2, p, flagged] + [f"{f[n]:.4f}" for n in sc.FEATURES])
        wrows.append([f"{ts:.3f}", w + 1, 0, 0, 0, sum(f["new_flows"] for _, f, _ in row_feats),
                      sum(f["rx_pps"] for _, f, _ in row_feats), flagged, 0, "sim",
                      len(ports), ml_rows, 0.4 if ml_rows else 0.0, 0])
        cpu = 3 + (0.8 * ml_rows if ml_rows else 0) + rnd.uniform(-0.3, 0.3)
        cpurows.append([f"{ts:.3f}", f"{max(0, cpu):.2f}"])

    if arp or scenario in ("arp_spoof", "chained"):
        for i in range(3):
            arows.append([f"{t0+astart+i:.3f}", 2, ATTACKER_PORT, "00:00:00:00:00:66",
                          "10.0.0.100", "ip_rebinding", 1 if i == 2 else 0])
        if detect:
            drows.append([f"{t0+astart+2:.3f}", 2, ATTACKER_PORT, "stage1_arp",
                          "arp_spoofing", "", "drop_20s"])

    _w(os.path.join(d, "windows.csv"),
       ["ts", "window"] + sc.WINDOW_STATS + ["flagged", "z", "z_stat", "active_ports",
        "ml_rows", "ml_ms", "packet_ins"], wrows)
    _w(os.path.join(d, "features.csv"),
       ["ts", "dpid", "port", "flagged"] + sc.FEATURES, frows)
    _w(os.path.join(d, "decisions.csv"),
       ["ts", "dpid", "port", "stage", "label", "p_attack", "action"], drows)
    _w(os.path.join(d, "arp.csv"),
       ["ts", "dpid", "port", "mac", "ip", "reason", "blocked"], arows)
    _w(os.path.join(d, "cpu.csv"), ["ts", "cpu_pct"], cpurows)
    json.dump({"scenario": scenario,
               "attacker_port": None if scenario in ("benign", "collect") else ATTACKER_PORT,
               "attacker_dpid": 2, "t0": t0,
               "attack_windows": [] if scenario in ("benign", "collect") else [astart, aend],
               "baseline_s": baseline, "total_windows": total},
              open(os.path.join(d, "ground_truth.json"), "w"), indent=2)
    json.dump({"framework": "sim", "mode": "detect" if detect else "collect",
               "gating": gating == "on", "classes": ["attack", "benign"], "pid": 0,
               "warmup_windows": baseline - 5}, open(os.path.join(d, "controller_config.json"), "w"))
    return d


def build(base):
    os.makedirs(base, exist_ok=True)
    made = []
    # training runs: a couple of each attack + benign collect, seeds 1-2
    for scen in ["syn_flood", "udp_flood", "icmp_flood", "port_scan", "arp_spoof", "chained"]:
        for seed in (1, 2):
            made.append(make_run(base, scen, "on", seed))
    for seed in (1, 2, 3):
        made.append(make_run(base, "collect", "on", seed, detect=False))
    # held-out eval runs: seed 9, gating on and off, plus benign and lowrate
    for scen in ["syn_flood", "udp_flood", "icmp_flood", "port_scan", "arp_spoof",
                 "chained", "lowrate", "benign"]:
        for gating in ("on", "off"):
            made.append(make_run(base, scen, gating, 9))
    return made


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp()
    made = build(base)
    print(base)
    print(f"made {len(made)} fake runs")
