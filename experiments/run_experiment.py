#!/usr/bin/env python3
"""
One experiment run end to end (must run as root, inside the VM):

  1. start the Ryu controller in the chosen mode/gating, into a fresh run dir
  2. start Mininet (topology.py) and the server sink
  3. BASELINE phase: only benign IoT traffic, so the entropy filter learns normality
  4. ATTACK phase: scheduled attacks from the one attacker host; benign traffic continues
  5. record ground truth (attack windows + attacker port) and sample controller CPU
  6. stop everything; the controller's CSV logs + ground_truth.json are the result

    sudo python3 experiments/run_experiment.py --scenario syn_flood --mode detect --gating on
    sudo python3 experiments/run_experiment.py --scenario collect --mode collect     # training data

Scenarios: benign, syn_flood, udp_flood, icmp_flood, port_scan, arp_spoof, chained,
           lowrate (evasive), collect (benign only, for training).
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "controller"))
import sentinel_common as sc  # noqa: E402

SERVER = "h100"
SERVER_IP = "10.0.0.100"
ATTACKER = "h9"
BENIGN = ["h10", "h11", "h12", "h13", "h14", "h15", "h16", "h17", "h18"]


def controller_cmd(run_dir, mode, gating, model, warmup):
    env = dict(os.environ, SENTINEL_MODE=mode, SENTINEL_GATING=gating,
               SENTINEL_RUN_DIR=run_dir, SENTINEL_MODEL=model or "",
               SENTINEL_WARMUP=str(warmup))
    mgr = "ryu-manager" if _which("ryu-manager") else "osken-manager"
    app = os.path.join(ROOT, "controller", "sentinel_controller.py")
    return [mgr, "--ofp-tcp-listen-port", "6633", app], env


def _which(x):
    return subprocess.call(["bash", "-lc", f"command -v {x}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


class CpuSampler:
    """Samples the controller process CPU% (via /proc) once a second in the background."""

    def __init__(self, pid, path):
        self.pid, self.path = pid, path
        self.proc = subprocess.Popen(
            ["python3", os.path.join(HERE, "cpu_sampler.py"), str(pid), path])

    def stop(self):
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--mode", choices=["detect", "collect"], default="detect")
    ap.add_argument("--gating", choices=["on", "off"], default="on")
    ap.add_argument("--model", default=os.path.join(ROOT, "models", "classifier.joblib"))
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--baseline", type=float, default=45.0, help="benign-only seconds")
    ap.add_argument("--attack-at", type=float, default=15.0, help="seconds into attack phase")
    ap.add_argument("--attack-dur", type=float, default=30.0)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("must run as root (Mininet needs it): sudo python3 ...")

    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.log import setLogLevel
    from topology import SentinelTopo
    setLogLevel("warning")

    warmup = int(a.baseline - 5)
    run_dir = a.run_dir or os.path.join(
        ROOT, "runs", f"{a.scenario}_{a.mode}_{a.gating}_s{a.seed}_{int(time.time())}")
    os.makedirs(run_dir, exist_ok=True)
    model = a.model if (a.mode == "detect" and os.path.exists(a.model)) else ""

    cmd, env = controller_cmd(run_dir, a.mode, a.gating, model, warmup)
    print(f"[run] {a.scenario} mode={a.mode} gating={a.gating} -> {run_dir}")
    ctl = subprocess.Popen(cmd, env=env, cwd=ROOT,
                           stdout=open(f"{run_dir}/controller.log", "w"),
                           stderr=subprocess.STDOUT)
    time.sleep(6)                                   # let it bind 6633 and read the model
    cfg = json.load(open(f"{run_dir}/controller_config.json"))
    sampler = CpuSampler(cfg["pid"], f"{run_dir}/cpu.csv")

    net = Mininet(topo=SentinelTopo(), controller=None, switch=OVSSwitch)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    net.start()
    procs = []
    try:
        net.pingAll(timeout="1")
        srv = net.get(SERVER)
        procs.append(srv.popen(f"python3 {ROOT}/traffic/server.py --udp 9000 --tcp 8000",
                               shell=True))
        time.sleep(1)
        for i, name in enumerate(BENIGN):
            h = net.get(name)
            procs.append(h.popen(
                f"python3 {ROOT}/traffic/iot_device.py --server {SERVER_IP} "
                f"--port {9000 if i % 2 else 8000} --proto {'udp' if i % 2 else 'tcp'} "
                f"--seed {a.seed * 100 + i} --duration 999", shell=True))

        t0 = time.time()
        open(f"{run_dir}/traffic_started", "w").close()   # controller starts learning now
        print(f"[run] baseline {a.baseline}s (learning benign)")
        time.sleep(a.baseline)

        gt = {"scenario": a.scenario, "attacker_port": None, "attack_windows": [],
              "t0": t0, "baseline_s": a.baseline}
        if a.scenario not in ("benign", "collect"):
            time.sleep(a.attack_at)
            astart = time.time()
            gt["attacker_port"] = 12                       # h9 is on s2 edge port 12
            gt["attacker_dpid"] = 2
            print(f"[run] ATTACK: {a.scenario} for {a.attack_dur}s")
            run_attack(net, a.scenario, a.attack_dur, a.seed)
            aend = time.time()
            gt["attack_windows"] = [int(astart - t0), int(aend - t0) + 1]
            time.sleep(8)                                   # let mitigation settle / log
        else:
            time.sleep(a.attack_dur)

        gt["total_windows"] = int(time.time() - t0)
        json.dump(gt, open(f"{run_dir}/ground_truth.json", "w"), indent=2)
        print(f"[run] done -> {run_dir}")
    finally:
        for p in procs:
            _kill(p)
        net.stop()
        sampler.stop()
        ctl.send_signal(signal.SIGINT)
        try:
            ctl.wait(timeout=6)
        except subprocess.TimeoutExpired:
            ctl.kill()
        subprocess.call(["bash", "-lc", "mn -c >/dev/null 2>&1"])
    print(run_dir)


def run_attack(net, scenario, dur, seed):
    atk = net.get(ATTACKER)
    iface = f"{ATTACKER}-eth0"
    cmds = []
    if scenario in ("syn_flood", "chained"):
        cmds.append(f"timeout {dur} hping3 -S --flood --rand-source -p 80 {SERVER_IP}")
    if scenario == "udp_flood":
        cmds.append(f"timeout {dur} hping3 --udp --flood --rand-source -p 9000 {SERVER_IP}")
    if scenario == "icmp_flood":
        cmds.append(f"timeout {dur} hping3 --icmp --flood {SERVER_IP}")
    if scenario == "port_scan":
        cmds.append(f"timeout {dur} bash -c 'while true; do nmap -sS -T4 -p1-1024 {SERVER_IP}; done'")
    if scenario == "lowrate":                              # evasive: below the entropy flag
        cmds.append(f"timeout {dur} hping3 -S -i u20000 --rand-source -p 80 {SERVER_IP}")
    if scenario in ("arp_spoof", "chained"):
        cmds.append(f"python3 {ROOT}/traffic/arp_spoof.py --iface {iface} "
                    f"--victim-ip 10.0.0.10 --gateway-ip {SERVER_IP} --count 20 --interval 0.5")
    procs = [atk.popen(c, shell=True) for c in cmds]
    deadline = time.time() + dur + 2
    for p in procs:
        try:
            p.wait(timeout=max(0, deadline - time.time()))
        except Exception:
            _kill(p)


def _kill(p):
    try:
        p.send_signal(signal.SIGTERM)
    except Exception:
        pass


if __name__ == "__main__":
    main()
