"""
Turn a set of runs into the numbers and figures for the review.

    python3 analysis/evaluate.py --runs runs/*_detect_* --out out/

Per detect run it reports:
    detected          did any block land on the attacker's port during/after the attack
    reaction_s        seconds from attack start to that block
    benign_blocks     blocks on any non-attacker port (false positives)
    ml_share          fraction of (port,window) evaluations that reached the classifier
    mean_cpu, p95_cpu controller CPU% during the attack phase

Across gating on vs off it reports the headline comparison:
    ML-on-all vs ML-on-flagged: ml_share and controller CPU.
Writes summary.json, results_table.csv, and (if matplotlib) cpu.png + ml_share.png.
"""

import argparse
import csv
import glob
import json
import os
import statistics as st


def read_csv(path):
    return list(csv.DictReader(open(path))) if os.path.exists(path) else []


def run_metrics(run_dir):
    gt = json.load(open(os.path.join(run_dir, "ground_truth.json")))
    cfg = json.load(open(os.path.join(run_dir, "controller_config.json")))
    t0 = gt["t0"]
    win = gt.get("attack_windows") or []
    aport, adpid = gt.get("attacker_port"), gt.get("attacker_dpid")

    dec = read_csv(os.path.join(run_dir, "decisions.csv"))
    blocks = [d for d in dec if d["action"].startswith("drop")]
    detected, reaction, benign_blocks = False, None, 0
    for d in blocks:
        is_atk = aport is not None and int(d["port"]) == aport and int(d["dpid"]) == adpid
        rel = float(d["ts"]) - t0
        if is_atk and win and rel >= win[0] - 1:
            if not detected:
                detected, reaction = True, round(rel - win[0], 2)
        elif not is_atk:
            benign_blocks += 1

    wins = read_csv(os.path.join(run_dir, "windows.csv"))
    active = sum(int(w["active_ports"]) for w in wins)
    ml = sum(int(w["ml_rows"]) for w in wins)
    ml_share = (ml / active) if active else 0.0
    ml_ms = [float(w["ml_ms"]) for w in wins if float(w["ml_ms"]) > 0]

    cpu_rows = read_csv(os.path.join(run_dir, "cpu.csv"))
    acpu = []
    for c in cpu_rows:
        rel = float(c["ts"]) - t0
        if not win or (win and win[0] <= rel <= win[1] + 8):
            acpu.append(float(c["cpu_pct"]))
    all_cpu = [float(c["cpu_pct"]) for c in cpu_rows]

    return {
        "run": os.path.basename(run_dir.rstrip("/")), "scenario": gt["scenario"],
        "mode": cfg["mode"], "gating": "on" if cfg["gating"] else "off",
        "detected": detected, "reaction_s": reaction, "benign_blocks": benign_blocks,
        "active_evals": active, "ml_evals": ml, "ml_share": round(ml_share, 4),
        "mean_ml_ms": round(st.mean(ml_ms), 3) if ml_ms else 0.0,
        "mean_cpu": round(st.mean(acpu), 2) if acpu else 0.0,
        "p95_cpu": round(sorted(acpu)[int(0.95 * (len(acpu) - 1))], 2) if acpu else 0.0,
        "mean_cpu_all": round(st.mean(all_cpu), 2) if all_cpu else 0.0,
    }


def expand(patterns):
    dirs = []
    for p in patterns:
        dirs.extend(sorted(glob.glob(p)))
    return [d for d in dirs if os.path.isdir(d)
            and os.path.exists(os.path.join(d, "ground_truth.json"))]


def agg(metrics, key):
    xs = [m[key] for m in metrics if m[key] is not None]
    return {"mean": round(st.mean(xs), 3), "sd": round(st.pstdev(xs), 3) if len(xs) > 1 else 0.0,
            "n": len(xs)} if xs else {"mean": None, "sd": None, "n": 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--out", default="out")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    metrics = [run_metrics(d) for d in expand(a.runs)]
    if not metrics:
        raise SystemExit("no runs with ground_truth.json matched")

    cols = ["run", "scenario", "mode", "gating", "detected", "reaction_s", "benign_blocks",
            "ml_share", "mean_ml_ms", "mean_cpu", "p95_cpu"]
    with open(os.path.join(a.out, "results_table.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for m in metrics:
            w.writerow({k: m[k] for k in cols})

    detect = [m for m in metrics if m["mode"] == "detect"]
    on = [m for m in detect if m["gating"] == "on" and m["scenario"] not in ("benign",)]
    off = [m for m in detect if m["gating"] == "off" and m["scenario"] not in ("benign",)]
    benign = [m for m in detect if m["scenario"] == "benign"]

    summary = {
        "n_runs": len(metrics),
        "detection": {
            "attacks": len([m for m in detect if m["scenario"] not in ("benign",)]),
            "detected": len([m for m in detect
                             if m["scenario"] not in ("benign",) and m["detected"]]),
        },
        "reaction_s": agg([m for m in detect if m["detected"]], "reaction_s"),
        "false_positive_blocks_total": sum(m["benign_blocks"] for m in detect),
        "benign_runs": len(benign),
        "benign_runs_with_block": len([m for m in benign if m["benign_blocks"] > 0]),
        "gating_on": {"ml_share": agg(on, "ml_share"), "mean_cpu": agg(on, "mean_cpu"),
                      "p95_cpu": agg(on, "p95_cpu")},
        "gating_off": {"ml_share": agg(off, "ml_share"), "mean_cpu": agg(off, "mean_cpu"),
                       "p95_cpu": agg(off, "p95_cpu")},
    }
    if on and off and summary["gating_off"]["mean_cpu"]["mean"]:
        red = 100 * (1 - summary["gating_on"]["mean_cpu"]["mean"]
                     / summary["gating_off"]["mean_cpu"]["mean"])
        summary["cpu_reduction_pct_gated_vs_all"] = round(red, 1)
    json.dump(summary, open(os.path.join(a.out, "summary.json"), "w"), indent=2)

    _print(summary)
    _plots(a.out, on, off)


def _print(s):
    d = s["detection"]
    print("\n=== SDN-IoT Sentinel: results ===")
    print(f"runs analysed                 {s['n_runs']}")
    print(f"attacks detected              {d['detected']}/{d['attacks']}")
    r = s["reaction_s"]
    print(f"reaction time (s)             mean {r['mean']} ± {r['sd']} (n={r['n']})")
    print(f"false-positive blocks total   {s['false_positive_blocks_total']}")
    print(f"benign runs with any block    {s['benign_runs_with_block']}/{s['benign_runs']}")
    on, off = s["gating_on"], s["gating_off"]
    print(f"ML share  gated {on['ml_share']['mean']}   all-traffic {off['ml_share']['mean']}")
    print(f"CPU mean  gated {on['mean_cpu']['mean']}%  all-traffic {off['mean_cpu']['mean']}%")
    if "cpu_reduction_pct_gated_vs_all" in s:
        print(f"CPU reduction (gated vs all)  {s['cpu_reduction_pct_gated_vs_all']}%")
    print()


def _plots(out, on, off):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return
    if on and off:
        fig, ax = plt.subplots(figsize=(4.2, 3.2))
        labels = ["ML on\nflagged only", "ML on\nall traffic"]
        vals = [st.mean([m["mean_cpu"] for m in on]), st.mean([m["mean_cpu"] for m in off])]
        ax.bar(labels, vals, color=["#2e7d32", "#c62828"])
        ax.set_ylabel("Controller CPU (% of one core)")
        ax.set_title("Controller cost: gating the classifier")
        for i, v in enumerate(vals):
            ax.text(i, v, f"{v:.1f}%", ha="center", va="bottom")
        fig.tight_layout()
        fig.savefig(os.path.join(out, "cpu.png"), dpi=140)

        fig, ax = plt.subplots(figsize=(4.2, 3.2))
        vals = [100 * st.mean([m["ml_share"] for m in on]),
                100 * st.mean([m["ml_share"] for m in off])]
        ax.bar(labels, vals, color=["#2e7d32", "#c62828"])
        ax.set_ylabel("% of port-windows sent to the classifier")
        ax.set_title("Traffic reaching the ML stage")
        for i, v in enumerate(vals):
            ax.text(i, v, f"{v:.0f}%", ha="center", va="bottom")
        fig.tight_layout()
        fig.savefig(os.path.join(out, "ml_share.png"), dpi=140)
        print(f"wrote {out}/cpu.png and {out}/ml_share.png")


if __name__ == "__main__":
    main()
