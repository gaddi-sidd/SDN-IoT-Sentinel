"""
Turn a run's features.csv + ground_truth.json into labelled rows.

A feature row (ts, dpid, port, features...) is labelled:
    attack  if it is the attacker's port during the attack window
    benign  otherwise
Split is BY RUN, never by row: train and test use different runs, so windows from
one capture can't leak across the split (the IUDBMS lesson).
"""

import csv
import json
import os

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "controller"))
import sentinel_common as sc  # noqa: E402


def load_run(run_dir):
    gt = json.load(open(os.path.join(run_dir, "ground_truth.json")))
    t0 = gt["t0"]
    win = gt.get("attack_windows") or []
    aport, adpid = gt.get("attacker_port"), gt.get("attacker_dpid")
    rows = []
    fpath = os.path.join(run_dir, "features.csv")
    if not os.path.exists(fpath):
        return rows
    for r in csv.DictReader(fpath and open(fpath)):
        rel = float(r["ts"]) - t0
        is_attacker = (aport is not None and int(r["port"]) == aport
                       and int(r["dpid"]) == adpid)
        in_window = bool(win) and win[0] <= rel <= win[1]
        label = "attack" if (is_attacker and in_window) else "benign"
        x = [float(r[name]) for name in sc.FEATURES]
        rows.append({"run": os.path.basename(run_dir.rstrip("/")), "rel": rel,
                     "dpid": int(r["dpid"]), "port": int(r["port"]),
                     "label": label, "scenario": gt["scenario"], "x": x})
    return rows


def load_runs(run_dirs):
    out = []
    for d in run_dirs:
        if os.path.exists(os.path.join(d, "ground_truth.json")):
            out.extend(load_run(d))
    return out
