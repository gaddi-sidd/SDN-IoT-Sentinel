"""
Train the Stage-3 classifier on labelled rows from collect/attack runs.

    python3 analysis/train_classifier.py --runs runs/collect_* runs/*train* \
            --out models/classifier.joblib

Model: RandomForest (robust, no scaling needed, fast inference). Features are the
behavioural ones in sentinel_common.FEATURES; IP/MAC are deliberately excluded so
the model cannot memorise the attacker's identity.
"""

import argparse
import glob
import json
import os
import sys

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "controller"))
sys.path.insert(0, os.path.dirname(__file__))
import sentinel_common as sc  # noqa: E402
from label_features import load_runs  # noqa: E402


def expand(patterns):
    dirs = []
    for p in patterns:
        dirs.extend(sorted(glob.glob(p)))
    return [d for d in dirs if os.path.isdir(d)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--out", default="models/classifier.joblib")
    ap.add_argument("--trees", type=int, default=120)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    rows = load_runs(expand(a.runs))
    if not rows:
        sys.exit("no labelled rows found in the given runs")
    X = np.array([r["x"] for r in rows])
    y = np.array([r["label"] for r in rows])
    n_atk = int((y == "attack").sum())
    if n_atk == 0:
        sys.exit("no attack rows: include attack-scenario runs, not only collect runs")

    clf = RandomForestClassifier(n_estimators=a.trees, random_state=a.seed,
                                 class_weight="balanced", n_jobs=-1)
    clf.fit(X, y)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    joblib.dump({"model": clf, "features": sc.FEATURES}, a.out)

    imp = sorted(zip(sc.FEATURES, clf.feature_importances_), key=lambda t: -t[1])
    meta = {"n_rows": len(rows), "n_attack": n_atk, "n_benign": int((y == "benign").sum()),
            "runs": sorted({r["run"] for r in rows}),
            "feature_importance": [[k, round(float(v), 4)] for k, v in imp]}
    json.dump(meta, open(a.out + ".meta.json", "w"), indent=2)
    print(f"trained on {len(rows)} rows ({n_atk} attack / {len(rows)-n_atk} benign)")
    print("top features:", ", ".join(f"{k}={v:.2f}" for k, v in imp[:5]))
    print(f"saved {a.out}")


if __name__ == "__main__":
    main()
