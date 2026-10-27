#!/usr/bin/env bash
# The whole experiment campaign, start to finish. Run as root inside the VM:
#     sudo bash run_all.sh
# Produces: training runs -> models/classifier.joblib -> held-out detect runs
#           -> out/summary.json, out/results_table.csv, out/*.png
#
# Point RYU at your Python 3.9 venv's manager if it isn't on PATH:
#     RYU_BIN=~/ryu39/bin sudo -E bash run_all.sh
set -euo pipefail
cd "$(dirname "$0")"

RYU_BIN="${RYU_BIN:-$HOME/ryu39/bin}"
export PATH="$RYU_BIN:$PATH"
PY=python3
SEEDS_TRAIN="${SEEDS_TRAIN:-1 2}"
SEEDS_EVAL="${SEEDS_EVAL:-9 10 11}"
ATTACKS="syn_flood udp_flood icmp_flood port_scan arp_spoof chained"

mkdir -p runs models out
run() { echo; echo ">>> $*"; $PY experiments/run_experiment.py "$@"; }

echo "############ PHASE 1: collect training data ############"
for s in $SEEDS_TRAIN; do
  for a in $ATTACKS; do run --scenario "$a" --mode detect --gating on --seed "$s"; done
  run --scenario collect --mode collect --seed "$s"
done

echo "############ PHASE 2: train the classifier ############"
$PY analysis/train_classifier.py --runs "runs/*_detect_on_s1_*" "runs/*_detect_on_s2_*" \
    "runs/collect_*" --out models/classifier.joblib

echo "############ PHASE 3: held-out evaluation (gated vs all) ############"
for s in $SEEDS_EVAL; do
  for a in $ATTACKS lowrate; do
    run --scenario "$a" --mode detect --gating on  --seed "$s"
    run --scenario "$a" --mode detect --gating off --seed "$s"
  done
  run --scenario benign --mode detect --gating on --seed "$s"
done

echo "############ PHASE 4: results ############"
$PY analysis/evaluate.py --runs "runs/*_detect_*_s9_*" "runs/*_detect_*_s10_*" \
    "runs/*_detect_*_s11_*" --out out
echo
echo "Done. See out/summary.json, out/results_table.csv, out/cpu.png, out/ml_share.png"
