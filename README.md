# SDN-IoT Sentinel

A closed-loop defence for an SDN-controlled IoT network, running on **Mininet +
Ryu** with real Open vSwitch and real OpenFlow. It screens all traffic with two
cheap pre-filters, sends only flagged traffic to a machine-learning classifier,
and turns confirmed attacks into OpenFlow drop rules.

This is the **emulated-testbed implementation** of the proposal: real kernel
networking stack and real OpenFlow messages, with scripted (not captured-from-the-wild)
traffic. It is the same methodology as a QEMU/Mininet testbed — real stack,
generated workload.

## The pipeline (per device, per 1-second window)

| Stage | What | Based on |
|---|---|---|
| 1. Layer 2 | **ARP dual-cache** — unsolicited reply / IP rebinding / one MAC → many IPs; 3 strikes in 10 s blocks the port | Patrice et al. 2024 |
| 2. Layer 3/4 | **Entropy + volume z-scores** of source IP, dest IP, dest port, new-flow and packet rate, against a baseline learned from benign traffic | Puranik et al. 2023 |
| 3. ML | **RandomForest** on 11 behavioural features — runs **only on windows Stage 2 flags** | Suman et al. 2024 |
| 4. Mitigation | **2-of-3 verdict gate → OpenFlow drop rule** with a timeout | Meng et al. 2024 |

The central claim — *gating the classifier behind the pre-filters keeps controller
overhead low* — is **measured**, not modelled: every run records controller CPU and
the fraction of traffic that reached the ML stage, with gating on vs off.

### No identity features
The classifier uses packet rate, byte rate, packet size, new-flow count, unique
destination IPs/ports, unique **source** IPs, protocol mix and destination-port
entropy. It never sees an IP or MAC address, so it cannot simply memorise "the
attacker is 10.0.0.9". Training and testing use **different runs**, so windows from
one capture cannot leak across the split.

## Repository layout

```
controller/
  sentinel_common.py       detection logic (no Ryu import; unit-tested)
  sentinel_controller.py   the Ryu app: 4 stages wired to OpenFlow events
traffic/
  server.py  iot_device.py  arp_spoof.py    benign + attack traffic
experiments/
  topology.py              11-host, 3-switch Mininet topology
  run_experiment.py        one run: baseline -> attack -> logs + ground truth + CPU
  cpu_sampler.py           per-second controller CPU from /proc
analysis/
  label_features.py  train_classifier.py  evaluate.py
tests/
  test_common.py           unit tests (run anywhere)
  sim_controller.py        drives the controller with real packets, fake switch
  make_fake_runs.py        fabricates runs to test the analysis offline
setup_vm.sh  run_all.sh  requirements.txt
```

## Quick start (Ubuntu 22.04 VM)

See `VM_SETUP.md` for creating the VM. Then, inside it:

```bash
cd sdn-sentinel
sudo bash setup_vm.sh                 # one time: Mininet, OVS, tools, Ryu venv
RYU_BIN=~/ryu39/bin sudo -E bash run_all.sh    # the whole campaign (~15-25 min)
```

Results land in `out/`:
- `summary.json` — detection rate, reaction time, false positives, **CPU gated vs all**
- `results_table.csv` — one row per run
- `cpu.png`, `ml_share.png` — the two figures for your slides

### Run one scenario by hand
```bash
# terminal A — the controller
~/ryu39/bin/ryu-manager --ofp-tcp-listen-port 6633 controller/sentinel_controller.py
# terminal B — one attack run
sudo python3 experiments/run_experiment.py --scenario syn_flood --mode detect --gating on
```

Scenarios: `benign syn_flood udp_flood icmp_flood port_scan arp_spoof chained lowrate collect`.
`lowrate` is the deliberately evasive attack (stays under the entropy filter);
`collect` is benign-only, for training data.

## What to tell the reviewers

- **Real:** Linux network stack, Open vSwitch, OpenFlow 1.3 messages, the Ryu
  control loop, scheduled attacks from `hping3`/`nmap`, and measured controller CPU.
- **Emulated / scripted:** the hosts are Mininet namespaces and the traffic is
  generated, not a real-world capture; the classifier is trained on this testbed's
  own traffic, not yet on Bot-IoT.
- **Known limit:** the pre-filter is a gate — anything it doesn't flag never reaches
  the classifier, so the `lowrate` attack is caught late or missed. This is reported,
  not hidden (it is a scenario in the results table).

## Tests (no VM needed)
```bash
python3 -m unittest discover -s tests -p 'test_*.py'    # detection logic
python3 tests/make_fake_runs.py /tmp/fr && \
  python3 analysis/evaluate.py --runs '/tmp/fr/*_detect_*' --out /tmp/fr/out
```

## Honest status
Testbed implementation with measured results on emulated traffic. Not validated on
physical hardware, real users, or the Bot-IoT dataset. Mitigation is real within the
emulation (OpenFlow drop rules are installed in Open vSwitch).
