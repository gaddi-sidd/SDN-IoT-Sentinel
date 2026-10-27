#!/usr/bin/env bash
# One-time setup inside a fresh Ubuntu 22.04 VM. Run with sudo:
#     sudo bash setup_vm.sh
# Installs Mininet + Open vSwitch, the attack tools, Python deps, and the Ryu
# controller in its own Python 3.9 venv (Ryu breaks on Python >= 3.10).
set -euo pipefail

echo "[1/5] apt packages (Mininet, OVS, attack tools)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y mininet openvswitch-switch openvswitch-testcontroller \
    hping3 nmap python3-pip python3-venv git

echo "[2/5] making sure Open vSwitch is running..."
systemctl enable --now openvswitch-switch || service openvswitch-switch start || true
# the distro's test controller must NOT squat on 6633
systemctl disable --now openvswitch-testcontroller 2>/dev/null || true
pkill -f ovs-testcontroller 2>/dev/null || true

echo "[3/5] analysis deps (host Python 3)..."
pip3 install --break-system-packages 'scikit-learn>=1.3' 'numpy>=1.24' joblib matplotlib 2>/dev/null \
  || pip3 install 'scikit-learn>=1.3' numpy joblib matplotlib

echo "[4/5] Ryu controller venv (Python 3.9)..."
if ! command -v python3.9 >/dev/null 2>&1; then
    add-apt-repository -y ppa:deadsnakes/ppa
    apt-get update -q
    apt-get install -y python3.9 python3.9-venv python3.9-distutils
fi
SUDO_USER_HOME=$(eval echo "~${SUDO_USER:-root}")
VENV="${SUDO_USER_HOME}/ryu39"
python3.9 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip wheel
# pinned versions that actually install together on 3.9
"$VENV/bin/pip" install 'eventlet==0.30.2' 'ryu==4.34' 'setuptools<67' 'scikit-learn>=1.3' \
    numpy joblib 'protobuf<4'
echo "ryu venv at: $VENV"

echo "[5/5] self-test (no network needed)..."
python3 -m unittest discover -s tests -p 'test_*.py' -v 2>&1 | tail -4 || true

cat <<EOF

Setup done.
  * ryu-manager:   $VENV/bin/ryu-manager
  * run everything: sudo bash run_all.sh
If 'sudo mn --test pingall' works, Mininet is healthy.
EOF
