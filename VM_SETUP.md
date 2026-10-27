# Setting up the Ubuntu VM (Windows + VirtualBox)

You're on Windows and Mininet only runs on Linux, so everything runs inside an
Ubuntu virtual machine. You already have **VirtualBox**. Budget ~45 min, most of
it unattended downloading.

## 1. Download Ubuntu
Get **Ubuntu 22.04.x LTS Desktop** (the `.iso`) from `releases.ubuntu.com/22.04`.
Use 22.04, not 24.04 — the Mininet/Ryu stack is best tested there.

## 2. Create the VM in VirtualBox
- **New** → Name `sentinel`, Type **Linux**, Version **Ubuntu (64-bit)**.
  - If you only see 32-bit options, enable **virtualization** in your laptop's
    BIOS (on the HP Victus: restart, tap **Esc/F10**, enable *Virtualization
    Technology (VT-x)*, save, exit).
- **Memory:** 4096 MB (6144 if you can spare it). **CPUs:** 2–4.
- **Create a virtual hard disk**, VDI, dynamically allocated, **30 GB**.
- Select the VM → **Settings → Storage** → click the empty optical drive → pick
  your Ubuntu `.iso` → OK.
- **Start** the VM and install Ubuntu (Minimal installation is fine; tick
  "Install third-party…" if asked). Create a username you'll remember.
- After install: **Devices → Insert Guest Additions CD** → run it → reboot (gives
  a bigger screen and shared clipboard). Optional but nice.

## 3. Get the project into the VM
Easiest: in the VM's Firefox, download the project `.zip` (the one Claude sent you),
then in a terminal:
```bash
cd ~/Downloads
unzip sdn-sentinel.zip -d ~
cd ~/sdn-sentinel
```
(Or enable a VirtualBox Shared Folder: **Settings → Shared Folders**, add your
Windows folder, then `sudo usermod -aG vboxsf $USER` and reboot.)

## 4. Install and run
```bash
sudo bash setup_vm.sh                            # one time, ~10-15 min
sudo mn --test pingall                           # sanity check: should say 0% dropped
RYU_BIN=~/ryu39/bin sudo -E bash run_all.sh      # the full campaign, ~15-25 min
```

Then open `out/summary.json` and the two `.png` files.

## Troubleshooting
- **`mn` errors / stuck network:** run `sudo mn -c` to clean up, then retry.
- **Controller won't bind 6633 / "address in use":** Ubuntu's test controller is
  squatting the port. `sudo systemctl disable --now openvswitch-testcontroller`
  and `sudo pkill -f ovs-testcontroller`, then retry.
- **`ryu-manager: command not found`:** it's in the venv. Use the full path
  `~/ryu39/bin/ryu-manager`, or prefix the campaign with `RYU_BIN=~/ryu39/bin`.
- **Ryu import error about `imp`/`distutils`:** you're on the wrong Python. Ryu
  must run from the `~/ryu39` (Python 3.9) venv; `setup_vm.sh` builds it.
- **pingall shows 100% dropped:** the controller isn't running or isn't on 6633 —
  start it first (or let `run_all.sh` manage it).
- **VM very slow:** give it more CPUs/RAM in Settings, and close Opera on Windows.

## If you run out of time
You can still demo without the full campaign:
```bash
# one terminal:
~/ryu39/bin/ryu-manager --ofp-tcp-listen-port 6633 controller/sentinel_controller.py
# another:
sudo python3 experiments/run_experiment.py --scenario chained --mode detect --gating on
```
The `chained` scenario shows ARP spoofing **and** a flood being blocked in one run —
the most impressive single thing to show live.
