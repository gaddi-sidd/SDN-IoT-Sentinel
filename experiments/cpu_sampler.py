#!/usr/bin/env python3
"""Sample a process's CPU% from /proc once a second until SIGINT. No psutil needed.

    python3 cpu_sampler.py <pid> <out.csv>
"""

import csv
import os
import signal
import sys
import time

CLK = os.sysconf("SC_CLK_TCK")
NCPU = os.cpu_count() or 1


def proc_ticks(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().split()
    return int(parts[13]) + int(parts[14])            # utime + stime


def main():
    pid, out = int(sys.argv[1]), sys.argv[2]
    running = {"v": True}
    signal.signal(signal.SIGINT, lambda *_: running.update(v=False))
    w = csv.writer(open(out, "w", newline=""))
    w.writerow(["ts", "cpu_pct"])                     # % of ONE core
    last_t, last_ticks = time.time(), proc_ticks(pid)
    while running["v"]:
        time.sleep(1.0)
        try:
            now, ticks = time.time(), proc_ticks(pid)
        except (FileNotFoundError, ProcessLookupError):
            break
        dt = now - last_t
        cpu = 100.0 * (ticks - last_ticks) / CLK / dt if dt > 0 else 0.0
        w.writerow([f"{now:.3f}", f"{cpu:.2f}"])
        last_t, last_ticks = now, ticks
    sys.stdout.flush()


if __name__ == "__main__":
    main()
