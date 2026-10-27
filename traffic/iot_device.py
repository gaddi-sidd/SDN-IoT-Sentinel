#!/usr/bin/env python3
"""
A benign IoT device: periodic small telemetry to the server, with a little jitter,
occasional idle gaps, and rare short bursts. Deliberately NOT perfectly regular,
so the entropy baseline learns realistic benign traffic (the Corpus-A lesson:
benign devices must also go quiet sometimes).

    python3 iot_device.py --server 10.0.0.100 --port 9000 --proto udp --seed 7 --duration 120
"""

import argparse
import random
import socket
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--proto", choices=["udp", "tcp"], default="udp")
    ap.add_argument("--period", type=float, default=1.0, help="mean seconds between messages")
    ap.add_argument("--jitter", type=float, default=0.4)
    ap.add_argument("--size", type=int, default=64)
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    rnd = random.Random(a.seed)
    end = time.time() + a.duration
    while time.time() < end:
        # occasional idle gap (device asleep) and occasional small burst
        roll = rnd.random()
        if roll < 0.05:
            time.sleep(rnd.uniform(3, 8))
            continue
        burst = 1 if roll > 0.97 else 0
        for _ in range(1 + burst * rnd.randint(2, 5)):
            payload = bytes(rnd.getrandbits(8) for _ in range(a.size))
            try:
                if a.proto == "udp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(payload, (a.server, a.port))
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    s.connect((a.server, a.port))
                    s.sendall(payload)
                s.close()
            except OSError:
                pass
        time.sleep(max(0.05, rnd.gauss(a.period, a.jitter)))


if __name__ == "__main__":
    main()
