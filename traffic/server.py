#!/usr/bin/env python3
"""A tiny sink: accepts UDP datagrams and TCP connections so SYNs complete. """

import argparse
import socket
import threading


def udp_sink(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    while True:
        try:
            s.recvfrom(2048)
        except OSError:
            break


def tcp_sink(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(128)
    while True:
        try:
            c, _ = s.accept()
            c.close()
        except OSError:
            break


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--udp", type=int, default=9000)
    ap.add_argument("--tcp", type=int, default=8000)
    a = ap.parse_args()
    threading.Thread(target=udp_sink, args=(a.udp,), daemon=True).start()
    tcp_sink(a.tcp)
