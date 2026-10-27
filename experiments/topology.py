#!/usr/bin/env python3
"""
Mininet topology for the testbed: 3 edge switches in a line, all managed by the
remote Ryu controller, with IoT hosts and one server. Host-facing switch ports
start at 10 (sentinel_common.EDGE_PORT_MIN); inter-switch links use ports 1-2.

Run directly for a quick interactive check:
    sudo python3 experiments/topology.py
Normally it is imported by run_experiment.py.

Host plan (11 hosts):
    server  h100  10.0.0.100   s1 port 10
    benign  h10..h16 (7 IoT)   spread across s1/s2/s3
    extra   h17,h18 (2 IoT)    s3
    attack  h9                 s2 port 12   (the only malicious host)
"""

from mininet.topo import Topo

SERVER_IP = "10.0.0.100"
ATTACKER = "h9"
ATTACKER_IP = "10.0.0.9"


class SentinelTopo(Topo):
    def build(self):
        switches = [self.addSwitch(f"s{i}", protocols="OpenFlow13") for i in (1, 2, 3)]
        # inter-switch backbone on low port numbers
        self.addLink(switches[0], switches[1], port1=1, port2=1)
        self.addLink(switches[1], switches[2], port1=2, port2=1)

        def host(name, ip, sw, port):
            h = self.addHost(name, ip=f"{ip}/24", mac=_mac(ip))
            self.addLink(h, sw, port2=port)

        # server + benign IoT devices (edge ports 10, 11, 12, ...)
        host("h100", SERVER_IP, switches[0], 10)
        plan = [("h10", "10.0.0.10", 0, 11), ("h11", "10.0.0.11", 0, 12),
                ("h12", "10.0.0.12", 0, 13), ("h13", "10.0.0.13", 1, 10),
                ("h14", "10.0.0.14", 1, 11), ("h9", ATTACKER_IP, 1, 12),
                ("h15", "10.0.0.15", 2, 10), ("h16", "10.0.0.16", 2, 11),
                ("h17", "10.0.0.17", 2, 12), ("h18", "10.0.0.18", 2, 13)]
        for name, ip, sw, port in plan:
            host(name, ip, switches[sw], port)


def _mac(ip):
    last = int(ip.split(".")[-1])
    return "00:00:00:00:00:%02x" % last


topos = {"sentinel": SentinelTopo}

if __name__ == "__main__":
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    setLogLevel("info")
    net = Mininet(topo=SentinelTopo(), controller=None, switch=OVSSwitch)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    net.start()
    CLI(net)
    net.stop()
