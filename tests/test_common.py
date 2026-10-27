"""Unit tests for the Ryu-free detection logic. Run: python3 -m unittest discover tests"""

import os
import sys
import unittest
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "controller"))

import sentinel_common as sc  # noqa: E402


class TestEntropy(unittest.TestCase):
    def test_values(self):
        self.assertEqual(sc.entropy(Counter()), 0.0)
        self.assertEqual(sc.entropy(Counter({"a": 5})), 0.0)
        self.assertAlmostEqual(sc.entropy(Counter({"a": 1, "b": 1})), 1.0)
        self.assertAlmostEqual(sc.entropy(Counter({i: 1 for i in range(8)})), 3.0)


class TestArpGuard(unittest.TestCase):
    A, B, EVIL = "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:66"

    def test_normal_exchange_is_clean(self):
        g = sc.ArpGuard()
        self.assertFalse(g.inspect("p1", 1, self.A, "10.0.0.1", "10.0.0.2", now=0).malicious)
        self.assertFalse(g.inspect("p2", 2, self.B, "10.0.0.2", "10.0.0.1", now=0.01).malicious)
        self.assertEqual(g.bindings["10.0.0.2"], self.B)

    def test_unsolicited_reply(self):
        g = sc.ArpGuard()
        v = g.inspect("px", 2, self.EVIL, "10.0.0.1", "10.0.0.2", now=0)
        self.assertTrue(v.malicious)
        self.assertEqual(v.reason, "unsolicited_reply")

    def test_rebinding_even_if_requested(self):
        g = sc.ArpGuard()
        g.inspect("p1", 1, self.A, "10.0.0.1", "10.0.0.2", now=0)
        g.inspect("p2", 2, self.B, "10.0.0.2", "10.0.0.1", now=0.01)
        g.inspect("p1", 1, self.A, "10.0.0.1", "10.0.0.2", now=1)
        v = g.inspect("px", 2, self.EVIL, "10.0.0.2", "10.0.0.1", now=1.01)
        self.assertTrue(v.malicious)
        self.assertEqual(v.reason, "ip_rebinding")

    def test_block_after_three_in_ten_seconds(self):
        g = sc.ArpGuard()
        r = [g.inspect("px", 2, self.EVIL, "10.0.0.1", "10.0.0.100", now=t).block
             for t in (0, 0.5, 1.0)]
        self.assertEqual(r, [False, False, True])

    def test_strikes_expire(self):
        g = sc.ArpGuard()
        r = [g.inspect("px", 2, self.EVIL, "10.0.0.1", "10.0.0.100", now=t).block
             for t in (0, 11, 22)]
        self.assertEqual(r, [False, False, False])

    def test_pending_expires(self):
        g = sc.ArpGuard()
        g.inspect("p1", 1, self.A, "10.0.0.1", "10.0.0.2", now=0)
        v = g.inspect("p2", 2, self.B, "10.0.0.2", "10.0.0.1", now=sc.ARP_PENDING_SECONDS + 1)
        self.assertEqual(v.reason, "unsolicited_reply")


class TestEntropyFilter(unittest.TestCase):
    def base(self, **kw):
        s = {"h_src_ip": 2.0, "h_dst_ip": 0.5, "h_dst_port": 1.5, "new_flows": 10, "edge_pps": 200}
        s.update(kw)
        return s

    def test_warmup_then_flag(self):
        f = sc.EntropyFilter(warmup=10)
        for i in range(10):
            flagged, _, why = f.observe(self.base(new_flows=10 + (i % 3), edge_pps=200 + i))
            self.assertFalse(flagged)
            self.assertEqual(why, "warmup")
        self.assertTrue(f.ready)
        self.assertFalse(f.observe(self.base())[0])
        flagged, z, k = f.observe(self.base(h_src_ip=9.0))
        self.assertTrue(flagged)
        self.assertEqual(k, "h_src_ip")
        self.assertTrue(f.observe(self.base(new_flows=400))[0])
        self.assertTrue(f.observe(self.base(edge_pps=5000))[0])

    def test_volume_drop_is_not_flagged(self):
        f = sc.EntropyFilter(warmup=5)
        for _ in range(5):
            f.observe(self.base(new_flows=50, edge_pps=1000))
        self.assertFalse(f.observe(self.base(new_flows=0, edge_pps=0))[0])


class TestFeatures(unittest.TestCase):
    def test_port_window(self):
        w = sc.PortWindow()
        for p in range(100):
            w.add_flow(6, f"1.2.3.{p}", "10.0.0.100", 80, bare_syn=True)
        f = w.features(rx_pkts=1000, rx_bytes=54000, seconds=1.0)
        self.assertEqual(list(f), sc.FEATURES)
        self.assertEqual(f["tcp_frac"], 1.0)
        self.assertEqual(f["uniq_src_ip"], 100)
        self.assertEqual(f["mean_pkt_size"], 54.0)
        self.assertEqual(f["dst_port_entropy"], 0.0)

    def test_empty(self):
        f = sc.PortWindow().features(0, 0, 1.0)
        self.assertTrue(all(v == 0 for v in f.values()))


class TestGate(unittest.TestCase):
    def test_two_of_three(self):
        g = sc.PortGate()
        self.assertFalse(g.update("p", True))
        self.assertFalse(g.update("p", False))
        self.assertTrue(g.update("p", True))
        self.assertFalse(g.update("p", True))   # history cleared after a block

    def test_edge_ports(self):
        self.assertFalse(sc.is_edge_port(1))
        self.assertTrue(sc.is_edge_port(10))
        self.assertFalse(sc.is_edge_port(0xFFFFFFFE))


if __name__ == "__main__":
    unittest.main()
