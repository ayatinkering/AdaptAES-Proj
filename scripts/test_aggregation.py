"""Check policy deadlines, flow isolation, and preservation of every message."""

import random
import unittest
from collections import defaultdict

from aggregate_records import MODES, Packet, aggregate


class AggregationTests(unittest.TestCase):
    def test_exact_deadline_and_trace_end(self):
        packets = [Packet(t, 1, b"x", i) for i, t in enumerate((0, 1000))]
        batches = aggregate(packets, "fixed", max_delay_ns=1000)
        self.assertEqual([b.released_ns for b in batches], [1000, 2000])
        self.assertEqual([len(b.packets) for b in batches], [1, 1])

    def test_adaptive_burst_and_large_message_bypass(self):
        packets = [Packet(i * 10, 1, b"x", i) for i in range(4)]
        packets.append(Packet(50, 1, bytes(1024), 4))
        batches = aggregate(packets, "adaptive", max_delay_ns=1000, max_packets=8)
        self.assertEqual([len(b.packets) for b in batches], [4, 1])
        self.assertEqual([b.released_ns for b in batches], [50, 50])

    def test_sparse_messages_bypass_after_first_deadline(self):
        packets = [Packet(i * 2000, 1, b"x", i) for i in range(3)]
        batches = aggregate(packets, "adaptive", max_delay_ns=1000)
        self.assertEqual([b.released_ns for b in batches], [1000, 2000, 4000])

    def test_bytes_bound_and_oversized_singleton(self):
        packets = [Packet(i, 1, bytes(size), i) for i, size in enumerate((8, 8, 100))]
        batches = aggregate(packets, "fixed", max_bytes=20)
        self.assertEqual([len(b.packets) for b in batches], [1, 1, 1])
        self.assertEqual(batches[-1].released_ns, 2)

    def test_randomized_conservation_isolation_and_bounds(self):
        rng, now, packets = random.Random(42), 0, []
        for i in range(200):
            now += rng.randrange(30)
            packets.append(Packet(now, rng.randrange(5), rng.randbytes(rng.randrange(1, 800)), i))
        original = defaultdict(list)
        for packet in packets:
            original[packet.flow].append(packet.packet_id)
        for mode in MODES:
            recovered = defaultdict(list)
            batches = aggregate(packets, mode, max_delay_ns=100, max_packets=4, max_bytes=1024)
            for batch in batches:
                self.assertLessEqual(len(batch.packets), 4)
                self.assertTrue(len(batch.packets) == 1 or sum(len(p.payload) + 4 for p in batch.packets) <= 1024)
                for packet in batch.packets:
                    self.assertEqual(packet.flow, batch.flow)
                    self.assertTrue(0 <= batch.released_ns - packet.timestamp_ns <= 100)
                    recovered[packet.flow].append(packet.packet_id)
                    if mode == "immediate":
                        self.assertEqual(batch.released_ns, packet.timestamp_ns)
            self.assertEqual(dict(recovered), dict(original))

    def test_invalid_inputs(self):
        for kwargs in ({"mode": "unknown"}, {"mode": "fixed", "max_packets": 0},
                       {"mode": "fixed", "max_bytes": 65537}):
            with self.assertRaises(ValueError):
                aggregate([], **kwargs)
        for packets in ([Packet(2, 0, b"a", 0), Packet(1, 0, b"a", 1)],
                        [Packet(0, 0, b"", 0)]):
            with self.assertRaises(ValueError):
                aggregate(packets, "fixed")


if __name__ == "__main__":
    unittest.main()
