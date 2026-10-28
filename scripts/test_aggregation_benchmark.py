"""Verify trace fidelity and analytic record-overhead accounting."""

import csv
import tempfile
import unittest
from pathlib import Path

from benchmark_aggregation import benchmark, controlled_trace, load_trace


class ReplayTests(unittest.TestCase):
    def test_trace_order_flow_identity_and_seed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "trace.csv"
            fields = ["packet_index", "timestamp_seconds", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "payload_length"]
            with path.open("w", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(fields)
                for i, timestamp, source in ((1, "1617031672.000000002", "A"),
                                             (2, "1617031672.000000001", "B"),
                                             (3, "1617031672.000000003", "A")):
                    writer.writerow([i, timestamp, "TCP", source, 1, "C", 2, 16])
            packets = load_trace(path, 3)
            self.assertEqual([p.timestamp_ns for p in packets], [0, 1, 2])
            self.assertEqual(packets[1].flow, packets[2].flow)
            self.assertNotEqual(packets[0].flow, packets[1].flow)
            self.assertEqual(packets, load_trace(path, 3))
            self.assertNotEqual(packets[0].payload, load_trace(path, 3, seed=43)[0].payload)
            self.assertEqual(len(load_trace(path, 2)), 2)

    def test_controlled_workload_accounting(self):
        policy = {"max_delay_ns": 1_000_000, "max_packets": 8, "max_bytes": 16384, "small_bytes": 512}
        rows = benchmark(controlled_trace(True, count=16), policy, repeats=1)
        self.assertEqual([row["record_count"] for row in rows], [16, 2, 2])
        self.assertEqual([row["overhead_bytes"] for row in rows], [16 * 40, 16 * 4 + 2 * 36, 16 * 4 + 2 * 36])
        self.assertTrue(all(row["queue_max_us"] <= 1000 for row in rows))
        self.assertTrue(all(row["processing_cpu_ns"] > 0 for row in rows))


if __name__ == "__main__":
    unittest.main()
