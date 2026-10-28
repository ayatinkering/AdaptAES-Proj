"""Check that benchmark output follows the adaptive policy and rejects bad settings."""

import unittest

from benchmark_dataset_timings import benchmark_payload


class BenchmarkTests(unittest.TestCase):
    def test_all_modes(self):
        for size, rounds in ((16, 4), (129, 6), (513, 8), (1025, 10)):
            rows = benchmark_payload(bytes(size), size, repeats=2)
            self.assertEqual([r["rounds_used"] for r in rows], [10, 4, rounds])
            self.assertTrue(all(r["encryption_time_ns"] > 0 and r["decryption_time_ns"] > 0 for r in rows))

    def test_invalid_repeats(self):
        with self.assertRaises(ValueError):
            benchmark_payload(bytes(16), 16, repeats=0)


if __name__ == "__main__":
    unittest.main()
