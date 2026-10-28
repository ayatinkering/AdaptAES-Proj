"""Check dataset coverage in the quick statistical analysis."""

import unittest

from security_performance_analysis import summarize


class AnalysisTests(unittest.TestCase):
    def test_limit_applies_to_each_dataset(self):
        rows = [{"dataset_name": name, "payload_id": i, "payload_length": 16, "payload": bytes(16)}
                for name in ("A", "B") for i in (1, 2)]
        _, _, security = summarize(rows, {}, 1)
        self.assertEqual(len(security), 6)
        self.assertEqual({row["dataset_name"] for row in security}, {"A", "B"})


if __name__ == "__main__":
    unittest.main()
