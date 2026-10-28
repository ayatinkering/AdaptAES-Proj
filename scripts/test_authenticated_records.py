"""Exercise real AES-GCM authentication, framing, and ordered record delivery."""

import unittest

from authenticated_records import HEADER, MAX_BODY, RecordCipher
from cryptography.exceptions import InvalidTag


class RecordTests(unittest.TestCase):
    def test_round_trip_and_nonce_uniqueness(self):
        cipher = RecordCipher()
        nonces = set()
        for flow in (0, 7, 0):
            messages = [b"a", bytes(128), bytes(range(256))]
            record = cipher.seal(flow, messages)
            nonces.add(HEADER.unpack_from(record)[2])
            self.assertEqual(cipher.open(record, flow), messages)
        self.assertEqual(len(nonces), 3)

    def test_tamper_rejected_without_consuming_record(self):
        cipher = RecordCipher()
        record = cipher.seal(3, [b"hello", b"world"])
        for position in (4, 8, HEADER.size, len(record) - 1):
            changed = bytearray(record)
            changed[position] ^= 1
            with self.assertRaises(InvalidTag):
                cipher.open(bytes(changed), 3)
        self.assertEqual(cipher.open(record, 3), [b"hello", b"world"])

    def test_wrong_session_flow_and_order(self):
        cipher = RecordCipher()
        first, second = cipher.seal(1, [b"first"]), cipher.seal(2, [b"second"])
        with self.assertRaises(InvalidTag):
            RecordCipher().open(first, 1)
        for record, flow in ((first, 2), (second, 2)):
            with self.assertRaises(ValueError):
                cipher.open(record, flow)
        self.assertEqual(cipher.open(first, 1), [b"first"])
        with self.assertRaises(ValueError):
            cipher.open(first, 1)
        self.assertEqual(cipher.open(second, 2), [b"second"])

    def test_record_bounds(self):
        cipher = RecordCipher()
        for messages in ([], [b""], [bytes(MAX_BODY)]):
            with self.assertRaises(ValueError):
                cipher.seal(0, messages)
        for record in (b"", bytes(HEADER.size + 16)):
            with self.assertRaises(ValueError):
                cipher.open(record, 0)
        record = cipher.seal(0, [bytes(MAX_BODY - 4)])
        self.assertEqual(cipher.open(record, 0), [bytes(MAX_BODY - 4)])


if __name__ == "__main__":
    unittest.main()
