"""Regression checks for the actual scripts-based research implementation."""

from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import aes_core
import aes_hybrid
from aes_adaptive import adaptaes_encrypt
from aes_adaptive_arx import adaptaes_arx_encrypt, adaptaes_arx_decrypt


class AdaptiveARXTests(unittest.TestCase):
    def test_inverse_operations(self):
        rng = random.Random(42)
        for _ in range(100):
            block, key = rng.randbytes(16), rng.randbytes(16)
            self.assertEqual(aes_hybrid.decrypt_block(aes_hybrid.encrypt_block(block, key), key), block)
            self.assertEqual(aes_hybrid.arx(aes_hybrid.arx(list(block), key), key, undo=True), list(block))

    def test_policy_and_original_branches(self):
        key = bytes(range(16))
        for size, expected in ((1, 4), (15, 4), (16, 4), (17, 4), (127, 4), (128, 4),
                               (129, 6), (511, 6), (512, 6), (513, 8), (1024, 8), (1025, 10)):
            payload = random.Random(size).randbytes(size)
            ct, rounds = adaptaes_arx_encrypt(payload, key)
            self.assertEqual(rounds, expected)
            self.assertEqual(adaptaes_arx_decrypt(ct, key, size), (payload, expected))
            if expected == 4:
                self.assertEqual(ct, aes_hybrid.encrypt(payload, key))
            else:
                self.assertEqual((ct, rounds), adaptaes_encrypt(payload, key))

    def test_standard_vector_unchanged(self):
        self.assertEqual(aes_core.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"),
                                               bytes(range(16))).hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            adaptaes_arx_encrypt(b"", bytes(16))
        with self.assertRaises(ValueError):
            adaptaes_arx_encrypt(b"x", b"short")
        ct, _ = adaptaes_arx_encrypt(b"hello", bytes(16))
        with self.assertRaises(ValueError):
            adaptaes_arx_decrypt(ct, bytes(16), 6)
        with self.assertRaises(ValueError):
            adaptaes_arx_decrypt(ct[:-1], bytes(16), 5)
