"""Correctness checks for the educational AES implementation. Run with unittest."""

import random
import unittest

from aes_adaptive import adaptaes_decrypt, adaptaes_encrypt, select_rounds
from aes_core import (
    decrypt_block,
    decrypt_data,
    encrypt_block,
    encrypt_data,
    unpad_data,
)
from aes_reduced import reduced_aes_decrypt, reduced_aes_encrypt


class AESTests(unittest.TestCase):
    def test_reduced_round_outputs_unchanged(self):
        # Regression values from the original educational implementation.
        expected = {4: "6a9a894caa06dd37f05a3061a6fe9f3a",
                    6: "b6e3b9ede3d146f398a2c823ede4c224",
                    8: "795fa5f512e0dacf6dbeea9358a87e47"}
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        for rounds, ciphertext in expected.items():
            self.assertEqual(encrypt_block(block, bytes(range(16)), rounds).hex(), ciphertext)

    def test_known_answers(self):
        vectors = (
            ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
             "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("00" * 16, "00" * 16, "66e94bd4ef8a2c3b884cfa59ca342b2e"),
        )
        for key, plaintext, ciphertext in vectors:
            key, plaintext, ciphertext = map(bytes.fromhex, (key, plaintext, ciphertext))
            self.assertEqual(encrypt_block(plaintext, key), ciphertext)
            self.assertEqual(decrypt_block(ciphertext, key), plaintext)

    def test_block_round_trips(self):
        rng = random.Random(42)
        for rounds in (4, 6, 8, 10):
            for _ in range(10):
                key, block = rng.randbytes(16), rng.randbytes(16)
                self.assertEqual(decrypt_block(encrypt_block(block, key, rounds), key, rounds), block)

    def test_payload_boundaries(self):
        key = bytes(range(16))
        for size in (1, 15, 16, 17, 127, 128, 129, 511, 512, 513, 1023, 1024, 1025):
            with self.subTest(size=size):
                payload = random.Random(size).randbytes(size)
                self.assertEqual(decrypt_data(encrypt_data(payload, key), key), payload)
                self.assertEqual(reduced_aes_decrypt(reduced_aes_encrypt(payload, key), key), payload)
                ciphertext, rounds = adaptaes_encrypt(payload, key)
                plaintext, decoded_rounds = adaptaes_decrypt(ciphertext, key, size)
                self.assertEqual((plaintext, decoded_rounds), (payload, rounds))

    def test_policy(self):
        for size, rounds in ((1, 4), (128, 4), (129, 6), (512, 6), (513, 8), (1024, 8), (1025, 10)):
            self.assertEqual(select_rounds(size), rounds)
        with self.assertRaises(ValueError):
            select_rounds(0)

    def test_invalid_inputs(self):
        key = bytes(16)
        for block, block_key, rounds in ((b"", key, 10), (key, b"", 10), (key, key, 0), (key, key, 11)):
            with self.assertRaises(ValueError):
                encrypt_block(block, block_key, rounds)
        for padded in (b"", b"abc\x00", b"abc\x02", bytes([17]) * 17):
            with self.assertRaises(ValueError):
                unpad_data(padded)
        with self.assertRaises(ValueError):
            decrypt_data(b"short", key)


if __name__ == "__main__":
    unittest.main()
