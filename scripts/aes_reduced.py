"""Insecure fixed four-round AES comparison for the historical experiment."""

from aes_core import decrypt_block, decrypt_data, encrypt_block, encrypt_data

REDUCED_ROUNDS = 4


# -----------------------------
# BLOCK ENCRYPTION
# -----------------------------

def reduced_aes_encrypt_block(block, key):
    return encrypt_block(
        block,
        key,
        rounds=REDUCED_ROUNDS
    )


# -----------------------------
# BLOCK DECRYPTION
# -----------------------------

def reduced_aes_decrypt_block(block, key):
    return decrypt_block(
        block,
        key,
        rounds=REDUCED_ROUNDS
    )


# -----------------------------
# ARBITRARY-LENGTH ENCRYPTION
# -----------------------------

def reduced_aes_encrypt(data, key):
    return encrypt_data(data, key, rounds=REDUCED_ROUNDS)


def reduced_aes_decrypt(ciphertext, key):
    return decrypt_data(ciphertext, key, rounds=REDUCED_ROUNDS)
