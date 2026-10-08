# aes_reduced.py

from aes_core import (
    encrypt_block,
    decrypt_block,
    pad_data,
    unpad_data
)


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

    padded_data = pad_data(data)

    ciphertext = bytearray()

    for i in range(0, len(padded_data), 16):

        block = padded_data[i:i + 16]

        encrypted_block = reduced_aes_encrypt_block(
            block,
            key
        )

        ciphertext.extend(encrypted_block)

    return bytes(ciphertext)


# -----------------------------
# ARBITRARY-LENGTH DECRYPTION
# -----------------------------

def reduced_aes_decrypt(ciphertext, key):

    if len(ciphertext) % 16 != 0:
        raise ValueError(
            "Ciphertext length must be a multiple of 16."
        )

    plaintext = bytearray()

    for i in range(0, len(ciphertext), 16):

        block = ciphertext[i:i + 16]

        decrypted_block = reduced_aes_decrypt_block(
            block,
            key
        )

        plaintext.extend(decrypted_block)

    return unpad_data(bytes(plaintext))

