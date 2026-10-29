# aes_adaptive.py

from aes_core import (
    encrypt_block,
    decrypt_block,
    pad_data,
    unpad_data
)


# -----------------------------
# ADAPTIVE ROUND SELECTION
# -----------------------------

def select_rounds(payload_size):

    if payload_size <= 0:
        raise ValueError(
            "Payload size must be greater than 0."
        )

    if payload_size <= 128:
        return 4

    elif payload_size <= 512:
        return 6

    elif payload_size <= 1024:
        return 8

    else:
        return 10


# -----------------------------
# BLOCK ENCRYPTION
# -----------------------------

def adaptaes_encrypt_block(block, key, rounds):

    return encrypt_block(
        block,
        key,
        rounds=rounds
    )


# -----------------------------
# BLOCK DECRYPTION
# -----------------------------

def adaptaes_decrypt_block(block, key, rounds):

    return decrypt_block(
        block,
        key,
        rounds=rounds
    )


# -----------------------------
# ARBITRARY-LENGTH ENCRYPTION
# -----------------------------

def adaptaes_encrypt(data, key):

    # Original payload size is used
    # to select the number of rounds.

    payload_size = len(data)

    rounds = select_rounds(payload_size)

    padded_data = pad_data(data)

    ciphertext = bytearray()

    for i in range(0, len(padded_data), 16):

        block = padded_data[i:i + 16]

        encrypted_block = adaptaes_encrypt_block(
            block,
            key,
            rounds
        )

        ciphertext.extend(encrypted_block)

    return bytes(ciphertext), rounds


# -----------------------------
# ARBITRARY-LENGTH DECRYPTION
# -----------------------------

def adaptaes_decrypt(ciphertext, key, payload_size):

    if len(ciphertext) % 16 != 0:
        raise ValueError(
            "Ciphertext length must be a multiple of 16."
        )

    # The receiver needs the original payload size
    # to determine which round count was used.

    rounds = select_rounds(payload_size)

    plaintext = bytearray()

    for i in range(0, len(ciphertext), 16):

        block = ciphertext[i:i + 16]

        decrypted_block = adaptaes_decrypt_block(
            block,
            key,
            rounds
        )

        plaintext.extend(decrypted_block)

    plaintext = unpad_data(bytes(plaintext))

    return plaintext, rounds


