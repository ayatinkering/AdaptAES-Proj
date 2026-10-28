"""Insecure reduced-round comparison; the current experiment uses authenticated_records."""

from aes_core import decrypt_block, decrypt_data, encrypt_block, encrypt_data

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
    rounds = select_rounds(len(data))
    return encrypt_data(data, key, rounds=rounds), rounds


def adaptaes_decrypt(ciphertext, key, payload_size):
    # The receiver uses the original payload size to select the same rounds.
    rounds = select_rounds(payload_size)
    return decrypt_data(ciphertext, key, rounds=rounds), rounds
