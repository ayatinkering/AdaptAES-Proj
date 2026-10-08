# reduced_aes.py
# Experimental fixed 4-round AES variant.

from aes_core import encrypt_block


REDUCED_ROUNDS = 4


def reduced_aes_encrypt(block, key):
    """
    Encrypt one 16-byte block using
    the experimental 4-round AES construction.
    """

    return encrypt_block(
        block,
        key,
        rounds=REDUCED_ROUNDS
    )


if __name__ == "__main__":

    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    )

    plaintext = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    ciphertext = reduced_aes_encrypt(
        plaintext,
        key
    )

    print("Fixed Reduced-Round AES")
    print("-----------------------")
    print("Rounds    :", REDUCED_ROUNDS)
    print("Plaintext :", plaintext.hex())
    print("Key       :", key.hex())
    print("Ciphertext:", ciphertext.hex())