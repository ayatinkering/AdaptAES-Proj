import time

from aes_core import encrypt_block
from aes_adaptive import select_rounds


KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
)


def pad_data(data):
    """
    PKCS#7 padding.
    AES block size is 16 bytes.
    """

    block_size = 16

    padding_length = (
        block_size - (len(data) % block_size)
    )

    return data + bytes(
        [padding_length] * padding_length
    )


def encrypt_payload(payload, rounds):
    """
    Encrypt an arbitrary-size payload
    using the specified AES round count.
    """

    padded = pad_data(payload)

    ciphertext = bytearray()

    for i in range(0, len(padded), 16):

        block = padded[i:i + 16]

        encrypted = encrypt_block(
            block,
            KEY,
            rounds=rounds
        )

        ciphertext.extend(encrypted)

    return bytes(ciphertext)


def test_payload(size):

    payload = bytes([65]) * size

    print("\nPayload size:", size, "bytes")

    # Standard AES
    start = time.perf_counter()

    standard_ciphertext = encrypt_payload(
        payload,
        rounds=10
    )

    standard_time = (
        time.perf_counter() - start
    )

    # Reduced AES
    start = time.perf_counter()

    reduced_ciphertext = encrypt_payload(
        payload,
        rounds=4
    )

    reduced_time = (
        time.perf_counter() - start
    )

    # AdaptAES
    adaptive_rounds = select_rounds(
        len(payload)
    )

    start = time.perf_counter()

    adaptive_ciphertext = encrypt_payload(
        payload,
        rounds=adaptive_rounds
    )

    adaptive_time = (
        time.perf_counter() - start
    )

    print(
        "Standard AES :",
        standard_time,
        "seconds"
    )

    print(
        "Reduced AES  :",
        reduced_time,
        "seconds"
    )

    print(
        "AdaptAES     :",
        adaptive_time,
        "seconds",
        "| Rounds:",
        adaptive_rounds
    )


if __name__ == "__main__":

    test_sizes = [
        32,
        64,
        128,
        129,
        256,
        512,
        513,
        1024,
        1025,
        2048
    ]

    for size in test_sizes:
        test_payload(size)