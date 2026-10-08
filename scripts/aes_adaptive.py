# adaptaes.py
# AdaptAES: packet-payload-size based AES round selection

from aes_core import encrypt_block


def select_rounds(payload_size):
    """
    Select AES round count based on payload size.

    1 - 128 bytes       -> 4 rounds
    129 - 512 bytes     -> 6 rounds
    513 - 1024 bytes    -> 8 rounds
    > 1024 bytes        -> 10 rounds
    """

    if payload_size >= 1 and payload_size <= 128:
        return 4

    elif payload_size >= 129 and payload_size <= 512:
        return 6

    elif payload_size >= 513 and payload_size <= 1024:
        return 8

    elif payload_size > 1024:
        return 10

    else:
        raise ValueError("Payload size must be greater than 0.")


def pad_data(data):
    """
    PKCS#7 padding.

    AES block size = 16 bytes.
    """

    block_size = 16

    padding_length = (
        block_size - (len(data) % block_size)
    )

    padding = bytes(
        [padding_length] * padding_length
    )

    return data + padding


def unpad_data(data):
    """
    Remove PKCS#7 padding.
    """

    if len(data) == 0:
        raise ValueError("Cannot unpad empty data.")

    padding_length = data[-1]

    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding.")

    if data[-padding_length:] != bytes(
        [padding_length] * padding_length
    ):
        raise ValueError("Invalid padding.")

    return data[:-padding_length]


def adaptaes_encrypt(payload, key):
    """
    Encrypt an arbitrary-length payload using AdaptAES.

    The number of AES rounds is selected
    from the ORIGINAL payload size.
    """

    if len(key) != 16:
        raise ValueError(
            "AES-128 key must be exactly 16 bytes."
        )

    if len(payload) == 0:
        raise ValueError(
            "Payload cannot be empty."
        )

    # IMPORTANT:
    # Round selection uses the original payload size,
    # not the padded size.

    original_size = len(payload)

    rounds = select_rounds(original_size)

    # Pad payload to AES block size
    padded_payload = pad_data(payload)

    ciphertext = bytearray()

    # Encrypt each 16-byte block
    for i in range(
        0,
        len(padded_payload),
        16
    ):

        block = padded_payload[i:i + 16]

        encrypted_block = encrypt_block(
            block,
            key,
            rounds=rounds
        )

        ciphertext.extend(encrypted_block)

    return bytes(ciphertext), rounds


def adaptaes_decrypt(ciphertext, key, rounds):
    """
    Decrypt an AdaptAES ciphertext.

    The round count used during encryption
    must be supplied for decryption.
    """

    # NOTE:
    # This requires an inverse AES implementation.
    # It will be added when we implement the
    # decryption side.
    
    raise NotImplementedError(
        "Decryption will be implemented with "
        "the inverse AES operations."
    )


if __name__ == "__main__":

    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    )

    test_sizes = [
        1,
        16,
        64,
        128,
        129,
        256,
        512,
        513,
        768,
        1024,
        1025,
        2048
    ]

    print("AdaptAES Round Selection")
    print("========================")

    for size in test_sizes:

        rounds = select_rounds(size)

        print(
            f"{size:4d} bytes -> {rounds:2d} rounds"
        )