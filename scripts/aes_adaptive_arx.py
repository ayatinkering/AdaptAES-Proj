"""Experimental AdaptAES: harden only the four-round branch with AES–ARX.

This custom cipher is not authenticated encryption or validated AES security.
Original payload length is required out of band, as in the original AdaptAES.
"""

from aes_adaptive import adaptaes_decrypt, adaptaes_encrypt, select_rounds
import aes_hybrid


def adaptaes_arx_encrypt(data, key):
    rounds = select_rounds(len(data))
    if rounds == 4:
        return aes_hybrid.encrypt(data, key), rounds
    return adaptaes_encrypt(data, key)


def adaptaes_arx_decrypt(ciphertext, key, payload_size):
    rounds = select_rounds(payload_size)
    if rounds == 4:
        plaintext = aes_hybrid.decrypt(ciphertext, key)
    else:
        plaintext, _ = adaptaes_decrypt(ciphertext, key, payload_size)
    if len(plaintext) != payload_size:
        raise ValueError("Recovered length differs from original payload size")
    return plaintext, rounds
