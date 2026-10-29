"""Experimental four-round AES with a keyed, reversible ARX middle step.

Research prototype only. Passing one attack is not a security guarantee.
"""
from aes_core import (expand_key, add_round_key, sub_bytes, shift_rows,
                      mix_columns, inv_sub_bytes, inv_shift_rows,
                      inv_mix_columns, pad_data, unpad_data)

MASK = 0xffffffff


def rol(x, n):
    return ((x << n) | (x >> (32-n))) & MASK


def ror(x, n):
    return ((x >> n) | (x << (32-n))) & MASK


def arx(state, key, undo=False):
    """Invertible 128-bit mixing with four independent 32-bit key words."""
    w = [int.from_bytes(bytes(state[i:i+4]), 'little') for i in range(0, 16, 4)]
    k = [int.from_bytes(key[i:i+4], 'little') for i in range(0, 16, 4)]
    if not undo:
        for _ in range(2):
            w[0] = (w[0] + w[1] + k[0]) & MASK
            w[3] ^= rol(w[0], 7)
            w[2] = (w[2] + w[3] + k[1]) & MASK
            w[1] ^= rol(w[2], 11)
            w[0] = (w[0] + w[1] + k[2]) & MASK
            w[3] ^= rol(w[0], 17)
            w[2] = (w[2] + w[3] + k[3]) & MASK
            w[1] ^= rol(w[2], 23)
    else:
        for _ in range(2):
            w[1] ^= rol(w[2], 23)
            w[2] = (w[2] - w[3] - k[3]) & MASK
            w[3] ^= rol(w[0], 17)
            w[0] = (w[0] - w[1] - k[2]) & MASK
            w[1] ^= rol(w[2], 11)
            w[2] = (w[2] - w[3] - k[1]) & MASK
            w[3] ^= rol(w[0], 7)
            w[0] = (w[0] - w[1] - k[0]) & MASK
    return list(b''.join(x.to_bytes(4, 'little') for x in w))


def encrypt_block(block, key):
    if len(block) != 16 or len(key) != 16:
        raise ValueError('block and key must each be 16 bytes')
    keys = expand_key(key)
    state = add_round_key(list(block), keys[0])
    for r in range(1, 4):
        state = add_round_key(mix_columns(shift_rows(sub_bytes(state))), keys[r])
        if r == 2:
            state = arx(state, key)
    return bytes(add_round_key(shift_rows(sub_bytes(state)), keys[4]))


def decrypt_block(block, key):
    if len(block) != 16 or len(key) != 16:
        raise ValueError('block and key must each be 16 bytes')
    keys = expand_key(key)
    state = inv_sub_bytes(inv_shift_rows(add_round_key(list(block), keys[4])))
    for r in range(3, 0, -1):
        if r == 2:
            state = arx(state, key, undo=True)
        state = inv_sub_bytes(inv_shift_rows(inv_mix_columns(add_round_key(state, keys[r]))))
    return bytes(add_round_key(state, keys[0]))


def encrypt(data, key):
    padded = pad_data(data)
    return b''.join(encrypt_block(padded[i:i+16], key) for i in range(0,len(padded),16))


def decrypt(data, key):
    if not data or len(data)%16:
        raise ValueError('invalid ciphertext length')
    return unpad_data(b''.join(decrypt_block(data[i:i+16], key) for i in range(0,len(data),16)))
