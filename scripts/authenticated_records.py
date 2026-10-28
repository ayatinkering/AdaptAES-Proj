"""Authenticated records for an ordered, in-memory college experiment."""

import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER = struct.Struct(">4sI12s")  # Version, directional flow ID, record sequence/nonce.
LENGTH = struct.Struct(">I")
MAX_BODY = 65536


class RecordCipher:
    """Own one fresh AES-128 key and ordered send/receive counters per trial.

    Keys cannot be supplied or reused across instances. This is an in-memory
    record experiment, not a key-exchange or session-persistence protocol.
    """

    def __init__(self):
        self._aes = AESGCM(AESGCM.generate_key(bit_length=128))
        self._sent = 0
        self._received = 0

    def seal(self, flow, messages):
        if not messages or any(not message for message in messages):
            raise ValueError("A record needs nonempty messages.")
        if sum(LENGTH.size + len(message) for message in messages) > MAX_BODY:
            raise ValueError("Record body exceeds 64 KiB.")
        if not 0 <= flow < 2**32 or self._sent >= 2**96:
            raise ValueError("Flow ID or nonce counter exhausted.")
        body = b"".join(LENGTH.pack(len(message)) + message for message in messages)
        nonce = self._sent.to_bytes(12, "big")
        self._sent += 1
        header = HEADER.pack(b"AA01", flow, nonce)
        return header + self._aes.encrypt(nonce, body, header)

    def open(self, record, expected_flow):
        if not HEADER.size + 16 < len(record) <= HEADER.size + MAX_BODY + 16:
            raise ValueError("Invalid record length.")
        magic, flow, nonce = HEADER.unpack_from(record)
        if magic != b"AA01":
            raise ValueError("Unknown record version.")
        # Verify authentication before interpreting or returning any plaintext.
        body = self._aes.decrypt(nonce, record[HEADER.size:], record[:HEADER.size])
        if flow != expected_flow or int.from_bytes(nonce, "big") != self._received:
            raise ValueError("Wrong flow, replayed, missing, or reordered record.")
        messages, offset = [], 0
        while offset < len(body):
            if len(body) - offset < LENGTH.size:
                raise ValueError("Truncated message length.")
            size = LENGTH.unpack_from(body, offset)[0]
            offset += LENGTH.size
            if not 0 < size <= len(body) - offset:
                raise ValueError("Invalid message length.")
            messages.append(body[offset:offset + size])
            offset += size
        if not messages:
            raise ValueError("Empty record.")
        self._received += 1
        return messages
