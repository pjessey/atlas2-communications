"""
XTEA cipher (16 rounds) and Atlas 2 encryption-key derivation.

All integers are treated as unsigned 32-bit values (little-endian).
"""

import struct
from typing import Sequence

DELTA: int = 0x9E3779B9
ROUNDS: int = 16
MASK32: int = 0xFFFFFFFF

# Product-specific seed codes (3 bytes each)
PRODUCT_CODES: dict[str, list[int]] = {
    "atlas":   [0x4E, 0x75, 0x7E],
    "atlas2":  [0xAA, 0x69, 0x44],
    "juno":    [0x8D, 0xAF, 0x11],
}


def build_key(info: bytes, product: str = "atlas2") -> list[int]:
    """Derive the 16-byte XTEA key from the Info (Type Zero) message.

    Parameters
    ----------
    info:    Raw 32-byte Info message bytes.
    product: Device type key – one of "atlas", "atlas2", "juno".

    Returns
    -------
    A list of 16 unsigned bytes that form the XTEA key.
    """
    codes = PRODUCT_CODES[product.lower()]

    key_bytes = [
        codes[0],       # pos  0
        info[23],       # pos  1  Total Jump Seconds[0]
        info[6],        # pos  2  Serial Number[1]
        info[13],       # pos  3  Serial Number[8]
        info[24],       # pos  4  Total Jump Seconds[1]
        info[22],       # pos  5  Total Jumps[1]
        info[12],       # pos  6  Serial Number[7]
        codes[1],       # pos  7
        info[7],        # pos  8  SerialNum[2]
        info[8],        # pos  9  SerialNum[3]
        info[10],       # pos 10  SerialNum[5]
        codes[2],       # pos 11
        info[9],        # pos 12  Serial Number[4]
        info[11],       # pos 13  Serial Number[6]
        info[26],       # pos 14  Total Jump Seconds[3]
        info[25],       # pos 15  Total Jump Seconds[2]
    ]
    return key_bytes


def _key_to_words(key_bytes: Sequence[int]) -> list[int]:
    """Pack 16 key bytes into 4 uint32 words (little-endian)."""
    return list(struct.unpack("<4I", bytes(key_bytes)))


def xtea_encode_block(v0: int, v1: int, key_words: list[int]) -> tuple[int, int]:
    """Encrypt a single 8-byte block (two uint32 values) with XTEA."""
    y, z = v0 & MASK32, v1 & MASK32
    total = 0
    for _ in range(ROUNDS):
        y = (y + ((((z << 4) ^ (z >> 5)) + z) ^ (key_words[total & 3] + total))) & MASK32
        total = (total + DELTA) & MASK32
        z = (z + ((((y << 4) ^ (y >> 5)) + y) ^ (key_words[(total >> 11) & 3] + total))) & MASK32
    return y, z


def xtea_decode_block(v0: int, v1: int, key_words: list[int]) -> tuple[int, int]:
    """Decrypt a single 8-byte block (two uint32 values) with XTEA."""
    y, z = v0 & MASK32, v1 & MASK32
    total = (DELTA * ROUNDS) & MASK32
    for _ in range(ROUNDS):
        z = (z - ((((y << 4) ^ (y >> 5)) + y) ^ (key_words[(total >> 11) & 3] + total))) & MASK32
        total = (total - DELTA) & MASK32
        y = (y - ((((z << 4) ^ (z >> 5)) + z) ^ (key_words[total & 3] + total))) & MASK32
    return y, z


def encrypt(data: bytes, key_bytes: Sequence[int]) -> bytes:
    """Encrypt *data* (must be a multiple of 8 bytes) with XTEA.

    Pads *data* with zeros to the nearest multiple of 8 if necessary.
    """
    key_words = _key_to_words(key_bytes)
    # Pad to multiple of 8
    if len(data) % 8:
        data = data + b"\x00" * (8 - len(data) % 8)
    out = bytearray()
    for i in range(0, len(data), 8):
        v0, v1 = struct.unpack_from("<II", data, i)
        e0, e1 = xtea_encode_block(v0, v1, key_words)
        out += struct.pack("<II", e0, e1)
    return bytes(out)


def decrypt(data: bytes, key_bytes: Sequence[int]) -> bytes:
    """Decrypt *data* (must be a multiple of 8 bytes) with XTEA."""
    key_words = _key_to_words(key_bytes)
    if len(data) % 8:
        raise ValueError("Encrypted data length must be a multiple of 8 bytes.")
    out = bytearray()
    for i in range(0, len(data), 8):
        v0, v1 = struct.unpack_from("<II", data, i)
        d0, d1 = xtea_decode_block(v0, v1, key_words)
        out += struct.pack("<II", d0, d1)
    return bytes(out)
