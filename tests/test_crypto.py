"""Tests for atlas2.crypto – XTEA and key derivation."""

import struct
import pytest
from atlas2.crypto import (
    build_key,
    encrypt,
    decrypt,
    xtea_encode_block,
    xtea_decode_block,
    _key_to_words,
    PRODUCT_CODES,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_info(serial: str = "200221245", total_jumps: int = 42, total_seconds: int = 12345) -> bytes:
    """Build a minimal 32-byte fake Info message."""
    data = bytearray(32)
    data[0] = 0x1E
    data[1] = 0x00
    # serial number bytes at positions 5-13
    for i, ch in enumerate(serial[:9]):
        data[5 + i] = ord(ch)
    data[21] = total_jumps & 0xFF
    data[22] = (total_jumps >> 8) & 0xFF
    data[23] = total_seconds & 0xFF
    data[24] = (total_seconds >> 8) & 0xFF
    data[25] = (total_seconds >> 16) & 0xFF
    data[26] = (total_seconds >> 24) & 0xFF
    return bytes(data)


# ---------------------------------------------------------------------------
# build_key
# ---------------------------------------------------------------------------

class TestBuildKey:
    def test_length(self):
        info = _make_info()
        key = build_key(info, "atlas2")
        assert len(key) == 16

    def test_product_code_embedded(self):
        info = _make_info()
        for product, codes in PRODUCT_CODES.items():
            key = build_key(info, product)
            assert key[0] == codes[0]
            assert key[7] == codes[1]
            assert key[11] == codes[2]

    def test_serial_bytes_in_key(self):
        serial = "200221245"
        info = _make_info(serial=serial)
        key = build_key(info, "atlas2")
        # pos 2 = info[6] = serial[1] = '0' = 0x30
        assert key[2] == ord(serial[1])
        # pos 8 = info[7] = serial[2]
        assert key[8] == ord(serial[2])

    def test_unknown_product_raises(self):
        info = _make_info()
        with pytest.raises(KeyError):
            build_key(info, "unknown_product")


# ---------------------------------------------------------------------------
# XTEA block cipher
# ---------------------------------------------------------------------------

class TestXteaBlock:
    def _kw(self, key_bytes=None):
        if key_bytes is None:
            key_bytes = list(range(16))
        return _key_to_words(key_bytes)

    def test_encode_decode_roundtrip(self):
        kw = self._kw()
        for v0, v1 in [(0, 0), (0xDEADBEEF, 0xCAFEBABE), (1, 1), (0xFFFFFFFF, 0xFFFFFFFF)]:
            e0, e1 = xtea_encode_block(v0, v1, kw)
            d0, d1 = xtea_decode_block(e0, e1, kw)
            assert (d0, d1) == (v0, v1), f"Roundtrip failed for ({v0:#010x}, {v1:#010x})"

    def test_encode_is_not_identity(self):
        kw = self._kw()
        v0, v1 = 0x12345678, 0x9ABCDEF0
        e0, e1 = xtea_encode_block(v0, v1, kw)
        assert (e0, e1) != (v0, v1)

    def test_different_keys_produce_different_ciphertext(self):
        kw1 = _key_to_words(list(range(16)))
        kw2 = _key_to_words(list(range(1, 17)))
        v0, v1 = 0xAABBCCDD, 0x11223344
        assert xtea_encode_block(v0, v1, kw1) != xtea_encode_block(v0, v1, kw2)


# ---------------------------------------------------------------------------
# encrypt / decrypt (byte-level)
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    KEY = list(range(16))

    def test_roundtrip_8_bytes(self):
        plain = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        assert decrypt(encrypt(plain, self.KEY), self.KEY)[:8] == plain

    def test_roundtrip_32_bytes(self):
        plain = bytes(range(32))
        assert decrypt(encrypt(plain, self.KEY), self.KEY) == plain

    def test_auto_pad_to_8(self):
        plain = b"\xAA\xBB\xCC"
        cipher = encrypt(plain, self.KEY)
        assert len(cipher) == 8
        result = decrypt(cipher, self.KEY)
        assert result[:3] == plain

    def test_decrypt_non_multiple_of_8_raises(self):
        with pytest.raises(ValueError):
            decrypt(b"\x00" * 7, self.KEY)

    def test_encrypt_decrypt_with_real_key(self):
        info = _make_info()
        key = build_key(info, "atlas2")
        plain = bytes(range(32))
        assert decrypt(encrypt(plain, key), key) == plain
