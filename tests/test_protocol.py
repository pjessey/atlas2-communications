"""Tests for atlas2.protocol – packet building/parsing and date/time."""

import struct
import datetime
import pytest
from atlas2.protocol import (
    PACKET_SIZE,
    checksum,
    parse_info_message,
    build_packet,
    verify_packet,
    encode_datetime,
    decode_datetime,
)


# ---------------------------------------------------------------------------
# checksum
# ---------------------------------------------------------------------------

class TestChecksum:
    def test_zeros(self):
        assert checksum([0, 0, 0]) == 0

    def test_wraps_at_256(self):
        assert checksum([0xFF, 0x01]) == 0

    def test_simple(self):
        assert checksum([0x10, 0x20, 0x30]) == 0x60


# ---------------------------------------------------------------------------
# parse_info_message
# ---------------------------------------------------------------------------

EXAMPLE_ASCII = b"1E 00 05 10 09 32 33 30 30 37 34 32 33 20 01 0C 01 00 20 01 00 03 00 BF 00 00 00 20 05 00 00 E9"

class TestParseInfoMessage:
    def test_from_ascii_hex(self):
        info = parse_info_message(EXAMPLE_ASCII)
        assert info["length"] == 0x1E
        assert info["record_type"] == 0x00

    def test_serial_decoded(self):
        info = parse_info_message(EXAMPLE_ASCII)
        # bytes 5-13: 0x32 0x33 0x30 0x30 0x37 0x34 0x32 0x33 0x20 = "230074232 "
        assert "2" in info["serial"]

    def test_total_jumps(self):
        info = parse_info_message(EXAMPLE_ASCII)
        # bytes 21-22 (little-endian): 0x03 0x00 = 3
        assert info["total_jumps"] == 3

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError):
            parse_info_message(b"\x00" * 10)

    def test_from_raw_bytes(self):
        raw = bytes(int(x, 16) for x in EXAMPLE_ASCII.split())
        info = parse_info_message(raw)
        assert info["length"] == 0x1E

    def test_raw_field_present(self):
        info = parse_info_message(EXAMPLE_ASCII)
        assert len(info["raw"]) == PACKET_SIZE


# ---------------------------------------------------------------------------
# build_packet / verify_packet
# ---------------------------------------------------------------------------

class TestBuildPacket:
    def test_length_is_32(self):
        pkt = build_packet(0xA4)
        assert len(pkt) == PACKET_SIZE

    def test_command_byte(self):
        pkt = build_packet(0xA4)
        assert pkt[1] == 0xA4

    def test_verify_passes(self):
        pkt = build_packet(0xA4)
        assert verify_packet(pkt)

    def test_payload_embedded(self):
        payload = b"\x01\x02\x03\x04"
        pkt = build_packet(0xA0, payload)
        assert pkt[2:6] == payload

    def test_corrupt_fails_verify(self):
        pkt = bytearray(build_packet(0xA4))
        pkt[2] ^= 0xFF  # flip bits
        assert not verify_packet(bytes(pkt))

    def test_too_large_payload_raises(self):
        with pytest.raises(ValueError):
            build_packet(0xA0, b"\x00" * 30)

    def test_verify_wrong_length_returns_false(self):
        assert not verify_packet(b"\x00" * 10)


# ---------------------------------------------------------------------------
# encode_datetime / decode_datetime
# ---------------------------------------------------------------------------

class TestDatetime:
    CASES = [
        datetime.datetime(2023, 6, 15, 14, 30, 45),
        datetime.datetime(2000, 1, 1, 0, 0, 0),
        datetime.datetime(2099, 12, 31, 23, 59, 59),
    ]

    def test_roundtrip(self):
        for dt in self.CASES:
            encoded = encode_datetime(dt)
            decoded = decode_datetime(encoded)
            assert decoded == dt, f"Roundtrip failed for {dt}"

    def test_encoded_length(self):
        dt = datetime.datetime(2024, 3, 10, 12, 0, 0)
        assert len(encode_datetime(dt)) == 8

    def test_wrong_type_raises(self):
        with pytest.raises(TypeError):
            encode_datetime("2024-01-01")

    def test_year_encoding(self):
        dt = datetime.datetime(2024, 1, 1, 0, 0, 0)
        buf = encode_datetime(dt)
        # year stored little-endian in bytes 0-1
        year = buf[0] + (buf[1] << 8)
        assert year == 2024
