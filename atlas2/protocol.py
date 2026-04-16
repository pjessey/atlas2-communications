"""
Packet building and parsing for the Atlas 2 protocol.

All packets are 32 bytes long, little-endian.
"""

import struct
from typing import Sequence

PACKET_SIZE: int = 32


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------

def checksum(data: Sequence[int]) -> int:
    """Return the single-byte checksum (sum of bytes mod 256)."""
    return sum(data) & 0xFF


# ---------------------------------------------------------------------------
# Info (Type Zero) message
# ---------------------------------------------------------------------------

def parse_info_message(raw: bytes) -> dict:
    """Parse the 32-byte unencrypted Info message.

    The device sends the bytes as ASCII hex pairs separated by spaces, e.g.:
        ``1E 00 05 10 09 32 33 30 30 37 34 32 33 20 01 0C ...``

    This function accepts *either* that ASCII-hex string/bytes form **or** raw
    binary bytes (len == 32).
    """
    if isinstance(raw, (str, bytes)) and len(raw) > 32:
        # ASCII-hex form
        text = raw.decode("ascii") if isinstance(raw, bytes) else raw
        data = bytes(int(x, 16) for x in text.split())
    else:
        data = bytes(raw)

    if len(data) != PACKET_SIZE:
        raise ValueError(f"Info message must be 32 bytes, got {len(data)}.")

    length    = data[0]
    rec_type  = data[1]
    sw_rev    = (data[3] >> 4) & 0xF
    sw_major  = data[3] & 0xF
    sw_minor  = data[4]

    serial_bytes = data[5:14]
    serial = serial_bytes.decode("ascii", errors="replace").strip("\x00 ")

    hw_id      = data[14]
    product_id = data[15]
    fram_cfg   = data[16]

    fram_detail_addr = struct.unpack_from("<I", data, 17)[0]
    total_jumps      = struct.unpack_from("<H", data, 21)[0]
    total_seconds    = struct.unpack_from("<I", data, 23)[0]
    fram_summary_addr = struct.unpack_from("<I", data, 27)[0]
    chk = data[31]

    return {
        "length":            length,
        "record_type":       rec_type,
        "sw_rev":            sw_rev,
        "sw_major":          sw_major,
        "sw_minor":          sw_minor,
        "serial":            serial,
        "hw_id":             hw_id,
        "product_id":        product_id,
        "fram_cfg":          fram_cfg,
        "fram_detail_addr":  fram_detail_addr,
        "total_jumps":       total_jumps,
        "total_seconds":     total_seconds,
        "fram_summary_addr": fram_summary_addr,
        "checksum":          chk,
        "raw":               data,
    }


# ---------------------------------------------------------------------------
# Generic packet helpers
# ---------------------------------------------------------------------------

def build_packet(command: int, payload: bytes = b"") -> bytes:
    """Build a plain (unencrypted) 32-byte packet.

    Structure: [length, command, ...payload..., checksum] padded to 32 bytes.
    The length byte counts everything except itself (i.e., bytes 1-31 that are
    actually used by the payload + command + checksum).
    """
    # length = command(1) + payload + checksum(1)
    body = bytes([command]) + payload
    # total content length (excluding length byte itself, excluding trailing pad)
    content_len = 1 + len(payload) + 1  # cmd + payload + chksum
    if content_len > PACKET_SIZE - 1:
        raise ValueError("Payload too large for a single 32-byte packet.")

    raw = bytearray(PACKET_SIZE)
    raw[0] = content_len
    raw[1] = command
    raw[2 : 2 + len(payload)] = payload
    chk_pos = content_len  # index of checksum byte (1-based into packet)
    raw[chk_pos] = checksum(raw[1:chk_pos])
    return bytes(raw)


def verify_packet(data: bytes) -> bool:
    """Return True if the 32-byte packet has a valid checksum."""
    if len(data) != PACKET_SIZE:
        return False
    length = data[0]
    chk_pos = length
    if chk_pos >= PACKET_SIZE:
        return False
    expected = checksum(data[1:chk_pos])
    return expected == data[chk_pos]


# ---------------------------------------------------------------------------
# Date / Time
# ---------------------------------------------------------------------------

def encode_datetime(dt) -> bytes:
    """Encode a Python :class:`datetime.datetime` into the 8-byte device format."""
    import datetime
    if not isinstance(dt, datetime.datetime):
        raise TypeError("Expected a datetime.datetime instance.")
    buf = bytearray(8)
    buf[0] = dt.year & 0xFF
    buf[1] = (dt.year >> 8) & 0xFF
    buf[2] = dt.month
    buf[3] = dt.day
    buf[4] = 0  # checksum placeholder (device fills this)
    buf[5] = dt.hour
    buf[6] = dt.minute
    buf[7] = dt.second
    return bytes(buf)


def decode_datetime(data: bytes):
    """Decode 8 device bytes into a Python :class:`datetime.datetime`."""
    import datetime
    year   = data[0] + (data[1] << 8)
    month  = data[2]
    day    = data[3]
    hour   = data[5]
    minute = data[6]
    second = data[7]
    return datetime.datetime(year, month, day, hour, minute, second)
