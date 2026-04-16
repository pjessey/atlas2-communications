"""
Serial connection management for the Atlas 2 altimeter.

Handles:
- CTS/RTS flow control (must not write while CTS is low)
- DTR enabled
- Info message handshake
- Encrypted packet send/receive
"""

import time
import logging
from typing import Optional

import serial

from .protocol import (
    PACKET_SIZE,
    parse_info_message,
    verify_packet,
)
from .crypto import build_key, encrypt, decrypt

log = logging.getLogger(__name__)

# Response codes from device
RESP_ABORT       = 0x30
RESP_ACK         = 0x31
RESP_LEN_ERR     = 0x32
RESP_CHKSUM_ERR  = 0x33
RESP_OVERFLOW    = 0x34

# Command response codes
CMD_OK           = 0x35
CMD_UNKNOWN      = 0x36
CMD_SYNTAX       = 0x37
CMD_EEPROM_ERR   = 0x38
CMD_ERASE_ERR    = 0x39
CMD_ADDR_ERR     = 0x41
CMD_FLASH_ERR    = 0x42

RESPONSE_NAMES = {
    RESP_ABORT:      "ABORT",
    RESP_ACK:        "ACK",
    RESP_LEN_ERR:    "LENGTH_ERROR",
    RESP_CHKSUM_ERR: "CHECKSUM_ERROR",
    RESP_OVERFLOW:   "OVERFLOW_ERROR",
    CMD_OK:          "COMMAND_OK",
    CMD_UNKNOWN:     "UNKNOWN_COMMAND",
    CMD_SYNTAX:      "SYNTAX_ERROR",
    CMD_EEPROM_ERR:  "EEPROM_WRITE_ERROR",
    CMD_ERASE_ERR:   "FLASH_ERASE_ERROR",
    CMD_ADDR_ERR:    "INFO_MEM_OUT_OF_BOUNDS",
    CMD_FLASH_ERR:   "FLASH_WRITE_ERROR",
}

# How long to wait (seconds) for CTS to go high before giving up
CTS_TIMEOUT = 2.0
# How long to wait for a device response (seconds)
READ_TIMEOUT = 3.0


class Atlas2Error(Exception):
    """Base exception for Atlas 2 communication errors."""


class CtsTimeoutError(Atlas2Error):
    """CTS did not go high within the timeout period."""


class DeviceError(Atlas2Error):
    """Device returned an error code."""

    def __init__(self, code: int):
        name = RESPONSE_NAMES.get(code, f"0x{code:02X}")
        super().__init__(f"Device error: {name} (0x{code:02X})")
        self.code = code


class Atlas2Connection:
    """Manages the serial connection to an Atlas 2 altimeter.

    Usage::

        with Atlas2Connection("/dev/ttyUSB0") as conn:
            info = conn.info
            print(info)
    """

    def __init__(self, port: str, product: str = "atlas2", timeout: float = READ_TIMEOUT):
        self._port    = port
        self._product = product
        self._timeout = timeout
        self._serial: Optional[serial.Serial] = None
        self._info: Optional[dict] = None
        self._key: Optional[list[int]] = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def info(self) -> dict:
        """Parsed Info message dict (available after :meth:`open`)."""
        if self._info is None:
            raise Atlas2Error("Not connected – call open() first.")
        return self._info

    @property
    def key(self) -> list[int]:
        """XTEA encryption key (available after :meth:`open`)."""
        if self._key is None:
            raise Atlas2Error("Not connected – call open() first.")
        return self._key

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Open the serial port and perform the Info-message handshake."""
        log.debug("Opening serial port %s …", self._port)
        self._serial = serial.Serial(
            port=self._port,
            baudrate=57600,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            rtscts=True,
            dsrdtr=False,
            timeout=self._timeout,
        )
        # Enable DTR
        self._serial.dtr = True
        time.sleep(0.1)

        # Perform Info handshake
        self._info = self._handshake()
        self._key  = build_key(self._info["raw"], self._product)
        log.debug("Connected. Serial: %s  Jumps: %d", self._info["serial"], self._info["total_jumps"])

    def close(self) -> None:
        """Send the AF exit command and close the port."""
        if self._serial and self._serial.is_open:
            try:
                self._send_command(0xAF)
            except Exception:  # noqa: BLE001
                pass
            self._serial.close()
            log.debug("Port closed.")

    # ------------------------------------------------------------------
    # Info handshake
    # ------------------------------------------------------------------

    def _handshake(self) -> dict:
        """Send 6 dummy bytes and parse the returned Info message."""
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()
        # Send 6 bytes (content doesn't matter)
        self._safe_write(bytes(6))
        # The Info message is 32 bytes sent as ASCII hex pairs + spaces
        # Format: "XX XX XX … XX\r\n"  (32 pairs × 3 chars - 1 space + newline = ~96 chars)
        raw_line = self._serial.read_until(b"\n", size=200)
        if not raw_line:
            raise Atlas2Error("No Info message received from device.")
        log.debug("Raw info: %s", raw_line.strip())
        info = parse_info_message(raw_line.strip())
        return info

    # ------------------------------------------------------------------
    # Low-level I/O
    # ------------------------------------------------------------------

    def _wait_cts(self) -> None:
        """Block until CTS is high (device ready to receive)."""
        deadline = time.monotonic() + CTS_TIMEOUT
        while not self._serial.cts:
            if time.monotonic() > deadline:
                raise CtsTimeoutError("CTS did not go high within timeout.")
            time.sleep(0.005)

    def _safe_write(self, data: bytes) -> None:
        """Write *data* byte-by-byte, respecting CTS flow control."""
        for byte in data:
            self._wait_cts()
            self._serial.write(bytes([byte]))

    def _read_response_code(self) -> int:
        """Read a single-byte response code from the device."""
        b = self._serial.read(1)
        if not b:
            raise Atlas2Error("Timeout: no response from device.")
        return b[0]

    def _send_ack(self) -> None:
        """Send a single ACK byte (0x31) to the device."""
        self._safe_write(b"\x31")

    # ------------------------------------------------------------------
    # Encrypted packet send / receive
    # ------------------------------------------------------------------

    def _send_packet(self, plain: bytes) -> None:
        """Encrypt and send a 32-byte packet, then wait for ACK."""
        if len(plain) != PACKET_SIZE:
            raise ValueError(f"Packet must be {PACKET_SIZE} bytes, got {len(plain)}.")
        cipher = encrypt(plain, self._key)
        self._safe_write(cipher)
        code = self._read_response_code()
        if code != RESP_ACK:
            raise DeviceError(code)

    def _receive_packet(self) -> bytes:
        """Read one encrypted 32-byte packet, decrypt, verify, then ACK."""
        cipher = self._serial.read(PACKET_SIZE)
        if len(cipher) != PACKET_SIZE:
            raise Atlas2Error(f"Short read: expected {PACKET_SIZE} bytes, got {len(cipher)}.")
        plain = decrypt(cipher, self._key)
        if not verify_packet(plain):
            raise Atlas2Error("Checksum mismatch on received packet.")
        self._send_ack()
        return plain

    # ------------------------------------------------------------------
    # High-level command helpers
    # ------------------------------------------------------------------

    def _send_command(self, cmd: int, payload: bytes = b"") -> None:
        """Build, encrypt and send a command packet."""
        from .protocol import build_packet
        pkt = build_packet(cmd, payload)
        self._send_packet(pkt)

    def send_keepalive(self) -> int:
        """Send A4 keep-alive; returns the single-byte response code."""
        self._send_command(0xA4)
        return self._read_response_code()

    def read_eeprom(self, address: int, length: int) -> bytes:
        """A0: Read *length* bytes from EEProm starting at *address*."""
        return self._read_memory(0xA0, address, length)

    def read_info_memory(self, address: int, length: int) -> bytes:
        """A1: Read *length* bytes from Info Memory starting at *address*."""
        return self._read_memory(0xA1, address, length)

    def _read_memory(self, cmd: int, address: int, length: int) -> bytes:
        """Generic read for A0/A1 commands."""
        import struct
        payload = struct.pack("<IH", address, length)
        self._send_command(cmd, payload)
        code = self._read_response_code()
        if code != CMD_OK:
            raise DeviceError(code)
        # Collect response packets
        result = bytearray()
        remaining = length
        while remaining > 0:
            pkt = self._receive_packet()
            # pkt[8:31] is data (up to 23 bytes); pkt[0] is length
            pkt_len = pkt[0]
            data_start = 8
            data_end   = pkt_len  # checksum is at pkt[pkt_len]
            chunk = pkt[data_start:data_end]
            result += chunk
            remaining -= len(chunk)
        return bytes(result[:length])

    def read_datetime(self):
        """A2: Read date/time from device. Returns a :class:`datetime.datetime`."""
        from .protocol import decode_datetime
        self._send_command(0xA2)
        code = self._read_response_code()
        if code != CMD_OK:
            raise DeviceError(code)
        pkt = self._receive_packet()
        return decode_datetime(pkt[2:10])

    def write_eeprom(self, address: int, data: bytes) -> None:
        """B0: Write *data* to EEProm at *address* (max 25 bytes per call)."""
        self._write_memory(0xB0, address, data)

    def write_info_memory(self, address: int, data: bytes) -> None:
        """B1: Write *data* to Info Memory at *address* (max 25 bytes per call)."""
        self._write_memory(0xB1, address, data)

    def _write_memory(self, cmd: int, address: int, data: bytes) -> None:
        """Generic write for B0/B1 commands (max 25 bytes of payload data)."""
        import struct
        if len(data) > 25:
            raise ValueError("Maximum 25 bytes of data per write packet.")
        payload = struct.pack("<I", address) + data
        self._send_command(cmd, payload)
        code = self._read_response_code()
        if code != CMD_OK:
            raise DeviceError(code)

    def set_datetime(self, dt=None) -> None:
        """B2: Set date/time on the device. Uses current UTC time if *dt* is None."""
        import datetime
        from .protocol import encode_datetime
        if dt is None:
            dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        payload = encode_datetime(dt)
        self._send_command(0xB2, payload)
        code = self._read_response_code()
        if code != CMD_OK:
            raise DeviceError(code)

    def erase_info_memory(self) -> None:
        """B3: Erase Info Memory."""
        self._send_command(0xB3)
        code = self._read_response_code()
        if code != CMD_OK:
            raise DeviceError(code)
