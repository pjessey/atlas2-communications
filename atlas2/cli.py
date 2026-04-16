"""
Interactive command-line interface for the Atlas 2 altimeter.

Run with:
    python main.py --port /dev/ttyUSB0
"""

import argparse
import datetime
import logging
import sys
import textwrap

import serial

from .connection import Atlas2Connection, Atlas2Error, RESPONSE_NAMES


def _header(title: str) -> None:
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")


def _print_info(info: dict) -> None:
    _header("Device Information")
    print(f"  Serial number  : {info['serial']}")
    print(f"  Software       : {info['sw_rev']}.{info['sw_major']}.{info['sw_minor']}")
    print(f"  Hardware ID    : 0x{info['hw_id']:02X}")
    print(f"  Product ID     : 0x{info['product_id']:02X}")
    print(f"  Total jumps    : {info['total_jumps']}")
    total = info['total_seconds']
    h, rem = divmod(total, 3600)
    m, s   = divmod(rem, 60)
    print(f"  Total freefall : {h}h {m}m {s}s  ({total} s)")
    print(f"  FRAM detail @  : 0x{info['fram_detail_addr']:08X}")
    print(f"  FRAM summary @ : 0x{info['fram_summary_addr']:08X}")


MENU = textwrap.dedent("""\

    ┌─────────────────────────────────────────┐
    │       Atlas 2 Altimeter Interface       │
    ├─────────────────────────────────────────┤
    │  i  – Show device info                  │
    │  t  – Read date/time from device        │
    │  T  – Sync device date/time to PC       │
    │  r  – Read EEProm bytes (hex dump)      │
    │  R  – Read Info Memory bytes (hex dump) │
    │  w  – Write EEProm bytes                │
    │  W  – Write Info Memory bytes           │
    │  k  – Send keep-alive (A4)              │
    │  q  – Quit                              │
    └─────────────────────────────────────────┘
""")


def _hex_dump(data: bytes, start_addr: int = 0) -> None:
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part  = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {start_addr + i:08X}  {hex_part:<47}  {ascii_part}")


def _prompt_int(msg: str, base: int = 10) -> int:
    raw = input(msg).strip()
    return int(raw, base)


def _prompt_hex_bytes(msg: str) -> bytes:
    raw = input(msg).strip()
    # Accept space-separated or plain hex string
    raw = raw.replace(" ", "")
    if len(raw) % 2:
        raw = "0" + raw
    return bytes.fromhex(raw)


def run_interactive(conn: Atlas2Connection) -> None:
    """Main interactive loop."""
    _print_info(conn.info)

    while True:
        print(MENU)
        try:
            choice = input("Choice: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            choice = "q"

        if choice == "q":
            print("Exiting…")
            break

        elif choice == "i":
            _print_info(conn.info)

        elif choice == "t":
            try:
                dt = conn.read_datetime()
                print(f"  Device date/time: {dt.isoformat()}")
            except Atlas2Error as exc:
                print(f"  Error: {exc}")

        elif choice == "T":
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            try:
                conn.set_datetime(now)
                print(f"  Date/time set to: {now.isoformat()} UTC")
            except Atlas2Error as exc:
                print(f"  Error: {exc}")

        elif choice in ("r", "R"):
            try:
                addr = _prompt_int("  Start address (hex, e.g. 0000): ", 16)
                length = _prompt_int("  Number of bytes (decimal): ", 10)
                if choice == "r":
                    data = conn.read_eeprom(addr, length)
                else:
                    data = conn.read_info_memory(addr, length)
                _hex_dump(data, addr)
            except (Atlas2Error, ValueError) as exc:
                print(f"  Error: {exc}")

        elif choice in ("w", "W"):
            try:
                addr = _prompt_int("  Destination address (hex): ", 16)
                data = _prompt_hex_bytes("  Bytes to write (hex, space-separated): ")
                if not data:
                    print("  No data entered.")
                    continue
                if len(data) > 25:
                    print("  Maximum 25 bytes per write operation.")
                    continue
                if choice == "w":
                    conn.write_eeprom(addr, data)
                else:
                    conn.write_info_memory(addr, data)
                print(f"  Written {len(data)} byte(s) to 0x{addr:08X}.")
            except (Atlas2Error, ValueError) as exc:
                print(f"  Error: {exc}")

        elif choice == "k":
            try:
                code = conn.send_keepalive()
                name = RESPONSE_NAMES.get(code, f"0x{code:02X}")
                print(f"  Keep-alive response: {name} (0x{code:02X})")
            except Atlas2Error as exc:
                print(f"  Error: {exc}")

        else:
            print("  Unknown option.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Communicate with an Alti-2 Atlas 2 altimeter over USB/serial.",
    )
    parser.add_argument(
        "--port", "-p",
        required=True,
        help="Serial port, e.g. /dev/ttyUSB0 or COM3",
    )
    parser.add_argument(
        "--product",
        default="atlas2",
        choices=["atlas", "atlas2", "juno"],
        help="Altimeter product type (default: atlas2)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        with Atlas2Connection(args.port, product=args.product) as conn:
            run_interactive(conn)
    except Atlas2Error as exc:
        print(f"Connection error: {exc}", file=sys.stderr)
        return 1
    except serial.SerialException as exc:
        print(f"Serial port error: {exc}", file=sys.stderr)
        return 1

    return 0
