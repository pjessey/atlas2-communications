# Atlas 2 Python Communication Tool

A Python application to communicate with **Alti-2** altimeters (Atlas, Atlas 2, Juno) connected via USB.

> **⚠️ WARNING** – Altering your device's software may cause unreliable operation and lead to severe injury or death. Use of this software is entirely at your own risk.

---

## Requirements

- Python 3.10 or newer
- `pyserial` library

```bash
pip install -r requirements.txt
```

---

## Quick Start

```bash
python main.py --port /dev/ttyUSB0
```

On Windows replace `/dev/ttyUSB0` with the appropriate COM port (e.g. `COM3`).

### Command-line options

| Option | Description | Default |
|--------|-------------|---------|
| `--port` / `-p` | Serial port | **required** |
| `--product` | Device model: `atlas`, `atlas2`, `juno` | `atlas2` |
| `--verbose` / `-v` | Enable debug logging | off |

---

## Interactive Menu

Once connected the following menu is displayed:

```
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
```

---

## Project Structure

```
atlas2/
├── __init__.py       – Package metadata
├── crypto.py         – XTEA 16-round cipher + key derivation
├── protocol.py       – Packet building/parsing, date-time helpers
├── connection.py     – Serial port management, all A/B commands
└── cli.py            – Interactive command-line interface
main.py               – Entry point
requirements.txt
tests/
├── test_crypto.py
└── test_protocol.py
```

---

## Running the Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Protocol Summary

| Layer | Detail |
|-------|--------|
| Baud rate | 57 600 |
| Data / Parity / Stop | 8 N 1 |
| Flow control | CTS/RTS hardware |
| DTR | Enabled |
| Packet size | 32 bytes (padded + encrypted) |
| Byte order | Little-endian |
| Encryption | XTEA, **16 rounds** |
| Key length | 128 bits (16 bytes) |

The device must not receive data while CTS is low — the library handles this automatically.

---

## Supported Commands

### Read (A-series)

| Cmd | Description |
|-----|-------------|
| A0 | Read EEProm (up to 64 KB) |
| A1 | Read Info Memory (up to 128 bytes) |
| A2 | Read Time & Date |
| A4 | Keep-alive / ACK |
| A5 | Request encrypted Info message |
| AF | Exit / disconnect |

### Write (B-series)

| Cmd | Description |
|-----|-------------|
| B0 | Write EEProm (max 25 bytes per packet) |
| B1 | Write Info Memory (max 25 bytes per packet) |
| B2 | Set Time & Date |
| B3 | Erase Info Memory |
| B4 | Reset to Bootloader (**dangerous**) |

---

## Using the Library Programmatically

```python
from atlas2.connection import Atlas2Connection

with Atlas2Connection("/dev/ttyUSB0", product="atlas2") as conn:
    print(conn.info)                     # device metadata dict
    data = conn.read_eeprom(0x0000, 16)  # read 16 bytes from address 0
    conn.set_datetime()                  # sync clock to UTC now
```
