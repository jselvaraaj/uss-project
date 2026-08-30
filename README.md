# Remote ID Terminal Scanner

Streams ASTM F3411 / Open Drone ID broadcasts (e.g. from a **Ruko R111/R111S**
module) live into your terminal, over your Mac's built-in Bluetooth. No pairing
and no connection — Remote ID is a one-way beacon and this tool only listens.

## How it works

The R111S broadcasts Bluetooth 4 Legacy advertisements (plus Bluetooth 5 Long
Range, which Macs can't receive — the BT4 stream carries the same data).
Each advertisement carries service data for UUID `0xFFFA` (ASTM Remote ID):
one 25-byte message per advertisement, rotating between message types —
Basic ID (serial number), Location (lat/lon/alt/speed), System (operator
position), Operator ID, and Self ID.

## Setup

```bash
pip3 install bleak
```

**Bluetooth permission (one-time):** macOS only lets apps with Bluetooth
permission scan. Run the script from Terminal.app or iTerm — the first run
should pop a "would like to use Bluetooth" prompt; click Allow. If no prompt
appears (or you previously denied it), enable your terminal app under
**System Settings → Privacy & Security → Bluetooth**, then run it again.
If it's not listed, add it with **+**. Without this, macOS kills the process
the moment it touches Bluetooth.

## Raspberry Pi / Linux (BlueZ)

The same script runs on Linux. On a Pi with a USB dongle (e.g. a Sena UD100)
there are two adapters — the onboard radio and the dongle — so pick one:

```bash
sudo apt install python3-bleak        # or: python3 -m venv ~/rid && ~/rid/bin/pip install bleak
bluetoothctl list                     # shows every adapter with its MAC
python3 rid_scan.py --adapter hci1    # hci1 is usually the USB dongle
```

The adapter must be powered (`bluetoothctl power on`) and not rfkill-blocked.
`--adapter` is ignored on macOS. The script asks BlueZ for every received
advertisement (`DuplicateData` discovery filter); without that, bluetoothd
only reports a beacon when its bytes change.

## Usage

```bash
# Human-readable stream of every decoded message
python3 rid_scan.py

# Live dashboard: one block per aircraft, refreshed in place
python3 rid_scan.py --table

# Machine-readable: one JSON object per line (pipe into jq, a file, etc.)
python3 rid_scan.py --jsonl
python3 rid_scan.py --jsonl | jq 'select(.message_type=="LOCATION") | {lat: .latitude, lon: .longitude, alt: .altitude_geo_m}'

# Extras
python3 rid_scan.py --raw          # include raw message hex
python3 rid_scan.py --all          # also log non-RID BLE devices (debug, to stderr)
python3 rid_scan.py --duration 30  # stop after 30 seconds
python3 rid_scan.py --adapter hci1  # Linux: which adapter scans
```

The default stream suppresses byte-identical radio retransmissions (BLE
repeats each frame several times per second) so you only see new messages;
`--jsonl` keeps every advertisement for full fidelity.

Power on the R111S and give it a minute to get a GPS fix; it broadcasts
immediately, but Location messages show `—` / `null` coordinates until it has
a fix. Typical receive range with a laptop is tens to a few hundred metres,
line of sight.

## What you'll see

- **BASIC_ID** — the module's CTA-2063-A serial number and aircraft type
- **LOCATION** — latitude, longitude, geodetic + barometric altitude, height
  above takeoff, ground track, horizontal/vertical speed, accuracy classes,
  and a tenths-of-a-second timestamp
- **SYSTEM** — operator (ground station) location and timestamp
- **OPERATOR_ID** — FAA registration number, if configured in the Ruko app
- **SELF_ID** — free-text flight description, if configured

## Notes

- Receive-only; complies with the listen-only nature of Broadcast Remote ID.
- macOS cannot receive Bluetooth 5 Long Range or Wi-Fi NAN/Beacon Remote ID —
  Apple exposes no API for those. For BT5 LR you'd need an nRF52840 dongle
  running [Sniffle](https://github.com/nccgroup/Sniffle). Not needed for the
  R111S since it also transmits BT4 Legacy.
- Wire format per [opendroneid-core-c](https://github.com/opendroneid/opendroneid-core-c)
  (ASTM F3411-22a).
