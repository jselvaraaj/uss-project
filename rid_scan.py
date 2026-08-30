#!/usr/bin/env python3
"""Stream ASTM F3411 / Open Drone ID Remote ID broadcasts to the terminal.

Listens for Bluetooth LE legacy advertisements carrying service data for
UUID 0xFFFA (ASTM Remote ID) with AD application code 0x0D (Open Drone ID),
decodes every message type, and prints them as they arrive.

This is receive-only. Remote ID is a one-way beacon: nothing is paired,
connected to, or transmitted.

    python3 rid_scan.py               # human-readable stream
    python3 rid_scan.py --table       # live per-aircraft summary
    python3 rid_scan.py --jsonl       # one JSON object per line, for piping
    python3 rid_scan.py --adapter hci1   # Linux: scan on a specific adapter

Runs on macOS (CoreBluetooth) and Linux (BlueZ, e.g. a Raspberry Pi).
"""

import argparse
import asyncio
import datetime as dt
import json
import os
import struct
import sys

from bleak import BleakScanner
from bleak.exc import BleakError

ODID_SERVICE_UUID = "0000fffa-0000-1000-8000-00805f9b34fb"
ODID_AD_APP_CODE = 0x0D
MESSAGE_SIZE = 25

# Timestamps in the System message count seconds from this epoch.
ODID_EPOCH = dt.datetime(2019, 1, 1, tzinfo=dt.timezone.utc)

MESSAGE_TYPES = {
    0: "BASIC_ID",
    1: "LOCATION",
    2: "AUTH",
    3: "SELF_ID",
    4: "SYSTEM",
    5: "OPERATOR_ID",
    0xF: "MESSAGE_PACK",
}

ID_TYPES = {
    0: "None",
    1: "Serial Number (CTA-2063-A)",
    2: "CAA Registration ID",
    3: "UTM (USS) Assigned UUID",
    4: "Specific Session ID",
}

UA_TYPES = {
    0: "Undeclared",
    1: "Aeroplane",
    2: "Helicopter/Multirotor",
    3: "Gyroplane",
    4: "Hybrid Lift",
    5: "Ornithopter",
    6: "Glider",
    7: "Kite",
    8: "Free Balloon",
    9: "Captive Balloon",
    10: "Airship",
    11: "Free Fall/Parachute",
    12: "Rocket",
    13: "Tethered Powered Aircraft",
    14: "Ground Obstacle",
    15: "Other",
}

STATUS = {
    0: "Undeclared",
    1: "Ground",
    2: "Airborne",
    3: "Emergency",
    4: "Remote ID System Failure",
}

HEIGHT_TYPE = {0: "Above Takeoff", 1: "AGL"}

OPERATOR_LOCATION_TYPE = {0: "Takeoff", 1: "Live GNSS", 2: "Fixed"}

CLASSIFICATION_TYPE = {0: "Undeclared", 1: "EU"}

DESC_TYPE = {0: "Text", 1: "Emergency", 2: "Extended Status"}

AUTH_TYPE = {
    0: "None",
    1: "UAS ID Signature",
    2: "Operator ID Signature",
    3: "Message Set Signature",
    4: "Network Remote ID",
    5: "Specific Method",
}

HORIZ_ACCURACY = {
    0: "Unknown",
    1: "<10 NM",
    2: "<4 NM",
    3: "<2 NM",
    4: "<1 NM",
    5: "<0.5 NM",
    6: "<0.3 NM",
    7: "<0.1 NM",
    8: "<0.05 NM",
    9: "<30 m",
    10: "<10 m",
    11: "<3 m",
    12: "<1 m",
}

VERT_ACCURACY = {
    0: "Unknown",
    1: "<150 m",
    2: "<45 m",
    3: "<25 m",
    4: "<10 m",
    5: "<3 m",
    6: "<1 m",
}

SPEED_ACCURACY = {
    0: "Unknown",
    1: "<10 m/s",
    2: "<3 m/s",
    3: "<1 m/s",
    4: "<0.3 m/s",
}

INVALID_ALT = -1000.0


def _enum(table, value):
    return table.get(value, f"Reserved/Unknown ({value})")


def _printable(s):
    """Neutralize terminal control sequences in untrusted broadcast text.

    Remote ID fields are attacker-controlled radio data written to a terminal
    that interprets ANSI/OSC escapes, so keep printable ASCII only.
    """
    return "".join(ch if 0x20 <= ord(ch) <= 0x7E else "�" for ch in s)


def _text(raw):
    """Decode a fixed-width ASCII field, dropping padding."""
    s = raw.split(b"\x00")[0].decode("ascii", errors="replace")
    return _printable(s).strip()


def _altitude(encoded):
    """uint16 -> metres, or None when the field carries the invalid sentinel."""
    value = encoded * 0.5 - 1000.0
    return None if value == INVALID_ALT else round(value, 1)


def _coords(lat_enc, lon_enc):
    """int32 1e-7 degrees. The PAIR (0,0) is the 'no fix' sentinel —
    a single zero coordinate (equator / prime meridian) is a valid fix."""
    if lat_enc == 0 and lon_enc == 0:
        return None, None
    return lat_enc / 1e7, lon_enc / 1e7


def decode_basic_id(b):
    id_type = b[1] >> 4
    raw_id = b[2:22]
    if id_type in (1, 2):  # serial number / CAA registration: ASCII
        uas_id = _text(raw_id)
    elif not any(raw_id):
        uas_id = None
    else:  # UTM UUID / Specific Session ID: binary, per F3411
        uas_id = raw_id.hex()
    return {
        "id_type": _enum(ID_TYPES, id_type),
        "ua_type": _enum(UA_TYPES, b[1] & 0x0F),
        "uas_id": uas_id,
    }


def decode_location(b):
    flags = b[1]
    speed_mult = flags & 0x01
    ew_direction = (flags >> 1) & 0x01
    height_type = (flags >> 2) & 0x01
    status = flags >> 4

    direction = b[2]
    track = None if direction > 179 else direction + (180 if ew_direction else 0)

    speed_enc = b[3]
    if speed_mult == 0:
        # enc 255 with mult=0 is a valid 63.75 m/s, not the invalid sentinel
        speed_h = round(speed_enc * 0.25, 2)
    elif speed_enc == 0xFF:
        speed_h = None  # decoded 255 m/s = INV_SPEED_H
    else:
        speed_h = round(speed_enc * 0.75 + 255 * 0.25, 2)

    speed_v_enc = struct.unpack_from("<b", b, 4)[0]
    # INV_SPEED_V is the decoded value 63 m/s (encoded 126), not encoded 127
    speed_v = round(speed_v_enc * 0.5, 2)
    if abs(speed_v) >= 63:
        speed_v = None

    lat, lon = _coords(*struct.unpack_from("<ii", b, 5))
    alt_baro, alt_geo, height = struct.unpack_from("<HHH", b, 13)
    timestamp = struct.unpack_from("<H", b, 21)[0]
    ts_acc = b[23] & 0x0F

    return {
        "status": _enum(STATUS, status),
        "track_deg": track,
        "speed_h_mps": speed_h,
        "speed_v_mps": speed_v,
        "latitude": lat,
        "longitude": lon,
        "altitude_baro_m": _altitude(alt_baro),
        "altitude_geo_m": _altitude(alt_geo),
        "height_m": _altitude(height),
        "height_ref": _enum(HEIGHT_TYPE, height_type),
        "horiz_accuracy": _enum(HORIZ_ACCURACY, b[19] & 0x0F),
        "vert_accuracy": _enum(VERT_ACCURACY, b[19] >> 4),
        "speed_accuracy": _enum(SPEED_ACCURACY, b[20] & 0x0F),
        "baro_accuracy": _enum(VERT_ACCURACY, b[20] >> 4),
        # Tenths of a second since the top of the current UTC hour.
        "timestamp_s_into_hour": None if timestamp == 0xFFFF else timestamp / 10.0,
        # Enum steps of 0.1 s; 0 = unknown.
        "timestamp_accuracy_s": None if ts_acc == 0 else round(ts_acc * 0.1, 1),
    }


def decode_auth(b):
    page = b[1] & 0x0F
    out = {"auth_type": _enum(AUTH_TYPE, b[1] >> 4), "page": page}
    if page == 0:
        out["last_page_index"] = b[2]
        out["length"] = b[3]
        out["timestamp"] = _odid_time(struct.unpack_from("<I", b, 4)[0])
        out["data_hex"] = b[8:25].hex()
    else:
        out["data_hex"] = b[2:25].hex()
    return out


def decode_self_id(b):
    return {"desc_type": _enum(DESC_TYPE, b[1]), "description": _text(b[2:25])}


def _odid_time(seconds):
    """uint32 seconds since 2019-01-01T00:00:00Z (System/Auth timestamp).

    The reference decode defines no invalid sentinel for this field, but real
    transmitters without a clock broadcast 0; treating that as 'unset' is a
    deliberate display deviation. All other values decode as-is.
    """
    if seconds == 0:
        return None
    return (ODID_EPOCH + dt.timedelta(seconds=seconds)).isoformat()


def decode_system(b):
    flags = b[1]
    lat, lon = _coords(*struct.unpack_from("<ii", b, 2))
    area_count = struct.unpack_from("<H", b, 10)[0]
    area_radius = b[12]
    ceiling, floor = struct.unpack_from("<HH", b, 13)
    operator_alt = struct.unpack_from("<H", b, 18)[0]
    timestamp = struct.unpack_from("<I", b, 20)[0]

    return {
        "operator_location_type": _enum(OPERATOR_LOCATION_TYPE, flags & 0x03),
        "classification_type": _enum(CLASSIFICATION_TYPE, (flags >> 2) & 0x07),
        "operator_latitude": lat,
        "operator_longitude": lon,
        "area_count": area_count,
        "area_radius_m": area_radius * 10,
        "area_ceiling_m": _altitude(ceiling),
        "area_floor_m": _altitude(floor),
        "class_eu": b[17] & 0x0F,
        "category_eu": b[17] >> 4,
        "operator_altitude_geo_m": _altitude(operator_alt),
        "timestamp": _odid_time(timestamp),
    }


def decode_operator_id(b):
    return {"operator_id_type": b[1], "operator_id": _text(b[2:22])}


DECODERS = {
    0: decode_basic_id,
    1: decode_location,
    2: decode_auth,
    3: decode_self_id,
    4: decode_system,
    5: decode_operator_id,
}


def decode_message(b, in_pack=False):
    """Decode one 25-byte Open Drone ID message."""
    if len(b) < MESSAGE_SIZE:
        return [{"message_type": "TRUNCATED", "raw_hex": b.hex()}]

    msg_type = b[0] >> 4
    proto = b[0] & 0x0F

    if msg_type == 0xF:
        # Message pack: a container of back-to-back single messages.
        # Per the reference decoder: single size must be 25, count 1-9,
        # and packs cannot nest.
        single_size, count = b[1], b[2]
        if in_pack or single_size != MESSAGE_SIZE or not 1 <= count <= 9:
            return [{"message_type": "INVALID_PACK", "raw_hex": b.hex()}]
        out = []
        for i in range(count):
            start = 3 + i * single_size
            chunk = b[start : start + single_size]
            if len(chunk) < MESSAGE_SIZE:
                break
            out.extend(decode_message(chunk, in_pack=True))
        return out

    decoder = DECODERS.get(msg_type)
    entry = {
        "message_type": _enum(MESSAGE_TYPES, msg_type),
        "protocol_version": proto,
        "raw_hex": b[:MESSAGE_SIZE].hex(),
    }
    if decoder:
        entry.update(decoder(b))
    return [entry]


def parse_service_data(data):
    """Strip the ODID service-data header and decode the payload.

    Layout after the 0xFFFA UUID: [app code 0x0D][message counter][message...]
    """
    if len(data) < 2 or data[0] != ODID_AD_APP_CODE:
        return None, None
    counter = data[1]
    return counter, decode_message(bytes(data[2:]))


# --- output modes -----------------------------------------------------------


def fmt_stream(device, rssi, counter, messages, show_raw):
    now = dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    lines = []
    for msg in messages:
        head = (
            f"\033[2m{now}\033[0m  \033[1m{msg['message_type']:<12}\033[0m "
            f"\033[36m{device}\033[0m  rssi={rssi}dBm  seq={counter}"
        )
        lines.append(head)
        for key, value in msg.items():
            if key in ("message_type", "raw_hex"):
                continue
            if value is None:
                value = "\033[2m—\033[0m"
            lines.append(f"    {key:<24} {value}")
        if show_raw:
            lines.append(f"    \033[2m{msg.get('raw_hex', '')}\033[0m")
    return "\n".join(lines)


class Tracker:
    """Accumulates the latest field values per transmitting device."""

    def __init__(self):
        self.drones = {}

    def update(self, device, rssi, messages):
        state = self.drones.setdefault(device, {"device": device, "msgs": 0})
        state["rssi"] = rssi
        state["last_seen"] = dt.datetime.now()
        state["msgs"] += len(messages)
        for msg in messages:
            for key, value in msg.items():
                if key in ("raw_hex", "message_type"):
                    continue
                # None (sentinel) values DO overwrite: after GPS loss the
                # last-known fix must not keep rendering as current.
                state[key] = value

    def render(self):
        now = dt.datetime.now()
        # Prune aircraft not heard from in 60 s so dead rows don't accumulate.
        self.drones = {
            d: s
            for d, s in self.drones.items()
            if (now - s["last_seen"]).total_seconds() <= 60.0
        }
        rows = ["\033[1mOpen Drone ID — live\033[0m  (Ctrl-C to stop)", ""]
        if not self.drones:
            rows.append("  waiting for broadcasts…")
        for state in sorted(
            self.drones.values(), key=lambda s: s["last_seen"], reverse=True
        ):
            age = (now - state["last_seen"]).total_seconds()
            rows.append(
                f"\033[1m\033[32m{state.get('uas_id') or state['device']}\033[0m"
                f"  \033[2m{state.get('ua_type', '?')}\033[0m"
            )
            rows.append(
                f"  status   {state.get('status', '?')}    "
                f"rssi {state.get('rssi')}dBm    "
                f"msgs {state['msgs']}    age {age:.1f}s"
            )

            def num(key, suffix=""):
                value = state.get(key)
                return "—" if value is None else f"{value}{suffix}"

            lat, lon = state.get("latitude"), state.get("longitude")
            has_fix = lat is not None and lon is not None
            pos = f"{lat:.6f}, {lon:.6f}" if has_fix else "no fix"
            rows.append(
                f"  position {pos}    alt(geo) {num('altitude_geo_m', 'm')}    "
                f"height {num('height_m', 'm')}"
            )
            rows.append(
                f"  speed    {num('speed_h_mps', ' m/s')} h    "
                f"{num('speed_v_mps', ' m/s')} v    "
                f"track {num('track_deg', '°')}"
            )
            olat, olon = state.get("operator_latitude"), state.get("operator_longitude")
            if olat is not None and olon is not None:
                rows.append(f"  operator {olat:.6f}, {olon:.6f}")
            if state.get("operator_id"):
                rows.append(f"  op id    {state['operator_id']}")
            if state.get("description"):
                rows.append(f"  self id  {state['description']}")
            rows.append("")
        # Home + per-line erase + clear-to-end: repaints without the full-screen
        # clear that makes the display flicker at advertisement rates.
        return "\033[H" + "\n".join(r + "\033[K" for r in rows) + "\n\033[0J"


def patch_allow_duplicates():
    """Make CoreBluetooth deliver every advertisement, not just the first.

    bleak starts scanning with options=None, so macOS coalesces repeat
    advertisements from the same peripheral and a Remote ID beacon would
    appear exactly once. Remote ID rotates message types across successive
    advertisements, so duplicates are the whole point here.
    """
    if sys.platform != "darwin":
        return False
    try:
        from bleak.backends.corebluetooth import CentralManagerDelegate as cmd
        from CoreBluetooth import CBUUID, CBCentralManagerScanOptionAllowDuplicatesKey
        from Foundation import NSArray, NSDictionary
    except ImportError:
        return False

    async def start_scan(self, service_uuids):
        uuids = (
            NSArray.alloc().initWithArray_(
                [CBUUID.UUIDWithString_(u) for u in service_uuids]
            )
            if service_uuids
            else None
        )
        options = NSDictionary.dictionaryWithObject_forKey_(
            True, CBCentralManagerScanOptionAllowDuplicatesKey
        )
        self.central_manager.scanForPeripheralsWithServices_options_(uuids, options)

    cmd.CentralManagerDelegate.start_scan = start_scan
    return True


def linux_usb_adapter():
    """Return the first USB Bluetooth adapter (e.g. hciN), or None.

    A Raspberry Pi has its onboard controller (on the serial/platform bus)
    plus any USB dongle. A dongle like the Sena UD100 is almost always the
    intended Remote ID receiver — better antenna, and it leaves the onboard
    radio free — so when no adapter is named we prefer it.
    """
    import glob
    for hci in sorted(glob.glob("/sys/class/bluetooth/hci*")):
        try:
            dev = os.path.realpath(os.path.join(hci, "device"))
        except OSError:
            continue
        # A USB path looks like .../usb1/1-1/1-1:1.0/...; the onboard radio sits
        # on the serial/platform bus with no "usb" component.
        if "/usb" in dev:
            return os.path.basename(hci)
    return None


def bluez_scanner_kwargs(adapter):
    """Linux/BlueZ counterpart of patch_allow_duplicates().

    bluetoothd merges advertisements into one Device object and only emits a
    PropertiesChanged signal when the data differs, so byte-identical repeats
    of a Remote ID frame would never reach the callback. The DuplicateData
    discovery filter turns that suppression off. `adapter` selects which hci
    device scans (a Pi has its onboard radio plus any USB dongle).
    """
    if sys.platform != "linux":
        return {}
    kwargs = {}
    if adapter:
        kwargs["adapter"] = adapter
    # bleak wraps filter values in D-Bus Variants itself (and defaults
    # DuplicateData to False), so pass a plain bool here.
    kwargs["bluez"] = {"filters": {"DuplicateData": True}}
    return kwargs


async def main():
    ap = argparse.ArgumentParser(
        description="Stream Open Drone ID / ASTM F3411 Remote ID broadcasts."
    )
    ap.add_argument("--table", action="store_true", help="live per-aircraft summary")
    ap.add_argument("--jsonl", action="store_true", help="one JSON object per line")
    ap.add_argument("--raw", action="store_true", help="also print raw message hex")
    ap.add_argument(
        "--all", action="store_true", help="log every BLE device seen, for debugging"
    )
    ap.add_argument(
        "--duration", type=float, help="stop after N seconds instead of running forever"
    )
    ap.add_argument(
        "--adapter",
        help="Linux only: Bluetooth adapter to scan with, e.g. hci1 "
        "(default: a USB dongle if present, else the system default)",
    )
    args = ap.parse_args()

    duplicates = patch_allow_duplicates()
    tracker = Tracker() if args.table else None

    # On Linux, default to the USB dongle when the user didn't name an adapter.
    if sys.platform == "linux" and not args.adapter:
        args.adapter = linux_usb_adapter()
        if args.adapter and not args.jsonl:
            print(
                f"Using Bluetooth adapter {args.adapter} (auto-selected USB dongle; "
                f"override with --adapter).",
                flush=True,
            )

    if not args.jsonl:
        print(
            "Scanning for Open Drone ID broadcasts (service UUID 0xFFFA)…", flush=True
        )
        if sys.platform == "darwin" and not duplicates:
            print(
                "\033[33mwarning:\033[0m could not enable duplicate advertisement "
                "reports; you may only see each device once.",
                flush=True,
            )
        print("Ctrl-C to stop.\n", flush=True)

    last_frame = {}
    stop = asyncio.Event()

    def callback(device, adv):
        try:
            _handle(device, adv)
        except BrokenPipeError:
            # Downstream reader (e.g. `--jsonl | head`) closed the pipe.
            # Point stdout at devnull so the interpreter's shutdown flush of
            # the broken stream doesn't add noise, then stop scanning.
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
            os.close(devnull)
            stop.set()

    def _handle(device, adv):
        # Debug output goes to stderr so it can never corrupt --jsonl pipes,
        # and is suppressed in table mode where it would scroll the display.
        if args.all and not args.table and ODID_SERVICE_UUID not in adv.service_data:
            name = _printable(adv.local_name or "")
            print(
                f"\033[2m[other] {device.address} {name}\033[0m",
                file=sys.stderr,
            )

        data = adv.service_data.get(ODID_SERVICE_UUID)
        if not data:
            return

        if not args.jsonl and not args.table:
            # BLE retransmits the same frame several times per second before
            # the module rotates to the next message; printing every radio
            # repeat would bury real changes. New messages differ in counter
            # or payload, so exact-repeat suppression loses nothing.
            frame = bytes(data)
            if last_frame.get(device.address) == frame:
                return
            last_frame[device.address] = frame

        counter, messages = parse_service_data(data)
        if not messages:
            return

        if args.jsonl:
            for msg in messages:
                record = {
                    "time": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "device": device.address,
                    "rssi": adv.rssi,
                    "seq": counter,
                    **msg,
                }
                if not args.raw:
                    record.pop("raw_hex", None)
                print(json.dumps(record), flush=True)
        elif tracker:
            # Rendering happens on the fixed-rate loop in main(), not per
            # advertisement — beacons arrive at 3-15 Hz with duplicates on.
            tracker.update(device.address, adv.rssi, messages)
        else:
            print(
                fmt_stream(device.address, adv.rssi, counter, messages, args.raw),
                flush=True,
            )

    scanner = BleakScanner(
        detection_callback=callback, **bluez_scanner_kwargs(args.adapter)
    )
    try:
        # bleak raises BleakError (BleakBluetoothNotAvailableError) when
        # Bluetooth is off, unsupported, or this process lacks permission;
        # the timeout covers the rare case where CoreBluetooth never reports
        # a state at all.
        await asyncio.wait_for(scanner.start(), timeout=10)
    except (asyncio.TimeoutError, BleakError) as e:
        # str() on bleak's not-available error yields a (message, reason)
        # tuple repr; args[0] is the readable message.
        msg = e.args[0] if e.args else str(e)
        if msg:
            print(f"\033[31m{msg}\033[0m", file=sys.stderr, flush=True)
        print(bluetooth_help(), file=sys.stderr, flush=True)
        return 1

    render_task = None
    if tracker:
        # One-time clear + hide cursor; the loop repaints in place.
        print("\033[2J\033[?25l", end="", flush=True)

        async def render_loop():
            while True:
                print(tracker.render(), end="", flush=True)
                await asyncio.sleep(0.25)

        render_task = asyncio.ensure_future(render_loop())

    try:
        # stop is set on downstream pipe close; timeout=None waits forever.
        await asyncio.wait_for(stop.wait(), timeout=args.duration)
    except asyncio.TimeoutError:
        pass
    finally:
        if render_task:
            render_task.cancel()
            print("\033[?25h", end="", file=sys.stderr, flush=True)
        await scanner.stop()
    return 0


def bluetooth_help():
    if sys.platform == "linux":
        return (
            "\n\033[31mBluetooth did not become available.\033[0m\n\n"
            "On Linux (BlueZ) check, in order:\n\n"
            "  1. bluetoothd is running:        systemctl status bluetooth\n"
            "  2. the adapter exists:           bluetoothctl list   (or: hciconfig -a)\n"
            "  3. it is not rfkill-blocked:     rfkill list bluetooth ; sudo rfkill unblock bluetooth\n"
            "  4. it is powered on:             bluetoothctl -- select <MAC> ; bluetoothctl power on\n"
            "  5. you picked the right one:     --adapter hci0 / --adapter hci1\n"
        )
    auth = "unavailable"
    if sys.platform == "darwin":
        try:
            from CoreBluetooth import CBManager

            auth = {
                0: "notDetermined",
                1: "restricted",
                2: "denied",
                3: "allowedAlways",
            }.get(CBManager.authorization(), str(CBManager.authorization()))
        except Exception:
            pass

    return (
        f"\n\033[31mBluetooth did not become available.\033[0m "
        f"(CoreBluetooth authorization: {auth})\n\n"
        "On macOS this almost always means the process running this script has not\n"
        "been granted Bluetooth access. macOS can only show that prompt to a real\n"
        "app, so:\n\n"
        "  1. Open Terminal.app or iTerm yourself (not an editor/agent shell).\n"
        "  2. Run this script there — macOS will ask to allow Bluetooth.\n"
        "  3. If no prompt appears, enable your terminal under\n"
        "     System Settings -> Privacy & Security -> Bluetooth, then retry.\n\n"
        "Also confirm Bluetooth is on:  system_profiler SPBluetoothDataType\n"
    )


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()) or 0)
    except KeyboardInterrupt:
        # stderr: a Ctrl-C must not append junk to `--jsonl > file` captures
        print("\nstopped.", file=sys.stderr)
