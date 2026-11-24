#!/usr/bin/env python3
"""BLE probe for Level locks.

Scans for Level locks, dumps the GATT map, and optionally initiates the user
key exchange (M1) so we can capture the lock's M2 reply. Uses the same UUIDs
and wire format (protobuf + FDBF fragments) as the integration.

    python3 tools/ble_probe.py --scan
    python3 tools/ble_probe.py --address <UUID-or-MAC> --dump
    python3 tools/ble_probe.py --address <...> --dump --handshake

Install once:  pip3 install bleak cryptography
"""

from __future__ import annotations

import argparse
import asyncio

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import _shared  # noqa: F401  (puts the integration's stdlib modules on sys.path)
from const import (  # type: ignore[import-not-found]
    LEVEL_NAME_HINTS,
    LEVEL_UUID_PREFIX,
    LEVEL_UUIDS,
    UUID_LEVEL_RX,
    UUID_LEVEL_SERVICE,
    UUID_LEVEL_TX,
    UUID_SERVICE_MAIN,
)
from wire import (  # type: ignore[import-not-found]
    VERSION_1,
    FragmentReassembler,
    decode_message,
    encode_message,
    frame_message,
)


async def scan(seconds: float) -> None:
    print(f"Scanning {seconds:g}s...")
    found = await BleakScanner.discover(timeout=seconds, return_adv=True)
    hits = 0
    for device, adv in found.values():
        uuids = {u.lower() for u in (adv.service_uuids or [])}
        name = (device.name or adv.local_name or "").lower()
        if uuids & LEVEL_UUIDS or any(h in name for h in LEVEL_NAME_HINTS):
            hits += 1
            print(f"\n{device.address}  rssi={adv.rssi}  name={device.name!r}")
            print(f"  services: {sorted(uuids)}")
            print(f"  manufacturer: { {k: v.hex() for k, v in adv.manufacturer_data.items()} }")
    if not hits:
        print("No Level-looking devices found. Wake the lock (touch it) and scan again.")


def dump(client: BleakClient) -> None:
    print(f"connected={client.is_connected} mtu={client.mtu_size}")
    for service in client.services:
        print(f"\nservice {service.uuid}  {service.description}")
        for char in service.characteristics:
            print(f"  char {char.uuid}  handle={char.handle}  props={','.join(char.properties)}")


def pick_write_char(client: BleakClient):
    """(characteristic, framed): FDBF/0x0010 like the app, else 9161b202, else any 9161b20x."""
    fallback = None
    for service in client.services:
        for char in service.characteristics:
            uuid = char.uuid.lower()
            if not ({"write", "write-without-response"} & set(char.properties)):
                continue
            if service.uuid.lower() == UUID_LEVEL_SERVICE and uuid == UUID_LEVEL_TX:
                return char, True
            if uuid == UUID_SERVICE_MAIN:
                fallback = fallback or (char, False)
            elif uuid.startswith(LEVEL_UUID_PREFIX) and fallback is None:
                fallback = (char, False)
    return fallback or (None, False)


def show_message(raw: bytes) -> None:
    try:
        print(f"  message: {decode_message(raw)}")
    except ValueError as exc:
        print(f"  (not a co.level.Message: {exc})")


async def handshake(client: BleakClient, listen: float) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    payload = encode_message({"version": VERSION_1, "userM1": {"userEphemeralEcPubkey33": public}})
    print(f"\nM1 public={public.hex()}")
    print(f"M1 protobuf={payload.hex()} ({len(payload)} bytes)")

    target, framed = pick_write_char(client)
    reassembler = FragmentReassembler()

    def on_notify(sender, data: bytearray) -> None:
        raw = bytes(data)
        uuid = getattr(sender, "uuid", str(sender)).lower()
        print(f"NOTIFY {uuid}: {raw.hex()}")
        if not framed:
            show_message(raw)
        elif uuid == UUID_LEVEL_RX:
            try:
                message = reassembler.feed(raw)
            except ValueError as exc:
                print(f"  bad fragment: {exc}")
                return
            if message is not None:
                print(f"  reassembled {len(message)} bytes: {message.hex()}")
                show_message(message)

    for service in client.services:
        for char in service.characteristics:
            if "notify" in char.properties or "indicate" in char.properties:
                try:
                    await client.start_notify(char, on_notify)
                    print(f"subscribed {char.uuid}")
                except Exception as exc:  # noqa: BLE001
                    print(f"could not subscribe {char.uuid}: {exc}")

    if target is None:
        print("no writable Level characteristic (FDBF 0x0010 or 9161b20x); share the --dump output instead")
        return

    writes = frame_message(payload, client.mtu_size) if framed else [payload]
    print(f"writing M1 to {target.uuid} in {len(writes)} write(s)")
    try:
        for chunk in writes:
            await client.write_gatt_char(target, chunk, response="write" in target.properties)
    except Exception as exc:  # noqa: BLE001
        print(f"write failed: {exc}")
        return
    await asyncio.sleep(listen)
    print("done listening")


async def connect_and_run(address: str, do_dump: bool, do_handshake: bool, listen: float) -> None:
    async with BleakClient(address, timeout=30) as client:
        if do_dump:
            dump(client)
        if do_handshake:
            await handshake(client, listen)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scan", action="store_true", help="list nearby Level-looking devices")
    ap.add_argument("--address", help="device address (MAC, or CoreBluetooth UUID on macOS)")
    ap.add_argument("--dump", action="store_true", help="print the GATT table")
    ap.add_argument("--handshake", action="store_true", help="send M1 and print notifications")
    ap.add_argument("--seconds", type=float, default=10, help="scan/listen time (default 10)")
    args = ap.parse_args()

    if args.scan:
        asyncio.run(scan(args.seconds))
    elif args.address and (args.dump or args.handshake):
        asyncio.run(connect_and_run(args.address, args.dump, args.handshake, args.seconds))
    else:
        ap.error("choose --scan, or --address with --dump and/or --handshake")


if __name__ == "__main__":
    main()
