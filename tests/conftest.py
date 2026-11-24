"""Shared fixtures."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from bleak.backends.device import BLEDevice
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak

from custom_components.level_ble.const import (
    CONF_DEVICE,
    CONF_PRIVATE_KEY,
    CONF_TOKEN,
    DOMAIN,
    UUID_SERVICE_MAIN,
    UUID_SERVICE_NOTIFY,
)

LOCK_UUID = "6b1e0b9a-0000-4000-8000-000000000001"
LOCK_ADDRESS = "AA:BB:CC:DD:EE:01"

# Deterministic secp256k1 keys for the account and the lock's long-term key.
ACCOUNT_UUID = "0b6c1f7e-9f1a-4c55-8d2e-1a2b3c4d5e6f"
USER_PRIVATE_HEX = "11" * 32
LOCK_PRIVATE_HEX = "22" * 32
LOCK_PUBLIC_HEX = (
    ec.derive_private_key(int(LOCK_PRIVATE_HEX, 16), ec.SECP256K1())
    .public_key()
    .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    .hex()
)

ENTRY_DATA = {
    "email": "user@example.com",
    CONF_TOKEN: "token-abc",
    CONF_PRIVATE_KEY: USER_PRIVATE_HEX,
    "account_uuid": ACCOUNT_UUID,
    CONF_DEVICE: {
        "uuid": LOCK_UUID,
        "name": "Front Door",
        "ble_name": "LEVEL-1234",
        "location": "Home",
        "product": "Level Bolt",
        "serial": "SN123",
        "public_key": LOCK_PUBLIC_HEX,
        "bolt_state": "LOCKED",
    },
}


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Let Home Assistant load custom_components/level_ble."""


def service_info(
    address: str = LOCK_ADDRESS,
    name: str | None = "LEVEL-1234",
    service_uuids: list[str] | None = None,
    service_data: dict[str, bytes] | None = None,
    rssi: int = -60,
) -> BluetoothServiceInfoBleak:
    device = BLEDevice(address, name, {})
    return BluetoothServiceInfoBleak(
        name=name or "",
        address=address,
        rssi=rssi,
        manufacturer_data={0x1234: b"\x01\x02"},
        service_data=service_data or {},
        service_uuids=service_uuids or [],
        source="esphome-proxy",
        device=device,
        advertisement=None,
        connectable=True,
        time=0,
        tx_power=None,
    )


def gatt(*services: tuple[str, list[tuple[str, list[str]]]]) -> list[SimpleNamespace]:
    """Build a fake bleak service collection: (service uuid, [(char uuid, props)])."""
    handle = 0
    out = []
    for service_uuid, chars in services:
        built = []
        for char_uuid, props in chars:
            handle += 1
            built.append(SimpleNamespace(uuid=char_uuid, handle=handle, properties=props))
        out.append(SimpleNamespace(uuid=service_uuid, characteristics=built))
    return out


LEVEL_GATT = gatt(
    ("00001800-0000-1000-8000-00805f9b34fb", [("00002a00-0000-1000-8000-00805f9b34fb", ["read"])]),
    (
        "9d8e06fe-9d7f-48a1-b63e-233e50e7d4e2",
        [
            (UUID_SERVICE_MAIN, ["write", "write-without-response"]),
            (UUID_SERVICE_NOTIFY, ["notify"]),
        ],
    ),
)


# The GATT table of a real Level lock (product "Apollo"), from level_ble.dump_gatt.
HAP = "-0000-1000-8000-0026bb765291"
FDBF_GATT = gatt(
    ("00001800-0000-1000-8000-00805f9b34fb", [("00002a00-0000-1000-8000-00805f9b34fb", ["read", "write"])]),
    ("00001801-0000-1000-8000-00805f9b34fb", [("00002a05-0000-1000-8000-00805f9b34fb", ["indicate"])]),
    (
        "0000fdbf-0000-1000-8000-00805f9b34fb",
        [
            ("00000010-0000-1000-8000-00805f9b34fb", ["write-without-response", "write"]),
            ("00000011-0000-1000-8000-00805f9b34fb", ["notify"]),
            ("00000012-0000-1000-8000-00805f9b34fb", ["notify"]),
            ("00000013-0000-1000-8000-00805f9b34fb", ["write", "notify"]),
            ("00000014-0000-1000-8000-00805f9b34fb", ["write-without-response"]),
            ("00000015-0000-1000-8000-00805f9b34fb", ["read"]),
        ],
    ),
    (f"00000045{HAP}", [(f"0000001d{HAP}", ["read", "write", "indicate"])]),
)


class FakeBleakClient:
    """Stands in for the client establish_connection returns.

    `replies` are sent once, after the first write: bytes go to the first
    subscribed characteristic, (uuid, bytes) to that characteristic.
    """

    def __init__(
        self,
        services: list[Any],
        replies: list[bytes | tuple[str, bytes]] | None = None,
        mtu: int = 247,
        responder: Any = None,
    ) -> None:
        self.services = services
        self.is_connected = True
        self.mtu_size = mtu
        self.replies = replies or []
        # responder(data) -> [(uuid, bytes)] answers every write (a simulated lock).
        self.responder = responder
        self.callbacks: dict[str, Any] = {}
        self.writes: list[tuple[str, bytes, bool]] = []
        self.disconnect = AsyncMock(side_effect=self._disconnect)

    async def _disconnect(self) -> None:
        self.is_connected = False

    async def start_notify(self, char: Any, callback: Any) -> None:
        self.callbacks[char.uuid] = (char, callback)

    async def write_gatt_char(self, char: Any, data: bytes, response: bool) -> None:
        self.writes.append((char.uuid, bytes(data), response))
        if self.responder is not None:
            for uuid, reply in self.responder(bytes(data)):
                notify_char, callback = self.callbacks[uuid]
                callback(notify_char, bytearray(reply))
            return
        if len(self.writes) > 1:
            return
        for reply in self.replies:
            if isinstance(reply, tuple):
                notify_char, callback = self.callbacks[reply[0]]
                reply = reply[1]
            else:
                notify_char, callback = next(iter(self.callbacks.values()))
            callback(notify_char, bytearray(reply))


@pytest.fixture
def fake_ble():
    """Patch establish_connection; yields a factory to set what the 'lock' looks like."""
    state: dict[str, Any] = {"client": FakeBleakClient(LEVEL_GATT)}
    connect = AsyncMock(side_effect=lambda *a, **kw: state["client"])
    with patch("custom_components.level_ble.ble.establish_connection", connect):
        yield SimpleNamespace(state=state, connect=connect)


__all__ = [
    "ACCOUNT_UUID",
    "DOMAIN",
    "ENTRY_DATA",
    "LOCK_ADDRESS",
    "LOCK_PRIVATE_HEX",
    "LOCK_UUID",
    "USER_PRIVATE_HEX",
    "gatt",
    "service_info",
]
