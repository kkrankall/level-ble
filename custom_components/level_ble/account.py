"""Parse Level account payloads.

Standard library only: tools/level_keychain.py imports this file directly.

Field names follow the app's own API models (co.level.network.openapi.models
in co.level.app 2.5.0.56): Account.Location is a list of LocationItem, each
with a `devices` list of DeviceItem. Keys are case-sensitive. Lower-case
spellings are kept as fallbacks only.
"""

from __future__ import annotations

from typing import Any


def login_statuses(data: Any) -> list[str]:
    """The login response's status as a list; Level sends e.g. {"status": ["loginFailed"]}."""
    status = data.get("status") if isinstance(data, dict) else None
    if status is None:
        return []
    if isinstance(status, list):
        return [str(item) for item in status]
    return [str(status)]


def _first(mapping: dict, *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        # BSON arrays sometimes arrive keyed "0", "1", ...
        return list(value.values())
    return []


def iter_devices(account: dict) -> list[dict]:
    """Flatten Location -> devices from an account payload.

    Devices without a UUID are skipped because the UUID is the config entry's
    unique ID; a device listed in two locations is returned once.
    """
    devices: list[dict] = []
    seen: set[str] = set()
    for location in _as_list(_first(account, "Location", "location", "locations")):
        if not isinstance(location, dict):
            continue
        location_name = _first(location, "LocationName", "locationName", "name") or "Home"
        for device in _as_list(_first(location, "devices", "device")):
            if not isinstance(device, dict):
                continue
            uuid = str(_first(device, "DeviceUUID", "deviceUUID", "uuid") or "")
            if not uuid or uuid in seen:
                continue
            seen.add(uuid)
            devices.append(
                {
                    "uuid": uuid,
                    # `name` is the label set in the app; `DeviceName` is the lock's
                    # own identifier (e.g. "A1B2C3D4"), kept for Bluetooth matching.
                    "name": _first(device, "name", "DeviceName", "deviceName") or "Level Lock",
                    "ble_name": _first(device, "DeviceName", "bleName"),
                    "location": str(location_name),
                    "product": _first(device, "Product", "product"),
                    "serial": _first(device, "SerialNumber", "serialNumber"),
                    "public_key": _first(device, "device_publicKey", "devicePublicKey"),
                    "bolt_state": _first(device, "BoltState", "boltState"),
                }
            )
    return devices
