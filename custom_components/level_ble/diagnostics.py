"""Diagnostics for Level BLE (Settings -> Devices -> Level BLE -> Download diagnostics)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_EMAIL
from homeassistant.core import HomeAssistant

from .const import CONF_ACCOUNT_UUID, CONF_DEVICE, CONF_PRIVATE_KEY, CONF_TOKEN
from .discovery import async_capture_targets, async_find_lock
from .entity import LevelConfigEntry

# The lock UUID is redacted too: it is the key to the lock's state broadcast.
TO_REDACT = {CONF_EMAIL, CONF_TOKEN, CONF_PRIVATE_KEY, CONF_ACCOUNT_UUID, "uuid", "serial", "public_key"}


def _advert(info: Any) -> dict[str, Any] | None:
    if info is None:
        return None
    return {
        "address": info.address,
        "name": info.name,
        "rssi": info.rssi,
        "source": info.source,
        "connectable": info.connectable,
        "service_uuids": list(info.service_uuids or []),
        "manufacturer_data": {str(k): v.hex() for k, v in (info.manufacturer_data or {}).items()},
        "service_data": {k: v.hex() for k, v in (info.service_data or {}).items()},
    }


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: LevelConfigEntry) -> dict[str, Any]:
    monitor = getattr(entry, "runtime_data", None)
    return {
        "entry": async_redact_data(dict(entry.data), TO_REDACT),
        "matched_advertisement": _advert(async_find_lock(hass, entry.data[CONF_DEVICE])),
        "level_like_advertisements": [_advert(i) for i in async_capture_targets(hass)],
        "monitor": None
        if monitor is None
        else {
            "address": monitor.address,
            "available": monitor.available,
            "rssi": monitor.rssi,
            "broadcast": asdict(monitor.broadcast) if monitor.broadcast else None,
        },
    }
