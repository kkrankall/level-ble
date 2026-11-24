"""Find Level locks among the advertisements Home Assistant has seen."""

from __future__ import annotations

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.core import HomeAssistant, callback

from .const import CONF_DEVICE, DOMAIN, LEVEL_NAME_HINTS, LEVEL_UUIDS


def looks_like_level(info: BluetoothServiceInfoBleak, *, use_name_hints: bool) -> bool:
    """True if the advertisement carries a Level UUID (or, optionally, a Level-ish name)."""
    advertised = {uuid.lower() for uuid in info.service_uuids or []}
    advertised |= {uuid.lower() for uuid in info.service_data or {}}
    if advertised & LEVEL_UUIDS:
        return True
    name = (info.name or "").lower()
    return use_name_hints and any(hint in name for hint in LEVEL_NAME_HINTS)


@callback
def async_capture_targets(hass: HomeAssistant, address: str | None = None) -> list[BluetoothServiceInfoBleak]:
    """Connectable devices the developer actions should talk to.

    With an address, only that device (Level-looking or not). Without one,
    every configured lock Home Assistant can see, plus every connectable device
    that advertises a Level UUID or has "level" or "bolt" in its name (as
    tools/ble_probe.py --scan does).
    """
    if address:
        info = bluetooth.async_last_service_info(hass, address.upper(), connectable=True)
        if info is None:
            info = bluetooth.async_last_service_info(hass, address, connectable=True)
        return [info] if info else []
    targets: dict[str, BluetoothServiceInfoBleak] = {}
    for entry in hass.config_entries.async_entries(DOMAIN):
        info = async_find_lock(hass, entry.data.get(CONF_DEVICE) or {})
        if info is not None:
            targets.setdefault(info.address, info)
    for info in bluetooth.async_discovered_service_info(hass, connectable=True):
        if looks_like_level(info, use_name_hints=True):
            targets.setdefault(info.address, info)
    return list(targets.values())


@callback
def async_find_lock(hass: HomeAssistant, device: dict) -> BluetoothServiceInfoBleak | None:
    """The advertisement for one configured lock, or None if it can't be told apart.

    An advertised name equal to the lock's BLE or display name wins. Otherwise a
    device advertising a Level UUID is used only when it is the only one, so a
    second lock in range is never mistaken for this one.
    """
    names = {name for name in (device.get("ble_name"), device.get("name")) if name}
    candidates: list[BluetoothServiceInfoBleak] = []
    for info in bluetooth.async_discovered_service_info(hass, connectable=True):
        if info.name and info.name in names:
            return info
        if looks_like_level(info, use_name_hints=False):
            candidates.append(info)
    return candidates[0] if len(candidates) == 1 else None
