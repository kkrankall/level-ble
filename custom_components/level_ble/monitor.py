"""Follow one lock's advertisements: live state, battery, firmware, signal strength."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import UUID

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import (
    BluetoothCallbackMatcher,
    BluetoothChange,
    BluetoothScanningMode,
    BluetoothServiceInfoBleak,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.event import async_track_time_interval

from .broadcast import LockBroadcast, decode_broadcast
from .const import CONF_DEVICE, DOMAIN, UUID_LEVEL_ADVERTISEMENT
from .discovery import async_find_lock

_LOGGER = logging.getLogger(__name__)

# Home Assistant only passes on advertisements whose data changed, so the
# signal strength is also read from its latest advertisement on this interval.
RSSI_INTERVAL = timedelta(seconds=60)


class LevelLockMonitor:
    """Decodes this lock's state broadcasts and tells the entities when they change."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry_id = entry.entry_id
        self.device: dict = entry.data[CONF_DEVICE]
        self.lock_uuid = UUID(str(self.device["uuid"]))
        self.address: str | None = None
        self.broadcast: LockBroadcast | None = None
        self.rssi: int | None = None
        self.available = False
        self._listeners: list[Callable[[], None]] = []
        self._cancel_unavailable: CALLBACK_TYPE | None = None

    @property
    def firmware(self) -> str | None:
        return self.broadcast.firmware if self.broadcast else None

    @callback
    def async_add_listener(self, update: Callable[[], None]) -> CALLBACK_TYPE:
        self._listeners.append(update)

        @callback
        def remove() -> None:
            self._listeners.remove(update)

        return remove

    @callback
    def _async_notify(self) -> None:
        for update in list(self._listeners):
            update()

    @callback
    def async_start(self) -> CALLBACK_TYPE:
        """Start listening; the returned callback stops it."""
        cancels = [
            bluetooth.async_register_callback(
                self.hass,
                self._async_on_advertisement,
                BluetoothCallbackMatcher(service_data_uuid=UUID_LEVEL_ADVERTISEMENT, connectable=False),
                BluetoothScanningMode.PASSIVE,
            ),
            async_track_time_interval(self.hass, self._async_refresh_rssi, RSSI_INTERVAL),
        ]
        # Start from what Home Assistant has already seen, if the lock is in range.
        info = async_find_lock(self.hass, self.device)
        if info is not None:
            self._async_on_advertisement(info, BluetoothChange.ADVERTISEMENT)

        @callback
        def stop() -> None:
            for cancel in cancels:
                cancel()
            if self._cancel_unavailable is not None:
                self._cancel_unavailable()
                self._cancel_unavailable = None

        return stop

    @callback
    def _is_this_lock(self, info: BluetoothServiceInfoBleak) -> bool:
        if info.address == self.address:
            return True
        names = {name for name in (self.device.get("ble_name"), self.device.get("name")) if name}
        if info.name and info.name in names:
            return True
        found = async_find_lock(self.hass, self.device)
        return found is not None and found.address == info.address

    @callback
    def _async_on_advertisement(self, info: BluetoothServiceInfoBleak, change: BluetoothChange) -> None:
        data = (info.service_data or {}).get(UUID_LEVEL_ADVERTISEMENT)
        if data is None or not self._is_this_lock(info):
            return
        if info.address != self.address:
            self.address = info.address
            self._async_track_unavailable()
        decoded = decode_broadcast(self.lock_uuid, data)
        if decoded is not None:
            if decoded.firmware != self.firmware:
                self._async_update_firmware(decoded.firmware)
            if decoded != self.broadcast:
                _LOGGER.debug("%s broadcast: %s", self.device.get("name"), decoded)
            self.broadcast = decoded
        self.rssi = info.rssi
        self.available = True
        self._async_notify()

    @callback
    def _async_track_unavailable(self) -> None:
        if self._cancel_unavailable is not None:
            self._cancel_unavailable()
        assert self.address is not None
        self._cancel_unavailable = bluetooth.async_track_unavailable(
            self.hass, self._async_on_unavailable, self.address, connectable=False
        )

    @callback
    def _async_on_unavailable(self, info: BluetoothServiceInfoBleak) -> None:
        self.available = False
        self._async_notify()

    @callback
    def _async_refresh_rssi(self, now: datetime) -> None:
        if not self.available or self.address is None:
            return
        info = bluetooth.async_last_service_info(self.hass, self.address, connectable=False)
        if info is not None and info.rssi != self.rssi:
            self.rssi = info.rssi
            self._async_notify()

    @callback
    def _async_update_firmware(self, firmware: str) -> None:
        registry = dr.async_get(self.hass)
        identifier = (DOMAIN, str(self.device["uuid"]))
        for device in dr.async_entries_for_config_entry(registry, self.entry_id):
            if identifier in device.identifiers and device.sw_version != firmware:
                registry.async_update_device(device.id, sw_version=firmware)
