"""Base entity: one Level lock's device, fed by its LevelLockMonitor."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity

from .const import CONF_DEVICE, DOMAIN, MANUFACTURER, MODEL
from .monitor import LevelLockMonitor

type LevelConfigEntry = ConfigEntry[LevelLockMonitor]


class LevelEntity(Entity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry: LevelConfigEntry, key: str) -> None:
        device = entry.data[CONF_DEVICE]
        self._entry = entry
        self._device = device
        self.monitor = entry.runtime_data
        self._attr_unique_id = f"{device['uuid']}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device["uuid"])},
            manufacturer=MANUFACTURER,
            model=device.get("product") or MODEL,
            name=device["name"],
            serial_number=device.get("serial"),
            sw_version=self.monitor.firmware,
        )

    @property
    def available(self) -> bool:
        return self.monitor.available

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.monitor.async_add_listener(self._handle_monitor_update))

    @callback
    def _handle_monitor_update(self) -> None:
        self.async_write_ha_state()
