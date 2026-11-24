"""Level BLE integration."""

from __future__ import annotations

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN
from .entity import LevelConfigEntry
from .monitor import LevelLockMonitor
from .services import async_setup_services

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.LOCK, Platform.SENSOR]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the developer actions, which work with or without a config entry."""
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: LevelConfigEntry) -> bool:
    """Follow the lock's advertisements, then set up its entities."""
    monitor = LevelLockMonitor(hass, entry)
    entry.runtime_data = monitor
    entry.async_on_unload(monitor.async_start())
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: LevelConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
