"""Binary sensors from the lock's state broadcast: low battery and, where fitted, the door."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .entity import LevelConfigEntry, LevelEntity

LOW_BATTERY = {"GREEN": False, "YELLOW": True, "RED": True}
DOOR_OPEN = {"DOOR_OPEN": True, "DOOR_CLOSED": False}


async def async_setup_entry(
    hass: HomeAssistant, entry: LevelConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    monitor = entry.runtime_data
    async_add_entities([LevelLowBattery(entry)])

    # Only locks with door sense get a door sensor; the lock says so in its broadcast.
    door_added = False

    @callback
    def _add_door_when_supported() -> None:
        nonlocal door_added
        if not door_added and monitor.broadcast and monitor.broadcast.door != "NOT_SUPPORTED":
            door_added = True
            async_add_entities([LevelDoor(entry)])

    _add_door_when_supported()
    entry.async_on_unload(monitor.async_add_listener(_add_door_when_supported))


class LevelLowBattery(LevelEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.BATTERY

    def __init__(self, entry: LevelConfigEntry) -> None:
        super().__init__(entry, "battery_low")

    @property
    def is_on(self) -> bool | None:
        broadcast = self.monitor.broadcast
        return LOW_BATTERY.get(broadcast.battery) if broadcast else None


class LevelDoor(LevelEntity, BinarySensorEntity):
    """Level's door sense: unknown until it is calibrated in the Level app."""

    _attr_device_class = BinarySensorDeviceClass.DOOR

    def __init__(self, entry: LevelConfigEntry) -> None:
        super().__init__(entry, "door")

    @property
    def is_on(self) -> bool | None:
        broadcast = self.monitor.broadcast
        return DOOR_OPEN.get(broadcast.door) if broadcast else None
