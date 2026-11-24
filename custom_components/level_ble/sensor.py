"""Sensors from the lock's state broadcast: battery level, last operation, signal strength."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import SIGNAL_STRENGTH_DECIBELS_MILLIWATT, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType

from .broadcast import OPERATION_SOURCES
from .entity import LevelConfigEntry, LevelEntity
from .monitor import LevelLockMonitor

# Level locks report a battery band, not a percentage.
BATTERY_LEVELS = {"GREEN": "good", "YELLOW": "low", "RED": "critical"}
OPERATION_SOURCE_STATES = {source: source.lower() for source in OPERATION_SOURCES if source != "UNKNOWN"}


@dataclass(frozen=True, kw_only=True)
class LevelSensorDescription(SensorEntityDescription):
    value: Callable[[LevelLockMonitor], StateType | datetime]


def _broadcast_value(read: Callable) -> Callable[[LevelLockMonitor], StateType | datetime]:
    return lambda monitor: read(monitor.broadcast) if monitor.broadcast else None


SENSORS = (
    LevelSensorDescription(
        key="battery_level",
        translation_key="battery_level",
        device_class=SensorDeviceClass.ENUM,
        options=list(BATTERY_LEVELS.values()),
        value=_broadcast_value(lambda b: BATTERY_LEVELS.get(b.battery)),
    ),
    LevelSensorDescription(
        key="last_operated",
        translation_key="last_operated",
        device_class=SensorDeviceClass.TIMESTAMP,
        value=_broadcast_value(lambda b: b.operated_at),
    ),
    LevelSensorDescription(
        key="last_operated_by",
        translation_key="last_operated_by",
        device_class=SensorDeviceClass.ENUM,
        options=list(OPERATION_SOURCE_STATES.values()),
        value=_broadcast_value(lambda b: OPERATION_SOURCE_STATES.get(b.operation_source)),
    ),
    LevelSensorDescription(
        key="signal_strength",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value=lambda monitor: monitor.rssi,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: LevelConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities(LevelSensor(entry, description) for description in SENSORS)


class LevelSensor(LevelEntity, SensorEntity):
    entity_description: LevelSensorDescription

    def __init__(self, entry: LevelConfigEntry, description: LevelSensorDescription) -> None:
        super().__init__(entry, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> StateType | datetime:
        return self.entity_description.value(self.monitor)
