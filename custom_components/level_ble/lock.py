"""Lock platform: lock and unlock over Level's own BLE protocol (Bixby).

The state between commands comes from the lock's own state broadcast (see
broadcast.py), so turning the thumb turn or using the keypad shows up too.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from bleak.exc import BleakError
from homeassistant.components.lock import LockEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import LevelError
from .bixby import KeyExchangeError, UserKeyExchange
from .ble import LevelBleClient, LevelBleError
from .credentials import async_credentials
from .discovery import async_find_lock
from .entity import LevelConfigEntry, LevelEntity

_LOGGER = logging.getLogger(__name__)

STEP_TIMEOUT = 10  # seconds to wait for each reply from the lock
OK_OPERATION_RESULTS = {"SUCCESS", "ALREADY_THERE"}
LOCKED_STATES = {"EXTENDED": True, "RETRACTED": False}

# Who last moved the bolt, as the lock reports it. BLE covers both the Level
# app and Home Assistant: the lock can't tell them apart.
CHANGED_BY = {
    "MANUAL": "Manual",
    "BLE": "Bluetooth",
    "HOME_KIT": "HomeKit",
    "CONSOLE": "Console",
    "AUTO_LOCK": "Auto-lock",
    "MATTER": "Matter",
    "APPROACH_TO_UNLOCK": "Approach to unlock",
    "NFC": "NFC",
    "ZIGBEE": "Zigbee",
    "TOUCH": "Touch",
    "REMOTE": "Remote",
    "RING": "Ring",
    "ALEXA": "Alexa",
    "KEYPAD": "Keypad",
    "GOOGLE": "Google",
}


async def async_setup_entry(
    hass: HomeAssistant, entry: LevelConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities([LevelBleLock(entry)])


class LevelBleLock(LevelEntity, LockEntity):
    _attr_name = None

    def __init__(self, entry: LevelConfigEntry) -> None:
        super().__init__(entry, "lock")
        # Unknown until the lock's broadcast or a command reports the bolt
        # position. The cloud's boltState from setup time would go stale.
        self._attr_is_locked = None
        self._last_operation: dict[str, Any] = {}
        self._busy = asyncio.Lock()
        self._seen: tuple[int, str] | None = None
        self._apply_broadcast()

    @property
    def available(self) -> bool:
        # Before the lock has been heard at all, commands may still find it.
        return self.monitor.available or self.monitor.address is None

    def _set_bolt_state(self, bolt_state: str, default: bool | None = None) -> None:
        """PARTIAL (the bolt stopped part way) is jammed, neither locked nor unlocked."""
        self._attr_is_jammed = bolt_state == "PARTIAL"
        self._attr_is_locked = None if self._attr_is_jammed else LOCKED_STATES.get(bolt_state, default)

    def _apply_broadcast(self) -> None:
        """Take the bolt position from a new broadcast, unless a command is running."""
        broadcast = self.monitor.broadcast
        if broadcast is None or (broadcast.sequence_id, broadcast.bolt_state) == self._seen:
            return
        self._seen = (broadcast.sequence_id, broadcast.bolt_state)
        self._attr_changed_by = CHANGED_BY.get(broadcast.operation_source)
        if not self._busy.locked():
            self._set_bolt_state(broadcast.bolt_state)

    @callback
    def _handle_monitor_update(self) -> None:
        self._apply_broadcast()
        self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {f"last_{key}": value for key, value in self._last_operation.items()}

    async def async_lock(self, **kwargs: Any) -> None:
        await self._async_command(unlock=False)

    async def async_unlock(self, **kwargs: Any) -> None:
        await self._async_command(unlock=True)

    async def _async_command(self, *, unlock: bool) -> None:
        action = "unlock" if unlock else "lock"
        name = self._device["name"]
        async with self._busy:  # one BLE session at a time
            info = async_find_lock(self.hass, self._device)
            if info is None:
                raise HomeAssistantError(
                    f"{name} is not in Bluetooth range, or more than one Level lock is and it "
                    "can't tell which; check the ESPHome proxy"
                )
            try:
                user_uuid, user_key, lock_uuid, lock_key = await async_credentials(self.hass, self._entry)
            except (LevelError, ValueError, KeyError) as exc:
                raise HomeAssistantError(f"Missing Level credentials for {name}: {exc}") from exc

            exchange = UserKeyExchange(
                user_uuid, user_key, lambda uuid: lock_key if uuid == lock_uuid else None
            )
            client = LevelBleClient(info.device)
            if unlock:
                self._attr_is_unlocking = True
            else:
                self._attr_is_locking = True
            self.async_write_ha_state()
            try:
                report = await client.async_operate_bolt(exchange, unlock, STEP_TIMEOUT)
            except (BleakError, LevelBleError, KeyExchangeError, TimeoutError) as exc:
                raise HomeAssistantError(f"Could not {action} {name}: {exc}") from exc
            finally:
                self._attr_is_unlocking = False
                self._attr_is_locking = False
                await client.async_disconnect()
                self.async_write_ha_state()

            _LOGGER.debug("%s %s: %s", name, action, report)
            self._last_operation = {
                "operation": action,
                "result": report.get("result"),
                "operation_result": report.get("operation_result"),
                "bolt_state": report.get("bolt_state"),
                "command_version": report.get("command"),
            }
            if report.get("result") != "Success":
                self.async_write_ha_state()
                raise HomeAssistantError(f"{name} refused to {action}: {report.get('result')}")
            operation_result = report.get("operation_result")
            if operation_result is not None and operation_result not in OK_OPERATION_RESULTS:
                self._set_bolt_state(str(report.get("bolt_state")))
                self.async_write_ha_state()
                raise HomeAssistantError(f"{name} could not {action}: {operation_result}")
            self._set_bolt_state(str(report.get("bolt_state")), not unlock)
            self.async_write_ha_state()
