"""Lock entity and diagnostics."""

from __future__ import annotations

from unittest.mock import patch
from uuid import UUID

import pytest
from homeassistant.const import STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.components.diagnostics import (
    get_diagnostics_for_config_entry,
)

from custom_components.level_ble.bixby import load_private_key
from custom_components.level_ble.const import DOMAIN
from custom_components.level_ble.discovery import async_find_lock

from .conftest import (
    ACCOUNT_UUID,
    ENTRY_DATA,
    FDBF_GATT,
    LOCK_PRIVATE_HEX,
    LOCK_UUID,
    USER_PRIVATE_HEX,
    FakeBleakClient,
    service_info,
)
from .fake_lock import FakeLock

pytestmark = pytest.mark.usefixtures("enable_bluetooth")

DISCOVERY = "custom_components.level_ble.discovery.bluetooth.async_discovered_service_info"


@pytest.fixture
async def entry(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(domain=DOMAIN, unique_id=LOCK_UUID, data=ENTRY_DATA, title="Front Door")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def _entity_id(hass: HomeAssistant) -> str:
    entity_id = er.async_get(hass).async_get_entity_id("lock", DOMAIN, f"{LOCK_UUID}_lock")
    assert entity_id
    return entity_id


async def test_entity_named_after_device_with_unknown_state(hass: HomeAssistant, entry) -> None:
    state = hass.states.get(_entity_id(hass))
    assert state.state == STATE_UNKNOWN  # no stale cloud snapshot
    assert state.attributes["friendly_name"] == "Front Door"


def _simulated_lock(**kwargs) -> FakeLock:
    user_public = load_private_key(USER_PRIVATE_HEX).public_key()
    return FakeLock(UUID(LOCK_UUID), LOCK_PRIVATE_HEX, UUID(ACCOUNT_UUID), user_public, **kwargs)


async def _press(hass: HomeAssistant, service: str) -> None:
    with patch(DISCOVERY, return_value=[service_info()]):
        await hass.services.async_call("lock", service, {"entity_id": _entity_id(hass)}, blocking=True)


async def test_unlock_then_lock(hass: HomeAssistant, entry, fake_ble) -> None:
    lock = _simulated_lock(bolt_locked=True)
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, responder=lock.on_write)
    await _press(hass, "unlock")
    state = hass.states.get(_entity_id(hass))
    assert state.state == "unlocked"
    assert state.attributes["last_result"] == "Success"
    assert state.attributes["last_bolt_state"] == "RETRACTED"
    assert state.attributes["last_command_version"] == 88
    request = lock.requests[0]
    assert (request["request_id"], request["command"], request["payload"]) == (1, 88, b"\x00\x02\x00")

    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, responder=lock.on_write)
    await _press(hass, "lock")
    assert hass.states.get(_entity_id(hass)).state == "locked"
    assert lock.requests[-1]["payload"] == b"\x01\x02\x00"
    assert fake_ble.state["client"].disconnect.await_count == 1


async def test_older_firmware_falls_back_to_v3(hass: HomeAssistant, entry, fake_ble) -> None:
    lock = _simulated_lock(supported_commands=frozenset({54}))
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, responder=lock.on_write)
    await _press(hass, "unlock")
    assert [r["command"] for r in lock.requests] == [88, 54]
    assert [r["request_id"] for r in lock.requests] == [1, 2]
    assert lock.requests[1]["payload"] == b"\x00\x02"  # V3 has no flags byte
    state = hass.states.get(_entity_id(hass))
    assert state.state == "unlocked"
    assert state.attributes["last_command_version"] == 54


async def test_bolt_failure_is_reported(hass: HomeAssistant, entry, fake_ble) -> None:
    lock = _simulated_lock(operation_result=8, bolt_locked=True)  # DOOR_OPEN
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, responder=lock.on_write)
    with pytest.raises(HomeAssistantError, match="DOOR_OPEN"):
        await _press(hass, "unlock")
    state = hass.states.get(_entity_id(hass))
    assert state.state == "locked"  # the lock reported the bolt still extended
    assert state.attributes["last_operation_result"] == "DOOR_OPEN"


async def test_impostor_lock_gets_no_command(hass: HomeAssistant, entry, fake_ble) -> None:
    lock = _simulated_lock(signing_key_hex="33" * 32)
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, responder=lock.on_write)
    with pytest.raises(HomeAssistantError, match="signature"):
        await _press(hass, "unlock")
    assert lock.requests == []
    assert len(fake_ble.state["client"].writes) == 1  # only M1
    assert hass.states.get(_entity_id(hass)).state == STATE_UNKNOWN


async def test_out_of_range(hass: HomeAssistant, entry, fake_ble) -> None:
    with patch(DISCOVERY, return_value=[]), pytest.raises(HomeAssistantError, match="not in Bluetooth range"):
        await hass.services.async_call("lock", "lock", {"entity_id": _entity_id(hass)}, blocking=True)
    fake_ble.connect.assert_not_called()


async def test_unload(hass: HomeAssistant, entry) -> None:
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert hass.services.has_service(DOMAIN, "dump_gatt")  # actions outlive entries


async def test_find_lock_prefers_name_and_refuses_to_guess(hass: HomeAssistant) -> None:
    device = ENTRY_DATA["device"]
    mine = service_info("AA:00:00:00:00:01", name="LEVEL-1234")
    level_uuid = ["9161b202-1b4b-4727-a3ca-47b35cdcf5c1"]
    other_a = service_info("AA:00:00:00:00:02", name="x", service_uuids=level_uuid)
    other_b = service_info("AA:00:00:00:00:03", name="y", service_uuids=level_uuid)

    with patch(DISCOVERY, return_value=[other_a, mine]):
        assert async_find_lock(hass, device) is mine
    with patch(DISCOVERY, return_value=[other_a]):
        assert async_find_lock(hass, device) is other_a  # only Level device in range
    with patch(DISCOVERY, return_value=[other_a, other_b]):
        assert async_find_lock(hass, device) is None  # two locks: don't guess
    with patch(DISCOVERY, return_value=[service_info(name="Level Speaker")]):
        assert async_find_lock(hass, device) is None  # name hints alone don't count


async def test_diagnostics_redacts_secrets(hass: HomeAssistant, entry, hass_client) -> None:
    with patch(DISCOVERY, return_value=[service_info()]):
        diag = await get_diagnostics_for_config_entry(hass, hass_client, entry)
    flat = repr(diag)
    for secret in ("token-abc", "11" * 32, "user@example.com", "SN123", LOCK_UUID, ACCOUNT_UUID):
        assert secret.lower() not in flat.lower()
    assert diag["entry"]["device"]["name"] == "Front Door"
    assert diag["matched_advertisement"]["address"] == "AA:BB:CC:DD:EE:01"
    assert diag["matched_advertisement"]["manufacturer_data"] == {"4660": "0102"}
