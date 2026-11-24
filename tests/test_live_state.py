"""Live state from the lock's advertisements: lock, battery, firmware, signal strength."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

import pytest
from homeassistant.components.bluetooth import BluetoothChange
from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_fire_time_changed
from pytest_homeassistant_custom_component.components.diagnostics import (
    get_diagnostics_for_config_entry,
)

from custom_components.level_ble.const import DOMAIN, UUID_LEVEL_ADVERTISEMENT

from .conftest import ENTRY_DATA, FDBF_GATT, LOCK_ADDRESS, LOCK_UUID, FakeBleakClient, service_info
from .fake_lock import state_broadcast
from .test_lock import _press, _simulated_lock

pytestmark = pytest.mark.usefixtures("enable_bluetooth")

MONITOR = "custom_components.level_ble.monitor.bluetooth"
DISCOVERY = "custom_components.level_ble.discovery.bluetooth.async_discovered_service_info"


@pytest.fixture
def radio():
    """Capture the callbacks the monitor registers with Home Assistant's Bluetooth."""
    radio = SimpleNamespace(advertisement=None, matcher=None, unavailable=None, tracked=None, last=None)

    def register(hass, callback, matcher, mode):
        radio.advertisement, radio.matcher = callback, matcher
        return lambda: None

    def track(hass, callback, address, connectable=True):
        radio.unavailable, radio.tracked = callback, (address, connectable)
        return lambda: None

    with (
        patch(f"{MONITOR}.async_register_callback", side_effect=register),
        patch(f"{MONITOR}.async_track_unavailable", side_effect=track),
        patch(f"{MONITOR}.async_last_service_info", side_effect=lambda *a, **kw: radio.last),
    ):
        yield radio


@pytest.fixture
async def entry(hass: HomeAssistant, radio) -> MockConfigEntry:
    entry = MockConfigEntry(domain=DOMAIN, unique_id=LOCK_UUID, data=ENTRY_DATA, title="Front Door")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def _device(hass: HomeAssistant, entry: MockConfigEntry) -> dr.DeviceEntry:
    (device,) = dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
    assert (DOMAIN, LOCK_UUID) in device.identifiers
    return device


def _id(hass: HomeAssistant, domain: str, key: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id(domain, DOMAIN, f"{LOCK_UUID}_{key}")
    assert entity_id, (domain, key)
    return entity_id


def _state(hass: HomeAssistant, domain: str, key: str):
    return hass.states.get(_id(hass, domain, key))


async def _advertise(
    hass: HomeAssistant,
    radio,
    *,
    address: str = LOCK_ADDRESS,
    name: str = "LEVEL-1234",
    rssi: int = -60,
    **fields,
) -> None:
    data = state_broadcast(UUID(LOCK_UUID), **fields)
    info = service_info(address, name, service_data={UUID_LEVEL_ADVERTISEMENT: data}, rssi=rssi)
    radio.advertisement(info, BluetoothChange.ADVERTISEMENT)
    await hass.async_block_till_done()


async def test_listens_for_level_service_data(hass: HomeAssistant, entry, radio) -> None:
    assert radio.matcher == {"service_data_uuid": UUID_LEVEL_ADVERTISEMENT, "connectable": False}


async def test_before_the_lock_is_heard(hass: HomeAssistant, entry) -> None:
    lock = _state(hass, "lock", "lock")
    assert lock.state == STATE_UNKNOWN  # still usable: a command can find the lock
    for domain, key in [
        ("sensor", "battery_level"),
        ("sensor", "signal_strength"),
        ("binary_sensor", "battery_low"),
    ]:
        assert _state(hass, domain, key).state == STATE_UNAVAILABLE


async def test_broadcast_fills_everything(hass: HomeAssistant, entry, radio) -> None:
    await _advertise(hass, radio, bolt=1, battery=3, source=14, sequence=10, timestamp=328851621, rssi=-71)

    lock = _state(hass, "lock", "lock")
    assert lock.state == "locked"
    assert lock.attributes["changed_by"] == "Keypad"
    assert _state(hass, "sensor", "battery_level").state == "good"
    assert _state(hass, "binary_sensor", "battery_low").state == "off"
    assert _state(hass, "sensor", "last_operated").state == "2026-11-24T03:40:21+00:00"
    assert _state(hass, "sensor", "last_operated_by").state == "keypad"
    signal = _state(hass, "sensor", "signal_strength")
    assert (signal.state, signal.attributes["unit_of_measurement"]) == ("-71", "dBm")
    assert radio.tracked == (LOCK_ADDRESS, False)

    device = _device(hass, entry)
    assert device.sw_version == "2.30"
    # No door sense on this lock, so no door sensor.
    assert er.async_get(hass).async_get_entity_id("binary_sensor", DOMAIN, f"{LOCK_UUID}_door") is None


async def test_thumb_turn_and_jam(hass: HomeAssistant, entry, radio) -> None:
    await _advertise(hass, radio, bolt=1, sequence=10)
    await _advertise(hass, radio, bolt=0, sequence=11, source=1)
    lock = _state(hass, "lock", "lock")
    assert (lock.state, lock.attributes["changed_by"]) == ("unlocked", "Manual")

    await _advertise(hass, radio, bolt=2, sequence=12, source=5, result=2)
    assert _state(hass, "lock", "lock").state == "jammed"


@pytest.mark.parametrize(
    ("battery", "level", "low"), [(2, "low", "on"), (1, "critical", "on"), (0, STATE_UNKNOWN, STATE_UNKNOWN)]
)
async def test_battery(hass: HomeAssistant, entry, radio, battery: int, level: str, low: str) -> None:
    await _advertise(hass, radio, battery=battery)
    assert _state(hass, "sensor", "battery_level").state == level
    assert _state(hass, "binary_sensor", "battery_low").state == low


async def test_door_sensor_appears_with_door_sense(hass: HomeAssistant, entry, radio) -> None:
    await _advertise(hass, radio, door=1)
    assert _state(hass, "binary_sensor", "door").state == "on"
    await _advertise(hass, radio, door=2, sequence=1396)
    assert _state(hass, "binary_sensor", "door").state == "off"
    await _advertise(hass, radio, door=3, sequence=1397)  # not calibrated
    assert _state(hass, "binary_sensor", "door").state == STATE_UNKNOWN


async def test_stale_clock(hass: HomeAssistant, entry, radio) -> None:
    await _advertise(hass, radio, time_stale=1)
    assert _state(hass, "sensor", "last_operated").state == STATE_UNKNOWN


async def test_other_level_lock_is_ignored(hass: HomeAssistant, entry, radio) -> None:
    await _advertise(hass, radio, address="AA:BB:CC:DD:EE:99", name="OTHER-LOCK", bolt=0)
    assert _state(hass, "lock", "lock").state == STATE_UNKNOWN
    assert _state(hass, "sensor", "battery_level").state == STATE_UNAVAILABLE


async def test_learned_address_is_followed_without_a_name(hass: HomeAssistant, entry, radio) -> None:
    await _advertise(hass, radio, bolt=1, sequence=10)
    await _advertise(hass, radio, name="", bolt=0, sequence=11)  # scan response without the name
    assert _state(hass, "lock", "lock").state == "unlocked"


async def test_out_of_range_and_back(hass: HomeAssistant, entry, radio) -> None:
    await _advertise(hass, radio)
    radio.unavailable(service_info())
    await hass.async_block_till_done()
    assert _state(hass, "lock", "lock").state == STATE_UNAVAILABLE
    assert _state(hass, "sensor", "signal_strength").state == STATE_UNAVAILABLE

    await _advertise(hass, radio, bolt=0, sequence=1396)
    assert _state(hass, "lock", "lock").state == "unlocked"
    assert _state(hass, "sensor", "battery_level").state == "good"


async def test_firmware_update_reaches_the_device(hass: HomeAssistant, entry, radio) -> None:
    await _advertise(hass, radio, firmware=(2, 30))
    await _advertise(hass, radio, firmware=(2, 31), sequence=1396)
    device = _device(hass, entry)
    assert device.sw_version == "2.31"


async def test_signal_strength_refreshes(hass: HomeAssistant, entry, radio) -> None:
    await _advertise(hass, radio, rssi=-60)
    radio.last = service_info(rssi=-82)
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=61))
    await hass.async_block_till_done()
    assert _state(hass, "sensor", "signal_strength").state == "-82"


async def test_known_lock_at_startup(hass: HomeAssistant, radio) -> None:
    """A lock Home Assistant already heard is shown as soon as the entry loads."""
    data = state_broadcast(UUID(LOCK_UUID), bolt=0)
    seen = service_info(service_data={UUID_LEVEL_ADVERTISEMENT: data})
    entry = MockConfigEntry(domain=DOMAIN, unique_id=LOCK_UUID, data=ENTRY_DATA, title="Front Door")
    entry.add_to_hass(hass)
    with patch(
        "custom_components.level_ble.discovery.bluetooth.async_discovered_service_info", return_value=[seen]
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    assert _state(hass, "lock", "lock").state == "unlocked"
    device = _device(hass, entry)
    assert device.sw_version == "2.30"


async def test_old_broadcast_does_not_undo_a_command(hass: HomeAssistant, entry, radio, fake_ble) -> None:
    await _advertise(hass, radio, bolt=1, sequence=20)
    assert _state(hass, "lock", "lock").state == "locked"

    lock = _simulated_lock(bolt_locked=True)
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, responder=lock.on_write)
    await _press(hass, "unlock")
    assert _state(hass, "lock", "lock").state == "unlocked"

    await _advertise(hass, radio, bolt=1, sequence=20)  # repeated from before the command
    assert _state(hass, "lock", "lock").state == "unlocked"
    await _advertise(hass, radio, bolt=1, sequence=22, source=1)  # locked by hand afterwards
    assert _state(hass, "lock", "lock").state == "locked"


async def test_diagnostics_show_the_broadcast(hass: HomeAssistant, entry, radio, hass_client) -> None:
    await _advertise(hass, radio, rssi=-64)
    diagnostics = await get_diagnostics_for_config_entry(hass, hass_client, entry)
    monitor = diagnostics["monitor"]
    assert (monitor["address"], monitor["available"], monitor["rssi"]) == (LOCK_ADDRESS, True, -64)
    assert monitor["broadcast"]["bolt_state"] == "EXTENDED"
    assert monitor["broadcast"]["firmware"] == "2.30"
