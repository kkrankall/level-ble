"""Developer actions: dump_gatt and handshake."""

from __future__ import annotations

from unittest.mock import patch
from uuid import UUID

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.level_ble.bixby import load_private_key
from custom_components.level_ble.ble import (
    FRAGMENT_FIRST,
    FRAGMENT_LAST,
    FRAGMENT_MIDDLE,
    FRAGMENT_SINGLE,
    frame_message,
)
from custom_components.level_ble.const import (
    DOMAIN,
    UUID_LEVEL_ADVERTISEMENT,
    UUID_SERVICE_MAIN,
    UUID_SERVICE_NOTIFY,
)
from custom_components.level_ble.wire import VERSION_1, decode_bixby, encode_message

from .conftest import (
    ACCOUNT_UUID,
    ENTRY_DATA,
    FDBF_GATT,
    LOCK_ADDRESS,
    LOCK_PRIVATE_HEX,
    LOCK_UUID,
    USER_PRIVATE_HEX,
    FakeBleakClient,
    gatt,
    service_info,
)
from .fake_lock import FakeLock, state_broadcast

pytestmark = pytest.mark.usefixtures("enable_bluetooth")

DISCOVERY = "custom_components.level_ble.discovery.bluetooth"


@pytest.fixture
async def setup(hass: HomeAssistant) -> None:
    assert await async_setup_component(hass, DOMAIN, {})
    await hass.async_block_till_done()


def _visible(*infos):
    by_address = {i.address: i for i in infos}
    return (
        patch(f"{DISCOVERY}.async_discovered_service_info", return_value=list(infos)),
        patch(
            f"{DISCOVERY}.async_last_service_info",
            side_effect=lambda hass, address, connectable: by_address.get(address),
        ),
    )


async def _call(hass: HomeAssistant, service: str, data: dict | None = None):
    return await hass.services.async_call(DOMAIN, service, data or {}, blocking=True, return_response=True)


@pytest.mark.usefixtures("setup")
async def test_services_registered_without_config_entry(hass: HomeAssistant) -> None:
    assert hass.services.has_service(DOMAIN, "dump_gatt")
    assert hass.services.has_service(DOMAIN, "handshake")


@pytest.mark.usefixtures("setup")
async def test_dump_gatt(hass: HomeAssistant, fake_ble) -> None:
    other = service_info("11:22:33:44:55:66", name="Some Speaker")
    a, b = _visible(service_info(), other)
    with a, b:
        response = await _call(hass, "dump_gatt")
    [device] = response["devices"]  # the speaker is not Level-looking
    assert device["address"] == LOCK_ADDRESS
    assert device["source"] == "esphome-proxy"
    assert device["mtu"] == 247
    uuids = [c["uuid"] for s in device["services"] for c in s["characteristics"]]
    assert UUID_SERVICE_MAIN in uuids
    fake_ble.state["client"].disconnect.assert_awaited()


@pytest.mark.usefixtures("setup")
async def test_dump_gatt_works_without_level_characteristics(hass: HomeAssistant, fake_ble) -> None:
    # Regression: dump_gatt used to fail exactly when the map was unknown.
    fake_ble.state["client"] = FakeBleakClient(gatt(("1234", [("abcd", ["read", "notify"])])))
    a, b = _visible(service_info())
    with a, b:
        response = await _call(hass, "dump_gatt")
    [device] = response["devices"]
    assert "error" not in device
    assert device["services"][0]["characteristics"][0]["uuid"] == "abcd"


@pytest.mark.usefixtures("setup")
async def test_dump_gatt_by_address_reports_connect_errors(hass: HomeAssistant, fake_ble) -> None:
    from bleak.exc import BleakError

    fake_ble.connect.side_effect = BleakError("out of slots")
    target = service_info("11:22:33:44:55:66", name="Unnamed")
    a, b = _visible(target)
    with a, b:
        response = await _call(hass, "dump_gatt", {"address": "11:22:33:44:55:66"})
    [device] = response["devices"]
    assert "out of slots" in device["error"]


@pytest.mark.usefixtures("setup")
async def test_handshake_captures_notifications(hass: HomeAssistant, fake_ble) -> None:
    reply = encode_message({"version": VERSION_1, "userM2": {"deviceEphemeralEcPubkey33": b"\x02" * 33}})
    fake_ble.state["client"] = FakeBleakClient(
        fake_ble.state["client"].services, replies=[reply, b"\x01\x02"]
    )
    a, b = _visible(service_info())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1})

    client = fake_ble.state["client"]
    [(written_uuid, m1, with_response)] = client.writes
    assert written_uuid == UUID_SERVICE_MAIN
    assert with_response is True
    assert response["write_uuid"] == UUID_SERVICE_MAIN
    assert response["subscribed"] == [UUID_SERVICE_NOTIFY]
    assert response["m1_hex"] == m1.hex()
    sent = decode_bixby(m1)  # default protocol: Bixby binary M1
    assert (sent["channel"], sent["version"], sent["message"]) == ("USER_KEY_EXCHANGE", "V2_0", "M1")
    assert len(sent["payload"]) == 33
    assert response["framed"] is False
    assert response["notifications"] == [
        {"uuid": UUID_SERVICE_NOTIFY, "hex": reply.hex()},
        {"uuid": UUID_SERVICE_NOTIFY, "hex": "0102"},
    ]
    first, second = response["messages"]  # unframed: each notification is a message
    assert first["message"] == {"version": VERSION_1, "userM2": {"deviceEphemeralEcPubkey33": "02" * 33}}
    assert second == {"uuid": UUID_SERVICE_NOTIFY, "hex": "0102"}
    assert "error" not in response
    client.disconnect.assert_awaited()


@pytest.mark.usefixtures("setup")
async def test_handshake_without_command_char_returns_error(hass: HomeAssistant, fake_ble) -> None:
    fake_ble.state["client"] = FakeBleakClient(gatt(("1234", [("abcd", ["notify"])])))
    a, b = _visible(service_info())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1})
    assert "no writable Level" in response["error"]
    assert response["m1_hex"] is None


@pytest.mark.usefixtures("setup")
async def test_handshake_ambiguous_needs_address(hass: HomeAssistant, fake_ble) -> None:
    a, b = _visible(service_info(), service_info("AA:BB:CC:DD:EE:02", name="Level Bolt"))
    with a, b, pytest.raises(ServiceValidationError, match="pass an address"):
        await _call(hass, "handshake")
    fake_ble.connect.assert_not_called()


@pytest.mark.usefixtures("setup")
@pytest.mark.parametrize("data", [{}, {"address": "00:00:00:00:00:00"}])
async def test_nothing_visible(hass: HomeAssistant, fake_ble, data: dict) -> None:
    a, b = _visible()
    with a, b, pytest.raises(ServiceValidationError):
        await _call(hass, "dump_gatt", data)


@pytest.mark.usefixtures("setup")
async def test_handshake_duration_is_validated(hass: HomeAssistant) -> None:
    import voluptuous as vol

    with pytest.raises(vol.Invalid):
        await _call(hass, "handshake", {"duration": 600})


# Shaped like a real Level lock: an ID-like name, no "level"/"bolt" in it, and
# only the 16-bit FDBF service (as UUID and service data), not the 9161b20x UUIDs.
REAL_ADDRESS = "C0:FF:EE:00:00:01"
REAL_NAME = "A1B2C3D4"


def _real_lock(*, uuids: bool = True, data: bool = True):
    return service_info(
        REAL_ADDRESS,
        name=REAL_NAME,
        service_uuids=[UUID_LEVEL_ADVERTISEMENT] if uuids else None,
        service_data={UUID_LEVEL_ADVERTISEMENT: state_broadcast(UUID(LOCK_UUID))} if data else None,
    )


@pytest.mark.usefixtures("setup")
@pytest.mark.parametrize(("uuids", "data"), [(True, False), (False, True)])
async def test_capture_finds_lock_by_fdbf(hass: HomeAssistant, fake_ble, uuids: bool, data: bool) -> None:
    # Regression: the real lock matched no Level UUID or name hint, so the
    # actions said no Level lock was visible unless given an address.
    a, b = _visible(_real_lock(uuids=uuids, data=data), service_info("11:22:33:44:55:66", name="Speaker"))
    with a, b:
        response = await _call(hass, "dump_gatt")
    assert [d["address"] for d in response["devices"]] == [REAL_ADDRESS]


@pytest.mark.usefixtures("setup")
async def test_capture_includes_configured_lock_by_name(hass: HomeAssistant, fake_ble) -> None:
    data = {**ENTRY_DATA, "device": {**ENTRY_DATA["device"], "ble_name": REAL_NAME}}
    MockConfigEntry(domain=DOMAIN, unique_id="lock-uuid", data=data).add_to_hass(hass)
    a, b = _visible(_real_lock(uuids=False, data=False))  # nothing Level-looking but the name
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1, "protocol": "skyline"})
    assert response["address"] == REAL_ADDRESS
    assert response["mode"] == "capture"
    assert "error" not in response


@pytest.mark.usefixtures("setup")
async def test_configured_lock_listed_once(hass: HomeAssistant, fake_ble) -> None:
    data = {**ENTRY_DATA, "device": {**ENTRY_DATA["device"], "ble_name": REAL_NAME}}
    MockConfigEntry(domain=DOMAIN, unique_id="lock-uuid", data=data).add_to_hass(hass)
    a, b = _visible(_real_lock())  # matches by name and by FDBF
    with a, b:
        response = await _call(hass, "dump_gatt")
    assert [d["address"] for d in response["devices"]] == [REAL_ADDRESS]


TX = "00000010-0000-1000-8000-00805f9b34fb"
RX = "00000012-0000-1000-8000-00805f9b34fb"


@pytest.mark.usefixtures("setup")
async def test_handshake_on_fdbf_transport(hass: HomeAssistant, fake_ble) -> None:
    """The real lock's layout: framed M1 to 0x0010, framed reply reassembled from 0x0012."""
    reply = encode_message(
        {
            "version": VERSION_1,
            "userM2": {"deviceEphemeralEcPubkey33": b"\x02" * 33, "cipherText": b"\x07" * 150},
        }
    )
    fragments = frame_message(reply, 64)  # several fragments
    assert len(fragments) > 2
    noise = ("00000011-0000-1000-8000-00805f9b34fb", b"\x99")
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, replies=[noise] + [(RX, f) for f in fragments])
    a, b = _visible(_real_lock())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1})

    client = fake_ble.state["client"]
    [(written_uuid, fragment, with_response)] = client.writes  # ~100 bytes: one fragment at MTU 247
    assert written_uuid == TX
    assert with_response is True
    assert fragment[0] == FRAGMENT_SINGLE
    assert fragment[1:].hex() == response["m1_hex"]
    assert response["write_uuid"] == TX
    assert response["framed"] is True
    assert response["subscribed"][0] == RX
    assert "0000001d-0000-1000-8000-0026bb765291" not in response["subscribed"]  # HomeKit left alone
    [message] = response["messages"]
    assert message["uuid"] == RX
    assert message["message"]["userM2"]["cipherText"] == "07" * 150
    assert len(response["notifications"]) == len(fragments) + 1
    assert "fragment_errors" not in response
    assert "error" not in response


@pytest.mark.usefixtures("setup")
async def test_handshake_fragments_m1_at_small_mtu(hass: HomeAssistant, fake_ble) -> None:
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, mtu=40)  # 35 payload bytes per write
    a, b = _visible(_real_lock())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1})
    writes = fake_ble.state["client"].writes
    assert [w[1][0] for w in writes] == [FRAGMENT_FIRST] + [FRAGMENT_MIDDLE] * (len(writes) - 2) + [
        FRAGMENT_LAST
    ]
    assert all(len(w[1]) <= 36 for w in writes)
    assert b"".join(w[1][1:] for w in writes).hex() == response["m1_hex"]


@pytest.mark.usefixtures("setup")
async def test_handshake_reports_bad_fragments(hass: HomeAssistant, fake_ble) -> None:
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, replies=[(RX, bytes([FRAGMENT_LAST, 1, 2]))])
    a, b = _visible(_real_lock())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1})
    assert response["messages"] == []
    assert response["fragment_errors"] == ["unexpected fragment type 0x36 after start"]


def _bixby_m2(key: bytes) -> bytes:
    return bytes([1, 1, 2]) + bytes(range(80)) + key  # USER_KEY_EXCHANGE, V2_0, M2


@pytest.mark.usefixtures("setup")
async def test_handshake_bixby_default_on_real_lock(hass: HomeAssistant, fake_ble) -> None:
    """Default protocol: 01 01 01 <key> framed on 0x0010; a Bixby M2 reply is labelled."""
    lock_key = bytes([0x03]) + bytes(range(32))
    reply = _bixby_m2(lock_key)
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, replies=[(RX, f) for f in frame_message(reply, 64)])
    a, b = _visible(_real_lock())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1})

    [(uuid, fragment, _)] = fake_ble.state["client"].writes
    assert uuid == TX
    assert fragment[:4] == bytes([FRAGMENT_SINGLE, 0x01, 0x01, 0x01])
    assert len(fragment) == 1 + 3 + 33
    assert fragment[1:].hex() == response["m1_hex"]
    assert response["protocol"] == "bixby"
    assert response["framed"] is True
    [message] = response["messages"]
    bixby = message["bixby"]
    assert (bixby["channel"], bixby["version"], bixby["message"]) == ("USER_KEY_EXCHANGE", "V2_0", "M2")
    assert bixby["deviceEphemeralEcPubkey33"] == lock_key.hex()
    assert bixby["sealed"] == bytes(range(80)).hex()


@pytest.mark.usefixtures("setup")
async def test_handshake_skyline_option_sends_unframed_protobuf(hass: HomeAssistant, fake_ble) -> None:
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, replies=[(RX, b"\x08\x01")])
    a, b = _visible(_real_lock())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1, "protocol": "skyline"})
    [(uuid, data, _)] = fake_ble.state["client"].writes
    assert uuid == TX
    assert data[:6] == bytes([0x08, 0x01, 0x7A, 0x23, 0x0A, 0x21])  # no fragment header
    assert response["protocol"] == "skyline"
    assert response["framed"] is False
    assert response["messages"] == [{"uuid": RX, "hex": "0801", "message": {"version": VERSION_1}}]


@pytest.mark.usefixtures("setup")
async def test_handshake_rejects_unknown_protocol(hass: HomeAssistant) -> None:
    import voluptuous as vol

    with pytest.raises(vol.Invalid):
        await _call(hass, "handshake", {"protocol": "matter"})


def _front_door_entry(hass: HomeAssistant, **device_overrides) -> MockConfigEntry:
    data = {**ENTRY_DATA, "device": {**ENTRY_DATA["device"], "ble_name": REAL_NAME, **device_overrides}}
    entry = MockConfigEntry(domain=DOMAIN, unique_id=ENTRY_DATA["device"]["uuid"], data=data)
    entry.add_to_hass(hass)
    return entry


def _simulated_lock(**kwargs) -> FakeLock:
    user_public = load_private_key(USER_PRIVATE_HEX).public_key()
    return FakeLock(UUID(LOCK_UUID), LOCK_PRIVATE_HEX, UUID(ACCOUNT_UUID), user_public, **kwargs)


@pytest.mark.usefixtures("setup")
async def test_handshake_runs_full_key_exchange(hass: HomeAssistant, fake_ble) -> None:
    _front_door_entry(hass)
    lock = _simulated_lock()
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, responder=lock.on_write)
    a, b = _visible(_real_lock())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 2})

    assert "error" not in response, response.get("error")
    assert response["mode"] == "key_exchange"
    assert response["key_exchange"] == {
        "lock_uuid": LOCK_UUID,
        "lock_uuid_matches": True,
        "lock_signature_valid": True,
        "m3_hex": response["key_exchange"]["m3_hex"],
        "result": "Success",
        "session_established": True,
    }
    assert lock.accepted is True
    writes = fake_ble.state["client"].writes
    assert [len(w[1]) for w in writes] == [1 + 36, 1 + 83]  # M1 and M3, one fragment each
    assert [m["bixby"]["message"] for m in response["messages"]] == ["M2", "M4"]
    assert response["messages"][1]["bixby"]["result"] == "Success"


@pytest.mark.usefixtures("setup")
async def test_handshake_stops_when_lock_is_an_impostor(hass: HomeAssistant, fake_ble) -> None:
    _front_door_entry(hass)
    lock = _simulated_lock(signing_key_hex="33" * 32)
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, responder=lock.on_write)
    a, b = _visible(_real_lock())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 2})
    assert "signature" in response["error"]
    assert response["key_exchange"]["lock_signature_valid"] is False
    assert response["key_exchange"]["m3_hex"] is None
    assert len(fake_ble.state["client"].writes) == 1  # no M3 sent


@pytest.mark.usefixtures("setup")
async def test_handshake_times_out_without_m2(hass: HomeAssistant, fake_ble) -> None:
    _front_door_entry(hass)
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT)
    a, b = _visible(_real_lock())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1})
    assert response["mode"] == "key_exchange"
    assert "did not answer" in response["error"]


@pytest.mark.usefixtures("setup")
async def test_older_entry_fetches_account_uuid_once(hass: HomeAssistant, fake_ble) -> None:
    entry = _front_door_entry(hass)
    data = dict(entry.data)
    del data["account_uuid"]
    hass.config_entries.async_update_entry(entry, data=data)
    lock = _simulated_lock()
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT, responder=lock.on_write)
    account = {"uuid": ACCOUNT_UUID, "Location": []}
    a, b = _visible(_real_lock())
    with (
        a,
        b,
        patch(
            "custom_components.level_ble.credentials.LevelCloud.async_account", return_value=account
        ) as fetch,
    ):
        response = await _call(hass, "handshake", {"duration": 2})
    assert response["key_exchange"]["session_established"] is True
    assert entry.data["account_uuid"] == ACCOUNT_UUID
    fetch.assert_awaited_once()


@pytest.mark.usefixtures("setup")
async def test_credentials_error_falls_back_to_capture(hass: HomeAssistant, fake_ble) -> None:
    _front_door_entry(hass, public_key="not a key!")
    fake_ble.state["client"] = FakeBleakClient(FDBF_GATT)
    a, b = _visible(_real_lock())
    with a, b:
        response = await _call(hass, "handshake", {"duration": 1})
    assert response["mode"] == "capture"
    assert "neither hex nor base64" in response["credentials_error"]
