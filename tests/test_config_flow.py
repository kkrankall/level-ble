"""Config flow."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.level_ble.api import LevelAuthError, LevelError, LevelTfaRequired
from custom_components.level_ble.const import DOMAIN
from custom_components.level_ble.keychain import KeychainError

pytestmark = pytest.mark.usefixtures("enable_bluetooth")

USER_INPUT = {"email": " user@example.com ", "password": "pw"}
PRIVATE_KEY = bytes(range(32))


def _account(*devices: dict) -> dict:
    return {"Location": [{"LocationName": "Home", "LocationUUID": "loc-1", "devices": list(devices)}]}


LOCK_A = {
    "DeviceUUID": "uuid-a",
    "name": "Front",
    "DeviceName": "A1B2C3D4",
    "SerialNumber": "SA",
    "device_publicKey": "AgM=",
}
LOCK_B = {"DeviceUUID": "uuid-b", "DeviceName": "Back", "SerialNumber": "SB"}


def _patch_cloud(
    account: dict | None = None,
    *,
    login_error: Exception | None = None,
    unlock_error: Exception | None = None,
    keychain_doc: dict | None = None,
):
    login = AsyncMock(return_value="tok", side_effect=login_error)
    unlock = (
        patch("custom_components.level_ble.config_flow.unlock_account", side_effect=unlock_error)
        if unlock_error
        else patch(
            "custom_components.level_ble.config_flow.unlock_account",
            return_value=(PRIVATE_KEY, keychain_doc or {}),
        )
    )
    return (
        patch("custom_components.level_ble.config_flow.LevelCloud.async_login", login),
        patch(
            "custom_components.level_ble.config_flow.LevelCloud.async_account",
            AsyncMock(return_value=account if account is not None else _account(LOCK_A)),
        ),
        unlock,
        patch("custom_components.level_ble.async_setup_entry", return_value=True),
    )


async def _start(hass: HomeAssistant):
    return await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})


async def test_single_lock_creates_entry(hass: HomeAssistant) -> None:
    result = await _start(hass)
    assert result["type"] is FlowResultType.FORM
    p1, p2, p3, p4 = _patch_cloud()
    with p1, p2, p3, p4:
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Front"
    assert result["result"].unique_id == "uuid-a"
    data = result["data"]
    assert data["email"] == "user@example.com"
    assert data["token"] == "tok"
    assert data["private_key"] == PRIVATE_KEY.hex()
    assert "password" not in data
    assert data["device"]["public_key"] == "AgM="
    assert data["device"]["name"] == "Front"
    assert data["device"]["ble_name"] == "A1B2C3D4"
    assert data["device"]["serial"] == "SA"


async def test_multiple_locks_ask_which(hass: HomeAssistant) -> None:
    MockConfigEntry(domain=DOMAIN, unique_id="uuid-c").add_to_hass(hass)
    lock_c = {"DeviceUUID": "uuid-c", "DeviceName": "Garage"}
    result = await _start(hass)
    p1, p2, p3, p4 = _patch_cloud(_account(LOCK_A, LOCK_B, lock_c))
    with p1, p2, p3, p4:
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "device"
        options = result["data_schema"].schema["device"].container
        assert set(options) == {"uuid-a", "uuid-b"}  # already-configured lock hidden
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {"device": "uuid-b"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Back"


async def test_devices_from_keychain_when_rest_has_none(hass: HomeAssistant) -> None:
    keychain_doc = {
        "locations": [{"name": "Home", "device": [{"uuid": "uuid-k", "name": "Side", "bleName": "L-1"}]}]
    }
    result = await _start(hass)
    p1, p2, p3, p4 = _patch_cloud({"location": []}, keychain_doc=keychain_doc)
    with p1, p2, p3, p4:
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"]["device"]["ble_name"] == "L-1"


@pytest.mark.parametrize(
    ("login_error", "unlock_error", "error"),
    [
        (LevelAuthError("nope"), None, "invalid_auth"),
        (LevelTfaRequired("otp"), None, "tfa"),
        (LevelError("down"), None, "cannot_connect"),
        (None, KeychainError("bad blob"), "keychain_failed"),
        (RuntimeError("surprise"), None, "unknown"),
    ],
)
async def test_errors_then_recover(
    hass: HomeAssistant, login_error: Exception | None, unlock_error: Exception | None, error: str
) -> None:
    result = await _start(hass)
    p1, p2, p3, p4 = _patch_cloud(login_error=login_error, unlock_error=unlock_error)
    with p1, p2, p3, p4:
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    p1, p2, p3, p4 = _patch_cloud()
    with p1, p2, p3, p4:
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_no_locks_aborts(hass: HomeAssistant) -> None:
    result = await _start(hass)
    p1, p2, p3, p4 = _patch_cloud({"location": []})
    with p1, p2, p3, p4:
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_devices"


async def test_already_configured(hass: HomeAssistant) -> None:
    MockConfigEntry(domain=DOMAIN, unique_id="uuid-a").add_to_hass(hass)
    result = await _start(hass)
    p1, p2, p3, p4 = _patch_cloud()
    with p1, p2, p3, p4:
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
