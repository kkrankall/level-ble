"""Level cloud client and account parsing."""

from __future__ import annotations

import base64
import hashlib
import json

import aiohttp
import pytest
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.level_ble.api import (
    API_BASE,
    LevelAuthError,
    LevelCloud,
    LevelError,
    LevelTfaRequired,
    iter_devices,
)
from custom_components.level_ble.keychain import login_password

LOGIN = f"{API_BASE}/v2/login"
ACCOUNT = f"{API_BASE}/v2/account/get"


def _app_login_hash(password: str) -> str:
    """The app's b8d.a(): SHA-256 for i in 0..101 over UTF-8(password) + salt, then base64."""
    data = password.encode() + b"CFF33588-AC1D-4F77-943B-728CF61FCC1B"
    for _ in range(0, 101 + 1):
        data = hashlib.sha256(data).digest()
    return base64.b64encode(data).decode()


def test_login_password_is_salted_hash_not_password() -> None:
    sent = login_password("hunter2")
    assert sent == _app_login_hash("hunter2")
    assert len(sent) == 44 and sent.endswith("=")
    assert sent != base64.b64encode(b"hunter2").decode()
    assert login_password("pässwörd") == _app_login_hash("pässwörd")


def _cloud(hass: HomeAssistant) -> LevelCloud:
    return LevelCloud(async_get_clientsession(hass), email="a@b.c", password="pw")


async def test_login_reads_token_case_insensitively(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    aioclient_mock.post(LOGIN, json={"status": "ok"}, headers={"accesstoken": "tok"})
    aioclient_mock.get(ACCOUNT, json={"location": []})
    cloud = _cloud(hass)
    assert await cloud.async_login() == "tok"
    assert await cloud.async_account() == {"location": []}
    _, _, body, headers = aioclient_mock.mock_calls[0]
    assert json.loads(body) == {"userID": "a@b.c", "password": _app_login_hash("pw")}
    assert aioclient_mock.mock_calls[1][3]["AccessToken"] == "tok"


async def test_login_tfa_even_with_token(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    aioclient_mock.post(LOGIN, json={"status": "tfaRequired"}, headers={"AccessToken": "tok"})
    with pytest.raises(LevelTfaRequired):
        await _cloud(hass).async_login()


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"status": 401}, LevelAuthError),
        ({"status": 500, "text": "boom"}, LevelError),
        ({"text": "<html>not json</html>", "headers": {"AccessToken": "t"}}, LevelError),
        ({"json": {"status": "ok"}}, LevelAuthError),  # 200 but no token
        ({"json": {"status": ["loginFailed"]}}, LevelAuthError),  # what Level actually sends
        ({"json": {"status": ["tfaRequired"]}, "headers": {"AccessToken": "t"}}, LevelTfaRequired),
        ({"exc": aiohttp.ClientConnectionError()}, LevelError),
        ({"exc": TimeoutError()}, LevelError),
    ],
)
async def test_login_errors(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, kwargs: dict, error: type
) -> None:
    aioclient_mock.post(LOGIN, **kwargs)
    with pytest.raises(error):
        await _cloud(hass).async_login()


def test_iter_devices_app_schema() -> None:
    """Keys as in the app's Account / LocationItem / DeviceItem models (case-sensitive)."""
    account = {
        "uuid": "acct",
        "userID": "a@b.c",
        "blob": {},
        "encryptedBlobKeys": [],
        "Location": [
            {
                "CanonicalID": "c",
                "LocationUUID": "loc-1",
                "LocationName": "Cabin",
                "Time_zone": "America/New_York",
                "devicesDisplayOrder": ["u1"],
                "devices": [
                    {
                        "DeviceUUID": "u1",
                        "name": "Back Door",
                        "DeviceName": "A1B2C3D4",
                        "SerialNumber": "S1",
                        "Product": "LEVEL_BOLT",
                        "BoltState": "Locked",
                        "device_publicKey": "AgM=",
                        "AutoLockTimeout": 0,
                    },
                    {"DeviceName": "no uuid"},
                    "junk",
                ],
            },
            "junk",
        ],
    }
    assert iter_devices(account) == [
        {
            "uuid": "u1",
            "name": "Back Door",
            "ble_name": "A1B2C3D4",
            "location": "Cabin",
            "product": "LEVEL_BOLT",
            "serial": "S1",
            "public_key": "AgM=",
            "bolt_state": "Locked",
        }
    ]


def test_iter_devices_lowercase_regression() -> None:
    # Regression: the integration used to read only lower-case keys, so a real
    # account (capital "Location") produced no locks and setup aborted.
    assert iter_devices({"location": []}) == []
    assert iter_devices({"Location": [{"devices": [{"DeviceUUID": "x"}]}]})[0]["uuid"] == "x"


def test_iter_devices_lowercase_fallbacks() -> None:
    doc = {
        "locations": {"0": {"name": "Home", "device": [{"uuid": "u2", "name": "Front", "bleName": "LVL-9"}]}},
    }
    [device] = iter_devices(doc)
    assert device == {
        "uuid": "u2",
        "name": "Front",
        "ble_name": "LVL-9",
        "location": "Home",
        "product": None,
        "serial": None,
        "public_key": None,
        "bolt_state": None,
    }


def test_iter_devices_dedupes_and_handles_empty() -> None:
    loc = {"devices": [{"uuid": "x"}, {"uuid": "x"}]}
    assert len(iter_devices({"location": [loc, loc]})) == 1
    assert iter_devices({}) == []
