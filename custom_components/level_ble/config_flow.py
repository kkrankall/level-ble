"""Config flow: Level cloud login, keychain unlock, lock selection."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .account import iter_devices
from .api import LevelAuthError, LevelCloud, LevelError, LevelTfaRequired
from .const import CONF_ACCOUNT_UUID, CONF_DEVICE, CONF_PRIVATE_KEY, CONF_TOKEN, DOMAIN
from .keychain import KeychainError, unlock_account

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema({vol.Required(CONF_EMAIL): str, vol.Required(CONF_PASSWORD): str})


async def _validate(hass: HomeAssistant, email: str, password: str) -> tuple[str, bytes, list[dict], str]:
    cloud = LevelCloud(async_get_clientsession(hass), email=email, password=password)
    token = await cloud.async_login()
    account = await cloud.async_account()
    private_key, keychain = await hass.async_add_executor_job(unlock_account, account, password)
    # The lock list may live in the REST payload or in the decrypted keychain.
    devices = iter_devices(account) or iter_devices(keychain)
    return token, private_key, devices, str(account.get("uuid") or "")


class LevelBleConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._email: str | None = None
        self._token: str | None = None
        self._private_key: bytes | None = None
        self._devices: list[dict] = []
        self._account_uuid: str | None = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            email = user_input[CONF_EMAIL].strip()
            try:
                token, private_key, devices, account_uuid = await _validate(
                    self.hass, email, user_input[CONF_PASSWORD]
                )
            except LevelTfaRequired:
                errors["base"] = "tfa"
            except LevelAuthError:
                errors["base"] = "invalid_auth"
            except KeychainError as exc:
                _LOGGER.warning("Signed in to Level but could not unlock the keychain: %s", exc)
                errors["base"] = "keychain_failed"
            except LevelError as exc:
                _LOGGER.warning("Level login failed: %s", exc)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during Level login")
                errors["base"] = "unknown"
            else:
                if not devices:
                    return self.async_abort(reason="no_devices")
                self._email = email
                self._token = token
                self._private_key = private_key
                self._devices = devices
                self._account_uuid = account_uuid
                if len(devices) == 1:
                    return await self._async_create(devices[0])
                return await self.async_step_device()

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                STEP_USER_SCHEMA, {CONF_EMAIL: (user_input or {}).get(CONF_EMAIL, "")}
            ),
            errors=errors,
        )

    async def async_step_device(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            chosen = next((d for d in self._devices if d["uuid"] == user_input[CONF_DEVICE]), None)
            if chosen is None:
                return self.async_abort(reason="unknown_device")
            return await self._async_create(chosen)

        configured = self._async_current_ids(include_ignore=False)
        options = {
            d["uuid"]: f"{d['name']} ({d['location']}) - {d.get('serial') or d['uuid']}"
            for d in self._devices
            if d["uuid"] not in configured
        }
        if not options:
            return self.async_abort(reason="already_configured")
        return self.async_show_form(
            step_id="device",
            data_schema=vol.Schema({vol.Required(CONF_DEVICE): vol.In(options)}),
        )

    async def _async_create(self, device: dict) -> ConfigFlowResult:
        await self.async_set_unique_id(device["uuid"])
        self._abort_if_unique_id_configured()

        public_key = device.get("public_key")
        if isinstance(public_key, (bytes, bytearray)):
            public_key = bytes(public_key).hex()

        data = {
            CONF_EMAIL: self._email,
            CONF_TOKEN: self._token,
            CONF_PRIVATE_KEY: self._private_key.hex() if self._private_key else None,
            CONF_ACCOUNT_UUID: self._account_uuid or None,
            CONF_DEVICE: {
                "uuid": device["uuid"],
                "name": device["name"],
                "ble_name": device.get("ble_name"),
                "location": device["location"],
                "product": str(device.get("product") or ""),
                "serial": device.get("serial"),
                "public_key": public_key,
                "bolt_state": str(device.get("bolt_state") or ""),
            },
        }
        return self.async_create_entry(title=device["name"], data=data)
