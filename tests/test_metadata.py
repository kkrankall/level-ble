"""Translations and action descriptions load the way Home Assistant loads them."""

from __future__ import annotations

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.helpers.service import async_get_all_descriptions
from homeassistant.helpers.translation import async_get_translations
from homeassistant.setup import async_setup_component

from custom_components.level_ble.const import DOMAIN

pytestmark = pytest.mark.usefixtures("enable_bluetooth")

ERRORS = {"invalid_auth", "cannot_connect", "tfa", "keychain_failed", "unknown"}
ABORTS = {"already_configured", "no_devices", "unknown_device"}


async def test_config_flow_strings(hass: HomeAssistant) -> None:
    strings = await async_get_translations(hass, "en", "config", [DOMAIN])
    prefix = f"component.{DOMAIN}.config"
    for key in ERRORS:
        assert f"{prefix}.error.{key}" in strings, key
    for key in ABORTS:
        assert f"{prefix}.abort.{key}" in strings, key


async def test_action_descriptions(hass: HomeAssistant) -> None:
    assert await async_setup_component(hass, DOMAIN, {})
    descriptions = (await async_get_all_descriptions(hass))[DOMAIN]
    assert set(descriptions) == {"dump_gatt", "handshake"}
    assert set(descriptions["handshake"]["fields"]) == {"address", "duration", "protocol"}

    strings = await async_get_translations(hass, "en", "services", [DOMAIN])
    prefix = f"component.{DOMAIN}.services"
    assert strings[f"{prefix}.dump_gatt.name"] == "Dump GATT"
    assert strings[f"{prefix}.handshake.fields.duration.name"] == "Duration"
