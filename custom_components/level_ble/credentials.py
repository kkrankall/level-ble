"""Credentials for the Bixby key exchange, from a config entry."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .account import iter_devices
from .api import LevelCloud
from .bixby import load_private_key, load_public_key
from .const import CONF_ACCOUNT_UUID, CONF_DEVICE, CONF_PRIVATE_KEY, CONF_TOKEN

Credentials = tuple[UUID, Any, UUID, Any]


async def async_credentials(hass: HomeAssistant, entry: ConfigEntry) -> Credentials:
    """(account UUID, account key, lock UUID, lock key) for the user key exchange.

    Entries made before the account UUID was stored fetch it once from Level's
    cloud with the saved token and keep it.
    """
    data = entry.data
    device = data[CONF_DEVICE]
    account_uuid = data.get(CONF_ACCOUNT_UUID)
    public_key = device.get("public_key")
    if not account_uuid or not public_key:
        cloud = LevelCloud(async_get_clientsession(hass), token=data.get(CONF_TOKEN))
        account = await cloud.async_account()
        account_uuid = account_uuid or str(account.get("uuid") or "")
        if not public_key:
            match = next(
                (d for d in iter_devices(account) if d["uuid"].lower() == str(device["uuid"]).lower()),
                None,
            )
            public_key = match.get("public_key") if match else None
        if not account_uuid:
            raise ValueError("the Level account payload has no uuid")
        hass.config_entries.async_update_entry(
            entry,
            data={**data, CONF_ACCOUNT_UUID: account_uuid, CONF_DEVICE: {**device, "public_key": public_key}},
        )
    if not public_key:
        raise ValueError("Level's account data has no public key for this lock")
    return (
        UUID(str(account_uuid)),
        load_private_key(data[CONF_PRIVATE_KEY]),
        UUID(str(device["uuid"])),
        load_public_key(public_key),
    )
