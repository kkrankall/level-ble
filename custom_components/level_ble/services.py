"""Developer actions: GATT dump and the Bixby handshake, through Home Assistant's proxy stack."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from uuid import UUID

import voluptuous as vol
from bleak.exc import BleakError
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv

from .api import LevelError
from .bixby import KeyExchangeError, UserKeyExchange
from .ble import PROTOCOL_BIXBY, PROTOCOLS, LevelBleClient, LevelBleError
from .const import CONF_DEVICE, DOMAIN
from .credentials import Credentials, async_credentials
from .discovery import async_capture_targets, async_find_lock
from .wire import decode_bixby, decode_message

_LOGGER = logging.getLogger(__name__)

SERVICE_DUMP_GATT = "dump_gatt"
SERVICE_HANDSHAKE = "handshake"
ATTR_ADDRESS = "address"
ATTR_DURATION = "duration"
ATTR_PROTOCOL = "protocol"
DEFAULT_DURATION = 10

DUMP_GATT_SCHEMA = vol.Schema({vol.Optional(ATTR_ADDRESS): cv.string})
HANDSHAKE_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_ADDRESS): cv.string,
        vol.Optional(ATTR_DURATION, default=DEFAULT_DURATION): vol.All(
            vol.Coerce(int), vol.Range(min=1, max=60)
        ),
        vol.Optional(ATTR_PROTOCOL, default=PROTOCOL_BIXBY): vol.In(PROTOCOLS),
    }
)

# Errors worth reporting in the response instead of failing the whole action,
# so a partial capture still comes back.
CAPTURE_ERRORS = (BleakError, LevelBleError, KeyExchangeError, TimeoutError, ValueError)


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _describe(info: BluetoothServiceInfoBleak) -> dict[str, Any]:
    return {
        "address": info.address,
        "name": info.name,
        "rssi": info.rssi,
        "source": info.source,
        "service_uuids": list(info.service_uuids or []),
        "manufacturer_data": {str(k): v.hex() for k, v in (info.manufacturer_data or {}).items()},
    }


def _no_targets(address: str | None) -> ServiceValidationError:
    if address:
        return ServiceValidationError(
            f"{address} is not a connectable Bluetooth device Home Assistant has seen recently"
        )
    return ServiceValidationError(
        "No Level lock is visible to Home Assistant Bluetooth. Check that the proxy is "
        "online and the lock is awake, or pass its address."
    )


def _decode_notification(uuid: str, raw: bytes) -> dict[str, Any]:
    entry: dict[str, Any] = {"uuid": uuid, "hex": raw.hex()}
    try:
        entry["bixby"] = _jsonable(decode_bixby(raw))
    except ValueError:
        pass  # Not a Bixby message header.
    try:
        entry["message"] = _jsonable(decode_message(raw))
    except ValueError:
        pass  # Not a protobuf co.level.Message.
    return entry


async def _dump_gatt(info: BluetoothServiceInfoBleak) -> dict[str, Any]:
    result = _describe(info)
    client = LevelBleClient(info.device)
    try:
        result["services"] = await client.async_dump()
        result["mtu"] = client.mtu_size
    except CAPTURE_ERRORS as exc:
        result["error"] = repr(exc)
    finally:
        await client.async_disconnect()
    return result


@callback
def _entry_for(hass: HomeAssistant, info: BluetoothServiceInfoBleak) -> ConfigEntry | None:
    """The config entry whose lock is this advertisement, if any."""
    for entry in hass.config_entries.async_entries(DOMAIN):
        found = async_find_lock(hass, entry.data.get(CONF_DEVICE) or {})
        if found is not None and found.address == info.address:
            return entry
    return None


async def _handshake(
    info: BluetoothServiceInfoBleak,
    duration: int,
    protocol: str,
    credentials: Credentials | None = None,
) -> dict[str, Any]:
    """Full Bixby user key exchange when credentials are given, else send M1 and listen."""
    result = _describe(info)
    client = LevelBleClient(info.device)
    exchange: UserKeyExchange | None = None
    lock_uuid: UUID | None = None
    try:
        if credentials is not None:
            user_uuid, user_key, lock_uuid, lock_key = credentials
            exchange = UserKeyExchange(
                user_uuid, user_key, lambda uuid: lock_key if uuid == lock_uuid else None
            )
            result["mode"] = "key_exchange"
            await client.async_user_key_exchange(exchange, duration)
        else:
            result["mode"] = "capture"
            await client.async_start_session(protocol)
            await asyncio.sleep(duration)
    except CAPTURE_ERRORS as exc:
        result["error"] = repr(exc)
    finally:
        result["mtu"] = client.mtu_size
        await client.async_disconnect()
    if exchange is not None:
        result["key_exchange"] = {
            "lock_uuid": str(exchange.lock_uuid) if exchange.lock_uuid else None,
            "lock_uuid_matches": exchange.lock_uuid == lock_uuid if exchange.lock_uuid else None,
            "lock_signature_valid": exchange.lock_signature_valid,
            "m3_hex": client.last_m3.hex() if client.last_m3 else None,
            "result": exchange.result,
            "session_established": exchange.result == "Success",
        }
    result["write_uuid"] = client.write_uuid
    result["protocol"] = client.protocol
    result["framed"] = client.framed
    result["subscribed"] = client.subscribed
    result["m1_hex"] = client.last_m1.hex() if client.last_m1 else None
    result["notifications"] = [{"uuid": u, "hex": raw.hex()} for u, raw in client.notifications]
    # Whole messages put back together from the FDBF fragments, decoded (Bixby, protobuf) where they parse.
    result["messages"] = [_decode_notification(u, raw) for u, raw in client.messages]
    if client.fragment_errors:
        result["fragment_errors"] = client.fragment_errors
    return result


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the developer actions (once per Home Assistant start)."""

    async def dump_gatt(call: ServiceCall) -> ServiceResponse:
        address = call.data.get(ATTR_ADDRESS)
        targets = async_capture_targets(hass, address)
        if not targets:
            raise _no_targets(address)
        return {"devices": [await _dump_gatt(info) for info in targets]}

    async def handshake(call: ServiceCall) -> ServiceResponse:
        address = call.data.get(ATTR_ADDRESS)
        targets = async_capture_targets(hass, address)
        if not targets:
            raise _no_targets(address)
        if len(targets) > 1:
            found = ", ".join(f"{i.address} ({i.name})" for i in targets)
            raise ServiceValidationError(
                f"More than one possible Level lock is visible ({found}); pass an address"
            )
        info = targets[0]
        protocol = call.data[ATTR_PROTOCOL]
        entry = _entry_for(hass, info) if protocol == PROTOCOL_BIXBY else None
        credentials = None
        credentials_error = None
        if entry is not None:
            try:
                credentials = await async_credentials(hass, entry)
            except (LevelError, ValueError, KeyError) as exc:
                credentials_error = repr(exc)
        result = await _handshake(info, call.data[ATTR_DURATION], protocol, credentials)
        if credentials_error:
            result["credentials_error"] = credentials_error
        return result

    hass.services.async_register(
        DOMAIN,
        SERVICE_DUMP_GATT,
        dump_gatt,
        schema=DUMP_GATT_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_HANDSHAKE,
        handshake,
        schema=HANDSHAKE_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
