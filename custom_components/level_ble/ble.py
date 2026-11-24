"""BLE transport for Level locks.

Status: PROBE. The handshake is initiated (M1) and the lock's notifications are
captured, but the M2-M4 exchange and command encryption are not complete yet.

Run the level_ble.dump_gatt and level_ble.handshake actions (or
tools/ble_probe.py) near the lock to capture the real service map and the M2
payload; that is the last missing input for the session implementation.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import establish_connection
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .bixby import (
    BOLT_COMMANDS,
    VERSION_MISMATCH_RESULTS,
    BixbySession,
    KeyExchangeError,
    UserKeyExchange,
    bolt_payload,
    parse_bolt_payload,
)
from .const import (
    LEVEL_UUID_PREFIX,
    LEVEL_UUIDS,
    UUID_LEVEL_RX,
    UUID_LEVEL_SERVICE,
    UUID_LEVEL_TX,
    UUID_SERVICE_MAIN,
)
from .wire import (  # noqa: F401  (re-exported for tests and callers)
    FRAGMENT_FIRST,
    FRAGMENT_LAST,
    FRAGMENT_MIDDLE,
    FRAGMENT_SINGLE,
    VERSION_1,
    FragmentReassembler,
    bixby_user_m1,
    encode_message,
    frame_message,
)

_LOGGER = logging.getLogger(__name__)

HANDSHAKE_INFO_M2 = b"user-m2n"
HANDSHAKE_INFO_M3 = b"user-m3n"

# Which of the app's two protocol stacks to speak (see wire.py).
PROTOCOL_BIXBY = "bixby"  # binary messages, framed on FDBF (cloud-account locks)
PROTOCOL_SKYLINE = "skyline"  # protobuf co.level.Message, unframed
PROTOCOLS = (PROTOCOL_BIXBY, PROTOCOL_SKYLINE)


class LevelBleError(Exception):
    """The lock could not be reached or did not expose the expected GATT layout."""


# ---------------------------------------------------------------------------
# GATT helpers
# ---------------------------------------------------------------------------


def gatt_map(services: Iterable[Any]) -> list[dict]:
    """Service/characteristic table in a JSON-friendly shape."""
    return [
        {
            "service": service.uuid,
            "characteristics": [
                {"uuid": char.uuid, "handle": char.handle, "properties": list(char.properties)}
                for char in service.characteristics
            ],
        }
        for service in services
    ]


def _is_level_uuid(uuid: str) -> bool:
    uuid = uuid.lower()
    return uuid.startswith(LEVEL_UUID_PREFIX) or uuid in LEVEL_UUIDS


@dataclass
class LevelChannels:
    """Where to send messages and what to listen on."""

    write: Any | None
    notify: list[Any] = field(default_factory=list)
    # True for the FDBF transport, whose messages are split into fragments.
    framed: bool = False


def pick_characteristics(services: Iterable[Any]) -> LevelChannels:
    """Choose the command characteristic and the characteristics to subscribe to.

    Prefers the FDBF transport the Level app uses (write 0x0010, listen on
    0x0012). Older layouts fall back to 9161b202, then any writable 9161b20x
    characteristic. Notifications come from every Level characteristic that
    notifies or indicates (0x0012 first); if there are none, from every
    characteristic that does, so a capture does not miss the reply.
    """
    fdbf_tx = preferred = fallback = None
    level_notify: list[Any] = []
    any_notify: list[Any] = []
    for service in services:
        service_uuid = service.uuid.lower()
        for char in service.characteristics:
            uuid = char.uuid.lower()
            props = set(char.properties)
            if props & {"notify", "indicate"}:
                any_notify.append(char)
                if _is_level_uuid(uuid) or _is_level_uuid(service_uuid):
                    level_notify.append(char)
            if not props & {"write", "write-without-response"}:
                continue
            if service_uuid == UUID_LEVEL_SERVICE and uuid == UUID_LEVEL_TX:
                fdbf_tx = char
            elif uuid == UUID_SERVICE_MAIN:
                preferred = char
            elif uuid.startswith(LEVEL_UUID_PREFIX) and fallback is None:
                fallback = char
    notify = level_notify or any_notify
    notify.sort(key=lambda char: char.uuid.lower() != UUID_LEVEL_RX)
    if fdbf_tx is not None:
        return LevelChannels(fdbf_tx, notify, framed=True)
    return LevelChannels(preferred or fallback, notify)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class LevelSession:
    """User key exchange state machine (client side). One per connection."""

    def __init__(self) -> None:
        # Level's Bixby and Skyline stacks both use secp256k1 (app class kg3: ac5.SECP_256_K1).
        self._ephemeral = ec.generate_private_key(ec.SECP256K1())
        self.device_public_key: ec.EllipticCurvePublicKey | None = None
        self.shared_secret: bytes | None = None

    def m1(self, protocol: str = PROTOCOL_BIXBY) -> bytes:
        public = self._ephemeral.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        if protocol == PROTOCOL_BIXBY:
            return bixby_user_m1(public)  # 01 01 01 <33-byte key>
        # 08 01 7A 23 0A 21 <33-byte key>: Message{version=VERSION_1, userM1{key}} in protobuf.
        return encode_message({"version": VERSION_1, "userM1": {"userEphemeralEcPubkey33": public}})

    def handle_m2(self, message: dict) -> None:
        m2 = message.get("userM2") or {}
        device_pub = m2.get("deviceEphemeralEcPubkey33")
        cipher_text = m2.get("cipherText")
        if not device_pub or not cipher_text:
            raise ValueError("M2 missing ephemeral key or ciphertext")
        self.device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes(device_pub)
        )
        self.shared_secret = self._ephemeral.exchange(ec.ECDH(), self.device_public_key)
        _LOGGER.debug(
            "M2 received: shared secret %d bytes, ciphertext %d bytes",
            len(self.shared_secret),
            len(cipher_text),
        )

    # The Bixby user key exchange (M1-M4) lives in bixby.UserKeyExchange.


class LevelBleClient:
    """A single connection to a Level lock. Create a new one for every session."""

    def __init__(self, device: BLEDevice) -> None:
        self._device = device
        self._client: BleakClient | None = None
        self._session = LevelSession()
        self.notifications: list[tuple[str, bytes]] = []
        self.messages: list[tuple[str, bytes]] = []
        self.fragment_errors: list[str] = []
        self.subscribed: list[str] = []
        self.write_uuid: str | None = None
        self.framed = False
        self.protocol = PROTOCOL_BIXBY
        self.last_m1: bytes | None = None
        self.last_m3: bytes | None = None
        self._reassembler = FragmentReassembler()
        self._incoming: asyncio.Queue[bytes] = asyncio.Queue()
        self._write_char: Any = None

    @property
    def mtu_size(self) -> int | None:
        return self._client.mtu_size if self._client and self._client.is_connected else None

    def _on_disconnect(self, _client: BleakClient) -> None:
        _LOGGER.debug("%s disconnected", self._device.address)

    def _on_notify(self, sender: Any, data: bytearray) -> None:
        uuid = getattr(sender, "uuid", str(sender))
        raw = bytes(data)
        _LOGGER.debug("notification %s: %s", uuid, raw.hex())
        self.notifications.append((uuid, raw))
        if not self.framed:
            self.messages.append((uuid, raw))  # unframed layouts: one notification, one message
            self._incoming.put_nowait(raw)
            return
        if uuid.lower() != UUID_LEVEL_RX:
            return
        try:
            message = self._reassembler.feed(raw)
        except ValueError as exc:
            _LOGGER.debug("dropping fragment from %s: %s", uuid, exc)
            self.fragment_errors.append(str(exc))
            return
        if message is not None:
            self.messages.append((uuid, message))
            self._incoming.put_nowait(message)

    async def async_connect(self) -> BleakClient:
        if self._client is None or not self._client.is_connected:
            self._client = await establish_connection(
                BleakClient,
                self._device,
                self._device.name or self._device.address,
                disconnected_callback=self._on_disconnect,
            )
            for service in self._client.services:
                _LOGGER.debug("service %s", service.uuid)
                for char in service.characteristics:
                    _LOGGER.debug("  char %s props=%s", char.uuid, char.properties)
        return self._client

    async def async_disconnect(self) -> None:
        if self._client is not None and self._client.is_connected:
            await self._client.disconnect()

    async def async_dump(self) -> list[dict]:
        """Return the GATT map. Works even if Level's characteristics are absent."""
        client = await self.async_connect()
        return gatt_map(client.services)

    async def _async_open(self, protocol: str) -> BleakClient:
        """Connect, choose the characteristics and subscribe."""
        if protocol not in PROTOCOLS:
            raise ValueError(f"unknown protocol {protocol!r}")
        self.protocol = protocol
        client = await self.async_connect()
        channels = pick_characteristics(client.services)
        if channels.write is None:
            raise LevelBleError(
                "no writable Level characteristic (FDBF 0x0010 or 9161b20x); run level_ble.dump_gatt "
                "and share the result"
            )
        self._write_char = channels.write
        self.write_uuid = channels.write.uuid
        self.framed = channels.framed and protocol == PROTOCOL_BIXBY
        for char in channels.notify:
            try:
                await client.start_notify(char, self._on_notify)
            except (BleakError, ValueError) as exc:
                _LOGGER.debug("could not subscribe to %s: %s", char.uuid, exc)
            else:
                self.subscribed.append(char.uuid)
        return client

    async def _async_send(self, client: BleakClient, message: bytes) -> None:
        char = self._write_char
        writes = frame_message(message, client.mtu_size) if self.framed else [message]
        _LOGGER.debug("sending %d bytes in %d write(s) to %s", len(message), len(writes), char.uuid)
        for chunk in writes:
            await client.write_gatt_char(char, chunk, response="write" in char.properties)

    async def _async_receive(self, timeout: float) -> bytes:
        try:
            return await asyncio.wait_for(self._incoming.get(), timeout)
        except TimeoutError as exc:
            raise LevelBleError(f"the lock did not answer within {timeout:g} s") from exc

    async def async_start_session(self, protocol: str = PROTOCOL_BIXBY) -> bytes:
        """Capture mode: subscribe and send M1 with a throwaway key. Returns M1.

        Bixby messages are framed on the FDBF transport; Skyline (protobuf)
        messages are written as they are.
        """
        client = await self._async_open(protocol)
        m1 = self._session.m1(protocol)
        self.last_m1 = m1
        await self._async_send(client, m1)
        return m1

    async def async_user_key_exchange(self, exchange: UserKeyExchange, timeout: float) -> str:
        """Run the Bixby user key exchange M1-M4. Returns the lock's result code.

        Raises KeyExchangeError if the lock's M2 fails a check (wrong lock UUID
        or signature), and LevelBleError if the lock stops answering.
        """
        client = await self._async_open(PROTOCOL_BIXBY)
        self.last_m1 = exchange.m1()
        await self._async_send(client, self.last_m1)
        m3 = exchange.process_m2(await self._async_receive(timeout))
        self.last_m3 = m3
        await self._async_send(client, m3)
        return exchange.process_m4(await self._async_receive(timeout))

    async def _async_receive_response(
        self, session: BixbySession, request_id: int, timeout: float
    ) -> dict[str, Any]:
        """The next encrypted, unsigned response carrying this request ID."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            message = await self._async_receive(max(deadline - loop.time(), 0.001))
            try:
                response = session.parse_unsigned_response(session.decrypt(message))
            except ValueError as exc:
                _LOGGER.debug("skipping message %s: %s", message.hex(), exc)
                continue
            if response["request_id"] == request_id:
                return response
            _LOGGER.debug("skipping response to request %s", response["request_id"])

    async def async_operate_bolt(
        self, exchange: UserKeyExchange, unlock: bool, timeout: float
    ) -> dict[str, Any]:
        """Key exchange, then lock or unlock. Returns what the lock reported.

        Tries BoltControllerOperateV4, then V3, then V2, moving on only when the
        lock says the version doesn't fit (the app picks by firmware version,
        which this integration doesn't know yet).
        """
        result = await self.async_user_key_exchange(exchange, timeout)
        if result != "Success":
            raise KeyExchangeError(f"the lock answered the key exchange with {result}")
        session = exchange.session()
        client = self._client
        attempts: list[dict[str, Any]] = []
        for request_id, command in enumerate(BOLT_COMMANDS, start=1):
            await self._async_send(
                client, session.request(request_id, command, bolt_payload(command, unlock))
            )
            response = await self._async_receive_response(session, request_id, timeout)
            attempts.append({"command": command, "result": response["result"]})
            if response["result"] in VERSION_MISMATCH_RESULTS:
                continue
            return {
                "command": command,
                "result": response["result"],
                **parse_bolt_payload(response["payload"]),
                "attempts": attempts,
            }
        raise LevelBleError(f"the lock rejected every bolt command version: {attempts}")
