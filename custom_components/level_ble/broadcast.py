"""Level's state broadcast: the FDBF service data every Level lock advertises.

The lock puts its state in every advertisement, so Home Assistant can follow
it without connecting. Layout, from co.level.app 2.5.0.56 (co.level.bixby.k and
the StateBroadcastPayload serializer), checked against a real lock:

    [fw major][fw minor][flags][state, 2 bytes][nonce byte][extension, 7 bytes]

The state and the extension are encrypted with ChaCha20 (8-byte nonce, the
same nonce for both) under a key derived from the lock's UUID alone, so only
someone who knows that UUID can read them. Keep real lock UUIDs out of logs,
issues and tests.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .bixby import BOLT_STATES, OPERATION_RESULTS, chacha20_8

BROADCAST_LENGTH = 13
BROADCAST_SALT = b"Bixby"
BROADCAST_INFO = b"State-Broadcast-Key-Default-Info"
BROADCAST_NONCE = b"BSE-N-01"  # byte 3 is replaced by the advertised nonce byte

# The app rejects service data starting with 4 (a different payload).
_OTHER_PAYLOAD = 4

# Level's own epoch for lock timestamps (the app's Instant.fromEpochSeconds(1466640000)).
LEVEL_EPOCH = datetime(2016, 6, 23, tzinfo=UTC)

BATTERY_LEVELS = ("UNKNOWN", "RED", "YELLOW", "GREEN")
DOOR_STATES = ("NOT_SUPPORTED", "DOOR_OPEN", "DOOR_CLOSED", "NOT_CALIBRATED")
OPERATION_SOURCES = (
    "UNKNOWN",
    "MANUAL",
    "BLE",
    "HOME_KIT",
    "CONSOLE",
    "AUTO_LOCK",
    "MATTER",
    "APPROACH_TO_UNLOCK",
    "NFC",
    "ZIGBEE",
    "TOUCH",
    "REMOTE",
    "RING",
    "ALEXA",
    "KEYPAD",
    "GOOGLE",
)
PRODUCTS = (
    "APOLLO",
    "GEMINI",
    "LINUS",
    "JUNO",
    "SETI",
    "GEMINIHK",
    "STARGATE",
    "GEMINI_MATTER",
    "MAVEN_MATTER",
    "APOLLO_MATTER",
    "LINUS_MATTER",
)

_EXTENSION = struct.Struct("<HIB")  # sequence ID, timestamp, result | source << 4


def _name(table: tuple[str, ...], index: int) -> str:
    return table[index] if index < len(table) else str(index)


@dataclass(frozen=True, slots=True)
class LockBroadcast:
    """One decoded state broadcast."""

    firmware: str
    owned: bool
    homekit_paired: bool
    product: str
    sidewalk_provisioned: bool
    sidewalk_registered: bool
    bolt_state: str
    battery: str
    door: str
    time_stale: bool
    sequence_id: int
    operated_at: datetime | None  # None when the lock says its clock is stale
    operation_result: str
    operation_source: str


@lru_cache(maxsize=16)
def broadcast_key(lock_uuid: UUID) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=BROADCAST_SALT,
        info=BROADCAST_INFO,
    ).derive(lock_uuid.bytes)


def broadcast_nonce(nonce_byte: int) -> bytes:
    nonce = bytearray(BROADCAST_NONCE)
    nonce[3] = nonce_byte
    return bytes(nonce)


def decode_broadcast(lock_uuid: UUID, data: bytes) -> LockBroadcast | None:
    """Decode a lock's FDBF service data, or None if it isn't a state broadcast.

    Bit fields are packed least significant bit first. The state's second byte
    is a CRC-8 the app doesn't check, so neither do we: a broadcast from a
    different lock decrypts to noise, which is why the caller must pick this
    lock's advertisements by name or address first.
    """
    if len(data) != BROADCAST_LENGTH or data[0] == _OTHER_PAYLOAD:
        return None
    key = broadcast_key(lock_uuid)
    nonce = broadcast_nonce(data[5])
    state = chacha20_8(key, nonce, data[3:5])[0]
    sequence_id, timestamp, last = _EXTENSION.unpack(chacha20_8(key, nonce, data[6:13]))
    flags = data[2]
    time_stale = bool(state >> 4 & 1)
    return LockBroadcast(
        firmware=f"{data[0]}.{data[1]}",
        owned=bool(flags & 1),
        homekit_paired=bool(flags >> 1 & 1),
        product=_name(PRODUCTS, flags >> 2 & 0x0F),
        sidewalk_provisioned=bool(flags >> 6 & 1),
        sidewalk_registered=bool(flags >> 7 & 1),
        bolt_state=BOLT_STATES[state & 3],
        battery=BATTERY_LEVELS[state >> 2 & 3],
        door=DOOR_STATES[state >> 5 & 3],
        time_stale=time_stale,
        sequence_id=sequence_id,
        operated_at=None if time_stale else LEVEL_EPOCH + timedelta(seconds=timestamp),
        operation_result=_name(OPERATION_RESULTS, last & 0x0F),
        operation_source=_name(OPERATION_SOURCES, last >> 4),
    )
