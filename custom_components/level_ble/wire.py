"""Level's BLE wire format: fragments, the Bixby binary protocol, and protobuf.

Standard library only: tools/ble_probe.py imports this file directly.

Everything here comes from co.level.app 2.5.0.56, which has two protocol stacks:

- Bixby (cloud-account locks, e.g. product "Apollo"): little-endian binary
  messages with a 3-byte header, sent over the FDBF transport in fragments.
- Skyline (the app's separate list of local devices): `co.level.Message`
  encoded with kotlinx.serialization.protobuf.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Fragments (FDBF transport)
# ---------------------------------------------------------------------------

# First byte of every fragment, as in co.level.app (classes j1a and pf9).
FRAGMENT_SINGLE = 0x6D  # the whole message
FRAGMENT_FIRST = 0x2A
FRAGMENT_MIDDLE = 0x17
FRAGMENT_LAST = 0x36
MAX_FRAGMENT = 120  # bytes per write, header included
DEFAULT_ATT_MTU = 23


def frame_message(payload: bytes, mtu: int | None) -> list[bytes]:
    """Split a message into fragments of min(120, MTU - 4) bytes, as the app does."""
    size = min(MAX_FRAGMENT, (mtu or DEFAULT_ATT_MTU) - 4)
    if size <= 1:
        raise ValueError(f"MTU {mtu} is too small to send a fragment")
    step = size - 1
    fragments = []
    for start in range(0, len(payload), step):
        end = min(start + step, len(payload))
        if start == 0 and end == len(payload):
            kind = FRAGMENT_SINGLE
        elif start == 0:
            kind = FRAGMENT_FIRST
        elif end == len(payload):
            kind = FRAGMENT_LAST
        else:
            kind = FRAGMENT_MIDDLE
        fragments.append(bytes([kind]) + payload[start:end])
    return fragments


class FragmentReassembler:
    """Joins the lock's notification fragments back into whole messages."""

    _COMPLETES = {(None, FRAGMENT_SINGLE), (FRAGMENT_FIRST, FRAGMENT_LAST), (FRAGMENT_MIDDLE, FRAGMENT_LAST)}
    _CONTINUES = {
        (None, FRAGMENT_FIRST),
        (FRAGMENT_FIRST, FRAGMENT_MIDDLE),
        (FRAGMENT_MIDDLE, FRAGMENT_MIDDLE),
    }

    def __init__(self) -> None:
        self._previous: int | None = None
        self._buffer = bytearray()

    def feed(self, fragment: bytes) -> bytes | None:
        """Add one fragment; return the message once its last fragment arrives."""
        if not fragment:
            raise ValueError("empty fragment")
        kind, body = fragment[0], fragment[1:]
        step = (self._previous, kind)
        if step in self._COMPLETES:
            message = bytes(self._buffer + body)
            self._previous = None
            self._buffer.clear()
            return message
        if step in self._CONTINUES:
            self._buffer += body
            self._previous = kind
            return None
        previous = "start" if self._previous is None else f"0x{self._previous:02x}"
        self._previous = None
        self._buffer.clear()
        raise ValueError(f"unexpected fragment type 0x{kind:02x} after {previous}")


# ---------------------------------------------------------------------------
# Protobuf
# ---------------------------------------------------------------------------

WIRE_VARINT = 0
WIRE_I64 = 1
WIRE_LEN = 2
WIRE_I32 = 5

# Message.ProtocolVersion (@ProtoNumber on each entry).
UNSET = 0
VERSION_1 = 1

# Field name -> (field number, kind). A kind is "varint", "bytes", or the name
# of another schema for a nested message. Read from the app's $$serializer
# classes; nested types not listed here are kept as raw bytes.
SCHEMAS: dict[str, dict[str, tuple[int, str]]] = {
    "Message": {
        "version": (1, "varint"),
        "encSignedMsg": (9, "EncryptedSignedMessage"),
        "signedMsg": (10, "SignedMessage"),
        "owningM1": (11, "bytes"),
        "owningM2": (12, "bytes"),
        "owningM3": (13, "bytes"),
        "owningM4": (14, "bytes"),
        "userM1": (15, "UserSessionM1"),
        "userM2": (16, "UserSessionM2"),
        "userM3": (17, "UserSessionM3"),
        "userM4": (18, "UserSessionM4"),
    },
    "UserSessionM1": {"userEphemeralEcPubkey33": (1, "bytes")},
    "UserSessionM2": {"deviceEphemeralEcPubkey33": (1, "bytes"), "cipherText": (2, "bytes")},
    "UserSessionM2PlainText": {"deviceEcSignature64": (1, "bytes"), "deviceSigned": (2, "bytes")},
    "UserSessionM3": {"cipherText": (2, "bytes")},
    "UserSessionM3PlainText": {"userEcSignature64": (1, "bytes"), "userSigned": (2, "bytes")},
    "UserSessionM4": {"status": (1, "varint")},
    "EncryptedSignedMessage": {"chachaNonce8": (1, "bytes"), "cipherText": (2, "bytes")},
    "SignedMessage": {
        "none": (1, "bytes"),
        "sender": (2, "bytes"),
        "service": (3, "bytes"),
        "admin": (4, "bytes"),
        "device": (5, "bytes"),
        "ecSignature64": (33, "bytes"),
        "command": (34, "bytes"),
        "response": (35, "bytes"),
        "message": (36, "bytes"),
    },
}


def encode_varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1  # protobuf encodes negative int32/int64 as 10-byte varints
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift >= 70:
            raise ValueError("varint too long")


def _tag(number: int, wire_type: int) -> bytes:
    return encode_varint(number << 3 | wire_type)


def encode_message(value: dict[str, Any], schema: str = "Message") -> bytes:
    """Encode a dict as the named message. Fields set to None are left out."""
    fields = SCHEMAS[schema]
    unknown = set(value) - set(fields)
    if unknown:
        raise KeyError(f"{schema} has no field(s) {sorted(unknown)}")
    out = bytearray()
    for name, (number, kind) in sorted(fields.items(), key=lambda item: item[1][0]):
        item = value.get(name)
        if item is None:
            continue
        if kind == "varint":
            out += _tag(number, WIRE_VARINT) + encode_varint(int(item))
            continue
        body = bytes(item) if kind == "bytes" else encode_message(item, kind)
        out += _tag(number, WIRE_LEN) + encode_varint(len(body)) + body
    return bytes(out)


def _read_fields(data: bytes) -> list[tuple[int, int, Any]]:
    fields = []
    pos = 0
    while pos < len(data):
        key, pos = decode_varint(data, pos)
        number, wire_type = key >> 3, key & 7
        if number == 0:
            raise ValueError("field number 0")
        if wire_type == WIRE_VARINT:
            value, pos = decode_varint(data, pos)
        elif wire_type == WIRE_LEN:
            size, pos = decode_varint(data, pos)
            if pos + size > len(data):
                raise ValueError("truncated length-delimited field")
            value, pos = data[pos : pos + size], pos + size
        elif wire_type in (WIRE_I64, WIRE_I32):
            size = 8 if wire_type == WIRE_I64 else 4
            if pos + size > len(data):
                raise ValueError("truncated fixed-width field")
            value, pos = data[pos : pos + size], pos + size
        else:
            raise ValueError(f"unsupported wire type {wire_type}")
        fields.append((number, wire_type, value))
    return fields


def decode_message(data: bytes, schema: str = "Message") -> dict[str, Any]:
    """Decode the named message. Unknown fields are kept as "#<number>"."""
    by_number = {number: (name, kind) for name, (number, kind) in SCHEMAS[schema].items()}
    result: dict[str, Any] = {}
    for number, wire_type, value in _read_fields(bytes(data)):
        name, kind = by_number.get(number, (f"#{number}", "raw"))
        if kind == "varint":
            if wire_type != WIRE_VARINT:
                raise ValueError(f"{schema}.{name}: expected a varint")
        elif kind == "bytes":
            if wire_type != WIRE_LEN:
                raise ValueError(f"{schema}.{name}: expected bytes")
        elif kind != "raw":
            if wire_type != WIRE_LEN:
                raise ValueError(f"{schema}.{name}: expected a nested message")
            value = decode_message(value, kind)
        if name in result:  # repeated field
            previous = result[name]
            result[name] = [*previous, value] if isinstance(previous, list) else [previous, value]
        else:
            result[name] = value
    return result


# ---------------------------------------------------------------------------
# Bixby (binary) protocol
# ---------------------------------------------------------------------------

# Every Bixby message starts with [channel][protocol version][message id]
# (co.level.app erf/rrf; enums q2a, nzb, srf).
BIXBY_CHANNELS = (
    "OWNING",
    "USER_KEY_EXCHANGE",
    "ADMIN_KEY_EXCHANGE",
    "ENCRYPTED",
    "UNENCRYPTED",
    "ENCRYPTED_NOTIFICATION",
    "UNENCRYPTED_NOTIFICATION",
    "KEYPAD_KEY_EXCHANGE",
    "SERVICE_SESSION_KEY_EXCHANGE",
    "EPHEMERAL_KEY_EXCHANGE",
)
BIXBY_VERSIONS = ("V1_0", "V2_0")
BIXBY_MESSAGES = ("None", "M1", "M2", "M3", "M4")
# Key exchange result codes (enum uqc), carried by M4.
BIXBY_RESULTS = (
    "Success",
    "InternalError",
    "NotFound",
    "NotSupported",
    "InvalidParam",
    "InvalidState",
    "InvalidLength",
    "InvalidFlags",
    "InvalidData",
    "InvalidDataSize",
    "Timeout",
    "Forbidden",
    "Busy",
    "StorageFull",
    "Failure",
)
BIXBY_USER_KEY_EXCHANGE = 1
BIXBY_V2 = 1  # the app's default (ozb.a = V2_0)
BIXBY_M1, BIXBY_M2, BIXBY_M3, BIXBY_M4 = 1, 2, 3, 4

# HKDF/nonce labels the app uses for the user key exchange (rrf).
UKE_SALT = b"User-Key-Exchange-Device-To-Client-Salt"
UKE_INFO = b"User-Key-Exchange-Device-To-Client-Info"
UKE_NONCE_M2 = b"UKE-N-M2"
UKE_NONCE_M3 = b"UKE-N-M3"

# M2 payload after the header: 80-byte sealed block, then the lock's
# 33-byte compressed ephemeral key (rrf reads them in that order).
M2_SEALED_LENGTH = 80
M2_KEY_LENGTH = 33


def encode_bixby(channel: int, message_id: int, payload: bytes, version: int = BIXBY_V2) -> bytes:
    return bytes([channel, version, message_id]) + bytes(payload)


def bixby_user_m1(ephemeral_public_key33: bytes) -> bytes:
    """01 01 01 <33-byte compressed key>: USER_KEY_EXCHANGE, V2_0, M1."""
    if len(ephemeral_public_key33) != 33:
        raise ValueError("M1 needs a 33-byte compressed P-256 key")
    return encode_bixby(BIXBY_USER_KEY_EXCHANGE, BIXBY_M1, ephemeral_public_key33)


def _name(table: tuple[str, ...], index: int, what: str) -> str:
    if index >= len(table):
        raise ValueError(f"unknown Bixby {what} {index}")
    return table[index]


def decode_bixby(raw: bytes) -> dict[str, Any]:
    """Label a Bixby message's header and, for user key exchange, its payload."""
    if len(raw) < 3:
        raise ValueError("Bixby message shorter than its 3-byte header")
    channel, version, message_id, payload = raw[0], raw[1], raw[2], bytes(raw[3:])
    result: dict[str, Any] = {
        "channel": _name(BIXBY_CHANNELS, channel, "channel"),
        "version": _name(BIXBY_VERSIONS, version, "protocol version"),
    }
    if not result["channel"].endswith("KEY_EXCHANGE"):
        result["header_byte_3"] = message_id
        result["payload"] = payload
        return result
    result["message"] = _name(BIXBY_MESSAGES, message_id, "message id")
    result["payload"] = payload
    if channel == BIXBY_USER_KEY_EXCHANGE:
        if message_id == BIXBY_M2 and len(payload) == M2_SEALED_LENGTH + M2_KEY_LENGTH:
            result["sealed"] = payload[:M2_SEALED_LENGTH]
            result["deviceEphemeralEcPubkey33"] = payload[M2_SEALED_LENGTH:]
        elif message_id == BIXBY_M4 and len(payload) == 1:
            result["result"] = _name(BIXBY_RESULTS, payload[0], "result")
    return result
