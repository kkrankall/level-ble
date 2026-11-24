"""Bixby user key exchange (M1-M4), as co.level.app 2.5.0.56 does it.

Sources in the app: rrf (message flow), mn3 (crypto calls), h92 (HKDF-SHA256 to
a 32-byte key), d92/c92 (ChaCha20 with an 8-byte nonce), tc5 (ECDH), xc5 /
ECSignatureSpi(false) (ECDSA-SHA256, plain r||s), kg3 (all on SECP_256_K1).

  M1  client -> lock  [01 01 01] our ephemeral key (33, compressed)
  M2  lock -> client  [01 01 02] sealed(80) + lock ephemeral key (33)
        sealed opens with key/"UKE-N-M2" to: signature(64) + lock UUID(16)
        signature covers: our eph (33) + lock eph (33) + lock UUID (16)
        and verifies with the lock's long-term key from the account
  M3  client -> lock  [01 01 03] sealed(80) with key/"UKE-N-M3" of:
        signature(64) + account UUID(16); signature by the account key over
        lock eph (33) + our eph (33) + account UUID (16)
  M4  lock -> client  [01 01 04] result code (Success, Forbidden, ...)

key = HKDF-SHA256(ikm=ECDH x-coordinate, salt="User-Key-Exchange-Device-To-
Client-Salt", info="User-Key-Exchange-Device-To-Client-Info", 32 bytes).
"""

from __future__ import annotations

import base64
import binascii
import os
import struct
from collections.abc import Callable
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .wire import (
    BIXBY_M2,
    BIXBY_M3,
    BIXBY_M4,
    BIXBY_MESSAGES,
    BIXBY_RESULTS,
    BIXBY_USER_KEY_EXCHANGE,
    M2_KEY_LENGTH,
    M2_SEALED_LENGTH,
    UKE_INFO,
    UKE_NONCE_M2,
    UKE_NONCE_M3,
    UKE_SALT,
    bixby_user_m1,
    encode_bixby,
)

CURVE = ec.SECP256K1()
SIGNATURE_LENGTH = 64


class KeyExchangeError(Exception):
    """The lock's reply failed a check, so the handshake was stopped."""


# ---------------------------------------------------------------------------
# Primitives, matching the app byte for byte
# ---------------------------------------------------------------------------


def minimal_unsigned(value: int) -> bytes:
    """Java BigInteger.toByteArray() with its sign byte removed (no zero padding)."""
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def ecdh_shared_secret(private_key: ec.EllipticCurvePrivateKey, peer: ec.EllipticCurvePublicKey) -> bytes:
    x = int.from_bytes(private_key.exchange(ec.ECDH(), peer), "big")
    return minimal_unsigned(x)


def derive_session_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=UKE_SALT, info=UKE_INFO).derive(shared_secret)


def chacha20_8(key: bytes, nonce8: bytes, data: bytes) -> bytes:
    """Original ChaCha20 (8-byte nonce, counter 0); encrypts and decrypts."""
    if len(nonce8) != 8:
        raise ValueError("nonce must be 8 bytes")
    # cryptography takes a 16-byte block: 4-byte counter + RFC 7539 nonce.
    # Counter 0 and nonce 0000||nonce8 is the same keystream as DJB ChaCha20.
    return Cipher(algorithms.ChaCha20(key, bytes(8) + nonce8), mode=None).encryptor().update(data)


def sign_plain(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    r, s = decode_dss_signature(private_key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_plain(public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
    if len(signature) != SIGNATURE_LENGTH:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def compressed(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def _as_bytes(value: bytes | bytearray | str | list[int]) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, list):
        return bytes(value)
    text = value.strip()
    if len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text):
        return bytes.fromhex(text)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("key is neither hex nor base64") from exc


def load_public_key(value: bytes | bytearray | str | list[int]) -> ec.EllipticCurvePublicKey:
    """A secp256k1 public key from SEC1 (33/65 bytes), raw X||Y (64), or DER; hex or base64."""
    raw = _as_bytes(value)
    if len(raw) in (33, 65):
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, raw)
    if len(raw) == 64:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, b"\x04" + raw)
    try:
        key = serialization.load_der_public_key(raw)
    except ValueError as exc:
        raise ValueError(f"unrecognised public key encoding ({len(raw)} bytes)") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != CURVE.name:
        raise ValueError("public key is not on secp256k1")
    return key


def load_private_key(value: bytes | bytearray | str | list[int]) -> ec.EllipticCurvePrivateKey:
    raw = _as_bytes(value)
    if len(raw) != 32:
        raise ValueError(f"private key must be 32 bytes, got {len(raw)}")
    return ec.derive_private_key(int.from_bytes(raw, "big"), CURVE)


# ---------------------------------------------------------------------------
# The exchange
# ---------------------------------------------------------------------------


def _check_header(message: bytes, expected_id: int) -> bytes:
    if len(message) < 3:
        raise KeyExchangeError("reply shorter than a Bixby header")
    channel, _version, message_id = message[0], message[1], message[2]
    if channel != BIXBY_USER_KEY_EXCHANGE or message_id != expected_id:
        got = BIXBY_MESSAGES[message_id] if message_id < len(BIXBY_MESSAGES) else message_id
        raise KeyExchangeError(
            f"expected user key exchange {BIXBY_MESSAGES[expected_id]}, got channel {channel} message {got}"
        )
    return message[3:]


class UserKeyExchange:
    """Client side of the Bixby user key exchange. One per connection."""

    def __init__(
        self,
        user_uuid: UUID,
        user_private_key: ec.EllipticCurvePrivateKey,
        lock_public_key: Callable[[UUID], ec.EllipticCurvePublicKey | None],
    ) -> None:
        self._user_uuid = user_uuid
        self._user_key = user_private_key
        self._lock_public_key = lock_public_key
        self._ephemeral = ec.generate_private_key(CURVE)
        self.our_ephemeral = compressed(self._ephemeral.public_key())
        self.session_key: bytes | None = None
        self.lock_uuid: UUID | None = None
        self.lock_signature_valid: bool | None = None
        self.result: str | None = None

    def m1(self) -> bytes:
        return bixby_user_m1(self.our_ephemeral)

    def process_m2(self, message: bytes) -> bytes:
        """Check the lock's M2 and return M3. Raises KeyExchangeError on any mismatch."""
        payload = _check_header(message, BIXBY_M2)
        if len(payload) != M2_SEALED_LENGTH + M2_KEY_LENGTH:
            raise KeyExchangeError(f"M2 payload is {len(payload)} bytes, expected 113")
        sealed, lock_ephemeral = payload[:M2_SEALED_LENGTH], payload[M2_SEALED_LENGTH:]
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, lock_ephemeral)
        except ValueError as exc:
            raise KeyExchangeError("lock's ephemeral key is not a secp256k1 point") from exc

        self.session_key = derive_session_key(ecdh_shared_secret(self._ephemeral, peer))
        opened = chacha20_8(self.session_key, UKE_NONCE_M2, sealed)
        signature, lock_uuid_bytes = opened[:SIGNATURE_LENGTH], opened[SIGNATURE_LENGTH:]
        self.lock_uuid = UUID(bytes=lock_uuid_bytes)

        long_term = self._lock_public_key(self.lock_uuid)
        if long_term is None:
            raise KeyExchangeError(
                f"M2 names lock {self.lock_uuid}, which is not this lock (or the session key is wrong)"
            )
        transcript = self.our_ephemeral + lock_ephemeral + lock_uuid_bytes
        self.lock_signature_valid = verify_plain(long_term, transcript, signature)
        if not self.lock_signature_valid:
            raise KeyExchangeError("the lock's M2 signature does not verify with its account key")

        user_uuid = self._user_uuid.bytes
        user_signature = sign_plain(self._user_key, lock_ephemeral + self.our_ephemeral + user_uuid)
        sealed_m3 = chacha20_8(self.session_key, UKE_NONCE_M3, user_signature + user_uuid)
        return encode_bixby(BIXBY_USER_KEY_EXCHANGE, BIXBY_M3, sealed_m3)

    def session(self) -> BixbySession:
        """The encrypted channel, once the lock answered M4 with Success."""
        if self.result != "Success" or self.session_key is None or self.lock_uuid is None:
            raise KeyExchangeError("no session: the key exchange did not succeed")
        return BixbySession(self.session_key, self._user_uuid, self._user_key, self.lock_uuid)

    def process_m4(self, message: bytes) -> str:
        """The lock's result code ("Success" when it accepted us)."""
        payload = _check_header(message, BIXBY_M4)
        if len(payload) != 1:
            raise KeyExchangeError(f"M4 payload is {len(payload)} bytes, expected 1")
        code = payload[0]
        self.result = BIXBY_RESULTS[code] if code < len(BIXBY_RESULTS) else f"Unknown({code})"
        return self.result


# ---------------------------------------------------------------------------
# Session layer (after M4): co.level.app wlc / p2a / zce / vlc / kuf / b1a
# ---------------------------------------------------------------------------

CHANNEL_ENCRYPTED = 3
SIGNING_UNSIGNED = 0
SIGNING_SENDER = 1
PROTOCOL_V2 = 1

CMD_BOLT_V2 = 22  # firmware < 2.24
CMD_BOLT_V3 = 54  # firmware 2.24 .. 3.4
CMD_BOLT_V4 = 88  # firmware >= 3.4 (adds a flags byte)
BOLT_COMMANDS = (CMD_BOLT_V4, CMD_BOLT_V3, CMD_BOLT_V2)

BOLT_UNLOCK = 0
BOLT_LOCK = 1
SOURCE_BLE = 2

BOLT_STATES = ("RETRACTED", "EXTENDED", "PARTIAL", "UNKNOWN")
OPERATION_RESULTS = (
    "SUCCESS",
    "TIMEOUT",
    "STALL",
    "INTERNAL_ERROR",
    "ALREADY_THERE",
    "BATTERY_VOLTAGE_DROOPED",
    "INVALID_INSTALL",
    "BATTERY_CRITICALLY_LOW",
    "DOOR_OPEN",
    "UNKNOWN",
)
# Lock answers that mean "this command version isn't for me": try an older one.
VERSION_MISMATCH_RESULTS = frozenset({"NotSupported", "InvalidLength", "InvalidParam", "InvalidDataSize"})

_BOLT_PAYLOAD = struct.Struct("<BBiiihihiB")  # BoltOperationResponsePayloadV3, 27 bytes


def _name_or_code(table: tuple[str, ...], code: int) -> str:
    return table[code] if code < len(table) else f"Unknown({code})"


def bolt_payload(command: int, unlock: bool) -> bytes:
    """[operation][source] (+ [flags] for V4). Flags are bit-packed and all zero."""
    body = bytes([BOLT_UNLOCK if unlock else BOLT_LOCK, SOURCE_BLE])
    return body + b"\x00" if command == CMD_BOLT_V4 else body


def parse_bolt_payload(payload: bytes) -> dict[str, object]:
    result: dict[str, object] = {"payload": payload.hex()}
    if len(payload) >= 2:
        result["bolt_state"] = _name_or_code(BOLT_STATES, payload[0])
        result["operation_result"] = _name_or_code(OPERATION_RESULTS, payload[1])
    if len(payload) == _BOLT_PAYLOAD.size:
        fields = _BOLT_PAYLOAD.unpack(payload)
        result.update(
            max_current=fields[2],
            average_current=fields[3],
            current_variance=fields[4],
            duration=fields[5],
            min_voltage=fields[6],
            operation_sequence_id=fields[7],
            operation_timestamp=fields[8],
        )
    return result


class BixbySession:
    """The encrypted request/response channel set up by a successful key exchange."""

    def __init__(
        self,
        key: bytes,
        user_uuid: UUID,
        user_private_key: ec.EllipticCurvePrivateKey,
        lock_uuid: UUID,
    ) -> None:
        self._key = key
        self._user_uuid = user_uuid
        self._user_key = user_private_key
        self.lock_uuid = lock_uuid

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(8)
        return bytes([CHANNEL_ENCRYPTED]) + nonce + chacha20_8(self._key, nonce, plaintext)

    def decrypt(self, message: bytes) -> bytes:
        if len(message) < 9 or message[0] != CHANNEL_ENCRYPTED:
            raise ValueError("not an encrypted Bixby message")
        return chacha20_8(self._key, message[1:9], message[9:])

    def sender_signed_command(self, request_id: int, command: int, payload: bytes) -> bytes:
        body = bytes([request_id]) + self._user_uuid.bytes + self.lock_uuid.bytes + bytes([command]) + payload
        return sign_plain(self._user_key, body) + body

    def request(self, request_id: int, command: int, payload: bytes) -> bytes:
        plain = bytes([SIGNING_SENDER, PROTOCOL_V2]) + self.sender_signed_command(
            request_id, command, payload
        )
        return self.encrypt(plain)

    @staticmethod
    def parse_unsigned_response(plaintext: bytes) -> dict[str, object]:
        """[signing 0][version][request id][command][result] + payload."""
        if len(plaintext) < 5:
            raise ValueError("response shorter than its 5-byte header")
        if plaintext[0] != SIGNING_UNSIGNED:
            raise ValueError(f"signing type {plaintext[0]} is not an unsigned response")
        return {
            "request_id": plaintext[2],
            "command": plaintext[3],
            "result": _name_or_code(BIXBY_RESULTS, plaintext[4]),
            "payload": plaintext[5:],
        }
