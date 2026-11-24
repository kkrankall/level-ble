"""Bixby user key exchange against a simulated lock."""

from __future__ import annotations

import base64
import os
import struct
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from custom_components.level_ble.bixby import (
    CMD_BOLT_V2,
    CMD_BOLT_V3,
    CMD_BOLT_V4,
    BixbySession,
    KeyExchangeError,
    UserKeyExchange,
    bolt_payload,
    chacha20_8,
    load_private_key,
    load_public_key,
    minimal_unsigned,
    parse_bolt_payload,
)
from custom_components.level_ble.keychain import chacha20

from .conftest import ACCOUNT_UUID, LOCK_PRIVATE_HEX, LOCK_UUID, USER_PRIVATE_HEX
from .fake_lock import FakeLock

USER_KEY = load_private_key(USER_PRIVATE_HEX)
LOCK_KEY = ec.derive_private_key(int(LOCK_PRIVATE_HEX, 16), ec.SECP256K1())


LOCK = UUID(LOCK_UUID)


def _exchange(lock_uuid: UUID = LOCK) -> UserKeyExchange:
    public = LOCK_KEY.public_key()
    return UserKeyExchange(UUID(ACCOUNT_UUID), USER_KEY, lambda u: public if u == lock_uuid else None)


def _lock(**kwargs) -> FakeLock:
    return FakeLock(UUID(LOCK_UUID), LOCK_PRIVATE_HEX, UUID(ACCOUNT_UUID), USER_KEY.public_key(), **kwargs)


def test_full_exchange_is_accepted() -> None:
    exchange, lock = _exchange(), _lock()
    m1 = exchange.m1()
    assert m1[:3] == b"\x01\x01\x01" and len(m1) == 36
    m3 = exchange.process_m2(lock.reply(m1))
    assert exchange.lock_uuid == UUID(LOCK_UUID)
    assert exchange.lock_signature_valid is True
    assert m3[:3] == b"\x01\x01\x03" and len(m3) == 83
    assert exchange.process_m4(lock.reply(m3)) == "Success"
    assert lock.accepted is True
    assert exchange.session_key is not None and len(exchange.session_key) == 32


def test_m1_key_is_secp256k1() -> None:
    exchange = _exchange()
    m1 = exchange.m1()
    point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), m1[3:])  # raises if not
    assert point.public_numbers() == exchange._ephemeral.public_key().public_numbers()
    assert exchange._ephemeral.curve.name == "secp256k1"


def test_m2_from_another_lock_is_refused() -> None:
    exchange, lock = _exchange(), _lock(claim_uuid=uuid4())
    with pytest.raises(KeyExchangeError, match="not this lock"):
        exchange.process_m2(lock.reply(exchange.m1()))


def test_m2_with_bad_signature_is_refused() -> None:
    exchange, lock = _exchange(), _lock(signing_key_hex="33" * 32)
    with pytest.raises(KeyExchangeError, match="signature"):
        exchange.process_m2(lock.reply(exchange.m1()))
    assert exchange.lock_signature_valid is False


def test_lock_rejecting_m3_reports_forbidden() -> None:
    # The lock expects a different account: it answers M4 with Forbidden.
    other_user = ec.generate_private_key(ec.SECP256K1()).public_key()
    exchange = _exchange()
    lock = FakeLock(UUID(LOCK_UUID), LOCK_PRIVATE_HEX, UUID(ACCOUNT_UUID), other_user)
    m3 = exchange.process_m2(lock.reply(exchange.m1()))
    assert exchange.process_m4(lock.reply(m3)) == "Forbidden"
    assert lock.accepted is False


@pytest.mark.parametrize(
    ("message", "match"),
    [
        (b"\x01\x01", "shorter"),
        (b"\x01\x01\x04\x00", "expected user key exchange M2"),
        (b"\x02\x01\x02" + bytes(113), "channel 2"),
        (b"\x01\x01\x02" + bytes(10), "113"),
    ],
)
def test_bad_m2_messages(message: bytes, match: str) -> None:
    with pytest.raises(KeyExchangeError, match=match):
        _exchange().process_m2(message)


def test_bad_m4_messages() -> None:
    exchange = _exchange()
    with pytest.raises(KeyExchangeError, match="M4"):
        exchange.process_m4(b"\x01\x01\x02\x00")
    with pytest.raises(KeyExchangeError, match="1"):
        exchange.process_m4(b"\x01\x01\x04\x00\x00")
    assert exchange.process_m4(b"\x01\x01\x04\x63") == "Unknown(99)"


def test_minimal_unsigned_matches_java_biginteger() -> None:
    assert minimal_unsigned(0x00FF) == b"\xff"
    assert len(minimal_unsigned(1 << 247)) == 31  # leading zero byte dropped, not padded
    assert len(minimal_unsigned((1 << 256) - 1)) == 32
    assert minimal_unsigned(0) == b"\x00"


@pytest.mark.parametrize("size", [0, 1, 63, 64, 80, 200])
def test_chacha20_8_matches_rfc7539_with_zero_prefix(size: int) -> None:
    key, data = os.urandom(32), os.urandom(size)
    assert chacha20_8(key, b"UKE-N-M2", data) == chacha20(key, b"\x00" * 4 + b"UKE-N-M2", data)


def test_load_public_key_formats() -> None:
    public = LOCK_KEY.public_key()
    compressed = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    uncompressed = public.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    for value in (
        compressed.hex(),
        base64.b64encode(uncompressed).decode(),
        uncompressed[1:].hex(),  # raw X||Y
        base64.b64encode(der).decode(),
        list(compressed),
    ):
        assert load_public_key(value).public_numbers() == public.public_numbers()
    p256 = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(ValueError):
        load_public_key(
            p256.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
    with pytest.raises(ValueError):
        load_public_key("not a key!")


def test_load_private_key() -> None:
    assert load_private_key("11" * 32).private_numbers().private_value == int("11" * 32, 16)
    with pytest.raises(ValueError):
        load_private_key("11" * 31)


def test_session_requires_success() -> None:
    with pytest.raises(KeyExchangeError, match="no session"):
        _exchange().session()


def test_bolt_payloads() -> None:
    assert bolt_payload(CMD_BOLT_V4, unlock=True) == b"\x00\x02\x00"
    assert bolt_payload(CMD_BOLT_V4, unlock=False) == b"\x01\x02\x00"
    assert bolt_payload(CMD_BOLT_V3, unlock=True) == b"\x00\x02"
    assert bolt_payload(CMD_BOLT_V2, unlock=False) == b"\x01\x02"


def test_parse_bolt_payload() -> None:
    raw = struct.pack("<BBiiihihiB", 0, 4, 900, 400, 12, 750, 5100, 7, 1700000000, 0x5A)
    parsed = parse_bolt_payload(raw)
    assert parsed["bolt_state"] == "RETRACTED"
    assert parsed["operation_result"] == "ALREADY_THERE"
    assert parsed["duration"] == 750 and parsed["min_voltage"] == 5100
    assert parse_bolt_payload(b"\x01\x08") == {
        "payload": "0108",
        "bolt_state": "EXTENDED",
        "operation_result": "DOOR_OPEN",
    }
    assert parse_bolt_payload(b"\x09\x63")["bolt_state"] == "Unknown(9)"


def test_session_round_trip_with_simulated_lock() -> None:
    exchange, lock = _exchange(), _lock()
    m3 = exchange.process_m2(lock.reply(exchange.m1()))
    exchange.process_m4(lock.reply(m3))
    session = exchange.session()
    request = session.request(1, CMD_BOLT_V4, bolt_payload(CMD_BOLT_V4, unlock=True))
    assert request[0] == 3 and len(request) == 1 + 8 + 2 + 64 + 1 + 16 + 16 + 1 + 3
    response = session.parse_unsigned_response(session.decrypt(lock.reply(request)))
    assert (response["request_id"], response["command"], response["result"]) == (1, 88, "Success")
    assert parse_bolt_payload(response["payload"])["bolt_state"] == "RETRACTED"


@pytest.mark.parametrize(
    ("plain", "match"), [(b"\x00\x01\x01", "shorter"), (b"\x01\x01\x01\x58\x00", "signing type 1")]
)
def test_parse_unsigned_response_rejects(plain: bytes, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        BixbySession.parse_unsigned_response(plain)
