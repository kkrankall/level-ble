"""Protobuf encoding of Level's BLE messages."""

from __future__ import annotations

import os

import pytest

from custom_components.level_ble.ble import LevelSession
from custom_components.level_ble.wire import (
    SCHEMAS,
    VERSION_1,
    bixby_user_m1,
    decode_bixby,
    decode_message,
    decode_varint,
    encode_message,
    encode_varint,
)


def test_m1_matches_the_apps_protobuf() -> None:
    # Message{version: VERSION_1 (#1, varint), userM1 (#15, LEN){userEphemeralEcPubkey33 (#1, LEN)}}
    key = bytes([0x02]) + os.urandom(32)
    expected = bytes([0x08, 0x01, 0x7A, 0x23, 0x0A, 0x21]) + key
    assert encode_message({"version": VERSION_1, "userM1": {"userEphemeralEcPubkey33": key}}) == expected


def test_session_m1_bixby_by_default() -> None:
    m1 = LevelSession().m1()
    assert len(m1) == 36
    assert m1[:3] == bytes([0x01, 0x01, 0x01])  # USER_KEY_EXCHANGE, V2_0, M1
    assert m1[3] in (0x02, 0x03)  # compressed P-256 point


def test_session_m1_skyline_is_protobuf() -> None:
    m1 = LevelSession().m1("skyline")
    assert len(m1) == 39
    assert m1[:6] == bytes([0x08, 0x01, 0x7A, 0x23, 0x0A, 0x21])
    assert m1[6] in (0x02, 0x03)
    assert decode_message(m1)["userM1"]["userEphemeralEcPubkey33"] == m1[6:]


def test_bixby_user_m1_layout() -> None:
    key = bytes([0x02]) + os.urandom(32)
    assert bixby_user_m1(key) == b"\x01\x01\x01" + key
    with pytest.raises(ValueError):
        bixby_user_m1(key + b"\x00")


def test_decode_bixby_m2_and_m4() -> None:
    key = bytes([0x03]) + os.urandom(32)
    sealed = os.urandom(80)
    m2 = decode_bixby(bytes([1, 1, 2]) + sealed + key)
    assert (m2["channel"], m2["version"], m2["message"]) == ("USER_KEY_EXCHANGE", "V2_0", "M2")
    assert m2["sealed"] == sealed
    assert m2["deviceEphemeralEcPubkey33"] == key
    assert decode_bixby(bytes([1, 1, 4, 11]))["result"] == "Forbidden"
    assert decode_bixby(bytes([1, 1, 4, 0]))["result"] == "Success"
    odd = decode_bixby(bytes([1, 1, 2, 9, 9]))  # unexpected length: header labelled, payload kept
    assert odd["message"] == "M2" and "sealed" not in odd and odd["payload"] == b"\x09\x09"


def test_decode_bixby_other_channels() -> None:
    encrypted = decode_bixby(bytes([3, 1, 7, 1, 2]))
    assert encrypted == {
        "channel": "ENCRYPTED",
        "version": "V2_0",
        "header_byte_3": 7,
        "payload": b"\x01\x02",
    }


@pytest.mark.parametrize("raw", [b"", b"\x01\x01", bytes([10, 1, 1]), bytes([1, 2, 1]), bytes([1, 1, 5])])
def test_decode_bixby_rejects_bad_headers(raw: bytes) -> None:
    with pytest.raises(ValueError):
        decode_bixby(raw)


@pytest.mark.parametrize("value", [0, 1, 127, 128, 300, 2**32, 2**63])
def test_varint_round_trip(value: int) -> None:
    raw = encode_varint(value)
    assert decode_varint(raw + b"\xff", 0) == (value, len(raw))


def test_negative_varint_is_ten_bytes() -> None:
    assert len(encode_varint(-1)) == 10


def test_round_trip_every_handshake_message() -> None:
    message = {
        "version": VERSION_1,
        "encSignedMsg": {"chachaNonce8": os.urandom(8), "cipherText": os.urandom(200)},
        "userM2": {"deviceEphemeralEcPubkey33": os.urandom(33), "cipherText": os.urandom(130)},
        "userM3": {"cipherText": os.urandom(90)},
        "userM4": {"status": 3},
        "signedMsg": {"ecSignature64": os.urandom(64), "command": b"\x0a\x00"},
    }
    assert decode_message(encode_message(message)) == message


def test_none_fields_are_left_out_and_unknown_names_rejected() -> None:
    assert encode_message({"version": None, "userM4": {"status": 0}}) == bytes([0x92, 0x01, 0x02, 0x08, 0x00])
    with pytest.raises(KeyError):
        encode_message({"bogus": 1})


def test_unknown_and_repeated_fields_are_kept() -> None:
    raw = encode_message({"version": VERSION_1}) + bytes([0xA0, 0x06, 0x05]) + encode_message({"version": 2})
    decoded = decode_message(raw)
    assert decoded["#100"] == 5
    assert decoded["version"] == [VERSION_1, 2]


@pytest.mark.parametrize(
    "raw",
    [
        b"\x08",  # varint missing
        b"\x7a\x05\x0a",  # length past the end
        b"\x80",  # truncated key
        b"\x0b",  # wire type 3 (groups) unsupported
        b"\x00\x01",  # field number 0
        b"\x0a\x00",  # version sent as bytes
        b"\x7a\x01\x08",  # userM1 as a varint
    ],
)
def test_malformed_input_raises_value_error(raw: bytes) -> None:
    with pytest.raises(ValueError):
        decode_message(raw)


def test_schema_numbers_are_unique() -> None:
    for name, fields in SCHEMAS.items():
        numbers = [number for number, _ in fields.values()]
        assert len(numbers) == len(set(numbers)), name
