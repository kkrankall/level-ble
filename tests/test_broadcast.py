"""Decoding the lock's FDBF state broadcast."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from custom_components.level_ble.broadcast import LEVEL_EPOCH, decode_broadcast

from .conftest import LOCK_UUID
from .fake_lock import state_broadcast

UUID_ = UUID(LOCK_UUID)


def test_decodes_every_field() -> None:
    decoded = decode_broadcast(UUID_, state_broadcast(UUID_, sequence=1395, timestamp=328851621))
    assert decoded is not None
    assert decoded.firmware == "2.30"
    assert (decoded.owned, decoded.homekit_paired, decoded.product) == (True, True, "APOLLO")
    assert (decoded.sidewalk_provisioned, decoded.sidewalk_registered) == (False, False)
    assert (decoded.bolt_state, decoded.battery, decoded.door) == ("EXTENDED", "GREEN", "NOT_SUPPORTED")
    assert decoded.sequence_id == 1395
    # The Level epoch puts this real lock event at 2026-11-24 03:40:21 UTC.
    assert decoded.operated_at == datetime(2026, 11, 24, 3, 40, 21, tzinfo=UTC)
    assert (decoded.operation_result, decoded.operation_source) == ("SUCCESS", "BLE")


@pytest.mark.parametrize(
    ("bolt", "battery", "door", "expected"),
    [
        (0, 3, 0, ("RETRACTED", "GREEN", "NOT_SUPPORTED")),
        (1, 2, 1, ("EXTENDED", "YELLOW", "DOOR_OPEN")),
        (2, 1, 2, ("PARTIAL", "RED", "DOOR_CLOSED")),
        (3, 0, 3, ("UNKNOWN", "UNKNOWN", "NOT_CALIBRATED")),
    ],
)
def test_state_bits(bolt: int, battery: int, door: int, expected: tuple[str, str, str]) -> None:
    decoded = decode_broadcast(UUID_, state_broadcast(UUID_, bolt=bolt, battery=battery, door=door))
    assert (decoded.bolt_state, decoded.battery, decoded.door) == expected


@pytest.mark.parametrize(
    ("result", "source", "expected"),
    [
        (0, 1, ("SUCCESS", "MANUAL")),
        (4, 5, ("ALREADY_THERE", "AUTO_LOCK")),
        (2, 14, ("STALL", "KEYPAD")),
        (8, 15, ("DOOR_OPEN", "GOOGLE")),
        (12, 0, ("12", "UNKNOWN")),  # a result code this version doesn't know
    ],
)
def test_last_operation(result: int, source: int, expected: tuple[str, str]) -> None:
    decoded = decode_broadcast(UUID_, state_broadcast(UUID_, result=result, source=source))
    assert (decoded.operation_result, decoded.operation_source) == expected


def test_flags_and_firmware() -> None:
    decoded = decode_broadcast(UUID_, state_broadcast(UUID_, firmware=(3, 4), flags=0b1100_1000))
    assert decoded.firmware == "3.4"
    assert (decoded.owned, decoded.homekit_paired) == (False, False)
    assert decoded.product == "LINUS"
    assert (decoded.sidewalk_provisioned, decoded.sidewalk_registered) == (True, True)


def test_stale_clock_has_no_time() -> None:
    decoded = decode_broadcast(UUID_, state_broadcast(UUID_, time_stale=1, timestamp=0))
    assert decoded.time_stale is True
    assert decoded.operated_at is None
    fresh = decode_broadcast(UUID_, state_broadcast(UUID_, timestamp=0))
    assert fresh.operated_at == LEVEL_EPOCH


def test_nonce_byte_changes_ciphertext_not_state() -> None:
    a = state_broadcast(UUID_, nonce_byte=0x01)
    b = state_broadcast(UUID_, nonce_byte=0x02)
    assert a[3:5] != b[3:5]
    assert decode_broadcast(UUID_, a) == decode_broadcast(UUID_, b)


@pytest.mark.parametrize(
    "data",
    [b"", bytes(12), bytes(14), b"\x04" + bytes(12)],
    ids=["empty", "short", "long", "other-payload"],
)
def test_not_a_state_broadcast(data: bytes) -> None:
    assert decode_broadcast(UUID_, data) is None


def test_wrong_lock_uuid_reads_noise() -> None:
    data = state_broadcast(UUID_, sequence=1395)
    other = decode_broadcast(UUID("00000000-0000-4000-8000-000000000000"), data)
    assert other is not None and other.sequence_id != 1395
