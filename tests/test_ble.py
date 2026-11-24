"""FDBF fragment framing and characteristic choice."""

from __future__ import annotations

import os

import pytest

from custom_components.level_ble.ble import (
    FRAGMENT_FIRST,
    FRAGMENT_LAST,
    FRAGMENT_MIDDLE,
    FRAGMENT_SINGLE,
    FragmentReassembler,
    frame_message,
    pick_characteristics,
)
from custom_components.level_ble.const import UUID_SERVICE_MAIN

from .conftest import FDBF_GATT, LEVEL_GATT, gatt


def test_single_fragment_when_it_fits() -> None:
    payload = os.urandom(119)
    assert frame_message(payload, 247) == [bytes([FRAGMENT_SINGLE]) + payload]


def test_fragments_follow_the_app() -> None:
    # min(120, mtu - 4) bytes per write, 1 of them the header: 119 payload bytes at MTU 247.
    payload = os.urandom(300)
    fragments = frame_message(payload, 247)
    assert [f[0] for f in fragments] == [FRAGMENT_FIRST, FRAGMENT_MIDDLE, FRAGMENT_LAST]
    assert [len(f) for f in fragments] == [120, 120, 63]
    assert b"".join(f[1:] for f in fragments) == payload


def test_small_and_unknown_mtu() -> None:
    assert [len(f) for f in frame_message(bytes(40), 23)] == [19, 19, 5]  # MTU 23: 18 per write
    assert frame_message(bytes(40), None) == frame_message(bytes(40), 23)
    assert frame_message(b"", 247) == []
    with pytest.raises(ValueError):
        frame_message(b"x", 5)


@pytest.mark.parametrize("size", [1, 119, 120, 238, 239, 1000])
def test_round_trip(size: int) -> None:
    payload = os.urandom(size)
    reassembler = FragmentReassembler()
    results = [reassembler.feed(f) for f in frame_message(payload, 247)]
    assert results[:-1] == [None] * (len(results) - 1)
    assert results[-1] == payload
    # The reassembler is ready for the next message.
    assert reassembler.feed(bytes([FRAGMENT_SINGLE]) + b"next") == b"next"


@pytest.mark.parametrize(
    "sequence",
    [
        [FRAGMENT_MIDDLE],
        [FRAGMENT_LAST],
        [FRAGMENT_FIRST, FRAGMENT_SINGLE],
        [FRAGMENT_FIRST, FRAGMENT_FIRST],
        [0x00],
    ],
)
def test_reassembler_rejects_bad_sequences(sequence: list[int]) -> None:
    reassembler = FragmentReassembler()
    with pytest.raises(ValueError, match="unexpected fragment type"):
        for kind in sequence:
            reassembler.feed(bytes([kind, 1]))
    # A bad sequence resets it.
    assert reassembler.feed(bytes([FRAGMENT_SINGLE, 9])) == b"\x09"
    with pytest.raises(ValueError):
        reassembler.feed(b"")


def test_pick_fdbf_transport() -> None:
    channels = pick_characteristics(FDBF_GATT)
    assert channels.framed is True
    assert channels.write.uuid == "00000010-0000-1000-8000-00805f9b34fb"
    assert [c.uuid[4:8] for c in channels.notify] == ["0012", "0011", "0013"]


def test_pick_legacy_9161_layout() -> None:
    channels = pick_characteristics(LEVEL_GATT)
    assert channels.framed is False
    assert channels.write.uuid == UUID_SERVICE_MAIN


def test_pick_nothing_writable() -> None:
    channels = pick_characteristics(gatt(("1234", [("abcd", ["notify"])])))
    assert channels.write is None
    assert [c.uuid for c in channels.notify] == ["abcd"]
