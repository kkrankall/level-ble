"""A simulated Level lock for the Bixby user key exchange.

Written separately from custom_components/level_ble/bixby.py so the tests
check our code against an independent reading of the protocol: ChaCha20 here
is the pure-Python RFC 7539 one from keychain.py, not the cryptography library
cipher bixby.py uses.
"""

from __future__ import annotations

import os
import struct
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from custom_components.level_ble.keychain import chacha20
from custom_components.level_ble.wire import FragmentReassembler, frame_message

K1 = ec.SECP256K1()
RX = "00000012-0000-1000-8000-00805f9b34fb"


def _stream(key: bytes, label: bytes, data: bytes) -> bytes:
    return chacha20(key, b"\x00\x00\x00\x00" + label, data)  # DJB ChaCha20, 8-byte nonce


def _point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def state_broadcast(
    lock_uuid: UUID,
    *,
    firmware: tuple[int, int] = (2, 30),
    flags: int = 0b0000_0011,  # owned, HomeKit paired, product 0 (APOLLO)
    bolt: int = 1,  # EXTENDED
    battery: int = 3,  # GREEN
    time_stale: int = 0,
    door: int = 0,  # NOT_SUPPORTED
    sequence: int = 1395,
    timestamp: int = 328851621,  # seconds since 2016-06-23T00:00:00Z
    result: int = 0,  # SUCCESS
    source: int = 2,  # BLE
    nonce_byte: int = 0xBE,
) -> bytes:
    """The FDBF service data a Level lock advertises (co.level.bixby StateBroadcastPayload)."""
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"Bixby", info=b"State-Broadcast-Key-Default-Info"
    ).derive(lock_uuid.bytes)
    nonce = b"BSE" + bytes([nonce_byte]) + b"N-01"  # "BSE-N-01" with byte 3 replaced
    state = bolt | battery << 2 | time_stale << 4 | door << 5
    extension = struct.pack("<HIB", sequence, timestamp, result | source << 4)
    return (
        bytes([*firmware, flags])
        + _stream(key, nonce, bytes([state, 0x00]))  # second byte: a CRC-8 nobody checks
        + bytes([nonce_byte])
        + _stream(key, nonce, extension)
    )


class FakeLock:
    def __init__(
        self,
        lock_uuid: UUID,
        lock_private_hex: str,
        user_uuid: UUID,
        user_public: ec.EllipticCurvePublicKey,
        *,
        claim_uuid: UUID | None = None,
        signing_key_hex: str | None = None,
        mtu: int = 247,
        supported_commands: frozenset[int] = frozenset({22, 54, 88}),
        operation_result: int = 0,
        bolt_locked: bool = True,
    ) -> None:
        self.lock_uuid = lock_uuid
        self.claim_uuid = claim_uuid or lock_uuid
        self.signing_key = ec.derive_private_key(int(signing_key_hex or lock_private_hex, 16), K1)
        self.user_uuid = user_uuid
        self.user_public = user_public
        self.mtu = mtu
        self.reassembler = FragmentReassembler()
        self.accepted: bool | None = None
        self.result_code: int | None = None
        self.supported_commands = supported_commands
        self.operation_result = operation_result
        self.bolt_locked = bolt_locked
        self.requests: list[dict] = []

    def _key(self, client_point: bytes) -> bytes:
        peer = ec.EllipticCurvePublicKey.from_encoded_point(K1, client_point)
        x = self.ephemeral.exchange(ec.ECDH(), peer).lstrip(b"\x00")  # BigInteger, no sign byte
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"User-Key-Exchange-Device-To-Client-Salt",
            info=b"User-Key-Exchange-Device-To-Client-Info",
        ).derive(x)

    def m2(self, m1: bytes) -> bytes:
        assert m1[:3] == b"\x01\x01\x01", m1[:3].hex()
        self.client_point = m1[3:]
        assert len(self.client_point) == 33
        self.ephemeral = ec.generate_private_key(K1)
        self.point = _point(self.ephemeral.public_key())
        self.key = self._key(self.client_point)
        uuid = self.claim_uuid.bytes
        r, s = decode_dss_signature(
            self.signing_key.sign(self.client_point + self.point + uuid, ec.ECDSA(hashes.SHA256()))
        )
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return b"\x01\x01\x02" + _stream(self.key, b"UKE-N-M2", signature + uuid) + self.point

    def m4(self, m3: bytes) -> bytes:
        assert m3[:3] == b"\x01\x01\x03", m3[:3].hex()
        opened = _stream(self.key, b"UKE-N-M3", m3[3:])
        assert len(opened) == 80
        signature, uuid = opened[:64], opened[64:]
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        try:
            self.user_public.verify(
                encode_dss_signature(r, s),
                self.point + self.client_point + uuid,
                ec.ECDSA(hashes.SHA256()),
            )
            valid = UUID(bytes=uuid) == self.user_uuid
        except Exception:  # noqa: BLE001 - any failure is a rejection
            valid = False
        self.accepted = valid
        self.result_code = 0 if valid else 11  # Success / Forbidden
        return bytes([0x01, 0x01, 0x04, self.result_code])

    def command(self, message: bytes) -> bytes:
        """An encrypted, sender-signed request after M4: check it, act, answer unsigned."""
        assert self.accepted, "command before a successful key exchange"
        assert message[0] == 3, "not the ENCRYPTED channel"
        plain = _stream(self.key, message[1:9], message[9:])
        assert plain[:2] == b"\x01\x01", plain[:2].hex()  # SENDER_SIGNED, V2_0
        signature, body = plain[2:66], plain[66:]
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        self.user_public.verify(encode_dss_signature(r, s), body, ec.ECDSA(hashes.SHA256()))
        request_id, user, lock, command, payload = (
            body[0],
            UUID(bytes=body[1:17]),
            UUID(bytes=body[17:33]),
            body[33],
            body[34:],
        )
        assert user == self.user_uuid and lock == self.lock_uuid
        self.requests.append({"request_id": request_id, "command": command, "payload": payload})
        if command not in self.supported_commands:
            return self._answer(request_id, command, 3, b"")  # NotSupported
        operation = payload[0]  # 0 unlock, 1 lock
        if self.operation_result == 0:
            self.bolt_locked = operation == 1
        state = 1 if self.bolt_locked else 0  # EXTENDED / RETRACTED
        reply = struct.pack(
            "<BBiiihihiB", state, self.operation_result, 900, 400, 12, 750, 5100, 7, 1700000000, 0x5A
        )
        return self._answer(request_id, command, 0, reply)

    def _answer(self, request_id: int, command: int, result: int, payload: bytes) -> bytes:
        nonce = os.urandom(8)
        plain = bytes([0, 1, request_id, command, result]) + payload
        return b"\x03" + nonce + _stream(self.key, nonce, plain)

    def reply(self, message: bytes) -> bytes:
        if message[0] == 3:
            return self.command(message)
        return self.m2(message) if message[2] == 1 else self.m4(message)

    def on_write(self, fragment: bytes) -> list[tuple[str, bytes]]:
        """For FakeBleakClient(responder=...): reassemble, answer, fragment the answer."""
        message = self.reassembler.feed(fragment)
        if message is None:
            return []
        return [(RX, f) for f in frame_message(self.reply(message), self.mtu)]
