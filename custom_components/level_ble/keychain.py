"""Crypto, BSON and keychain primitives reverse engineered from co.level.app 2.5.0.56.

Standard library only: tools/level_keychain.py and tools/ble_probe.py import
this file directly so the integration and the tools share one implementation.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from typing import Any

# Both password hashes in the app are SHA-256 over (UTF-8 password + salt),
# re-hashed for i in 0..101 inclusive: 102 digests in total.
KDF_ITERATIONS = 102
# Keychain unlock key (the app's ei1 class).
KDF_SALT = b"C0771591-BE41-4E22-8C89-D4521D9538B4"
# Password proof sent to POST /v2/login (the app's b8d class).
LOGIN_SALT = b"CFF33588-AC1D-4F77-943B-728CF61FCC1B"


class KeychainError(ValueError):
    """The account keychain could not be decrypted or parsed."""


# ---------------------------------------------------------------------------
# ChaCha20 (RFC 7539): 32-byte key, 12-byte nonce, counter starts at 0.
# ---------------------------------------------------------------------------


def _rotl(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state.append(counter & 0xFFFFFFFF)
    state += list(struct.unpack("<3I", nonce))
    working = list(state)
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w + s) & 0xFFFFFFFF for w, s in zip(working, state, strict=True)])


def chacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    """Encrypt or decrypt (it is a stream cipher, so both are the same)."""
    if len(key) != 32:
        raise ValueError(f"ChaCha20 key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"ChaCha20 nonce must be 12 bytes, got {len(nonce)}")
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i : i + 64], ks, strict=False))
    return bytes(out)


# ---------------------------------------------------------------------------
# BSON
# ---------------------------------------------------------------------------


class BSONReader:
    """Minimal BSON decoder. Arrays decode to lists, documents to dicts."""

    def __init__(self, data: bytes):
        self.data = bytes(data)
        self.pos = 0

    def _cstring(self) -> str:
        end = self.data.index(b"\x00", self.pos)
        value = self.data[self.pos : end].decode("utf-8", "replace")
        self.pos = end + 1
        return value

    def _read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("negative BSON length")
        chunk = self.data[self.pos : self.pos + n]
        if len(chunk) != n:
            raise ValueError("truncated BSON")
        self.pos += n
        return chunk

    def document(self) -> dict:
        start = self.pos
        size = struct.unpack("<i", self._read(4))[0]
        end = start + size
        if size < 5 or end > len(self.data):
            raise ValueError(f"bad BSON document size {size} at offset {start}")
        result: dict = {}
        while self.pos < end - 1:
            kind = self._read(1)[0]
            if kind == 0:
                break
            name = self._cstring()
            result[name] = self._value(kind)
        self.pos = end
        return result

    def _value(self, kind: int) -> Any:
        if kind == 0x01:
            return struct.unpack("<d", self._read(8))[0]
        if kind == 0x02:
            size = struct.unpack("<i", self._read(4))[0]
            raw = self._read(size - 1)
            self._read(1)
            return raw.decode("utf-8", "replace")
        if kind == 0x03:
            return self.document()
        if kind == 0x04:
            # A BSON array is a document keyed "0", "1", ... in order.
            return list(self.document().values())
        if kind == 0x05:
            size = struct.unpack("<i", self._read(4))[0]
            self._read(1)  # subtype
            return self._read(size)
        if kind == 0x06:
            return None
        if kind == 0x07:
            return self._read(12)
        if kind == 0x08:
            return self._read(1) != b"\x00"
        if kind == 0x09:
            return struct.unpack("<q", self._read(8))[0]
        if kind == 0x0A:
            return None
        if kind == 0x0B:
            return {"pattern": self._cstring(), "flags": self._cstring()}
        if kind == 0x10:
            return struct.unpack("<i", self._read(4))[0]
        if kind in (0x11, 0x12):
            return struct.unpack("<q", self._read(8))[0]
        if kind == 0x13:
            return self._read(16)
        raise ValueError(f"unsupported BSON type 0x{kind:02x} at offset {self.pos}")


def bson_decode(raw: bytes) -> dict:
    return BSONReader(raw).document()


def _cstring(value: str) -> bytes:
    raw = value.encode()
    if b"\x00" in raw:
        raise ValueError(f"BSON key contains NUL: {value!r}")
    return raw + b"\x00"


def _bson_element(key: str, item: Any) -> bytes:
    name = _cstring(key)
    if item is None:
        return b"\x0a" + name
    if isinstance(item, bool):
        return b"\x08" + name + (b"\x01" if item else b"\x00")
    if isinstance(item, int):
        if -(2**31) <= item < 2**31:
            return b"\x10" + name + struct.pack("<i", item)
        return b"\x12" + name + struct.pack("<q", item)
    if isinstance(item, float):
        return b"\x01" + name + struct.pack("<d", item)
    if isinstance(item, str):
        raw = item.encode()
        return b"\x02" + name + struct.pack("<i", len(raw) + 1) + raw + b"\x00"
    if isinstance(item, (bytes, bytearray)):
        return b"\x05" + name + struct.pack("<i", len(item)) + b"\x00" + bytes(item)
    if isinstance(item, dict):
        return b"\x03" + name + bson_encode(item)
    if isinstance(item, (list, tuple)):
        return b"\x04" + name + bson_encode({str(i): v for i, v in enumerate(item)})
    raise TypeError(f"unsupported BSON value for {key}: {type(item)!r}")


def bson_encode(value: dict) -> bytes:
    body = b"".join(_bson_element(key, item) for key, item in value.items())
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


# ---------------------------------------------------------------------------
# Keychain
# ---------------------------------------------------------------------------


def _iterated_sha256(password: str, salt: bytes) -> bytes:
    digest = password.encode() + salt
    for _ in range(KDF_ITERATIONS):
        digest = hashlib.sha256(digest).digest()
    return digest


def derive_password_key(password: str) -> bytes:
    """32-byte key that unwraps the account's password blob key."""
    return _iterated_sha256(password, KDF_SALT)


def login_password(password: str) -> str:
    """The `password` field for POST /v2/login: base64 of the salted hash, never the password."""
    return base64.b64encode(_iterated_sha256(password, LOGIN_SALT)).decode()


def decode_flexible(value: str) -> bytes:
    """The app hex-decodes exact-length strings and base64-decodes anything else."""
    if len(value) in (24, 64) and all(c in "0123456789abcdefABCDEF" for c in value):
        return bytes.fromhex(value)
    return base64.b64decode(value)


def decrypt_blob_key(encrypted_keys: list[dict], password: str) -> bytes:
    for item in encrypted_keys:
        if str(item.get("name", "")).lower() == "password":
            return chacha20(
                derive_password_key(password),
                decode_flexible(item["nonce"]),
                decode_flexible(item["value"]),
            )
    raise KeychainError("account has no password blob key")


def decrypt_account_blob(blob: dict, blob_key: bytes) -> dict:
    plain = chacha20(blob_key, bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["value"]))
    return BSONReader(plain).document()


def _as_key_bytes(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray)) and value:
        return bytes(value)
    if (
        isinstance(value, list)
        and value
        and all(isinstance(i, int) and not isinstance(i, bool) and 0 <= i <= 255 for i in value)
    ):
        return bytes(value)
    return None


def find_private_keys(node: Any, path: str = "") -> list[tuple[str, bytes]]:
    """Every `privateKey` in the decrypted blob, stored as BSON binary or int array."""
    found: list[tuple[str, bytes]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            raw = _as_key_bytes(value) if key == "privateKey" else None
            if raw is not None:
                found.append((child, raw))
            else:
                found += find_private_keys(value, child)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            found += find_private_keys(item, f"{path}[{index}]")
    return found


def find_private_key(node: Any) -> bytes | None:
    found = find_private_keys(node)
    return found[0][1] if found else None


def unlock_account(account: dict, password: str) -> tuple[bytes, dict]:
    """Return (EC private key, decrypted keychain document) for an account payload."""
    try:
        blob_key = decrypt_blob_key(account.get("encryptedBlobKeys") or [], password)
        doc = decrypt_account_blob(account["blob"], blob_key)
    except KeychainError:
        raise
    except (KeyError, TypeError, ValueError, struct.error, RecursionError) as exc:
        raise KeychainError(f"could not decrypt the account blob: {exc!r}") from exc
    private_key = find_private_key(doc)
    if not private_key:
        raise KeychainError("no privateKey in the decrypted account blob")
    return private_key, doc
