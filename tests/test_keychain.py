"""Keychain crypto, BSON, and account unlock."""

from __future__ import annotations

import ast
import base64
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from custom_components.level_ble import keychain
from custom_components.level_ble.keychain import (
    KeychainError,
    bson_decode,
    bson_encode,
    chacha20,
    decode_flexible,
    derive_password_key,
    find_private_keys,
    unlock_account,
)

INTEGRATION = Path(keychain.__file__).parent


def _reference_chacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    full_nonce = counter.to_bytes(4, "little") + nonce
    return Cipher(algorithms.ChaCha20(key, full_nonce), mode=None).encryptor().update(data)


@pytest.mark.parametrize("length", [0, 1, 63, 64, 65, 200])
@pytest.mark.parametrize("counter", [0, 1, 7])
def test_chacha20_matches_cryptography(length: int, counter: int) -> None:
    key, nonce, data = os.urandom(32), os.urandom(12), os.urandom(length)
    assert chacha20(key, nonce, data, counter) == _reference_chacha20(key, nonce, data, counter)
    assert chacha20(key, nonce, chacha20(key, nonce, data, counter), counter) == data


def test_chacha20_rejects_bad_sizes() -> None:
    with pytest.raises(ValueError):
        chacha20(b"k" * 31, b"n" * 12, b"x")
    with pytest.raises(ValueError):
        chacha20(b"k" * 32, b"n" * 8, b"x")


def test_password_kdf_is_102_rounds_of_sha256() -> None:
    import hashlib

    digest = hashlib.sha256(b"hunter2" + keychain.KDF_SALT).digest()
    for _ in range(101):
        digest = hashlib.sha256(digest).digest()
    assert derive_password_key("hunter2") == digest


def test_bson_round_trip() -> None:
    doc = {
        "s": "héllo",
        "i": -5,
        "big": 2**40,
        "f": 1.5,
        "t": True,
        "n": None,
        "b": b"\x00\x01\xff",
        "d": {"inner": "x"},
        "a": [1, "two", {"three": 3}, [4]],
    }
    assert bson_decode(bson_encode(doc)) == doc


def test_bson_array_decodes_as_list() -> None:
    # Regression: arrays used to decode as {"0": ..., "1": ...}, which hid the
    # privateKey from find_private_key.
    assert bson_decode(bson_encode({"privateKey": [1, 2, 3]})) == {"privateKey": [1, 2, 3]}


@pytest.mark.parametrize("garbage", [b"", b"\x01\x00", b"\xff\xff\xff\x7f\x00", os.urandom(64)])
def test_bson_rejects_garbage(garbage: bytes) -> None:
    with pytest.raises(ValueError):
        bson_decode(garbage)


def test_decode_flexible() -> None:
    assert decode_flexible("00" * 12) == bytes(12)
    assert decode_flexible("ab" * 32) == b"\xab" * 32
    assert decode_flexible(base64.b64encode(b"x" * 32).decode()) == b"x" * 32


def _make_account(password: str, key_doc: dict, *, encoding: str = "hex") -> dict:
    blob_key = os.urandom(32)
    key_nonce, blob_nonce = os.urandom(12), os.urandom(12)
    wrapped = chacha20(derive_password_key(password), key_nonce, blob_key)
    encode = bytes.hex if encoding == "hex" else (lambda b: base64.b64encode(b).decode())
    return {
        "encryptedBlobKeys": [
            {"name": "recovery", "nonce": "00" * 12, "value": "00" * 32},
            {"name": "Password", "nonce": encode(key_nonce), "value": encode(wrapped)},
        ],
        "blob": {
            "nonce": blob_nonce.hex(),
            "value": chacha20(blob_key, blob_nonce, bson_encode(key_doc)).hex(),
        },
    }


@pytest.mark.parametrize("encoding", ["hex", "base64"])
def test_unlock_account_with_int_array_key(encoding: str) -> None:
    private = bytes(range(1, 33))
    doc = {"userID": "u", "keys": [{"privateKey": list(private)}]}
    key, decrypted = unlock_account(_make_account("pw", doc, encoding=encoding), "pw")
    assert key == private
    assert decrypted == doc


def test_unlock_account_with_binary_key() -> None:
    private = os.urandom(32)
    key, _ = unlock_account(_make_account("pw", {"account": {"privateKey": private}}), "pw")
    assert key == private


def test_unlock_account_wrong_password() -> None:
    account = _make_account("right", {"privateKey": list(range(32))})
    with pytest.raises(KeychainError):
        unlock_account(account, "wrong")


def test_unlock_account_without_key_or_blob() -> None:
    with pytest.raises(KeychainError, match="no privateKey"):
        unlock_account(_make_account("pw", {"other": 1}), "pw")
    with pytest.raises(KeychainError, match="no password blob key"):
        unlock_account({"encryptedBlobKeys": []}, "pw")
    account = _make_account("pw", {"privateKey": [1]})
    del account["blob"]
    with pytest.raises(KeychainError):
        unlock_account(account, "pw")


def test_find_private_keys_reports_paths_and_skips_non_bytes() -> None:
    doc = {"a": {"privateKey": [1, 2]}, "b": [{"privateKey": "not-a-key"}, {"privateKey": [300]}]}
    assert find_private_keys(doc) == [("a.privateKey", b"\x01\x02")]


@pytest.mark.parametrize("module", ["keychain.py", "const.py", "account.py", "wire.py"])
def test_tool_shared_modules_are_stdlib_only(module: str) -> None:
    """tools/ import these files without Home Assistant or any pip packages."""
    tree = ast.parse((INTEGRATION / module).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports break tools/_shared.py"
            imported.add(node.module.split(".")[0])
    assert imported <= set(sys.stdlib_module_names) | {"__future__"}
