#!/usr/bin/env python3
"""
Level keychain proof-of-concept.

Logs into Level's cloud with email + password, reproduces the app's
password-derived blob key, decrypts the account blob and reports what it
contains (notably the account EC private key used for BLE sessions).

It talks only to api.level.co and does not touch the lock. The crypto and
BSON code is the integration's own (custom_components/level_ble/keychain.py).

Usage:
    LEVEL_EMAIL='you@example.com' LEVEL_PASSWORD='...' python3 tools/level_keychain.py
    python3 tools/level_keychain.py --show-key          # also print the private key
    python3 tools/level_keychain.py --save account.json # save the raw account JSON

Requires Python 3.9+. No third-party packages.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request

import _shared  # noqa: F401  (puts the integration's stdlib modules on sys.path)
from account import iter_devices, login_statuses  # type: ignore[import-not-found]
from keychain import (  # type: ignore[import-not-found]
    KDF_ITERATIONS,
    BSONReader,
    KeychainError,
    chacha20,
    decrypt_blob_key,
    find_private_keys,
    login_password,
)

DEFAULT_API = "https://api.level.co"


class Client:
    def __init__(self, base: str, debug: bool) -> None:
        self.base = base.rstrip("/")
        self.debug = debug

    def request(self, method: str, path: str, *, body: dict | None = None, token: str | None = None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json", "User-Agent": "level-keychain-poc/0.1"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["AccessToken"] = token
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                if self.debug:
                    print(f"  {method} {path} -> {resp.status}")
                    for key, value in resp.headers.items():
                        shown = "<redacted>" if key.lower() == "accesstoken" else value
                        print(f"    {key}: {shown}")
                parsed = json.loads(raw) if raw.strip() else None
                return resp.status, resp.headers, parsed
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:800]
            raise SystemExit(f"HTTP {e.code} on {method} {path}: {detail}") from None
        except urllib.error.URLError as e:
            raise SystemExit(f"Could not reach {self.base}: {e.reason}") from None

    def login(self, email: str, password: str) -> str:
        # The app sends a salted SHA-256 hash of the password, never the password.
        body = {"userID": email, "password": login_password(password)}
        status, headers, parsed = self.request("POST", "/v2/login", body=body)
        token = headers.get("AccessToken")  # email.message.Message: case-insensitive
        statuses = login_statuses(parsed)
        print(f"  login status={status} api_status={statuses} token={'yes' if token else 'no'}")
        if self.debug and not token:
            print(f"  body: {parsed!r}")
        if any("tfa" in s.lower() for s in statuses):
            raise SystemExit(
                "This account has 2FA enabled. OTP login is not implemented yet; please open an issue."
            )
        if not token:
            if any("loginfailed" in s.lower() for s in statuses):
                raise SystemExit(
                    "Level rejected the email or password. Check them in the Level app; "
                    "repeated failures may lock the account for a while."
                )
            raise SystemExit("No AccessToken in the login response. Re-run with --debug to see it.")
        return token


def summarize_keychain(doc: dict) -> None:
    print(f"\nKeychain document keys: {', '.join(sorted(doc.keys()))}")


def summarize_locks(account: dict) -> None:
    """The locks Home Assistant's setup will offer, parsed exactly as the integration does."""
    devices = iter_devices(account)
    print(f"\nLocks on this account: {len(devices)}")
    for d in devices:
        print(
            f"  - {d['name']} ({d['location']}) ble_name={d['ble_name']} product={d['product']} "
            f"uuid={d['uuid']} serial={'yes' if d['serial'] else 'no'} "
            f"public_key={'yes' if d['public_key'] else 'no'}"
        )
    if not devices:
        print(f"  none found; account top-level keys: {', '.join(sorted(account.keys()))}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Level keychain proof-of-concept")
    ap.add_argument("--show-key", action="store_true", help="print the decrypted EC private key")
    ap.add_argument("--save", metavar="FILE", help="save the raw account JSON (sensitive)")
    ap.add_argument("--debug", action="store_true", help="print response status and headers")
    ap.add_argument("--api", default=DEFAULT_API, help="override API base URL")
    args = ap.parse_args()

    client = Client(args.api, args.debug)
    email = os.environ.get("LEVEL_EMAIL") or input("Level email: ").strip()
    password = os.environ.get("LEVEL_PASSWORD") or getpass.getpass("Level password: ")

    print("Logging in...")
    token = client.login(email, password)

    print("Fetching account...")
    _, _, account = client.request("GET", "/v2/account/get", token=token)
    if not isinstance(account, dict):
        raise SystemExit(f"Unexpected account response: {account!r}")

    if args.save:
        with open(args.save, "w") as fh:
            json.dump(account, fh, indent=2)
        os.chmod(args.save, 0o600)
        print(f"  saved raw account JSON to {args.save} (mode 600)")

    enc_keys = account.get("encryptedBlobKeys") or []
    blob = account.get("blob")
    print(f"  encrypted blob keys: {[k.get('name') for k in enc_keys]}")
    if not blob:
        raise SystemExit("Account has no blob")

    print(f"Deriving blob key (SHA-256 x{KDF_ITERATIONS}, ChaCha20)...")
    try:
        blob_key = decrypt_blob_key(enc_keys, password)
    except KeychainError as exc:
        raise SystemExit(str(exc)) from None
    print(f"  blob key: {len(blob_key)} bytes")

    plain = chacha20(blob_key, bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["value"]))
    print(f"  account blob: {len(plain)} bytes")

    try:
        doc = BSONReader(plain).document()
    except ValueError as exc:
        print(f"  BSON parse failed ({exc}); first bytes:")
        print("  " + plain[:64].hex())
        raise SystemExit(1) from None

    summarize_keychain(doc)
    summarize_locks(account)

    keys = find_private_keys(doc)
    print(f"\nPrivate keys found: {len(keys)}")
    for path, raw in keys:
        print(f"  {path}: {len(raw)} bytes, prefix={raw[:1].hex()}")
        if args.show_key:
            print(f"    hex: {raw.hex()}")

    if keys:
        print("\nKeychain unlocked. Next stage: BLE session + lock commands.")
    else:
        print("\nBlob decrypted but no privateKey field; please open an issue with the key list.")


if __name__ == "__main__":
    sys.exit(main())
