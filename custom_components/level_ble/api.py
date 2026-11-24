"""Minimal async client for Level's mobile backend (api.level.co)."""

from __future__ import annotations

import json
from typing import Any

import aiohttp
from multidict import CIMultiDict

from .account import iter_devices, login_statuses
from .keychain import login_password

__all__ = ["LevelAuthError", "LevelCloud", "LevelError", "LevelTfaRequired", "iter_devices"]

API_BASE = "https://api.level.co"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)
USER_AGENT = "ha-level-ble/0.1"


class LevelError(Exception):
    """Base error."""


class LevelAuthError(LevelError):
    """Credentials or token rejected."""


class LevelTfaRequired(LevelError):
    """Account has 2FA enabled; OTP login is not implemented yet."""


class LevelCloud:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        email: str | None = None,
        password: str | None = None,
        token: str | None = None,
        base_url: str = API_BASE,
    ) -> None:
        self._session = session
        self._email = email
        self._password = password
        self._token = token
        self._base = base_url.rstrip("/")

    @property
    def token(self) -> str | None:
        return self._token

    async def _request(
        self, method: str, path: str, *, body: dict | None = None
    ) -> tuple[Any, CIMultiDict[str]]:
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._token:
            headers["AccessToken"] = self._token
        try:
            async with self._session.request(
                method,
                self._base + path,
                data=json.dumps(body) if body is not None else None,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            ) as resp:
                text = await resp.text()
                if resp.status in (401, 403):
                    raise LevelAuthError(f"{method} {path} rejected: HTTP {resp.status}")
                if resp.status >= 400:
                    raise LevelError(f"{method} {path} failed: HTTP {resp.status} {text[:300]}")
                response_headers = CIMultiDict(resp.headers)
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise LevelError(f"{method} {path} failed: {exc!r}") from exc
        try:
            data = json.loads(text) if text.strip() else None
        except ValueError as exc:
            raise LevelError(f"{method} {path} returned non-JSON: {text[:200]!r}") from exc
        return data, response_headers

    async def async_login(self) -> str:
        if not self._email or self._password is None:
            raise LevelAuthError("email and password are required")
        data, headers = await self._request(
            "POST",
            "/v2/login",
            body={"userID": self._email, "password": login_password(self._password)},
        )
        statuses = login_statuses(data)
        # A 2FA account can still get a (limited) token back, so check the
        # status first rather than only when the token is missing.
        if any("tfa" in status.lower() for status in statuses):
            raise LevelTfaRequired("account requires 2FA")
        token = headers.get("AccessToken")
        if not token:
            raise LevelAuthError(f"login rejected (status={statuses})")
        self._token = token
        return token

    async def async_account(self) -> dict:
        data, _ = await self._request("GET", "/v2/account/get")
        if not isinstance(data, dict):
            raise LevelError("unexpected account payload")
        return data
