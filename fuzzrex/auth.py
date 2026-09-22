"""Authentication header construction for fuzzing sessions."""

from __future__ import annotations

from typing import Any

import requests

DEFAULT_TIMEOUT = 10.0


class AuthHandler:
    """Build Authorization headers for bearer-token or OAuth2 client-credentials flows."""

    def __init__(
        self,
        auth_type: str | None = None,
        token: str | None = None,
        oauth2: dict[str, Any] | None = None,
    ) -> None:
        if auth_type not in (None, "token", "oauth2"):
            raise ValueError(f"Unsupported auth_type: {auth_type!r}")
        if auth_type == "token" and not token:
            raise ValueError("auth_type='token' requires a token")
        if auth_type == "oauth2" and not oauth2:
            raise ValueError("auth_type='oauth2' requires an oauth2 config dict")
        if auth_type == "oauth2":
            missing = {"client_id", "client_secret", "token_url"} - oauth2.keys()
            if missing:
                raise ValueError(f"oauth2 config missing keys: {sorted(missing)}")

        self.auth_type = auth_type
        self.token = token
        self.oauth2 = oauth2 or {}
        self._cached_token: str | None = None

    def headers(self) -> dict[str, str]:
        if self.auth_type == "token" and self.token:
            return {"Authorization": f"Bearer {self.token}"}
        if self.auth_type == "oauth2":
            token = self._cached_token or self._retrieve_oauth2_token()
            if not token:
                raise RuntimeError("Failed to obtain OAuth2 access token")
            self._cached_token = token
            return {"Authorization": f"Bearer {token}"}
        return {}

    def invalidate(self) -> None:
        """Drop any cached OAuth2 token (e.g. after a 401)."""
        self._cached_token = None

    def _retrieve_oauth2_token(self) -> str | None:
        try:
            response = requests.post(
                self.oauth2["token_url"],
                data={
                    "grant_type": self.oauth2.get("grant_type", "client_credentials"),
                    "client_id": self.oauth2["client_id"],
                    "client_secret": self.oauth2["client_secret"],
                    "scope": self.oauth2.get("scope", ""),
                },
                timeout=DEFAULT_TIMEOUT,
            )
        except requests.RequestException:
            return None
        if response.status_code != 200:
            return None
        return response.json().get("access_token")
