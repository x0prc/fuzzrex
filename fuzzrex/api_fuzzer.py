"""Stateful black-box fuzzer driven by an OpenAPI specification.

Includes the bearer/OAuth2 auth handler and the response-value state
manager used during fuzzing sessions.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import requests

from fuzzrex.oracle import HttpRequest, send_request
from fuzzrex.schema import fuzz_value, load_spec

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
JSON_CONTENT = "application/json"
DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True)
class Finding:
    """A single suspicious response observed during a fuzzing run."""

    method: str
    path: str
    status_code: int | None
    detail: str


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


class StateManager:
    """Collect scalar values from JSON responses so later requests can reuse them."""

    def __init__(self) -> None:
        self.known_values: dict[str, Any] = {}
        self.last_response: dict[str, Any] | None = None

    def update(self, response: requests.Response) -> None:
        try:
            body = response.json()
        except ValueError:
            return
        if isinstance(body, dict):
            self.last_response = body
            self._collect(body)

    def resolve(self, name: str, default: Any = None) -> Any:
        return self.known_values.get(name, default)

    def _collect(self, payload: dict[str, Any]) -> None:
        for key, value in payload.items():
            if isinstance(value, dict):
                self._collect(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._collect(item)
            elif value is not None:
                self.known_values[key] = value


class ApiFuzzer:
    def __init__(
        self,
        spec_path: str,
        base_url: str | None = None,
        auth: AuthHandler | None = None,
        state: StateManager | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.spec = load_spec(spec_path)
        self.base_url = (base_url or self._default_base_url()).rstrip("/")
        self.auth = auth or AuthHandler()
        self.state = state or StateManager()
        self.timeout = timeout

    def _default_base_url(self) -> str:
        servers = self.spec.get("servers") or []
        if servers and isinstance(servers[0], dict) and servers[0].get("url"):
            url = str(servers[0]["url"])
            # Skip relative server URLs; caller must supply an absolute base.
            if url.startswith(("http://", "https://")):
                return url
        return "http://localhost:5000"

    def iter_operations(self) -> Iterator[tuple[str, str, dict[str, Any]]]:
        """Yield (method, path, operation) for each documented operation."""
        for path, path_item in (self.spec.get("paths") or {}).items():
            if not isinstance(path_item, dict):
                continue
            shared_params = path_item.get("parameters") or []
            for method, details in path_item.items():
                if method.lower() not in HTTP_METHODS or not isinstance(details, dict):
                    continue
                details = {**details}
                details["_shared_parameters"] = shared_params
                yield method.upper(), path, details

    def plan(self) -> list[HttpRequest]:
        """Build the full request sequence once so it can be replayed across config cells."""
        planned: list[HttpRequest] = []
        for method, path, details in self.iter_operations():
            built = self._build_request(method, path, details)
            planned.append(
                HttpRequest(
                    method=method,
                    url=built["url"],
                    params=built["params"],
                    headers=built["headers"],
                    cookies=built["cookies"],
                    body=built["json"],
                    path=path,
                    label=f"{method} {path}",
                ),
            )
        return planned

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for request in self.plan():
            try:
                response = send_request(request, timeout=self.timeout)
            except requests.RequestException as exc:
                findings.append(
                    Finding(
                        request.method,
                        request.path or request.label,
                        None,
                        f"request error: {exc}",
                    ),
                )
                continue

            self.state.update(response)
            if response.status_code >= 500:
                findings.append(
                    Finding(
                        request.method,
                        request.path or request.label,
                        response.status_code,
                        "server error",
                    ),
                )
        return findings

    def _build_request(self, method: str, path: str, details: dict[str, Any]) -> dict[str, Any]:
        parameters = list(details.get("_shared_parameters") or [])
        parameters.extend(details.get("parameters") or [])

        resolved_path = path
        params: dict[str, Any] = {}
        headers = self.auth.headers()
        cookies: dict[str, Any] = {}
        body: Any = None

        for param in parameters:
            if not isinstance(param, dict) or "$ref" in param:
                continue
            name = param.get("name")
            if not name:
                continue
            location = param.get("in", "query")
            schema = param.get("schema") or {"type": "string"}
            value = self._value_for(name, schema)

            if location == "path":
                resolved_path = resolved_path.replace(
                    "{" + name + "}",
                    quote(str(value), safe=""),
                )
            elif location == "query":
                params[name] = value
            elif location == "header":
                headers[name] = str(value)
            elif location == "cookie":
                cookies[name] = str(value)

        body_schema = self._request_body_schema(details)
        if body_schema is not None:
            body = fuzz_value(body_schema)

        return {
            "url": f"{self.base_url}{resolved_path}",
            "params": params,
            "headers": headers,
            "cookies": cookies,
            "json": body,
        }

    def _request_body_schema(self, details: dict[str, Any]) -> dict[str, Any] | None:
        request_body = details.get("requestBody")
        if not isinstance(request_body, dict):
            return None
        content = request_body.get("content") or {}
        if JSON_CONTENT in content:
            return (content[JSON_CONTENT] or {}).get("schema")
        # Fall back to the first content type that carries a schema.
        for media in content.values():
            if isinstance(media, dict) and media.get("schema"):
                return media["schema"]
        return None

    def _value_for(self, name: str, schema: dict[str, Any]) -> Any:
        # Prefer values harvested from prior responses (producer-consumer links).
        known = self.state.resolve(name)
        if known is not None and not isinstance(known, (dict, list)):
            return known
        return fuzz_value(schema)
