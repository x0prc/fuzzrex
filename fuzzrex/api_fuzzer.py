"""Stateful black-box fuzzer driven by an OpenAPI specification."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import requests

from fuzzrex.auth import AuthHandler
from fuzzrex.mutations import fuzz_value
from fuzzrex.spec import load_spec
from fuzzrex.state import StateManager

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

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for method, path, details in self.iter_operations():
            request_kwargs = self._build_request(method, path, details)
            try:
                response = requests.request(
                    method,
                    request_kwargs["url"],
                    params=request_kwargs["params"],
                    headers=request_kwargs["headers"],
                    cookies=request_kwargs["cookies"],
                    json=request_kwargs["json"],
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                findings.append(Finding(method, path, None, f"request error: {exc}"))
                continue

            self.state.update(response)
            if response.status_code >= 500:
                findings.append(
                    Finding(method, path, response.status_code, "server error"),
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
