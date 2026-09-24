"""Differential oracle: flag security-relevant response changes across config cells."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import requests

from fuzzrex.orchestrator import DockerComposeOrchestrator, configured_service

DEFAULT_TIMEOUT = 10.0
SENSITIVE_KEY_MARKERS = (
    "stack",
    "traceback",
    "debug",
    "password",
    "secret",
    "token",
    "cwd",
    "config",
)
AUTH_STATUSES = frozenset({401, 403})


@dataclass(frozen=True)
class HttpRequest:
    """A single planned request; identical instances are replayed across config cells."""

    method: str
    url: str
    params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Any = None
    path: str = ""
    label: str = ""


@dataclass(frozen=True)
class ResponseSnapshot:
    status_code: int | None
    body: Any
    text_sample: str
    sensitive_keys: frozenset[str]

    @property
    def ok(self) -> bool:
        return self.status_code is not None


@dataclass(frozen=True)
class Divergence:
    """A security-relevant difference between baseline and variant responses."""

    request_label: str
    kind: str
    detail: str
    baseline_status: int | None
    variant_status: int | None


def send_request(request: HttpRequest, timeout: float = DEFAULT_TIMEOUT) -> requests.Response:
    return requests.request(
        request.method,
        request.url,
        params=request.params,
        headers=request.headers,
        cookies=request.cookies,
        json=request.body,
        timeout=timeout,
    )


def snapshot_response(response: requests.Response) -> ResponseSnapshot:
    try:
        body: Any = response.json()
    except ValueError:
        body = None
    keys = _collect_keys(body) if body is not None else frozenset()
    sensitive = frozenset(k for k in keys if is_sensitive_key(k))
    text_sample = response.text[:1000]
    if "traceback" in text_sample.lower() and "traceback" not in {k.lower() for k in sensitive}:
        sensitive = sensitive | {"traceback"}
    return ResponseSnapshot(
        status_code=response.status_code,
        body=body,
        text_sample=text_sample,
        sensitive_keys=sensitive,
    )


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)


def execute_sequence(
    sequence: Sequence[HttpRequest],
    timeout: float = DEFAULT_TIMEOUT,
) -> list[ResponseSnapshot]:
    snapshots: list[ResponseSnapshot] = []
    for request in sequence:
        try:
            response = send_request(request, timeout=timeout)
        except requests.RequestException:
            snapshots.append(ResponseSnapshot(None, None, "", frozenset()))
            continue
        snapshots.append(snapshot_response(response))
    return snapshots


def compare_sequences(
    sequence: Sequence[HttpRequest],
    baseline: Sequence[ResponseSnapshot],
    variant: Sequence[ResponseSnapshot],
) -> list[Divergence]:
    if not (len(sequence) == len(baseline) == len(variant)):
        raise ValueError("planned requests and snapshots must have equal length")

    divergences: list[Divergence] = []
    for request, base_snap, var_snap in zip(sequence, baseline, variant, strict=True):
        divergences.extend(_compare_pair(request, base_snap, var_snap))
    return divergences


def differential_probe(
    orchestrator: DockerComposeOrchestrator,
    baseline_config: Any,
    variant_config: Any,
    sequence: Sequence[HttpRequest],
    timeout: float = DEFAULT_TIMEOUT,
) -> list[Divergence]:
    """Execute the same planned sequence under two config cells and diff the results."""
    with configured_service(orchestrator, baseline_config):
        baseline = execute_sequence(sequence, timeout=timeout)
    with configured_service(orchestrator, variant_config):
        variant = execute_sequence(sequence, timeout=timeout)
    return compare_sequences(sequence, baseline, variant)


def _compare_pair(
    request: HttpRequest,
    baseline: ResponseSnapshot,
    variant: ResponseSnapshot,
) -> list[Divergence]:
    label = request.label or f"{request.method} {request.url}"
    base_status, var_status = baseline.status_code, variant.status_code
    found: list[Divergence] = []

    if base_status is None or var_status is None:
        if base_status != var_status:
            found.append(
                Divergence(
                    label,
                    "transport",
                    "reachable in only one config cell",
                    base_status,
                    var_status,
                ),
            )
        return found

    if _crosses_auth(base_status, var_status):
        if var_status in AUTH_STATUSES:
            direction = "auth required under variant"
        else:
            direction = "auth bypassed under variant"
        found.append(
            Divergence(label, "auth-boundary", direction, base_status, var_status),
        )
    elif base_status != var_status and (base_status >= 500 or var_status >= 500):
        found.append(
            Divergence(
                label,
                "server-error",
                "5xx in only one config cell",
                base_status,
                var_status,
            ),
        )
    elif base_status != var_status and _is_success(base_status) != _is_success(var_status):
        found.append(
            Divergence(
                label,
                "status",
                "success/failure changed across configs",
                base_status,
                var_status,
            ),
        )

    leaked = variant.sensitive_keys - baseline.sensitive_keys
    if leaked:
        found.append(
            Divergence(
                label,
                "info-leak",
                f"sensitive keys under variant only: {sorted(leaked)}",
                base_status,
                var_status,
            ),
        )
    return found


def _crosses_auth(baseline: int, variant: int) -> bool:
    return (_is_success(baseline) and variant in AUTH_STATUSES) or (
        baseline in AUTH_STATUSES and _is_success(variant)
    )


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _collect_keys(body: Any) -> frozenset[str]:
    keys: set[str] = set()
    stack: list[Any] = [body]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                keys.add(str(key))
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    return frozenset(keys)
