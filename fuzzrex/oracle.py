"""Differential oracle and joint config x API search.

Flags security-relevant response changes across config cells, and drives
the feedback loop that mutates configs while replaying a fixed request
sequence.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

import requests

from fuzzrex.config_fuzzer import mutate_config
from fuzzrex.mutation import mutate_request
from fuzzrex.orchestrator import (
    DockerComposeOrchestrator,
    OrchestratorError,
    configured_service,
)

DEFAULT_TIMEOUT = 10.0
# Re-seed from the baseline this often so a single interesting cell cannot
# monopolize the mutation chain (diversity vs. exploitation balance).
RESTART_EVERY = 4
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
    """A single planned request; identical instances are replayed across config cells.

    `token_from` labels an earlier request whose JSON `token` field becomes
    this request's `Authorization: Bearer` value at send time (resolved
    independently inside each config cell). `param_from` maps query-parameter
    names to `(label, json_key)` producer links resolved the same way.
    `files` carries multipart payloads as `field -> (filename, content, type)`.
    """

    method: str
    url: str
    params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Any = None
    path: str = ""
    label: str = ""
    token_from: str = ""
    param_from: dict[str, tuple[str, str]] = field(default_factory=dict)
    files: dict[str, tuple[str, bytes, str]] | None = None


@dataclass(frozen=True)
class ResponseSnapshot:
    status_code: int | None
    body: Any
    text_sample: str
    sensitive_keys: frozenset[str]
    location: str = ""

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
    # Redirects are not followed: the immediate status + Location are part of
    # what differs across config cells (e.g. 302 to a login page).
    return requests.request(
        request.method,
        request.url,
        params=request.params,
        headers=request.headers,
        cookies=request.cookies,
        json=None if request.files else request.body,
        files=request.files,
        timeout=timeout,
        allow_redirects=False,
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
    # requests.structures.CaseInsensitiveDict is a Mapping, not a dict.
    headers = getattr(response, "headers", None)
    location = ""
    if isinstance(headers, Mapping):
        raw = headers.get("Location", "")
        location = raw if isinstance(raw, str) else ""
    return ResponseSnapshot(
        status_code=response.status_code,
        body=body,
        text_sample=text_sample,
        sensitive_keys=sensitive,
        location=location,
    )


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)


def execute_sequence(
    sequence: Sequence[HttpRequest],
    timeout: float = DEFAULT_TIMEOUT,
) -> list[ResponseSnapshot]:
    snapshots: list[ResponseSnapshot] = []
    captured: dict[str, dict[str, Any]] = {}
    for request in sequence:
        planned = _resolve_links(request, captured)
        try:
            response = send_request(planned, timeout=timeout)
        except requests.RequestException:
            snapshots.append(ResponseSnapshot(None, None, "", frozenset()))
            continue
        snapshot = snapshot_response(response)
        snapshots.append(snapshot)
        if isinstance(snapshot.body, dict):
            captured[request.label] = snapshot.body
    return snapshots


def _resolve_links(request: HttpRequest, captured: dict[str, dict[str, Any]]) -> HttpRequest:
    """Fill bearer token and query params from responses of earlier requests."""
    headers = request.headers
    params = request.params
    changed = False

    if request.token_from:
        token = (captured.get(request.token_from) or {}).get("token")
        if token:
            headers = {**headers, "Authorization": f"Bearer {token}"}
            changed = True

    for name, (label, key) in request.param_from.items():
        producer = captured.get(label) or {}
        if key in producer:
            params = {**params, name: producer[key]}
            changed = True

    if not changed:
        return request
    return replace(request, headers=headers, params=params)


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

    if _crosses_auth(base_status, baseline.location, var_status, variant.location):
        if _is_auth_status(var_status, variant.location):
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


def _crosses_auth(base_status: int, base_location: str, var_status: int, var_location: str) -> bool:
    return (
        _is_success(base_status) and _is_auth_status(var_status, var_location)
    ) or (
        _is_auth_status(base_status, base_location) and _is_success(var_status)
    )


def _is_auth_status(status: int, location: str) -> bool:
    """401/403, or a redirect whose Location targets a login page."""
    if status in AUTH_STATUSES:
        return True
    return status is not None and 300 <= status < 400 and "login" in (location or "").lower()


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


@dataclass(frozen=True)
class CellResult:
    """A config cell whose responses diverged from the baseline in a security-relevant way."""

    config: Any
    divergences: tuple[Divergence, ...]
    # With request-side mutation: the single-slot patch that defined the
    # request variant this cell was replayed under (empty when fixed-sequence).
    request_patch: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SearchTrace:
    """Full record of one joint-search run, divergent or not."""

    divergent_cells: tuple[CellResult, ...]
    unique_cells: int
    cells_visited: int
    cells_unhealthy: int
    first_divergence_iteration: int | None
    first_divergence_s: float | None
    elapsed_s: float
    stopped_early: bool = False
    request_iterations: int = 0


def canonical_config(config: Any) -> str:
    """Canonical form for deduplicating configs (mutations never add keys)."""
    return json.dumps(config, sort_keys=True, separators=(",", ":"), default=str)


def _variant_key(patch: Mapping[str, Any]) -> str:
    """Canonical form of a request-mutation patch; equal patches are the same variant."""
    if not patch:
        return ""
    return json.dumps(patch, sort_keys=True, separators=(",", ":"), default=str)


def run_joint_search_traced(
    orchestrator: DockerComposeOrchestrator,
    baseline_config: Any,
    sequence: Sequence[HttpRequest],
    *,
    iterations: int = 20,
    seed: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    enums: dict[str, Any] | None = None,
    feedback: bool = True,
    stall_window: int | None = None,
    request_mutation: float = 0.0,
) -> SearchTrace:
    """Alternate config mutation and API probing; trace the whole run.

    Baseline snapshots are recorded once. Each iteration mutates a config,
    replays the fixed request sequence under it, and diffs against
    baseline. Cells that fail to become healthy are counted and skipped.

    `feedback=True` grows the mutation base from divergent cells (with
    periodic restarts to the baseline); `feedback=False` is the ablation
    arm -- every iteration mutates the baseline independently, so no
    divergence information ever influences where the search goes.
    `enums` constrains named keys to their allowed values during mutation.

    `stall_window=None` disables early stopping. With `stall_window=k`,
    the run stops (trace `stopped_early=True`) once k consecutive
    iterations produced no *new* unique divergent cell; unhealthy,
    non-divergent, and duplicate-divergent iterations all count as
    stalls.

    `request_mutation=p` (default 0.0, the archived fixed-sequence
    protocol) makes an iteration replay a single-slot mutated copy of
    the planned sequence with probability p (p=1.0 mutates every
    iteration). Pairing is preserved: the
    variant's baseline snapshots are recorded lazily under c0 on first
    use and cached, so both sides of every comparison see the same
    request inputs and only the config can explain a divergence.
    Mutations use a dedicated RNG seeded like the config one, so the
    request schedule is identical across arms of the same seed.
    """
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    if stall_window is not None and stall_window < 1:
        raise ValueError("stall_window must be >= 1 or None")
    if not 0.0 <= request_mutation <= 1.0:
        raise ValueError("request_mutation must be in [0.0, 1.0]")

    rng = random.Random(seed)
    # Cells are applied with defer=True (disk-only exit, no restart) since
    # every next block re-applies a config before any request is sent; the
    # final restore() lands the SUT back on c0 exactly once. Profiling shows
    # eager per-block restore was ~40-50% of campaign wall time.
    try:
        with configured_service(orchestrator, baseline_config, defer=True):
            baseline_snaps = execute_sequence(sequence, timeout=timeout)

        mutation_base = baseline_config
        results: list[CellResult] = []
        visited = unhealthy = 0
        first_iteration: int | None = None
        first_at: float | None = None
        seen_unique: set[str] = set()
        stall = 0
        stopped = False
        request_iters = 0
        rng_request = random.Random(seed) if request_mutation > 0.0 else None
        variant_baselines: dict[str, list[ResponseSnapshot]] = {}
        started = time.monotonic()

        for index in range(iterations):
            variant = mutate_config(mutation_base, rng, enums=enums)
            replay: list[HttpRequest] = sequence
            base_key = ""
            patch: dict[str, Any] = {}
            if rng_request is not None and rng_request.random() < request_mutation:
                request_iters += 1
                replay, patch = mutate_request(sequence, rng_request)
                base_key = _variant_key(patch)
            new_unique = False
            try:
                if base_key:
                    base_snaps = variant_baselines.get(base_key)
                    if base_snaps is None:  # first sighting: record c0 under this variant
                        with configured_service(orchestrator, baseline_config, defer=True):
                            base_snaps = execute_sequence(replay, timeout=timeout)
                        variant_baselines[base_key] = base_snaps
                else:
                    base_snaps = baseline_snaps
                with configured_service(orchestrator, variant, defer=True):
                    snaps = execute_sequence(replay, timeout=timeout)
            except OrchestratorError:
                unhealthy += 1
            else:
                visited += 1
                divergences = compare_sequences(replay, base_snaps, snaps)
                if divergences:
                    results.append(CellResult(variant, tuple(divergences), request_patch=patch))
                    if first_iteration is None:
                        first_iteration = index
                        first_at = time.monotonic() - started
                    key = f"{canonical_config(variant)}|{base_key}"
                    if key not in seen_unique:
                        seen_unique.add(key)
                        new_unique = True
                    if feedback:
                        mutation_base = variant
                elif feedback and index % RESTART_EVERY == RESTART_EVERY - 1:
                    mutation_base = baseline_config

            stall = 0 if new_unique else stall + 1
            if stall_window is not None and stall >= stall_window:
                stopped = True
                break

        return SearchTrace(
            divergent_cells=tuple(results),
            unique_cells=len(seen_unique),
            cells_visited=visited,
            cells_unhealthy=unhealthy,
            first_divergence_iteration=first_iteration,
            first_divergence_s=first_at,
            elapsed_s=time.monotonic() - started,
            stopped_early=stopped,
            request_iterations=request_iters,
        )
    finally:
        orchestrator.restore()


def run_joint_search(
    orchestrator: DockerComposeOrchestrator,
    baseline_config: Any,
    sequence: Sequence[HttpRequest],
    *,
    iterations: int = 20,
    seed: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    enums: dict[str, Any] | None = None,
    feedback: bool = True,
) -> list[CellResult]:
    """Run the joint search and return only the divergent cells (see `run_joint_search_traced`)."""
    trace = run_joint_search_traced(
        orchestrator,
        baseline_config,
        sequence,
        iterations=iterations,
        seed=seed,
        timeout=timeout,
        enums=enums,
        feedback=feedback,
    )
    return list(trace.divergent_cells)
