"""Discover a deployable spec subset and observable config knobs on a live SUT.

Both passes replace manual fixture work with mechanical, reproducible
probes against the baseline cell: `prune_spec` drops operations the
deployment does not serve (plus anything chained to them), and
`filter_knobs` drops candidate config keys whose values never change
an HTTP response. What remains is what the joint search can actually
observe; endpoint relevance to config gates stays fixture work.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from fuzzrex.api_fuzzer import HTTP_METHODS, ApiFuzzer
from fuzzrex.config_fuzzer import _collect_leaves
from fuzzrex.oracle import DEFAULT_TIMEOUT, HttpRequest, ResponseSnapshot, execute_sequence
from fuzzrex.orchestrator import (
    DockerComposeOrchestrator,
    OrchestratorError,
    configured_service,
)
from fuzzrex.schema import load_spec

DEFAULT_DROP_STATUSES = frozenset({404, 501})


def prune_spec(
    orchestrator: DockerComposeOrchestrator,
    spec_path: str | Path,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    drop_statuses: frozenset[int] = DEFAULT_DROP_STATUSES,
) -> dict[str, Any]:
    """Return a copy of the spec keeping only operations this deployment serves.

    The SUT must be running the baseline cell. Every operation is
    probed once (links resolved); operations answering with a status in
    `drop_statuses` or with no response at all are removed, as is any
    operation whose token/param producer was removed (transitively).
    404/501 are treated as "not served" by default; specs where 404
    carries application semantics need a custom `drop_statuses`.
    """
    spec = load_spec(spec_path)
    fuzzer = ApiFuzzer(str(spec_path), base_url=orchestrator.base_url, timeout=timeout)
    sequence = fuzzer.plan()
    snapshots = execute_sequence(sequence, timeout=timeout)

    dropped: set[str] = {
        request.label
        for request, snapshot in zip(sequence, snapshots, strict=True)
        if snapshot.status_code is None or snapshot.status_code in drop_statuses
    }
    changed = True
    while changed:
        changed = False
        for request in sequence:
            producers = {request.token_from} if request.token_from else set()
            producers |= {label for label, _ in request.param_from.values()}
            if request.label not in dropped and producers & dropped:
                dropped.add(request.label)
                changed = True

    pruned = copy.deepcopy(spec)
    paths: dict[str, Any] = pruned["paths"]
    kept = 0
    for path in list(paths):
        path_item = paths[path]
        if not isinstance(path_item, dict):
            continue
        for method in list(path_item):
            if method.lower() in HTTP_METHODS and f"{method.upper()} {path}" in dropped:
                del path_item[method]
        methods = [m for m in path_item if m.lower() in HTTP_METHODS]
        if methods:
            kept += len(methods)
        else:
            del paths[path]
    if not kept:
        raise ValueError("no operations survived pruning under the baseline cell")
    return pruned


def filter_knobs(
    orchestrator: DockerComposeOrchestrator,
    baseline_config: Any,
    domains: Mapping[str, Sequence[Any]],
    sequence: Sequence[HttpRequest],
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, list[Any]]:
    """Return the candidate keys whose values change an HTTP response.

    For each (key, value) in `domains`, the baseline cell is cloned with
    that one leaf set to `value` and the sequence is replayed; a key is
    kept when any value yields a response snapshot different from the
    baseline's (raw exact comparison: status, location, sensitive keys,
    body, text sample). Values equal to the baseline value and values
    that fail to deploy are skipped without evidence. The SUT must be
    running the baseline cell when called; it is restored (restart +
    health) before returning.

    Keys are matched by leaf name anywhere in the config tree (nested
    documents included). Limitation: the comparison is exact, so a SUT
    whose responses embed non-determinism (timestamps, nonces) will
    make every key look observable.
    """
    base_snaps = execute_sequence(sequence, timeout=timeout)
    kept: dict[str, list[Any]] = {}
    try:
        for key, values in domains.items():
            evidence = False
            for value in values:
                variant = copy.deepcopy(baseline_config)
                leaves = [(c, k) for c, k in _collect_leaves(variant) if k == key]
                if not leaves:
                    raise ValueError(f"config key {key!r} not present in baseline config")
                container, leaf_key = leaves[0]
                if container[leaf_key] == value:
                    continue
                container[leaf_key] = value
                try:
                    with configured_service(orchestrator, variant, defer=True):
                        snaps = execute_sequence(sequence, timeout=timeout)
                except OrchestratorError:
                    continue
                if _snapshots_differ(base_snaps, snaps):
                    evidence = True
            if evidence:
                kept[key] = list(values)
    finally:
        orchestrator.restore()
    return kept


def _snapshots_differ(
    baseline: Sequence[ResponseSnapshot],
    variant: Sequence[ResponseSnapshot],
) -> bool:
    return any(base != var for base, var in zip(baseline, variant, strict=True))
