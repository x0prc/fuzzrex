"""Request-side mutation for the joint search.

Mutates scalar request values (query params, cookies, JSON body leaves)
of the planned sequence, keeping methods, URLs, links, headers, and file
payloads intact so every replay means the same thing structurally. One
slot is mutated per call; the returned patch record identifies the
variant canonically for baseline caching and pair identity.
"""

from __future__ import annotations

import copy
import random
from collections.abc import Iterator, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing only: oracle imports this module at runtime
    from fuzzrex.oracle import HttpRequest

BOUNDARY_INTS = (0, 1, -1, 2**31 - 1, 2**31, 2**63 - 1, -(2**31))
BOUNDARY_FLOATS = (0.0, -1.0, 1.0, 1e308, -1e308)
SPECIAL_STRINGS = (
    "",
    ";id",
    "$(id)",
    "|id",
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../",
    "%00",
    "${7*7}",
    "A" * 256,
)


def mutate_request(
    sequence: Sequence[HttpRequest],
    rng: random.Random,
) -> tuple[list[HttpRequest], dict[str, Any]]:
    """Return the sequence with one scalar slot mutated plus its patch record.

    The slot is chosen uniformly over every query-param, cookie, and
    JSON body leaf in the sequence; its value is resampled from typed
    pools (booleans flip, ints/floats take boundary values, strings take
    a special-string pool, None becomes a string). Requests without
    mutable slots (multipart-only, header-only) stay in the returned
    sequence unchanged. The patch records the label, field, path, and
    new value -- JSON-ready, so equal patches denote the same variant.
    """
    slots = [
        (index, field, path)
        for index, request in enumerate(sequence)
        for field, path in _slots_of(request)
    ]
    if not slots:
        return list(sequence), {}
    index, field, path = rng.choice(slots)
    target = sequence[index]
    value = _resample(_get_slot(target, field, path), rng)
    mutated = replace(target, **{field: _with_slot(getattr(target, field), path, value)})
    patch = {
        "label": target.label,
        "field": field,
        "path": list(path),
        "value": value,
    }
    result = list(sequence)
    result[index] = mutated
    return result, patch


def _slots_of(request: HttpRequest) -> Iterator[tuple[str, tuple[Any, ...]]]:
    """Yield (field, path) for every mutable scalar slot; headers excluded (auth)."""
    for field in ("params", "cookies"):
        for key in sorted(getattr(request, field), key=str):
            yield field, (key,)
    if isinstance(request.body, (dict, list)):
        for path, _ in _walk_scalars(request.body):
            yield "body", path


def _walk_scalars(node: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[tuple[Any, ...], Any]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk_scalars(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk_scalars(value, (*path, index))
    else:
        yield path, node


def _get_slot(request: HttpRequest, field: str, path: tuple[Any, ...]) -> Any:
    node = getattr(request, field)
    for step in path[:-1]:
        node = node[step]
    return node[path[-1]]


def _with_slot(container: Any, path: tuple[Any, ...], value: Any) -> Any:
    copy_ = copy.deepcopy(container)
    node = copy_
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    return copy_


def _resample(value: Any, rng: random.Random) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return rng.choice([v for v in BOUNDARY_INTS if v != value])
    if isinstance(value, float):
        return rng.choice([v for v in BOUNDARY_FLOATS if v != value])
    if isinstance(value, str):
        return rng.choice([s for s in SPECIAL_STRINGS if s != value])
    return rng.choice(SPECIAL_STRINGS)  # None or any other scalar
