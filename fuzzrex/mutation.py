"""Request-side mutation for the joint search.

Mutates one slot of the planned sequence per call -- a scalar request
value (query param, cookie, JSON body leaf) or a multipart file aspect
(content bytes, filename, content type) -- keeping methods, URLs,
links, and headers intact so every replay means the same thing
structurally. The returned patch record identifies the variant
canonically for baseline caching and pair identity; file patches
describe content by pool name, never raw bytes, so they stay JSON-ready.
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
FILE_CONTENTS: tuple[tuple[str, bytes], ...] = (
    ("empty", b""),
    ("php-tag", b"<?php system($_GET['c']); ?>"),
    ("script-tag", b"<script>alert(1)</script>"),
    ("null-block", b"\x00" * 512),
    ("binary-junk", bytes(range(256)) * 4),
    ("oversize", b"A" * (1 << 20)),
)
FILE_NAMES = (
    "shell.php",
    "../evil.mp4",
    "x.mp4.php",
    "A" * 256 + ".mp4",
    "payload",
    "x%00.mp4",
    ".hidden",
)
FILE_CONTENT_TYPES = (
    "text/plain",
    "text/html",
    "application/x-sh",
    "image/png",
    "application/json",
)
_FILE_ASPECT_ORDER = ("filename", "content", "content_type")


def mutate_request(
    sequence: Sequence[HttpRequest],
    rng: random.Random,
    *,
    skip_labels: frozenset[str] = frozenset(),
) -> tuple[list[HttpRequest], dict[str, Any]]:
    """Return the sequence with one slot mutated plus its patch record.

    The slot is chosen uniformly over every query-param, cookie, JSON
    body leaf, and multipart file aspect (filename, content, content
    type) in the sequence. Scalars are resampled from typed pools
    (booleans flip, ints/floats take boundary values, strings take a
    special-string pool, None becomes a string); files take their own
    pools of adversarial payloads, names, and mismatched types.
    Requests without mutable slots (header-only) and requests whose
    label is in `skip_labels` are never chosen. The patch records the
    label, field, path, and new value -- JSON-ready (file content is
    described by pool name, never embedded), so equal patches denote
    the same variant.
    """
    slots: list[tuple[str, Any, ...]] = [
        ("scalar", index, field, path)
        for index, request in enumerate(sequence)
        if request.label not in skip_labels
        for field, path in _slots_of(request)
    ]
    slots += [
        ("file", index, file_field, aspect)
        for index, request in enumerate(sequence)
        if request.label not in skip_labels
        for file_field, aspect in _file_slots_of(request)
    ]
    if not slots:
        return list(sequence), {}
    pick = rng.choice(slots)
    if pick[0] == "scalar":
        _, index, field, path = pick
        target = sequence[index]
        value = _resample(_get_slot(target, field, path), rng)
        mutated = replace(target, **{field: _with_slot(getattr(target, field), path, value)})
        patch = {
            "label": target.label,
            "field": field,
            "path": list(path),
            "value": value,
        }
    else:
        _, index, file_field, aspect = pick
        target = sequence[index]
        new_value, described = _resample_file(aspect, target.files[file_field], rng)
        entry = list(target.files[file_field])
        entry[_FILE_ASPECT_ORDER.index(aspect)] = new_value
        files = dict(target.files)
        files[file_field] = tuple(entry)
        mutated = replace(target, files=files)
        patch = {
            "label": target.label,
            "field": "files",
            "path": [file_field],
            "aspect": aspect,
            "value": described,
        }
    result = list(sequence)
    result[index] = mutated
    return result, patch


def vary_plan(
    sequence: Sequence[HttpRequest],
    rng: random.Random,
    mutations: int,
) -> list[HttpRequest]:
    """Return the planned sequence with `mutations` accumulated slot mutations.

    Per-seed plan variety: seeds no longer share one global plan.
    Producer requests (those other requests draw tokens or params from)
    are excluded so chained links keep resolving; everything else is
    eligible. `mutations <= 0` returns the sequence unchanged, and a
    sequence without eligible slots is never altered. Deterministic in
    `rng`, so re-running a seed reproduces its plan.
    """
    if mutations <= 0:
        return list(sequence)
    producers = {request.token_from for request in sequence if request.token_from}
    producers |= {label for request in sequence for label, _ in request.param_from.values()}
    varied = list(sequence)
    for _ in range(mutations):
        varied, _ = mutate_request(varied, rng, skip_labels=frozenset(producers))
    return varied


def _slots_of(request: HttpRequest) -> Iterator[tuple[str, tuple[Any, ...]]]:
    """Yield (field, path) for every mutable scalar slot; headers excluded (auth)."""
    for field in ("params", "cookies"):
        for key in sorted(getattr(request, field), key=str):
            yield field, (key,)
    if isinstance(request.body, (dict, list)):
        for path, _ in _walk_scalars(request.body):
            yield "body", path


def _file_slots_of(request: HttpRequest) -> Iterator[tuple[str, str]]:
    """Yield (file field, aspect) for every mutable multipart aspect."""
    for file_field in sorted(request.files or {}, key=str):
        for aspect in _FILE_ASPECT_ORDER:
            yield file_field, aspect


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


def _resample_file(
    aspect: str, entry: tuple[str, bytes, str], rng: random.Random
) -> tuple[Any, str]:
    """Resample one file aspect from its pool, never equal to the current.

    Returns (new value, JSON-safe description): raw content bytes are
    described by their pool name so the patch stays serializable.
    """
    filename, content, content_type = entry
    if aspect == "content":
        pool: list[tuple[str, Any]] = [
            (name, data) for name, data in FILE_CONTENTS if data != content
        ] or list(FILE_CONTENTS)
        name, data = rng.choice(pool)
        return data, name
    if aspect == "filename":
        pool = [name for name in FILE_NAMES if name != filename] or list(FILE_NAMES)
    else:
        pool = [t for t in FILE_CONTENT_TYPES if t != content_type] or list(FILE_CONTENT_TYPES)
    chosen = rng.choice(pool)
    return chosen, chosen
