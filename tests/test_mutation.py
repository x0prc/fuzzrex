import json
import random

from fuzzrex.mutation import (
    BOUNDARY_INTS,
    SPECIAL_STRINGS,
    _get_slot,
    _resample,
    mutate_request,
)
from fuzzrex.oracle import HttpRequest


def _req(label="GET /x", params=None, body=None, cookies=None, files=None):
    return HttpRequest(
        method="GET",
        url="http://sut.test/x",
        params=params or {},
        body=body,
        cookies=cookies or {},
        path="/x",
        label=label,
        files=files,
    )


def _structure(request):
    return (
        request.method,
        request.url,
        request.label,
        request.token_from,
        request.param_from,
        request.files,
    )


def test_mutates_exactly_one_slot_and_keeps_structure():
    sequence = [
        _req(
            "GET /a",
            params={"q": 1, "page": 2},
            body={"user": {"name": "bob", "age": 30}},
        ),
        _req("GET /b", params={"z": "hi"}, cookies={"sid": "abc"}),
    ]

    for seed in range(30):
        rng = random.Random(seed)
        result, patch = mutate_request(sequence, rng)

        changed = [i for i, (a, b) in enumerate(zip(sequence, result, strict=True)) if a != b]
        assert len(changed) == 1
        index = changed[0]
        assert result[index].label == patch["label"]
        value = _get_slot(result[index], patch["field"], tuple(patch["path"]))
        assert value == patch["value"]
        assert value != _get_slot(sequence[index], patch["field"], tuple(patch["path"]))
        for before, after in zip(sequence, result, strict=True):
            assert _structure(before) == _structure(after)
        # patch is JSON-ready and canonical
        assert json.dumps(patch, sort_keys=True)


def test_sequence_without_mutable_slots_returns_unchanged():
    sequence = [
        HttpRequest(
            method="POST",
            url="http://sut.test/upload",
            path="/upload",
            label="POST /upload",
            files={"file": ("clip.mp4", b"\x00", "video/mp4")},
        )
    ]

    result, patch = mutate_request(sequence, random.Random(0))

    assert patch == {}
    assert result == list(sequence)


def test_resample_bool_flips():
    for seed in range(10):
        assert _resample(True, random.Random(seed)) is False
        assert _resample(False, random.Random(seed)) is True


def test_resample_int_and_string_stay_in_pools():
    rng = random.Random(7)
    for _ in range(30):
        assert _resample(5, rng) in BOUNDARY_INTS
        assert _resample("hello", rng) in SPECIAL_STRINGS
        assert _resample(None, rng) in SPECIAL_STRINGS


def test_resample_never_returns_the_same_scalar():
    rng = random.Random(3)
    for value in (0, -1, 2**63 - 1, 0.0, "", ";id"):
        for _ in range(10):
            assert _resample(value, rng) != value
