import random

import pytest

from fuzzrex.mutations import (
    fuzz_array,
    fuzz_boolean,
    fuzz_integer,
    fuzz_number,
    fuzz_object,
    fuzz_string,
    fuzz_value,
)


def test_fuzz_string_length_bounds():
    value = fuzz_string(5, 10, rng=random.Random(0))
    assert 5 <= len(value) <= 10


def test_fuzz_integer_probes_outside_range():
    rng = random.Random(0)
    values = {fuzz_integer(0, 10, rng=rng) for _ in range(50)}
    assert any(v < 0 or v > 10 for v in values)


def test_fuzz_number_within_expanded_range():
    value = fuzz_number(0.0, 1.0, rng=random.Random(1))
    assert -11.0 <= value <= 11.0


def test_fuzz_boolean_returns_bool():
    assert isinstance(fuzz_boolean(rng=random.Random(0)), bool)


def test_fuzz_array_item_count():
    rng = random.Random(0)
    values = fuzz_array({"type": "integer"}, 1, 5, rng=rng)
    assert 1 <= len(values) <= 5
    assert all(isinstance(v, int) for v in values)


def test_fuzz_object_recursive():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer"},
        },
    }
    result = fuzz_object(schema, rng=random.Random(0))
    assert set(result) == {"name", "count"}
    assert isinstance(result["name"], str)
    assert isinstance(result["count"], int)


def test_fuzz_value_enum():
    schema = {"type": "string", "enum": ["a", "b"]}
    assert fuzz_value(schema, rng=random.Random(0)) in {"a", "b"}


def test_fuzz_value_type_union_prefers_non_null():
    schema = {"type": ["integer", "null"]}
    assert isinstance(fuzz_value(schema, rng=random.Random(0)), int)


def test_fuzz_value_defaults_to_string():
    assert isinstance(fuzz_value(None, rng=random.Random(0)), str)


@pytest.mark.parametrize("schema", [{}, {"type": "unknown"}])
def test_fuzz_value_unknown_type_is_string(schema):
    assert isinstance(fuzz_value(schema, rng=random.Random(0)), str)
