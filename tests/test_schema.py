import json
import random

import pytest
import yaml

from fuzzrex.schema import (
    dump_document,
    fuzz_array,
    fuzz_boolean,
    fuzz_integer,
    fuzz_number,
    fuzz_object,
    fuzz_string,
    fuzz_value,
    load_document,
    load_spec,
)

# --- Document I/O ---


def test_load_json(tmp_path):
    path = tmp_path / "doc.json"
    path.write_text(json.dumps({"a": 1}))
    assert load_document(path) == {"a": 1}


def test_load_yaml(tmp_path):
    path = tmp_path / "doc.yaml"
    path.write_text(yaml.safe_dump({"a": 1}))
    assert load_document(path) == {"a": 1}


def test_load_missing_file():
    with pytest.raises(FileNotFoundError):
        load_document("/nonexistent/file.json")


def test_load_spec_requires_paths(tmp_path):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({"openapi": "3.0.0"}))
    with pytest.raises(ValueError, match="paths"):
        load_spec(path)


def test_load_spec_non_mapping(tmp_path):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps([1, 2, 3]))
    with pytest.raises(ValueError, match="mapping"):
        load_spec(path)


def test_dump_roundtrip_yaml(tmp_path):
    path = tmp_path / "out.yaml"
    dump_document({"key": "value", "n": 3}, path)
    assert load_document(path) == {"key": "value", "n": 3}


def test_dump_roundtrip_json(tmp_path):
    path = tmp_path / "out.json"
    dump_document({"key": [1, 2]}, path)
    assert load_document(path) == {"key": [1, 2]}


# --- Value generation ---


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
