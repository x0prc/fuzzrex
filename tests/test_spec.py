import json

import pytest
import yaml

from fuzzrex.spec import dump_document, load_document, load_spec


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
