import json
from pathlib import Path

import pytest
import yaml

from fuzzrex.config_fuzzer import ConfigFuzzer, mutate_config


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "app.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "debug": False,
                "port": 8080,
                "secret": "hunter2",
                "features": {"beta": True, "name": "core"},
                "hosts": ["a.example", "b.example"],
            },
        ),
    )
    return path


def test_requires_structured_document(tmp_path: Path):
    path = tmp_path / "flat.json"
    path.write_text('"just a string"')
    with pytest.raises(ValueError, match="mapping or sequence"):
        ConfigFuzzer(path)


def test_variants_differ_from_original(config_file: Path):
    fuzzer = ConfigFuzzer(config_file)
    variants = fuzzer.generate_variants(count=25, seed=42)
    assert len(variants) == 25
    assert any(v != fuzzer.original for v in variants)
    # Original must not be mutated in place.
    assert fuzzer.original["debug"] is False
    assert fuzzer.original["secret"] == "hunter2"


def test_seed_is_deterministic(config_file: Path):
    fuzzer = ConfigFuzzer(config_file)
    first = fuzzer.generate_variants(count=10, seed=7)
    second = fuzzer.generate_variants(count=10, seed=7)
    assert first == second


def test_run_writes_files(config_file: Path, tmp_path: Path):
    fuzzer = ConfigFuzzer(config_file)
    out_dir = tmp_path / "out"
    written = fuzzer.run(out_dir, count=5, seed=1)
    assert len(written) == 5
    for path in written:
        assert path.exists()
        assert path.suffix == ".yaml"
        loaded = yaml.safe_load(path.read_text())
        assert isinstance(loaded, dict)


def test_json_config_roundtrip(tmp_path: Path):
    path = tmp_path / "conf.json"
    path.write_text(json.dumps({"mode": "prod", "retries": 3}))
    fuzzer = ConfigFuzzer(path)
    written = fuzzer.run(tmp_path / "out", count=3, seed=0)
    assert len(written) == 3
    for item in written:
        assert isinstance(json.loads(item.read_text()), dict)


def test_invalid_count(config_file: Path):
    with pytest.raises(ValueError):
        ConfigFuzzer(config_file).generate_variants(count=0)


def test_mutate_config_returns_copy_not_in_place():
    original = {"debug": False, "port": 80}
    mutated = mutate_config(original)
    assert mutated is not original
    assert original == {"debug": False, "port": 80}


def test_mutate_config_deterministic_with_seed():
    import random

    original = {"debug": False, "port": 80, "name": "x"}
    seed_rng = lambda: random.Random(7)  # noqa: E731
    assert mutate_config(original, seed_rng()) == mutate_config(original, seed_rng())


def test_config_fuzzer_still_uses_mutate_config(tmp_path: Path):
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"debug": False, "port": 80}))
    variants = ConfigFuzzer(path).generate_variants(count=10, seed=3)
    assert any(v != {"debug": False, "port": 80} for v in variants)
