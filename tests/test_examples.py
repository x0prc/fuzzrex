"""Sanity checks for the bundled example fixtures (no Docker required)."""

from pathlib import Path

import yaml

from fuzzrex.schema import load_document, load_spec

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_all_example_specs_load():
    for spec_path in [
        EXAMPLES / "demo-api" / "openapi.json",
        EXAMPLES / "dvwa" / "openapi.yml",
        EXAMPLES / "grafana" / "openapi.yml",
    ]:
        spec = load_spec(spec_path)
        assert spec["paths"], f"{spec_path} has no paths"


def test_all_example_compose_files_parse():
    for compose_path in [
        EXAMPLES / "demo-api" / "docker-compose.yml",
        EXAMPLES / "dvwa" / "compose.yml",
        EXAMPLES / "grafana" / "compose.yml",
    ]:
        compose = yaml.safe_load(compose_path.read_text())
        assert compose.get("services"), f"{compose_path} has no services"


def test_dvwa_matrix_is_config_mapping():
    matrix = load_document(EXAMPLES / "dvwa" / "matrix.json")
    assert matrix["disable_authentication"] is False
    assert matrix["default_security_level"] in {"low", "medium", "high", "impossible"}


def test_grafana_ini_loads_with_coerced_boolean():
    config = load_document(EXAMPLES / "grafana" / "grafana.ini")
    assert config == {"auth.anonymous": {"enabled": False}}


def test_dvwa_shim_overlays_matrix_json():
    shim = (EXAMPLES / "dvwa" / "config.inc.php").read_text()
    assert "matrix.json" in shim
    assert "array_merge" in shim
