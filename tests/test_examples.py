"""Sanity checks for the bundled example fixtures (no Docker required)."""

import json
from pathlib import Path

import yaml

from fuzzrex.api_fuzzer import ApiFuzzer
from fuzzrex.schema import load_document, load_spec

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_all_example_specs_load():
    for spec_path in [
        EXAMPLES / "demo-api" / "openapi.json",
        EXAMPLES / "dvwa" / "openapi.yml",
        EXAMPLES / "grafana" / "openapi.yml",
        EXAMPLES / "crapi" / "openapi.yml",
    ]:
        spec = load_spec(spec_path)
        assert spec["paths"], f"{spec_path} has no paths"


def test_all_example_compose_files_parse():
    for compose_path in [
        EXAMPLES / "demo-api" / "docker-compose.yml",
        EXAMPLES / "dvwa" / "compose.yml",
        EXAMPLES / "grafana" / "compose.yml",
        EXAMPLES / "crapi" / "compose.yml",
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


def test_crapi_env_knobs_match_campaign_grid():
    env = load_document(EXAMPLES / "crapi" / ".env")
    assert env["ENABLE_SHELL_INJECTION"] is False
    assert env["TLS_ENABLED"] is False
    compose = yaml.safe_load((EXAMPLES / "crapi" / "compose.yml").read_text())
    environment = compose["services"]["crapi-identity"]["environment"]
    assert any("${ENABLE_SHELL_INJECTION" in entry for entry in environment)
    assert any("${TLS_ENABLED" in entry for entry in environment)


def test_crapi_spec_chains_resolve_and_examples_are_probe_verified():
    sequence = ApiFuzzer(str(EXAMPLES / "crapi" / "openapi.yml")).plan()
    labels = {request.label for request in sequence}
    for request in sequence:
        if request.token_from:
            assert request.token_from in labels, request.token_from
        for producer, _ in request.param_from.values():
            assert producer in labels, producer

    by_label = {request.label: request for request in sequence}
    login = by_label["POST /identity/api/auth/login"]
    assert login.body == {"email": "admin@example.com", "password": "Admin!123"}
    upload = by_label["POST /identity/api/v2/user/videos"]
    assert upload.files is not None and "file" in upload.files
    put = by_label["PUT /identity/api/v2/user/videos/{video_id}"]
    assert put.body["conversion_params"] == "$(id)"
    convert = by_label["GET /identity/api/v2/user/videos/convert_video"]
    assert convert.param_from == {
        "video_id": ("POST /identity/api/v2/user/videos", "id")
    }


def test_crapi_jwks_key_material_loads():
    jwks = json.loads((EXAMPLES / "crapi" / "keys" / "jwks.json").read_text())
    assert jwks["keys"], "jwks.json has no keys"
