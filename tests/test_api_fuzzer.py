import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fuzzrex.api_fuzzer import ApiFuzzer, Finding
from fuzzrex.auth import AuthHandler

SPEC = {
    "openapi": "3.0.0",
    "servers": [{"url": "http://api.test"}],
    "paths": {
        "/users/{userId}": {
            "parameters": [
                {"name": "userId", "in": "path", "schema": {"type": "integer"}},
            ],
            "get": {
                "parameters": [
                    {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
                    {"name": "X-Trace", "in": "header", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "ok"}},
            },
        },
        "/users": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"name": {"type": "string"}},
                            },
                        },
                    },
                },
                "responses": {"201": {"description": "created"}},
            },
        },
        "/health": {
            "get": {"responses": {"200": {"description": "ok"}}},
        },
    },
}


@pytest.fixture
def spec_path(tmp_path: Path) -> Path:
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(SPEC))
    return path


def test_iter_operations(spec_path: Path):
    fuzzer = ApiFuzzer(str(spec_path))
    ops = {(m, p) for m, p, _ in fuzzer.iter_operations()}
    assert ops == {
        ("GET", "/users/{userId}"),
        ("POST", "/users"),
        ("GET", "/health"),
    }


def test_default_base_url_from_servers(spec_path: Path):
    fuzzer = ApiFuzzer(str(spec_path))
    assert fuzzer.base_url == "http://api.test"


def test_base_url_override(spec_path: Path):
    fuzzer = ApiFuzzer(str(spec_path), base_url="http://other.test/")
    assert fuzzer.base_url == "http://other.test"


def test_path_query_header_routing(spec_path: Path):
    fuzzer = ApiFuzzer(str(spec_path))
    details = next(
        d for m, p, d in fuzzer.iter_operations() if m == "GET" and p == "/users/{userId}"
    )
    request = fuzzer._build_request("GET", "/users/{userId}", details)
    assert request["url"].startswith("http://api.test/users/")
    assert "{userId}" not in request["url"]
    assert "verbose" in request["params"]
    assert "X-Trace" in request["headers"]
    assert request["json"] is None


def test_request_body_is_fuzzed(spec_path: Path):
    fuzzer = ApiFuzzer(str(spec_path))
    details = next(d for m, _, d in fuzzer.iter_operations() if m == "POST")
    request = fuzzer._build_request("POST", "/users", details)
    assert isinstance(request["json"], dict)
    assert "name" in request["json"]


def test_auth_headers_included(spec_path: Path):
    auth = AuthHandler(auth_type="token", token="abc")
    fuzzer = ApiFuzzer(str(spec_path), auth=auth)
    request = fuzzer._build_request("GET", "/health", {"_shared_parameters": []})
    assert request["headers"] == {"Authorization": "Bearer abc"}


def test_state_values_preferred_for_params(spec_path: Path):
    fuzzer = ApiFuzzer(str(spec_path))
    fuzzer.state.known_values["userId"] = 99
    details = next(
        d for m, p, d in fuzzer.iter_operations() if p == "/users/{userId}"
    )
    request = fuzzer._build_request("GET", "/users/{userId}", details)
    assert request["url"].endswith("/users/99")


@patch("fuzzrex.api_fuzzer.requests.request")
def test_run_reports_server_errors(mock_request, spec_path: Path):
    ok = MagicMock(status_code=200)
    ok.json.return_value = {"ok": True}
    error = MagicMock(status_code=500)
    error.json.side_effect = ValueError("no json")
    mock_request.side_effect = [ok, error, ok]

    fuzzer = ApiFuzzer(str(spec_path))
    findings = fuzzer.run()

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.status_code == 500
    assert finding.detail == "server error"


@patch("fuzzrex.api_fuzzer.requests.request")
def test_run_captures_request_errors(mock_request, spec_path: Path):
    import requests as requests_lib

    mock_request.side_effect = requests_lib.ConnectionError("down")
    fuzzer = ApiFuzzer(str(spec_path))
    findings = fuzzer.run()
    assert len(findings) == len(list(fuzzer.iter_operations()))
    assert all(f.status_code is None for f in findings)
