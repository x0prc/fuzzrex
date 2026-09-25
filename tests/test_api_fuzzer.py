import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fuzzrex.api_fuzzer import ApiFuzzer, AuthHandler, Finding, StateManager

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


# --- AuthHandler ---


def test_no_auth_returns_empty_headers():
    assert AuthHandler().headers() == {}


def test_token_auth_header():
    handler = AuthHandler(auth_type="token", token="sekret")
    assert handler.headers() == {"Authorization": "Bearer sekret"}


def test_token_auth_requires_token():
    with pytest.raises(ValueError):
        AuthHandler(auth_type="token")


def test_oauth2_requires_config():
    with pytest.raises(ValueError):
        AuthHandler(auth_type="oauth2")
    with pytest.raises(ValueError):
        AuthHandler(auth_type="oauth2", oauth2={"client_id": "x"})


def test_unsupported_auth_type():
    with pytest.raises(ValueError):
        AuthHandler(auth_type="basic")


@patch("fuzzrex.api_fuzzer.requests.post")
def test_oauth2_retrieves_and_caches_token(mock_post):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"access_token": "tok-1"}
    mock_post.return_value = mock_response

    handler = AuthHandler(
        auth_type="oauth2",
        oauth2={
            "client_id": "id",
            "client_secret": "secret",
            "token_url": "https://auth.example/token",
            "scope": "read",
        },
    )
    assert handler.headers() == {"Authorization": "Bearer tok-1"}
    assert handler.headers() == {"Authorization": "Bearer tok-1"}
    assert mock_post.call_count == 1

    handler.invalidate()
    handler.headers()
    assert mock_post.call_count == 2


@patch("fuzzrex.api_fuzzer.requests.post")
def test_oauth2_failure_raises(mock_post):
    mock_response = MagicMock(status_code=401)
    mock_post.return_value = mock_response
    handler = AuthHandler(
        auth_type="oauth2",
        oauth2={"client_id": "id", "client_secret": "s", "token_url": "https://x/t"},
    )
    with pytest.raises(RuntimeError):
        handler.headers()


# --- StateManager ---


def _state_response(payload, as_json=True):
    response = MagicMock()
    if as_json:
        response.json.return_value = payload
    else:
        response.json.side_effect = ValueError("not json")
    return response


def test_collects_flat_scalars():
    state = StateManager()
    state.update(_state_response({"userId": 42, "sessionToken": "abc"}))
    assert state.resolve("userId") == 42
    assert state.resolve("sessionToken") == "abc"
    assert state.last_response == {"userId": 42, "sessionToken": "abc"}


def test_collects_nested_and_list_values():
    state = StateManager()
    state.update(
        _state_response(
            {
                "user": {"id": 7, "profile": {"name": "ada"}},
                "items": [{"sku": "x1"}],
            },
        ),
    )
    assert state.resolve("id") == 7
    assert state.resolve("name") == "ada"
    assert state.resolve("sku") == "x1"


def test_non_json_response_is_ignored():
    state = StateManager()
    state.update(_state_response(None, as_json=False))
    assert state.known_values == {}
    assert state.last_response is None


def test_null_values_not_stored():
    state = StateManager()
    state.update(_state_response({"token": None, "ok": "yes"}))
    assert state.resolve("token") is None
    assert state.resolve("ok") == "yes"
