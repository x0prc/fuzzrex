from unittest.mock import MagicMock, patch

import pytest

from fuzzrex.auth import AuthHandler


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


@patch("fuzzrex.auth.requests.post")
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


@patch("fuzzrex.auth.requests.post")
def test_oauth2_failure_raises(mock_post):
    mock_response = MagicMock(status_code=401)
    mock_post.return_value = mock_response
    handler = AuthHandler(
        auth_type="oauth2",
        oauth2={"client_id": "id", "client_secret": "s", "token_url": "https://x/t"},
    )
    with pytest.raises(RuntimeError):
        handler.headers()
