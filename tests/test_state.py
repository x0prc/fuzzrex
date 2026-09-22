from unittest.mock import MagicMock

from fuzzrex.state import StateManager


def _response(payload, as_json=True):
    response = MagicMock()
    if as_json:
        response.json.return_value = payload
    else:
        response.json.side_effect = ValueError("not json")
    return response


def test_collects_flat_scalars():
    state = StateManager()
    state.update(_response({"userId": 42, "sessionToken": "abc"}))
    assert state.resolve("userId") == 42
    assert state.resolve("sessionToken") == "abc"
    assert state.last_response == {"userId": 42, "sessionToken": "abc"}


def test_collects_nested_and_list_values():
    state = StateManager()
    state.update(
        _response(
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
    state.update(_response(None, as_json=False))
    assert state.known_values == {}
    assert state.last_response is None


def test_null_values_not_stored():
    state = StateManager()
    state.update(_response({"token": None, "ok": "yes"}))
    assert state.resolve("token") is None
    assert state.resolve("ok") == "yes"
