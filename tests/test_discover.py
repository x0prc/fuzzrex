import json
from unittest.mock import MagicMock, patch

import pytest

from fuzzrex.discover import filter_knobs, prune_spec
from fuzzrex.oracle import HttpRequest, ResponseSnapshot


def _snap(status=None, body=None, text="", sensitive=frozenset(), location=""):
    return ResponseSnapshot(status, body, text, sensitive, location)


def _orchestrator_mock():
    orch = MagicMock()
    orch.base_url = "http://sut.test"
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=orch)
    cm.__exit__ = MagicMock(return_value=False)
    return orch, cm


def _write_spec(tmp_path, paths):
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps({"openapi": "3.0.0", "paths": paths}))
    return spec


@pytest.fixture(autouse=True)
def _canary(monkeypatch):
    """Keep prune_spec's canary probe off the network unless a test overrides it."""
    response = MagicMock(status_code=404)
    send = MagicMock(return_value=response)
    monkeypatch.setattr("fuzzrex.discover.send_request", send)
    return response


def _ok_path():
    return {"get": {"responses": {"200": {"description": "ok"}}}}


# --- prune_spec ---


@patch("fuzzrex.discover.execute_sequence")
def test_prune_spec_drops_unserved_and_chained_operations(mock_execute, tmp_path):
    paths = {
        "/a": _ok_path(),
        "/b": _ok_path(),
        "/c": {
            "post": {
                "responses": {"200": {"description": "ok"}},
                "x-fuzzrex-token-from": "GET /b",
            },
        },
        "/d": _ok_path(),
    }
    spec = _write_spec(tmp_path, paths)
    mock_execute.return_value = [_snap(200), _snap(404), _snap(200), _snap(200)]

    orch, _ = _orchestrator_mock()
    pruned = prune_spec(orch, spec)

    # /b is not served (404) and /c chained to it; /a and /d survive
    assert sorted(pruned["paths"]) == ["/a", "/d"]
    assert list(pruned["paths"]["/a"]) == ["get"]


@patch("fuzzrex.discover.execute_sequence")
def test_prune_spec_transport_failures_drop_and_custom_statuses_keep(
    mock_execute, tmp_path,
):
    paths = {"/ok": _ok_path(), "/gone": _ok_path(), "/down": _ok_path(), "/err": _ok_path()}
    spec = _write_spec(tmp_path, paths)
    # /gone: 404 (default drop), /down: 503 (kept unless dropped), /err: no response
    mock_execute.return_value = [_snap(200), _snap(404), _snap(503), _snap(None)]

    orch, _ = _orchestrator_mock()
    pruned = prune_spec(orch, spec, drop_statuses=frozenset({404}))

    assert sorted(pruned["paths"]) == ["/down", "/ok"]


@patch("fuzzrex.discover.execute_sequence")
def test_prune_spec_raises_when_nothing_survives(mock_execute, tmp_path):
    spec = _write_spec(tmp_path, {"/gone": _ok_path()})
    mock_execute.return_value = [_snap(404)]

    orch, _ = _orchestrator_mock()
    with pytest.raises(ValueError, match="no operations survived"):
        prune_spec(orch, spec)


@patch("fuzzrex.discover.execute_sequence")
def test_prune_spec_warns_when_reachability_is_blind(mock_execute, tmp_path, _canary):
    _canary.status_code = 401  # auth middleware answers before routing
    spec = _write_spec(tmp_path, {"/a": _ok_path()})
    mock_execute.return_value = [_snap(200)]

    orch, _ = _orchestrator_mock()
    with pytest.warns(UserWarning, match="canary probe"):
        prune_spec(orch, spec)


# --- filter_knobs ---


def _request() -> HttpRequest:
    return HttpRequest(method="GET", url="http://sut.test/x", label="GET /x")


@patch("fuzzrex.discover.execute_sequence")
@patch("fuzzrex.discover.configured_service")
def test_filter_knobs_keeps_observable_keys_only(mock_cm, mock_execute):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    base = _snap(200, body={"ok": True})
    dirty = _snap(200, body={"ok": False})
    # baseline, debug=True (differs), log="b" (identical)
    mock_execute.side_effect = [[base], [dirty], [base]]

    kept = filter_knobs(
        orch,
        {"debug": False, "log": "a"},
        {"debug": [False, True], "log": ["a", "b"]},
        [_request()],
    )

    assert kept == {"debug": [False, True]}
    assert mock_execute.call_count == 3
    assert mock_cm.call_args.kwargs["defer"] is True
    assert orch.restore.call_count == 1


@patch("fuzzrex.discover.execute_sequence")
@patch("fuzzrex.discover.configured_service")
def test_filter_knobs_matches_nested_keys(mock_cm, mock_execute):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    mock_execute.side_effect = [[_snap(200)], [_snap(200, location="/login")]]

    kept = filter_knobs(
        orch,
        {"auth.anonymous": {"enabled": False}},
        {"enabled": [False, True]},
        [_request()],
    )

    assert kept == {"enabled": [False, True]}


@patch("fuzzrex.discover.execute_sequence")
@patch("fuzzrex.discover.configured_service")
def test_filter_knobs_skips_undeployable_values(mock_cm, mock_execute):
    from fuzzrex.orchestrator import OrchestratorError

    orch, cm = _orchestrator_mock()
    mock_execute.return_value = [_snap(200)]

    enters = {"count": 0}

    def enter(_self=None):
        enters["count"] += 1
        if enters["count"] == 1:
            raise OrchestratorError("unhealthy")
        return orch

    mock_cm.return_value.__enter__ = MagicMock(side_effect=enter)

    kept = filter_knobs(
        orch,
        {"flag": False},
        {"flag": [False, True]},
        [_request()],
    )

    # flag=False equals the baseline (skipped), flag=True fails to deploy
    assert kept == {}
    assert orch.restore.call_count == 1


@patch("fuzzrex.discover.execute_sequence")
def test_filter_knobs_unknown_key_raises(mock_execute):
    mock_execute.return_value = [_snap(200)]

    orch, _ = _orchestrator_mock()
    with pytest.raises(ValueError, match="not present in baseline"):
        filter_knobs(orch, {"flag": False}, {"nope": [1]}, [_request()])
