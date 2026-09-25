import json
from unittest.mock import MagicMock, patch

import pytest
import requests as requests_lib

from fuzzrex.oracle import (
    RESTART_EVERY,
    CellResult,
    Divergence,
    HttpRequest,
    ResponseSnapshot,
    compare_sequences,
    differential_probe,
    execute_sequence,
    is_sensitive_key,
    run_joint_search,
    send_request,
    snapshot_response,
)


def _request(label: str = "GET /x") -> HttpRequest:
    return HttpRequest(method="GET", url="http://sut.test/x", path="/x", label=label)


def _snap(
    status: int | None = 200,
    body=None,
    keys: frozenset[str] = frozenset(),
    text: str = "",
) -> ResponseSnapshot:
    return ResponseSnapshot(status, body, text, keys)


def _response(status: int, payload=None, text: str | None = None) -> MagicMock:
    response = MagicMock(status_code=status)
    if payload is None:
        response.json.side_effect = ValueError("no json")
        response.text = text or ""
    else:
        response.json.return_value = payload
        response.text = text or json.dumps(payload)
    return response


def test_is_sensitive_key():
    assert is_sensitive_key("stackTrace")
    assert is_sensitive_key("client_secret")
    assert not is_sensitive_key("greeting")


def test_snapshot_collects_nested_sensitive_keys():
    response = _response(200, {"ok": True, "debug": {"stack": "x", "cwd": "/app"}})
    snap = snapshot_response(response)
    assert "debug" in snap.sensitive_keys
    assert "stack" in snap.sensitive_keys
    assert "cwd" in snap.sensitive_keys
    assert "ok" not in snap.sensitive_keys


def test_snapshot_detects_traceback_in_text():
    response = MagicMock(status_code=500)
    response.json.side_effect = ValueError("html")
    response.text = "Traceback (most recent call last): boom"
    snap = snapshot_response(response)
    assert "traceback" in snap.sensitive_keys


def test_identical_responses_yield_no_divergence():
    planned = [_request()]
    base = [_snap(200, {"a": 1}, frozenset({"a"}))]
    var = [_snap(200, {"a": 2}, frozenset({"a"}))]
    assert compare_sequences(planned, base, var) == []


def test_auth_boundary_bypass():
    planned = [_request("GET /admin")]
    divergences = compare_sequences(planned, [_snap(401)], [_snap(200)])
    assert len(divergences) == 1
    d = divergences[0]
    assert d.kind == "auth-boundary"
    assert "bypassed" in d.detail
    assert d.baseline_status == 401 and d.variant_status == 200


def test_auth_boundary_enabled():
    planned = [_request()]
    divergences = compare_sequences(planned, [_snap(200)], [_snap(403)])
    assert divergences[0].kind == "auth-boundary"
    assert "required" in divergences[0].detail


def test_server_error_only_under_variant():
    planned = [_request()]
    divergences = compare_sequences(planned, [_snap(200)], [_snap(500)])
    assert divergences[0].kind == "server-error"


def test_status_success_vs_failure():
    planned = [_request()]
    divergences = compare_sequences(planned, [_snap(200)], [_snap(404)])
    assert divergences[0].kind == "status"


def test_info_leak_on_new_sensitive_keys():
    planned = [_request("GET /info")]
    base = [_snap(200, {"service": "api"}, frozenset({"service"}))]
    var = [
        _snap(
            200,
            {"service": "api", "debug": {"stack": "x"}},
            frozenset({"service", "debug", "stack"}),
        ),
    ]
    kinds = {d.kind for d in compare_sequences(planned, base, var)}
    assert kinds == {"info-leak"}
    leak = compare_sequences(planned, base, var)[0]
    assert "debug" in leak.detail


def test_transport_mismatch():
    planned = [_request()]
    divergences = compare_sequences(planned, [_snap(None)], [_snap(200)])
    assert divergences[0].kind == "transport"


def test_length_mismatch_raises():
    with pytest.raises(ValueError):
        compare_sequences([_request()], [], [_snap(200)])


@patch("fuzzrex.oracle.requests.request")
def test_send_request_passes_fields(mock_request):
    mock_request.return_value = _response(200, {"ok": True})
    req = HttpRequest(
        method="POST",
        url="http://sut.test/items",
        params={"q": "1"},
        headers={"X-A": "1"},
        cookies={"c": "v"},
        body={"n": 1},
    )
    send_request(req, timeout=3.0)
    kwargs = mock_request.call_args.kwargs
    assert mock_request.call_args.args == ("POST", "http://sut.test/items")
    assert kwargs["params"] == {"q": "1"}
    assert kwargs["json"] == {"n": 1}
    assert kwargs["timeout"] == 3.0


@patch("fuzzrex.oracle.send_request")
def test_execute_sequence_handles_transport_error(mock_send):
    mock_send.side_effect = [
        _response(200, {"a": 1}),
        requests_lib.ConnectionError("down"),
    ]
    snaps = execute_sequence([_request("GET /a"), _request("GET /b")])
    assert snaps[0].status_code == 200
    assert snaps[1].status_code is None


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_differential_probe_uses_same_sequence(mock_cm, mock_execute):
    orchestrator = MagicMock()
    baseline = [_snap(401)]
    variant = [_snap(200)]
    mock_execute.side_effect = [baseline, variant]

    mock_cm.return_value.__enter__ = MagicMock(return_value=orchestrator)
    mock_cm.return_value.__exit__ = MagicMock(return_value=False)

    planned = [_request("GET /admin")]
    divergences = differential_probe(orchestrator, {"a": 1}, {"a": 2}, planned)

    assert mock_execute.call_count == 2
    # Both calls receive the identical planned sequence object
    assert mock_execute.call_args_list[0].args[0] is planned
    assert mock_execute.call_args_list[1].args[0] is planned
    assert len(divergences) == 1
    assert divergences[0].kind == "auth-boundary"
    assert isinstance(divergences[0], Divergence)


# --- Joint config x API search ---


def _orchestrator_mock():
    orch = MagicMock()
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=orch)
    cm.__exit__ = MagicMock(return_value=False)
    return orch, cm


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_returns_only_divergent_cells(mock_cm, mock_execute):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    baseline = [_snap(200)]
    clean = [_snap(200)]
    dirty = [_snap(401)]
    # baseline recording, then one clean cell, then one dirty cell
    mock_execute.side_effect = [baseline, clean, dirty]

    planned = [_request("GET /admin")]
    results = run_joint_search(orch, {"debug": False}, planned, iterations=2, seed=1)

    assert len(results) == 1
    assert isinstance(results[0], CellResult)
    assert results[0].divergences[0].kind == "auth-boundary"
    # baseline + 2 cells = 3 executions
    assert mock_execute.call_count == 3


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_skips_unhealthy_cells(mock_cm, mock_execute):
    from fuzzrex.orchestrator import OrchestratorError

    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    baseline = [_snap(200)]
    healthy = [_snap(401)]
    mock_execute.side_effect = [baseline, healthy]

    planned = [_request("GET /admin")]
    # Make configured_service's __enter__ raise on the 2nd call.
    enters = {"count": 0}

    def enter(_self=None):
        enters["count"] += 1
        if enters["count"] == 2:
            raise OrchestratorError("unhealthy")
        return orch

    mock_cm.return_value.__enter__ = MagicMock(side_effect=enter)

    results = run_joint_search(orch, {"debug": False}, planned, iterations=2, seed=1)
    # first cell skipped, second cell executed with healthy snapshots (dirty)
    assert len(results) == 1
    assert mock_execute.call_count == 2  # baseline + one successful cell


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_restart_every_resets_mutation_base(mock_cm, mock_execute):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    dirty = [_snap(401)]
    clean = [_snap(200)]
    # baseline recorded as clean 200; every probed cell then diverges
    mock_execute.side_effect = [clean] + [dirty] * (RESTART_EVERY + 1)

    planned = [_request("GET /admin")]
    results = run_joint_search(
        orch,
        {"debug": False},
        planned,
        iterations=RESTART_EVERY + 1,
        seed=2,
    )

    # every executed cell diverged
    assert len(results) == RESTART_EVERY + 1
    # baseline recorded once only
    assert mock_execute.call_count == RESTART_EVERY + 2


def test_iterations_validation():
    orch, _ = _orchestrator_mock()
    with pytest.raises(ValueError, match="iterations"):
        run_joint_search(orch, [], {"a": 1}, iterations=0)
