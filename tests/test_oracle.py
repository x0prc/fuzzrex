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
    run_joint_search_traced,
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


@patch("fuzzrex.oracle.send_request")
def test_execute_sequence_resolves_token_and_param_links(mock_send):
    mock_send.side_effect = [
        _response(200, {"token": "tok123"}),
        _response(200, {"id": 7}),
        _response(200, {"ok": True}),
    ]
    login = HttpRequest(method="POST", url="http://sut.test/login", label="POST /login")
    upload = HttpRequest(
        method="POST", url="http://sut.test/videos", label="POST /videos",
        token_from="POST /login",
    )
    convert = HttpRequest(
        method="GET", url="http://sut.test/convert", label="GET /convert",
        token_from="POST /login",
        param_from={"video_id": ("POST /videos", "id")},
    )
    execute_sequence([login, upload, convert])

    sent_upload = mock_send.call_args_list[1].args[0]
    assert sent_upload.headers["Authorization"] == "Bearer tok123"
    sent_convert = mock_send.call_args_list[2].args[0]
    assert sent_convert.headers["Authorization"] == "Bearer tok123"
    assert sent_convert.params == {"video_id": 7}
    # The planned instances stay untouched for cross-cell equality.
    assert upload.headers == {}
    assert convert.params == {}


@patch("fuzzrex.oracle.send_request")
def test_execute_sequence_missing_producer_sends_request_unchanged(mock_send):
    mock_send.return_value = _response(200, {"ok": True})
    orphan = HttpRequest(
        method="GET", url="http://sut.test/convert", label="GET /convert",
        param_from={"video_id": ("GET /missing", "id")},
    )
    execute_sequence([orphan])
    sent = mock_send.call_args.args[0]
    assert sent.params == {}
    assert "Authorization" not in sent.headers


@patch("fuzzrex.oracle.requests.request")
def test_send_request_passes_files_and_drops_json(mock_request):
    mock_request.return_value = _response(200, {"ok": True})
    req = HttpRequest(
        method="POST",
        url="http://sut.test/upload",
        body={"ignored": True},
        files={"file": ("clip.mp4", b"\x00\x01", "video/mp4")},
    )
    send_request(req, timeout=3.0)
    kwargs = mock_request.call_args.kwargs
    assert kwargs["files"] == {"file": ("clip.mp4", b"\x00\x01", "video/mp4")}
    assert kwargs["json"] is None


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


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_stall_window_stops_early(mock_cm, mock_execute):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    clean = [_snap(200)]
    # baseline, then only clean cells: three stalls in a row -> stop
    mock_execute.side_effect = [clean] + [clean] * 3

    trace = run_joint_search_traced(
        orch,
        {"debug": False},
        [_request("GET /x")],
        iterations=10,
        seed=1,
        stall_window=3,
    )

    assert trace.stopped_early is True
    assert trace.cells_visited == 3
    assert trace.unique_cells == 0
    assert mock_execute.call_count == 4  # baseline + 3 cells


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_new_unique_cell_resets_stall(mock_cm, mock_execute):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    baseline = [_snap(200)]
    clean = [_snap(200)]
    dirty = [_snap(401)]
    # baseline, 2 stalls, 1 new unique divergent cell (reset), 3 stalls -> stop
    mock_execute.side_effect = [baseline, clean, clean, dirty, clean, clean, clean]

    with patch("fuzzrex.oracle.mutate_config") as mock_mutate:
        mock_mutate.side_effect = [
            {"debug": v} for v in (True, False, False, True, False, False)
        ]
        trace = run_joint_search_traced(
            orch,
            {"debug": False},
            [_request("GET /admin")],
            iterations=20,
            seed=1,
            stall_window=3,
        )

    assert trace.stopped_early is True
    assert trace.cells_visited == 6
    assert trace.unique_cells == 1
    assert trace.first_divergence_iteration == 2


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_duplicate_divergence_counts_as_stall(mock_cm, mock_execute):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    baseline = [_snap(200)]
    dirty = [_snap(401)]
    # every cell diverges but is the same config: only the first is new
    # unique; duplicates stall -> stop after 3 cells
    mock_execute.side_effect = [baseline] + [dirty] * 3

    with patch("fuzzrex.oracle.mutate_config") as mock_mutate:
        mock_mutate.side_effect = [{"debug": True}] * 3
        trace = run_joint_search_traced(
            orch,
            {"debug": False},
            [_request("GET /admin")],
            iterations=5,
            seed=1,
            stall_window=2,
        )

    assert trace.stopped_early is True
    assert trace.cells_visited == 3
    assert trace.divergent_cells and trace.unique_cells == 1


def test_stall_window_validation():
    orch, _ = _orchestrator_mock()
    with pytest.raises(ValueError, match="stall_window"):
        run_joint_search_traced(orch, {}, [], iterations=1, stall_window=0)


def test_request_mutation_validation():
    orch, _ = _orchestrator_mock()
    with pytest.raises(ValueError, match="request_mutation"):
        run_joint_search_traced(orch, {}, [], iterations=1, request_mutation=1.5)


@patch("fuzzrex.oracle.mutate_request")
@patch("fuzzrex.oracle.mutate_config")
@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_request_mutation_pairs_variant_with_cached_baseline(
    mock_cm, mock_execute, mock_config, mock_request,
):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    mutated = [_request("GET /x-mutated")]
    patch = {"label": "GET /x", "field": "params", "path": ["q"], "value": 99}
    # both iterations draw the same variant -> second one must hit the cache
    mock_request.side_effect = [(mutated, patch), (mutated, patch)]
    mock_config.return_value = {"debug": True}
    # planned-sequence baseline, c0-under-variant, cell 0, cell 1
    mock_execute.side_effect = [[_snap(200)], [_snap(200)], [_snap(401)], [_snap(401)]]

    trace = run_joint_search_traced(
        orch,
        {"debug": False},
        [_request("GET /x")],
        iterations=2,
        seed=1,
        request_mutation=1.0,
    )

    calls = mock_execute.call_args_list
    # c0-under-variant recorded once, then two cells: no second baseline replay
    assert mock_execute.call_count == 4
    assert calls[0].args[0] == [_request("GET /x")]  # initial fixed-sequence baseline
    assert all(call.args[0] == mutated for call in calls[1:])  # pair replay matches
    assert trace.request_iterations == 2
    assert trace.cells_visited == 2
    assert trace.unique_cells == 1  # same (config, patch) pair twice
    assert trace.divergent_cells[0].request_patch == patch


@patch("fuzzrex.oracle.mutate_request")
@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_request_mutation_off_by_default(mock_cm, mock_execute, mock_request):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm
    clean = [_snap(200)]
    mock_execute.side_effect = [clean, clean, clean]

    planned = [_request("GET /x")]
    trace = run_joint_search_traced(orch, {"debug": False}, planned, iterations=2, seed=1)

    mock_request.assert_not_called()
    assert mock_execute.call_count == 3  # baseline + 2 cells, as in the fixed protocol
    for call in mock_execute.call_args_list:
        assert call.args[0] == planned
    assert trace.request_iterations == 0
    # the archived protocol records no interaction detail at all
    assert trace.visits == []
    assert trace.request_variants == []


@patch("fuzzrex.oracle.mutate_request")
@patch("fuzzrex.oracle.mutate_config")
@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_request_mutation_records_interaction_detail(
    mock_cm, mock_execute, mock_config, mock_request,
):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    mutated = [_request("GET /x-mutated")]
    patch = {"label": "GET /x", "field": "params", "path": ["q"], "value": 99}
    mock_request.side_effect = [(mutated, patch)] * 3
    mock_config.return_value = {"debug": True}
    # planned baseline, c0-under-variant (patch clean at c0), then
    # divergent, clean, divergent cells
    mock_execute.side_effect = [
        [_snap(200)],
        [_snap(200)],
        [_snap(401)],
        [_snap(200)],
        [_snap(401)],
    ]

    trace = run_joint_search_traced(
        orch,
        {"debug": False},
        [_request("GET /x")],
        iterations=3,
        seed=1,
        request_mutation=1.0,
    )

    assert trace.request_iterations == 3
    assert mock_execute.call_count == 5  # baseline + c0 + 3 cells (no extra requests)
    assert [v["divergent"] for v in trace.visits] == [True, False, True]
    assert all(v["healthy"] for v in trace.visits)
    # clean visits keep their patch too: they are the counterfactual context
    assert trace.visits[1]["patch"] == patch
    assert trace.request_variants == [
        {"patch": patch, "diverges_at_c0": False, "kinds": []}
    ]


@patch("fuzzrex.oracle.mutate_request")
@patch("fuzzrex.oracle.mutate_config")
@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_request_mutation_flags_patch_that_diverges_at_c0(
    mock_cm, mock_execute, mock_config, mock_request,
):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    mutated = [_request("GET /x-mutated")]
    patch = {"label": "GET /x", "field": "params", "path": ["q"], "value": 99}
    mock_request.side_effect = [(mutated, patch)]
    mock_config.return_value = {"debug": True}
    # planned baseline 200, c0-under-variant 401 (patch alone diverges),
    # cell clean against its own c0 reference
    mock_execute.side_effect = [[_snap(200)], [_snap(401)], [_snap(401)]]

    trace = run_joint_search_traced(
        orch,
        {"debug": False},
        [_request("GET /x")],
        iterations=1,
        seed=1,
        request_mutation=1.0,
    )

    record = trace.request_variants[0]
    assert record["diverges_at_c0"] is True
    assert record["kinds"]  # the request-side finding's kinds are kept
    assert trace.divergent_cells == ()  # config had no effect under this patch


@patch("fuzzrex.oracle.mutate_request")
@patch("fuzzrex.oracle.mutate_config")
@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_request_mutation_records_unhealthy_visit(mock_cm, mock_execute, mock_config, mock_request):
    from fuzzrex.orchestrator import OrchestratorError

    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm

    mutated = [_request("GET /x-mutated")]
    patch = {"label": "GET /x", "field": "params", "path": ["q"], "value": 99}
    mock_request.side_effect = [(mutated, patch)]
    mock_config.return_value = {"debug": True}
    mock_execute.side_effect = [[_snap(200)], [_snap(200)]]

    enters = {"count": 0}

    def enter(_self=None):
        enters["count"] += 1
        if enters["count"] == 3:  # baseline, c0, then the cell itself
            raise OrchestratorError("unhealthy")
        return orch

    mock_cm.return_value.__enter__ = MagicMock(side_effect=enter)

    trace = run_joint_search_traced(
        orch,
        {"debug": False},
        [_request("GET /x")],
        iterations=1,
        seed=1,
        request_mutation=1.0,
    )

    assert trace.cells_unhealthy == 1
    assert trace.visits == [
        {
            "iteration": 0,
            "config": {"debug": True},
            "patch": patch,
            "healthy": False,
            "divergent": False,
            "kinds": [],
        }
    ]
    # the variant's c0 record survives even when the cell itself was unhealthy
    assert trace.request_variants[0]["diverges_at_c0"] is False
    assert mock_execute.call_count == 2


def test_iterations_validation():
    orch, _ = _orchestrator_mock()
    with pytest.raises(ValueError, match="iterations"):
        run_joint_search(orch, [], {"a": 1}, iterations=0)


@patch("fuzzrex.oracle.mutate_config")
@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_feedback_false_always_mutates_baseline(mock_cm, mock_execute, mock_mutate):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm
    mock_execute.side_effect = [[_snap(200)]] + [[_snap(401)]] * 3
    baseline_config = {"debug": False}
    mock_mutate.return_value = {"debug": True}

    planned = [_request("GET /admin")]
    trace = run_joint_search_traced(
        orch, baseline_config, planned, iterations=3, seed=5, feedback=False
    )

    assert len(trace.divergent_cells) == 3
    # every iteration mutated the baseline, never a divergent cell
    for call in mock_mutate.call_args_list:
        assert call.args[0] is baseline_config


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_traced_records_metrics(mock_cm, mock_execute):
    from fuzzrex.orchestrator import OrchestratorError

    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm
    mock_execute.side_effect = [[_snap(200)], [_snap(200)], [_snap(401)]]

    planned = [_request("GET /admin")]
    enters = {"count": 0}

    def enter(_self=None):
        enters["count"] += 1
        if enters["count"] == 2:
            raise OrchestratorError("unhealthy")
        return orch

    mock_cm.return_value.__enter__ = MagicMock(side_effect=enter)

    trace = run_joint_search_traced(orch, {"debug": False}, planned, iterations=3, seed=1)

    assert trace.cells_visited == 2  # one unhealthy skipped
    assert trace.cells_unhealthy == 1
    assert trace.first_divergence_iteration == 2  # second healthy cell diverged
    assert trace.first_divergence_s is not None
    assert trace.elapsed_s >= trace.first_divergence_s


@patch("fuzzrex.oracle.mutate_config")
@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_trace_dedupes_repeat_configs(mock_cm, mock_execute, mock_mutate):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm
    mock_execute.side_effect = [[_snap(200)]] + [[_snap(401)]] * 3
    mock_mutate.side_effect = [{"debug": True}, {"debug": True}, {"debug": False}]

    planned = [_request("GET /admin")]
    trace = run_joint_search_traced(
        orch, {"debug": False}, planned, iterations=3, seed=1, feedback=False
    )

    # three divergent probes but only two effective configs
    assert len(trace.divergent_cells) == 3
    assert trace.unique_cells == 2


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_traced_defers_blocks_and_restores_once(mock_cm, mock_execute):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm
    mock_execute.side_effect = [[_snap(200)], [_snap(401)]]

    planned = [_request("GET /admin")]
    trace = run_joint_search_traced(orch, {"debug": False}, planned, iterations=1, seed=1)

    assert trace.cells_visited == 1
    # baseline snapshot + one cell, both disk-only exits
    assert mock_cm.call_count == 2
    assert all(call.kwargs.get("defer") is True for call in mock_cm.call_args_list)
    # the SUT lands back on c0 exactly once, after the search
    orch.restore.assert_called_once()


@patch("fuzzrex.oracle.execute_sequence")
@patch("fuzzrex.oracle.configured_service")
def test_traced_restores_even_when_search_raises(mock_cm, mock_execute):
    orch, cm = _orchestrator_mock()
    mock_cm.return_value = cm
    mock_execute.side_effect = RuntimeError("replay exploded")

    planned = [_request("GET /admin")]
    with pytest.raises(RuntimeError, match="replay exploded"):
        run_joint_search_traced(orch, {"debug": False}, planned, iterations=1, seed=1)

    orch.restore.assert_called_once()


def test_canonical_config_is_key_order_independent():
    from fuzzrex.oracle import canonical_config

    assert canonical_config({"a": 1, "b": {"x": True}}) == canonical_config(
        {"b": {"x": True}, "a": 1}
    )
    assert canonical_config({"a": 1}) != canonical_config({"a": 2})


# --- Redirect handling ---


def test_login_redirect_vs_success_is_auth_boundary():
    planned = [_request("GET /secret")]
    base = [_snap(302)]
    base[0] = ResponseSnapshot(302, None, "", frozenset(), location="login.php")
    divergences = compare_sequences(planned, base, [_snap(200)])
    assert divergences[0].kind == "auth-boundary"
    assert "bypassed" in divergences[0].detail


def test_success_vs_login_redirect_is_auth_boundary():
    planned = [_request("GET /secret")]
    var = [ResponseSnapshot(302, None, "", frozenset(), location="/login.php")]
    divergences = compare_sequences(planned, [_snap(200)], var)
    assert divergences[0].kind == "auth-boundary"
    assert "required" in divergences[0].detail


def test_non_login_redirect_is_plain_status_change():
    planned = [_request("GET /moved")]
    base = [ResponseSnapshot(302, None, "", frozenset(), location="/elsewhere")]
    divergences = compare_sequences(planned, base, [_snap(200)])
    assert divergences[0].kind == "status"


@patch("fuzzrex.oracle.requests.request")
def test_send_request_does_not_follow_redirects(mock_request):
    mock_request.return_value = _response(302, None)
    send_request(_request())
    assert mock_request.call_args.kwargs["allow_redirects"] is False


def test_snapshot_captures_location_header():
    from requests.structures import CaseInsensitiveDict

    response = _response(302, None)
    response.headers = CaseInsensitiveDict({"Location": "../../login.php"})
    snap = snapshot_response(response)
    assert snap.location == "../../login.php"
