import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from fuzzrex.campaign import _load_cells, _resolve_arms, _seed_from_dict, build_parser, main, run
from fuzzrex.experiments import ArmStats, ComparisonResult, SeedResult, config_grid
from fuzzrex.orchestrator import OrchestratorError
from fuzzrex.schema import load_document

REPO = Path(__file__).resolve().parent.parent

REQUIRED = [
    "--compose", "compose.yml",
    "--service", "sut",
    "--config", "sut.ini",
    "--base-url", "http://sut.test",
    "--spec", "openapi.yml",
    "--baseline-config", "base.json",
    "--cells", "cells.json",
]


def _stats(**overrides):
    fields = dict(
        divergent_cells=1,
        unique_cells=1,
        kinds={"status": 1},
        cells_visited=5,
        cells_unhealthy=0,
        first_divergence_iteration=2,
        first_divergence_s=1.0,
        elapsed_s=9.0,
    )
    fields.update(overrides)
    return ArmStats(**fields)


def _files(tmp_path, cells='{"flag": [false, true]}'):
    base = tmp_path / "base.json"
    base.write_text('{"flag": false}')
    cells_path = tmp_path / "cells.json"
    cells_path.write_text(cells)
    spec = tmp_path / "openapi.json"
    spec.write_text('{"openapi": "3.0.0", "paths": {}}')
    out = tmp_path / "out" / "campaign.json"
    return [
        "--baseline-config", str(base),
        "--cells", str(cells_path),
        "--spec", str(spec),
        "--out", str(out),
    ], out


def _one_seed(orch, baseline, spec, cells, **kwargs):
    return ComparisonResult(
        name=kwargs["name"],
        seeds=[SeedResult(seed=kwargs["seeds"][0], arms={"joint": _stats()})],
    )


def test_parser_requires_sut_and_search_arguments():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])
    args = parser.parse_args(REQUIRED)
    assert args.seeds == 10
    assert args.iterations == 30
    assert args.request_mutation == 0.0
    assert args.plan_mutations == 0
    assert args.stall is None
    assert args.reload == "restart"


def test_load_cells_domains_grid_from_baseline(tmp_path):
    domains = tmp_path / "domains.json"
    domains.write_text('{"a": [1, 2], "b": [true, false]}')
    cells, enums = _load_cells(domains, {"a": 0, "b": True})
    assert len(cells) == 4
    # every cell is the baseline document with the domain keys applied
    assert all(set(cell) == {"a", "b"} for cell in cells)
    assert {"a": 2, "b": False} in cells
    assert enums == {"a": [1, 2], "b": [True, False]}


def test_load_cells_explicit_list_keeps_documents_and_no_default_enums(tmp_path):
    explicit = tmp_path / "cells.json"
    explicit.write_text('[{"flag": false}, {"flag": true}]')
    cells, enums = _load_cells(explicit, {"flag": False})
    assert cells == [{"flag": False}, {"flag": True}]
    assert enums is None

    bad = tmp_path / "bad.json"
    bad.write_text('"nope"')
    with pytest.raises(SystemExit, match="--cells"):
        _load_cells(bad, {"flag": False})


def test_load_cells_dotted_domains_nest_into_baseline(tmp_path):
    path = tmp_path / "domains.json"
    path.write_text('{"auth.anonymous.enabled": [false, true]}')
    baseline = {"auth.anonymous": {"enabled": False}}
    cells, enums = _load_cells(path, baseline)
    assert cells == [
        {"auth.anonymous": {"enabled": False}},
        {"auth.anonymous": {"enabled": True}},
    ]
    assert enums == {"enabled": [False, True]}  # leaf name, as config_fuzzer matches


def test_load_cells_literal_dotted_key_stays_flat(tmp_path):
    path = tmp_path / "domains.json"
    path.write_text('{"log4j.appender.file": ["a", "b"]}')
    baseline = {"log4j.appender.file": "a"}
    cells, enums = _load_cells(path, baseline)
    assert cells == [{"log4j.appender.file": "a"}, {"log4j.appender.file": "b"}]
    assert enums == {"log4j.appender.file": ["a", "b"]}


def test_load_cells_rejects_unknown_and_conflicting_keys(tmp_path):
    unknown = tmp_path / "unknown.json"
    unknown.write_text('{"missing.key": [1]}')
    with pytest.raises(SystemExit, match="not found"):
        _load_cells(unknown, {"flag": False})

    conflict = tmp_path / "conflict.json"
    conflict.write_text('{"a": [1], "a.b": [2]}')
    with pytest.raises(SystemExit, match="prefix"):
        _load_cells(conflict, {"a": 1})

    scalar_baseline = tmp_path / "domains.json"
    scalar_baseline.write_text('{"flag": [true]}')
    with pytest.raises(SystemExit, match="baseline-config"):
        _load_cells(scalar_baseline, "not-a-document")


def test_resolve_arms_filters_and_rejects_unknown():
    assert [a.name for a in _resolve_arms("joint")] == ["joint"]
    assert [a.name for a in _resolve_arms("joint,joint-no-feedback")] == [
        "joint",
        "joint-no-feedback",
    ]
    with pytest.raises(SystemExit, match="unknown arms"):
        _resolve_arms("joint,typo")


def test_stale_checkpoint_rejected():
    with pytest.raises(ValueError, match="unique_cells"):
        _seed_from_dict(
            {"seed": 0, "arms": {"joint": {"divergent_cells": 1}},
             "baseline_findings": 0, "baseline_per_cell": [], "baseline_signatures": []}
        )


def _load_phase1_module():
    spec = importlib.util.spec_from_file_location(
        "phase1_campaign", REPO / "examples" / "phase1_campaign.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_inputs_reproduce_the_phase1_protocol():
    """The committed baseline/cells files must yield exactly the inputs
    examples/phase1_campaign.py hardcodes, so CLI campaigns are
    comparable with the archived Phase-1 numbers."""
    phase1 = _load_phase1_module()

    # crAPI: flat domains -> identical grid and enum pools
    crapi = REPO / "examples" / "crapi"
    assert load_document(crapi / "baseline.json") == {
        "ENABLE_SHELL_INJECTION": False,
        "TLS_ENABLED": False,
    }
    cells, enums = _load_cells(crapi / "cells.json", load_document(crapi / "baseline.json"))
    assert cells == config_grid(phase1.CRAPI_KNOBS)
    assert enums == phase1.CRAPI_KNOBS

    # DVWA: 8-cell grid; the bool domain appears in the default enums too,
    # but it pools {false,true} exactly like fuzz_boolean did in Phase 1
    dvwa = REPO / "examples" / "dvwa"
    assert load_document(dvwa / "baseline.json") == {
        "disable_authentication": False,
        "default_security_level": "low",
    }
    cells, enums = _load_cells(dvwa / "cells.json", load_document(dvwa / "baseline.json"))
    assert cells == config_grid(
        {"disable_authentication": [False, True], "default_security_level": phase1.DVWA_LEVELS}
    )
    assert enums["default_security_level"] == phase1.DVWA_LEVELS

    # grafana: dotted domain nests through the INI-style section
    grafana = REPO / "examples" / "grafana"
    baseline = load_document(grafana / "baseline.json")
    assert baseline == {"auth.anonymous": {"enabled": False}}
    cells, enums = _load_cells(grafana / "cells.json", baseline)
    assert cells == [
        {"auth.anonymous": {"enabled": False}},
        {"auth.anonymous": {"enabled": True}},
    ]
    assert enums == {"enabled": [False, True]}


@patch("fuzzrex.campaign.run_comparison")
@patch("fuzzrex.campaign.DockerComposeOrchestrator")
def test_run_resumes_done_seeds_and_checkpoints(mock_orch, mock_compare, tmp_path):
    argv, out = _files(tmp_path)
    mock_compare.side_effect = _one_seed

    assert main(REQUIRED + argv + ["--seeds", "1"]) == 0
    mock_compare.reset_mock()
    mock_orch.return_value.up.reset_mock()
    mock_orch.return_value.restore.reset_mock()

    # second invocation resumes: only seed 1 runs, checkpoint holds both
    assert main(REQUIRED + argv + ["--seeds", "2"]) == 0
    assert mock_compare.call_count == 1
    assert mock_compare.call_args.kwargs["seeds"] == (1,)
    stored = json.loads(out.read_text())
    assert [s["seed"] for s in stored["seeds"]] == [0, 1]
    assert stored["budget"]["grid_cells"] == 2
    mock_orch.return_value.up.assert_called_once()
    mock_orch.return_value.restore.assert_called_once()


@patch("fuzzrex.campaign.run_comparison")
@patch("fuzzrex.campaign.DockerComposeOrchestrator")
def test_run_rejects_resume_with_a_different_protocol(mock_orch, mock_compare, tmp_path):
    argv, out = _files(tmp_path)
    mock_compare.side_effect = _one_seed
    assert main(REQUIRED + argv + ["--seeds", "1"]) == 0

    with pytest.raises(SystemExit, match="budget mismatch.*stall_window"):
        main(REQUIRED + argv + ["--seeds", "1", "--stall", "8"])
    assert mock_compare.call_count == 1  # no mixed-protocol run happened
    assert mock_orch.return_value.up.call_count == 1


@patch("fuzzrex.campaign.run_comparison")
@patch("fuzzrex.campaign.DockerComposeOrchestrator")
def test_run_forwards_feature_flags_into_budget(mock_orch, mock_compare, tmp_path):
    argv, out = _files(tmp_path)
    mock_compare.return_value = ComparisonResult(
        name="sut",
        seeds=[
            SeedResult(seed=0, arms={"joint": _stats(stopped_early=True, request_iterations=6)})
        ],
    )

    code = main(
        REQUIRED
        + argv
        + [
            "--seeds", "1",
            "--stall", "8",
            "--request-mutation", "0.3",
            "--plan-mutations", "2",
            "--arms", "joint",
            "--no-baseline",
        ]
    )

    assert code == 0
    kwargs = mock_compare.call_args.kwargs
    assert kwargs["stall_window"] == 8
    assert kwargs["request_mutation"] == 0.3
    assert kwargs["plan_mutations"] == 2
    assert kwargs["run_baseline"] is False
    assert [a.name for a in kwargs["arms"]] == ["joint"]
    budget = json.loads(out.read_text())["budget"]
    assert budget["stall_window"] == 8
    assert budget["request_mutation"] == 0.3
    assert budget["plan_mutations"] == 2
    assert budget["arms"] == ["joint"]


@patch("fuzzrex.campaign.run_comparison")
@patch("fuzzrex.campaign.DockerComposeOrchestrator")
def test_run_returns_one_and_keeps_checkpoint_on_sut_failure(mock_orch, mock_compare, tmp_path):
    argv, out = _files(tmp_path)
    mock_compare.side_effect = OrchestratorError("service unhealthy")

    code = main(REQUIRED + argv + ["--seeds", "1"])

    assert code == 1
    assert out.is_file()  # checkpoint written for resume
    assert json.loads(out.read_text())["seeds"] == []
    mock_orch.return_value.restore.assert_called_once()


@patch("fuzzrex.campaign.run_comparison")
@patch("fuzzrex.campaign.DockerComposeOrchestrator")
def test_run_short_circuits_when_all_seeds_done(mock_orch, mock_compare, tmp_path):
    argv, _ = _files(tmp_path)
    mock_compare.side_effect = _one_seed
    assert main(REQUIRED + argv + ["--seeds", "1"]) == 0
    mock_compare.reset_mock()
    mock_orch.return_value.up.reset_mock()

    assert run(build_parser().parse_args(REQUIRED + argv + ["--seeds", "1"])) == 0
    mock_compare.assert_not_called()
    mock_orch.return_value.up.assert_not_called()
