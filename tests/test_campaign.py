import json
from unittest.mock import patch

import pytest

from fuzzrex.campaign import _load_cells, _resolve_arms, _seed_from_dict, build_parser, main, run
from fuzzrex.experiments import ArmStats, ComparisonResult, SeedResult
from fuzzrex.orchestrator import OrchestratorError

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


def test_load_cells_domains_grid_and_explicit_list(tmp_path):
    domains = tmp_path / "domains.json"
    domains.write_text('{"a": [1, 2], "b": [true, false]}')
    cells, parsed_domains = _load_cells(domains)
    assert len(cells) == 4
    assert parsed_domains == {"a": [1, 2], "b": [True, False]}

    explicit = tmp_path / "cells.json"
    explicit.write_text('[{"flag": false}, {"flag": true}]')
    cells, parsed_domains = _load_cells(explicit)
    assert cells == [{"flag": False}, {"flag": True}]
    assert parsed_domains is None

    bad = tmp_path / "bad.json"
    bad.write_text('"nope"')
    with pytest.raises(SystemExit, match="--cells"):
        _load_cells(bad)


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


@patch("fuzzrex.campaign.run_comparison")
@patch("fuzzrex.campaign.DockerComposeOrchestrator")
def test_run_resumes_done_seeds_and_checkpoints(mock_orch, mock_compare, tmp_path):
    argv, out = _files(tmp_path)
    previous = ComparisonResult(name="sut", seeds=[SeedResult(seed=0, arms={"joint": _stats()})])
    out.parent.mkdir(parents=True)
    out.write_text(json.dumps(previous.to_dict()))

    def _one_seed(orch, baseline, spec, cells, **kwargs):
        return ComparisonResult(
            name=kwargs["name"],
            seeds=[SeedResult(seed=kwargs["seeds"][0], arms={"joint": _stats()})],
        )

    mock_compare.side_effect = _one_seed
    code = main(REQUIRED + argv + ["--seeds", "2"])

    assert code == 0
    assert mock_compare.call_count == 1
    assert mock_compare.call_args.kwargs["seeds"] == (1,)
    stored = json.loads(out.read_text())
    assert [s["seed"] for s in stored["seeds"]] == [0, 1]
    assert stored["budget"]["grid_cells"] == 2
    mock_orch.return_value.up.assert_called_once()
    mock_orch.return_value.restore.assert_called_once()


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
    argv, out = _files(tmp_path)
    previous = ComparisonResult(name="sut", seeds=[SeedResult(seed=0, arms={"joint": _stats()})])
    out.parent.mkdir(parents=True)
    out.write_text(json.dumps(previous.to_dict()))

    assert run(build_parser().parse_args(REQUIRED + argv + ["--seeds", "1"])) == 0
    mock_compare.assert_not_called()
    mock_orch.return_value.up.assert_not_called()
