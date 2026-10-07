from unittest.mock import MagicMock, patch

from fuzzrex.baseline import BaselineFinding, BaselineResult
from fuzzrex.experiments import (
    ArmStats,
    ComparisonResult,
    JointArm,
    SeedResult,
    config_grid,
    run_comparison,
)
from fuzzrex.oracle import CellResult, Divergence, SearchTrace


def test_config_grid_is_cartesian_product():
    grid = config_grid({"a": [1, 2], "b": ["x", "y", "z"]})
    assert len(grid) == 6
    assert {"a": 1, "b": "x"} in grid
    assert {"a": 2, "b": "z"} in grid


def test_config_grid_single_domain():
    assert config_grid({"flag": [True, False]}) == [{"flag": True}, {"flag": False}]


def _trace(
    divergent: int,
    unhealthy: int = 0,
    first_iter: int | None = None,
    unique: int | None = None,
) -> SearchTrace:
    cells = tuple(
        CellResult({"flag": True}, (Divergence("GET /x", "auth-boundary", "bypassed", 302, 200),))
        for _ in range(divergent)
    )
    return SearchTrace(
        divergent_cells=cells,
        unique_cells=divergent if unique is None else unique,
        cells_visited=5,
        cells_unhealthy=unhealthy,
        first_divergence_iteration=first_iter,
        first_divergence_s=1.5 if first_iter is not None else None,
        elapsed_s=9.0,
    )


def _baseline(config, findings_count):
    findings = (
        (BaselineFinding("failure", "server error", 1, ("POST /x",)),)
        if findings_count
        else ()
    )
    return BaselineResult(config, findings, 10, 0)


@patch("fuzzrex.experiments.run_baseline_matrix")
@patch("fuzzrex.experiments.run_joint_search_traced")
def test_run_comparison_runs_all_arms_and_baseline(mock_traced, mock_baseline, tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text(
        '{"openapi": "3.0.0", "paths": '
        '{"/x": {"get": {"responses": {"200": {"description": "ok"}}}}}}'
    )
    mock_traced.side_effect = [
        _trace(1, first_iter=4, unique=1),
        _trace(0, unhealthy=1),
        _trace(0),
        _trace(2, first_iter=0, unique=1),  # two probes, one effective config
    ]
    mock_baseline.side_effect = [
        [_baseline({"flag": False}, 0), _baseline({"flag": True}, 1)],
        [_baseline({"flag": False}, 0), _baseline({"flag": True}, 0)],
    ]

    orch = MagicMock()
    orch.base_url = "http://sut.test"
    seeds: list[SeedResult] = []
    result = run_comparison(
        orch,
        {"flag": False},
        str(spec),
        [{"flag": False}, {"flag": True}],
        name="sut-x",
        seeds=(7, 9),
        joint_iterations=3,
        baseline_max_examples=2,
        enums={"flag": [True, False]},
        on_seed=seeds.append,
    )

    assert isinstance(result, ComparisonResult)
    assert result.name == "sut-x"
    assert len(seeds) == 2

    # both joint arms ran per seed, ablation second
    assert [c.kwargs["feedback"] for c in mock_traced.call_args_list] == [
        True, False, True, False,
    ]
    assert mock_traced.call_args_list[0].kwargs["iterations"] == 3
    assert mock_traced.call_args_list[0].kwargs["enums"] == {"flag": [True, False]}

    # arm aggregates: joint 1 then 0 probes; ablation 0 then 2 (1 unique)
    assert result.mean_cells("joint") == 0.5
    assert result.mean_cells("joint-no-feedback") == 1.0
    # unique counts dedupe: ablation's 2 probes are 1 effective config
    assert result.mean_unique_cells("joint") == 0.5
    assert result.mean_unique_cells("joint-no-feedback") == 0.5
    assert result.total_kinds("joint") == {"auth-boundary": 1}
    assert result.total_kinds("joint-no-feedback") == {"auth-boundary": 2}
    assert result.mean_first_divergence_iteration("joint") == 4.0
    assert result.mean_first_divergence_iteration("joint-no-feedback") == 0.0

    # baseline: seed 7 -> 1 finding, seed 9 -> 0
    assert result.mean_baseline_findings == 0.5
    assert result.seeds[0].baseline_per_cell == [0, 1]
    assert result.baseline_unique_signatures == ["server error (POST /x)"]


@patch("fuzzrex.experiments.run_baseline_matrix")
@patch("fuzzrex.experiments.run_joint_search_traced")
def test_run_comparison_can_skip_baseline(mock_traced, mock_baseline, tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text(
        '{"openapi": "3.0.0", "paths": '
        '{"/x": {"get": {"responses": {"200": {"description": "ok"}}}}}}'
    )
    mock_traced.return_value = _trace(0)

    orch = MagicMock()
    orch.base_url = "http://sut.test"
    result = run_comparison(
        orch,
        {"flag": False},
        str(spec),
        [{"flag": False}],
        seeds=(0,),
        arms=(JointArm("joint"),),
        run_baseline=False,
    )

    mock_baseline.assert_not_called()
    assert result.mean_baseline_findings == 0.0
    assert result.seeds[0].baseline_per_cell == []


def test_comparison_result_to_dict_is_json_ready():
    import json

    result = ComparisonResult(
        name="x",
        seeds=[
            SeedResult(
                seed=1,
                arms={
                    "joint": ArmStats(
                        divergent_cells=2,
                        unique_cells=1,
                        kinds={"status": 4},
                        cells_visited=10,
                        cells_unhealthy=1,
                        first_divergence_iteration=3,
                        first_divergence_s=2.5,
                        elapsed_s=30.0,
                    )
                },
            )
        ],
    )
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["arms"]["joint"]["mean_divergent_cells"] == 2.0
    assert payload["arms"]["joint"]["mean_unique_cells"] == 1.0
    assert payload["arms"]["joint"]["kinds"] == {"status": 4}
    assert payload["arms"]["joint"]["mean_first_divergence_iteration"] == 3.0
    assert payload["seeds"][0]["arms"]["joint"]["cells_unhealthy"] == 1
    assert payload["baseline_unique_findings"] == 0
