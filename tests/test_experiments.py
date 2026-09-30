from unittest.mock import MagicMock, patch

from fuzzrex.baseline import BaselineFinding, BaselineResult
from fuzzrex.experiments import ComparisonResult, SeedResult, config_grid, run_comparison
from fuzzrex.oracle import CellResult, Divergence


def test_config_grid_is_cartesian_product():
    grid = config_grid({"a": [1, 2], "b": ["x", "y", "z"]})
    assert len(grid) == 6
    assert {"a": 1, "b": "x"} in grid
    assert {"a": 2, "b": "z"} in grid


def test_config_grid_single_domain():
    assert config_grid({"flag": [True, False]}) == [{"flag": True}, {"flag": False}]


def _cell() -> CellResult:
    div = Divergence("GET /x", "auth-boundary", "bypassed", 302, 200)
    return CellResult({"flag": True}, (div,))


def _baseline(config, findings_count):
    findings = (
        (BaselineFinding("failure", "server error", 1, ("POST /x",)),)
        if findings_count
        else ()
    )
    return BaselineResult(config, findings, 10, 0)


@patch("fuzzrex.experiments.run_baseline_matrix")
@patch("fuzzrex.experiments.run_joint_search")
def test_run_comparison_aggregates_both_arms(mock_joint, mock_baseline, tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text(
        '{"openapi": "3.0.0", "paths": '
        '{"/x": {"get": {"responses": {"200": {"description": "ok"}}}}}}'
    )
    mock_joint.side_effect = [[_cell()], []]
    mock_baseline.side_effect = [
        [_baseline({"flag": False}, 0), _baseline({"flag": True}, 1)],
        [_baseline({"flag": False}, 0), _baseline({"flag": True}, 0)],
    ]

    orch = MagicMock()
    orch.base_url = "http://sut.test"
    seen: list[SeedResult] = []
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
        on_seed=seen.append,
    )

    assert isinstance(result, ComparisonResult)
    assert result.name == "sut-x"
    assert len(seen) == 2
    assert result.mean_joint_cells == 0.5
    assert result.total_joint_kinds == {"auth-boundary": 1}
    # seed 7: 0+1 findings; seed 9: 0+0
    assert result.mean_baseline_findings == 0.5
    assert result.seeds[0].baseline_per_cell == [0, 1]
    # the one finding in seed 7 appears in the unique set
    assert result.baseline_unique_signatures == ["server error (POST /x)"]

    # joint arm receives the planned sequence and enums
    joint_kwargs = mock_joint.call_args_list[0].kwargs
    assert joint_kwargs["iterations"] == 3
    assert joint_kwargs["enums"] == {"flag": [True, False]}


def test_comparison_result_to_dict_is_json_ready():
    import json

    result = ComparisonResult(
        name="x",
        seeds=[SeedResult(1, 2, {"status": 4}, 0, [0, 0])],
    )
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["mean_joint_divergent_cells"] == 2.0
    assert payload["joint_kinds"] == {"status": 4}
    assert payload["seeds"][0]["seed"] == 1
