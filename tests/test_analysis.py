import json

import pytest

from fuzzrex.analysis import (
    load_results,
    main,
    paired_test,
    render_report,
    sign_flip_pvalue,
    summarize_arm,
    write_per_seed_csv,
)


def _payload() -> dict:
    def arm(cells, first, unhealthy=0, elapsed=100.0, unique=None):
        return {
            "divergent_cells": cells,
            "unique_cells": cells if unique is None else unique,
            "kinds": {"auth-boundary": cells},
            "cells_visited": 30,
            "cells_unhealthy": unhealthy,
            "first_divergence_iteration": first,
            "first_divergence_s": 2.0 if first is not None else None,
            "elapsed_s": elapsed,
        }

    seeds = [
        {
            "seed": 0,
            "arms": {"joint": arm(10, 3, unique=8), "joint-no-feedback": arm(4, 5)},
            "baseline_findings": 40,
            "baseline_per_cell": [5, 5],
            "baseline_signatures": ["Server error (POST /x)"],
        },
        {
            "seed": 1,
            "arms": {"joint": arm(6, 0), "joint-no-feedback": arm(4, 1)},
            "baseline_findings": 40,
            "baseline_per_cell": [5, 5],
            "baseline_signatures": ["Server error (POST /x)"],
        },
        {
            "seed": 2,
            "arms": {"joint": arm(8, None, unique=7), "joint-no-feedback": arm(4, 2, unhealthy=1)},
            "baseline_findings": 38,
            "baseline_per_cell": [5, 4],
            "baseline_signatures": ["Server error (POST /x)"],
        },
    ]
    return {
        "name": "sut-x",
        "arms": {},
        "mean_baseline_findings": 39.333,
        "baseline_unique_findings": 1,
        "baseline_signatures": ["Server error (POST /x)"],
        "seeds": seeds,
        "budget": {"seeds": [0, 1, 2], "joint_iterations": 30, "grid_cells": 2},
    }


def test_sign_flip_identical_pairs_is_one():
    p, exact = sign_flip_pvalue([0.0, 0.0, 0.0])
    assert p == 1.0 and exact


def test_sign_flip_uniform_advantage_is_small():
    p, exact = sign_flip_pvalue([5.0, 4.0, 6.0, 3.0])
    assert exact
    # all-positive diffs: only the all-same-sign extreme(s) count
    assert p == pytest.approx(2 / 16)


def test_sign_flip_monte_carlo_kicks_in_above_exact_limit():
    diffs = [1.0] * 25
    p, exact = sign_flip_pvalue(diffs)
    assert not exact
    assert 0.0 < p <= 0.05


def test_summarize_arm_aggregates():
    summary = summarize_arm(_payload(), "joint")
    assert summary.n == 3
    assert summary.mean_cells == pytest.approx(8.0)
    assert summary.std_cells > 0
    assert summary.mean_unique_cells == pytest.approx(7.0)  # (8+6+7)/3
    assert summary.n_found == 2  # seed 2 has no divergence
    assert summary.mean_first_iteration == pytest.approx(1.5)


def test_paired_test_mean_diff_and_pairs():
    test = paired_test(_payload(), "joint", "joint-no-feedback")
    assert test.n_pairs == 3
    # diffs: (10-4), (6-4), (8-4) -> mean 4.0
    assert test.mean_diff == pytest.approx(4.0)
    assert test.exact
    assert 0.0 < test.p_value <= 0.5


def test_paired_test_requires_three_pairs():
    payload = _payload()
    payload["seeds"] = payload["seeds"][:2]
    with pytest.raises(ValueError, match=">= 3"):
        paired_test(payload, "joint", "joint-no-feedback")


def test_render_report_has_arms_and_paired_line():
    report = render_report(_payload())
    assert "joint-no-feedback" in report
    assert "unique" in report  # dedup column
    assert "7.00" in report  # joint mean unique cells
    assert "baseline" in report
    assert "paired joint vs joint-no-feedback" in report
    assert "Δ=+4.00" in report


def test_csv_roundtrip_and_load(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    (results / "sut-x.json").write_text(json.dumps(_payload()))
    (results / "broken.json").write_text("{not json")

    payloads = load_results(results)
    assert list(payloads) == ["sut-x"]  # broken file skipped

    csv_path = results / "per_seed.csv"
    write_per_seed_csv(payloads, csv_path)
    rows = csv_path.read_text().splitlines()
    assert rows[0] == "sut,seed,arm,metric,value"
    assert "sut-x,0,joint,divergent_cells,10" in rows
    assert "sut-x,0,joint,unique_cells,8" in rows
    assert "sut-x,0,baseline,findings,40" in rows
    # None first-divergence omitted
    assert not any(",first_divergence_iteration," in r and r.endswith(",") for r in rows)


def test_main_writes_table_and_csv(tmp_path, capsys):
    results = tmp_path / "results"
    results.mkdir()
    (results / "sut-x.json").write_text(json.dumps(_payload()))

    rc = main([str(results)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "== sut-x ==" in out
    assert "wrote" in out
    assert (results / "per_seed.csv").is_file()


def test_main_empty_dir_fails(tmp_path, capsys):
    rc = main([str(tmp_path / "missing")])
    assert rc == 1
    assert "no results" in capsys.readouterr().err
