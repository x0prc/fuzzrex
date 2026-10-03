"""Analysis pipeline: campaign JSON -> summary table, significance, CSV.

Stdlib-only (exact paired sign-flip test instead of scipy). Run as
`python -m fuzzrex.analysis findings/phase1` or import `load_results`
and friends for notebooks.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ARM_METRICS = (
    "divergent_cells",
    "first_divergence_iteration",
    "first_divergence_s",
    "cells_visited",
    "cells_unhealthy",
    "elapsed_s",
)


@dataclass(frozen=True)
class ArmSummary:
    arm: str
    n: int
    mean_cells: float
    std_cells: float
    n_found: int
    mean_first_iteration: float | None
    mean_unhealthy: float
    mean_elapsed: float


@dataclass(frozen=True)
class PairedTest:
    arm_a: str
    arm_b: str
    metric: str
    n_pairs: int
    mean_diff: float
    p_value: float
    exact: bool


def load_results(results_dir: str | Path) -> dict[str, dict[str, Any]]:
    """Load every <name>.json campaign result; skip unreadable files."""
    payloads: dict[str, dict[str, Any]] = {}
    directory = Path(results_dir)
    if not directory.is_dir():
        return payloads
    for path in sorted(directory.glob("*.json")):
        try:
            payloads[path.stem] = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: skipping {path.name}: {exc}", file=sys.stderr)
    return payloads


def summarize_arm(payload: dict[str, Any], arm: str) -> ArmSummary:
    rows = [s["arms"][arm] for s in payload["seeds"] if arm in s.get("arms", {})]
    if not rows:
        raise ValueError(f"arm {arm!r} not present in {payload.get('name')!r}")
    cells = [r["divergent_cells"] for r in rows]
    firsts = [r["first_divergence_iteration"] for r in rows]
    found = [f for f in firsts if f is not None]
    return ArmSummary(
        arm=arm,
        n=len(rows),
        mean_cells=statistics.fmean(cells),
        std_cells=statistics.stdev(cells) if len(cells) > 1 else 0.0,
        n_found=len(found),
        mean_first_iteration=statistics.fmean(found) if found else None,
        mean_unhealthy=statistics.fmean(r["cells_unhealthy"] for r in rows),
        mean_elapsed=statistics.fmean(r["elapsed_s"] for r in rows),
    )


def sign_flip_pvalue(diffs: Sequence[float], *, max_exact: int = 20) -> tuple[float, bool]:
    """Two-sided paired permutation test on mean difference.

    Exact enumeration of sign assignments up to `max_exact` pairs,
    Monte Carlo afterwards (fixed seed for reproducibility).
    """
    non_zero = [d for d in diffs if d != 0]
    if not non_zero:
        return 1.0, True
    observed = abs(sum(non_zero))
    n = len(non_zero)
    if n <= max_exact:
        count = 0
        for mask in range(2**n):
            total = sum(d if mask >> i & 1 else -d for i, d in enumerate(non_zero))
            if abs(total) >= observed:
                count += 1
        return count / 2**n, True

    rng = random.Random(0)
    draws = 100_000
    count = 0
    for _ in range(draws):
        total = sum(d if rng.random() < 0.5 else -d for d in non_zero)
        if abs(total) >= observed:
            count += 1
    return (count + 1) / (draws + 1), False


def paired_test(
    payload: dict[str, Any], arm_a: str, arm_b: str, metric: str = "divergent_cells"
) -> PairedTest:
    """Paired (matched-seed) comparison of `metric` between two arms."""
    by_arm: dict[str, dict[int, float]] = {arm_a: {}, arm_b: {}}
    for seed in payload["seeds"]:
        for arm in by_arm:
            value = seed.get("arms", {}).get(arm, {}).get(metric)
            if value is not None:
                by_arm[arm][seed["seed"]] = value
    shared = sorted(set(by_arm[arm_a]) & set(by_arm[arm_b]))
    if len(shared) < 3:
        raise ValueError(f"need >= 3 matched seeds for {arm_a} vs {arm_b}, got {len(shared)}")
    diffs = [by_arm[arm_a][s] - by_arm[arm_b][s] for s in shared]
    p_value, exact = sign_flip_pvalue(diffs)
    return PairedTest(
        arm_a=arm_a,
        arm_b=arm_b,
        metric=metric,
        n_pairs=len(shared),
        mean_diff=statistics.fmean(diffs),
        p_value=p_value,
        exact=exact,
    )


def render_report(payload: dict[str, Any]) -> str:
    name = payload.get("name", "?")
    budget = payload.get("budget", {})
    arms = sorted({arm for s in payload.get("seeds", []) for arm in s.get("arms", {})})
    summaries = [summarize_arm(payload, arm) for arm in arms]

    lines = [
        f"== {name} ==  ({budget.get('seeds', '?')} seeds x "
        f"{budget.get('joint_iterations', '?')} iterations, "
        f"grid {budget.get('grid_cells', '?')} cells)",
        f"{'arm':<24} {'cells/seed':>16} {'found':>7} {'first-div':>10} "
        f"{'unhealthy':>10} {'sec/seed':>9}",
    ]
    for s in summaries:
        first = f"{s.mean_first_iteration:.1f}" if s.mean_first_iteration is not None else "-"
        lines.append(
            f"{s.arm:<24} {s.mean_cells:>10.2f} ±{s.std_cells:>4.2f} "
            f"{s.n_found:>3}/{s.n:<3} {first:>10} {s.mean_unhealthy:>10.1f} {s.mean_elapsed:>9.1f}"
        )
    if payload.get("seeds") and any("baseline_findings" in s for s in payload["seeds"]):
        lines.append(
            f"{'baseline':<24} {payload.get('mean_baseline_findings', 0):>13.2f} findings/seed, "
            f"{payload.get('baseline_unique_findings', 0)} unique"
        )

    if "joint" in arms and "joint-no-feedback" in arms:
        test = paired_test(payload, "joint", "joint-no-feedback")
        method = "exact" if test.exact else "monte-carlo"
        lines.append(
            f"paired {test.arm_a} vs {test.arm_b} ({test.metric}): "
            f"Δ={test.mean_diff:+.2f}, p={test.p_value:.4f} "
            f"({method} sign-flip, n={test.n_pairs})"
        )
    return "\n".join(lines)


def write_per_seed_csv(payloads: dict[str, dict[str, Any]], path: str | Path) -> None:
    """Long-format rows: sut, seed, arm, metric, value (plotting-friendly)."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sut", "seed", "arm", "metric", "value"])
        for sut, payload in sorted(payloads.items()):
            for seed in payload.get("seeds", []):
                for arm, stats in seed.get("arms", {}).items():
                    for metric in ARM_METRICS:
                        value = stats.get(metric)
                        if value is not None:
                            writer.writerow([sut, seed["seed"], arm, metric, value])
                if "baseline_findings" in seed:
                    writer.writerow([sut, seed["seed"], "baseline", "findings",
                                     seed["baseline_findings"]])


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fuzzrex.analysis",
        description="Summarize campaign JSONs: table, paired sign-flip test, CSV.",
    )
    parser.add_argument("results_dir", nargs="?", default="findings/phase1")
    parser.add_argument("--csv", default=None, help="CSV output path (default: <dir>/per_seed.csv)")
    parser.add_argument("--no-csv", action="store_true", help="skip CSV export")
    args = parser.parse_args(argv)

    payloads = load_results(args.results_dir)
    if not payloads:
        print(f"no results found in {args.results_dir}", file=sys.stderr)
        return 1

    for name in sorted(payloads):
        print(render_report(payloads[name]))
        print()

    if not args.no_csv:
        csv_path = Path(args.csv) if args.csv else Path(args.results_dir) / "per_seed.csv"
        write_per_seed_csv(payloads, csv_path)
        print(f"wrote {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
