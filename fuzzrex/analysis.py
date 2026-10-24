"""Analysis pipeline: campaign JSON -> summary table, significance, interactions.

Stdlib-only (exact paired sign-flip test instead of scipy). Run as
`python -m fuzzrex.analysis findings/phase1` or import `load_results`
and friends for notebooks. When request-side mutation recorded per-visit
detail, divergent findings are classified into the Config x API
interaction taxonomy (config-only / interaction / request-sufficient /
...).
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ARM_METRICS = (
    "divergent_cells",
    "unique_cells",
    "first_divergence_iteration",
    "first_divergence_s",
    "cells_visited",
    "cells_unhealthy",
    "elapsed_s",
    "stopped_early",
    "request_iterations",
)


@dataclass(frozen=True)
class ArmSummary:
    arm: str
    n: int
    mean_cells: float
    std_cells: float
    mean_unique_cells: float
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
        mean_unique_cells=statistics.fmean(r["unique_cells"] for r in rows),
        n_found=len(found),
        mean_first_iteration=statistics.fmean(found) if found else None,
        mean_unhealthy=statistics.fmean(r["cells_unhealthy"] for r in rows),
        mean_elapsed=statistics.fmean(r["elapsed_s"] for r in rows),
    )


def _canonical(value: Any) -> str:
    """Canonical JSON, mirroring oracle.canonical_config/_variant_key."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def classify_findings(
    visits: Sequence[dict[str, Any]], variants: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    """Classify divergent visits into the Config x API interaction taxonomy.

    Each finding is one unique (config, patch) pair. Unpatched findings
    are `config_only`. Patched findings take the counterfactual context
    into account, most restrictive first:

    - config_reproducible: the original request also diverged at this
      config, so the config alone reproduces the finding;
    - request_sufficient: the patch already diverged against the
      original sequence at c0, so the request change alone suffices;
    - interaction: the patch diverges only under this config, is clean
      at c0, and the original request is clean while healthy here -
      both changes are required;
    - unclassified: missing counterfactual context (the config was never
      visited unpatched while healthy, or the variant's c0 record is
      missing).

    Also reports how many distinct patches were tried and how many
    already diverged at c0 (pure request-side findings).
    """
    variants_by_patch = {_canonical(v.get("patch")): v for v in variants}
    context: dict[str, dict[str, bool]] = {}
    for visit in visits:
        if visit.get("patch") or not visit.get("healthy", True):
            continue
        slot = context.setdefault(
            _canonical(visit.get("config")), {"divergent": False, "clean": False}
        )
        if visit.get("divergent"):
            slot["divergent"] = True
        else:
            slot["clean"] = True

    counts: Counter[str] = Counter()
    interactions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for visit in visits:
        if not visit.get("divergent"):
            continue
        patch = visit.get("patch") or {}
        key = f"{_canonical(visit.get('config'))}|{_canonical(patch)}"
        if key in seen:
            continue
        seen.add(key)
        if not patch:
            classification = "config_only"
        else:
            slot = context.get(_canonical(visit.get("config")), {})
            record = variants_by_patch.get(_canonical(patch))
            diverges_at_c0 = None if record is None else bool(record.get("diverges_at_c0"))
            if slot.get("divergent"):
                classification = "config_reproducible"
            elif diverges_at_c0 is True:
                classification = "request_sufficient"
            elif slot.get("clean") and diverges_at_c0 is False:
                classification = "interaction"
            else:
                classification = "unclassified"
        counts[classification] += 1
        if classification == "interaction":
            interactions.append(
                {"config": visit.get("config"), "patch": patch, "kinds": visit.get("kinds", [])}
            )
    return {
        "findings": dict(counts),
        "total_unique": sum(counts.values()),
        "patches_tried": len(variants),
        "patches_divergent_c0": sum(1 for v in variants if v.get("diverges_at_c0")),
        "interactions": interactions,
    }


def arm_interactions(payload: dict[str, Any], arm: str) -> dict[str, Any] | None:
    """Classification aggregated over seeds for one arm.

    Returns None when no seed recorded interaction detail (e.g. the
    archived Phase 1 checkpoints), so reports degrade cleanly.
    """
    totals: dict[str, Any] | None = None
    for seed in payload.get("seeds", []):
        seed_visits = seed.get("visits", {}).get(arm)
        if seed_visits is None:
            continue
        result = classify_findings(
            seed_visits, seed.get("request_variants", {}).get(arm, [])
        )
        if totals is None:
            totals = {
                "findings": Counter(),
                "patches_tried": 0,
                "patches_divergent_c0": 0,
                "interactions": [],
            }
        totals["findings"].update(result["findings"])
        totals["patches_tried"] += result["patches_tried"]
        totals["patches_divergent_c0"] += result["patches_divergent_c0"]
        totals["interactions"].extend(result["interactions"])
    if totals is None:
        return None
    totals["findings"] = dict(totals["findings"])
    totals["total_unique"] = sum(totals["findings"].values())
    # seeds are independent trials (counts sum), but the example case
    # studies are deduplicated so the report doesn't repeat them per seed
    seen_cases: set[str] = set()
    unique_cases = []
    for case in totals["interactions"]:
        key = _canonical(case)
        if key not in seen_cases:
            seen_cases.add(key)
            unique_cases.append(case)
    totals["interactions"] = unique_cases
    return totals


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
        f"{'arm':<24} {'cells/seed':>16} {'unique':>8} {'found':>7} {'first-div':>10} "
        f"{'unhealthy':>10} {'sec/seed':>9}",
    ]
    for s in summaries:
        first = f"{s.mean_first_iteration:.1f}" if s.mean_first_iteration is not None else "-"
        lines.append(
            f"{s.arm:<24} {s.mean_cells:>10.2f} ±{s.std_cells:>4.2f} "
            f"{s.mean_unique_cells:>8.2f} "
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

    usage = []
    for arm in arms:
        rows = [s["arms"][arm] for s in payload.get("seeds", []) if arm in s.get("arms", {})]
        req = sum(r.get("request_iterations", 0) for r in rows)
        stopped = sum(1 for r in rows if r.get("stopped_early"))
        if req or stopped:
            usage.append(f"{arm}: req-iters={req}, stopped={stopped}/{len(rows)} seeds")
    if usage:
        lines.append("feature usage: " + "; ".join(usage))

    detail = [(arm, arm_interactions(payload, arm)) for arm in arms]
    detail = [(arm, found) for arm, found in detail if found]
    if detail:
        lines.append("interaction classification (unique findings, summed over seeds):")
        for arm, found in detail:
            counts = found["findings"]
            lines.append(
                f"  {arm}: interaction={counts.get('interaction', 0)} "
                f"config-only={counts.get('config_only', 0)} "
                f"config-reproducible={counts.get('config_reproducible', 0)} "
                f"request-sufficient={counts.get('request_sufficient', 0)} "
                f"unclassified={counts.get('unclassified', 0)} "
                f"| c0-divergent patches {found['patches_divergent_c0']}"
                f"/{found['patches_tried']}"
            )
            for case in found["interactions"][:3]:
                lines.append(
                    "    interaction: " + json.dumps(case, default=str, sort_keys=True)
                )
    return "\n".join(lines)


def _seed_classification(seed: dict[str, Any], arm: str) -> dict[str, Any] | None:
    visits = seed.get("visits", {}).get(arm)
    if visits is None:
        return None
    return classify_findings(visits, seed.get("request_variants", {}).get(arm, []))


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
                        if value is None:
                            continue
                        if isinstance(value, bool):
                            value = int(value)
                        writer.writerow([sut, seed["seed"], arm, metric, value])
                    classified = _seed_classification(seed, arm)
                    if classified is not None:
                        for cls, count in sorted(classified["findings"].items()):
                            writer.writerow([sut, seed["seed"], arm, f"findings_{cls}", count])
                        writer.writerow(
                            [
                                sut,
                                seed["seed"],
                                arm,
                                "patches_divergent_c0",
                                classified["patches_divergent_c0"],
                            ]
                        )
                        writer.writerow(
                            [sut, seed["seed"], arm, "patches_tried", classified["patches_tried"]]
                        )
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
