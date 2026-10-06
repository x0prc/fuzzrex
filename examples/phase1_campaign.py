"""Phase 1 campaign: joint / joint-no-feedback / baseline, matched seeds.

Reproduces the results table: 10 seeds x 30 iterations, three arms,
per-seed checkpointing into findings/phase1/<sut>.json. Re-running
skips seeds already present (crash-safe resume).

Usage: python examples/phase1_campaign.py dvwa|grafana
"""

import json
import sys
import time
from pathlib import Path

from fuzzrex.experiments import ArmStats, ComparisonResult, SeedResult, config_grid, run_comparison
from fuzzrex.orchestrator import DockerComposeOrchestrator, OrchestratorError

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "findings" / "phase1"
OUT.mkdir(parents=True, exist_ok=True)

DVWA_LEVELS = ["low", "medium", "high", "impossible"]
SEEDS = tuple(range(10))
JOINT_ITERATIONS = 30


def _seed_from_dict(data: dict) -> SeedResult:
    return SeedResult(
        seed=data["seed"],
        arms={name: ArmStats(**stats) for name, stats in data["arms"].items()},
        baseline_findings=data["baseline_findings"],
        baseline_per_cell=data["baseline_per_cell"],
        baseline_signatures=data["baseline_signatures"],
    )


def _write_checkpoint(path: Path, result: ComparisonResult, budget: dict) -> None:
    payload = result.to_dict()
    payload["budget"] = budget
    path.write_text(json.dumps(payload, indent=2))


def main(target: str) -> None:
    if target == "dvwa":
        orch = DockerComposeOrchestrator(
            REPO / "examples/dvwa/compose.yml",
            "dvwa",
            REPO / "examples/dvwa/matrix.json",
            "http://127.0.0.1:4280",
            health_path="/login.php",
        )
        baseline = {"disable_authentication": False, "default_security_level": "low"}
        cells = config_grid(
            {"disable_authentication": [False, True], "default_security_level": DVWA_LEVELS}
        )
        spec = str(REPO / "examples/dvwa/openapi.yml")
        enums = {"default_security_level": DVWA_LEVELS}
    else:
        orch = DockerComposeOrchestrator(
            REPO / "examples/grafana/compose.yml",
            "grafana",
            REPO / "examples/grafana/grafana.ini",
            "http://127.0.0.1:3000",
            health_path="/api/health",
        )
        baseline = {"auth.anonymous": {"enabled": False}}
        cells = [
            {"auth.anonymous": {"enabled": False}},
            {"auth.anonymous": {"enabled": True}},
        ]
        spec = str(REPO / "examples/grafana/openapi.yml")
        enums = {"enabled": [False, True]}

    path = OUT / f"{target}.json"
    budget = {
        "seeds": list(SEEDS),
        "joint_iterations": JOINT_ITERATIONS,
        "baseline_max_examples": 5,
        "grid_cells": len(cells),
    }
    started = time.time()

    result = ComparisonResult(name=target)
    if path.is_file():
        previous = json.loads(path.read_text())
        done = {s["seed"] for s in previous.get("seeds", [])}
        result.seeds = [_seed_from_dict(s) for s in previous.get("seeds", [])]
        print(f"resuming: {sorted(done)} already done", flush=True)
    else:
        done = set()

    remaining = [s for s in SEEDS if s not in done]
    if not remaining:
        print("nothing left to do", flush=True)
        return

    orch.up()
    try:
        for seed in remaining:
            partial = run_comparison(
                orch,
                baseline,
                spec,
                cells,
                name=target,
                seeds=(seed,),
                joint_iterations=JOINT_ITERATIONS,
                baseline_max_examples=5,
                enums=enums,
            )
            result.seeds.extend(partial.seeds)
            budget["elapsed_s"] = round(time.time() - started, 1)
            _write_checkpoint(path, result, budget)
            seed_result = partial.seeds[0]
            parts = [
                f"{arm}={stats.divergent_cells} cells "
                f"(first@{stats.first_divergence_iteration}, "
                f"visited={stats.cells_visited}, bad={stats.cells_unhealthy})"
                for arm, stats in seed_result.arms.items()
            ]
            print(
                f"  seed {seed_result.seed}: " + " | ".join(parts)
                + f" | baseline={seed_result.baseline_findings}",
                flush=True,
            )
    except OrchestratorError as exc:
        budget["elapsed_s"] = round(time.time() - started, 1)
        _write_checkpoint(path, result, budget)
        print(f"stopping: {exc}\n(checkpoint kept: {len(result.seeds)} seeds)", flush=True)
        sys.exit(1)
    finally:
        try:
            orch.restore()
        except OrchestratorError as exc:
            print(f"warning: restore failed: {exc}", flush=True)

    budget["elapsed_s"] = round(time.time() - started, 1)
    _write_checkpoint(path, result, budget)
    print(f"\n== {target} ==", flush=True)
    payload = result.to_dict()
    for arm, stats in payload["arms"].items():
        print(f"  {arm}: {stats['mean_divergent_cells']:.1f} cells/seed "
              f"kinds={stats['kinds']} "
              f"first-divergence@iter={stats['mean_first_divergence_iteration']}",
              flush=True)
    print(f"  baseline: {payload['mean_baseline_findings']:.1f} findings/seed, "
          f"{payload['baseline_unique_findings']} unique", flush=True)
    print(f"  wrote {path} ({budget['elapsed_s']}s)", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("dvwa", "grafana"):
        raise SystemExit("usage: phase1_campaign.py dvwa|grafana")
    main(sys.argv[1])
