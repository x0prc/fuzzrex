"""Checkpointed campaign runner with the full search feature surface.

Runs a multi-seed comparison against any docker-compose SUT from the
command line, checkpointing after every seed; re-running skips
completed seeds (crash-safe resume). Phase 1's archived protocol stays
in examples/phase1_campaign.py untouched -- this runner is for new
campaigns that use the stall window, request-side mutation, or
per-seed plan variety.

Cells file: either an explicit list of config documents, or a domains
object {key: [values]} expanded with config_grid (which then also
supplies the default enum constraints for mutation; --enums overrides).

Usage:
  fuzzrex-campaign --compose examples/crapi/compose.yml --service crapi-identity \
      --config examples/crapi/.env --base-url http://127.0.0.1:8080 \
      --health-path /identity/health_check --reload recreate \
      --spec examples/crapi/openapi.yml --baseline-config baseline.json \
      --cells knobs.json --out findings/phase2/crapi.json \
      --stall 8 --request-mutation 0.2 --plan-mutations 2
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from fuzzrex.experiments import (
    DEFAULT_ARMS,
    ArmStats,
    ComparisonResult,
    JointArm,
    SeedResult,
    config_grid,
    run_comparison,
)
from fuzzrex.orchestrator import DockerComposeOrchestrator, OrchestratorError
from fuzzrex.schema import load_document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzzrex-campaign",
        description="Checkpointed multi-seed Config x API comparison campaign.",
    )
    sut = parser.add_argument_group("SUT")
    sut.add_argument("--compose", required=True, type=Path, help="docker-compose file")
    sut.add_argument("--service", required=True, help="service to mutate and health-check")
    sut.add_argument("--config", required=True, type=Path, help="config file the service reads")
    sut.add_argument("--base-url", required=True, help="base URL the spec probes")
    sut.add_argument("--health-path", default="/health", help="health endpoint path")
    sut.add_argument(
        "--reload",
        choices=("restart", "recreate"),
        default="restart",
        help="how config cells take effect (default: restart)",
    )

    search = parser.add_argument_group("search")
    search.add_argument("--spec", required=True, type=Path, help="OpenAPI spec (JSON or YAML)")
    search.add_argument(
        "--baseline-config", required=True, type=Path, help="baseline cell (JSON/YAML/INI)"
    )
    search.add_argument(
        "--cells",
        required=True,
        type=Path,
        help="config grid: list of configs, or domains {key: [values]}",
    )
    search.add_argument(
        "--enums", type=Path, help="enum constraints for mutation (default: domains from --cells)"
    )
    search.add_argument(
        "--arms",
        default=",".join(arm.name for arm in DEFAULT_ARMS),
        help="comma-separated arm names (default: all)",
    )
    search.add_argument("--no-baseline", action="store_true", help="skip the baseline arm")
    search.add_argument(
        "--stall", type=int, default=None, help="stop a seed after k dry iterations"
    )
    search.add_argument(
        "--request-mutation", type=float, default=0.0, help="per-iteration request mutation p"
    )
    search.add_argument("--plan-mutations", type=int, default=0, help="per-seed plan variety k")

    budget = parser.add_argument_group("budget")
    budget.add_argument("--seeds", type=int, default=10, help="seed count (0..N-1)")
    budget.add_argument("--iterations", type=int, default=30, help="joint iterations per seed")
    budget.add_argument(
        "--baseline-max-examples", type=int, default=5, help="examples per grid cell"
    )
    budget.add_argument("--timeout", type=float, default=60.0, help="per-request timeout")

    output = parser.add_argument_group("output")
    output.add_argument("--name", help="campaign name (default: service)")
    output.add_argument(
        "--out",
        type=Path,
        help="checkpoint JSON (default: findings/campaigns/<name>.json)",
    )
    return parser


def _load_cells(path: Path) -> tuple[list[dict], dict[str, Any] | None]:
    data = load_document(path)
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict):
        return config_grid(data), data
    raise SystemExit(f"--cells must be a list of configs or a domains object: {path}")


def _resolve_arms(names: str) -> tuple[JointArm, ...]:
    known = {arm.name: arm for arm in DEFAULT_ARMS}
    requested = [name.strip() for name in names.split(",") if name.strip()]
    unknown = [name for name in requested if name not in known]
    if not requested or unknown:
        raise SystemExit(f"unknown arms {unknown or requested!r}; choose from {sorted(known)}")
    return tuple(known[name] for name in requested)


def _seed_from_dict(data: dict) -> SeedResult:
    arms = {}
    for name, stats in data["arms"].items():
        if "unique_cells" not in stats:
            raise ValueError(
                f"checkpoint for {data.get('seed')!r}/{name} predates unique_cells; "
                "delete it and rerun (mixed metrics would corrupt the table)"
            )
        arms[name] = ArmStats(**stats)
    return SeedResult(
        seed=data["seed"],
        arms=arms,
        baseline_findings=data["baseline_findings"],
        baseline_per_cell=data["baseline_per_cell"],
        baseline_signatures=data["baseline_signatures"],
    )


def _write_checkpoint(path: Path, result: ComparisonResult, budget: dict) -> None:
    payload = result.to_dict()
    payload["budget"] = budget
    path.write_text(json.dumps(payload, indent=2))


def run(args: argparse.Namespace) -> int:
    baseline = load_document(args.baseline_config)
    cells, domains = _load_cells(args.cells)
    enums = load_document(args.enums) if args.enums else domains
    arms = _resolve_arms(args.arms)
    name = args.name or args.service
    out = args.out or Path("findings") / "campaigns" / f"{name}.json"

    budget = {
        "seeds": list(range(args.seeds)),
        "joint_iterations": args.iterations,
        "baseline_max_examples": args.baseline_max_examples,
        "grid_cells": len(cells),
        "arms": [arm.name for arm in arms],
        "stall_window": args.stall,
        "request_mutation": args.request_mutation,
        "plan_mutations": args.plan_mutations,
    }
    started = time.time()
    result = ComparisonResult(name=name)
    if out.is_file():
        previous = json.loads(out.read_text())
        done = {s["seed"] for s in previous.get("seeds", [])}
        result.seeds = [_seed_from_dict(s) for s in previous.get("seeds", [])]
        print(f"resuming: {sorted(done)} already done", flush=True)
    else:
        done = set()

    remaining = [s for s in range(args.seeds) if s not in done]
    if not remaining:
        print("nothing left to do", flush=True)
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)

    orch = DockerComposeOrchestrator(
        args.compose,
        args.service,
        args.config,
        args.base_url,
        health_path=args.health_path,
        reload=args.reload,
    )
    orch.up()
    try:
        for seed in remaining:
            partial = run_comparison(
                orch,
                baseline,
                str(args.spec),
                cells,
                name=name,
                seeds=(seed,),
                joint_iterations=args.iterations,
                baseline_max_examples=args.baseline_max_examples,
                enums=enums,
                arms=arms,
                run_baseline=not args.no_baseline,
                timeout=args.timeout,
                stall_window=args.stall,
                request_mutation=args.request_mutation,
                plan_mutations=args.plan_mutations,
            )
            result.seeds.extend(partial.seeds)
            budget["elapsed_s"] = round(time.time() - started, 1)
            _write_checkpoint(out, result, budget)
            seed_result = partial.seeds[0]
            parts = [
                f"{arm}={stats.divergent_cells} probes/{stats.unique_cells} unique "
                f"(first@{stats.first_divergence_iteration}, "
                f"visited={stats.cells_visited}, bad={stats.cells_unhealthy}"
                + (", stopped" if stats.stopped_early else "")
                + (f", req@{stats.request_iterations}" if stats.request_iterations else "")
                + ")"
                for arm, stats in seed_result.arms.items()
            ]
            print(
                f"  seed {seed_result.seed}: " + " | ".join(parts)
                + f" | baseline={seed_result.baseline_findings}",
                flush=True,
            )
    except OrchestratorError as exc:
        budget["elapsed_s"] = round(time.time() - started, 1)
        _write_checkpoint(out, result, budget)
        print(f"stopping: {exc}\n(checkpoint kept: {len(result.seeds)} seeds)", flush=True)
        return 1
    finally:
        try:
            orch.restore()
        except OrchestratorError as exc:
            print(f"warning: restore failed: {exc}", flush=True)

    budget["elapsed_s"] = round(time.time() - started, 1)
    _write_checkpoint(out, result, budget)
    print(f"\n== {name} ==", flush=True)
    payload = result.to_dict()
    for arm, stats in payload["arms"].items():
        print(
            f"  {arm}: {stats['mean_divergent_cells']:.1f} probes, "
            f"{stats['mean_unique_cells']:.1f} unique cells/seed, "
            f"kinds={stats['kinds']} "
            f"first-divergence@iter={stats['mean_first_divergence_iteration']}",
            flush=True,
        )
    print(
        f"  baseline: {payload['mean_baseline_findings']:.1f} findings/seed, "
        f"{payload['baseline_unique_findings']} unique",
        flush=True,
    )
    print(f"  wrote {out} ({budget['elapsed_s']}s)", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
