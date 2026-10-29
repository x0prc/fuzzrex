"""Discover a pruned spec and observable config knobs for a live SUT.

Wraps fuzzrex.discover's two probe passes as a CI-runnable command: the
SUT runs the baseline cell, `prune_spec` keeps only the operations the
deployment serves, and `filter_knobs` keeps only candidate keys whose
values change an HTTP response. Outputs are exactly what a
fuzzrex-campaign dispatch consumes (--spec and --enums), so onboarding
a new SUT is: spec + candidate domains in, pruned fixtures out.
Endpoint relevance to config gates stays fixture work.

Usage:
  fuzzrex-discover --compose examples/crapi/compose.yml --service crapi-identity \
      --config examples/crapi/.env --base-url http://127.0.0.1:8080 \
      --health-path /identity/health_check --reload recreate \
      --spec examples/crapi/openapi.yml --baseline-config examples/crapi/baseline.json \
      --cells examples/crapi/cells.json \
      --out-spec examples/crapi/openapi.discovered.yml \
      --out-enums examples/crapi/enums.discovered.yml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from fuzzrex.api_fuzzer import HTTP_METHODS, ApiFuzzer
from fuzzrex.campaign import _load_cells, add_sut_arguments
from fuzzrex.discover import DEFAULT_DROP_STATUSES, filter_knobs, prune_spec
from fuzzrex.orchestrator import DockerComposeOrchestrator, OrchestratorError
from fuzzrex.schema import load_document


def _parse_statuses(text: str) -> frozenset[int]:
    try:
        statuses = frozenset(int(part.strip()) for part in text.split(",") if part.strip())
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid status list: {text!r}") from None
    if not statuses:
        raise argparse.ArgumentTypeError("--drop-statuses cannot be empty")
    return statuses


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzzrex-discover",
        description="Discover a pruned spec and observable config knobs on a live SUT.",
    )
    add_sut_arguments(parser)

    source = parser.add_argument_group("discovery")
    source.add_argument("--spec", required=True, type=Path, help="OpenAPI spec (JSON or YAML)")
    source.add_argument(
        "--baseline-config", required=True, type=Path, help="baseline cell (JSON/YAML/INI)"
    )
    source.add_argument(
        "--cells",
        required=True,
        type=Path,
        help="config grid: list of configs, or domains {key: [values]} supplying the "
        "candidate knobs (dotted keys nest into the baseline document)",
    )
    source.add_argument(
        "--enums", type=Path, help="candidate knobs override (default: domains from --cells)"
    )
    source.add_argument(
        "--only",
        choices=("both", "prune", "knobs"),
        default="both",
        help="which pass to run (default: both; prune writes --out-spec, knobs replays "
        "the pruned plan and writes --out-enums)",
    )
    source.add_argument(
        "--drop-statuses",
        type=_parse_statuses,
        default=DEFAULT_DROP_STATUSES,
        help="statuses meaning 'not served', comma-separated (default: 404,501)",
    )
    source.add_argument("--timeout", type=float, default=60.0, help="per-request timeout")

    output = parser.add_argument_group("output")
    output.add_argument("--out-spec", type=Path, help="pruned spec (required unless --only knobs)")
    output.add_argument(
        "--out-enums", type=Path, help="filtered knobs (required unless --only prune)"
    )
    return parser


def run(args: argparse.Namespace) -> int:
    if args.only != "knobs" and args.out_spec is None:
        raise SystemExit("--out-spec is required unless --only knobs")
    if args.only != "prune" and args.out_enums is None:
        raise SystemExit("--out-enums is required unless --only prune")
    for out in (args.out_spec, args.out_enums):
        for source in (args.spec, args.baseline_config, args.cells, args.enums):
            if out is not None and source is not None and out.resolve() == source.resolve():
                raise SystemExit(f"refusing to overwrite input file: {out}")

    baseline = load_document(args.baseline_config)
    enums = None
    if args.only != "prune":
        enums = load_document(args.enums) if args.enums else _load_cells(args.cells, baseline)[1]
        if enums is None:
            raise SystemExit(
                "--cells is a list of configs with no per-key candidates: "
                "pass --enums, or --only prune"
            )

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
        if args.only in ("both", "prune"):
            pruned = prune_spec(
                orch, args.spec, timeout=args.timeout, drop_statuses=args.drop_statuses
            )
            _write_document(args.out_spec, pruned)
            print(
                f"prune: {_count_operations(pruned)}/{_count_operations(load_document(args.spec))}"
                f" operations kept -> {args.out_spec}",
                flush=True,
            )
        if args.only in ("both", "knobs"):
            plan_spec = args.out_spec if args.only == "both" else args.spec
            fuzzer = ApiFuzzer(str(plan_spec), base_url=orch.base_url, timeout=args.timeout)
            sequence = fuzzer.plan()
            kept = filter_knobs(orch, baseline, enums, sequence, timeout=args.timeout)
            if not kept:
                print("warning: no candidate knob changed a response", file=sys.stderr, flush=True)
            _write_document(args.out_enums, kept)
            print(
                f"knobs: {len(kept)}/{len(enums)} candidate keys observable -> {args.out_enums}",
                flush=True,
            )
    except OrchestratorError as exc:
        print(f"stopping: {exc}", flush=True)
        return 1
    finally:
        try:
            orch.restore()
        except OrchestratorError as exc:
            print(f"warning: restore failed: {exc}", flush=True)
    return 0


def _count_operations(spec: Any) -> int:
    return sum(
        1
        for item in spec.get("paths", {}).values()
        if isinstance(item, dict)
        for method in item
        if method.lower() in HTTP_METHODS
    )


def _write_document(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".json":
        path.write_text(json.dumps(data, indent=2) + "\n")
    else:
        path.write_text(yaml.safe_dump(data, sort_keys=False))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
