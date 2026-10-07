"""Phase 1 comparison harness: joint Config×API search vs per-cell baseline.

Runs all evaluation arms under matched seeds on one SUT and returns a
JSON-serializable summary suitable for the results table.
"""

from __future__ import annotations

import itertools
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from fuzzrex.api_fuzzer import ApiFuzzer
from fuzzrex.baseline import run_baseline_matrix
from fuzzrex.oracle import run_joint_search_traced
from fuzzrex.orchestrator import DockerComposeOrchestrator


@dataclass(frozen=True)
class JointArm:
    """One joint-search arm: named, with the feedback loop on or off."""

    name: str
    feedback: bool = True


DEFAULT_ARMS = (JointArm("joint"), JointArm("joint-no-feedback", feedback=False))


@dataclass
class ArmStats:
    divergent_cells: int
    unique_cells: int
    kinds: dict[str, int]
    cells_visited: int
    cells_unhealthy: int
    first_divergence_iteration: int | None
    first_divergence_s: float | None
    elapsed_s: float


@dataclass
class SeedResult:
    seed: int
    arms: dict[str, ArmStats] = field(default_factory=dict)
    baseline_findings: int = 0
    baseline_per_cell: list[int] = field(default_factory=list)
    baseline_signatures: list[str] = field(default_factory=list)


@dataclass
class ComparisonResult:
    """Aggregate over seeds for one SUT."""

    name: str
    seeds: list[SeedResult] = field(default_factory=list)

    def mean_cells(self, arm: str) -> float:
        values = [s.arms[arm].divergent_cells for s in self.seeds if arm in s.arms]
        return sum(values) / len(values) if values else 0.0

    def mean_unique_cells(self, arm: str) -> float:
        values = [s.arms[arm].unique_cells for s in self.seeds if arm in s.arms]
        return sum(values) / len(values) if values else 0.0

    def total_kinds(self, arm: str) -> dict[str, int]:
        kinds: Counter[str] = Counter()
        for seed in self.seeds:
            if arm in seed.arms:
                kinds.update(seed.arms[arm].kinds)
        return dict(kinds)

    def mean_first_divergence_iteration(self, arm: str) -> float | None:
        values = [
            s.arms[arm].first_divergence_iteration
            for s in self.seeds
            if arm in s.arms and s.arms[arm].first_divergence_iteration is not None
        ]
        return sum(values) / len(values) if values else None

    @property
    def mean_baseline_findings(self) -> float:
        if not self.seeds:
            return 0.0
        return sum(s.baseline_findings for s in self.seeds) / len(self.seeds)

    @property
    def baseline_unique_signatures(self) -> list[str]:
        signatures: set[str] = set()
        for seed in self.seeds:
            signatures.update(seed.baseline_signatures)
        return sorted(signatures)

    def to_dict(self) -> dict[str, Any]:
        arm_names = sorted({name for s in self.seeds for name in s.arms})
        return {
            "name": self.name,
            "arms": {
                arm: {
                    "mean_divergent_cells": self.mean_cells(arm),
                    "mean_unique_cells": self.mean_unique_cells(arm),
                    "kinds": self.total_kinds(arm),
                    "mean_first_divergence_iteration": (
                        self.mean_first_divergence_iteration(arm)
                    ),
                }
                for arm in arm_names
            },
            "mean_baseline_findings": self.mean_baseline_findings,
            "baseline_unique_findings": len(self.baseline_unique_signatures),
            "baseline_signatures": self.baseline_unique_signatures,
            "seeds": [asdict(s) for s in self.seeds],
        }


def config_grid(domains: dict[str, Sequence[Any]]) -> list[dict[str, Any]]:
    """Cartesian product of flat config domains -> list of config dicts."""
    keys = list(domains)
    return [
        dict(zip(keys, combo, strict=True))
        for combo in itertools.product(*(domains[k] for k in keys))
    ]


def run_comparison(
    orchestrator: DockerComposeOrchestrator,
    baseline_config: Any,
    spec_path: str,
    cells: Sequence[Any],
    *,
    name: str = "sut",
    seeds: Sequence[int] = (0, 1, 2),
    joint_iterations: int = 8,
    baseline_max_examples: int = 5,
    enums: dict[str, Any] | None = None,
    timeout: float = 60.0,
    arms: Sequence[JointArm] = DEFAULT_ARMS,
    run_baseline: bool = True,
    on_seed: Callable[[SeedResult], None] | None = None,
) -> ComparisonResult:
    """Run every arm per seed against the same SUT.

    Joint arms: `run_joint_search_traced` from `baseline_config`, each
    with its feedback setting. Baseline arm: Schemathesis once per
    config cell in `cells` (the static grid the joint search is free
    to navigate); skipped when `run_baseline` is false.
    """
    sequence = ApiFuzzer(spec_path, base_url=orchestrator.base_url).plan()
    result = ComparisonResult(name=name)

    for seed in seeds:
        seed_result = SeedResult(seed=seed)

        for arm in arms:
            trace = run_joint_search_traced(
                orchestrator,
                baseline_config,
                sequence,
                iterations=joint_iterations,
                seed=seed,
                timeout=timeout,
                enums=enums,
                feedback=arm.feedback,
            )
            kinds: Counter[str] = Counter(
                divergence.kind
                for cell in trace.divergent_cells
                for divergence in cell.divergences
            )
            seed_result.arms[arm.name] = ArmStats(
                divergent_cells=len(trace.divergent_cells),
                unique_cells=trace.unique_cells,
                kinds=dict(kinds),
                cells_visited=trace.cells_visited,
                cells_unhealthy=trace.cells_unhealthy,
                first_divergence_iteration=trace.first_divergence_iteration,
                first_divergence_s=trace.first_divergence_s,
                elapsed_s=trace.elapsed_s,
            )

        if run_baseline:
            baseline = run_baseline_matrix(
                orchestrator,
                cells,
                spec_path,
                seed=seed,
                max_examples=baseline_max_examples,
                timeout=max(timeout, 120.0),
            )
            seed_result.baseline_findings = sum(run.total for run in baseline)
            seed_result.baseline_per_cell = [run.total for run in baseline]
            seed_result.baseline_signatures = sorted(
                {
                    f"{finding.title} ({', '.join(finding.operations)})"
                    for run in baseline
                    for finding in run.findings
                }
            )

        result.seeds.append(seed_result)
        if on_seed:
            on_seed(seed_result)

    return result
