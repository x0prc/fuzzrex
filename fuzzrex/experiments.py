"""Phase 1 comparison harness: joint Config×API search vs per-cell baseline.

Runs both arms under matched seeds on one SUT and returns a
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
from fuzzrex.oracle import run_joint_search
from fuzzrex.orchestrator import DockerComposeOrchestrator


@dataclass
class SeedResult:
    seed: int
    joint_divergent_cells: int
    joint_kinds: dict[str, int]
    baseline_findings: int
    baseline_per_cell: list[int]
    baseline_signatures: list[str] = field(default_factory=list)


@dataclass
class ComparisonResult:
    """Aggregate over seeds for one SUT."""

    name: str
    seeds: list[SeedResult] = field(default_factory=list)

    @property
    def mean_joint_cells(self) -> float:
        if not self.seeds:
            return 0.0
        return sum(s.joint_divergent_cells for s in self.seeds) / len(self.seeds)

    @property
    def total_joint_kinds(self) -> dict[str, int]:
        kinds: Counter[str] = Counter()
        for seed in self.seeds:
            kinds.update(seed.joint_kinds)
        return dict(kinds)

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
        return {
            "name": self.name,
            "mean_joint_divergent_cells": self.mean_joint_cells,
            "joint_kinds": self.total_joint_kinds,
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
    on_seed: Callable[[SeedResult], None] | None = None,
) -> ComparisonResult:
    """Run both arms per seed against the same SUT.

    Joint arm: `run_joint_search` from `baseline_config`. Baseline arm:
    Schemathesis once per config cell in `cells` (the static grid the
    joint search is free to navigate).
    """
    sequence = ApiFuzzer(spec_path, base_url=orchestrator.base_url).plan()
    result = ComparisonResult(name=name)

    for seed in seeds:
        joint = run_joint_search(
            orchestrator,
            baseline_config,
            sequence,
            iterations=joint_iterations,
            seed=seed,
            timeout=timeout,
            enums=enums,
        )
        kinds: Counter[str] = Counter(
            divergence.kind for cell in joint for divergence in cell.divergences
        )

        baseline = run_baseline_matrix(
            orchestrator,
            cells,
            spec_path,
            seed=seed,
            max_examples=baseline_max_examples,
            timeout=max(timeout, 120.0),
        )

        signatures = sorted(
            {
                f"{finding.title} ({', '.join(finding.operations)})"
                for run in baseline
                for finding in run.findings
            }
        )

        seed_result = SeedResult(
            seed=seed,
            joint_divergent_cells=len(joint),
            joint_kinds=dict(kinds),
            baseline_findings=sum(run.total for run in baseline),
            baseline_per_cell=[run.total for run in baseline],
            baseline_signatures=signatures,
        )
        result.seeds.append(seed_result)
        if on_seed:
            on_seed(seed_result)

    return result
