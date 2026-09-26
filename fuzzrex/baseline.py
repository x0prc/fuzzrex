"""Baseline runner: replay an off-the-shelf API fuzzer (Schemathesis) under config cells.

This provides the comparison arm for Config x API fuzzing: run a
standard single-cell API fuzzer against each configuration cell of the
SUT and collect its findings in a comparable format.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fuzzrex.orchestrator import DockerComposeOrchestrator, configured_service

DEFAULT_CHECKS = "not_a_server_error,status_code_conformance,ignored_auth"
DEFAULT_MAX_EXAMPLES = 25
DEFAULT_TIMEOUT = 300.0


@dataclass(frozen=True)
class BaselineFinding:
    """A single issue group reported by the baseline fuzzer."""

    kind: str  # "failure" (failed check) or "error" (test crash)
    title: str
    count: int
    operations: tuple[str, ...] = ()


@dataclass(frozen=True)
class BaselineResult:
    """Findings from one baseline fuzzer run against one config cell."""

    config: Any
    findings: tuple[BaselineFinding, ...]
    generated: int
    exit_code: int

    @property
    def total(self) -> int:
        return sum(finding.count for finding in self.findings)


def find_schemathesis() -> str:
    """Locate the schemathesis executable; raise with an install hint if absent."""
    exe = shutil.which("schemathesis")
    if exe:
        return exe
    sibling = Path(sys.executable).with_name("schemathesis")
    if sibling.is_file():
        return str(sibling)
    raise RuntimeError(
        "schemathesis executable not found; install with: pip install 'fuzzrex[baseline]'",
    )


def parse_report(report: dict[str, Any]) -> tuple[tuple[BaselineFinding, ...], int, int]:
    """Extract (findings, generated, exit_code) from a schemathesis JSON report."""
    findings = [
        BaselineFinding(
            kind="failure",
            title=str(group.get("title", "")),
            count=int(group.get("count", 0)),
            operations=tuple(str(op) for op in group.get("operations") or ()),
        )
        for group in report.get("failures") or []
    ]
    findings.extend(
        BaselineFinding(
            kind="error",
            title=str(group.get("title", "")),
            count=int(group.get("count", 0)),
        )
        for group in report.get("errors") or []
    )
    test_cases = report.get("test_cases") or {}
    return tuple(findings), int(test_cases.get("generated", 0)), int(report.get("exit_code", 0))


def build_command(
    executable: str,
    spec_path: str | Path,
    base_url: str,
    report_path: str | Path,
    *,
    seed: int | None = None,
    max_examples: int = DEFAULT_MAX_EXAMPLES,
    checks: str = DEFAULT_CHECKS,
    headers: dict[str, str] | None = None,
) -> list[str]:
    command = [
        executable,
        "run",
        str(spec_path),
        "-u",
        base_url,
        "--phases",
        "fuzzing",
        "-n",
        str(max_examples),
        "--checks",
        checks,
        "--workers",
        "1",
        "--report",
        "json",
        "--report-json-path",
        str(report_path),
        "--no-color",
    ]
    if seed is not None:
        command += ["--seed", str(seed)]
    for key, value in (headers or {}).items():
        command += ["-H", f"{key}:{value}"]
    return command


def run_schemathesis(
    spec_path: str | Path,
    base_url: str,
    *,
    config: Any = None,
    seed: int | None = None,
    max_examples: int = DEFAULT_MAX_EXAMPLES,
    checks: str = DEFAULT_CHECKS,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> BaselineResult:
    """Run Schemathesis against `base_url` and parse its JSON report.

    A non-zero exit code means issues were found; the report file is the
    source of truth either way.
    """
    executable = find_schemathesis()
    with tempfile.TemporaryDirectory(prefix="fuzzrex-baseline-") as tmp:
        report_path = Path(tmp) / "report.json"
        command = build_command(
            executable,
            spec_path,
            base_url,
            report_path,
            seed=seed,
            max_examples=max_examples,
            checks=checks,
            headers=headers,
        )
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"schemathesis timed out after {timeout}s") from exc

        if not report_path.is_file():
            detail = (completed.stderr or completed.stdout or "").strip()[-500:]
            raise RuntimeError(
                f"schemathesis produced no report (exit {completed.returncode}): {detail}",
            )

        report = json.loads(report_path.read_text(encoding="utf-8"))

    findings, generated, exit_code = parse_report(report)
    return BaselineResult(
        config=config,
        findings=findings,
        generated=generated,
        exit_code=exit_code,
    )


def run_baseline_matrix(
    orchestrator: DockerComposeOrchestrator,
    configs: Iterable[Any],
    spec_path: str | Path,
    **run_kwargs: Any,
) -> list[BaselineResult]:
    """Run the baseline fuzzer once per config cell, restoring the SUT afterwards.

    Each cell is applied via the orchestrator (restart + health check),
    the fuzzer runs, and the original config is restored by
    `configured_service`.
    """
    results: list[BaselineResult] = []
    for config in configs:
        with configured_service(orchestrator, config):
            results.append(
                run_schemathesis(
                    spec_path,
                    orchestrator.base_url,
                    config=config,
                    **run_kwargs,
                ),
            )
    return results
