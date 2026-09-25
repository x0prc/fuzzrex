"""Drive a Dockerized SUT through configuration variants for joint config x API fuzzing."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import requests

from fuzzrex.schema import dump_document, load_document

DEFAULT_COMPOSE = ("docker", "compose")
DEFAULT_HEALTH_TIMEOUT = 60.0
DEFAULT_REQUEST_TIMEOUT = 10.0


class OrchestratorError(RuntimeError):
    """Raised when the SUT cannot be reconfigured or reach a healthy state."""


class DockerComposeOrchestrator:
    """Apply config files to a bind-mounted service and restart it in place.

    The host-side config path must be the same file bind-mounted into the
    container; process restart is what causes the service to reload it.
    """

    def __init__(
        self,
        compose_file: str | Path,
        service: str,
        config_path: str | Path,
        base_url: str,
        *,
        health_path: str = "/health",
        compose_cmd: Sequence[str] = DEFAULT_COMPOSE,
        health_timeout: float = DEFAULT_HEALTH_TIMEOUT,
    ) -> None:
        self.compose_file = Path(compose_file)
        self.service = service
        self.config_path = Path(config_path)
        self.base_url = base_url.rstrip("/")
        self.health_path = health_path
        self.compose_cmd = tuple(compose_cmd)
        self.health_timeout = health_timeout

        if not self.compose_file.is_file():
            raise FileNotFoundError(f"Compose file not found: {self.compose_file}")
        if not self.config_path.is_file():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        self._original_config = self.config_path.read_bytes()

    def load_current_config(self) -> Any:
        return load_document(self.config_path)

    def up(self, *, build: bool = False) -> None:
        args = ["up", "-d"]
        if build:
            args.append("--build")
        args.append(self.service)
        self._compose(*args)
        self.wait_healthy()

    def apply_config(self, config: Any) -> None:
        dump_document(config, self.config_path)

    def restart(self) -> None:
        self._compose("restart", self.service)

    def wait_healthy(self, timeout: float | None = None) -> None:
        deadline = time.monotonic() + (timeout if timeout is not None else self.health_timeout)
        url = f"{self.base_url}{self.health_path}"
        last_error: str = "no response"
        while time.monotonic() < deadline:
            try:
                response = requests.get(url, timeout=DEFAULT_REQUEST_TIMEOUT)
                if response.status_code < 500:
                    return
                last_error = f"status {response.status_code}"
            except requests.RequestException as exc:
                last_error = str(exc)
            time.sleep(0.25)
        raise OrchestratorError(f"SUT not healthy at {url} within timeout: {last_error}")

    def restore(self) -> None:
        self.config_path.write_bytes(self._original_config)
        try:
            self.restart()
            self.wait_healthy()
        except (OrchestratorError, subprocess.CalledProcessError) as exc:
            raise OrchestratorError(f"Failed to restore SUT: {exc}") from exc

    def down(self) -> None:
        self._compose("down", "--remove-orphans")

    def _compose(self, *args: str) -> None:
        command = [*self.compose_cmd, "-f", str(self.compose_file), *args]
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except FileNotFoundError as exc:
            raise OrchestratorError(f"Compose command not found: {self.compose_cmd[0]}") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or str(exc)).strip()
            raise OrchestratorError(f"`{' '.join(command)}` failed: {detail}") from exc


@contextmanager
def configured_service(
    orchestrator: DockerComposeOrchestrator,
    config: Any,
) -> Iterator[DockerComposeOrchestrator]:
    """Apply `config`, restart, wait healthy; always restore the original config."""
    try:
        orchestrator.apply_config(config)
        orchestrator.restart()
        orchestrator.wait_healthy()
        yield orchestrator
    finally:
        orchestrator.restore()
