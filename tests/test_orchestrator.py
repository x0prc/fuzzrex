import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fuzzrex.orchestrator import (
    DockerComposeOrchestrator,
    OrchestratorError,
    configured_service,
)


@pytest.fixture
def project(tmp_path: Path) -> tuple[Path, Path]:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services: {}\n")
    config = tmp_path / "config.json"
    config.write_text('{"debug": false}\n')
    return compose, config


def make_orchestrator(compose: Path, config: Path) -> DockerComposeOrchestrator:
    return DockerComposeOrchestrator(
        compose,
        "demo-api",
        config,
        "http://localhost:5001",
        health_timeout=0.1,
    )


def test_missing_compose_file(tmp_path: Path):
    config = tmp_path / "c.json"
    config.write_text("{}")
    with pytest.raises(FileNotFoundError):
        DockerComposeOrchestrator(tmp_path / "missing.yml", "svc", config, "http://x")


def test_missing_config_file(tmp_path: Path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services: {}\n")
    with pytest.raises(FileNotFoundError):
        DockerComposeOrchestrator(compose, "svc", tmp_path / "missing.json", "http://x")


def test_apply_config_writes_file(project: tuple[Path, Path]):
    _, config = project
    orch = make_orchestrator(*project)
    orch.apply_config({"debug": True, "require_auth": True})
    assert orch.load_current_config() == {"debug": True, "require_auth": True}


@patch("fuzzrex.orchestrator.subprocess.run")
def test_restart_invokes_compose(mock_run, project: tuple[Path, Path]):
    mock_run.return_value = MagicMock(returncode=0)
    orch = make_orchestrator(*project)
    orch.restart()
    command = mock_run.call_args[0][0]
    assert command[:3] == ["docker", "compose", "-f"]
    assert "restart" in command
    assert "demo-api" in command


@patch("fuzzrex.orchestrator.subprocess.run")
def test_up_with_build(mock_run, project: tuple[Path, Path]):
    mock_run.return_value = MagicMock(returncode=0)
    orch = make_orchestrator(*project)
    with patch.object(orch, "wait_healthy"):
        orch.up(build=True)
    command = mock_run.call_args[0][0]
    assert "up" in command and "-d" in command and "--build" in command


@patch("fuzzrex.orchestrator.subprocess.run")
def test_recreate_mode_force_recreates_on_restart(mock_run, project: tuple[Path, Path]):
    mock_run.return_value = MagicMock(returncode=0)
    compose, config = project
    orch = DockerComposeOrchestrator(
        compose, "svc", config, "http://x", reload="recreate"
    )
    orch.restart()
    command = mock_run.call_args[0][0]
    assert command[:3] == ["docker", "compose", "-f"]
    assert "up" in command and "-d" in command
    assert "--force-recreate" in command
    assert "restart" not in command


def test_invalid_reload_mode_rejected(project: tuple[Path, Path]):
    compose, config = project
    with pytest.raises(ValueError, match="reload"):
        DockerComposeOrchestrator(compose, "svc", config, "http://x", reload="hot")


@patch("fuzzrex.orchestrator.subprocess.run")
def test_compose_failure_raises(mock_run, project: tuple[Path, Path]):
    mock_run.side_effect = subprocess.CalledProcessError(
        1,
        ["docker", "compose"],
        stderr="boom",
    )
    orch = make_orchestrator(*project)
    with pytest.raises(OrchestratorError, match="boom"):
        orch.restart()


@patch("fuzzrex.orchestrator.subprocess.run", side_effect=FileNotFoundError)
def test_missing_binary_raises(mock_run, project: tuple[Path, Path]):
    orch = make_orchestrator(*project)
    with pytest.raises(OrchestratorError, match="not found"):
        orch.restart()


DAEMON_ERROR = "failed to connect to the docker API at unix:///docker.sock: no such file"


@patch("fuzzrex.orchestrator.subprocess.run")
def test_compose_retries_after_daemon_blip(mock_run, project: tuple[Path, Path]):
    mock_run.side_effect = [
        subprocess.CalledProcessError(1, ["docker", "compose"], stderr=DAEMON_ERROR),
        MagicMock(returncode=0),  # docker info probe: daemon back
        MagicMock(returncode=0),  # retried compose command
    ]
    orch = make_orchestrator(*project)
    orch.restart()
    assert mock_run.call_count == 3
    assert mock_run.call_args_list[1].args[0] == ["docker", "info"]


@patch("fuzzrex.orchestrator.DAEMON_WAIT_TIMEOUT", 0)
@patch("fuzzrex.orchestrator.subprocess.run")
def test_compose_raises_when_daemon_never_returns(mock_run, project: tuple[Path, Path]):
    mock_run.side_effect = subprocess.CalledProcessError(
        1, ["docker", "compose"], stderr=DAEMON_ERROR
    )
    orch = make_orchestrator(*project)
    with pytest.raises(OrchestratorError, match="docker API"):
        orch.restart()


@patch("fuzzrex.orchestrator.subprocess.run")
def test_non_daemon_failure_does_not_probe(mock_run, project: tuple[Path, Path]):
    mock_run.side_effect = subprocess.CalledProcessError(1, ["docker", "compose"], stderr="boom")
    orch = make_orchestrator(*project)
    with pytest.raises(OrchestratorError, match="boom"):
        orch.restart()
    assert mock_run.call_count == 1


@patch("fuzzrex.orchestrator.requests.get")
@patch("fuzzrex.orchestrator.subprocess.run")
def test_configured_service_applies_and_restores(
    mock_run,
    mock_get,
    project: tuple[Path, Path],
):
    mock_run.return_value = MagicMock(returncode=0)
    mock_get.return_value = MagicMock(status_code=200)
    _, config = project
    orch = make_orchestrator(*project)

    with configured_service(orch, {"debug": True}):
        assert orch.load_current_config() == {"debug": True}

    assert orch.load_current_config() == {"debug": False}
    # restart called for apply + restore
    assert mock_run.call_count == 2


@patch("fuzzrex.orchestrator.requests.get")
@patch("fuzzrex.orchestrator.subprocess.run")
def test_configured_service_restores_on_fuzz_error(
    mock_run,
    mock_get,
    project: tuple[Path, Path],
):
    mock_run.return_value = MagicMock(returncode=0)
    mock_get.return_value = MagicMock(status_code=200)
    _, config = project
    orch = make_orchestrator(*project)

    with pytest.raises(RuntimeError, match="fuzz failed"):
        with configured_service(orch, {"debug": True}):
            raise RuntimeError("fuzz failed")

    assert orch.load_current_config() == {"debug": False}


@patch("fuzzrex.orchestrator.requests.get")
def test_wait_healthy_timeout(mock_get, project: tuple[Path, Path]):
    import requests as requests_lib

    mock_get.side_effect = requests_lib.ConnectionError("down")
    orch = make_orchestrator(*project)
    with pytest.raises(OrchestratorError, match="not healthy"):
        orch.wait_healthy(timeout=0.01)


@patch("fuzzrex.orchestrator.time.sleep", return_value=None)
@patch("fuzzrex.orchestrator.requests.get")
def test_wait_healthy_retries_until_ok(mock_get, _sleep, project: tuple[Path, Path]):
    mock_get.side_effect = [
        MagicMock(status_code=503),
        MagicMock(status_code=200),
    ]
    orch = make_orchestrator(*project)
    orch.wait_healthy(timeout=5)
    assert mock_get.call_count == 2
