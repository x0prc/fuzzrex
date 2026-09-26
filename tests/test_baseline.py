import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fuzzrex.baseline import (
    BaselineResult,
    build_command,
    find_schemathesis,
    parse_report,
    run_baseline_matrix,
    run_schemathesis,
)

REPORT = {
    "exit_code": 1,
    "test_cases": {"generated": 12, "with_failures": 2},
    "failures": [
        {
            "type": "check",
            "title": "Server error",
            "severity": "critical",
            "count": 3,
            "operations": ["POST /users", "GET /health"],
        },
    ],
    "errors": [{"title": "Connection error", "count": 1}],
}


def test_parse_report_extracts_findings():
    findings, generated, exit_code = parse_report(REPORT)
    assert generated == 12
    assert exit_code == 1
    assert len(findings) == 2
    failure, error = findings
    assert failure.kind == "failure"
    assert failure.count == 3
    assert failure.operations == ("POST /users", "GET /health")
    assert error.kind == "error"
    assert error.title == "Connection error"


def test_parse_report_empty_report():
    findings, generated, exit_code = parse_report({})
    assert findings == ()
    assert generated == 0
    assert exit_code == 0


def test_find_schemathesis_prefers_path_lookup():
    with patch("fuzzrex.baseline.shutil.which", return_value="/opt/bin/schemathesis"):
        assert find_schemathesis() == "/opt/bin/schemathesis"


def test_find_schemathesis_falls_back_to_venv_sibling():
    sibling = Path(sys.executable).with_name("schemathesis")
    with (
        patch("fuzzrex.baseline.shutil.which", return_value=None),
        patch.object(Path, "is_file", return_value=True),
    ):
        assert find_schemathesis() == str(sibling)


def test_find_schemathesis_missing_raises_install_hint():
    with (
        patch("fuzzrex.baseline.shutil.which", return_value=None),
        patch.object(Path, "is_file", return_value=False),
    ):
        with pytest.raises(RuntimeError, match=r"fuzzrex\[baseline\]"):
            find_schemathesis()


def test_build_command_includes_flags():
    command = build_command(
        "/bin/schemathesis",
        "openapi.json",
        "http://sut.test",
        "/tmp/report.json",
        seed=7,
        max_examples=5,
        checks="not_a_server_error",
        headers={"Authorization": "Bearer t"},
    )
    assert command[:3] == ["/bin/schemathesis", "run", "openapi.json"]
    assert ["-u", "http://sut.test"] == command[3:5]
    assert command[command.index("-n") + 1] == "5"
    assert command[command.index("--seed") + 1] == "7"
    assert command[command.index("--workers") + 1] == "1"
    assert command[command.index("--report-json-path") + 1] == "/tmp/report.json"
    assert "Authorization:Bearer t" in command


def test_build_command_omits_seed_by_default():
    command = build_command("st", "s.json", "http://x", "/tmp/r.json")
    assert "--seed" not in command


def _run_with_report(cmd, **kwargs):
    """Pretend to run schemathesis by writing the fixture report where asked."""
    report_path = Path(cmd[cmd.index("--report-json-path") + 1])
    report_path.write_text(json.dumps(REPORT))
    return MagicMock(returncode=1, stdout="", stderr="")


@patch("fuzzrex.baseline.find_schemathesis", return_value="/bin/st")
@patch("fuzzrex.baseline.subprocess.run", side_effect=_run_with_report)
def test_run_schemathesis_parses_report(mock_run, _mock_find):
    result = run_schemathesis(
        "openapi.json",
        "http://sut.test",
        config={"debug": True},
        seed=1,
        max_examples=3,
    )
    assert isinstance(result, BaselineResult)
    assert result.config == {"debug": True}
    assert result.generated == 12
    assert result.exit_code == 1
    assert result.total == 4  # 3 failures + 1 error
    assert result.findings[0].title == "Server error"


@patch("fuzzrex.baseline.find_schemathesis", return_value="/bin/st")
@patch("fuzzrex.baseline.subprocess.run")
def test_run_schemathesis_missing_report_raises(mock_run, _mock_find):
    mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="boom")
    with pytest.raises(RuntimeError, match="no report"):
        run_schemathesis("openapi.json", "http://sut.test")


@patch("fuzzrex.baseline.run_schemathesis")
@patch("fuzzrex.baseline.configured_service")
def test_run_baseline_matrix_applies_each_config(mock_cm, mock_run):
    orch = MagicMock()
    orch.base_url = "http://sut.test"
    mock_cm.return_value.__enter__ = MagicMock(return_value=orch)
    mock_cm.return_value.__exit__ = MagicMock(return_value=False)
    mock_run.side_effect = lambda *a, config=None, **kw: BaselineResult(config, (), 0, 0)

    configs = [{"debug": False}, {"debug": True}]
    results = run_baseline_matrix(orch, configs, "openapi.json", seed=3)

    assert [r.config for r in results] == configs
    assert mock_cm.call_count == 2
    assert mock_run.call_count == 2
    # every cell was probed against the orchestrator's base URL
    assert all(call.args[1] == "http://sut.test" for call in mock_run.call_args_list)
