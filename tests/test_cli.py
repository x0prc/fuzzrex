import json
from pathlib import Path

import pytest

from fuzzrex.cli import main


@pytest.fixture
def spec_path(tmp_path: Path) -> Path:
    path = tmp_path / "spec.json"
    path.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "servers": [{"url": "http://localhost:9"}],
                "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}},
            },
        ),
    )
    return path


def test_requires_target(capsys):
    with pytest.raises(SystemExit):
        main([])


def test_config_only_success(tmp_path: Path, capsys):
    config = tmp_path / "c.yaml"
    config.write_text("debug: false\nport: 80\n")
    out = tmp_path / "variants"
    code = main(["--config", str(config), "--out", str(out), "--variants", "3", "--seed", "1"])
    assert code == 0
    assert len(list(out.glob("*.yaml"))) == 3
    assert "3 config variant(s)" in capsys.readouterr().out


def test_api_findings_exit_code(spec_path: Path, capsys):
    # Connection to port 9 should fail -> findings -> exit 1
    code = main(["--api", str(spec_path), "--timeout", "0.2"])
    assert code == 1
    assert "finding" in capsys.readouterr().out


def test_auth_requires_token(spec_path: Path):
    with pytest.raises(SystemExit):
        main(["--api", str(spec_path), "--auth", "token"])


def test_bad_config_path(capsys):
    code = main(["--config", "/no/such/file.yaml"])
    assert code == 2
    assert "error:" in capsys.readouterr().err
