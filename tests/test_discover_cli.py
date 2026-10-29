import json
from unittest.mock import patch

import pytest
import yaml

from fuzzrex.discover_cli import _write_document, build_parser, main
from fuzzrex.orchestrator import OrchestratorError

REQUIRED = [
    "--compose", "compose.yml",
    "--service", "sut",
    "--config", "sut.ini",
    "--base-url", "http://sut.test",
    "--spec", "openapi.yml",
    "--baseline-config", "base.json",
    "--cells", "cells.json",
]


def _files(tmp_path, cells='{"flag": [false, true]}'):
    base = tmp_path / "base.json"
    base.write_text('{"flag": false}')
    cells_path = tmp_path / "cells.json"
    cells_path.write_text(cells)
    spec = tmp_path / "openapi.json"
    spec.write_text(
        '{"openapi": "3.0.0", "paths": '
        '{"/x": {"get": {"responses": {"200": {"description": "ok"}}}}}}'
    )
    out_spec = tmp_path / "out" / "pruned.yml"
    out_enums = tmp_path / "out" / "enums.yml"
    argv = [
        "--baseline-config", str(base),
        "--cells", str(cells_path),
        "--spec", str(spec),
        "--out-spec", str(out_spec),
        "--out-enums", str(out_enums),
    ]
    return argv, spec, out_spec, out_enums


def _pruned():
    return {
        "openapi": "3.0.0",
        "paths": {"/x": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }


@patch("fuzzrex.discover_cli.ApiFuzzer")
@patch("fuzzrex.discover_cli.filter_knobs")
@patch("fuzzrex.discover_cli.prune_spec")
@patch("fuzzrex.discover_cli.DockerComposeOrchestrator")
def test_both_passes_write_outputs(mock_orch, mock_prune, mock_knobs, mock_fuzzer, tmp_path):
    argv, _, out_spec, out_enums = _files(tmp_path)
    pruned = _pruned()
    mock_prune.return_value = pruned
    mock_knobs.return_value = {"flag": [True]}
    mock_fuzzer.return_value.plan.return_value = ["req"]
    mock_orch.return_value.base_url = "http://sut.test"

    assert main(REQUIRED + argv) == 0

    # knobs pass replays the pruned plan against the baseline cell
    assert mock_fuzzer.call_args.args[0] == str(out_spec)
    orchestrator, baseline, domains, sequence = mock_knobs.call_args.args
    assert baseline == {"flag": False}
    assert domains == {"flag": [False, True]}  # candidates from --cells domains
    assert sequence == ["req"]
    assert orchestrator is mock_orch.return_value
    # outputs are the campaign's --spec/--enums inputs
    assert yaml.safe_load(out_spec.read_text()) == pruned
    assert yaml.safe_load(out_enums.read_text()) == {"flag": [True]}
    assert mock_orch.return_value.up.called
    assert mock_orch.return_value.restore.called


@patch("fuzzrex.discover_cli.ApiFuzzer")
@patch("fuzzrex.discover_cli.filter_knobs")
@patch("fuzzrex.discover_cli.prune_spec")
@patch("fuzzrex.discover_cli.DockerComposeOrchestrator")
def test_only_prune_skips_knobs(mock_orch, mock_prune, mock_knobs, mock_fuzzer, tmp_path):
    argv, _, out_spec, out_enums = _files(tmp_path)
    mock_prune.return_value = _pruned()

    assert main(REQUIRED + argv + ["--only", "prune"]) == 0

    mock_knobs.assert_not_called()
    mock_fuzzer.assert_not_called()
    assert out_spec.is_file()
    assert not out_enums.exists()


@patch("fuzzrex.discover_cli.ApiFuzzer")
@patch("fuzzrex.discover_cli.filter_knobs")
@patch("fuzzrex.discover_cli.prune_spec")
@patch("fuzzrex.discover_cli.DockerComposeOrchestrator")
def test_only_knobs_uses_source_spec(mock_orch, mock_prune, mock_knobs, mock_fuzzer, tmp_path):
    argv, spec, _, out_enums = _files(tmp_path)
    mock_knobs.return_value = {"flag": [True, False]}
    mock_fuzzer.return_value.plan.return_value = ["req"]

    assert main(REQUIRED + argv + ["--only", "knobs"]) == 0

    mock_prune.assert_not_called()
    assert mock_fuzzer.call_args.args[0] == str(spec)  # no pruning happened
    assert yaml.safe_load(out_enums.read_text()) == {"flag": [True, False]}


@patch("fuzzrex.discover_cli.DockerComposeOrchestrator")
def test_list_cells_without_enums_is_rejected(mock_orch, tmp_path):
    argv, _, _, _ = _files(tmp_path, cells='[{"flag": false}]')

    with pytest.raises(SystemExit, match="per-key candidates"):
        main(REQUIRED + argv)

    mock_orch.assert_not_called()  # rejected before the SUT is touched


@patch("fuzzrex.discover_cli.DockerComposeOrchestrator")
def test_refuses_to_overwrite_inputs(mock_orch, tmp_path):
    argv, spec, _, _ = _files(tmp_path)
    argv[argv.index("--out-spec") + 1] = str(spec)

    with pytest.raises(SystemExit, match="refusing to overwrite"):
        main(REQUIRED + argv)

    mock_orch.assert_not_called()


@patch("fuzzrex.discover_cli.filter_knobs")
@patch("fuzzrex.discover_cli.prune_spec")
@patch("fuzzrex.discover_cli.DockerComposeOrchestrator")
def test_empty_kept_knobs_warns_but_writes(mock_orch, mock_prune, mock_knobs, tmp_path, capsys):
    argv, _, _, out_enums = _files(tmp_path)
    mock_prune.return_value = _pruned()
    mock_knobs.return_value = {}

    assert main(REQUIRED + argv) == 0

    assert "no candidate knob changed a response" in capsys.readouterr().err
    assert yaml.safe_load(out_enums.read_text()) == {}


@patch("fuzzrex.discover_cli.filter_knobs")
@patch("fuzzrex.discover_cli.prune_spec")
@patch("fuzzrex.discover_cli.DockerComposeOrchestrator")
def test_restore_runs_when_prune_fails(mock_orch, mock_prune, mock_knobs, tmp_path, capsys):
    argv, _, _, _ = _files(tmp_path)
    mock_prune.side_effect = OrchestratorError("compose down")

    assert main(REQUIRED + argv) == 1

    assert "stopping: compose down" in capsys.readouterr().out
    assert mock_orch.return_value.restore.called


def test_drop_statuses_parsing():
    parser = build_parser()
    assert parser.parse_args(REQUIRED).drop_statuses == frozenset({404, 501})
    args = parser.parse_args(REQUIRED + ["--drop-statuses", "400, 403"])
    assert args.drop_statuses == frozenset({400, 403})
    with pytest.raises(SystemExit):
        parser.parse_args(REQUIRED + ["--drop-statuses", "abc"])
    with pytest.raises(SystemExit):
        parser.parse_args(REQUIRED + ["--drop-statuses", ","])


def test_write_document_json_suffix(tmp_path):
    path = tmp_path / "nested" / "enums.json"
    _write_document(path, {"flag": [True]})
    assert json.loads(path.read_text()) == {"flag": [True]}
