"""Structural checks for the Phase 1 campaign workflow."""

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "phase1.yml"


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def test_dispatch_only_with_target_choice():
    document = _load()
    trigger = document.get("on", document.get(True))  # YAML parses bare `on` as True
    assert "workflow_dispatch" in trigger
    inputs = trigger["workflow_dispatch"]["inputs"]
    target = inputs["target"]
    assert target["type"] == "choice"
    assert set(target["options"]) == {"all", "dvwa", "grafana", "crapi"}
    fresh = inputs["fresh"]
    assert fresh["type"] == "boolean"
    assert fresh["default"] is False


def test_matrix_covers_all_suts_with_health_checks():
    matrix = _load()["jobs"]["campaign"]["strategy"]["matrix"]["include"]
    by_sut = {entry["sut"]: entry for entry in matrix}
    assert set(by_sut) == {"dvwa", "grafana", "crapi"}
    assert "login.php" in by_sut["dvwa"]["health"]
    assert by_sut["grafana"]["health"].endswith("/api/health")
    assert by_sut["crapi"]["health"].endswith("/identity/health_check")


def test_campaign_gates_steps_on_target_and_finishes_within_limit():
    campaign = _load()["jobs"]["campaign"]
    assert campaign["timeout-minutes"] <= 6 * 60
    gated = [
        step
        for step in campaign["steps"]
        if step.get("name") in ("Warm up SUT", "Run campaign")
    ]
    assert len(gated) == 2
    for step in gated:
        assert "matrix.sut" in step["if"]
        assert "inputs.target" in step["if"]


def test_resume_step_restores_previous_checkpoint_before_campaign():
    steps = _load()["jobs"]["campaign"]["steps"]
    names = [step.get("name") for step in steps]
    resume = steps[names.index("Resume from previous checkpoint")]
    assert "matrix.sut" in resume["if"]
    assert "inputs.target" in resume["if"]
    # fresh dispatches skip the restore so every seed reruns
    assert "inputs.fresh" in resume["if"]
    assert "gh api" in resume["run"]
    assert "findings-" in resume["run"]
    assert "findings/phase1" in resume["run"]
    assert resume["env"]["GH_TOKEN"]
    # restore must happen after install and before the campaign runs
    assert names.index("Install") < names.index("Resume from previous checkpoint")
    assert names.index("Resume from previous checkpoint") < names.index("Run campaign")


def test_analyze_needs_campaign_and_publishes_summary():
    analyze = _load()["jobs"]["analyze"]
    assert analyze["needs"] == "campaign"
    step_names = [step.get("name") for step in analyze["steps"]]
    assert "Summarize" in step_names
    summarize = next(s for s in analyze["steps"] if s.get("name") == "Summarize")
    assert "GITHUB_STEP_SUMMARY" in summarize["run"]
    assert "fuzzrex.analysis" in summarize["run"]


def test_partial_results_survive_failures():
    upload = next(
        step
        for step in _load()["jobs"]["campaign"]["steps"]
        if step.get("name") == "Upload checkpoint"
    )
    assert "always()" in upload["if"]
    assert upload["with"]["if-no-files-found"] == "ignore"
