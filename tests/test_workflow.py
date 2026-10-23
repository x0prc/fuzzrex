"""Structural checks for the Phase 1 and Phase 2 campaign workflows."""

from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "phase1.yml"
PHASE2 = WORKFLOWS / "phase2.yml"


def _load(workflow: Path = WORKFLOW) -> dict:
    return yaml.safe_load(workflow.read_text())


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


# --- Phase 2 ---------------------------------------------------------------


def test_phase2_dispatch_exposes_the_feature_inputs():
    document = _load(PHASE2)
    trigger = document.get("on", document.get(True))
    assert "workflow_dispatch" in trigger
    inputs = trigger["workflow_dispatch"]["inputs"]
    assert set(inputs) == {
        "target",
        "fresh",
        "seeds",
        "iterations",
        "stall",
        "request_mutation",
        "plan_mutations",
    }
    assert inputs["target"]["default"] == "crapi"
    assert inputs["fresh"]["type"] == "boolean"
    assert inputs["stall"]["default"] == "8"
    assert inputs["request_mutation"]["default"] == "0.2"
    assert inputs["plan_mutations"]["default"] == "2"


def test_phase2_matrix_ships_runner_arguments_per_sut():
    matrix = _load(PHASE2)["jobs"]["campaign"]["strategy"]["matrix"]["include"]
    by_sut = {entry["sut"]: entry for entry in matrix}
    assert set(by_sut) == {"dvwa", "grafana", "crapi"}
    assert "login.php" in by_sut["dvwa"]["health"]
    assert "recreate" in by_sut["crapi"]["runner"]
    assert "crapi-identity" in by_sut["crapi"]["runner"]
    for sut, entry in by_sut.items():
        assert f"examples/{sut}/compose.yml" in entry["runner"]
        assert entry["runner"].split()[0] == "--compose"


def test_phase2_run_step_wires_the_feature_flags():
    steps = _load(PHASE2)["jobs"]["campaign"]["steps"]
    run = next(step for step in steps if step.get("name") == "Run campaign")
    assert "fuzzrex-campaign" in run["run"]
    for flag in ("--seeds", "--iterations", "--stall", "--request-mutation",
                 "--plan-mutations", "--baseline-config", "--cells", "--spec"):
        assert flag in run["run"]
    assert "findings/phase2" in run["run"]
    assert "matrix.sut" in run["if"]
    assert "inputs.target" in run["if"]
    # stall is optional: only appended when the input is non-empty
    assert "[ -n " in run["run"]


def test_phase2_artifacts_do_not_collide_with_phase1():
    """Phase 1's analyze job downloads findings-*; Phase 2 checkpoints
    must not match that pattern or they would pollute its table."""
    campaign = _load(PHASE2)["jobs"]["campaign"]
    steps = campaign["steps"]
    upload = next(step for step in steps if step.get("name") == "Upload checkpoint")
    assert upload["with"]["name"] == "phase2-checkpoint-${{ matrix.sut }}"
    assert "always()" in upload["if"]
    resume = next(step for step in steps if step.get("name") == "Resume from previous checkpoint")
    assert "phase2-checkpoint-" in resume["run"]
    assert "findings/phase2" in resume["run"]
    assert resume["env"]["GH_TOKEN"]
    names = [step.get("name") for step in steps]
    assert names.index("Install") < names.index("Resume from previous checkpoint")
    assert names.index("Resume from previous checkpoint") < names.index("Run campaign")
    assert campaign["timeout-minutes"] <= 6 * 60

    analyze = _load(PHASE2)["jobs"]["analyze"]
    assert analyze["needs"] == "campaign"
    download = next(
        step
        for step in analyze["steps"]
        if str(step.get("uses", "")).startswith("actions/download")
    )
    assert download["with"]["pattern"] == "phase2-checkpoint-*"
    summarize = next(step for step in analyze["steps"] if step.get("name") == "Summarize")
    assert "fuzzrex.analysis findings/phase2" in summarize["run"]
    assert "GITHUB_STEP_SUMMARY" in summarize["run"]
