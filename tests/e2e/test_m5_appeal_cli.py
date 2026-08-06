from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from labcourt.cli import app
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import AppealStatus, CaseStatus, VerdictDecision
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m5_sqlite_alert_repository import _prepare_ready_case

ROOT = Path(__file__).parents[2]


def test_m5_appeal_cli_runs_explicit_overturn_chain_and_rejects_terminal_reopen(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = tmp_path / "runs"
    workspace.mkdir()
    _, evidence, _, ready, _, _ = _prepare_ready_case(workspace)
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    config = str(ROOT / "configs/demo.yaml")

    finalized = runner.invoke(
        app,
        ["finalize", "--run-id", RUN_ID, "--config", config, "--json"],
    )
    assert finalized.exit_code == 0, finalized.output

    submitted = runner.invoke(
        app,
        [
            "appeal",
            "submit",
            ready.case.case_id,
            "--run-id",
            RUN_ID,
            "--reason",
            "The original decision misread the cited evidence.",
            "--submitted-by",
            "subject-01",
            "--config",
            config,
            "--json",
        ],
    )
    assert submitted.exit_code == 0, submitted.output
    submission = json.loads(submitted.stdout)
    appeal_id = submission["appeal_id"]
    assert submission["status"] == AppealStatus.SUBMITTED.value

    reviewed = runner.invoke(
        app,
        [
            "appeal",
            "review",
            appeal_id,
            "--run-id",
            RUN_ID,
            "--reviewer-id",
            "reviewer-01",
            "--config",
            config,
            "--json",
        ],
    )
    assert reviewed.exit_code == 0, reviewed.output
    assert json.loads(reviewed.stdout)["status"] == AppealStatus.UNDER_REVIEW.value

    current = evidence.load_case(RUN_ID, ready.case.case_id).case
    crop = current.evidence_packs[-1].crops[0]
    labels_path = tmp_path / "appeal-labels.jsonl"
    authored = M5AppealTrainingLabelInput(
        crop_id=crop.crop_id,
        bbox=BBoxXYXY(
            x1=0,
            y1=0,
            x2=min(10, crop.output_width),
            y2=min(10, crop.output_height),
        ),
        label_name="original_decision_unsupported",
        label_value=True,
    )
    labels_path.write_text(
        canonical_json(authored.model_dump(mode="json")) + "\n",
        encoding="utf-8",
    )
    source_decision = ready.case.verdicts[-1].decision
    resolved_decision = (
        VerdictDecision.NOT_ESTABLISHED
        if source_decision == VerdictDecision.ESTABLISHED
        else VerdictDecision.ESTABLISHED
    )
    resolved_args = [
        "appeal",
        "resolve",
        appeal_id,
        "--run-id",
        RUN_ID,
        "--reviewer-id",
        "reviewer-01",
        "--status",
        AppealStatus.OVERTURNED.value,
        "--resolved-decision",
        resolved_decision.value,
        "--resolution-summary",
        "Human review found the original decision unsupported.",
        "--labels-jsonl",
        str(labels_path),
        "--precedent-situation",
        "The reviewed crop does not establish the alleged violation.",
        "--config",
        config,
        "--json",
    ]
    resolved = runner.invoke(app, resolved_args)
    assert resolved.exit_code == 0, resolved.output
    terminal = json.loads(resolved.stdout)
    assert terminal["status"] == AppealStatus.OVERTURNED.value
    assert terminal["final_decision"] == resolved_decision.value
    assert len(terminal["training_label_ids"]) == 1
    assert len(terminal["revoked_precedent_ids"]) == 1

    reopened = runner.invoke(app, resolved_args)
    assert reopened.exit_code == 2
    error = json.loads(reopened.stdout)
    assert error["reason_code"] == "TRANSITION_NOT_ALLOWED"
    durable = evidence.load_case(RUN_ID, ready.case.case_id).case
    assert durable.status == CaseStatus.APPEAL_RESOLVED
    assert durable.final_decision == resolved_decision
