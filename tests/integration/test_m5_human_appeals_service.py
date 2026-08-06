from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from labcourt.contracts.enums import AppealStatus, PrecedentStatus, VerdictDecision
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.services.m5_human_appeals import (
    begin_human_appeal_review,
    resolve_human_appeal,
    submit_human_appeal,
)
from labcourt.services.m5_operations import finalize_m5_run
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m5_sqlite_alert_repository import _prepare_ready_case

NOW = datetime(2026, 8, 2, 14, tzinfo=UTC)


def test_human_appeal_service_overturns_atomically_from_concise_explicit_inputs(
    tmp_path: Path,
) -> None:
    database, evidence, _, ready, _, config = _prepare_ready_case(tmp_path)
    finalize_m5_run(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=lambda: NOW,
    )
    submitted = submit_human_appeal(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        case_id=ready.case.case_id,
        reason="The cited evidence was interpreted incorrectly.",
        submitted_by="subject-01",
    )
    replayed = submit_human_appeal(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        case_id=ready.case.case_id,
        reason="The cited evidence was interpreted incorrectly.",
        submitted_by="subject-01",
    )
    assert replayed == submitted

    reviewed = begin_human_appeal_review(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        appeal_id=submitted.appeal_id,
        reviewer_id="reviewer-01",
    )
    assert reviewed.status == AppealStatus.UNDER_REVIEW

    appealed_case = evidence.load_case(RUN_ID, ready.case.case_id).case
    crop = appealed_case.evidence_packs[-1].crops[0]
    terminal = resolve_human_appeal(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        appeal_id=submitted.appeal_id,
        reviewer_id="reviewer-01",
        status=AppealStatus.OVERTURNED,
        resolved_decision=VerdictDecision.NOT_ESTABLISHED,
        resolution_summary="Human review found the original decision unsupported.",
        authored_labels=(
            M5AppealTrainingLabelInput(
                crop_id=crop.crop_id,
                bbox=BBoxXYXY(
                    x1=0,
                    y1=0,
                    x2=min(10, crop.output_width),
                    y2=min(10, crop.output_height),
                ),
                label_name="original_decision_unsupported",
                label_value=True,
            ),
        ),
        precedent_situation="The reviewed crop does not establish the alleged violation.",
        clock=lambda: NOW,
    )

    assert terminal.status == AppealStatus.OVERTURNED
    assert terminal.final_decision == VerdictDecision.NOT_ESTABLISHED
    assert terminal.replacement_precedent_id is not None
    assert len(terminal.revoked_precedent_ids) == 1
    assert len(terminal.training_label_ids) == 1
    current = evidence.load_case(RUN_ID, ready.case.case_id).case
    assert current.final_decision == VerdictDecision.NOT_ESTABLISHED
    assert current.appeals[-1].status == AppealStatus.OVERTURNED

    from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository

    repository = SQLiteM5Repository(database, config.storage.busy_timeout_ms)
    assert (
        repository.get_precedent(RUN_ID, terminal.revoked_precedent_ids[0]).precedent.status
        == PrecedentStatus.REVOKED
    )
    assert (
        repository.get_precedent(RUN_ID, terminal.replacement_precedent_id).precedent.status
        == PrecedentStatus.ACTIVE
    )
