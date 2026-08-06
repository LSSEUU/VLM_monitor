from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.application.m5_appeal_operations import (
    M5AppealOperationsError,
    M5AppealOperationsErrorCode,
)
from labcourt.contracts.enums import AppealStatus, CaseStatus
from labcourt.contracts.m5_appeals import (
    AppealResolutionCommand,
    AppealReviewCommand,
    AppealSubmissionCommand,
)
from labcourt.services.m5_appeal_operations import (
    begin_m5_appeal_review,
    resolve_m5_appeal,
    submit_m5_appeal,
)
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m5_sqlite_appeals import _prepare_closed_case


def test_explicit_upheld_commands_cross_the_real_sqlite_boundary_restart_safely(
    tmp_path: Path,
) -> None:
    database, repository, closed, _, config, _ = _prepare_closed_case(tmp_path)
    source = repository.load_closed_case_authority(RUN_ID, closed.case.case_id)

    submit_command = AppealSubmissionCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id="appeal-service-01",
        expected_case_revision=source.case_revision,
        expected_case_authority_sha256=source.authority_sha256,
        reason="The adjudication should receive an explicit human review.",
        submitted_by="subject-service-01",
    )
    submitted = submit_m5_appeal(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        command=submit_command,
    )
    assert (
        submit_m5_appeal(
            config=config,
            workspace_root=tmp_path,
            database_path=database,
            command=submit_command,
        )
        == submitted
    )

    review_command = AppealReviewCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id=submitted.appeal_id,
        expected_appeal_authority_sha256=submitted.appeal_authority_sha256,
        reviewer_id="reviewer-service-01",
    )
    reviewed = begin_m5_appeal_review(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        command=review_command,
    )
    assert (
        begin_m5_appeal_review(
            config=config,
            workspace_root=tmp_path,
            database_path=database,
            command=review_command,
        )
        == reviewed
    )

    resolution_command = AppealResolutionCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id=reviewed.appeal_id,
        expected_appeal_authority_sha256=reviewed.appeal_authority_sha256,
        status=AppealStatus.UPHELD,
        reviewer_id=reviewed.reviewer_id,
        resolution_summary="The assigned human reviewer upheld the original decision.",
        resolved_decision=source.final_decision,
    )
    resolved = resolve_m5_appeal(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        command=resolution_command,
    )

    assert resolved.status == AppealStatus.UPHELD
    assert resolved.reviewer_id == review_command.reviewer_id
    assert resolved.training_label_ids == ()
    assert resolved.revoked_precedent_ids == ()
    final_case = repository.load_case(RUN_ID, source.case_id)
    assert final_case.revision == source.case_revision + 3
    assert final_case.case.status == CaseStatus.APPEAL_RESOLVED
    assert final_case.case.final_decision == source.final_decision

    assert (
        resolve_m5_appeal(
            config=config,
            workspace_root=tmp_path,
            database_path=database,
            command=resolution_command,
        )
        == resolved
    )

    conflicting = resolution_command.model_copy(
        update={"resolution_summary": "A different human terminal finding."}
    )
    with pytest.raises(M5AppealOperationsError) as terminal_conflict:
        resolve_m5_appeal(
            config=config,
            workspace_root=tmp_path,
            database_path=database,
            command=conflicting,
        )
    assert terminal_conflict.value.code == M5AppealOperationsErrorCode.TERMINAL_COMMAND_CONFLICT


def test_appeal_service_rejects_database_outside_configured_workspace(
    tmp_path: Path,
) -> None:
    database, repository, closed, _, config, _ = _prepare_closed_case(tmp_path)
    source = repository.load_closed_case_authority(RUN_ID, closed.case.case_id)
    command = AppealSubmissionCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id="appeal-service-path-01",
        expected_case_revision=source.case_revision,
        expected_case_authority_sha256=source.authority_sha256,
        reason="This command must not escape its configured database boundary.",
        submitted_by="subject-service-01",
    )
    with pytest.raises(ValueError, match="configured appeal authority"):
        submit_m5_appeal(
            config=config,
            workspace_root=tmp_path,
            database_path=database.with_name("another.sqlite3"),
            command=command,
        )
