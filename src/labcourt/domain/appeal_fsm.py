"""Pure M5 appeal state transitions over additive version authorities."""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.appeals import Appeal
from labcourt.contracts.enums import AppealStatus
from labcourt.contracts.m5_appeals import (
    AppealResolutionCommand,
    AppealReviewCommand,
    AppealSubmissionCommand,
    AppealVersionAuthority,
    ClosedCaseAppealAuthority,
)


class AppealTransitionFailureCode(StrEnum):
    APPEAL_ALREADY_EXISTS = "APPEAL_ALREADY_EXISTS"
    AUTHORITY_MISMATCH = "AUTHORITY_MISMATCH"
    TRANSITION_NOT_ALLOWED = "TRANSITION_NOT_ALLOWED"
    REVIEWER_MISMATCH = "REVIEWER_MISMATCH"
    RESOLUTION_DECISION_INVALID = "RESOLUTION_DECISION_INVALID"


class AppealTransitionError(RuntimeError):
    def __init__(self, reason_code: AppealTransitionFailureCode) -> None:
        if not isinstance(reason_code, AppealTransitionFailureCode):
            raise TypeError("reason_code must be an AppealTransitionFailureCode")
        self.reason_code = reason_code
        super().__init__(f"appeal transition failed: {reason_code.value}")


def _fail(reason_code: AppealTransitionFailureCode) -> NoReturn:
    raise AppealTransitionError(reason_code)


def submit_appeal(
    case_authority: ClosedCaseAppealAuthority,
    command: AppealSubmissionCommand,
    current_authority: AppealVersionAuthority | None,
) -> AppealVersionAuthority:
    """Perform the sole absence/NONE -> SUBMITTED transition."""

    if not isinstance(case_authority, ClosedCaseAppealAuthority):
        raise TypeError("case_authority must be a ClosedCaseAppealAuthority")
    if not isinstance(command, AppealSubmissionCommand):
        raise TypeError("command must be an AppealSubmissionCommand")
    if current_authority is not None and not isinstance(current_authority, AppealVersionAuthority):
        raise TypeError("current_authority must be an AppealVersionAuthority or None")
    if current_authority is not None or case_authority.effective_appeal_ids:
        _fail(AppealTransitionFailureCode.APPEAL_ALREADY_EXISTS)
    if (
        command.run_id != case_authority.run_id
        or command.case_id != case_authority.case_id
        or command.expected_case_revision != case_authority.case_revision
        or command.expected_case_authority_sha256 != case_authority.authority_sha256
    ):
        _fail(AppealTransitionFailureCode.AUTHORITY_MISMATCH)

    appeal = Appeal(
        appeal_id=command.appeal_id,
        case_id=command.case_id,
        status=AppealStatus.SUBMITTED,
        reason=command.reason,
        submitted_by=command.submitted_by,
    )
    return AppealVersionAuthority(
        run_id=case_authority.run_id,
        appeal=appeal,
        version=1,
        source_case_authority=case_authority,
        source_case_revision=case_authority.case_revision,
        source_case_authority_sha256=case_authority.authority_sha256,
        source_verdict_id=case_authority.verdict_id,
        source_verdict_version=case_authority.verdict_version,
        source_verdict_sha256=case_authority.verdict_sha256,
        source_decision=case_authority.final_decision,
        text_embedding_manifest_id=case_authority.text_embedding_manifest_id,
        visual_embedding_manifest_id=case_authority.visual_embedding_manifest_id,
        manifest_id=case_authority.manifest_id,
        rule_version=case_authority.rule_version,
    )


def begin_appeal_review(
    current_authority: AppealVersionAuthority,
    command: AppealReviewCommand,
) -> AppealVersionAuthority:
    """Perform SUBMITTED -> UNDER_REVIEW with an immutable reviewer assignment."""

    if not isinstance(current_authority, AppealVersionAuthority):
        raise TypeError("current_authority must be an AppealVersionAuthority")
    if not isinstance(command, AppealReviewCommand):
        raise TypeError("command must be an AppealReviewCommand")
    if current_authority.version != 1 or current_authority.appeal.status != AppealStatus.SUBMITTED:
        _fail(AppealTransitionFailureCode.TRANSITION_NOT_ALLOWED)
    if (
        command.run_id != current_authority.run_id
        or command.case_id != current_authority.appeal.case_id
        or command.appeal_id != current_authority.appeal.appeal_id
        or command.expected_appeal_version != current_authority.version
        or command.expected_appeal_authority_sha256 != current_authority.authority_sha256
    ):
        _fail(AppealTransitionFailureCode.AUTHORITY_MISMATCH)

    appeal = current_authority.appeal.model_copy(update={"status": AppealStatus.UNDER_REVIEW})
    return AppealVersionAuthority(
        run_id=current_authority.run_id,
        appeal=appeal,
        version=2,
        previous_authority_sha256=current_authority.authority_sha256,
        assigned_reviewer_id=command.reviewer_id,
        source_case_authority=current_authority.source_case_authority,
        source_case_revision=current_authority.source_case_revision,
        source_case_authority_sha256=current_authority.source_case_authority_sha256,
        source_verdict_id=current_authority.source_verdict_id,
        source_verdict_version=current_authority.source_verdict_version,
        source_verdict_sha256=current_authority.source_verdict_sha256,
        source_decision=current_authority.source_decision,
        text_embedding_manifest_id=current_authority.text_embedding_manifest_id,
        visual_embedding_manifest_id=current_authority.visual_embedding_manifest_id,
        manifest_id=current_authority.manifest_id,
        rule_version=current_authority.rule_version,
    )


def resolve_appeal(
    current_authority: AppealVersionAuthority,
    command: AppealResolutionCommand,
) -> AppealVersionAuthority:
    """Perform UNDER_REVIEW -> UPHELD|OVERTURNED exactly once."""

    if not isinstance(current_authority, AppealVersionAuthority):
        raise TypeError("current_authority must be an AppealVersionAuthority")
    if not isinstance(command, AppealResolutionCommand):
        raise TypeError("command must be an AppealResolutionCommand")
    if (
        current_authority.version != 2
        or current_authority.appeal.status != AppealStatus.UNDER_REVIEW
    ):
        _fail(AppealTransitionFailureCode.TRANSITION_NOT_ALLOWED)
    if (
        command.run_id != current_authority.run_id
        or command.case_id != current_authority.appeal.case_id
        or command.appeal_id != current_authority.appeal.appeal_id
        or command.expected_appeal_version != current_authority.version
        or command.expected_appeal_authority_sha256 != current_authority.authority_sha256
    ):
        _fail(AppealTransitionFailureCode.AUTHORITY_MISMATCH)
    if command.reviewer_id != current_authority.assigned_reviewer_id:
        _fail(AppealTransitionFailureCode.REVIEWER_MISMATCH)
    decision_changed = command.resolved_decision != current_authority.source_decision
    if (command.status == AppealStatus.UPHELD and decision_changed) or (
        command.status == AppealStatus.OVERTURNED and not decision_changed
    ):
        _fail(AppealTransitionFailureCode.RESOLUTION_DECISION_INVALID)

    appeal = current_authority.appeal.model_copy(
        update={
            "status": command.status,
            "reviewer_id": command.reviewer_id,
            "resolution_summary": command.resolution_summary,
            "resolved_decision": command.resolved_decision,
        }
    )
    return AppealVersionAuthority(
        run_id=current_authority.run_id,
        appeal=appeal,
        version=3,
        previous_authority_sha256=current_authority.authority_sha256,
        assigned_reviewer_id=current_authority.assigned_reviewer_id,
        source_case_authority=current_authority.source_case_authority,
        source_case_revision=current_authority.source_case_revision,
        source_case_authority_sha256=current_authority.source_case_authority_sha256,
        source_verdict_id=current_authority.source_verdict_id,
        source_verdict_version=current_authority.source_verdict_version,
        source_verdict_sha256=current_authority.source_verdict_sha256,
        source_decision=current_authority.source_decision,
        text_embedding_manifest_id=current_authority.text_embedding_manifest_id,
        visual_embedding_manifest_id=current_authority.visual_embedding_manifest_id,
        manifest_id=current_authority.manifest_id,
        rule_version=current_authority.rule_version,
    )


__all__ = [
    "AppealTransitionError",
    "AppealTransitionFailureCode",
    "begin_appeal_review",
    "resolve_appeal",
    "submit_appeal",
]
