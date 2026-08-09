"""Restart-safe command orchestration for the M5 human appeal lifecycle."""

from __future__ import annotations

from enum import StrEnum

from labcourt.application.appeal_resolution import build_appeal_resolution_intent
from labcourt.contracts.enums import AppealStatus
from labcourt.contracts.m5_appeal_operations import (
    M5AppealResolutionCommandReport,
    M5AppealReviewCommandReport,
    M5AppealSubmissionCommandReport,
)
from labcourt.contracts.m5_appeals import (
    MAX_M5_APPEAL_TRAINING_LABELS,
    AppealResolutionCommand,
    AppealResolutionSideEffectIntent,
    AppealReviewCommand,
    AppealSubmissionCommand,
    AppealVersionAuthority,
)
from labcourt.domain.appeal_fsm import (
    begin_appeal_review,
    resolve_appeal,
    submit_appeal,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.appeals import AppealRepository


class M5AppealOperationsErrorCode(StrEnum):
    APPEAL_NOT_FOUND = "APPEAL_NOT_FOUND"
    CURRENT_AUTHORITY_MISMATCH = "CURRENT_AUTHORITY_MISMATCH"
    COMMIT_RESULT_INVALID = "COMMIT_RESULT_INVALID"
    RESOLUTION_COMMAND_INVALID = "RESOLUTION_COMMAND_INVALID"
    TERMINAL_COMMAND_CONFLICT = "TERMINAL_COMMAND_CONFLICT"


class M5AppealOperationsError(LabCourtError):
    def __init__(self, code: M5AppealOperationsErrorCode) -> None:
        if not isinstance(code, M5AppealOperationsErrorCode):
            raise TypeError("code must be an M5AppealOperationsErrorCode")
        self.code = code
        super().__init__(f"M5 appeal operation failed: {code.value}")


def _submission_report(
    authority: AppealVersionAuthority,
) -> M5AppealSubmissionCommandReport:
    if authority.version != 1 or authority.appeal.status != AppealStatus.SUBMITTED:
        raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID)
    return M5AppealSubmissionCommandReport(
        run_id=authority.run_id,
        case_id=authority.appeal.case_id,
        appeal_id=authority.appeal.appeal_id,
        source_case_revision=authority.source_case_revision,
        committed_case_revision=authority.source_case_revision + 1,
        appeal_authority_sha256=authority.authority_sha256,
    )


def _review_report(authority: AppealVersionAuthority) -> M5AppealReviewCommandReport:
    predecessor = authority.previous_authority_sha256
    reviewer_id = authority.assigned_reviewer_id
    if (
        authority.version != 2
        or authority.appeal.status != AppealStatus.UNDER_REVIEW
        or predecessor is None
        or reviewer_id is None
    ):
        raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID)
    return M5AppealReviewCommandReport(
        run_id=authority.run_id,
        case_id=authority.appeal.case_id,
        appeal_id=authority.appeal.appeal_id,
        source_case_revision=authority.source_case_revision,
        committed_case_revision=authority.source_case_revision + 2,
        reviewer_id=reviewer_id,
        previous_appeal_authority_sha256=predecessor,
        appeal_authority_sha256=authority.authority_sha256,
    )


def build_m5_appeal_resolution_report(
    intent: AppealResolutionSideEffectIntent,
) -> M5AppealResolutionCommandReport:
    """Project a validated durable terminal intent into its stable command report."""

    authority = intent.appeal_authority
    appeal = authority.appeal
    predecessor = authority.previous_authority_sha256
    reviewer_id = authority.assigned_reviewer_id
    replacement = intent.appeal_precedent_authority
    if (
        authority.version != 3
        or appeal.status not in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
        or predecessor is None
        or reviewer_id is None
    ):
        raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID)
    return M5AppealResolutionCommandReport(
        run_id=intent.run_id,
        case_id=intent.case_id,
        appeal_id=appeal.appeal_id,
        source_case_revision=authority.source_case_revision,
        committed_case_revision=authority.source_case_revision + 3,
        status=appeal.status,
        reviewer_id=reviewer_id,
        source_decision=intent.source_decision,
        final_decision=intent.final_decision,
        previous_appeal_authority_sha256=predecessor,
        appeal_authority_sha256=authority.authority_sha256,
        precedent_snapshot_sha256=intent.precedent_snapshot.snapshot_sha256,
        affected_citation_report_sha256=intent.affected_citations.report_sha256,
        resolution_intent_id=intent.intent_id,
        rescinded_alert_ids=tuple(sorted(item.alert_id for item in intent.alert_rescissions)),
        revoked_precedent_ids=tuple(
            sorted(item.precedent_id for item in intent.precedent_revocations)
        ),
        replacement_precedent_id=(
            replacement.precedent.precedent_id if replacement is not None else None
        ),
        training_label_ids=tuple(sorted(item.label_id for item in intent.training_labels)),
        affected_citation_case_ids=tuple(
            sorted({item.citing_case_id for item in intent.affected_citations.citations})
        ),
    )


def _validated_resolution_command(
    command: AppealResolutionCommand,
) -> AppealResolutionCommand:
    """Revalidate unchecked Pydantic instances before crossing the application boundary."""

    try:
        if (
            not isinstance(command.training_labels, tuple)
            or len(command.training_labels) > MAX_M5_APPEAL_TRAINING_LABELS
        ):
            raise ValueError("appeal resolution training labels exceed their contract")
        validated = AppealResolutionCommand.model_validate(
            command.model_dump(
                mode="python",
                exclude_computed_fields=True,
                round_trip=True,
            )
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise M5AppealOperationsError(
            M5AppealOperationsErrorCode.RESOLUTION_COMMAND_INVALID
        ) from exc
    if validated != command:
        raise M5AppealOperationsError(M5AppealOperationsErrorCode.RESOLUTION_COMMAND_INVALID)
    return validated


def _resolution_command_from_receipt(
    intent: AppealResolutionSideEffectIntent,
    current: AppealVersionAuthority,
) -> AppealResolutionCommand:
    """Recover every submitted resolution fact from its durable terminal receipt."""

    terminal = intent.appeal_authority
    appeal = terminal.appeal
    predecessor = terminal.previous_authority_sha256
    reviewer_id = appeal.reviewer_id
    summary = appeal.resolution_summary
    decision = appeal.resolved_decision
    if (
        terminal != current
        or terminal.version != 3
        or intent.run_id != current.run_id
        or intent.case_id != appeal.case_id
        or appeal.status not in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
        or predecessor is None
        or reviewer_id is None
        or reviewer_id != terminal.assigned_reviewer_id
        or summary is None
        or decision is None
    ):
        raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID)
    try:
        return AppealResolutionCommand(
            run_id=intent.run_id,
            case_id=intent.case_id,
            appeal_id=appeal.appeal_id,
            expected_appeal_authority_sha256=predecessor,
            status=appeal.status,
            reviewer_id=reviewer_id,
            resolution_summary=summary,
            resolved_decision=decision,
            appeal_precedent_authority=intent.appeal_precedent_authority,
            training_labels=intent.training_labels,
        )
    except (TypeError, ValueError) as exc:
        raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID) from exc


class M5AppealOperationsCoordinator:
    """Coordinate explicit human commands over one appeal repository."""

    def __init__(self, repository: AppealRepository) -> None:
        self._repository = repository

    def submit(
        self,
        command: AppealSubmissionCommand,
    ) -> M5AppealSubmissionCommandReport:
        if not isinstance(command, AppealSubmissionCommand):
            raise TypeError("command must be an AppealSubmissionCommand")
        source = self._repository.load_closed_case_authority(command.run_id, command.case_id)
        current = self._repository.load_current_appeal(command.run_id, command.case_id)
        proposed = submit_appeal(source, command, None)
        if current is not None:
            if current == proposed:
                return _submission_report(current)
            submit_appeal(source, command, current)
            raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID)
        committed = self._repository.append_appeal_version(proposed, None)
        if committed != proposed:
            raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID)
        return _submission_report(committed)

    def begin_review(
        self,
        command: AppealReviewCommand,
    ) -> M5AppealReviewCommandReport:
        if not isinstance(command, AppealReviewCommand):
            raise TypeError("command must be an AppealReviewCommand")
        current = self._load_current_by_id(command.run_id, command.appeal_id)
        if (
            current.version == 2
            and current.appeal.status == AppealStatus.UNDER_REVIEW
            and current.run_id == command.run_id
            and current.appeal.case_id == command.case_id
            and current.appeal.appeal_id == command.appeal_id
            and current.previous_authority_sha256 == command.expected_appeal_authority_sha256
            and current.assigned_reviewer_id == command.reviewer_id
        ):
            return _review_report(current)
        proposed = begin_appeal_review(current, command)
        committed = self._repository.append_appeal_version(
            proposed,
            current.authority_sha256,
        )
        if committed != proposed:
            raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID)
        return _review_report(committed)

    def resolve(
        self,
        command: AppealResolutionCommand,
    ) -> M5AppealResolutionCommandReport:
        if not isinstance(command, AppealResolutionCommand):
            raise TypeError("command must be an AppealResolutionCommand")
        command = _validated_resolution_command(command)
        current = self._load_current_by_id(command.run_id, command.appeal_id)

        if current.version == 3:
            receipt = self._repository.load_resolution(command.run_id, command.appeal_id)
            if receipt is None:
                raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID)
            durable_command = _resolution_command_from_receipt(receipt, current)
            if command != durable_command:
                raise M5AppealOperationsError(M5AppealOperationsErrorCode.TERMINAL_COMMAND_CONFLICT)
            return build_m5_appeal_resolution_report(receipt)

        # Only a non-terminal authority may enter the FSM and capture fresh effects.
        resolve_appeal(current, command)
        source = self._repository.load_closed_case_authority(
            command.run_id,
            command.case_id,
        )
        if source != current.source_case_authority:
            raise M5AppealOperationsError(M5AppealOperationsErrorCode.CURRENT_AUTHORITY_MISMATCH)
        snapshot = self._repository.load_resolution_precedent_snapshot(
            command.run_id,
            command.case_id,
        )
        intent = build_appeal_resolution_intent(
            case_authority=source,
            appeal_authority=current,
            precedent_snapshot=snapshot,
            command=command,
        )
        committed = self._repository.commit_resolution(intent)
        if committed != intent:
            raise M5AppealOperationsError(M5AppealOperationsErrorCode.COMMIT_RESULT_INVALID)
        return build_m5_appeal_resolution_report(committed)

    def _load_current_by_id(
        self,
        run_id: str,
        appeal_id: str,
    ) -> AppealVersionAuthority:
        by_id = self._repository.load_appeal_by_id(run_id, appeal_id)
        if by_id is None:
            raise M5AppealOperationsError(M5AppealOperationsErrorCode.APPEAL_NOT_FOUND)
        by_case = self._repository.load_current_appeal(run_id, by_id.appeal.case_id)
        if by_case != by_id:
            raise M5AppealOperationsError(M5AppealOperationsErrorCode.CURRENT_AUTHORITY_MISMATCH)
        return by_id


__all__ = [
    "M5AppealOperationsCoordinator",
    "M5AppealOperationsError",
    "M5AppealOperationsErrorCode",
    "build_m5_appeal_resolution_report",
]
