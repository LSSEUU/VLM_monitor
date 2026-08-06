"""Build one complete, storage-agnostic M5 appeal resolution intent."""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn

from labcourt.application.m5_appeal_precedent import (
    AppealPrecedentError,
    rebuild_appeal_overturn_precedent_nonpolicy_authority,
)
from labcourt.application.m5_human_labels import build_m5_appeal_training_labels
from labcourt.contracts.enums import (
    AppealStatus,
    PrecedentSource,
    PrecedentStatus,
)
from labcourt.contracts.m5_appeals import (
    MAX_M5_APPEAL_TRAINING_LABELS,
    AffectedCitationReport,
    AlertRescissionIntent,
    AppealResolutionCommand,
    AppealResolutionPrecedentSnapshot,
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    ClosedCaseAppealAuthority,
    PrecedentRevocationIntent,
    VerdictRescissionIntent,
)
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.domain.appeal_fsm import resolve_appeal
from labcourt.exceptions import ContractViolation, LabCourtError


class AppealResolutionFailureCode(StrEnum):
    CASE_AUTHORITY_MISMATCH = "CASE_AUTHORITY_MISMATCH"
    PRECEDENT_SNAPSHOT_MISMATCH = "PRECEDENT_SNAPSHOT_MISMATCH"
    AUTOMATIC_PRECEDENT_REQUIRED = "AUTOMATIC_PRECEDENT_REQUIRED"
    REPLACEMENT_PRECEDENT_INVALID = "REPLACEMENT_PRECEDENT_INVALID"
    TRAINING_LABELS_INVALID = "TRAINING_LABELS_INVALID"
    UPHELD_EFFECT_INVALID = "UPHELD_EFFECT_INVALID"


class AppealResolutionError(LabCourtError):
    def __init__(self, reason_code: AppealResolutionFailureCode) -> None:
        if not isinstance(reason_code, AppealResolutionFailureCode):
            raise TypeError("reason_code must be an AppealResolutionFailureCode")
        self.reason_code = reason_code
        super().__init__(f"appeal resolution build failed: {reason_code.value}")


def _fail(reason_code: AppealResolutionFailureCode) -> NoReturn:
    raise AppealResolutionError(reason_code)


def _validate_case_authority(
    case_authority: ClosedCaseAppealAuthority,
    appeal_authority: AppealVersionAuthority,
) -> None:
    if (
        case_authority != appeal_authority.source_case_authority
        or case_authority.run_id != appeal_authority.run_id
        or case_authority.case_id != appeal_authority.appeal.case_id
        or case_authority.case_revision != appeal_authority.source_case_revision
        or case_authority.authority_sha256 != appeal_authority.source_case_authority_sha256
        or case_authority.verdict_id != appeal_authority.source_verdict_id
        or case_authority.verdict_version != appeal_authority.source_verdict_version
        or case_authority.verdict_sha256 != appeal_authority.source_verdict_sha256
        or case_authority.final_decision != appeal_authority.source_decision
        or case_authority.text_embedding_manifest_id != appeal_authority.text_embedding_manifest_id
        or case_authority.visual_embedding_manifest_id
        != appeal_authority.visual_embedding_manifest_id
        or case_authority.manifest_id != appeal_authority.manifest_id
        or case_authority.rule_version != appeal_authority.rule_version
    ):
        _fail(AppealResolutionFailureCode.CASE_AUTHORITY_MISMATCH)


def _validate_training_labels(
    appeal_authority: AppealVersionAuthority,
    command: AppealResolutionCommand,
) -> None:
    if (
        not isinstance(command.training_labels, tuple)
        or len(command.training_labels) > MAX_M5_APPEAL_TRAINING_LABELS
    ):
        _fail(AppealResolutionFailureCode.TRAINING_LABELS_INVALID)
    if command.status == AppealStatus.OVERTURNED and not command.training_labels:
        _fail(AppealResolutionFailureCode.TRAINING_LABELS_INVALID)
    authored_inputs = tuple(
        M5AppealTrainingLabelInput(
            crop_id=label.crop_id,
            bbox=label.bbox,
            label_name=label.label_name,
            label_value=label.label_value,
        )
        for label in command.training_labels
    )
    try:
        trusted_labels = build_m5_appeal_training_labels(
            appeal_authority=appeal_authority,
            terminal_status=command.status,
            authored_inputs=authored_inputs,
        )
    except (ContractViolation, TypeError, ValueError):
        _fail(AppealResolutionFailureCode.TRAINING_LABELS_INVALID)
    if command.training_labels != trusted_labels:
        _fail(AppealResolutionFailureCode.TRAINING_LABELS_INVALID)


def _validate_precedent_snapshot(
    case_authority: ClosedCaseAppealAuthority,
    precedent_snapshot: AppealResolutionPrecedentSnapshot,
) -> None:
    if (
        precedent_snapshot.run_id != case_authority.run_id
        or precedent_snapshot.case_id != case_authority.case_id
        or any(
            item.decision_direction != case_authority.final_decision
            for item in precedent_snapshot.automatic_precedents
        )
    ):
        _fail(AppealResolutionFailureCode.PRECEDENT_SNAPSHOT_MISMATCH)


def _validate_replacement_precedent(
    case_authority: ClosedCaseAppealAuthority,
    precedent_snapshot: AppealResolutionPrecedentSnapshot,
    command: AppealResolutionCommand,
) -> None:
    authority = command.appeal_precedent_authority
    if authority is None:
        _fail(AppealResolutionFailureCode.REPLACEMENT_PRECEDENT_INVALID)
    try:
        rebuilt = rebuild_appeal_overturn_precedent_nonpolicy_authority(
            case_authority=case_authority,
            appeal_id=command.appeal_id,
            resolved_decision=command.resolved_decision,
            proposed=authority,
        )
    except AppealPrecedentError:
        _fail(AppealResolutionFailureCode.REPLACEMENT_PRECEDENT_INVALID)
    if rebuilt != authority:
        _fail(AppealResolutionFailureCode.REPLACEMENT_PRECEDENT_INVALID)
    precedent = authority.precedent
    revoked_ids = {item.precedent_id for item in precedent_snapshot.automatic_precedents}
    if (
        authority.run_id != case_authority.run_id
        or authority.config_sha256 != case_authority.config_sha256
        or authority.revision != 1
        or authority.text_embedding is None
        or authority.text_embedding.request.model_manifest_id
        != case_authority.text_embedding_manifest_id
        or any(
            embedding.request.model_manifest_id != case_authority.visual_embedding_manifest_id
            for embedding in authority.visual_embeddings
        )
        or precedent.precedent_id in revoked_ids
        or precedent.source != PrecedentSource.APPEAL_OVERTURN
        or precedent.status != PrecedentStatus.ACTIVE
        or precedent.decision_direction != command.resolved_decision
        or precedent.source_case_id != case_authority.case_id
        or precedent.evidence_class != case_authority.evidence_class
        or precedent.violation_type != case_authority.violation_type
        or precedent.rule_version != case_authority.rule_version
    ):
        _fail(AppealResolutionFailureCode.REPLACEMENT_PRECEDENT_INVALID)


def build_appeal_resolution_intent(
    *,
    case_authority: ClosedCaseAppealAuthority,
    appeal_authority: AppealVersionAuthority,
    precedent_snapshot: AppealResolutionPrecedentSnapshot,
    command: AppealResolutionCommand,
) -> AppealResolutionSideEffectIntent:
    """Resolve one appeal and materialize every required atomic side effect."""

    if not isinstance(case_authority, ClosedCaseAppealAuthority):
        raise TypeError("case_authority must be a ClosedCaseAppealAuthority")
    if not isinstance(appeal_authority, AppealVersionAuthority):
        raise TypeError("appeal_authority must be an AppealVersionAuthority")
    if not isinstance(precedent_snapshot, AppealResolutionPrecedentSnapshot):
        raise TypeError("precedent_snapshot must be an AppealResolutionPrecedentSnapshot")
    if not isinstance(command, AppealResolutionCommand):
        raise TypeError("command must be an AppealResolutionCommand")
    _validate_case_authority(case_authority, appeal_authority)
    _validate_precedent_snapshot(case_authority, precedent_snapshot)
    _validate_training_labels(appeal_authority, command)
    terminal = resolve_appeal(appeal_authority, command)

    if command.status == AppealStatus.UPHELD:
        if command.appeal_precedent_authority is not None:
            _fail(AppealResolutionFailureCode.UPHELD_EFFECT_INVALID)
        return AppealResolutionSideEffectIntent(
            run_id=case_authority.run_id,
            case_id=case_authority.case_id,
            expected_case_revision=case_authority.case_revision,
            appeal_authority=terminal,
            source_verdict_id=case_authority.verdict_id,
            source_decision=case_authority.final_decision,
            precedent_snapshot=precedent_snapshot,
            final_decision=command.resolved_decision,
            training_labels=command.training_labels,
            affected_citations=AffectedCitationReport(),
            text_embedding_manifest_id=case_authority.text_embedding_manifest_id,
            visual_embedding_manifest_id=case_authority.visual_embedding_manifest_id,
            manifest_id=case_authority.manifest_id,
            rule_version=case_authority.rule_version,
        )

    if not precedent_snapshot.automatic_precedents:
        _fail(AppealResolutionFailureCode.AUTOMATIC_PRECEDENT_REQUIRED)
    _validate_replacement_precedent(case_authority, precedent_snapshot, command)
    revocations = tuple(
        PrecedentRevocationIntent(
            precedent_id=item.precedent_id,
            prior_authority_id=item.precedent_authority_id,
            prior_revision=item.precedent_revision,
            previous_status=item.status,
        )
        for item in precedent_snapshot.automatic_precedents
    )
    citations = tuple(
        sorted(
            (
                citation
                for precedent in precedent_snapshot.automatic_precedents
                for citation in precedent.citations
            ),
            key=lambda item: item.sort_key,
        )
    )
    revoked_ids = tuple(item.precedent_id for item in revocations)
    return AppealResolutionSideEffectIntent(
        run_id=case_authority.run_id,
        case_id=case_authority.case_id,
        expected_case_revision=case_authority.case_revision,
        appeal_authority=terminal,
        source_verdict_id=case_authority.verdict_id,
        source_decision=case_authority.final_decision,
        precedent_snapshot=precedent_snapshot,
        verdict_rescission=VerdictRescissionIntent(
            verdict_id=case_authority.verdict_id,
            verdict_version=case_authority.verdict_version,
            verdict_sha256=case_authority.verdict_sha256,
        ),
        alert_rescissions=tuple(
            AlertRescissionIntent(alert_id=item.alert_id) for item in case_authority.alerts
        ),
        final_decision=command.resolved_decision,
        precedent_revocations=revocations,
        appeal_precedent_authority=command.appeal_precedent_authority,
        training_labels=command.training_labels,
        affected_citations=AffectedCitationReport(
            revoked_precedent_ids=revoked_ids,
            citations=citations,
        ),
        text_embedding_manifest_id=case_authority.text_embedding_manifest_id,
        visual_embedding_manifest_id=case_authority.visual_embedding_manifest_id,
        manifest_id=case_authority.manifest_id,
        rule_version=case_authority.rule_version,
    )


__all__ = [
    "AppealResolutionError",
    "AppealResolutionFailureCode",
    "build_appeal_resolution_intent",
]
