"""Build one exact M5 alert-policy causal cut from a typed source observation."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertPolicyAuthority,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_policy import (
    MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES,
    M6ReplayLockedAlertPolicyCausalCutAuthority,
    M6ReplayLockedCooldownCausalBasis,
    M6ReplayLockedCooldownCausalHead,
    M6ReplayLockedCooldownHistoryEntry,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
    M6ReplayLockedCooldownHistoryRowObservation,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedPolicySourceBuildErrorCode(StrEnum):
    """Closed failure vocabulary without source documents or database details."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    SNAPSHOT_IDENTITY_MISMATCH = "SNAPSHOT_IDENTITY_MISMATCH"
    SOURCE_VALIDATION_FAILED = "SOURCE_VALIDATION_FAILED"
    SOURCE_SCOPE_MISMATCH = "SOURCE_SCOPE_MISMATCH"
    COOLDOWN_HISTORY_MISMATCH = "COOLDOWN_HISTORY_MISMATCH"
    CAUSAL_CUT_INVALID = "CAUSAL_CUT_INVALID"


class M6ReplayLockedPolicySourceBuildError(LabCourtError):
    """Typed, payload-free failure while constructing the policy causal cut."""

    def __init__(self, code: M6ReplayLockedPolicySourceBuildErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedPolicySourceBuildErrorCode):
            raise TypeError("code must be an M6ReplayLockedPolicySourceBuildErrorCode")
        self.code = code
        super().__init__(f"M6 locked policy source build failed: {code.value}")


def _fail(code: M6ReplayLockedPolicySourceBuildErrorCode) -> NoReturn:
    raise M6ReplayLockedPolicySourceBuildError(code) from None


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _canonical_model(
    value: object,
    model_type: type[_ModelT],
) -> _ModelT:
    if type(value) is not model_type:
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.INVALID_ARGUMENT)
    try:
        controlled = model_type.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.DOCUMENT_INVALID)
    if controlled != value:
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.DOCUMENT_INVALID)
    return controlled


def _all_documents(
    observation: M6ReplayLockedAlertPolicySourceObservation,
) -> tuple[str, ...]:
    return (
        observation.replay_input_closure_canonical_document,
        observation.source_validation_report_canonical_document,
        observation.source_ready_case_canonical_document,
        observation.source_closed_case_canonical_document,
        observation.source_alert_policy_canonical_document,
        observation.closing_audit_entry_canonical_document,
        *(item.authority_canonical_document for item in observation.cooldown_eligible_history_rows),
    )


def _require_budget(observation: M6ReplayLockedAlertPolicySourceObservation) -> None:
    documents = _all_documents(observation)
    if any(not isinstance(document, str) for document in documents):
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.INVALID_ARGUMENT)
    total = sum(len(document.encode("utf-8")) for document in documents)
    if total > MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES:
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.DOCUMENT_TOO_LARGE)


def _require_document(model: BaseModel, document: str) -> str:
    expected = _document(model)
    if document != expected:
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.DOCUMENT_INVALID)
    return _sha256(document)


def _controlled_observation(
    value: object,
) -> tuple[
    M6ReplayLockedAlertPolicySourceObservation,
    M6ReplayInputClosureAuthority,
    M5ArtifactValidationReport,
    Case,
    Case,
    AlertPolicyAuthority,
    AuditEntry,
]:
    if type(value) is not M6ReplayLockedAlertPolicySourceObservation:
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.INVALID_ARGUMENT)
    observation = value
    _require_budget(observation)
    closure = _canonical_model(observation.replay_input_closure, M6ReplayInputClosureAuthority)
    report = _canonical_model(observation.source_validation_report, M5ArtifactValidationReport)
    ready = _canonical_model(observation.source_ready_case, Case)
    closed = _canonical_model(observation.source_closed_case, Case)
    policy = _canonical_model(observation.source_alert_policy, AlertPolicyAuthority)
    audit = _canonical_model(observation.closing_audit_entry, AuditEntry)
    _require_document(closure, observation.replay_input_closure_canonical_document)
    _require_document(report, observation.source_validation_report_canonical_document)
    _require_document(ready, observation.source_ready_case_canonical_document)
    _require_document(closed, observation.source_closed_case_canonical_document)
    _require_document(policy, observation.source_alert_policy_canonical_document)
    _require_document(audit, observation.closing_audit_entry_canonical_document)
    return observation, closure, report, ready, closed, policy, audit


def _require_source_scope(
    observation: M6ReplayLockedAlertPolicySourceObservation,
    closure: M6ReplayInputClosureAuthority,
    report: M5ArtifactValidationReport,
    ready: Case,
    closed: Case,
    policy: AlertPolicyAuthority,
) -> None:
    report_document_sha256 = _sha256(observation.source_validation_report_canonical_document)
    closed_document_sha256 = _sha256(observation.source_closed_case_canonical_document)
    if not report.passed or report.authority_root_sha256 is None:
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.SOURCE_VALIDATION_FAILED)
    if report.authority_root_sha256 != observation.source_m5_authority_root_sha256:
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.SOURCE_VALIDATION_FAILED)
    if (
        closure.source_case_id is None
        or closure.source_case_revision is None
        or closure.source_case_document_sha256 is None
        or closure.sample_id == ""
        or closure.source_run_id != ready.run_id
        or closure.source_run_id != closed.run_id
        or closure.source_case_id != ready.case_id
        or closure.source_case_id != closed.case_id
        or closure.source_case_revision != observation.source_closed_case_revision
        or closure.source_case_document_sha256 != closed_document_sha256
        or closure.source_manifest_id != ready.manifest_id
        or closure.source_manifest_id != closed.manifest_id
        or closure.source_validation_report_id != report.report_id
        or closure.source_validation_report_document_sha256 != report_document_sha256
        or report.run_id != ready.run_id
        or report.manifest_id != ready.manifest_id
        or report.config_sha256 != policy.request.config_sha256
        or policy.request.run_id != ready.run_id
        or policy.request.case_id != ready.case_id
        or policy.request.manifest_id != ready.manifest_id
        or observation.source_closed_case_revision != observation.source_ready_case_revision + 1
    ):
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.SOURCE_SCOPE_MISMATCH)


def _history_entries(
    observation: M6ReplayLockedAlertPolicySourceObservation,
    *,
    policy: AlertPolicyAuthority,
    source_close_audit_sequence: int,
) -> tuple[M6ReplayLockedCooldownHistoryEntry, ...]:
    rows = observation.cooldown_eligible_history_rows
    if any(type(row) is not M6ReplayLockedCooldownHistoryRowObservation for row in rows):
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.INVALID_ARGUMENT)
    if any(row.source_identity_sha256 != observation.source_identity_sha256 for row in rows):
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
    authorities: list[AlertCooldownAuthority] = []
    for row in rows:
        authority = _canonical_model(row.authority, AlertCooldownAuthority)
        _require_document(authority, row.authority_canonical_document)
        authorities.append(authority)

    revisions = tuple(row.revision for row in rows)
    sequences = tuple(row.writer_close_audit_sequence for row in rows)
    request = policy.request
    expected_key = (
        None
        if request.primary_track_ref is None
        else AlertCooldownKey(
            zone_id=request.zone_id,
            violation_type=request.violation_type,
            track_ref=request.primary_track_ref,
        )
    )
    expected_prior = authorities[-1] if authorities else None
    invalid_history = (
        revisions != tuple(range(1, len(rows) + 1))
        or sequences != tuple(sorted(set(sequences)))
        or any(sequence >= source_close_audit_sequence for sequence in sequences)
        or len({row.writer_close_audit_entry_hash for row in rows}) != len(rows)
        or len({row.writer_alert_policy_authority_id for row in rows}) != len(rows)
        or (expected_key is None and bool(rows))
        or any(
            authority.key != expected_key or authority.stream_id != request.stream_id
            for authority in authorities
        )
        or request.prior_cooldown != expected_prior
    )
    if invalid_history:
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.COOLDOWN_HISTORY_MISMATCH)
    try:
        return tuple(
            M6ReplayLockedCooldownHistoryEntry(
                revision=row.revision,
                writer_close_audit_sequence=row.writer_close_audit_sequence,
                writer_close_audit_entry_hash=row.writer_close_audit_entry_hash,
                writer_alert_policy_authority_id=row.writer_alert_policy_authority_id,
                authority=authority,
            )
            for row, authority in zip(rows, authorities, strict=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.COOLDOWN_HISTORY_MISMATCH)


def build_m6_replay_locked_alert_policy_causal_cut(
    *,
    observation: object,
) -> M6ReplayLockedAlertPolicyCausalCutAuthority:
    """Build the immutable policy cut without trusting caller-supplied roots."""

    (
        controlled,
        closure,
        report,
        ready,
        closed,
        policy,
        audit,
    ) = _controlled_observation(observation)
    _require_source_scope(controlled, closure, report, ready, closed, policy)
    history = _history_entries(
        controlled,
        policy=policy,
        source_close_audit_sequence=audit.sequence,
    )
    request = policy.request
    key = (
        None
        if request.primary_track_ref is None
        else AlertCooldownKey(
            zone_id=request.zone_id,
            violation_type=request.violation_type,
            track_ref=request.primary_track_ref,
        )
    )
    if key is None:
        basis = M6ReplayLockedCooldownCausalBasis.UNTRACKED
    elif request.prior_cooldown is None:
        basis = M6ReplayLockedCooldownCausalBasis.EMPTY_HISTORY
    else:
        basis = M6ReplayLockedCooldownCausalBasis.EXACT_PRIOR
    prior_revision = history[-1].revision if history else 0
    try:
        cooldown_head = M6ReplayLockedCooldownCausalHead(
            source_run_id=ready.run_id,
            basis=basis,
            source_close_audit_sequence=audit.sequence,
            source_close_audit_entry_hash=audit.entry_hash,
            key=key,
            prior_revision=prior_revision,
            prior_authority=request.prior_cooldown,
            eligible_history=history,
        )
        cut = M6ReplayLockedAlertPolicyCausalCutAuthority(
            source_identity_sha256=controlled.source_identity_sha256,
            sample_id=closure.sample_id,
            replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
            replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
            source_validation_report_id=report.report_id,
            source_validation_report_document_sha256=_sha256(
                controlled.source_validation_report_canonical_document
            ),
            source_m5_authority_root_sha256=(controlled.source_m5_authority_root_sha256),
            source_config_sha256=report.config_sha256,
            source_ready_case_revision=controlled.source_ready_case_revision,
            source_ready_case=ready,
            source_closed_case_revision=controlled.source_closed_case_revision,
            source_closed_case=closed,
            source_alert_policy=policy,
            closing_audit_entry=audit,
            cooldown_causal_head=cooldown_head,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.CAUSAL_CUT_INVALID)
    if len(_document(cut).encode("utf-8")) > MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES:
        _fail(M6ReplayLockedPolicySourceBuildErrorCode.DOCUMENT_TOO_LARGE)
    return cut


__all__ = [
    "M6ReplayLockedPolicySourceBuildError",
    "M6ReplayLockedPolicySourceBuildErrorCode",
    "build_m6_replay_locked_alert_policy_causal_cut",
]
