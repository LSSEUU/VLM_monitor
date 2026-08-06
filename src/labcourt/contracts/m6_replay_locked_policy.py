"""Exact causal source authority for M6 locked alert-policy replay.

The frozen replay-input closure intentionally excludes alert outputs.  This
independent M6 authority binds the validated M5 READY -> CLOSED transition and
the exact cooldown head that the deterministic policy consumed, without
changing the existing closure or source-seal wire identities.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal, Self, TypeVar

from pydantic import (
    BaseModel,
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertPolicyAuthority,
    AlertPolicyDisposition,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef

MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES = 64 * 1024 * 1024
MAX_M6_REPLAY_LOCKED_COOLDOWN_HISTORY_ENTRIES = 10_000
M6_REPLAY_LOCKED_EMERGENCY_CAUSAL_BASIS: Literal["DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY"] = (
    "DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY"
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _pop_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    if not claims:
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M6 policy content")


def _canonical_nested(model_type: type[_ModelT], value: object, label: str) -> _ModelT:
    if type(value) is not model_type:
        raise ValueError(f"{label} must use its exact canonical type")
    controlled = model_type.model_validate(
        value.model_dump(mode="json", exclude_computed_fields=True)
    )
    if controlled != value:
        raise ValueError(f"{label} must use its exact canonical type")
    return controlled


def _document_sha256(value: BaseModel) -> Sha256Hex:
    document = canonical_json(value.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


class M6ReplayLockedCooldownCausalBasis(StrEnum):
    """Why the source policy received this exact prior cooldown value."""

    UNTRACKED = "UNTRACKED"
    EMPTY_HISTORY = "EMPTY_HISTORY"
    EXACT_PRIOR = "EXACT_PRIOR"


class M6ReplayLockedCooldownHistoryEntry(FrozenContractModel):
    """One prior cooldown row and the exact earlier close that wrote it."""

    schema_version: Literal["m6-replay-locked-cooldown-history-entry-v1"] = (
        "m6-replay-locked-cooldown-history-entry-v1"
    )
    revision: int = Field(gt=0, strict=True)
    writer_close_audit_sequence: int = Field(ge=0, strict=True)
    writer_close_audit_entry_hash: Sha256Hex
    writer_alert_policy_authority_id: Sha256Hex
    authority: AlertCooldownAuthority

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "authority_content_sha256",
                "history_entry_id",
            ),
        )
        entry = handler(payload)
        _verify_claims(entry, claims)
        return entry

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        authority = _canonical_nested(
            AlertCooldownAuthority,
            self.authority,
            "M6 cooldown history authority",
        )
        object.__setattr__(self, "authority", authority)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_content_sha256(self) -> Sha256Hex:
        return _document_sha256(self.authority)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def history_entry_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-cooldown-history-entry",
                1,
                self.revision,
                self.writer_close_audit_sequence,
                self.writer_close_audit_entry_hash,
                self.writer_alert_policy_authority_id,
                self.authority.authority_id,
                self.authority_content_sha256,
            ]
        )


class M6ReplayLockedCooldownCausalHead(FrozenContractModel):
    """Snapshot-scoped cooldown head immediately before one Case close."""

    schema_version: Literal["m6-replay-locked-cooldown-causal-head-v1"] = (
        "m6-replay-locked-cooldown-causal-head-v1"
    )
    source_run_id: ReferenceToken
    basis: M6ReplayLockedCooldownCausalBasis
    source_close_audit_sequence: int = Field(ge=0, strict=True)
    source_close_audit_entry_hash: Sha256Hex
    key: AlertCooldownKey | None = None
    prior_revision: int = Field(ge=0, strict=True)
    prior_authority: AlertCooldownAuthority | None = None
    eligible_history: tuple[M6ReplayLockedCooldownHistoryEntry, ...] = Field(
        max_length=MAX_M6_REPLAY_LOCKED_COOLDOWN_HISTORY_ENTRIES,
    )

    @field_validator("source_run_id")
    @classmethod
    def validate_source_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 cooldown source run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "eligible_count",
                "eligible_inventory_root_sha256",
                "causal_head_id",
            ),
        )
        head = handler(payload)
        _verify_claims(head, claims)
        return head

    @model_validator(mode="after")
    def validate_exact_head(self) -> Self:
        key = (
            None
            if self.key is None
            else _canonical_nested(AlertCooldownKey, self.key, "M6 cooldown key")
        )
        prior = (
            None
            if self.prior_authority is None
            else _canonical_nested(
                AlertCooldownAuthority,
                self.prior_authority,
                "M6 prior cooldown authority",
            )
        )
        history = tuple(
            _canonical_nested(
                M6ReplayLockedCooldownHistoryEntry,
                item,
                "M6 cooldown history entry",
            )
            for item in self.eligible_history
        )
        revisions = tuple(item.revision for item in history)
        writer_sequences = tuple(item.writer_close_audit_sequence for item in history)
        if revisions != tuple(range(1, len(history) + 1)):
            raise ValueError("M6 cooldown eligible history revisions must be contiguous")
        if writer_sequences != tuple(sorted(set(writer_sequences))) or any(
            sequence >= self.source_close_audit_sequence for sequence in writer_sequences
        ):
            raise ValueError("M6 cooldown eligible writers must precede the source close")
        if len({item.writer_close_audit_entry_hash for item in history}) != len(history):
            raise ValueError("M6 cooldown eligible writer audit identities must be unique")
        if len({item.writer_alert_policy_authority_id for item in history}) != len(history):
            raise ValueError("M6 cooldown eligible writer policy identities must be unique")
        if key is not None and any(item.authority.key != key for item in history):
            raise ValueError("M6 cooldown eligible history contains another key")
        if self.basis == M6ReplayLockedCooldownCausalBasis.UNTRACKED:
            if key is not None or self.prior_revision != 0 or prior is not None or history:
                raise ValueError("UNTRACKED cooldown head cannot carry a key or prior authority")
        elif self.basis == M6ReplayLockedCooldownCausalBasis.EMPTY_HISTORY:
            if key is None or self.prior_revision != 0 or prior is not None or history:
                raise ValueError("EMPTY_HISTORY cooldown head requires one key and revision zero")
        elif (
            key is None
            or self.prior_revision <= 0
            or prior is None
            or prior.key != key
            or not history
            or self.prior_revision != history[-1].revision
            or prior != history[-1].authority
        ):
            raise ValueError("EXACT_PRIOR cooldown head requires its exact positive revision")
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "prior_authority", prior)
        object.__setattr__(self, "eligible_history", history)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def eligible_count(self) -> int:
        return len(self.eligible_history)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def eligible_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-cooldown-eligible-inventory",
                1,
                [item.history_entry_id for item in self.eligible_history],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def causal_head_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-cooldown-causal-head",
                1,
                self.source_run_id,
                self.basis,
                self.source_close_audit_sequence,
                self.source_close_audit_entry_hash,
                self.key.key_id if self.key is not None else None,
                self.prior_revision,
                (self.prior_authority.authority_id if self.prior_authority is not None else None),
                (
                    _document_sha256(self.prior_authority)
                    if self.prior_authority is not None
                    else None
                ),
                self.eligible_count,
                self.eligible_inventory_root_sha256,
            ]
        )


class M6ReplayLockedAlertPolicyCausalCutAuthority(FrozenContractModel):
    """Complete M5 alert-policy source cut for one locked CLOSED replay."""

    schema_version: Literal["m6-replay-locked-alert-policy-causal-cut-v1"] = (
        "m6-replay-locked-alert-policy-causal-cut-v1"
    )
    source_identity_sha256: Sha256Hex
    sample_id: ReferenceToken
    replay_input_closure_authority_id: Sha256Hex
    replay_input_closure_document_sha256: Sha256Hex
    source_validation_report_id: Sha256Hex
    source_validation_report_document_sha256: Sha256Hex
    source_m5_authority_root_sha256: Sha256Hex
    source_config_sha256: Sha256Hex
    source_ready_case_revision: int = Field(gt=0, strict=True)
    source_ready_case: Case
    source_closed_case_revision: int = Field(gt=0, strict=True)
    source_closed_case: Case
    source_alert_policy: AlertPolicyAuthority
    closing_audit_entry: AuditEntry
    cooldown_causal_head: M6ReplayLockedCooldownCausalHead
    emergency_causal_basis: Literal["DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY"] = (
        M6_REPLAY_LOCKED_EMERGENCY_CAUSAL_BASIS
    )

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 locked policy sample_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "source_ready_case_content_sha256",
                "source_closed_case_content_sha256",
                "source_alert_policy_content_sha256",
                "closing_audit_content_sha256",
                "policy_causal_cut_authority_id",
            ),
        )
        cut = handler(payload)
        _verify_claims(cut, claims)
        return cut

    @model_validator(mode="after")
    def validate_complete_policy_cut(self) -> Self:
        ready = _canonical_nested(Case, self.source_ready_case, "M6 policy READY Case")
        closed = _canonical_nested(Case, self.source_closed_case, "M6 policy CLOSED Case")
        policy = _canonical_nested(
            AlertPolicyAuthority,
            self.source_alert_policy,
            "M6 source alert-policy authority",
        )
        audit = _canonical_nested(AuditEntry, self.closing_audit_entry, "M6 closing audit")
        cooldown = _canonical_nested(
            M6ReplayLockedCooldownCausalHead,
            self.cooldown_causal_head,
            "M6 cooldown causal head",
        )
        if self.source_closed_case_revision != self.source_ready_case_revision + 1:
            raise ValueError("M6 policy Case revisions must be adjacent")
        if (
            ready.run_id != closed.run_id
            or ready.case_id != closed.case_id
            or ready.manifest_id != closed.manifest_id
            or ready.status != CaseStatus.READY_FOR_ALERT_POLICY
            or closed.status != CaseStatus.CLOSED
            or ready.alerts
            or ready.appeals
            or ready.final_decision is not None
            or ready.current_backlog_item_id is not None
            or closed.appeals
            or closed.current_backlog_item_id is not None
        ):
            raise ValueError("M6 policy source scope is not one READY to CLOSED Case")

        request = policy.request
        verdict = ready.verdicts[-1] if ready.verdicts else None
        review = ready.procedural_reviews[-1] if ready.procedural_reviews else None
        expected_case_authority = sha256_hex(
            ["alert-case-authority", 1, ready.model_dump(mode="json")]
        )
        if (
            verdict is None
            or review is None
            or request.run_id != ready.run_id
            or request.case_id != ready.case_id
            or request.case_authority_sha256 != expected_case_authority
            or request.source_case_status != ready.status
            or request.config_sha256 != self.source_config_sha256
            or request.manifest_id != ready.manifest_id
            or request.camera_id != ready.event.camera_id
            or request.stream_id != ready.event.stream_id
            or request.zone_id != ready.event.zone_id
            or request.violation_type != ready.event.violation_type
            or request.primary_track_ref != ready.event.primary_track_ref
            or request.trigger_frame != ready.event.trigger_frame
            or request.hard_rule != ready.event.hard_rule
            or request.verdict_id != verdict.verdict_id
            or request.verdict_version != verdict.version
            or request.verdict_sha256 != verdict.verdict_sha256
            or request.verdict_decision != verdict.decision
            or request.verdict_confidence != verdict.confidence
            or request.recommended_alert_level != verdict.recommended_alert_level
            or request.procedural_review_id != review.review_id
            or request.procedural_review_version != review.version
            or not request.procedural_review_passed
            or request.prior_cooldown != cooldown.prior_authority
            or request.prior_emergency_delivery is not None
        ):
            raise ValueError("M6 alert policy source scope differs from its READY Case")

        expected_key = (
            None
            if ready.event.primary_track_ref is None
            else AlertCooldownKey(
                zone_id=ready.event.zone_id,
                violation_type=ready.event.violation_type,
                track_ref=ready.event.primary_track_ref,
            )
        )
        if expected_key is None:
            expected_basis = M6ReplayLockedCooldownCausalBasis.UNTRACKED
        elif request.prior_cooldown is None:
            expected_basis = M6ReplayLockedCooldownCausalBasis.EMPTY_HISTORY
        else:
            expected_basis = M6ReplayLockedCooldownCausalBasis.EXACT_PRIOR
        if cooldown.key != expected_key or cooldown.basis != expected_basis:
            raise ValueError("M6 cooldown causal head differs from policy input")

        decision = policy.decision
        if decision is None:
            expected_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=ready.case_id)
            alerts = ready.alerts
            alert_id = "NONE"
        else:
            expected_ref = ArtifactRef(kind=ArtifactKind.ALERT, artifact_id=decision.alert_id)
            alerts = (*ready.alerts, decision)
            alert_id = decision.alert_id
        expected_timeline = (
            *ready.timeline,
            TimelineEntry(
                sequence=len(ready.timeline),
                action=AuditAction.CASE_CLOSED.value,
                stage="ALERT_POLICY",
                object_ref=expected_ref.artifact_id,
                details={
                    "alert_id": alert_id,
                    "disposition": policy.disposition.value,
                    "status": CaseStatus.CLOSED.value,
                },
            ),
        )
        expected_closed = ready.model_copy(
            update={
                "status": CaseStatus.CLOSED,
                "alerts": alerts,
                "final_decision": policy.final_decision,
                "timeline": expected_timeline,
            }
        )
        if expected_closed != closed:
            raise ValueError("M6 CLOSED Case is not the exact alert-policy successor")
        if (
            policy.target_case_status != CaseStatus.CLOSED
            or policy.final_decision != closed.final_decision
            or (
                policy.disposition == AlertPolicyDisposition.CLOSE_NO_ALERT
                and policy.decision is not None
            )
        ):
            raise ValueError("M6 source policy does not close its exact Case")

        if (
            cooldown.source_run_id != ready.run_id
            or cooldown.source_close_audit_sequence != audit.sequence
            or cooldown.source_close_audit_entry_hash != audit.entry_hash
            or audit.run_id != ready.run_id
            or audit.manifest_id != ready.manifest_id
            or audit.actor != AuditActorRole.SYSTEM.value
            or audit.action != AuditAction.CASE_CLOSED
            or audit.object_ref != expected_ref
            or audit.before_sha256 != self.source_ready_case_content_sha256
            or audit.after_sha256 != self.source_closed_case_content_sha256
        ):
            raise ValueError("M6 closing audit does not bind the exact policy transition")

        object.__setattr__(self, "source_ready_case", ready)
        object.__setattr__(self, "source_closed_case", closed)
        object.__setattr__(self, "source_alert_policy", policy)
        object.__setattr__(self, "closing_audit_entry", audit)
        object.__setattr__(self, "cooldown_causal_head", cooldown)
        if (
            len(canonical_json(self.model_dump(mode="json")).encode("utf-8"))
            > MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES
        ):
            raise ValueError("M6 policy causal cut exceeds its document byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_ready_case_content_sha256(self) -> Sha256Hex:
        return _document_sha256(self.source_ready_case)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_closed_case_content_sha256(self) -> Sha256Hex:
        return _document_sha256(self.source_closed_case)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_alert_policy_content_sha256(self) -> Sha256Hex:
        return _document_sha256(self.source_alert_policy)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def closing_audit_content_sha256(self) -> Sha256Hex:
        return _document_sha256(self.closing_audit_entry)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def policy_causal_cut_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-alert-policy-causal-cut",
                1,
                self.source_identity_sha256,
                self.sample_id,
                self.replay_input_closure_authority_id,
                self.replay_input_closure_document_sha256,
                self.source_validation_report_id,
                self.source_validation_report_document_sha256,
                self.source_m5_authority_root_sha256,
                self.source_config_sha256,
                self.source_ready_case_revision,
                self.source_ready_case_content_sha256,
                self.source_closed_case_revision,
                self.source_closed_case_content_sha256,
                self.source_alert_policy.authority_id,
                self.source_alert_policy_content_sha256,
                self.closing_audit_entry.entry_hash,
                self.closing_audit_content_sha256,
                self.cooldown_causal_head.causal_head_id,
                self.emergency_causal_basis,
            ]
        )


__all__ = [
    "M6_REPLAY_LOCKED_EMERGENCY_CAUSAL_BASIS",
    "MAX_M6_REPLAY_LOCKED_COOLDOWN_HISTORY_ENTRIES",
    "MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES",
    "M6ReplayLockedAlertPolicyCausalCutAuthority",
    "M6ReplayLockedCooldownCausalBasis",
    "M6ReplayLockedCooldownCausalHead",
    "M6ReplayLockedCooldownHistoryEntry",
]
