"""Typed source observations for one locked M5 alert-policy causal cut."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertPolicyAuthority,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.cases import Case
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority


def _require_sha256(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _require_strict_int(value: object, label: str, *, minimum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer greater than or equal to {minimum}")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedCooldownHistoryRowObservation:
    """One eligible cooldown row read from the same immutable source snapshot."""

    source_identity_sha256: str
    revision: int
    writer_close_audit_sequence: int
    writer_close_audit_entry_hash: str
    writer_alert_policy_authority_id: str
    authority: AlertCooldownAuthority
    authority_canonical_document: str

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "M6 policy source identity")
        _require_strict_int(self.revision, "M6 cooldown history revision", minimum=1)
        _require_strict_int(
            self.writer_close_audit_sequence,
            "M6 cooldown writer audit sequence",
            minimum=0,
        )
        _require_sha256(
            self.writer_close_audit_entry_hash,
            "M6 cooldown writer audit entry",
        )
        _require_sha256(
            self.writer_alert_policy_authority_id,
            "M6 cooldown writer policy authority",
        )
        if type(self.authority) is not AlertCooldownAuthority:
            raise TypeError("M6 cooldown history row requires an exact typed authority")
        if not isinstance(self.authority_canonical_document, str) or not (
            self.authority_canonical_document
        ):
            raise ValueError("M6 cooldown history row requires a canonical document")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedAlertPolicySourceObservation:
    """Complete read-cut observation needed to build one policy causal authority."""

    source_identity_sha256: str
    replay_input_closure: M6ReplayInputClosureAuthority
    replay_input_closure_canonical_document: str
    source_validation_report: M5ArtifactValidationReport
    source_validation_report_canonical_document: str
    source_m5_authority_root_sha256: str
    source_ready_case_revision: int
    source_ready_case: Case
    source_ready_case_canonical_document: str
    source_closed_case_revision: int
    source_closed_case: Case
    source_closed_case_canonical_document: str
    source_alert_policy: AlertPolicyAuthority
    source_alert_policy_canonical_document: str
    closing_audit_entry: AuditEntry
    closing_audit_entry_canonical_document: str
    cooldown_eligible_history_rows: tuple[
        M6ReplayLockedCooldownHistoryRowObservation,
        ...,
    ]

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "M6 policy source identity")
        _require_sha256(
            self.source_m5_authority_root_sha256,
            "M6 policy source M5 authority root",
        )
        _require_strict_int(
            self.source_ready_case_revision,
            "M6 policy READY Case revision",
            minimum=1,
        )
        _require_strict_int(
            self.source_closed_case_revision,
            "M6 policy CLOSED Case revision",
            minimum=1,
        )
        typed_documents = (
            (self.replay_input_closure, M6ReplayInputClosureAuthority),
            (self.source_validation_report, M5ArtifactValidationReport),
            (self.source_ready_case, Case),
            (self.source_closed_case, Case),
            (self.source_alert_policy, AlertPolicyAuthority),
            (self.closing_audit_entry, AuditEntry),
        )
        if any(type(value) is not expected for value, expected in typed_documents):
            raise TypeError("M6 policy source observation requires exact typed documents")
        canonical_documents = (
            self.replay_input_closure_canonical_document,
            self.source_validation_report_canonical_document,
            self.source_ready_case_canonical_document,
            self.source_closed_case_canonical_document,
            self.source_alert_policy_canonical_document,
            self.closing_audit_entry_canonical_document,
        )
        if any(not isinstance(value, str) or not value for value in canonical_documents):
            raise ValueError("M6 policy source observation requires canonical documents")
        if not isinstance(self.cooldown_eligible_history_rows, tuple) or any(
            type(item) is not M6ReplayLockedCooldownHistoryRowObservation
            for item in self.cooldown_eligible_history_rows
        ):
            raise TypeError("M6 policy source observation requires typed cooldown history rows")


@runtime_checkable
class M6ReplayLockedAlertPolicySourceProvider(Protocol):
    """Load one exact policy source observation without scanning another sample."""

    def load_alert_policy_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedAlertPolicySourceObservation: ...


__all__ = [
    "M6ReplayLockedAlertPolicySourceObservation",
    "M6ReplayLockedAlertPolicySourceProvider",
    "M6ReplayLockedCooldownHistoryRowObservation",
]
