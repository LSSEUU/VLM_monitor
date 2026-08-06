"""Pure CLOSED-policy continuation for one M6 locked replay sample."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.alert_policy_verifier import (
    AlertPolicyVerificationError,
    ConfiguredAlertPolicyVerifier,
)
from labcourt.contracts.alert_policy import AlertPolicyAuthority
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import AuditAction, CaseStatus
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.domain.alert_policy import AlertPolicyError
from labcourt.exceptions import LabCourtError

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedAlertPolicyErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_BINDING_MISMATCH = "SOURCE_BINDING_MISMATCH"
    PRE_POLICY_CASE_REJECTED = "PRE_POLICY_CASE_REJECTED"
    POLICY_REBUILD_REJECTED = "POLICY_REBUILD_REJECTED"
    CLOSED_CASE_REJECTED = "CLOSED_CASE_REJECTED"


class M6ReplayLockedAlertPolicyError(LabCourtError):
    """Payload-free failure from the pure locked policy continuation."""

    def __init__(self, code: M6ReplayLockedAlertPolicyErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedAlertPolicyErrorCode):
            raise TypeError("code must be an M6 locked alert-policy error code")
        self.code = code
        super().__init__(f"M6 locked alert-policy continuation failed: {code.value}")


def _fail(code: M6ReplayLockedAlertPolicyErrorCode) -> NoReturn:
    raise M6ReplayLockedAlertPolicyError(code) from None


def _canonical_model(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedAlertPolicyErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedAlertPolicyErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedAlertPolicyErrorCode.INVALID_ARGUMENT)
    return controlled


def _closed_successor(ready: Case, policy: AlertPolicyAuthority) -> Case:
    decision = policy.decision
    alert_id = decision.alert_id if decision is not None else "NONE"
    object_ref = decision.alert_id if decision is not None else ready.case_id
    alerts = ready.alerts if decision is None else (*ready.alerts, decision)
    return ready.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "alerts": alerts,
            "final_decision": policy.final_decision,
            "timeline": (
                *ready.timeline,
                TimelineEntry(
                    sequence=len(ready.timeline),
                    action=AuditAction.CASE_CLOSED.value,
                    stage="ALERT_POLICY",
                    object_ref=object_ref,
                    details={
                        "alert_id": alert_id,
                        "disposition": policy.disposition.value,
                        "status": CaseStatus.CLOSED.value,
                    },
                ),
            ),
        }
    )


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedPolicyCandidate:
    """In-memory READY -> CLOSED result; it performs no dispatch or storage."""

    ready_case: Case
    alert_policy: AlertPolicyAuthority
    closed_case: Case
    source_binding_authority_id: str
    policy_causal_cut_authority_id: str

    def __post_init__(self) -> None:
        if (
            type(self.ready_case) is not Case
            or type(self.alert_policy) is not AlertPolicyAuthority
            or type(self.closed_case) is not Case
        ):
            raise TypeError("M6 locked CLOSED policy candidate requires exact contract types")
        try:
            ready = Case.model_validate(
                self.ready_case.model_dump(mode="json", exclude_computed_fields=True)
            )
            policy = AlertPolicyAuthority.model_validate(
                self.alert_policy.model_dump(mode="json", exclude_computed_fields=True)
            )
            closed = Case.model_validate(
                self.closed_case.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 locked CLOSED policy candidate is not canonical") from None
        if (
            ready != self.ready_case
            or policy != self.alert_policy
            or closed != self.closed_case
            or ready.status != CaseStatus.READY_FOR_ALERT_POLICY
            or policy.request.case_id != ready.case_id
            or policy.request.run_id != ready.run_id
            or policy.request.manifest_id != ready.manifest_id
            or _closed_successor(ready, policy) != closed
            or len(self.source_binding_authority_id) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.source_binding_authority_id
            )
            or len(self.policy_causal_cut_authority_id) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.policy_causal_cut_authority_id
            )
        ):
            raise ValueError("M6 locked CLOSED policy candidate bindings differ")

    @property
    def canonical_closed_case_document(self) -> str:
        return canonical_json(self.closed_case.model_dump(mode="json"))


def build_m6_replay_locked_closed_policy_candidate(
    *,
    ready_case: object,
    source_binding: object,
    locked_config: object,
    locked_manifest: object,
) -> M6ReplayLockedClosedPolicyCandidate:
    """Rebuild L5 from the candidate-safe causal head and return its successor.

    The evaluator-only source policy and source CLOSED Case never cross this
    boundary.  A trusted Record builder performs that comparison after the
    candidate has been durably committed.
    """

    ready = _canonical_model(ready_case, Case)
    binding = _canonical_model(
        source_binding,
        M6ReplayLockedClosedPolicySourceBindingAuthority,
    )
    config = _canonical_model(locked_config, AppConfig)
    manifest = _canonical_model(locked_manifest, RunManifest)
    if (
        ready.status != CaseStatus.READY_FOR_ALERT_POLICY
        or ready.manifest_id != manifest.manifest_id
        or ready.alerts
        or ready.appeals
        or ready.final_decision is not None
        or ready.current_backlog_item_id is not None
        or not ready.verdicts
        or not ready.procedural_reviews
        or not ready.procedural_reviews[-1].passed
    ):
        _fail(M6ReplayLockedAlertPolicyErrorCode.PRE_POLICY_CASE_REJECTED)
    if (
        manifest.config_sha256 != config.config_sha256
        or binding.source_config_sha256 != config.config_sha256
    ):
        _fail(M6ReplayLockedAlertPolicyErrorCode.SOURCE_BINDING_MISMATCH)
    try:
        policy = ConfiguredAlertPolicyVerifier(config).rebuild(
            ready,
            manifest,
            binding.cooldown_causal_head.prior_authority,
            None,
        )
    except (AlertPolicyError, AlertPolicyVerificationError, TypeError, ValueError):
        _fail(M6ReplayLockedAlertPolicyErrorCode.POLICY_REBUILD_REJECTED)
    try:
        closed = _closed_successor(ready, policy)
        return M6ReplayLockedClosedPolicyCandidate(
            ready_case=ready,
            alert_policy=policy,
            closed_case=closed,
            source_binding_authority_id=binding.source_binding_authority_id,
            policy_causal_cut_authority_id=binding.policy_causal_cut_authority_id,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedAlertPolicyErrorCode.CLOSED_CASE_REJECTED)


__all__ = [
    "M6ReplayLockedAlertPolicyError",
    "M6ReplayLockedAlertPolicyErrorCode",
    "M6ReplayLockedClosedPolicyCandidate",
    "build_m6_replay_locked_closed_policy_candidate",
]
