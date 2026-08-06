"""Trusted reconstruction and persistence boundaries for M5 alert policy."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertPolicyAuthority,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
)
from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import CaseSnapshot


class ImmediateSafetyDeliveryFailureCode(StrEnum):
    DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY = "DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY"


class ImmediateSafetyDeliveryDisabledError(ContractViolation):
    """The incomplete immediate path cannot create trusted delivery authority."""

    def __init__(self, reason_code: ImmediateSafetyDeliveryFailureCode) -> None:
        if not isinstance(reason_code, ImmediateSafetyDeliveryFailureCode):
            raise TypeError("reason_code must be an ImmediateSafetyDeliveryFailureCode")
        self.reason_code = reason_code
        super().__init__(f"immediate safety delivery disabled: {reason_code.value}")


class AlertPolicyVerifier(Protocol):
    """Rebuild the only alert-policy authority eligible for durable commit."""

    def rebuild(
        self,
        case: Case,
        manifest: RunManifest,
        prior_cooldown: AlertCooldownAuthority | None,
        prior_emergency_delivery: ImmediateSafetyDeliveryAuthority | None,
    ) -> AlertPolicyAuthority: ...


class AutomaticPrecedentVerifier(Protocol):
    """Rebuild the only automatic precedent eligible for an alert close."""

    def rebuild(
        self,
        case: Case,
        manifest: RunManifest,
        alert_authority: AlertPolicyAuthority,
        created_at: datetime,
    ) -> M5PrecedentAuthority: ...


class AlertPolicyRepository(Protocol):
    """Persist immutable M5 alert roots and atomically close their source Case."""

    def list_ready_cases(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[CaseSnapshot, ...]: ...

    def load_current_cooldown(
        self,
        run_id: str,
        key: AlertCooldownKey,
        stream_id: str,
        stream_authority_sha256: str,
    ) -> AlertCooldownAuthority | None: ...

    def record_immediate_safety_delivery(
        self,
        run_id: str,
        authority: ImmediateSafetyDeliveryAuthority,
    ) -> ImmediateSafetyDeliveryAuthority: ...

    def load_immediate_safety_delivery(
        self,
        run_id: str,
        incident_id: str,
    ) -> ImmediateSafetyDeliveryAuthority | None: ...

    def commit_alert_policy(
        self,
        run_id: str,
        expected_revision: int,
        authority: AlertPolicyAuthority,
        automatic_precedent: M5PrecedentAuthority,
        application_batch: M5PrecedentApplicationBatchAuthority | None = None,
        application_citations: tuple[M5PrecedentApplicationCitationCommit, ...] = (),
    ) -> CaseSnapshot: ...


__all__ = [
    "AlertPolicyRepository",
    "AlertPolicyVerifier",
    "AutomaticPrecedentVerifier",
    "ImmediateSafetyDeliveryDisabledError",
    "ImmediateSafetyDeliveryFailureCode",
]
