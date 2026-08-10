"""Persistence port for additive M8 actor and operational-Case authorities."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseTransitionCommandV1,
)
from labcourt.contracts.m8_case_persistence import (
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseAuditEventV1,
    M8OperationalCaseCommitReceiptV1,
)


class M8OperationsRepository(Protocol):
    def publish_actor_authority(
        self,
        authority: M8ActorAuthorityV1,
        expected_prior_revision: int | None,
    ) -> M8ActorAuthorityCommitReceiptV1: ...

    def get_current_actor_authority(
        self,
        actor_id: str,
    ) -> M8ActorAuthorityCommitReceiptV1: ...

    def create_operational_case(
        self,
        command: M8OperationalCaseCreateCommandV1,
        subject_actor_id: str | None,
        case_manifest_id: str,
        audit_manifest_id: str,
    ) -> M8OperationalCaseCommitReceiptV1: ...

    def get_current_operational_case(
        self,
        case_id: str,
    ) -> M8OperationalCaseCommitReceiptV1: ...

    def transition_operational_case(
        self,
        command: M8OperationalCaseTransitionCommandV1,
        case_manifest_id: str,
        audit_manifest_id: str,
    ) -> M8OperationalCaseCommitReceiptV1: ...

    def list_operational_case_audit(
        self,
        case_id: str,
    ) -> tuple[M8OperationalCaseAuditEventV1, ...]: ...


__all__ = ["M8OperationsRepository"]
