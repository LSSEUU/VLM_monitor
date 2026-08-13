"""Authorization and orchestration service for the M8 loopback API."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import TypeVar

from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8Capability,
    M8OperationalCaseTransitionCommandV1,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_api import M8ApiCaseTransitionRequestV1, M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import (
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseAuditEventV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_sensor_persistence import M8SensorPollCacheCommitReceiptV1
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_inventory_repository import M8InventoryRepository
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.ports.m8_sensor_persistence_repository import M8SensorPersistenceRepository

_T = TypeVar("_T")


class M8ApiServiceFailureCode(StrEnum):
    FORBIDDEN = "FORBIDDEN"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    CONCURRENT_MODIFICATION = "CONCURRENT_MODIFICATION"
    INVALID_REQUEST = "INVALID_REQUEST"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"


class M8ApiServiceError(Exception):
    def __init__(self, reason_code: M8ApiServiceFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"M8 API service failed: {reason_code.value}")


class M8OperationsApiService:
    def __init__(
        self,
        inventory_repository: M8InventoryRepository,
        operations_repository: M8OperationsRepository,
        sensor_repository: M8SensorPersistenceRepository,
        case_manifest_id: str,
        audit_manifest_id: str,
    ) -> None:
        self._inventory = inventory_repository
        self._operations = operations_repository
        self._sensors = sensor_repository
        self._case_manifest_id = case_manifest_id
        self._audit_manifest_id = audit_manifest_id

    def session(self, principal: M8ApiPrincipalV1) -> M8ActorAuthorityCommitReceiptV1:
        """Resolve the current persisted actor authority for the authenticated token."""

        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        receipt = self._call(
            lambda: self._operations.get_current_actor_authority(principal.actor_id)
        )
        if not receipt.authority.active or receipt.authority.actor_id != principal.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return receipt

    def topology(
        self,
        principal: M8ApiPrincipalV1,
        campus_id: str,
    ) -> M8CampusTopologyCommitReceiptV1:
        actor = self._actor(principal)
        self._require_any(
            actor,
            M8Capability.VIEW_GLOBAL_OVERVIEW,
            M8Capability.VIEW_DEVICE_HEALTH,
        )
        return self._call(lambda: self._inventory.get_current_topology(campus_id))

    def source_catalog(
        self,
        principal: M8ApiPrincipalV1,
        campus_id: str,
    ) -> M8OperationalSourceCatalogCommitReceiptV1:
        actor = self._actor(principal)
        self._require_any(
            actor,
            M8Capability.VIEW_GLOBAL_OVERVIEW,
            M8Capability.VIEW_DEVICE_HEALTH,
        )
        return self._call(lambda: self._inventory.get_current_source_catalog(campus_id))

    def sensor_poll(
        self,
        principal: M8ApiPrincipalV1,
        request_id: str,
    ) -> M8SensorPollCacheCommitReceiptV1:
        actor = self._actor(principal)
        if actor.role not in {M8ActorRole.SAFETY_OFFICER, M8ActorRole.OPERATIONS}:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        self._require_any(
            actor,
            M8Capability.VIEW_GLOBAL_OVERVIEW,
            M8Capability.VIEW_DEVICE_HEALTH,
        )
        return self._call(lambda: self._sensors.get_poll_cache(request_id))

    def cases(
        self,
        principal: M8ApiPrincipalV1,
    ) -> tuple[M8OperationalCaseCommitReceiptV1, ...]:
        actor = self._actor(principal)
        current = self._call(lambda: self._operations.list_current_operational_cases(10_000))
        if actor.role == M8ActorRole.SAFETY_OFFICER:
            return tuple(item for item in current if self._actor_covers_case(actor, item))
        if actor.role == M8ActorRole.LEADER:
            return tuple(item for item in current if self._is_major(item))
        if actor.role == M8ActorRole.STUDENT:
            return tuple(
                item
                for item in current
                if item.audit_event.case_authority.subject_actor_id == actor.actor_id
            )
        return ()

    def case(
        self,
        principal: M8ApiPrincipalV1,
        case_id: str,
    ) -> M8OperationalCaseCommitReceiptV1:
        actor = self._actor(principal)
        case = self._call(lambda: self._operations.get_current_operational_case(case_id))
        self._require_case_read(actor, case)
        return case

    def case_audit(
        self,
        principal: M8ApiPrincipalV1,
        case_id: str,
    ) -> tuple[M8OperationalCaseAuditEventV1, ...]:
        actor = self._actor(principal)
        case = self._call(lambda: self._operations.get_current_operational_case(case_id))
        if (actor.role == M8ActorRole.SAFETY_OFFICER and self._actor_covers_case(actor, case)) or (
            actor.role == M8ActorRole.LEADER and self._is_major(case)
        ):
            self._require_any(actor, M8Capability.VIEW_AUDIT)
        else:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return self._call(lambda: self._operations.list_operational_case_audit(case_id))

    def transition_case(
        self,
        principal: M8ApiPrincipalV1,
        case_id: str,
        request: M8ApiCaseTransitionRequestV1,
    ) -> M8OperationalCaseCommitReceiptV1:
        return self.transition_case_with_authority(
            self.session(principal), case_id, request
        )

    def transition_case_with_authority(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        case_id: str,
        request: M8ApiCaseTransitionRequestV1,
    ) -> M8OperationalCaseCommitReceiptV1:
        current = self._call(
            lambda: self._operations.get_current_actor_authority(
                actor_receipt.authority.actor_id
            )
        )
        if current != actor_receipt or not current.authority.active:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        actor = current.authority
        try:
            command = M8OperationalCaseTransitionCommandV1(
                case_id=case_id,
                source_case_version=request.source_case_version,
                source_case_authority_sha256=request.source_case_authority_sha256,
                source_status=request.source_status,
                case_location_id=request.case_location_id,
                subject_actor_id=request.subject_actor_id,
                action=request.action,
                reason_code=request.reason_code,
                reason_summary=request.reason_summary,
                supporting_authorities=request.supporting_authorities,
                actor_authority=actor,
                appeal_resolution=request.appeal_resolution,
                explicit_human_confirmation=request.explicit_human_confirmation,
                command_manifest_id=request.command_manifest_id,
            )
        except ValidationError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN) from error
        return self._call(
            lambda: self._operations.transition_operational_case(
                command,
                self._case_manifest_id,
                self._audit_manifest_id,
            )
        )

    def _actor(self, principal: M8ApiPrincipalV1) -> M8ActorAuthorityV1:
        return self.session(principal).authority

    @staticmethod
    def _require_any(actor: M8ActorAuthorityV1, *capabilities: M8Capability) -> None:
        if not any(capability in actor.capabilities for capability in capabilities):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)

    def _require_case_read(
        self,
        actor: M8ActorAuthorityV1,
        case: M8OperationalCaseCommitReceiptV1,
    ) -> None:
        if actor.role == M8ActorRole.SAFETY_OFFICER and self._actor_covers_case(actor, case):
            self._require_any(actor, M8Capability.VIEW_GLOBAL_OVERVIEW)
            return
        if actor.role == M8ActorRole.LEADER and self._is_major(case):
            self._require_any(actor, M8Capability.VIEW_MAJOR_EVENTS)
            return
        if (
            actor.role == M8ActorRole.STUDENT
            and case.audit_event.case_authority.subject_actor_id == actor.actor_id
        ):
            self._require_any(actor, M8Capability.VIEW_OWN_CASE)
            return
        raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)

    @staticmethod
    def _actor_covers_case(
        actor: M8ActorAuthorityV1,
        case: M8OperationalCaseCommitReceiptV1,
    ) -> bool:
        if actor.scope_kind == M8ActorScopeKind.CAMPUS_WIDE:
            return True
        return (
            actor.scope_kind == M8ActorScopeKind.LOCATIONS
            and case.audit_event.case_authority.location_id in actor.scope_location_ids
        )

    @staticmethod
    def _is_major(case: M8OperationalCaseCommitReceiptV1) -> bool:
        return case.audit_event.case_authority.risk_level in {
            M8OperationalRiskLevel.SEVERE,
            M8OperationalRiskLevel.EMERGENCY,
        }

    @staticmethod
    def _call(function: Callable[[], _T]) -> _T:
        try:
            return function()
        except EvidenceMissing as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from error
        except ConcurrentModification as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION) from error
        except BudgetExceeded as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from error


__all__ = ["M8ApiServiceError", "M8ApiServiceFailureCode", "M8OperationsApiService"]
