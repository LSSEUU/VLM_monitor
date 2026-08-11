"""Authenticated role-scoped reads for the M8 notification center."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationAuditEventV1,
    M8NotificationCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import M8NotificationAudienceKind
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_notification_repository import M8NotificationRepository
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.services.m8_operations_api import M8ApiServiceError, M8ApiServiceFailureCode

_T = TypeVar("_T")


class M8NotificationApiService:
    def __init__(
        self,
        notification_repository: M8NotificationRepository,
        operations_repository: M8OperationsRepository,
    ) -> None:
        self._notifications = notification_repository
        self._operations = operations_repository

    def notifications(
        self,
        principal: M8ApiPrincipalV1,
    ) -> tuple[M8NotificationCommitReceiptV1, ...]:
        actor = self._actor(principal)
        current = self._call(lambda: self._notifications.list_current_notifications(20_000))
        return tuple(item for item in current if self._visible(actor, item))

    def notification(
        self,
        principal: M8ApiPrincipalV1,
        notification_id: str,
    ) -> M8NotificationCommitReceiptV1:
        actor = self._actor(principal)
        current = self._call(lambda: self._notifications.get_current_notification(notification_id))
        if not self._visible(actor, current):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return current

    def audit(
        self,
        principal: M8ApiPrincipalV1,
        notification_id: str,
    ) -> tuple[M8NotificationAuditEventV1, ...]:
        actor = self._actor(principal)
        current = self._call(lambda: self._notifications.get_current_notification(notification_id))
        if actor.role not in {M8ActorRole.SAFETY_OFFICER, M8ActorRole.LEADER} or not self._visible(
            actor, current
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return self._call(lambda: self._notifications.list_notification_audit(notification_id))

    def _actor(self, principal: M8ApiPrincipalV1) -> M8ActorAuthorityV1:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        receipt = self._call(
            lambda: self._operations.get_current_actor_authority(principal.actor_id)
        )
        actor = receipt.authority
        if not actor.active or actor.actor_id != principal.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return actor

    @staticmethod
    def _visible(
        actor: M8ActorAuthorityV1,
        notification: M8NotificationCommitReceiptV1,
    ) -> bool:
        plan = notification.audit_event.notification_authority.plan
        if actor.role == M8ActorRole.SAFETY_OFFICER:
            return actor.scope_kind == M8ActorScopeKind.CAMPUS_WIDE or (
                actor.scope_kind == M8ActorScopeKind.LOCATIONS
                and plan.location_id in actor.scope_location_ids
            )
        if actor.role == M8ActorRole.LEADER:
            return (
                plan.audience == M8NotificationAudienceKind.LEADER_MAJOR_EVENT
                or plan.risk_level
                in {
                    M8OperationalRiskLevel.SEVERE,
                    M8OperationalRiskLevel.EMERGENCY,
                }
            )
        if actor.role == M8ActorRole.STUDENT:
            return plan.target.actor_id == actor.actor_id
        return (
            actor.role == M8ActorRole.OPERATIONS
            and plan.audience == M8NotificationAudienceKind.OPERATIONS_DEVICE_RESPONSE
            and plan.target.actor_id == actor.actor_id
        )

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


__all__ = ["M8NotificationApiService"]
