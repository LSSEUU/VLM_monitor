"""Read-only current user and permission inventory for M8 operations."""

from __future__ import annotations

from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.services.m8_operations_api import (
    M8ApiServiceError,
    M8ApiServiceFailureCode,
)


class M8UserPermissionApiService:
    """Expose persisted actor authority without granting user mutation power."""

    def __init__(
        self,
        operations_repository: M8OperationsRepository,
        actor_ids: tuple[str, ...],
    ) -> None:
        if not actor_ids or actor_ids != tuple(sorted(actor_ids)):
            raise ValueError("M8 user permission actor IDs must be non-empty and sorted")
        if len(actor_ids) != len(set(actor_ids)):
            raise ValueError("M8 user permission actor IDs must be unique")
        self._operations = operations_repository
        self._actor_ids = actor_ids

    def users(
        self,
        principal: M8ApiPrincipalV1,
    ) -> tuple[M8ActorAuthorityCommitReceiptV1, ...]:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        current = self._operations.get_current_actor_authority(principal.actor_id).authority
        if not current.active or current.role not in {
            M8ActorRole.LEADER,
            M8ActorRole.SAFETY_OFFICER,
        }:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return tuple(
            self._operations.get_current_actor_authority(actor_id) for actor_id in self._actor_ids
        )


__all__ = ["M8UserPermissionApiService"]
