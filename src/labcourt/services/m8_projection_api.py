"""Authenticated role-scoped access to the read-only M8 operations projection."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from labcourt.application.m8_projection_view_workflow import build_operations_projection_view
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_projection_views import M8OperationsProjectionViewV1
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.ports.m8_projection_reader import M8OperationsProjectionReader
from labcourt.services.m8_operations_api import M8ApiServiceError, M8ApiServiceFailureCode

_T = TypeVar("_T")


class M8ProjectionApiService:
    """Resolve current persisted authority before returning one role-scoped stable cut."""

    def __init__(
        self,
        operations_repository: M8OperationsRepository,
        projection_reader: M8OperationsProjectionReader,
    ) -> None:
        self._operations = operations_repository
        self._projection_reader = projection_reader

    def projection(
        self,
        principal: M8ApiPrincipalV1,
        campus_id: str,
    ) -> M8OperationsProjectionViewV1:
        actor_receipt = self._actor_receipt(principal)
        projection = self._call(lambda: self._projection_reader.current_projection(campus_id))
        current_actor_receipt = self._call(
            lambda: self._operations.get_current_actor_authority(principal.actor_id)
        )
        if current_actor_receipt.commit_receipt_id != actor_receipt.commit_receipt_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        try:
            return build_operations_projection_view(projection, actor_receipt)
        except ValueError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN) from error

    def _actor_receipt(
        self,
        principal: M8ApiPrincipalV1,
    ) -> M8ActorAuthorityCommitReceiptV1:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        receipt = self._call(
            lambda: self._operations.get_current_actor_authority(principal.actor_id)
        )
        actor = receipt.authority
        if not actor.active or actor.actor_id != principal.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return receipt

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


__all__ = ["M8ProjectionApiService"]
