"""Authenticated read-only API orchestration for M8 adapter commissioning readiness."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import TypeVar

from labcourt.contracts.m8_access_cases import M8ActorRole, M8Capability
from labcourt.contracts.m8_adapter_commissioning import M8AdapterReadinessAssessmentV1
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService
from labcourt.services.m8_operations_api import M8ApiServiceError, M8ApiServiceFailureCode

_T = TypeVar("_T")


class M8CommissioningApiService:
    """Resolve current operations authority around one server-timed readiness read."""

    def __init__(
        self,
        readiness_service: M8AdapterReadinessService,
        operations_repository: M8OperationsRepository,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(readiness_service, M8AdapterReadinessService):
            raise TypeError("M8 commissioning API requires a readiness service")
        if not callable(clock):
            raise TypeError("M8 commissioning API requires an explicit clock")
        self._readiness = readiness_service
        self._operations = operations_repository
        self._clock = clock

    def readiness(
        self,
        principal: M8ApiPrincipalV1,
        candidate_authority_id: str,
    ) -> M8AdapterReadinessAssessmentV1:
        actor_receipt = self._actor_receipt(principal)
        actor = actor_receipt.authority
        if (
            actor.role != M8ActorRole.OPERATIONS
            or M8Capability.MANAGE_DEVICES not in actor.capabilities
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        assessed_at = self._server_time()
        assessment = self._call(
            lambda: self._readiness.assess(
                candidate_authority_id,
                actor.actor_id,
                assessed_at,
            )
        )
        if assessment.assessor_actor_receipt.commit_receipt_id != actor_receipt.commit_receipt_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        current_actor_receipt = self._call(
            lambda: self._operations.get_current_actor_authority(actor.actor_id)
        )
        if current_actor_receipt.commit_receipt_id != actor_receipt.commit_receipt_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        return assessment

    def _actor_receipt(
        self,
        principal: M8ApiPrincipalV1,
    ) -> M8ActorAuthorityCommitReceiptV1:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        try:
            receipt = self._operations.get_current_actor_authority(principal.actor_id)
        except EvidenceMissing as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN) from error
        except ConcurrentModification as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION) from error
        actor = receipt.authority
        if not actor.active or actor.actor_id != principal.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return receipt

    def _server_time(self) -> datetime:
        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE)
        return value

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


__all__ = ["M8CommissioningApiService"]
