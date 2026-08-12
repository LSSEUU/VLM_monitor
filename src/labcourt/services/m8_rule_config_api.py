"""Read-only typed rule configuration API for the M8 Demo."""

from __future__ import annotations

from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_sensor_signals import M8SensorRiskPolicyAuthorityV1
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.services.m8_operations_api import (
    M8ApiServiceError,
    M8ApiServiceFailureCode,
)


class M8RuleConfigApiService:
    """Return the exact configured policy without parsing ordinary documents."""

    def __init__(
        self,
        operations_repository: M8OperationsRepository,
        policy: M8SensorRiskPolicyAuthorityV1,
    ) -> None:
        if not isinstance(policy, M8SensorRiskPolicyAuthorityV1):
            raise TypeError("M8 rule config API requires a typed sensor risk policy")
        self._operations = operations_repository
        self._policy = policy

    def current_policy(self, principal: M8ApiPrincipalV1) -> M8SensorRiskPolicyAuthorityV1:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        actor = self._operations.get_current_actor_authority(principal.actor_id).authority
        if not actor.active or actor.role not in {
            M8ActorRole.LEADER,
            M8ActorRole.SAFETY_OFFICER,
        }:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return self._policy


__all__ = ["M8RuleConfigApiService"]
