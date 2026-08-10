"""Read-only M8 adapter readiness orchestration over persisted commissioning evidence."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from labcourt.application.m8_adapter_commissioning_workflow import (
    build_adapter_readiness_assessment,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import M8AdapterReadinessAssessmentV1
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m8_adapter_commissioning_repository import (
    M8AdapterCommissioningRepository,
)
from labcourt.ports.m8_operations_repository import M8OperationsRepository

_MAX_READINESS_EVIDENCE_SCAN = 10_000


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 {name} must be lowercase SHA-256 hex")
    return value


class M8AdapterReadinessService:
    """Rebuild readiness from current actor authority and append-only evidence receipts."""

    def __init__(
        self,
        commissioning_repository: M8AdapterCommissioningRepository,
        operations_repository: M8OperationsRepository,
        assessment_manifest_id: Sha256Hex,
    ) -> None:
        self._commissioning = commissioning_repository
        self._operations = operations_repository
        self._assessment_manifest_id = _validate_sha256(
            assessment_manifest_id,
            "adapter readiness assessment manifest",
        )

    def assess(
        self,
        candidate_authority_id: str,
        assessor_actor_id: str,
        assessed_at: datetime,
    ) -> M8AdapterReadinessAssessmentV1:
        candidate = self._commissioning.get_candidate(candidate_authority_id)
        evidence = self._commissioning.list_candidate_evidence(
            candidate_authority_id,
            _MAX_READINESS_EVIDENCE_SCAN,
        )
        assessor = self._operations.get_current_actor_authority(assessor_actor_id)
        try:
            return build_adapter_readiness_assessment(
                candidate,
                evidence,
                assessor,
                assessed_at,
                self._assessment_manifest_id,
            )
        except (ValidationError, ValueError) as error:
            raise ConcurrentModification("M8 adapter readiness cut is not authorized") from error


__all__ = ["M8AdapterReadinessService"]
