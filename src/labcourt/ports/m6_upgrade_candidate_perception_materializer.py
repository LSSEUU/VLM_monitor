"""Trusted boundary for materializing the next candidate perception slice."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.exceptions import ContractViolation


class M6UpgradeCandidatePerceptionMaterializerFailureCode(StrEnum):
    """Closed failures without source bodies, candidate rows, or host paths."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    EXECUTION_STATE_MISMATCH = "EXECUTION_STATE_MISMATCH"
    CATALOG_NOT_FOUND = "CATALOG_NOT_FOUND"
    CATALOG_REJECTED = "CATALOG_REJECTED"
    SOURCE_SEAL_REJECTED = "SOURCE_SEAL_REJECTED"
    SOURCE_PERCEPTION_REJECTED = "SOURCE_PERCEPTION_REJECTED"
    CANDIDATE_MANIFEST_MISMATCH = "CANDIDATE_MANIFEST_MISMATCH"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradeCandidatePerceptionMaterializerError(ContractViolation):
    """Payload-free failure at the candidate perception materialization boundary."""

    def __init__(
        self,
        reason_code: M6UpgradeCandidatePerceptionMaterializerFailureCode,
    ) -> None:
        if not isinstance(reason_code, M6UpgradeCandidatePerceptionMaterializerFailureCode):
            raise TypeError("reason_code must be an M6 candidate perception failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 candidate perception materialization failed: {reason_code.value}")


@runtime_checkable
class M6UpgradeCandidatePerceptionMaterializerV3(Protocol):
    """Materialize one exact next entry using only durable public identities."""

    def materialize_next_perception(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6ResolvedPerception: ...


__all__ = [
    "M6UpgradeCandidatePerceptionMaterializerError",
    "M6UpgradeCandidatePerceptionMaterializerFailureCode",
    "M6UpgradeCandidatePerceptionMaterializerV3",
]
