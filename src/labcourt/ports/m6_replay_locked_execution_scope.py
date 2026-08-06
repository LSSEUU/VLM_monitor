"""Durable publication boundary for one M6 locked execution scope."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked_execution import (
    MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
    M6ReplayLockedExecutionScopeAuthority,
)
from labcourt.exceptions import ContractViolation


class M6ReplayLockedExecutionScopeFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    SCOPE_CONFLICT = "SCOPE_CONFLICT"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6ReplayLockedExecutionScopeStoreError(ContractViolation):
    """Payload-free durable locked-scope failure."""

    def __init__(self, reason_code: M6ReplayLockedExecutionScopeFailureCode) -> None:
        if not isinstance(reason_code, M6ReplayLockedExecutionScopeFailureCode):
            raise TypeError("reason_code must be an M6 locked execution-scope failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 locked execution scope store failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class M6StoredReplayLockedExecutionScope:
    scope: M6ReplayLockedExecutionScopeAuthority
    canonical_document: str
    content_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if type(self.scope) is not M6ReplayLockedExecutionScopeAuthority:
            raise TypeError("scope must be an exact M6 locked execution scope")
        try:
            controlled = M6ReplayLockedExecutionScopeAuthority.model_validate(
                self.scope.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise ValueError("scope must be canonical") from exc
        if controlled != self.scope:
            raise ValueError("scope must be canonical")
        expected_document = canonical_json(controlled.model_dump(mode="json"))
        if not isinstance(self.canonical_document, str) or not self.canonical_document:
            raise TypeError("canonical_document must be non-empty text")
        if self.canonical_document != expected_document:
            raise ValueError("canonical_document differs from the locked scope")
        payload = self.canonical_document.encode("utf-8")
        if len(payload) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            raise ValueError("canonical_document exceeds the locked-scope budget")
        if self.content_sha256 != hashlib.sha256(payload).hexdigest():
            raise ValueError("content_sha256 differs from the locked scope document")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes <= 0
            or self.size_bytes != len(payload)
        ):
            raise ValueError("size_bytes differs from the locked scope document")


@runtime_checkable
class M6ReplayLockedExecutionScopePublisher(Protocol):
    def publish(
        self,
        scope: M6ReplayLockedExecutionScopeAuthority,
        canonical_document: str,
    ) -> M6StoredReplayLockedExecutionScope: ...


@runtime_checkable
class M6ReplayLockedExecutionScopeProvider(Protocol):
    def load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6StoredReplayLockedExecutionScope: ...


__all__ = [
    "M6ReplayLockedExecutionScopeFailureCode",
    "M6ReplayLockedExecutionScopeProvider",
    "M6ReplayLockedExecutionScopePublisher",
    "M6ReplayLockedExecutionScopeStoreError",
    "M6StoredReplayLockedExecutionScope",
]
