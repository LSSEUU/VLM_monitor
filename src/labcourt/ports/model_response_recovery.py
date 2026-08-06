"""Narrow authority boundary for provider-free model-call startup recovery."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.model_response_recovery import MAX_MODEL_CALL_RECOVERY_ITEMS
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import (
    CachedModelResponse,
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ModelResponseRecoveryIdentity:
    """Opaque, capability-free identity shared only by one recovery composition."""

    __slots__ = ()


class PersistedModelCallStatus(StrEnum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"


class ModelCallRecoveryScanFailureCode(StrEnum):
    CLAIM_AUTHORITY_INVALID = "CLAIM_AUTHORITY_INVALID"
    DATABASE_OBSERVATION_CONFLICT = "DATABASE_OBSERVATION_CONFLICT"


@dataclass(frozen=True, slots=True)
class ModelCallRecoveryCandidate:
    """One fully reconstructed canonical SQLite claim authority."""

    request: VLMCallRequest
    status: PersistedModelCallStatus
    lease_expires_at: datetime
    takeover_count: int
    response_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request, (VLMRequest, StructureRepairRequest)):
            raise TypeError("recovery candidate request must be a VLM call request")
        validated = type(self.request).model_validate(self.request.model_dump(mode="json"))
        if validated != self.request:
            raise ValueError("recovery candidate request is not canonical")
        if not isinstance(self.status, PersistedModelCallStatus):
            raise TypeError("recovery candidate status is invalid")
        if (
            not isinstance(self.takeover_count, int)
            or isinstance(self.takeover_count, bool)
            or self.takeover_count < 0
        ):
            raise ValueError("recovery candidate takeover count must be non-negative")
        if (
            not isinstance(self.lease_expires_at, datetime)
            or self.lease_expires_at.tzinfo is None
            or self.lease_expires_at.utcoffset() is None
            or self.lease_expires_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("recovery candidate lease expiry must use timezone-aware UTC")
        if self.status == PersistedModelCallStatus.ACTIVE:
            if self.response_id is not None:
                raise ValueError("active recovery candidate cannot bind a response")
        elif self.response_id is None or _SHA256.fullmatch(self.response_id) is None:
            raise ValueError("completed recovery candidate requires a SHA-256 response id")

    @property
    def sort_key(self) -> str:
        return self.request.request_id


@dataclass(frozen=True, slots=True)
class ModelCallRecoveryScanAnomaly:
    """One opaque malformed claim observation that cannot reconstruct a request."""

    run_id: str
    source_token: str
    failure_code: ModelCallRecoveryScanFailureCode

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "model call recovery anomaly run reference")
        if _SHA256.fullmatch(self.source_token) is None:
            raise ValueError("model call recovery anomaly requires an opaque SHA-256 token")
        if not isinstance(self.failure_code, ModelCallRecoveryScanFailureCode):
            raise TypeError("model call recovery anomaly failure code is invalid")

    @property
    def sort_key(self) -> str:
        return self.source_token


@dataclass(frozen=True, slots=True)
class ModelCallRecoveryScan:
    """A stable bounded inventory; incomplete scans authorize no mutation.

    ``max_items`` is the total inventory ceiling for the run.  Repository page
    sizes are private implementation details and must not change ``complete``.
    """

    run_id: str
    max_items: int
    candidates: tuple[ModelCallRecoveryCandidate, ...]
    complete: bool
    anomalies: tuple[ModelCallRecoveryScanAnomaly, ...] = ()

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "model call recovery scan run reference")
        if (
            not isinstance(self.max_items, int)
            or isinstance(self.max_items, bool)
            or not 1 <= self.max_items <= MAX_MODEL_CALL_RECOVERY_ITEMS
        ):
            raise ValueError(
                f"model call recovery max_items must be in [1, {MAX_MODEL_CALL_RECOVERY_ITEMS}]"
            )
        if not isinstance(self.candidates, tuple) or any(
            not isinstance(candidate, ModelCallRecoveryCandidate) for candidate in self.candidates
        ):
            raise TypeError("model call recovery candidates must be a tuple")
        if not isinstance(self.anomalies, tuple) or any(
            not isinstance(anomaly, ModelCallRecoveryScanAnomaly) for anomaly in self.anomalies
        ):
            raise TypeError("model call recovery anomalies must be a tuple")
        if type(self.complete) is not bool:
            raise TypeError("model call recovery scan complete flag must be a boolean")
        observed = len(self.candidates) + len(self.anomalies)
        if observed > self.max_items:
            raise ValueError("model call recovery observations exceed the scan budget")
        if not self.complete and observed != self.max_items:
            raise ValueError("incomplete model call scan must expose one full bounded page")
        if any(candidate.request.run_id != self.run_id for candidate in self.candidates):
            raise ValueError("model call recovery candidate belongs to another run")
        if any(anomaly.run_id != self.run_id for anomaly in self.anomalies):
            raise ValueError("model call recovery anomaly belongs to another run")
        keys = tuple(candidate.sort_key for candidate in self.candidates)
        if len(keys) != len(set(keys)):
            raise ValueError("model call recovery candidates must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("model call recovery candidates must use stable request order")
        anomaly_keys = tuple(anomaly.sort_key for anomaly in self.anomalies)
        if len(anomaly_keys) != len(set(anomaly_keys)):
            raise ValueError("model call recovery anomalies must be unique")
        if anomaly_keys != tuple(sorted(anomaly_keys)):
            raise ValueError("model call recovery anomalies must use stable token order")

    @property
    def claims_scanned(self) -> int:
        return len(self.candidates) + len(self.anomalies)


class ModelCallRecoveryRepository(Protocol):
    def scan_model_call_recovery_candidates(
        self,
        run_id: str,
        max_items: int,
    ) -> ModelCallRecoveryScan:
        """Inventory one stable snapshot up to the total per-run ceiling."""

        ...

    def complete_expired_model_call_from_recovery(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
        observed_lease_expires_at: datetime,
        observed_takeover_count: int,
    ) -> CachedModelResponse:
        """Atomically complete one expired claim from verified raw publication.

        This provider-free capability never returns a claim owner or an
        ``ACQUIRED`` state.  The caller must first recover the exact journaled
        publication, and the repository re-verifies its physical raw binding
        before committing response, cache, and claim completion in one
        transaction.
        """

        ...

    def get(
        self,
        run_id: str,
        request: VLMCallRequest,
    ) -> CachedModelResponse | None: ...

    def load_raw_response_for_request(
        self,
        run_id: str,
        request_id: str,
    ) -> VLMResponse | None: ...


__all__ = [
    "ModelCallRecoveryCandidate",
    "ModelCallRecoveryRepository",
    "ModelCallRecoveryScan",
    "ModelCallRecoveryScanAnomaly",
    "ModelCallRecoveryScanFailureCode",
    "ModelResponseRecoveryIdentity",
    "PersistedModelCallStatus",
]
