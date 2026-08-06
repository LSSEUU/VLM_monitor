"""Capability-minimal M4 boundary for provider-free response recovery."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelRequest,
    HearingModelResponse,
)
from labcourt.contracts.hearing_recovery import MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS
from labcourt.contracts.references import require_reference_token

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class HearingModelResponseRecoveryIdentity:
    """Opaque capability-free token shared only by maintenance composition."""

    __slots__ = ()


class PersistedHearingModelCallStatus(StrEnum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"


class HearingModelCallRecoveryScanFailureCode(StrEnum):
    CLAIM_AUTHORITY_INVALID = "CLAIM_AUTHORITY_INVALID"
    DATABASE_OBSERVATION_CONFLICT = "DATABASE_OBSERVATION_CONFLICT"


@dataclass(frozen=True, slots=True)
class HearingModelCallRecoveryCandidate:
    """One canonical request claim reconstructed entirely from SQLite."""

    request: HearingModelRequest
    status: PersistedHearingModelCallStatus
    takeover_count: int
    lease_expires_at: datetime | None = None
    response_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.request) is not HearingModelRequest:
            raise TypeError("hearing recovery candidate requires a HearingModelRequest")
        if HearingModelRequest.model_validate(self.request.model_dump(mode="json")) != self.request:
            raise ValueError("hearing recovery request is not canonical")
        if not isinstance(self.status, PersistedHearingModelCallStatus):
            raise TypeError("hearing recovery candidate status is invalid")
        if (
            not isinstance(self.takeover_count, int)
            or isinstance(self.takeover_count, bool)
            or self.takeover_count < 0
        ):
            raise ValueError("hearing recovery takeover count must be non-negative")
        if self.status == PersistedHearingModelCallStatus.ACTIVE:
            expiry = self.lease_expires_at
            if (
                not isinstance(expiry, datetime)
                or expiry.tzinfo is None
                or expiry.utcoffset() is None
                or expiry.utcoffset() != timedelta(0)
                or self.response_id is not None
            ):
                raise ValueError("active hearing recovery claim has invalid fields")
        elif (
            self.lease_expires_at is not None
            or self.response_id is None
            or _SHA256.fullmatch(self.response_id) is None
        ):
            raise ValueError("completed hearing recovery claim has invalid fields")

    @property
    def sort_key(self) -> str:
        return self.request.request_id


@dataclass(frozen=True, slots=True)
class HearingModelCallRecoveryScanAnomaly:
    """Opaque malformed claim that cannot safely expose reconstructed fields."""

    run_id: str
    source_token: str
    failure_code: HearingModelCallRecoveryScanFailureCode

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "hearing recovery anomaly run reference")
        if _SHA256.fullmatch(self.source_token) is None:
            raise ValueError("hearing recovery anomaly requires an opaque SHA-256 token")
        if not isinstance(self.failure_code, HearingModelCallRecoveryScanFailureCode):
            raise TypeError("hearing recovery anomaly failure code is invalid")

    @property
    def sort_key(self) -> str:
        return self.source_token


@dataclass(frozen=True, slots=True)
class HearingModelCallRecoveryScan:
    """Stable bounded inventory; incomplete or anomalous scans forbid mutation."""

    run_id: str
    max_items: int
    candidates: tuple[HearingModelCallRecoveryCandidate, ...]
    complete: bool
    anomalies: tuple[HearingModelCallRecoveryScanAnomaly, ...] = ()

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "hearing recovery scan run reference")
        if (
            not isinstance(self.max_items, int)
            or isinstance(self.max_items, bool)
            or not 1 <= self.max_items <= MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS
        ):
            raise ValueError("hearing recovery scan max_items is invalid")
        if type(self.complete) is not bool:
            raise TypeError("hearing recovery scan complete must be a boolean")
        if not isinstance(self.candidates, tuple) or any(
            not isinstance(item, HearingModelCallRecoveryCandidate) for item in self.candidates
        ):
            raise TypeError("hearing recovery candidates must be a typed tuple")
        if not isinstance(self.anomalies, tuple) or any(
            not isinstance(item, HearingModelCallRecoveryScanAnomaly) for item in self.anomalies
        ):
            raise TypeError("hearing recovery anomalies must be a typed tuple")
        observed = self.claims_scanned
        if observed > self.max_items or (not self.complete and observed != self.max_items):
            raise ValueError("hearing recovery scan conflicts with its hard bound")
        if any(item.request.run_id != self.run_id for item in self.candidates) or any(
            item.run_id != self.run_id for item in self.anomalies
        ):
            raise ValueError("hearing recovery scan contains another run")
        candidate_keys = tuple(item.sort_key for item in self.candidates)
        anomaly_keys = tuple(item.sort_key for item in self.anomalies)
        if (
            len(candidate_keys) != len(set(candidate_keys))
            or candidate_keys != tuple(sorted(candidate_keys))
            or len(anomaly_keys) != len(set(anomaly_keys))
            or anomaly_keys != tuple(sorted(anomaly_keys))
            or set(candidate_keys) & set(anomaly_keys)
        ):
            raise ValueError("hearing recovery observations must be unique and stable")

    @property
    def claims_scanned(self) -> int:
        return len(self.candidates) + len(self.anomalies)


class HearingModelCallRecoveryRepository(Protocol):
    """Only claim/cache operations needed to converge durable response journals."""

    def scan_hearing_model_call_recovery_candidates(
        self,
        run_id: str,
        max_items: int,
    ) -> HearingModelCallRecoveryScan: ...

    def complete_expired_hearing_model_call_from_recovery(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
        observed_lease_expires_at: datetime,
        observed_takeover_count: int,
    ) -> HearingModelCacheEntry:
        """Atomically bind response/cache/claim/usage without reserving again.

        The implementation must preserve the original media reservation, add
        output usage at most once, verify the raw file again in-transaction,
        and compare the observed lease fields as CAS authority.  It must never
        reset a session budget or expose an ACQUIRED/provider capability.
        """

        ...

    def load_hearing_model_cache_entry_for_recovery(
        self,
        run_id: str,
        request: HearingModelRequest,
    ) -> HearingModelCacheEntry | None: ...

    def load_hearing_model_response_for_request(
        self,
        run_id: str,
        request_id: str,
    ) -> HearingModelResponse | None: ...


class HearingRecoveryResponseStore(Protocol):
    """Journal convergence only: no publish, byte-read, or parser capability."""

    def probe_recovery(
        self,
        request: HearingModelRequest,
    ) -> HearingModelResponse | None: ...

    def recover(
        self,
        request: HearingModelRequest,
    ) -> HearingModelResponse | None: ...

    def verify_raw_response(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelResponse: ...

    def acknowledge(
        self,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> None: ...


__all__ = [
    "HearingModelCallRecoveryCandidate",
    "HearingModelCallRecoveryRepository",
    "HearingModelCallRecoveryScan",
    "HearingModelCallRecoveryScanAnomaly",
    "HearingModelCallRecoveryScanFailureCode",
    "HearingModelResponseRecoveryIdentity",
    "HearingRecoveryResponseStore",
    "PersistedHearingModelCallStatus",
]
