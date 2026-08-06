"""Bounded M3 backlog leasing and retry orchestration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol

from labcourt.contracts.backlog import (
    BacklogItem,
    BacklogRetryDisposition,
    BacklogRetryReport,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import BacklogStage, BacklogStatus
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ContractViolation
from labcourt.ports.backlog import BacklogStore
from labcourt.ports.screening_repository import M3BacklogRetryCommit


class BacklogRetryProcessor(Protocol):
    """Application capability that resolves one exact active lease atomically."""

    @property
    def minimum_backlog_lease_seconds(self) -> int: ...

    def retry_leased_item(self, leased_item: BacklogItem) -> M3BacklogRetryCommit: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


class BacklogRetryCoordinator:
    """Reclaim stale leases and process at most one current M3 screening item."""

    def __init__(
        self,
        *,
        backlog_store: BacklogStore,
        processor: BacklogRetryProcessor,
        lease_duration_seconds: int = 120,
        reclaim_limit: int = 100,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        for dependency, method, name in (
            (backlog_store, "reclaim_expired", "backlog_store"),
            (backlog_store, "lease_next", "backlog_store"),
            (processor, "retry_leased_item", "processor"),
        ):
            if not callable(getattr(dependency, method, None)):
                raise TypeError(f"{name} does not implement {method}")
        if (
            not isinstance(lease_duration_seconds, int)
            or isinstance(lease_duration_seconds, bool)
            or not 1 <= lease_duration_seconds <= 14_400
        ):
            raise ValueError("lease_duration_seconds must be an integer in [1, 14400]")
        minimum_lease = getattr(processor, "minimum_backlog_lease_seconds", None)
        if (
            not isinstance(minimum_lease, int)
            or isinstance(minimum_lease, bool)
            or not 1 <= minimum_lease <= 14_400
        ):
            raise TypeError("processor must expose a valid minimum_backlog_lease_seconds")
        if lease_duration_seconds < minimum_lease:
            raise ValueError(
                "lease_duration_seconds cannot cover stale-claim wait, two calls, and commit margin"
            )
        if (
            not isinstance(reclaim_limit, int)
            or isinstance(reclaim_limit, bool)
            or not 1 <= reclaim_limit <= 10_000
        ):
            raise ValueError("reclaim_limit must be an integer in [1, 10000]")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._backlog = backlog_store
        self._processor = processor
        self._lease_duration = timedelta(seconds=lease_duration_seconds)
        self._reclaim_limit = reclaim_limit
        self._clock = clock

    def run_once(self, run_id: str, worker_id: str) -> BacklogRetryReport:
        """Perform one bounded recovery/lease/process cycle without polling."""

        safe_run_id = require_reference_token(run_id, "backlog retry run reference")
        safe_worker_id = require_reference_token(worker_id, "backlog retry worker reference")
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("backlog retry clock must return a timezone-aware UTC datetime")

        reclaimed = self._backlog.reclaim_expired(
            safe_run_id,
            now,
            self._reclaim_limit,
        )
        reclaimed_ids = tuple(item.item_id for item in reclaimed)
        if (
            any(
                item.run_id != safe_run_id
                or item.stage != BacklogStage.SCREENING
                or item.status not in {BacklogStatus.PENDING, BacklogStatus.EXHAUSTED}
                or item.attempt_count <= 0
                for item in reclaimed
            )
            or len(reclaimed) > self._reclaim_limit
        ):
            raise ContractViolation("backlog reclaim returned an invalid recovered item")
        if len(reclaimed_ids) != len(set(reclaimed_ids)):
            raise ContractViolation("backlog reclaim returned duplicate items")
        reclaimed_exhausted_count = sum(
            item.status == BacklogStatus.EXHAUSTED for item in reclaimed
        )

        owner_sha256 = sha256_hex(["backlog-retry-worker", 1, safe_run_id, safe_worker_id])
        leased = self._backlog.lease_next(
            safe_run_id,
            BacklogStage.SCREENING,
            owner_sha256,
            now + self._lease_duration,
        )
        if leased is None:
            return BacklogRetryReport(
                run_id=safe_run_id,
                reclaimed_expired_count=len(reclaimed),
                reclaimed_exhausted_count=reclaimed_exhausted_count,
                disposition=BacklogRetryDisposition.NO_WORK,
            )
        if (
            leased.run_id != safe_run_id
            or leased.status != BacklogStatus.LEASED
            or leased.stage != BacklogStage.SCREENING
        ):
            raise ContractViolation("backlog lease did not return current SCREENING work")

        committed = self._processor.retry_leased_item(leased)
        disposition = {
            BacklogStatus.COMPLETED: BacklogRetryDisposition.COMPLETED,
            BacklogStatus.PENDING: BacklogRetryDisposition.RETRY_PENDING,
            BacklogStatus.EXHAUSTED: BacklogRetryDisposition.HUMAN_REVIEW,
        }.get(committed.item.status)
        if disposition is None:
            raise ContractViolation("backlog retry processor returned a non-terminal lease")
        return BacklogRetryReport(
            run_id=safe_run_id,
            reclaimed_expired_count=len(reclaimed),
            reclaimed_exhausted_count=reclaimed_exhausted_count,
            disposition=disposition,
            item=committed.item,
            receipt=committed.receipt,
        )


__all__ = ["BacklogRetryCoordinator", "BacklogRetryProcessor"]
