from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from labcourt.application.backlog_retry import BacklogRetryCoordinator
from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogRetryDisposition,
    BacklogRetryFailure,
    BacklogRetrySuccess,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    VlmRole,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ContractViolation
from labcourt.ports.backlog import BacklogStore
from labcourt.ports.screening_repository import M3BacklogRetryCommit

RUN_ID = "run-01"
NOW = datetime(2026, 7, 28, 12, tzinfo=UTC)


def _pending_item(
    *,
    stage: BacklogStage = BacklogStage.SCREENING,
    max_attempts: int = 3,
) -> BacklogItem:
    return BacklogItem(
        run_id=RUN_ID,
        case_id="case-01",
        stage=stage,
        role=(VlmRole.SCREENING if stage == BacklogStage.SCREENING else VlmRole.PROSECUTOR),
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id="1" * 64,
        ),
        stage_input_sha256="2" * 64,
        max_attempts=max_attempts,
        manifest_id="3" * 64,
    )


def _leased_item(
    *,
    stage: BacklogStage = BacklogStage.SCREENING,
    max_attempts: int = 3,
) -> BacklogItem:
    pending = _pending_item(stage=stage, max_attempts=max_attempts)
    return BacklogItem.model_validate(
        {
            **pending.model_dump(mode="json", exclude_computed_fields=True),
            "attempt_count": 1,
            "status": BacklogStatus.LEASED.value,
            "lease_id": "4" * 64,
            "lease_owner_sha256": "5" * 64,
            "lease_expires_at": "2026-07-28T12:02:00Z",
        }
    )


def _reclaimed_item(
    *,
    exhausted: bool = False,
    stage: BacklogStage = BacklogStage.SCREENING,
) -> BacklogItem:
    pending = _pending_item(
        stage=stage,
        max_attempts=(1 if exhausted else 3),
    )
    return BacklogItem.model_validate(
        {
            **pending.model_dump(mode="json", exclude_computed_fields=True),
            "attempt_count": 1,
            "status": (BacklogStatus.EXHAUSTED.value if exhausted else BacklogStatus.PENDING.value),
        }
    )


def _lease_identity(item: BacklogItem) -> BacklogLeaseIdentity:
    assert item.lease_id is not None
    return BacklogLeaseIdentity(
        run_id=item.run_id,
        item_id=item.item_id,
        lease_id=item.lease_id,
        attempt_count=item.attempt_count,
        retry_generation=item.retry_generation,
    )


def _success_result(item: BacklogItem) -> _Result:
    outcome = BacklogRetrySuccess(
        lease=_lease_identity(item),
        completion_case_status=CaseStatus.ESCALATED,
        completion_ref=ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id="6" * 64,
        ),
        response_refs=(ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id="7" * 64),),
        manifest_id=item.manifest_id,
    )
    completed = BacklogItem.model_validate(
        {
            **item.model_dump(mode="json", exclude_computed_fields=True),
            "status": BacklogStatus.COMPLETED.value,
            "lease_id": None,
            "lease_owner_sha256": None,
            "lease_expires_at": None,
        }
    )
    receipt = BacklogCompletionReceipt(
        outcome=outcome,
        backlog_status=BacklogStatus.COMPLETED,
        completion_ref=outcome.completion_ref,
        completion_case_status=CaseStatus.ESCALATED,
        completion_case_revision=4,
        completion_audit_sequence=8,
        completion_audit_entry_hash="8" * 64,
        manifest_id=item.manifest_id,
    )
    return _Result(completed, receipt)


def _failure_result(item: BacklogItem, *, exhausted: bool = False) -> _Result:
    status = BacklogStatus.EXHAUSTED if exhausted else BacklogStatus.PENDING
    outcome = BacklogRetryFailure(
        lease=_lease_identity(item),
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=status,
        manifest_id=item.manifest_id,
    )
    updated = BacklogItem.model_validate(
        {
            **item.model_dump(mode="json", exclude_computed_fields=True),
            "status": status.value,
            "lease_id": None,
            "lease_owner_sha256": None,
            "lease_expires_at": None,
        }
    )
    receipt = BacklogCompletionReceipt(
        outcome=outcome,
        backlog_status=status,
        completion_ref=ArtifactRef(
            kind=ArtifactKind.BACKLOG_ITEM,
            artifact_id=item.item_id,
        ),
        completion_case_status=outcome.completion_case_status,
        completion_case_revision=4,
        completion_audit_sequence=8,
        completion_audit_entry_hash="8" * 64,
        manifest_id=item.manifest_id,
    )
    return _Result(updated, receipt)


@dataclass(frozen=True, slots=True)
class _Result:
    item: BacklogItem
    receipt: BacklogCompletionReceipt


class _Store:
    def __init__(
        self,
        *,
        leased: BacklogItem | None,
        reclaimed: tuple[BacklogItem, ...] = (),
    ) -> None:
        self.leased = leased
        self.reclaimed = reclaimed
        self.reclaim_calls: list[tuple[str, datetime, int]] = []
        self.lease_calls: list[tuple[str, BacklogStage, str, datetime]] = []

    def reclaim_expired(
        self,
        run_id: str,
        not_after: datetime,
        limit: int,
    ) -> tuple[BacklogItem, ...]:
        self.reclaim_calls.append((run_id, not_after, limit))
        return self.reclaimed

    def lease_next(
        self,
        run_id: str,
        stage: BacklogStage,
        lease_owner_sha256: str,
        lease_expires_at: datetime,
    ) -> BacklogItem | None:
        self.lease_calls.append((run_id, stage, lease_owner_sha256, lease_expires_at))
        if self.leased is not None and self.leased.stage == stage:
            return self.leased
        return None


class _Processor:
    minimum_backlog_lease_seconds = 90

    def __init__(self, result: _Result | Exception) -> None:
        self.result = result
        self.calls: list[BacklogItem] = []

    def retry_leased_item(self, leased_item: BacklogItem) -> M3BacklogRetryCommit:
        self.calls.append(leased_item)
        if isinstance(self.result, Exception):
            raise self.result
        return cast(M3BacklogRetryCommit, self.result)


def _coordinator(
    store: _Store,
    processor: _Processor,
    *,
    lease_duration_seconds: int = 120,
) -> BacklogRetryCoordinator:
    return BacklogRetryCoordinator(
        backlog_store=cast(BacklogStore, store),
        processor=processor,
        lease_duration_seconds=lease_duration_seconds,
        clock=lambda: NOW,
    )


def test_run_once_reclaims_then_reports_no_work_without_processor_call() -> None:
    reclaimed = _reclaimed_item()
    store = _Store(leased=None, reclaimed=(reclaimed,))
    processor = _Processor(RuntimeError("must not run"))

    report = _coordinator(store, processor).run_once(RUN_ID, "worker-01")

    assert report.disposition == BacklogRetryDisposition.NO_WORK
    assert report.reclaimed_expired_count == 1
    assert report.reclaimed_exhausted_count == 0
    assert report.item is None
    assert processor.calls == []
    assert store.reclaim_calls == [(RUN_ID, NOW, 100)]


def test_run_once_reports_reclaimed_exhaustion_without_leasing_it() -> None:
    exhausted = _reclaimed_item(exhausted=True)
    store = _Store(leased=None, reclaimed=(exhausted,))
    processor = _Processor(RuntimeError("must not run"))

    report = _coordinator(store, processor).run_once(RUN_ID, "worker-01")

    assert report.disposition == BacklogRetryDisposition.NO_WORK
    assert report.reclaimed_expired_count == 1
    assert report.reclaimed_exhausted_count == 1
    assert report.item is None
    assert processor.calls == []


def test_m3_worker_rejects_a_hearing_item_returned_by_reclaim() -> None:
    hearing = _reclaimed_item(stage=BacklogStage.HEARING)
    store = _Store(leased=None, reclaimed=(hearing,))
    processor = _Processor(RuntimeError("must not run"))

    with pytest.raises(ContractViolation, match="invalid recovered item"):
        _coordinator(store, processor).run_once(RUN_ID, "worker-01")

    assert store.lease_calls == []
    assert processor.calls == []


@pytest.mark.parametrize(
    ("result_factory", "disposition"),
    [
        (_success_result, BacklogRetryDisposition.COMPLETED),
        (_failure_result, BacklogRetryDisposition.RETRY_PENDING),
    ],
)
def test_run_once_leases_exactly_one_and_returns_atomic_report(
    result_factory: object,
    disposition: BacklogRetryDisposition,
) -> None:
    leased = _leased_item()
    assert callable(result_factory)
    result = result_factory(leased)
    assert isinstance(result, _Result)
    store = _Store(leased=leased)
    processor = _Processor(result)

    report = _coordinator(store, processor).run_once(RUN_ID, "worker-01")

    assert report.disposition == disposition
    assert report.item == result.item
    assert report.receipt == result.receipt
    assert processor.calls == [leased]
    assert len(store.lease_calls) == 1
    assert store.lease_calls[0] == (
        RUN_ID,
        BacklogStage.SCREENING,
        sha256_hex(["backlog-retry-worker", 1, RUN_ID, "worker-01"]),
        NOW + timedelta(seconds=120),
    )


def test_run_once_reports_exhaustion_as_human_review() -> None:
    leased = _leased_item(max_attempts=1)
    result = _failure_result(leased, exhausted=True)

    report = _coordinator(
        _Store(leased=leased),
        _Processor(result),
    ).run_once(RUN_ID, "worker-01")

    assert report.disposition == BacklogRetryDisposition.HUMAN_REVIEW
    assert report.receipt is not None
    assert report.receipt.completion_case_status == CaseStatus.HUMAN_REVIEW


def test_worker_requests_screening_and_does_not_lease_future_stage() -> None:
    leased = _leased_item(stage=BacklogStage.HEARING)
    processor = _Processor(_success_result(_leased_item()))
    store = _Store(leased=leased)

    report = _coordinator(store, processor).run_once(RUN_ID, "worker-01")

    assert report.disposition == BacklogRetryDisposition.NO_WORK
    assert store.lease_calls[0][1] == BacklogStage.SCREENING
    assert processor.calls == []


def test_worker_rejects_lease_shorter_than_two_calls_before_queue_mutation() -> None:
    store = _Store(leased=None)
    processor = _Processor(RuntimeError("must not run"))

    with pytest.raises(ValueError, match="stale-claim wait"):
        _coordinator(store, processor, lease_duration_seconds=89)

    assert store.reclaim_calls == []
    assert store.lease_calls == []


def test_unexpected_processor_failure_is_not_swallowed_or_released() -> None:
    leased = _leased_item()
    processor = _Processor(RuntimeError("programming defect"))

    with pytest.raises(RuntimeError, match="programming defect"):
        _coordinator(_Store(leased=leased), processor).run_once(RUN_ID, "worker-01")

    assert processor.calls == [leased]
