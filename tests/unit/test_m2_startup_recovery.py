from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from labcourt.application.recovery import StartupRecoveryCoordinator
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    PurgeDisposition,
    PurgeReasonCode,
)
from labcourt.contracts.recovery import RecoveryReport
from labcourt.contracts.storage import ArtifactRef, PurgeItemResult
from labcourt.exceptions import ContractViolation

RUN_ID = "run-startup-recovery-01"
STARTED_AT = datetime(2026, 7, 27, 12, tzinfo=UTC)
MINIMUM_AGE = timedelta(minutes=10)
MEDIA_A = "a" * 64
MEDIA_B = "b" * 64
CROP = "c" * 64


def _retention_result(media_sha256: str, *, run_id: str = RUN_ID) -> PurgeItemResult:
    return PurgeItemResult(
        run_id=run_id,
        media_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=media_sha256),
        crop_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=CROP),),
        disposition=PurgeDisposition.RETAINED,
        reason_code=PurgeReasonCode.ALREADY_PURGED,
        previous_availability=MediaAvailability.PURGED_BY_RETENTION,
        current_availability=MediaAvailability.PURGED_BY_RETENTION,
        audit_sequences=(1, 2),
    )


def _orphan_report(
    *,
    run_id: str = RUN_ID,
    cutoff: datetime = STARTED_AT - MINIMUM_AGE,
) -> RecoveryReport:
    return RecoveryReport(run_id=run_id, not_modified_after=cutoff)


class _Retention:
    def __init__(
        self,
        timeline: list[str],
        result: tuple[PurgeItemResult, ...],
    ) -> None:
        self.timeline = timeline
        self.result = result

    def recover(self, run_id: str) -> tuple[PurgeItemResult, ...]:
        assert run_id == RUN_ID
        self.timeline.append("retention")
        return self.result


class _Orphan:
    def __init__(self, timeline: list[str], report: RecoveryReport) -> None:
        self.timeline = timeline
        self.report = report
        self.calls: list[tuple[str, datetime, timedelta]] = []

    def recover(
        self,
        run_id: str,
        now: datetime,
        minimum_age: timedelta,
    ) -> RecoveryReport:
        self.timeline.append("orphan")
        self.calls.append((run_id, now, minimum_age))
        return self.report


class _InvalidRetention:
    def __init__(self, timeline: list[str], result: object) -> None:
        self.timeline = timeline
        self.result = result

    def recover(self, run_id: str) -> object:
        self.timeline.append("retention")
        return self.result


class _InvalidOrphan:
    def __init__(self, timeline: list[str], result: object) -> None:
        self.timeline = timeline
        self.result = result

    def recover(self, run_id: str, now: datetime, minimum_age: timedelta) -> object:
        self.timeline.append("orphan")
        return self.result


def test_startup_recovery_runs_retention_first_and_normalizes_claim_order() -> None:
    timeline: list[str] = []
    retention = _Retention(
        timeline,
        (_retention_result(MEDIA_B), _retention_result(MEDIA_A)),
    )
    orphan = _Orphan(timeline, _orphan_report())

    report = StartupRecoveryCoordinator(
        retention=retention,
        orphan=orphan,
    ).recover(RUN_ID, STARTED_AT, MINIMUM_AGE)

    assert timeline == ["retention", "orphan"]
    assert orphan.calls == [(RUN_ID, STARTED_AT, MINIMUM_AGE)]
    assert tuple(item.media_ref.artifact_id for item in report.retention_items) == (
        MEDIA_A,
        MEDIA_B,
    )
    assert report.orphan_report == orphan.report


@pytest.mark.parametrize(
    ("result", "message"),
    [
        ([], "invalid results"),
        ((object(),), "invalid results"),
        ((_retention_result(MEDIA_A, run_id="other-run"),), "outside the run"),
        (
            (_retention_result(MEDIA_A), _retention_result(MEDIA_A)),
            "duplicate media",
        ),
    ],
)
def test_invalid_retention_results_stop_before_orphan_recovery(
    result: object,
    message: str,
) -> None:
    timeline: list[str] = []
    orphan = _Orphan(timeline, _orphan_report())
    coordinator = StartupRecoveryCoordinator(
        retention=_InvalidRetention(timeline, result),  # type: ignore[arg-type]
        orphan=orphan,
    )

    with pytest.raises(ContractViolation, match=message):
        coordinator.recover(RUN_ID, STARTED_AT, MINIMUM_AGE)

    assert timeline == ["retention"]
    assert orphan.calls == []


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (object(), "invalid report"),
        (_orphan_report(run_id="other-run"), "outside the run"),
        (
            _orphan_report(cutoff=STARTED_AT - timedelta(minutes=9)),
            "wrong cutoff",
        ),
    ],
)
def test_invalid_orphan_report_is_rejected_after_retention(
    result: object,
    message: str,
) -> None:
    timeline: list[str] = []
    coordinator = StartupRecoveryCoordinator(
        retention=_Retention(timeline, ()),
        orphan=_InvalidOrphan(timeline, result),  # type: ignore[arg-type]
    )

    with pytest.raises(ContractViolation, match=message):
        coordinator.recover(RUN_ID, STARTED_AT, MINIMUM_AGE)

    assert timeline == ["retention", "orphan"]


@pytest.mark.parametrize(
    ("run_id", "started_at", "minimum_age", "message"),
    [
        ("../other", STARTED_AT, MINIMUM_AGE, "startup recovery run_id"),
        (RUN_ID, STARTED_AT.replace(tzinfo=None), MINIMUM_AGE, "timezone-aware"),
        (RUN_ID, STARTED_AT, timedelta(0), "positive timedelta"),
    ],
)
def test_invalid_inputs_fail_before_any_recovery_mutation(
    run_id: str,
    started_at: datetime,
    minimum_age: timedelta,
    message: str,
) -> None:
    timeline: list[str] = []
    coordinator = StartupRecoveryCoordinator(
        retention=_Retention(timeline, ()),
        orphan=_Orphan(timeline, _orphan_report()),
    )

    with pytest.raises(ValueError, match=message):
        coordinator.recover(run_id, started_at, minimum_age)

    assert timeline == []
