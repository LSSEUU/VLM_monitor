from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from labcourt.application.recovery import OrphanRecoveryCoordinator
from labcourt.contracts.enums import (
    RecoveryArea,
    RecoveryDisposition,
    RecoveryReasonCode,
)
from labcourt.contracts.recovery import RecoveryItemResult, recovery_source_token
from labcourt.exceptions import ContractViolation
from labcourt.ports.recovery import (
    RecoveryCandidate,
    RecoveryScan,
    StagingCleanupCandidate,
)

RUN_ID = "run-recovery-01"
SHA_A = "a" * 64
SHA_B = "b" * 64
NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


def _candidate(area: RecoveryArea, digest: str) -> RecoveryCandidate:
    if area == RecoveryArea.FINAL_MEDIA:
        path = f"{RUN_ID}/frames/{digest}.png"
    else:
        path = f".staging/{RUN_ID}/crop-{'c' * 64}/media.png"
    return RecoveryCandidate(
        run_id=RUN_ID,
        area=area,
        source_relative_path=path,
        source_token=recovery_source_token(path),
        content_sha256=digest,
    )


class _Repository:
    def __init__(self, referenced: set[str], result_override: object | None = None) -> None:
        self.referenced = referenced
        self.result_override = result_override
        self.queries: list[tuple[str, str]] = []

    def media_is_referenced(self, run_id: str, media_sha256: str) -> bool:
        self.queries.append((run_id, media_sha256))
        if self.result_override is not None:
            return self.result_override  # type: ignore[return-value]
        return media_sha256 in self.referenced


class _FileOps:
    def __init__(self, scan: RecoveryScan) -> None:
        self.scan = scan
        self.quarantined: list[tuple[RecoveryCandidate, datetime]] = []
        self.cleaned: list[StagingCleanupCandidate] = []

    def discover(
        self,
        run_id: str,
        max_items: int,
        max_depth: int,
        max_name_bytes: int,
    ) -> RecoveryScan:
        assert (max_items, max_depth, max_name_bytes) == (10, 2, 128)
        return self.scan

    def quarantine(
        self,
        candidate: RecoveryCandidate,
        not_modified_after: datetime,
    ) -> RecoveryItemResult:
        self.quarantined.append((candidate, not_modified_after))
        if candidate.area == RecoveryArea.FINAL_MEDIA:
            reason = RecoveryReasonCode.ORPHAN_QUARANTINED
            locator = f".quarantine/{candidate.run_id}/frames/{candidate.content_sha256}.png"
        else:
            reason = RecoveryReasonCode.STAGING_QUARANTINED
            locator = (
                f".quarantine/{candidate.run_id}/staging/"
                f"{candidate.source_token}-{candidate.content_sha256}.bin"
            )
        return RecoveryItemResult(
            run_id=candidate.run_id,
            area=candidate.area,
            source_token=candidate.source_token,
            disposition=RecoveryDisposition.QUARANTINED,
            reason_code=reason,
            content_sha256=candidate.content_sha256,
            quarantine_relative_path=locator,
        )

    def cleanup_empty_staging(
        self,
        candidate: StagingCleanupCandidate,
        not_modified_after: datetime,
    ) -> RecoveryItemResult:
        assert not_modified_after < NOW
        self.cleaned.append(candidate)
        return RecoveryItemResult(
            run_id=candidate.run_id,
            area=RecoveryArea.STAGING,
            source_token=candidate.source_token,
            disposition=RecoveryDisposition.CLEANED,
            reason_code=RecoveryReasonCode.EMPTY_STAGING_CLEANED,
        )


def test_recovery_keeps_referenced_media_and_quarantines_only_unreferenced_files() -> None:
    referenced = _candidate(RecoveryArea.FINAL_MEDIA, SHA_A)
    orphan = _candidate(RecoveryArea.FINAL_MEDIA, SHA_B)
    staging = _candidate(RecoveryArea.STAGING, SHA_A)
    candidates = tuple(sorted((referenced, orphan, staging), key=lambda item: item.sort_key))
    file_ops = _FileOps(RecoveryScan(run_id=RUN_ID, candidates=candidates))
    repository = _Repository({SHA_A})
    coordinator = OrphanRecoveryCoordinator(
        repository,
        file_ops,
        max_items=10,
        max_depth=2,
        max_name_bytes=128,
    )

    report = coordinator.recover(RUN_ID, NOW, timedelta(hours=1))

    reasons = {item.source_token: item.reason_code for item in report.items}
    assert reasons[referenced.source_token] == RecoveryReasonCode.REFERENCED_MEDIA
    assert reasons[orphan.source_token] == RecoveryReasonCode.ORPHAN_QUARANTINED
    assert reasons[staging.source_token] == RecoveryReasonCode.STAGING_QUARANTINED
    assert [item[0] for item in file_ops.quarantined] == [orphan, staging]
    assert all(cutoff == NOW - timedelta(hours=1) for _, cutoff in file_ops.quarantined)
    assert set(repository.queries) == {(RUN_ID, SHA_A), (RUN_ID, SHA_B)}
    assert tuple(item.sort_key for item in report.items) == tuple(
        sorted(item.sort_key for item in report.items)
    )


def test_recovery_preserves_discovery_anomalies_without_querying_database() -> None:
    anomaly = RecoveryItemResult(
        run_id=RUN_ID,
        area=RecoveryArea.STAGING,
        source_token=SHA_A,
        disposition=RecoveryDisposition.ANOMALY,
        reason_code=RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE,
    )
    repository = _Repository(set())
    coordinator = OrphanRecoveryCoordinator(
        repository,
        _FileOps(RecoveryScan(run_id=RUN_ID, anomalies=(anomaly,))),
        max_items=10,
        max_depth=2,
        max_name_bytes=128,
    )

    report = coordinator.recover(RUN_ID, NOW, timedelta(minutes=5))

    assert report.items == (anomaly,)
    assert repository.queries == []


def test_recovery_cleans_exact_empty_staging_candidate_without_database_query() -> None:
    source = f".staging/{RUN_ID}/crop-{'d' * 64}"
    candidate = StagingCleanupCandidate(
        run_id=RUN_ID,
        source_relative_path=source,
        source_token=recovery_source_token(source),
    )
    file_ops = _FileOps(RecoveryScan(run_id=RUN_ID, staging_cleanup_candidates=(candidate,)))
    repository = _Repository(set())
    report = OrphanRecoveryCoordinator(
        repository,
        file_ops,
        max_items=10,
        max_depth=2,
        max_name_bytes=128,
    ).recover(RUN_ID, NOW, timedelta(minutes=5))

    assert file_ops.cleaned == [candidate]
    assert report.items[0].disposition == RecoveryDisposition.CLEANED
    assert report.items[0].reason_code == RecoveryReasonCode.EMPTY_STAGING_CLEANED
    assert repository.queries == []


def test_recovery_rejects_non_boolean_reference_answers() -> None:
    candidate = _candidate(RecoveryArea.FINAL_MEDIA, SHA_A)
    coordinator = OrphanRecoveryCoordinator(
        _Repository(set(), result_override=1),
        _FileOps(RecoveryScan(run_id=RUN_ID, candidates=(candidate,))),
        max_items=10,
        max_depth=2,
        max_name_bytes=128,
    )

    with pytest.raises(ContractViolation, match="boolean"):
        coordinator.recover(RUN_ID, NOW, timedelta(minutes=5))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_items": 0}, "max_items"),
        ({"max_depth": 3}, "max_depth"),
        ({"max_name_bytes": 256}, "max_name_bytes"),
    ],
)
def test_recovery_limits_are_hard_bounded(kwargs: dict[str, int], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        OrphanRecoveryCoordinator(
            _Repository(set()), _FileOps(RecoveryScan(run_id=RUN_ID)), **kwargs
        )


def test_recovery_requires_strict_run_time_and_positive_minimum_age() -> None:
    coordinator = OrphanRecoveryCoordinator(
        _Repository(set()), _FileOps(RecoveryScan(run_id=RUN_ID))
    )
    with pytest.raises(ValueError):
        coordinator.recover("../other", NOW, timedelta(minutes=1))
    with pytest.raises(ValueError, match="timezone-aware"):
        coordinator.recover(RUN_ID, datetime(2026, 7, 27), timedelta(minutes=1))
    with pytest.raises(ValueError, match="positive"):
        coordinator.recover(RUN_ID, NOW, timedelta(0))
