from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    PurgeDisposition,
    PurgeReasonCode,
    RecoveryArea,
    RecoveryDisposition,
    RecoveryReasonCode,
)
from labcourt.contracts.recovery import (
    RecoveryItemResult,
    RecoveryReport,
    StartupRecoveryReport,
)
from labcourt.contracts.storage import ArtifactRef, PurgeItemResult

RUN_ID = "run-startup-recovery-01"
STARTED_AT = datetime(2026, 7, 27, 12, tzinfo=UTC)
MEDIA_A = "a" * 64
MEDIA_B = "b" * 64
CROP = "c" * 64


def _retention_result(
    media_sha256: str,
    *,
    run_id: str = RUN_ID,
    attention: bool = False,
) -> PurgeItemResult:
    if attention:
        return PurgeItemResult(
            run_id=run_id,
            media_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=media_sha256),
            crop_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=CROP),),
            disposition=PurgeDisposition.RECOVERY_REQUIRED,
            reason_code=PurgeReasonCode.WORKSPACE_OPERATION_FAILED,
            previous_availability=MediaAvailability.PURGING,
            current_availability=MediaAvailability.PURGING,
            audit_sequences=(1,),
        )
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
    items: tuple[RecoveryItemResult, ...] = (),
    cutoff: datetime | None = None,
) -> RecoveryReport:
    return RecoveryReport(
        run_id=run_id,
        not_modified_after=cutoff or STARTED_AT - timedelta(minutes=5),
        items=items,
    )


def _orphan_item(
    disposition: RecoveryDisposition,
    reason_code: RecoveryReasonCode,
) -> RecoveryItemResult:
    return RecoveryItemResult(
        run_id=RUN_ID,
        area=RecoveryArea.FINAL_MEDIA,
        source_token="d" * 64,
        disposition=disposition,
        reason_code=reason_code,
        content_sha256=MEDIA_A if disposition == RecoveryDisposition.RETAINED else None,
    )


def test_startup_recovery_status_is_computed_and_serialized_claims_cannot_be_forged() -> None:
    report = StartupRecoveryReport(
        run_id=RUN_ID,
        started_at=STARTED_AT,
        retention_items=(_retention_result(MEDIA_A, attention=True),),
        orphan_report=_orphan_report(),
    )

    assert report.requires_attention is True
    assert report.passed is False
    payload = report.model_dump(mode="json")
    assert StartupRecoveryReport.model_validate(payload) == report

    with pytest.raises(ValidationError, match="requires_attention conflicts"):
        StartupRecoveryReport.model_validate({**payload, "requires_attention": False})
    with pytest.raises(ValidationError, match="passed conflicts"):
        StartupRecoveryReport.model_validate({**payload, "passed": True})
    with pytest.raises(ValidationError, match="requires_attention conflicts"):
        StartupRecoveryReport.model_validate({**payload, "requires_attention": 1})


def test_expected_retention_and_minimum_age_outcomes_are_not_failures() -> None:
    minimum_age_item = _orphan_item(
        RecoveryDisposition.RETAINED,
        RecoveryReasonCode.MINIMUM_AGE_NOT_MET,
    )
    report = StartupRecoveryReport(
        run_id=RUN_ID,
        started_at=STARTED_AT,
        retention_items=(_retention_result(MEDIA_A),),
        orphan_report=_orphan_report(items=(minimum_age_item,)),
    )

    assert report.requires_attention is False
    assert report.passed is True


def test_orphan_anomaly_requires_attention() -> None:
    anomaly = _orphan_item(
        RecoveryDisposition.ANOMALY,
        RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE,
    )
    report = StartupRecoveryReport(
        run_id=RUN_ID,
        started_at=STARTED_AT,
        orphan_report=_orphan_report(items=(anomaly,)),
    )

    assert report.requires_attention is True
    assert report.passed is False


def test_startup_recovery_enforces_run_scope_time_uniqueness_and_stable_order() -> None:
    item_a = _retention_result(MEDIA_A)
    item_b = _retention_result(MEDIA_B)

    with pytest.raises(ValidationError, match="stable media order"):
        StartupRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT,
            retention_items=(item_b, item_a),
            orphan_report=_orphan_report(),
        )
    with pytest.raises(ValidationError, match="unique by media"):
        StartupRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT,
            retention_items=(item_a, item_a),
            orphan_report=_orphan_report(),
        )
    with pytest.raises(ValidationError, match="belong to its run"):
        StartupRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT,
            retention_items=(_retention_result(MEDIA_A, run_id="other-run"),),
            orphan_report=_orphan_report(),
        )
    with pytest.raises(ValidationError, match="belong to its run"):
        StartupRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT,
            orphan_report=_orphan_report(run_id="other-run"),
        )
    with pytest.raises(ValidationError, match="earlier than startup"):
        StartupRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT,
            orphan_report=_orphan_report(cutoff=STARTED_AT),
        )
    with pytest.raises(ValidationError, match="timezone-aware"):
        StartupRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT.replace(tzinfo=None),
            orphan_report=_orphan_report(),
        )
