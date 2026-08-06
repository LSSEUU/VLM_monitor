from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import (
    RecoveryArea,
    RecoveryDisposition,
    RecoveryReasonCode,
)
from labcourt.contracts.recovery import (
    RecoveryItemResult,
    RecoveryReport,
    recovery_source_token,
)

RUN_ID = "run-recovery-01"
SHA_A = "a" * 64


def _orphan_result() -> RecoveryItemResult:
    source_token = recovery_source_token(f"{RUN_ID}/frames/{SHA_A}.png")
    return RecoveryItemResult(
        run_id=RUN_ID,
        area=RecoveryArea.FINAL_MEDIA,
        source_token=source_token,
        disposition=RecoveryDisposition.QUARANTINED,
        reason_code=RecoveryReasonCode.ORPHAN_QUARANTINED,
        content_sha256=SHA_A,
        quarantine_relative_path=f".quarantine/{RUN_ID}/frames/{SHA_A}.png",
    )


def test_recovery_result_enforces_controlled_quarantine_locations() -> None:
    orphan = _orphan_result()
    staging_path = f".staging/{RUN_ID}/crop-{'b' * 64}/media.png"
    staging_token = recovery_source_token(staging_path)
    staging = RecoveryItemResult(
        run_id=RUN_ID,
        area=RecoveryArea.STAGING,
        source_token=staging_token,
        disposition=RecoveryDisposition.QUARANTINED,
        reason_code=RecoveryReasonCode.STAGING_QUARANTINED,
        content_sha256=SHA_A,
        quarantine_relative_path=(f".quarantine/{RUN_ID}/staging/{staging_token}-{SHA_A}.bin"),
    )

    assert orphan.quarantine_relative_path.endswith(f"/{SHA_A}.png")
    assert staging.quarantine_relative_path.endswith(f"-{SHA_A}.bin")

    with pytest.raises(ValidationError, match="controlled location"):
        RecoveryItemResult.model_validate(
            {
                **orphan.model_dump(mode="json"),
                "quarantine_relative_path": f".trash/{RUN_ID}/{SHA_A}.png",
            }
        )


def test_recovery_result_rejects_invalid_disposition_reason_combinations() -> None:
    orphan = _orphan_result()
    with pytest.raises(ValidationError, match="retained reason"):
        RecoveryItemResult.model_validate(
            {
                **orphan.model_dump(mode="json"),
                "disposition": RecoveryDisposition.RETAINED,
                "quarantine_relative_path": None,
            }
        )

    with pytest.raises(ValidationError, match="only final media"):
        RecoveryItemResult(
            run_id=RUN_ID,
            area=RecoveryArea.STAGING,
            source_token=SHA_A,
            disposition=RecoveryDisposition.RETAINED,
            reason_code=RecoveryReasonCode.REFERENCED_MEDIA,
            content_sha256=SHA_A,
        )

    cleaned = RecoveryItemResult(
        run_id=RUN_ID,
        area=RecoveryArea.STAGING,
        source_token=SHA_A,
        disposition=RecoveryDisposition.CLEANED,
        reason_code=RecoveryReasonCode.EMPTY_STAGING_CLEANED,
    )
    assert cleaned.content_sha256 is None
    with pytest.raises(ValidationError, match="empty staging"):
        RecoveryItemResult.model_validate(
            {
                **cleaned.model_dump(mode="json"),
                "area": RecoveryArea.FINAL_MEDIA,
            }
        )
    age_retained = RecoveryItemResult(
        run_id=RUN_ID,
        area=RecoveryArea.STAGING,
        source_token=SHA_A,
        disposition=RecoveryDisposition.RETAINED,
        reason_code=RecoveryReasonCode.MINIMUM_AGE_NOT_MET,
    )
    assert age_retained.content_sha256 is None


def test_recovery_report_requires_run_scope_timezone_and_stable_order() -> None:
    first = _orphan_result()
    second = RecoveryItemResult(
        run_id=RUN_ID,
        area=RecoveryArea.STAGING,
        source_token="b" * 64,
        disposition=RecoveryDisposition.ANOMALY,
        reason_code=RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE,
    )
    stable = tuple(sorted((first, second), key=lambda item: item.sort_key))
    report = RecoveryReport(
        run_id=RUN_ID,
        not_modified_after=datetime(2026, 7, 27, tzinfo=UTC),
        items=stable,
    )
    assert report.items == stable

    with pytest.raises(ValidationError, match="stable order"):
        RecoveryReport(
            run_id=RUN_ID,
            not_modified_after=datetime(2026, 7, 27, tzinfo=UTC),
            items=tuple(reversed(stable)),
        )
    with pytest.raises(ValidationError, match="timezone-aware"):
        RecoveryReport(
            run_id=RUN_ID,
            not_modified_after=datetime(2026, 7, 27),
        )

    duplicate_source = RecoveryItemResult(
        run_id=RUN_ID,
        area=first.area,
        source_token=first.source_token,
        disposition=RecoveryDisposition.ANOMALY,
        reason_code=RecoveryReasonCode.ENTRY_CHANGED_DURING_RECOVERY,
        content_sha256=first.content_sha256,
    )
    duplicate_items = tuple(sorted((first, duplicate_source), key=lambda item: item.sort_key))
    with pytest.raises(ValidationError, match="unique"):
        RecoveryReport(
            run_id=RUN_ID,
            not_modified_after=datetime(2026, 7, 27, tzinfo=UTC),
            items=duplicate_items,
        )


@pytest.mark.parametrize(
    "unsafe_path",
    ("../secret", "C:/secret", "//server/share", "staging\\entry"),
)
def test_recovery_source_token_accepts_only_safe_relative_paths(unsafe_path: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        recovery_source_token(unsafe_path)
