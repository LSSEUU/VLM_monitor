from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertChannelIdempotencyGuarantee,
    AlertDispatchAttempt,
    AlertDispatchContinuation,
    AlertDispatchDisposition,
    AlertDispatchFailureCode,
    AlertDispatchReceipt,
    AlertPolicyDisposition,
)
from labcourt.contracts.enums import PrecedentStatus
from labcourt.contracts.m5_operations import (
    M5CloseCaseOutcome,
    M5DispatchCommandReport,
    M5FinalizeCommandReport,
    M5PrecedentActivationCommandReport,
    M5PrecedentConflictCommandReport,
    M5PrecedentImportReport,
)
from labcourt.contracts.m5_precedent_usage import MAX_M5_HEARING_PRECEDENT_EXPOSURES
from labcourt.contracts.m5_precedents import (
    M5PrecedentActivationOutcome,
    M5PrecedentActivationReceipt,
    M5PrecedentConflictBatchReceipt,
    M5PrecedentConflictNodeResult,
)


def _outcome(case_id: str = "case-01") -> M5CloseCaseOutcome:
    return M5CloseCaseOutcome(
        case_id=case_id,
        source_revision=8,
        closed_revision=9,
        disposition=AlertPolicyDisposition.ENQUEUE,
        alert_id="a" * 64,
        alert_policy_authority_id="b" * 64,
        automatic_precedent_id="c" * 64,
        automatic_precedent_authority_id="d" * 64,
    )


def test_finalize_report_requires_complete_stable_unique_outcomes() -> None:
    first = _outcome("case-01")
    second = _outcome("case-02")
    report = M5FinalizeCommandReport(
        run_id="run-01",
        manifest_id="e" * 64,
        config_sha256="f" * 64,
        selected_count=2,
        outcomes=(first, second),
    )
    assert report.selected_count == 2

    with pytest.raises(ValueError, match="stably ordered"):
        report.model_copy(update={"outcomes": (second, first)})
    with pytest.raises(ValueError, match="account"):
        report.model_copy(update={"selected_count": 1})


def test_close_outcome_binds_adjacent_revision_and_disposition() -> None:
    no_alert = _outcome().model_copy(
        update={
            "disposition": AlertPolicyDisposition.CLOSE_NO_ALERT,
            "alert_id": None,
        }
    )
    assert no_alert.alert_id is None
    with pytest.raises(ValueError, match="adjacent"):
        no_alert.model_copy(update={"closed_revision": 10})
    with pytest.raises(ValueError, match="cannot report"):
        no_alert.model_copy(update={"alert_id": "a" * 64})


def test_close_outcome_reports_bounded_applied_citation_usage() -> None:
    without_batch = _outcome()
    assert without_batch.application_batch_id is None
    assert without_batch.applied_citation_count == 0

    with_batch = without_batch.model_copy(
        update={
            "application_batch_id": "e" * 64,
            "applied_citation_count": MAX_M5_HEARING_PRECEDENT_EXPOSURES,
        }
    )
    assert with_batch.application_batch_id == "e" * 64
    assert with_batch.applied_citation_count == MAX_M5_HEARING_PRECEDENT_EXPOSURES

    empty_batch = with_batch.model_copy(update={"applied_citation_count": 0})
    assert empty_batch.application_batch_id == with_batch.application_batch_id

    with pytest.raises(ValueError, match="without an application batch"):
        without_batch.model_copy(update={"applied_citation_count": 1})
    with pytest.raises(ValueError, match="less than or equal"):
        without_batch.model_copy(
            update={
                "application_batch_id": "e" * 64,
                "applied_citation_count": MAX_M5_HEARING_PRECEDENT_EXPOSURES + 1,
            }
        )
    with pytest.raises(ValueError, match="valid integer"):
        without_batch.model_copy(
            update={
                "application_batch_id": "e" * 64,
                "applied_citation_count": True,
            }
        )


def test_dispatch_report_accounts_for_stably_ordered_receipts() -> None:
    started_at = datetime(2026, 8, 2, 12, tzinfo=UTC)
    capability = AlertChannelCapabilityAuthority(
        run_id="run-01",
        manifest_id="a" * 64,
        config_sha256="b" * 64,
        channel="fake-alert-channel",
        capability_revision="fake-alert-channel-v1",
        idempotency_guarantee=AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID,
        provider_idempotency_key="alert_id",
    )
    attempt = AlertDispatchAttempt(
        outbox_id="b" * 64,
        alert_id="c" * 64,
        case_id="case-01",
        attempt_number=1,
        fence=1,
        lease_owner_sha256="d" * 64,
        started_at=started_at,
        lease_expires_at=started_at + timedelta(minutes=1),
        channel_capability=capability,
        idempotency_key="c" * 64,
    )
    receipt = AlertDispatchReceipt(
        attempt_id=attempt.attempt_id,
        outbox_id=attempt.outbox_id,
        alert_id=attempt.alert_id,
        case_id=attempt.case_id,
        attempt_number=attempt.attempt_number,
        fence=attempt.fence,
        lease_owner_sha256=attempt.lease_owner_sha256,
        started_at=attempt.started_at,
        lease_expires_at=attempt.lease_expires_at,
        channel_capability=attempt.channel_capability,
        idempotency_key=attempt.idempotency_key,
        disposition=AlertDispatchDisposition.RETRYABLE_FAILURE,
        continuation=AlertDispatchContinuation.RETRY_ALLOWED,
        failure_code=AlertDispatchFailureCode.CHANNEL_DEFINITELY_NOT_SENT,
    )
    report = M5DispatchCommandReport(
        run_id="run-01",
        selected_count=1,
        succeeded_count=0,
        retryable_failure_count=1,
        unknown_delivery_count=0,
        attention_required_count=0,
        receipts=(receipt,),
    )
    assert report.retryable_failure_count == 1
    with pytest.raises(ValueError, match="counts"):
        report.model_copy(update={"succeeded_count": 1})


def test_precedent_import_report_requires_stable_parallel_identities() -> None:
    report = M5PrecedentImportReport(
        run_id="run-01",
        accepted_count=2,
        precedent_ids=("precedent-01", "precedent-02"),
        authority_ids=("a" * 64, "b" * 64),
    )
    assert report.accepted_count == 2
    with pytest.raises(ValueError, match="stably ordered"):
        report.model_copy(update={"precedent_ids": ("precedent-02", "precedent-01")})
    with pytest.raises(ValueError, match="account"):
        report.model_copy(update={"accepted_count": 1})


def test_precedent_activation_report_binds_scope_time_and_order() -> None:
    evaluated_at = datetime(2026, 8, 2, tzinfo=UTC)
    receipt = M5PrecedentActivationReceipt(
        run_id="run-01",
        precedent_id="precedent-01",
        prior_authority_id="a" * 64,
        prior_revision=1,
        appeal_snapshot_id="b" * 64,
        evaluated_at=evaluated_at,
        outcome=M5PrecedentActivationOutcome.ACTIVATED,
        resulting_authority_id="c" * 64,
        resulting_revision=2,
        status_before=PrecedentStatus.PROVISIONAL,
        status_after=PrecedentStatus.ACTIVE,
    )
    report = M5PrecedentActivationCommandReport(
        run_id="run-01",
        evaluated_at=evaluated_at,
        selected_count=1,
        receipts=(receipt,),
    )
    assert report.selected_count == 1
    with pytest.raises(ValueError, match="scope"):
        report.model_copy(update={"run_id": "run-02"})
    with pytest.raises(ValueError, match="UTC"):
        report.model_copy(update={"evaluated_at": evaluated_at.replace(tzinfo=None)})


def test_precedent_conflict_report_requires_stable_current_inventory() -> None:
    batch_receipt = M5PrecedentConflictBatchReceipt(
        run_id="run-01",
        config_sha256="a" * 64,
        policy_id="b" * 64,
        batch_authority_id="c" * 64,
        causal_cut_id="d" * 64,
        results=(
            M5PrecedentConflictNodeResult(
                precedent_id="precedent-01",
                prior_authority_id="d" * 64,
                prior_revision=1,
                resulting_authority_id="d" * 64,
                resulting_revision=1,
                status_after=PrecedentStatus.ACTIVE,
            ),
            M5PrecedentConflictNodeResult(
                precedent_id="precedent-02",
                prior_authority_id="e" * 64,
                prior_revision=1,
                resulting_authority_id="e" * 64,
                resulting_revision=1,
                status_after=PrecedentStatus.ACTIVE,
            ),
        ),
    )
    report = M5PrecedentConflictCommandReport(
        run_id="run-01",
        candidate_count=2,
        evaluated_pair_count=1,
        conflict_edge_count=0,
        causal_cut_id=batch_receipt.causal_cut_id,
        batch_authority_id=batch_receipt.batch_authority_id,
        batch_receipt_id=batch_receipt.receipt_id,
        applied_receipts=(batch_receipt,),
        current_conflict_precedent_ids=("precedent-01", "precedent-02"),
    )
    assert report.evaluated_pair_count == 1
    with pytest.raises(ValueError, match="stably ordered"):
        report.model_copy(
            update={"current_conflict_precedent_ids": ("precedent-02", "precedent-01")}
        )
