from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.enums import BacklogStatus, CaseStatus, VlmRole
from labcourt.contracts.hearing_state import HearingHumanReviewReason
from labcourt.contracts.m3_operations import (
    FakeVLMFixtureDisposition,
    FakeVLMResponseFixtureInput,
)
from labcourt.contracts.m4_operations import (
    M4BacklogRetryCommandReport,
    M4BacklogRetryDisposition,
    M4BacklogRetryReport,
    M4FakeVLMFixtureBundle,
    M4ProcessCaseOutcome,
    M4ProcessCommandReport,
    M4ProcessCounts,
    M4ProcessDisposition,
    M4ProcessReport,
    M4ProjectionDisposition,
    M4ProjectionOutcome,
)

RUN_ID = "run-m4-operation-contract"
CASE_ID = "case-m4-operation-contract"
MANIFEST_ID = "a" * 64
CACHE_KEY = "b" * 64


def _bundle() -> M4FakeVLMFixtureBundle:
    return M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=(
            FakeVLMResponseFixtureInput(
                disposition=FakeVLMFixtureDisposition.RESPONSE,
                cache_key=CACHE_KEY,
                raw_response_utf8='{"decision":"ESTABLISHED"}',
                input_tokens=2,
                output_tokens=3,
                latency_ms=4,
            ),
        ),
    )


def _ready_outcome() -> M4ProcessCaseOutcome:
    return M4ProcessCaseOutcome(
        event_id="event-m4-operation-contract",
        case_id=CASE_ID,
        initial_status=CaseStatus.ESCALATED,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        revision=8,
        disposition=M4ProcessDisposition.PROCESSED,
        pipeline_invoked=True,
        hearing_session_id="hearing-m4-operation-contract",
        checkpoint_id="checkpoint-m4-operation-contract",
        verdict_id="verdict-m4-operation-contract",
        procedural_review_id="review-m4-operation-contract",
        cache_hit_count=0,
        recovered_response_count=1,
    )


def _counts(outcome: M4ProcessCaseOutcome) -> M4ProcessCounts:
    return M4ProcessCounts(
        selected_cases=1,
        pipeline_invocations=1,
        processed_cases=int(outcome.disposition == M4ProcessDisposition.PROCESSED),
        deferred_to_backlog_cases=int(
            outcome.disposition == M4ProcessDisposition.DEFERRED_TO_BACKLOG
        ),
        transferred_to_human_cases=int(
            outcome.disposition == M4ProcessDisposition.TRANSFERRED_TO_HUMAN
        ),
        observed_existing_cases=0,
        skipped_not_hearing_ready_cases=0,
        cache_hits=outcome.cache_hit_count,
        recovered_responses=outcome.recovered_response_count,
    )


def test_m4_fixture_bundle_has_stable_identity_and_rejects_forged_claims() -> None:
    bundle = _bundle()

    assert bundle.fixture_count == 1
    assert bundle.acquisition_fixture_count == 0
    assert bundle.raw_response_total_bytes == len(
        bundle.fixtures[0].raw_response_utf8.encode("utf-8")  # type: ignore[union-attr]
    )
    assert M4FakeVLMFixtureBundle.model_validate_json(bundle.model_dump_json()) == bundle

    forged = bundle.model_dump(mode="json")
    forged["fixture_bundle_id"] = "c" * 64
    with pytest.raises(ValidationError):
        M4FakeVLMFixtureBundle.model_validate(forged)

    forged = bundle.model_dump(mode="json")
    forged["acquisition_fixture_count"] = 1
    with pytest.raises(ValidationError):
        M4FakeVLMFixtureBundle.model_validate(forged)


@pytest.mark.parametrize(
    ("status", "disposition", "extra"),
    (
        (
            CaseStatus.BACKLOGGED,
            M4ProcessDisposition.DEFERRED_TO_BACKLOG,
            {
                "hearing_session_id": "hearing-backlog",
                "checkpoint_id": "checkpoint-backlog",
                "backlog_item_id": "backlog-m4-operation",
            },
        ),
        (
            CaseStatus.HUMAN_REVIEW,
            M4ProcessDisposition.TRANSFERRED_TO_HUMAN,
            {
                "hearing_session_id": "hearing-human",
                "checkpoint_id": "checkpoint-human",
                "human_review_reason": HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
            },
        ),
    ),
)
def test_m4_active_nonready_outcomes_bind_exact_terminal_authority(
    status: CaseStatus,
    disposition: M4ProcessDisposition,
    extra: dict[str, object],
) -> None:
    outcome = M4ProcessCaseOutcome(
        event_id="event-m4-operation-contract",
        case_id=CASE_ID,
        initial_status=CaseStatus.ESCALATED,
        status=status,
        revision=4,
        disposition=disposition,
        pipeline_invoked=True,
        cache_hit_count=0,
        recovered_response_count=0,
        **extra,
    )

    assert outcome.status == status

    forged = outcome.model_dump(mode="json")
    if status == CaseStatus.BACKLOGGED:
        forged["backlog_item_id"] = None
    else:
        forged["human_review_reason"] = None
    with pytest.raises(ValidationError):
        M4ProcessCaseOutcome.model_validate(forged)


def test_m4_process_command_round_trips_and_rejects_mismatched_counts() -> None:
    bundle = _bundle()
    outcome = _ready_outcome()
    authority = M4ProcessReport(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        perception_mode="SIMULATED PERCEPTION",
        model_mode="FAKE VLM",
        precedent_mode="CONTROLLED FAKE",
        fixture_bundle_id=bundle.fixture_bundle_id,
        fixture_entry_count=bundle.fixture_count,
        requested_case_id=CASE_ID,
        selection_limit=1,
        available_case_count=1,
        selection_truncated=False,
        outcomes=(outcome,),
        counts=_counts(outcome),
    )
    report = M4ProcessCommandReport(
        run_id=RUN_ID,
        authority_report=authority,
        projection=M4ProjectionOutcome(
            disposition=M4ProjectionDisposition.REBUILT,
            generation_id="d" * 64,
        ),
    )

    assert M4ProcessCommandReport.model_validate_json(report.model_dump_json()) == report

    forged = authority.model_dump(mode="json")
    forged["counts"]["cache_hits"] = 99
    with pytest.raises(ValidationError):
        M4ProcessReport.model_validate(forged)


def test_observed_pre_m4_human_case_need_not_invent_a_hearing_reason() -> None:
    observed = M4ProcessCaseOutcome(
        event_id="event-observed-human",
        case_id="case-observed-human",
        initial_status=CaseStatus.HUMAN_REVIEW,
        status=CaseStatus.HUMAN_REVIEW,
        revision=2,
        disposition=M4ProcessDisposition.OBSERVED_EXISTING,
        pipeline_invoked=False,
        cache_hit_count=0,
        recovered_response_count=0,
    )

    assert observed.human_review_reason is None


def test_pending_projection_keeps_authority_complete_but_requires_reason() -> None:
    pending = M4ProjectionOutcome(
        disposition=M4ProjectionDisposition.PENDING_REBUILD,
        reason_code="PROJECTION_REBUILD_FAILED",
    )

    assert pending.generation_id is None
    with pytest.raises(ValidationError):
        M4ProjectionOutcome(
            disposition=M4ProjectionDisposition.PENDING_REBUILD,
        )


@pytest.mark.parametrize(
    ("disposition", "backlog_status", "case_status", "same_checkpoint", "human"),
    (
        (
            M4BacklogRetryDisposition.COMPLETED,
            BacklogStatus.COMPLETED,
            CaseStatus.DELIBERATING,
            False,
            None,
        ),
        (
            M4BacklogRetryDisposition.REQUEUED,
            BacklogStatus.PENDING,
            CaseStatus.BACKLOGGED,
            True,
            None,
        ),
        (
            M4BacklogRetryDisposition.EXHAUSTED,
            BacklogStatus.EXHAUSTED,
            CaseStatus.HUMAN_REVIEW,
            True,
            "f" * 64,
        ),
    ),
)
def test_m4_backlog_retry_report_binds_exact_lease_and_completion(
    disposition: M4BacklogRetryDisposition,
    backlog_status: BacklogStatus,
    case_status: CaseStatus,
    same_checkpoint: bool,
    human: str | None,
) -> None:
    source = "1" * 64
    report = M4BacklogRetryReport(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        fixture_bundle_id=_bundle().fixture_bundle_id,
        fixture_entry_count=1,
        disposition=disposition,
        reclaimed_completion_receipt_ids=("0" * 64,),
        lease=BacklogLeaseIdentity(
            run_id=RUN_ID,
            item_id="2" * 64,
            lease_id="3" * 64,
            attempt_count=1,
            retry_generation=0,
        ),
        case_id=CASE_ID,
        role=VlmRole.PROSECUTOR,
        completion_receipt_id="4" * 64,
        outcome_id="5" * 64,
        source_checkpoint_id=source,
        resulting_checkpoint_id=source if same_checkpoint else "6" * 64,
        backlog_status=backlog_status,
        resulting_case_status=case_status,
        resulting_retry_generation=0,
        human_review_receipt_id=human,
    )
    command = M4BacklogRetryCommandReport(
        run_id=RUN_ID,
        authority_report=report,
        projection=M4ProjectionOutcome(
            disposition=M4ProjectionDisposition.REBUILT,
            generation_id="7" * 64,
        ),
    )

    assert M4BacklogRetryCommandReport.model_validate_json(command.model_dump_json()) == command

    forged = report.model_dump(mode="json")
    forged["backlog_status"] = BacklogStatus.COMPLETED.value
    if disposition != M4BacklogRetryDisposition.COMPLETED:
        with pytest.raises(ValidationError):
            M4BacklogRetryReport.model_validate(forged)


def test_m4_backlog_no_work_is_secret_free_and_cannot_claim_a_lease() -> None:
    report = M4BacklogRetryReport(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        fixture_bundle_id=_bundle().fixture_bundle_id,
        fixture_entry_count=1,
        disposition=M4BacklogRetryDisposition.NO_WORK,
    )

    serialized = report.model_dump_json()
    assert "lease_owner" not in serialized
    assert "raw_response" not in serialized
    assert "local_path" not in serialized

    forged = report.model_dump(mode="json")
    forged["case_id"] = CASE_ID
    with pytest.raises(ValidationError):
        M4BacklogRetryReport.model_validate(forged)
