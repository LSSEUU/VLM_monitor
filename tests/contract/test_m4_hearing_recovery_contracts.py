from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from labcourt.application.hearing_request import HearingBudgetUsage
from labcourt.application.hearing_role_call import HearingRoleCallContext
from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.enums import BacklogReasonCode, BacklogStatus, VlmRole
from labcourt.contracts.hearing import (
    HearingBacklogRetryFailure,
    HearingModelResponseRecoveryDisposition,
    HearingModelResponseRecoveryItem,
    HearingModelResponseRecoveryReason,
    HearingModelResponseRecoveryReport,
    HearingStrictParseFailureAttempt,
    HearingStrictParseFailureProof,
)
from tests.unit.test_m4_hearing_backlog_retry import _strict_error
from tests.unit.test_m4_hearing_request import _prepare, _scenario


def test_hearing_recovery_report_round_trips_and_rejects_computed_tamper() -> None:
    scenario = _scenario()
    request = _prepare(scenario, VlmRole.PROSECUTOR).request
    item = HearingModelResponseRecoveryItem(
        run_id=request.run_id,
        request_id=request.request_id,
        disposition=HearingModelResponseRecoveryDisposition.DEFERRED,
        reason_code=HearingModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED,
    )
    report = HearingModelResponseRecoveryReport(
        run_id=request.run_id,
        started_at=datetime(2026, 7, 28, 8, tzinfo=UTC),
        claim_limit=10,
        claims_scanned=1,
        scan_complete=True,
        items=(item,),
    )

    assert (
        HearingModelResponseRecoveryReport.model_validate(report.model_dump(mode="json")) == report
    )
    with pytest.raises(ValidationError, match="report_id"):
        HearingModelResponseRecoveryReport.model_validate(
            {**report.model_dump(mode="json"), "report_id": "f" * 64}
        )


def test_incomplete_hearing_recovery_scan_cannot_claim_acknowledgement() -> None:
    scenario = _scenario()
    request = _prepare(scenario, VlmRole.PROSECUTOR).request
    with pytest.raises(ValidationError, match="incomplete"):
        HearingModelResponseRecoveryReport(
            run_id=request.run_id,
            started_at=datetime(2026, 7, 28, 8, tzinfo=UTC),
            claim_limit=1,
            claims_scanned=1,
            scan_complete=False,
            items=(
                HearingModelResponseRecoveryItem(
                    run_id=request.run_id,
                    request_id=request.request_id,
                    disposition=HearingModelResponseRecoveryDisposition.DEFERRED,
                    reason_code=HearingModelResponseRecoveryReason.CLAIM_RACE_LOST,
                ),
            ),
        )


def test_hearing_recovery_item_uses_hearing_response_identity_domain() -> None:
    scenario = _scenario()
    request = _prepare(scenario, VlmRole.PROSECUTOR).request
    with pytest.raises(ValidationError, match="request/content bound"):
        HearingModelResponseRecoveryItem(
            run_id=request.run_id,
            request_id=request.request_id,
            response_id="f" * 64,
            response_content_sha256="e" * 64,
            disposition=HearingModelResponseRecoveryDisposition.ACKNOWLEDGED,
            reason_code=HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED,
        )


def test_generation_zero_strict_pair_authorizes_exactly_one_generation_advance() -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    lease = BacklogLeaseIdentity(
        run_id=prepared.request.run_id,
        item_id="a" * 64,
        lease_id="b" * 64,
        attempt_count=1,
        retry_generation=0,
    )
    context = HearingRoleCallContext(
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage_before_primary=HearingBudgetUsage(),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
    )
    calls = _strict_error(prepared, context).failed_calls
    proof = HearingStrictParseFailureProof(
        lease=lease,
        source_checkpoint_id="c" * 64,
        source_checkpoint_sha256="d" * 64,
        source_checkpoint_version=2,
        role=VlmRole.PROSECUTOR,
        attempts=tuple(
            HearingStrictParseFailureAttempt(
                request=call.request,
                response=call.response,
                parse_receipt=call.parse_receipt,
            )
            for call in calls
        ),
    )
    failure = HearingBacklogRetryFailure(
        lease=lease,
        source_checkpoint_id=proof.source_checkpoint_id,
        source_checkpoint_sha256=proof.source_checkpoint_sha256,
        source_checkpoint_version=proof.source_checkpoint_version,
        request=calls[0].request,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        next_status=BacklogStatus.PENDING,
        response_refs=tuple(
            sorted(
                (call.response_ref for call in calls),
                key=lambda ref: ref.sort_key,
            )
        ),
        strict_parse_failure=proof,
        manifest_id=prepared.request.manifest_id,
    )

    assert failure.next_retry_generation == 1


def test_single_strict_failure_cannot_form_generation_authority() -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    context = HearingRoleCallContext(
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage_before_primary=HearingBudgetUsage(),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
    )
    call = _strict_error(prepared, context).failed_calls[0]
    with pytest.raises(ValidationError):
        HearingStrictParseFailureProof(
            lease=BacklogLeaseIdentity(
                run_id=prepared.request.run_id,
                item_id="a" * 64,
                lease_id="b" * 64,
                attempt_count=1,
                retry_generation=0,
            ),
            source_checkpoint_id="c" * 64,
            source_checkpoint_sha256="d" * 64,
            source_checkpoint_version=2,
            role=VlmRole.PROSECUTOR,
            attempts=(
                HearingStrictParseFailureAttempt(
                    request=call.request,
                    response=call.response,
                    parse_receipt=call.parse_receipt,
                ),
            ),
        )
