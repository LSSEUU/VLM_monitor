from __future__ import annotations

import pytest

from labcourt.application.hearing_request import HearingBudgetUsage
from labcourt.application.hearing_role_recovery import (
    HearingRoleRecoveryError,
    HearingRoleRecoveryFailureCode,
    plan_pending_hearing_role_recovery,
)
from labcourt.contracts.enums import ArtifactKind, VlmRole
from labcourt.contracts.hearing import HearingUsageReceipt
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import (
    begin_hearing,
    complete_precedent_retrieval,
    complete_prosecutor,
)
from labcourt.ports.hearing_repository import (
    HearingBudgetUsage as PersistedHearingBudgetUsage,
)
from tests.unit.test_m4_hearing_domain import (
    _payloads as domain_payloads,
)
from tests.unit.test_m4_hearing_domain import (
    _ref as domain_ref,
)
from tests.unit.test_m4_hearing_domain import (
    _repair_trace as domain_repair_trace,
)
from tests.unit.test_m4_hearing_domain import (
    _retrieval as domain_retrieval,
)
from tests.unit.test_m4_hearing_domain import (
    _role_output as domain_role_output,
)
from tests.unit.test_m4_hearing_domain import (
    _session as domain_session,
)
from tests.unit.test_m4_hearing_request import _prepare, _scenario


def _usage(request, *, output_tokens: int = 7) -> HearingUsageReceipt:
    return HearingUsageReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        request_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=request.request_id,
        ),
        response_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id="a" * 64,
        ),
        input_images=len(request.media),
        input_pixels=sum(item.width * item.height for item in request.media),
        input_tokens=5,
        output_tokens=output_tokens,
        latency_ms=3,
        retry_count=0,
        estimated_cost=0.01,
        manifest_id=request.manifest_id,
    )


def _aggregate(
    checkpoint,
    requests,
    usage,
) -> PersistedHearingBudgetUsage:
    return PersistedHearingBudgetUsage(
        hearing_session_id=checkpoint.hearing_session_id,
        request_count=len(requests),
        reserved_images=sum(len(item.media) for item in requests),
        reserved_pixels=sum(
            media.width * media.height for request in requests for media in request.media
        ),
        output_tokens=sum(item.output_tokens for item in usage),
        manifest_id=checkpoint.manifest_id,
    )


def test_fresh_pending_role_keeps_complete_aggregate_authority() -> None:
    scenario = _scenario()
    checkpoint = complete_precedent_retrieval(
        scenario.session,
        begin_hearing(scenario.session),
        scenario.retrieval,
    )
    aggregate = _aggregate(checkpoint, (), ())

    plan = plan_pending_hearing_role_recovery(
        checkpoint,
        aggregate,
        requests=(),
        usage_receipts=(),
    )

    assert plan.role == VlmRole.PROSECUTOR
    assert plan.budget_usage_before_primary == HearingBudgetUsage()
    assert plan.hearing_grant_before_primary is None
    assert plan.existing_primary is None
    assert plan.current_requests == ()


def test_completed_call_before_checkpoint_rebuilds_identical_primary() -> None:
    scenario = _scenario()
    checkpoint = complete_precedent_retrieval(
        scenario.session,
        begin_hearing(scenario.session),
        scenario.retrieval,
    )
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    usage = (_usage(prepared.request),)
    requests = (prepared.request,)

    plan = plan_pending_hearing_role_recovery(
        checkpoint,
        _aggregate(checkpoint, requests, usage),
        requests=requests,
        usage_receipts=usage,
    )
    rebuilt = _prepare(
        scenario,
        VlmRole.PROSECUTOR,
        grant=plan.hearing_grant_before_primary,
        budget_usage=plan.budget_usage_before_primary,
    )

    assert plan.existing_primary == prepared.request
    assert plan.budget_usage_before_primary == HearingBudgetUsage()
    assert plan.hearing_grant_before_primary is None
    assert rebuilt == prepared


def test_current_repair_is_subtracted_but_prior_role_grant_is_preserved() -> None:
    session = domain_session()
    opened = begin_hearing(session)
    retrieval = domain_retrieval(session, opened)
    prosecutor_pending = complete_precedent_retrieval(session, opened, retrieval)
    evidence_ref = domain_ref(ArtifactKind.CROP, "recovery-visible")
    prosecutor_payload, defender_payload, _ = domain_payloads(evidence_ref=evidence_ref)
    prosecutor_output, prosecutor_trace = domain_role_output(
        session,
        prosecutor_pending,
        retrieval,
        prosecutor_payload,
    )
    defender_pending = complete_prosecutor(
        session,
        prosecutor_pending,
        prosecutor_output,
        prosecutor_trace,
    )
    _, defender_primary_trace = domain_role_output(
        session,
        defender_pending,
        retrieval,
        defender_payload,
        prosecutor_output_id=prosecutor_output.output_id,
    )
    defender_trace = domain_repair_trace(
        defender_primary_trace.calls[0],
        defender_payload,
    )
    calls = (*prosecutor_trace.calls, *defender_trace.calls)
    requests = tuple(call.request for call in calls)
    usage = tuple(call.usage for call in calls)

    plan = plan_pending_hearing_role_recovery(
        defender_pending,
        _aggregate(defender_pending, requests, usage),
        requests=requests,
        usage_receipts=usage,
    )

    assert plan.role == VlmRole.DEFENDER
    assert plan.current_requests == tuple(call.request for call in defender_trace.calls)
    assert plan.budget_usage_before_primary == HearingBudgetUsage(
        reserved_images=1,
        accounted_output_tokens=10,
    )
    assert plan.hearing_grant_before_primary is not None
    assert plan.hearing_grant_before_primary.allowed_evidence_refs == (
        prosecutor_trace.calls[0].request.allowed_evidence_refs
    )


def test_budget_or_history_drift_fails_closed() -> None:
    scenario = _scenario()
    checkpoint = complete_precedent_retrieval(
        scenario.session,
        begin_hearing(scenario.session),
        scenario.retrieval,
    )
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    usage = (_usage(prepared.request),)
    aggregate = _aggregate(checkpoint, (prepared.request,), usage)
    drifted = PersistedHearingBudgetUsage(
        hearing_session_id=aggregate.hearing_session_id,
        request_count=aggregate.request_count,
        reserved_images=aggregate.reserved_images,
        reserved_pixels=aggregate.reserved_pixels,
        output_tokens=aggregate.output_tokens + 1,
        manifest_id=aggregate.manifest_id,
    )

    with pytest.raises(HearingRoleRecoveryError) as captured:
        plan_pending_hearing_role_recovery(
            checkpoint,
            drifted,
            requests=(prepared.request,),
            usage_receipts=usage,
        )

    assert (
        captured.value.reason_code == HearingRoleRecoveryFailureCode.BUDGET_RECONSTRUCTION_MISMATCH
    )
