from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from labcourt.application.hearing_backlog_retry import (
    HearingBacklogCallPlan,
    HearingBacklogRetryService,
)
from labcourt.application.hearing_model_parser import (
    finalize_hearing_parse,
    inspect_hearing_response,
)
from labcourt.application.hearing_request import (
    HearingBudgetUsage,
    HearingRequestGeneration,
    PreparedHearingRequest,
    prepare_hearing_repair_request,
)
from labcourt.application.hearing_role_call import (
    HearingRoleCallContext,
    HearingRoleCallError,
    HearingRoleCallFailureCode,
    HearingRoleCallResult,
)
from labcourt.application.hearing_role_output import build_hearing_role_output
from labcourt.contracts.backlog import BacklogItem, BacklogLeaseIdentity
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    ArgumentStance,
    ArtifactKind,
    AuditAction,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    ModelParseStatus,
    VlmRole,
)
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingBacklogCompletionReceipt,
    HearingBacklogRetryFailure,
    HearingCheckpoint,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    HearingUsageReceipt,
    ProsecutorModelPayload,
    derive_hearing_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Argument
from labcourt.domain.hearing_fsm import (
    HearingCallClosure,
    HearingCallTrace,
    begin_hearing,
    complete_precedent_retrieval,
    complete_prosecutor,
)
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.hearing_backlog import (
    HearingBacklogRetryAuthority,
    HearingBacklogRetryCommit,
    hearing_request_document_sha256,
)
from tests.unit.test_m4_hearing_request import Scenario, _prepare, _scenario


def _response(request: HearingModelRequest, raw: bytes) -> HearingModelResponse:
    content = hashlib.sha256(raw).hexdigest()
    response_id = derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        content,
    )
    return HearingModelResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        role=request.role,
        attempt_index=request.attempt_index,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content,
        size_bytes=len(raw),
        input_tokens=2,
        output_tokens=3,
        latency_ms=4,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _usage(request: HearingModelRequest, response: HearingModelResponse) -> HearingUsageReceipt:
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
            artifact_id=response.response_id,
        ),
        input_images=len(request.media),
        input_pixels=sum(item.width * item.height for item in request.media),
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        latency_ms=response.latency_ms,
        retry_count=0,
        estimated_cost=request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        ),
        manifest_id=request.manifest_id,
    )


def _payload(request: HearingModelRequest):
    crop_ref = next(ref for ref in request.allowed_evidence_refs if ref.kind == ArtifactKind.CROP)
    if request.role == VlmRole.PROSECUTOR:
        return ProsecutorModelPayload(
            arguments=(
                Argument(
                    stance=ArgumentStance.PROSECUTION,
                    claim="The disclosed crop supports the allegation.",
                    evidence_refs=(crop_ref,),
                    uncertainty=0.1,
                ),
            ),
            case_summary="The prosecution uses only disclosed evidence.",
        )
    return DefenderModelPayload(
        arguments=(
            Argument(
                stance=ArgumentStance.DEFENSE,
                claim="The disclosed crop retains material uncertainty.",
                evidence_refs=(crop_ref,),
                uncertainty=0.4,
            ),
        ),
        case_summary="The defense responds without inventing evidence.",
    )


def _parsed_closure(
    request: HearingModelRequest,
) -> tuple[HearingCallClosure, HearingRoleOutput]:
    payload = _payload(request)
    raw = b'{"typed":"test"}'
    response = _response(request, raw)
    parse = HearingModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        attempt_index=request.attempt_index,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_payload_sha256=payload.payload_sha256,
        manifest_id=request.manifest_id,
    )
    output = build_hearing_role_output(
        request=request,
        response=response,
        parse_receipt=parse,
        payload=payload,
    )
    return (
        HearingCallClosure(
            request=request,
            response=response,
            parse_receipt=parse,
            usage=_usage(request, response),
        ),
        output,
    )


def _success_result(prepared: PreparedHearingRequest) -> HearingRoleCallResult:
    closure, output = _parsed_closure(prepared.request)
    return HearingRoleCallResult(
        output=output,
        trace=HearingCallTrace(calls=(closure,)),
        prepared_primary=prepared,
        prepared_repair=None,
        cache_hit_count=0,
        recovered_response_count=0,
    )


def _context(
    scenario: Scenario,
    *,
    reserved_images: int = 0,
    output_tokens: int = 0,
    backlog_lease: BacklogLeaseIdentity | None = None,
) -> HearingRoleCallContext:
    return HearingRoleCallContext(
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage_before_primary=HearingBudgetUsage(
            reserved_images=reserved_images,
            accounted_output_tokens=output_tokens,
        ),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
        backlog_lease=backlog_lease,
    )


def _pending_checkpoint(scenario: Scenario) -> HearingCheckpoint:
    return complete_precedent_retrieval(
        scenario.session,
        begin_hearing(scenario.session),
        scenario.retrieval,
    )


def _leased_item(
    request: HearingModelRequest,
    *,
    reason: BacklogReasonCode = BacklogReasonCode.PROVIDER_UNAVAILABLE,
    attempt_count: int = 1,
    max_attempts: int = 3,
    retry_generation: int = 0,
) -> BacklogItem:
    return BacklogItem(
        run_id=request.run_id,
        case_id=request.case_id,
        stage=BacklogStage.HEARING,
        role=request.role,
        reason_code=reason,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=request.request_id,
        ),
        stage_input_sha256=hearing_request_document_sha256(request),
        attempt_count=attempt_count,
        max_attempts=max_attempts,
        retry_generation=retry_generation,
        status=BacklogStatus.LEASED,
        lease_id=sha256_hex(["test-hearing-lease", request.request_id, attempt_count]),
        lease_owner_sha256=sha256_hex("test-hearing-owner"),
        lease_expires_at=datetime(2026, 7, 28, 8, 2, tzinfo=UTC),
        manifest_id=request.manifest_id,
    )


def _case_snapshot(scenario: Scenario, item: BacklogItem) -> CaseSnapshot:
    return CaseSnapshot(
        case=Case(
            run_id=scenario.pack.run_id,
            status=CaseStatus.BACKLOGGED,
            event=scenario.pack.event,
            evidence_packs=(scenario.pack,),
            current_backlog_item_id=item.item_id,
            manifest_id=scenario.manifest.manifest_id,
        ),
        revision=4,
    )


def _authority(
    scenario: Scenario,
    *,
    checkpoint: HearingCheckpoint,
    stage: PreparedHearingRequest,
    primary_template: PreparedHearingRequest | None = None,
    unfinished: HearingModelRequest | None,
    item: BacklogItem | None = None,
    prior_primary: HearingCallClosure | None = None,
    reserved_images: int | None = None,
    output_tokens: int | None = None,
    reserved_images_before_primary: int | None = None,
    output_tokens_before_primary: int | None = None,
    latest_completion: HearingBacklogCompletionReceipt | None = None,
) -> HearingBacklogRetryAuthority:
    leased = item or _leased_item(stage.request)
    before_images = (
        (reserved_images if unfinished is None and reserved_images is not None else 0)
        if reserved_images_before_primary is None
        else reserved_images_before_primary
    )
    before_tokens = (
        (output_tokens if unfinished is None and output_tokens is not None else 0)
        if output_tokens_before_primary is None
        else output_tokens_before_primary
    )
    aggregate_images = (
        before_images
        + (len((primary_template or stage).request.media) if unfinished is not None else 0)
        if reserved_images is None
        else reserved_images
    )
    aggregate_tokens = (
        before_tokens
        + (
            prior_primary.usage.output_tokens
            if unfinished is not None
            and unfinished.attempt_index == 1
            and prior_primary is not None
            else 0
        )
        if output_tokens is None
        else output_tokens
    )
    return HearingBacklogRetryAuthority(
        item=leased,
        case=_case_snapshot(scenario, leased),
        audit_head=AuditHead(
            run_id=leased.run_id,
            manifest_id=leased.manifest_id,
            run_revision=4,
            sequence=8,
            entry_hash=sha256_hex("audit-before-hearing-retry"),
        ),
        session=scenario.session,
        cycle_scope=scenario.scope,
        checkpoint=checkpoint,
        stage_request=stage.request,
        primary_template_request=(primary_template or stage).request,
        unfinished_request=unfinished,
        reserved_images=aggregate_images,
        accounted_output_tokens=aggregate_tokens,
        reserved_images_before_primary=before_images,
        accounted_output_tokens_before_primary=before_tokens,
        prior_primary_failure=prior_primary,
        latest_completion=latest_completion,
    )


class _Repository:
    def __init__(self, authority: HearingBacklogRetryAuthority) -> None:
        self.authority = authority
        self.outcomes: list[object] = []
        self.stale = False
        self.load_count = 0

    def load_hearing_backlog_retry_authority(self, run_id, lease):
        self.load_count += 1
        if self.stale:
            raise ConcurrentModification("test stale authority")
        assert run_id == self.authority.item.run_id
        assert lease == self.authority.lease
        return self.authority

    def commit_hearing_backlog_retry(
        self,
        run_id,
        expected_case_revision,
        expected_audit_head,
        outcome,
        model_call_failure=None,
    ) -> HearingBacklogRetryCommit:
        del model_call_failure
        assert run_id == self.authority.item.run_id
        assert expected_case_revision == self.authority.case.revision
        assert expected_audit_head == self.authority.audit_head
        self.outcomes.append(outcome)
        failure = isinstance(outcome, HearingBacklogRetryFailure)
        status = outcome.next_status if failure else BacklogStatus.COMPLETED
        generation = outcome.next_retry_generation if failure else outcome.lease.retry_generation
        item = BacklogItem.model_validate(
            {
                **self.authority.item.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                ),
                "status": status.value,
                "retry_generation": generation,
                "lease_id": None,
                "lease_owner_sha256": None,
                "lease_expires_at": None,
            }
        )
        checkpoint = self.authority.checkpoint if failure else outcome.next_checkpoint
        case_status = (
            CaseStatus.BACKLOGGED
            if status == BacklogStatus.PENDING
            else CaseStatus.HUMAN_REVIEW
            if status == BacklogStatus.EXHAUSTED
            else CaseStatus.HUMAN_REVIEW
            if checkpoint.phase.value == "HUMAN_REVIEW"
            else CaseStatus.DELIBERATING
        )
        timeline = self.authority.case.case.timeline
        if case_status == CaseStatus.HUMAN_REVIEW:
            timeline = (
                *timeline,
                TimelineEntry(
                    sequence=len(timeline),
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="BACKLOG",
                    object_ref=item.item_id,
                    details={
                        "outcome": "FAILURE",
                        "reason_code": outcome.reason_code.value,
                        "status": BacklogStatus.EXHAUSTED.value,
                        "retry_generation": generation,
                    },
                ),
            )
        case = Case.model_validate(
            {
                **self.authority.case.case.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                ),
                "status": case_status.value,
                "current_backlog_item_id": (
                    item.item_id if status == BacklogStatus.PENDING else None
                ),
                "timeline": [entry.model_dump(mode="json") for entry in timeline],
            }
        )
        audit = AuditHead(
            run_id=run_id,
            manifest_id=item.manifest_id,
            run_revision=expected_case_revision + 1,
            sequence=expected_audit_head.sequence + 1,
            entry_hash=sha256_hex(["audit-after-hearing-retry", outcome.outcome_id]),
        )
        receipt = HearingBacklogCompletionReceipt(
            outcome=outcome,
            backlog_status=status,
            source_checkpoint_id=self.authority.checkpoint.checkpoint_id,
            source_checkpoint_sha256=self.authority.checkpoint.checkpoint_sha256,
            source_checkpoint_version=self.authority.checkpoint.version,
            resulting_checkpoint_id=checkpoint.checkpoint_id,
            resulting_checkpoint_sha256=checkpoint.checkpoint_sha256,
            resulting_checkpoint_version=checkpoint.version,
            completion_case_status=case_status,
            completion_case_revision=expected_case_revision + 1,
            completion_audit_sequence=audit.sequence,
            completion_audit_entry_hash=audit.entry_hash,
            manifest_id=item.manifest_id,
        )
        return HearingBacklogRetryCommit(
            item=item,
            receipt=receipt,
            case=CaseSnapshot(case=case, revision=expected_case_revision + 1),
            checkpoint=checkpoint,
            audit_head=audit,
            created=True,
        )


class _RoleCalls:
    def __init__(
        self,
        *,
        result: HearingRoleCallResult | None = None,
        error: HearingRoleCallError | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.execute_calls: list[HearingModelRequest] = []
        self.repair_calls: list[HearingModelRequest] = []

    def execute(self, prepared, context):
        self.execute_calls.append(prepared.request)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result

    def resume_repair(self, original, repair, primary_failure, context):
        self.repair_calls.append(repair.request)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


class _AggregateAdvancingRoleCalls(_RoleCalls):
    """Simulate exact call artifacts becoming durable before backlog commit."""

    def __init__(
        self,
        repository: _Repository,
        *,
        result: HearingRoleCallResult | None = None,
        error: HearingRoleCallError | None = None,
    ) -> None:
        super().__init__(result=result, error=error)
        self.repository = repository

    def execute(self, prepared, context):
        closures = (
            self.result.trace.calls
            if self.result is not None
            else self.error.failed_calls
            if self.error is not None
            else ()
        )
        try:
            return super().execute(prepared, context)
        finally:
            self.repository.authority = replace(
                self.repository.authority,
                accounted_output_tokens=(
                    self.repository.authority.accounted_output_tokens
                    + sum(call.usage.output_tokens for call in closures)
                ),
            )


def _strict_error(
    prepared: PreparedHearingRequest,
    context: HearingRoleCallContext,
) -> HearingRoleCallError:
    primary_raw = b"{"
    primary_response = _response(prepared.request, primary_raw)
    primary_inspection = inspect_hearing_response(
        primary_raw,
        request=prepared.request,
        response=primary_response,
    )
    repair = prepare_hearing_repair_request(
        original=prepared,
        response=primary_response,
        inspection=primary_inspection,
        raw_response=primary_raw,
        session=context.session,
        cycle_scope=context.cycle_scope,
        budget_usage=HearingBudgetUsage(
            reserved_images=len(prepared.request.media),
            accounted_output_tokens=primary_response.output_tokens,
        ),
        config=context.config,
        run_manifest=context.run_manifest,
        catalog=context.catalog,
    )
    primary_parse = finalize_hearing_parse(
        primary_inspection,
        repair_request_id=repair.request.request_id,
    ).receipt
    repair_raw = b"{}"
    repair_response = _response(repair.request, repair_raw)
    repair_parse = finalize_hearing_parse(
        inspect_hearing_response(
            repair_raw,
            request=repair.request,
            response=repair_response,
        )
    ).receipt
    calls = (
        HearingCallClosure(
            request=prepared.request,
            response=primary_response,
            parse_receipt=primary_parse,
            usage=_usage(prepared.request, primary_response),
        ),
        HearingCallClosure(
            request=repair.request,
            response=repair_response,
            parse_receipt=repair_parse,
            usage=_usage(repair.request, repair_response),
        ),
    )
    return HearingRoleCallError(
        HearingRoleCallFailureCode.STRICT_PARSE_FAILED,
        role=prepared.request.role,
        request_id=repair.request.request_id,
        request=repair.request,
        failed_calls=calls,
    )


def test_success_advances_only_the_leased_role_and_closes_receipt() -> None:
    scenario = _scenario()
    pending = _pending_checkpoint(scenario)
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    authority = _authority(
        scenario,
        checkpoint=pending,
        stage=prepared,
        unfinished=prepared.request,
    )
    repository = _Repository(authority)
    role_calls = _RoleCalls(result=_success_result(prepared))

    commit = HearingBacklogRetryService(
        repository=repository,
        role_calls=role_calls,
    ).retry_leased_item(
        authority,
        HearingBacklogCallPlan(
            prepared,
            _context(scenario, backlog_lease=authority.lease),
        ),
    )

    assert commit.item.status == BacklogStatus.COMPLETED
    assert commit.checkpoint.prosecutor_output is not None
    assert commit.checkpoint.defender_output is None
    assert commit.receipt.resulting_checkpoint_id == commit.checkpoint.checkpoint_id
    assert role_calls.execute_calls == [prepared.request]
    assert role_calls.repair_calls == []


@pytest.mark.parametrize("strict_failure", [False, True])
def test_exact_call_aggregate_may_advance_before_atomic_backlog_commit(
    strict_failure: bool,
) -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=prepared,
        unfinished=prepared.request,
    )
    repository = _Repository(authority)
    context = _context(scenario, backlog_lease=authority.lease)
    if strict_failure:
        role_calls = _AggregateAdvancingRoleCalls(
            repository,
            error=_strict_error(prepared, context),
        )
    else:
        role_calls = _AggregateAdvancingRoleCalls(
            repository,
            result=_success_result(prepared),
        )

    commit = HearingBacklogRetryService(
        repository=repository,
        role_calls=role_calls,
    ).retry_leased_item(
        authority,
        HearingBacklogCallPlan(prepared, context),
    )

    assert repository.load_count == 1
    assert repository.authority.accounted_output_tokens > authority.accounted_output_tokens
    assert commit.item.status == (
        BacklogStatus.PENDING if strict_failure else BacklogStatus.COMPLETED
    )


def test_defender_retry_preserves_completed_prosecutor_without_replaying_it() -> None:
    scenario = _scenario()
    prosecutor = _prepare(scenario, VlmRole.PROSECUTOR)
    prosecutor_result = _success_result(prosecutor)
    defender_pending = complete_prosecutor(
        scenario.session,
        _pending_checkpoint(scenario),
        prosecutor_result.output,
        prosecutor_result.trace,
    )
    defender = _prepare(
        scenario,
        VlmRole.DEFENDER,
        grant=prosecutor.hearing_grant,
        budget_usage=HearingBudgetUsage(reserved_images=1, accounted_output_tokens=3),
        prosecutor_output=prosecutor_result.output,
    )
    item = _leased_item(defender.request)
    authority = _authority(
        scenario,
        checkpoint=defender_pending,
        stage=defender,
        unfinished=defender.request,
        item=item,
        reserved_images=2,
        output_tokens=3,
        reserved_images_before_primary=1,
        output_tokens_before_primary=3,
    )
    role_calls = _RoleCalls(result=_success_result(defender))

    commit = HearingBacklogRetryService(
        repository=_Repository(authority),
        role_calls=role_calls,
    ).retry_leased_item(
        authority,
        HearingBacklogCallPlan(
            defender,
            _context(
                scenario,
                reserved_images=1,
                output_tokens=3,
                backlog_lease=authority.lease,
            ),
        ),
    )

    assert role_calls.execute_calls == [defender.request]
    assert commit.checkpoint.prosecutor_output == prosecutor_result.output
    assert commit.checkpoint.defender_output == _success_result(defender).output


def test_provider_failure_keeps_the_same_retry_generation() -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=prepared,
        unfinished=prepared.request,
    )
    error = HearingRoleCallError(
        HearingRoleCallFailureCode.PROVIDER_FAILED,
        role=prepared.request.role,
        request_id=prepared.request.request_id,
        request=prepared.request,
    )

    commit = HearingBacklogRetryService(
        repository=_Repository(authority),
        role_calls=_RoleCalls(error=error),
    ).retry_leased_item(
        authority,
        HearingBacklogCallPlan(
            prepared,
            _context(scenario, backlog_lease=authority.lease),
        ),
    )

    outcome = commit.receipt.outcome
    assert isinstance(outcome, HearingBacklogRetryFailure)
    assert outcome.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
    assert outcome.next_retry_generation == authority.item.retry_generation
    assert commit.checkpoint == authority.checkpoint


def test_claim_timeout_preserves_lease_for_provider_free_recovery() -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=prepared,
        unfinished=prepared.request,
    )
    error = HearingRoleCallError(
        HearingRoleCallFailureCode.CLAIM_TIMEOUT,
        role=prepared.request.role,
        request_id=prepared.request.request_id,
        request=prepared.request,
    )

    with pytest.raises(ContractViolation, match="CLAIM_RECOVERY_REQUIRED"):
        HearingBacklogRetryService(
            repository=_Repository(authority),
            role_calls=_RoleCalls(error=error),
        ).retry_leased_item(
            authority,
            HearingBacklogCallPlan(
                prepared,
                _context(scenario, backlog_lease=authority.lease),
            ),
        )


def test_two_strict_failures_advance_exactly_one_generation_even_from_zero() -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=prepared,
        unfinished=prepared.request,
    )

    commit = HearingBacklogRetryService(
        repository=_Repository(authority),
        role_calls=_RoleCalls(error=_strict_error(prepared, _context(scenario))),
    ).retry_leased_item(
        authority,
        HearingBacklogCallPlan(
            prepared,
            _context(scenario, backlog_lease=authority.lease),
        ),
    )

    outcome = commit.receipt.outcome
    assert isinstance(outcome, HearingBacklogRetryFailure)
    assert outcome.strict_parse_failure is not None
    assert outcome.next_retry_generation == 1
    assert commit.item.retry_generation == 1


def test_new_generation_restarts_only_the_same_role_primary() -> None:
    scenario = _scenario()
    stage = _prepare(scenario, VlmRole.PROSECUTOR)
    item = _leased_item(
        stage.request,
        reason=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        retry_generation=1,
    )
    generated = _prepare(
        scenario,
        VlmRole.PROSECUTOR,
        generation=HearingRequestGeneration(
            retry_generation=1,
            backlog_item_id=item.item_id,
        ),
    )
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=stage,
        primary_template=stage,
        unfinished=None,
        item=item,
    )
    role_calls = _RoleCalls(result=_success_result(generated))

    HearingBacklogRetryService(
        repository=_Repository(authority),
        role_calls=role_calls,
    ).retry_leased_item(
        authority,
        HearingBacklogCallPlan(
            generated,
            _context(scenario, backlog_lease=authority.lease),
        ),
    )

    assert role_calls.execute_calls == [generated.request]
    assert generated.request.role == stage.request.role
    assert generated.request.attempt_index == 0
    assert generated.request.backlog_retry_context is not None


def test_lease_expiry_preserves_a_generation_restart_without_a_fake_call() -> None:
    scenario = _scenario()
    stage = _prepare(scenario, VlmRole.PROSECUTOR)
    checkpoint = _pending_checkpoint(scenario)
    expired_item = _leased_item(
        stage.request,
        reason=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        retry_generation=1,
    )
    lease = BacklogLeaseIdentity(
        run_id=expired_item.run_id,
        item_id=expired_item.item_id,
        lease_id=expired_item.lease_id,
        attempt_count=expired_item.attempt_count,
        retry_generation=expired_item.retry_generation,
    )
    outcome = HearingBacklogRetryFailure(
        lease=lease,
        source_checkpoint_id=checkpoint.checkpoint_id,
        source_checkpoint_sha256=checkpoint.checkpoint_sha256,
        source_checkpoint_version=checkpoint.version,
        request=stage.request,
        request_binding="BACKLOG_STAGE_INPUT",
        role=stage.request.role,
        reason_code=BacklogReasonCode.WORKER_LEASE_EXPIRED,
        next_status=BacklogStatus.PENDING,
        manifest_id=stage.request.manifest_id,
    )
    receipt = HearingBacklogCompletionReceipt(
        outcome=outcome,
        backlog_status=BacklogStatus.PENDING,
        source_checkpoint_id=checkpoint.checkpoint_id,
        source_checkpoint_sha256=checkpoint.checkpoint_sha256,
        source_checkpoint_version=checkpoint.version,
        resulting_checkpoint_id=checkpoint.checkpoint_id,
        resulting_checkpoint_sha256=checkpoint.checkpoint_sha256,
        resulting_checkpoint_version=checkpoint.version,
        completion_case_status=CaseStatus.BACKLOGGED,
        completion_case_revision=4,
        completion_audit_sequence=8,
        completion_audit_entry_hash=sha256_hex("expiry-audit"),
        manifest_id=stage.request.manifest_id,
    )
    next_item = _leased_item(
        stage.request,
        reason=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        attempt_count=2,
        retry_generation=1,
    )

    authority = _authority(
        scenario,
        checkpoint=checkpoint,
        stage=stage,
        unfinished=None,
        item=next_item,
        latest_completion=receipt,
    )

    assert authority.restarts_primary is True
    assert authority.latest_completion == receipt


def test_repair_provider_failure_resumes_only_the_exact_repair() -> None:
    scenario = _scenario()
    primary = _prepare(scenario, VlmRole.PROSECUTOR)
    strict = _strict_error(primary, _context(scenario))
    primary_failure, failed_repair = strict.failed_calls
    repair_prepared = prepare_hearing_repair_request(
        original=primary,
        response=primary_failure.response,
        inspection=inspect_hearing_response(
            b"{",
            request=primary.request,
            response=primary_failure.response,
        ),
        raw_response=b"{",
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage=HearingBudgetUsage(
            reserved_images=1,
            accounted_output_tokens=primary_failure.response.output_tokens,
        ),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
    )
    assert repair_prepared.request == failed_repair.request
    item = _leased_item(repair_prepared.request)
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=repair_prepared,
        primary_template=primary,
        unfinished=repair_prepared.request,
        item=item,
        prior_primary=primary_failure,
    )
    repaired, output = _parsed_closure(repair_prepared.request)
    result = HearingRoleCallResult(
        output=output,
        trace=HearingCallTrace(calls=(primary_failure, repaired)),
        prepared_primary=primary,
        prepared_repair=repair_prepared,
        cache_hit_count=0,
        recovered_response_count=0,
    )
    role_calls = _RoleCalls(result=result)

    HearingBacklogRetryService(
        repository=_Repository(authority),
        role_calls=role_calls,
    ).retry_leased_item(
        authority,
        HearingBacklogCallPlan(
            primary,
            _context(scenario, backlog_lease=authority.lease),
            repair_prepared,
        ),
    )

    assert role_calls.execute_calls == []
    assert role_calls.repair_calls == [repair_prepared.request]


def test_exhausted_lease_creates_typed_human_authority_and_bidirectional_closure() -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    item = _leased_item(prepared.request, max_attempts=1)
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=prepared,
        unfinished=prepared.request,
        item=item,
    )
    error = HearingRoleCallError(
        HearingRoleCallFailureCode.PROVIDER_FAILED,
        role=prepared.request.role,
        request_id=prepared.request.request_id,
        request=prepared.request,
    )

    commit = HearingBacklogRetryService(
        repository=_Repository(authority),
        role_calls=_RoleCalls(error=error),
    ).retry_leased_item(
        authority,
        HearingBacklogCallPlan(
            prepared,
            _context(scenario, backlog_lease=authority.lease),
        ),
    )

    outcome = commit.receipt.outcome
    assert isinstance(outcome, HearingBacklogRetryFailure)
    assert outcome.human_review_receipt is not None
    assert outcome.human_review_receipt.reason.value == "HEARING_BACKLOG_EXHAUSTED"
    assert commit.item.status == BacklogStatus.EXHAUSTED
    assert commit.case.case.status == CaseStatus.HUMAN_REVIEW
    assert commit.receipt.outcome == outcome


def test_stale_lease_is_rejected_before_any_role_call() -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=prepared,
        unfinished=prepared.request,
    )
    repository = _Repository(authority)
    repository.stale = True
    role_calls = _RoleCalls(result=_success_result(prepared))

    with pytest.raises(ConcurrentModification):
        HearingBacklogRetryService(
            repository=repository,
            role_calls=role_calls,
        ).retry_leased_item(
            authority,
            HearingBacklogCallPlan(
                prepared,
                _context(scenario, backlog_lease=authority.lease),
            ),
        )
    assert role_calls.execute_calls == []


def test_retry_plan_cannot_reset_persisted_session_budget() -> None:
    scenario = _scenario()
    prepared = _prepare(
        scenario,
        VlmRole.PROSECUTOR,
        budget_usage=HearingBudgetUsage(reserved_images=2, accounted_output_tokens=10),
    )
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=prepared,
        unfinished=prepared.request,
        reserved_images=3,
        output_tokens=10,
        reserved_images_before_primary=2,
        output_tokens_before_primary=10,
    )
    with pytest.raises(ContractViolation, match="resets"):
        HearingBacklogRetryService(
            repository=_Repository(authority),
            role_calls=_RoleCalls(result=_success_result(prepared)),
        ).retry_leased_item(
            authority,
            HearingBacklogCallPlan(
                prepared,
                _context(scenario, backlog_lease=authority.lease),
            ),
        )
