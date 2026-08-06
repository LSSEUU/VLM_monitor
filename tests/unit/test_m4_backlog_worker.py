from __future__ import annotations

from labcourt.application.hearing_model_parser import inspect_hearing_response
from labcourt.application.hearing_request import (
    HearingBudgetUsage,
    prepare_hearing_repair_request,
)
from labcourt.application.hearing_role_call import HearingRoleCallContext
from labcourt.contracts.enums import BacklogReasonCode, VlmRole
from labcourt.services.m4_backlog_worker import M4HearingBacklogPlanBuilder
from tests.unit.test_m4_hearing_backlog_retry import (
    _authority,
    _leased_item,
    _pending_checkpoint,
    _strict_error,
)
from tests.unit.test_m4_hearing_request import _prepare, _scenario


class _PlanningRepository:
    def __init__(self, scenario, *, requests, usage) -> None:
        self.scenario = scenario
        self.requests = requests
        self.usage = usage

    def load_pack(self, run_id, pack_id):
        assert (run_id, pack_id) == (
            self.scenario.pack.run_id,
            self.scenario.pack.pack_id,
        )
        return self.scenario.pack

    def load_hearing_evidence_authority(self, run_id, hearing_id, pack_id):
        assert (run_id, hearing_id, pack_id) == (
            self.scenario.pack.run_id,
            self.scenario.session.session_id,
            self.scenario.pack.pack_id,
        )
        return self.scenario.authority

    def load_precedent_retrieval(self, run_id, receipt_id):
        assert (run_id, receipt_id) == (
            self.scenario.pack.run_id,
            self.scenario.retrieval.receipt_id,
        )
        return self.scenario.retrieval

    def load_hearing_role_output(self, run_id, output_id):
        raise AssertionError((run_id, output_id))

    def list_hearing_model_requests(self, run_id, hearing_id):
        assert (run_id, hearing_id) == (
            self.scenario.pack.run_id,
            self.scenario.session.session_id,
        )
        return self.requests

    def list_hearing_usage_receipts(self, run_id, hearing_id):
        assert (run_id, hearing_id) == (
            self.scenario.pack.run_id,
            self.scenario.session.session_id,
        )
        return self.usage

    def list_hearing_failure_authorities(self, run_id, hearing_id):
        assert (run_id, hearing_id) == (
            self.scenario.pack.run_id,
            self.scenario.session.session_id,
        )
        return ()


class _RawResponses:
    def __init__(self, response=None, raw: bytes = b"") -> None:
        self.response = response
        self.raw = raw

    def verify_raw_response(self, run_id, request, response):
        assert self.response == response
        assert run_id == request.run_id == response.run_id
        return response

    def read_bytes(self, run_id, response, max_bytes):
        assert self.response == response and run_id == response.run_id
        assert len(self.raw) <= max_bytes
        return self.raw


def _builder(scenario, repository, response_store) -> M4HearingBacklogPlanBuilder:
    return M4HearingBacklogPlanBuilder(
        config=scenario.config,
        manifest=scenario.manifest,
        catalog=scenario.catalog,
        repository=repository,  # type: ignore[arg-type]
        response_store=response_store,  # type: ignore[arg-type]
    )


def test_plan_builder_restarts_only_the_exact_role_at_generation_one() -> None:
    scenario = _scenario()
    primary = _prepare(scenario, VlmRole.PROSECUTOR)
    context = HearingRoleCallContext(
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage_before_primary=HearingBudgetUsage(),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
    )
    strict = _strict_error(primary, context)
    item = _leased_item(
        primary.request,
        reason=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        retry_generation=1,
    )
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=primary,
        unfinished=None,
        item=item,
        reserved_images=len(primary.request.media),
        output_tokens=sum(call.usage.output_tokens for call in strict.failed_calls),
    )
    repository = _PlanningRepository(
        scenario,
        requests=tuple(call.request for call in strict.failed_calls),
        usage=tuple(call.usage for call in strict.failed_calls),
    )

    plan = _builder(scenario, repository, _RawResponses()).build(authority)

    retry = plan.primary.request.backlog_retry_context
    assert retry is not None
    assert retry.backlog_item_id == item.item_id
    assert retry.retry_generation == 1
    assert plan.primary.request.role == VlmRole.PROSECUTOR
    assert plan.primary.request.request_id != primary.request.request_id
    assert plan.repair is None
    assert plan.context.backlog_lease == authority.lease
    assert plan.context.budget_usage_before_primary == HearingBudgetUsage(
        reserved_images=len(primary.request.media),
        accounted_output_tokens=sum(call.usage.output_tokens for call in strict.failed_calls),
    )


def test_plan_builder_resumes_persisted_repair_without_rebuilding_primary_call() -> None:
    scenario = _scenario()
    primary = _prepare(scenario, VlmRole.PROSECUTOR)
    context = HearingRoleCallContext(
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage_before_primary=HearingBudgetUsage(),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
    )
    primary_failure = _strict_error(primary, context).failed_calls[0]
    raw = b"{"
    inspection = inspect_hearing_response(
        raw,
        request=primary.request,
        response=primary_failure.response,
    )
    repair = prepare_hearing_repair_request(
        original=primary,
        response=primary_failure.response,
        inspection=inspection,
        raw_response=raw,
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage=HearingBudgetUsage(
            reserved_images=len(primary.request.media),
            accounted_output_tokens=primary_failure.usage.output_tokens,
        ),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
    )
    item = _leased_item(repair.request)
    authority = _authority(
        scenario,
        checkpoint=_pending_checkpoint(scenario),
        stage=repair,
        primary_template=primary,
        unfinished=repair.request,
        item=item,
        prior_primary=primary_failure,
    )
    repository = _PlanningRepository(
        scenario,
        requests=(primary.request, repair.request),
        usage=(primary_failure.usage,),
    )

    plan = _builder(
        scenario,
        repository,
        _RawResponses(primary_failure.response, raw),
    ).build(authority)

    assert plan.primary.request == primary.request
    assert plan.repair is not None
    assert plan.repair.request == repair.request
    assert plan.context.backlog_lease == authority.lease
    assert plan.context.budget_usage_before_primary == HearingBudgetUsage()
