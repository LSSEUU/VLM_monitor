"""M3 model-call physical closure tests for M6 upgrade execution."""

from __future__ import annotations

import hashlib
import traceback
from dataclasses import fields, is_dataclass, replace

import pytest

from labcourt.application import m6_upgrade_m3_model_physical as m3_physical
from labcourt.application.m6_upgrade_m3_model_physical import (
    M6M3ModelPhysicalPlan,
    M6M3ModelPhysicalResolutionError,
    M6M3ModelPhysicalResolutionErrorCode,
    plan_m6_m3_observed_model_call_closures,
    resolve_m6_m3_observed_model_call_closures,
    resolve_m6_m3_observed_model_call_physical_plan,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.screening import VLMCallRequest, VLMResponse
from labcourt.ports.m6_model_calls import (
    M6M3ModelCacheAuthorityDocument,
    M6M3ModelCallAuthoritySnapshot,
    M6M3ModelParseReceiptAuthorityDocument,
    M6M3ModelRequestAuthorityDocument,
    M6M3ModelResponseAuthorityDocument,
    M6M3ParsedOutputAuthorityDocument,
)
from labcourt.ports.m6_upgrade_model_physical import (
    M6ObservedModelCallPhysicalClosure,
    M6PlannedModelCallPhysicalClosure,
)
from tests.integration.test_m3_sqlite_repository import _parsed, _parsed_receipt, _response
from tests.unit.test_m6_model_call_authority import (
    _cache_entry,
    _document_sha256,
    _failure_document,
    _response_snapshot,
    _usage_document,
)
from tests.unit.test_m6_model_reference_authority import _repair_snapshot


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _RawVerifier:
    def __init__(self, returned: object | None = None) -> None:
        self.returned = returned
        self.calls: list[tuple[str, VLMCallRequest, VLMResponse]] = []

    def verify_raw_response(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> VLMResponse:
        self.calls.append((run_id, request, response))
        if isinstance(self.returned, BaseException):
            raise self.returned
        if self.returned is None:
            return response
        return self.returned  # type: ignore[return-value]


def _error_code(
    source_case: object,
    snapshot: object,
    verifier: object,
) -> M6M3ModelPhysicalResolutionErrorCode:
    with pytest.raises(M6M3ModelPhysicalResolutionError) as raised:
        resolve_m6_m3_observed_model_call_closures(
            source_case=source_case,  # type: ignore[arg-type]
            snapshot=snapshot,  # type: ignore[arg-type]
            raw_response_verifier=verifier,  # type: ignore[arg-type]
        )
    assert "secret raw payload" not in str(raised.value)
    return raised.value.code


def _resolve_plan_error(
    *,
    source_case: object,
    snapshot: object,
    plan: object,
    verifier: object,
) -> M6M3ModelPhysicalResolutionError:
    with pytest.raises(M6M3ModelPhysicalResolutionError) as raised:
        resolve_m6_m3_observed_model_call_physical_plan(
            source_case=source_case,  # type: ignore[arg-type]
            snapshot=snapshot,  # type: ignore[arg-type]
            plan=plan,  # type: ignore[arg-type]
            raw_response_verifier=verifier,  # type: ignore[arg-type]
        )
    return raised.value


def _assert_payload_free_public_failure(
    error: M6M3ModelPhysicalResolutionError,
    *,
    secret: str,
) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    assert secret not in rendered
    public_frames = []
    current = error.__traceback__
    while current is not None:
        if current.tb_frame.f_globals.get("__name__") == m3_physical.__name__:
            public_frames.append(current.tb_frame)
        current = current.tb_next
    assert len(public_frames) == 1
    forbidden = {"source_case", "snapshot", "plan", "verifier", "raw_response_verifier"}
    assert forbidden.isdisjoint(public_frames[0].f_locals)


def test_planned_and_observed_call_closures_share_an_exact_distinct_contract() -> None:
    assert is_dataclass(M6PlannedModelCallPhysicalClosure)
    assert is_dataclass(M6ObservedModelCallPhysicalClosure)
    assert M6PlannedModelCallPhysicalClosure is not M6ObservedModelCallPhysicalClosure
    assert not issubclass(M6PlannedModelCallPhysicalClosure, M6ObservedModelCallPhysicalClosure)
    assert not issubclass(M6ObservedModelCallPhysicalClosure, M6PlannedModelCallPhysicalClosure)
    assert tuple(field.name for field in fields(M6PlannedModelCallPhysicalClosure)) == tuple(
        field.name for field in fields(M6ObservedModelCallPhysicalClosure)
    )
    assert M6PlannedModelCallPhysicalClosure.__dataclass_params__.frozen
    assert M6ObservedModelCallPhysicalClosure.__dataclass_params__.frozen


def test_planner_builds_complete_stable_receipt_projected_plan_without_raw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_case, snapshot = _response_snapshot()

    def raw_trap(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("planner must not touch raw response verification")

    monkeypatch.setattr(m3_physical, "_verify_exact_raw_response", raw_trap)

    plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )

    assert type(plan) is M6M3ModelPhysicalPlan
    assert M6M3ModelPhysicalPlan.__dataclass_params__.frozen
    assert not hasattr(plan, "__dict__")
    assert len(plan.planned_calls) == 1
    (planned,) = plan.planned_calls
    assert type(planned) is M6PlannedModelCallPhysicalClosure
    assert not hasattr(planned, "__dict__")
    assert not hasattr(planned, "provider_invoked")
    assert not hasattr(planned, "raw_verified")
    assert planned.response_ref is not None
    response = snapshot.responses[0].response
    assert planned.response_ref.artifact_id == response.response_id
    assert planned.response_ref.document_sha256 == snapshot.responses[0].document_sha256
    assert planned.response_ref.content_sha256 == response.content_sha256
    assert planned.response_ref.size_bytes == response.size_bytes
    assert plan.planned_calls == tuple(sorted(plan.planned_calls, key=lambda item: item.sort_key))
    assert plan.planned_refs == tuple(sorted(plan.planned_refs, key=lambda ref: ref.sort_key))
    assert len({ref.physical_key for ref in plan.planned_refs}) == len(plan.planned_refs)
    assert plan.declared_physical_bytes == sum(ref.size_bytes for ref in plan.planned_refs)


def test_planner_projects_all_seven_model_physical_ref_kinds_across_result_paths() -> None:
    source_case, response_snapshot = _response_snapshot()
    response_plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=response_snapshot,
    )
    request_document = response_snapshot.requests[0]
    failure_snapshot = replace(
        response_snapshot,
        responses=(),
        caches=(),
        parse_receipts=(),
        parsed_outputs=(),
        usages=(),
        failures=(_failure_document(request_document),),
    )
    failure_plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=failure_snapshot,
    )

    planned_kinds = {ref.kind for ref in response_plan.planned_refs} | {
        ref.kind for ref in failure_plan.planned_refs
    }
    assert planned_kinds == {
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
    }


def test_two_phase_and_compatibility_interfaces_preserve_an_empty_call_graph() -> None:
    source_case, snapshot = _response_snapshot()
    empty_snapshot = replace(
        snapshot,
        requests=(),
        responses=(),
        caches=(),
        parse_receipts=(),
        parsed_outputs=(),
        failures=(),
        usages=(),
    )
    plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=empty_snapshot,
    )
    verifier = _RawVerifier(RuntimeError("must not be called"))

    observed = resolve_m6_m3_observed_model_call_physical_plan(
        source_case=source_case,
        snapshot=empty_snapshot,
        plan=plan,
        raw_response_verifier=verifier,
    )
    compatible = resolve_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=empty_snapshot,
        raw_response_verifier=verifier,
    )

    assert plan.planned_calls == ()
    assert plan.planned_refs == ()
    assert plan.declared_physical_bytes == 0
    assert observed == ()
    assert compatible == ()
    assert verifier.calls == []


def test_two_phase_resolver_returns_exact_observed_refinement_of_plan() -> None:
    source_case, snapshot = _response_snapshot()
    plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    verifier = _RawVerifier()

    observed = resolve_m6_m3_observed_model_call_physical_plan(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        raw_response_verifier=verifier,
    )

    assert len(observed) == len(plan.planned_calls)
    for planned_call, observed_call in zip(plan.planned_calls, observed, strict=True):
        assert type(observed_call) is M6ObservedModelCallPhysicalClosure
        assert observed_call.sort_key == planned_call.sort_key
        assert observed_call.artifact_refs == planned_call.artifact_refs
    assert verifier.calls == [
        (source_case.run_id, snapshot.requests[0].request, snapshot.responses[0].response)
    ]


def test_two_phase_resolver_preserves_failure_and_repair_call_order() -> None:
    source_case, response_snapshot = _response_snapshot()
    request_document = response_snapshot.requests[0]
    failure_snapshot = replace(
        response_snapshot,
        responses=(),
        caches=(),
        parse_receipts=(),
        parsed_outputs=(),
        usages=(),
        failures=(_failure_document(request_document),),
    )
    failure_plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=failure_snapshot,
    )
    failure_verifier = _RawVerifier(RuntimeError("must not be called"))
    failure_observed = resolve_m6_m3_observed_model_call_physical_plan(
        source_case=source_case,
        snapshot=failure_snapshot,
        plan=failure_plan,
        raw_response_verifier=failure_verifier,
    )

    repair_snapshot = _repair_snapshot()
    repair_plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=repair_snapshot,
    )
    repair_verifier = _RawVerifier()
    repair_observed = resolve_m6_m3_observed_model_call_physical_plan(
        source_case=source_case,
        snapshot=repair_snapshot,
        plan=repair_plan,
        raw_response_verifier=repair_verifier,
    )

    assert failure_observed[0].result_kind == M6LockedModelCallResultKind.FAILURE
    assert failure_verifier.calls == []
    assert tuple(item.attempt_index for item in repair_plan.planned_calls) == (0, 1)
    assert tuple(item.attempt_index for item in repair_observed) == (0, 1)
    assert tuple(item.artifact_refs for item in repair_observed) == tuple(
        item.artifact_refs for item in repair_plan.planned_calls
    )
    assert len(repair_verifier.calls) == 2


def test_two_phase_resolver_rejects_forged_plan_before_raw_verification() -> None:
    source_case, snapshot = _response_snapshot()
    forged_plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    object.__setattr__(
        forged_plan,
        "declared_physical_bytes",
        forged_plan.declared_physical_bytes + 1,
    )
    verifier = _RawVerifier(RuntimeError("must not be called"))

    error = _resolve_plan_error(
        source_case=source_case,
        snapshot=snapshot,
        plan=forged_plan,
        verifier=verifier,
    )

    assert error.code == M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID
    assert verifier.calls == []


def test_two_phase_resolver_rejects_late_receipt_drift_before_raw_verification() -> None:
    source_case, snapshot = _response_snapshot()
    plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    request = snapshot.requests[0].request
    response = snapshot.responses[0].response
    changed_response = response.model_copy(update={"latency_ms": response.latency_ms + 1})
    drifted_snapshot = replace(
        snapshot,
        responses=(
            M6M3ModelResponseAuthorityDocument(
                response=changed_response,
                document_sha256=_document_sha256(changed_response),
            ),
        ),
        usages=(_usage_document(request, changed_response),),
    )
    drifted_plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=drifted_snapshot,
    )
    verifier = _RawVerifier(RuntimeError("must not be called"))

    error = _resolve_plan_error(
        source_case=source_case,
        snapshot=drifted_snapshot,
        plan=plan,
        verifier=verifier,
    )

    assert drifted_plan.planned_refs != plan.planned_refs
    assert error.code == M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID
    assert verifier.calls == []


def test_two_phase_resolver_rechecks_budget_before_first_raw_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_case, snapshot = _response_snapshot()
    plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    monkeypatch.setattr(
        m3_physical,
        "MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES",
        plan.declared_physical_bytes - 1,
    )
    verifier = _RawVerifier(RuntimeError("must not be called"))

    error = _resolve_plan_error(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        verifier=verifier,
    )

    assert error.code == M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_BUDGET_EXCEEDED
    assert verifier.calls == []


def test_two_phase_resolver_cannot_accept_typed_error_spoof_from_verifier() -> None:
    source_case, snapshot = _response_snapshot()
    plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    spoof = M6M3ModelPhysicalResolutionError(
        M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH
    )

    error = _resolve_plan_error(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        verifier=_RawVerifier(spoof),
    )

    assert error.code == M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED
    assert error.__cause__ is None
    assert error.__context__ is None


def test_all_public_failures_drop_authority_and_verifier_traceback_locals() -> None:
    secret = "secret raw payload from external verifier"
    source_case, snapshot = _response_snapshot()
    plan = plan_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )

    plan_failure: M6M3ModelPhysicalResolutionError
    with pytest.raises(M6M3ModelPhysicalResolutionError) as plan_raised:
        plan_m6_m3_observed_model_call_closures(
            source_case=source_case,
            snapshot=replace(snapshot, case_id="foreign-case"),
        )
    plan_failure = plan_raised.value

    resolve_failure = _resolve_plan_error(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        verifier=_RawVerifier(RuntimeError(secret)),
    )

    with pytest.raises(M6M3ModelPhysicalResolutionError) as compatible_raised:
        resolve_m6_m3_observed_model_call_closures(
            source_case=source_case,
            snapshot=snapshot,
            raw_response_verifier=_RawVerifier(RuntimeError(secret)),
        )

    assert plan_failure.code == M6M3ModelPhysicalResolutionErrorCode.AUTHORITY_ASSEMBLY_FAILED
    assert resolve_failure.code == M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED
    assert (
        compatible_raised.value.code
        == M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED
    )
    _assert_payload_free_public_failure(plan_failure, secret="foreign-case")
    _assert_payload_free_public_failure(resolve_failure, secret=secret)
    _assert_payload_free_public_failure(compatible_raised.value, secret=secret)


def test_resolver_rebuilds_complete_response_closure_from_observed_bytes() -> None:
    source_case, snapshot = _response_snapshot()
    verifier = _RawVerifier()

    (observed,) = resolve_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=verifier,
    )

    request = snapshot.requests[0].request
    response = snapshot.responses[0].response
    request_document = canonical_json(request.model_dump(mode="json"))
    assert observed.source_identity_sha256 == snapshot.source_identity_sha256
    assert observed.run_id == source_case.run_id
    assert observed.case_id == source_case.case_id
    assert observed.manifest_id == source_case.manifest_id
    assert observed.layer == M6LockedModelCallLayer.SCREENING
    assert observed.role == M6LockedModelRole.SCREENING
    assert observed.attempt_index == 0
    assert observed.timeout_ms == int(request.budget.timeout_seconds * 1_000) == 15_000
    assert observed.execution_model_manifest_id == request.model_manifest_id
    assert observed.result_kind == M6LockedModelCallResultKind.RESPONSE
    assert observed.request_ref.artifact_id == request.request_id
    assert observed.request_ref.document_sha256 == _document_sha256(request)
    assert observed.request_ref.content_sha256 == observed.request_ref.document_sha256
    assert observed.request_ref.size_bytes == len(request_document.encode("utf-8"))
    assert observed.response_ref is not None
    assert observed.response_ref.artifact_id == response.response_id
    assert observed.response_ref.document_sha256 == _document_sha256(response)
    assert observed.response_ref.content_sha256 == response.content_sha256
    assert observed.response_ref.size_bytes == response.size_bytes
    assert observed.cache_ref is not None
    assert observed.parse_receipt_ref is not None
    assert observed.parsed_output_ref is not None
    assert observed.usage_receipt_ref is not None
    assert observed.usage_receipt_ref.artifact_id == request.request_id
    assert observed.failure_ref is None
    assert {ref.kind for ref in observed.artifact_refs} == {
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
    }
    assert all(
        ref.source == M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
        for ref in observed.artifact_refs
    )
    assert not hasattr(observed, "provider_invoked")
    assert verifier.calls == [(source_case.run_id, request, response)]


@pytest.mark.parametrize("field_name", ("run_id", "case_id"))
def test_observed_model_call_closure_requires_reference_token_scope(
    field_name: str,
) -> None:
    source_case, snapshot = _response_snapshot()
    (observed,) = resolve_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=_RawVerifier(),
    )

    with pytest.raises(ValueError, match="reference token"):
        replace(observed, **{field_name: "../invalid"})


def test_resolver_rebuilds_failed_call_without_touching_raw_store() -> None:
    source_case, response_snapshot = _response_snapshot()
    request_document = response_snapshot.requests[0]
    snapshot = replace(
        response_snapshot,
        responses=(),
        caches=(),
        parse_receipts=(),
        parsed_outputs=(),
        usages=(),
        failures=(_failure_document(request_document),),
    )
    verifier = _RawVerifier(RuntimeError("must not be called"))

    (observed,) = resolve_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=verifier,
    )

    assert observed.result_kind == M6LockedModelCallResultKind.FAILURE
    assert observed.request_ref.artifact_id == request_document.request.request_id
    assert observed.failure_ref is not None
    assert observed.failure_ref.artifact_id == snapshot.failures[0].authority.authority_id
    assert observed.response_ref is None
    assert observed.cache_ref is None
    assert observed.parse_receipt_ref is None
    assert observed.parsed_output_ref is None
    assert observed.usage_receipt_ref is None
    assert verifier.calls == []


def test_resolver_returns_stable_exact_primary_and_repair_attempts() -> None:
    source_case, _base = _response_snapshot()
    snapshot = _repair_snapshot()
    verifier = _RawVerifier()

    observed = resolve_m6_m3_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=verifier,
    )

    assert len(observed) == 2
    assert observed == tuple(sorted(observed, key=lambda item: item.sort_key))
    assert {item.attempt_index for item in observed} == {0, 1}
    assert {item.role for item in observed} == {M6LockedModelRole.SCREENING}
    assert {item.execution_model_manifest_id for item in observed} == {
        document.request.model_manifest_id for document in snapshot.requests
    }
    assert len(verifier.calls) == 2


@pytest.mark.parametrize(
    ("returned", "expected"),
    (
        (
            RuntimeError("secret raw payload"),
            M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED,
        ),
        (object(), M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_NOT_EXACT),
    ),
)
def test_resolver_converts_raw_rejection_and_non_response_to_payload_free_failure(
    returned: object,
    expected: M6M3ModelPhysicalResolutionErrorCode,
) -> None:
    source_case, snapshot = _response_snapshot()

    assert _error_code(source_case, snapshot, _RawVerifier(returned)) == expected


def test_resolver_rejects_raw_verifier_response_that_is_not_exact() -> None:
    source_case, snapshot = _response_snapshot()
    changed = snapshot.responses[0].response.model_copy(update={"latency_ms": 20})

    assert (
        _error_code(source_case, snapshot, _RawVerifier(changed))
        == M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_NOT_EXACT
    )


def test_resolver_rejects_empty_raw_response_before_verification() -> None:
    source_case, snapshot = _response_snapshot()
    empty = snapshot.responses[0].response.model_copy(update={"size_bytes": 0})
    forged_snapshot = replace(
        snapshot,
        responses=(
            M6M3ModelResponseAuthorityDocument(
                response=empty,
                document_sha256=_document_sha256(empty),
            ),
        ),
    )
    verifier = _RawVerifier()

    assert (
        _error_code(source_case, forged_snapshot, verifier)
        == M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_EMPTY
    )
    assert verifier.calls == []


@pytest.mark.parametrize(
    "mutate",
    (
        lambda snapshot: replace(
            snapshot,
            requests=(replace(snapshot.requests[0], document_sha256=_sha("forged-request")),),
        ),
        lambda snapshot: replace(snapshot, case_id="foreign-case"),
        lambda snapshot: replace(snapshot, usages=snapshot.usages * 2),
    ),
)
def test_resolver_converts_document_and_scope_tampering_to_assembly_failure(
    mutate: object,
) -> None:
    source_case, snapshot = _response_snapshot()
    verifier = _RawVerifier()
    assert callable(mutate)

    assert (
        _error_code(source_case, mutate(snapshot), verifier)
        == M6M3ModelPhysicalResolutionErrorCode.AUTHORITY_ASSEMBLY_FAILED
    )
    assert verifier.calls == []


def _large_declared_raw_snapshot() -> tuple[object, M6M3ModelCallAuthoritySnapshot]:
    source_case, template = _response_snapshot()
    template_request = template.requests[0].request
    requests: list[M6M3ModelRequestAuthorityDocument] = []
    responses: list[M6M3ModelResponseAuthorityDocument] = []
    caches: list[M6M3ModelCacheAuthorityDocument] = []
    receipts: list[M6M3ModelParseReceiptAuthorityDocument] = []
    outputs: list[M6M3ParsedOutputAuthorityDocument] = []
    usages = []
    raw_size = 16_777_216
    assert 17 * raw_size > MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES
    for index in range(17):
        budget = template_request.budget.model_copy(update={"max_response_bytes": raw_size})
        request = template_request.model_copy(
            update={
                "rendered_prompt_sha256": _sha(f"large-prompt-{index}"),
                "budget": budget,
            }
        )
        response = _response(
            request,
            content_sha256=_sha(f"large-raw-{index}"),
            input_tokens=11,
            output_tokens=7,
            latency_ms=19,
        ).model_copy(update={"size_bytes": raw_size})
        output = _parsed(request, response)
        receipt = _parsed_receipt(request, response, output)
        cache = _cache_entry(request, response)
        requests.append(
            M6M3ModelRequestAuthorityDocument(
                request=request,
                document_sha256=_document_sha256(request),
            )
        )
        responses.append(
            M6M3ModelResponseAuthorityDocument(
                response=response,
                document_sha256=_document_sha256(response),
            )
        )
        caches.append(
            M6M3ModelCacheAuthorityDocument(
                request=request,
                request_document_sha256=_document_sha256(request),
                entry=cache,
                document_sha256=_document_sha256(cache),
            )
        )
        receipts.append(
            M6M3ModelParseReceiptAuthorityDocument(
                receipt=receipt,
                document_sha256=_document_sha256(receipt),
            )
        )
        outputs.append(
            M6M3ParsedOutputAuthorityDocument(
                output=output,
                document_sha256=_document_sha256(output),
            )
        )
        usages.append(_usage_document(request, response))
    return source_case, M6M3ModelCallAuthoritySnapshot(
        source_identity_sha256=template.source_identity_sha256,
        run_id=template.run_id,
        case_id=template.case_id,
        manifest_id=template.manifest_id,
        requests=tuple(sorted(requests, key=lambda item: item.request.request_id)),
        responses=tuple(sorted(responses, key=lambda item: item.response.response_id)),
        caches=tuple(sorted(caches, key=lambda item: item.entry.cache_entry_id)),
        parse_receipts=tuple(sorted(receipts, key=lambda item: item.receipt.parse_receipt_id)),
        parsed_outputs=tuple(sorted(outputs, key=lambda item: item.output.parsed_output_id)),
        failures=(),
        usages=tuple(sorted(usages, key=lambda item: item.request_id)),
    )


def test_resolver_preflights_whole_case_byte_budget_before_any_raw_verification() -> None:
    source_case, snapshot = _large_declared_raw_snapshot()
    verifier = _RawVerifier()

    assert (
        _error_code(source_case, snapshot, verifier)
        == M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_BUDGET_EXCEEDED
    )
    assert verifier.calls == []
