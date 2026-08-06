"""M4 hearing model-call physical closure tests for M6 upgrade execution."""

from __future__ import annotations

import hashlib
import sqlite3
import traceback
from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from pathlib import Path
from typing import Any

import pytest

import labcourt.application.m6_upgrade_m4_model_physical as resolver_module
from labcourt.adapters.storage.readonly_m6_hearing_model_calls import (
    ReadonlyM6HearingModelCallAuthorityRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.application.m6_hearing_model_call_authority import (
    derive_m6_hearing_model_call_authority_root,
)
from labcourt.application.m6_upgrade_m4_model_physical import (
    M6M4ModelPhysicalPlan,
    M6M4ModelPhysicalResolutionError,
    M6M4ModelPhysicalResolutionErrorCode,
    plan_m6_m4_observed_model_call_closures,
    resolve_m6_m4_observed_model_call_closures,
    resolve_m6_m4_observed_model_call_physical_plan,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    ModelParseStatus,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
)
from labcourt.contracts.hearing import (
    HearingModelParseReceipt,
    HearingModelResponse,
    HearingUsageReceipt,
)
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
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import ProceduralDefect
from labcourt.ports.m6_model_calls import (
    M6M4ModelCallAuthoritySnapshot,
    M6M4ModelParseReceiptAuthorityDocument,
    M6M4ModelResponseAuthorityDocument,
    M6M4ModelUsageAuthorityDocument,
)
from labcourt.ports.m6_upgrade_model_physical import (
    M6ObservedModelCallPhysicalClosure,
    M6PlannedModelCallPhysicalClosure,
)
from tests.integration import test_m4_sqlite_backlog as m4_sqlite_backlog
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m4_replay_authority_snapshot import _one_role_call
from tests.integration.test_m4_sqlite_hearing_retry import _provider_outage_seed


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_sha256(document: object) -> str:
    assert hasattr(document, "model_dump")
    return _sha(canonical_json(document.model_dump(mode="json")))


def _mutate_dataclass(value: object, attribute: str, replacement: object) -> None:
    setattr(value, attribute, replacement)


class _RawVerifier:
    def __init__(self, returned: object | None = None) -> None:
        self.returned = returned
        self.calls: list[tuple[str, object, HearingModelResponse]] = []

    def verify_raw_response(
        self,
        run_id: str,
        request: object,
        response: HearingModelResponse,
    ) -> HearingModelResponse:
        self.calls.append((run_id, request, response))
        if isinstance(self.returned, BaseException):
            raise self.returned
        if self.returned is None:
            return response
        return self.returned  # type: ignore[return-value]


@pytest.fixture(scope="module")
def response_authority(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Case, M6M4ModelCallAuthoritySnapshot]:
    started = _one_role_call(tmp_path_factory.mktemp("m6-m4-physical-response"))
    source = started.repository.load_case(RUN_ID, started.session.case_id)
    with readonly_sqlite_snapshot(started.database) as private_snapshot:
        authority = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot).load_authority(
            source.case
        )
    return source.case, authority


@pytest.fixture(scope="module")
def failure_authority(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Case, M6M4ModelCallAuthoritySnapshot]:
    seed = _provider_outage_seed(tmp_path_factory.mktemp("m6-m4-physical-failure"))
    with sqlite3.connect(seed.database) as connection:
        row = connection.execute(
            "SELECT case_id FROM m4_hearings WHERE run_id = ? AND hearing_id = ?",
            (RUN_ID, seed.hearing_id),
        ).fetchone()
    assert row is not None and isinstance(row[0], str)
    source = seed.repository.load_case(RUN_ID, row[0])
    with readonly_sqlite_snapshot(seed.database) as private_snapshot:
        authority = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot).load_authority(
            source.case
        )
    return source.case, authority


def _reroot(
    snapshot: M6M4ModelCallAuthoritySnapshot,
    **changes: Any,
) -> M6M4ModelCallAuthoritySnapshot:
    updated = replace(snapshot, **changes)
    root = derive_m6_hearing_model_call_authority_root(
        source_identity_sha256=updated.source_identity_sha256,
        run_id=updated.run_id,
        case_id=updated.case_id,
        manifest_id=updated.manifest_id,
        m4_replay_authority_root_sha256=updated.m4_replay_authority_root_sha256,
        requests=updated.requests,
        responses=updated.responses,
        caches=updated.caches,
        usages=updated.usages,
        parse_receipts=updated.parse_receipts,
        role_outputs=updated.role_outputs,
        failures=updated.failures,
    )
    return replace(updated, model_call_authority_root_sha256=root)


def _error_code(
    source_case: object,
    snapshot: object,
    verifier: object,
) -> M6M4ModelPhysicalResolutionErrorCode:
    with pytest.raises(M6M4ModelPhysicalResolutionError) as raised:
        resolve_m6_m4_observed_model_call_closures(
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
) -> M6M4ModelPhysicalResolutionError:
    with pytest.raises(M6M4ModelPhysicalResolutionError) as raised:
        resolve_m6_m4_observed_model_call_physical_plan(
            source_case=source_case,  # type: ignore[arg-type]
            snapshot=snapshot,  # type: ignore[arg-type]
            plan=plan,  # type: ignore[arg-type]
            raw_response_verifier=verifier,  # type: ignore[arg-type]
        )
    return raised.value


def _assert_payload_free_public_failure(
    error: M6M4ModelPhysicalResolutionError,
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
        if current.tb_frame.f_globals.get("__name__") == resolver_module.__name__:
            public_frames.append(current.tb_frame)
        current = current.tb_next
    assert len(public_frames) == 1
    forbidden = {"source_case", "snapshot", "plan", "verifier", "raw_response_verifier"}
    assert forbidden.isdisjoint(public_frames[0].f_locals)


def _stored_current_case(database: Path) -> Case:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT version.case_json
            FROM cases AS current
            JOIN case_versions AS version
              ON version.run_id = current.run_id
             AND version.case_id = current.case_id
             AND version.revision = current.current_revision
            WHERE current.run_id = ?
            """,
            (RUN_ID,),
        ).fetchone()
    assert row is not None and isinstance(row[0], str)
    return Case.model_validate_json(row[0])


def _four_call_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Case, M6M4ModelCallAuthoritySnapshot]:
    m4_sqlite_backlog.test_hearing_record_reload_includes_malformed_primary_and_valid_repair(
        tmp_path,
        monkeypatch,
    )
    database = next(tmp_path.glob("*.sqlite3"))
    source_case = _stored_current_case(database)
    with readonly_sqlite_snapshot(database) as private_snapshot:
        authority = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot).load_authority(
            source_case
        )
    return source_case, authority


def test_planned_and_observed_m4_closures_are_exact_distinct_contracts() -> None:
    assert is_dataclass(M6PlannedModelCallPhysicalClosure)
    assert is_dataclass(M6ObservedModelCallPhysicalClosure)
    assert len({M6PlannedModelCallPhysicalClosure, M6ObservedModelCallPhysicalClosure}) == 2
    assert tuple(field.name for field in fields(M6PlannedModelCallPhysicalClosure)) == tuple(
        field.name for field in fields(M6ObservedModelCallPhysicalClosure)
    )


def test_m4_planner_builds_complete_stable_exact_plan_without_raw(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_case, snapshot = response_authority

    def raw_trap(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("M4 planner must not touch raw response verification")

    monkeypatch.setattr(resolver_module, "_verify_exact_raw_response", raw_trap)

    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )

    assert type(plan) is M6M4ModelPhysicalPlan
    assert not hasattr(plan, "__dict__")
    assert plan.source_identity_sha256 == snapshot.source_identity_sha256
    assert plan.run_id == source_case.run_id
    assert plan.case_id == source_case.case_id
    assert plan.manifest_id == source_case.manifest_id
    assert len(plan.planned_calls) == 1
    (planned,) = plan.planned_calls
    assert type(planned) is M6PlannedModelCallPhysicalClosure
    assert not hasattr(planned, "__dict__")
    with pytest.raises(FrozenInstanceError):
        _mutate_dataclass(plan, "declared_physical_bytes", plan.declared_physical_bytes)
    with pytest.raises(FrozenInstanceError):
        _mutate_dataclass(planned, "attempt_index", planned.attempt_index)
    assert not hasattr(planned, "provider_invoked")
    assert not hasattr(planned, "raw_verified")
    assert planned.source_identity_sha256 == plan.source_identity_sha256
    assert planned.run_id == plan.run_id
    assert planned.case_id == plan.case_id
    assert planned.manifest_id == plan.manifest_id
    assert planned.layer == M6LockedModelCallLayer.HEARING
    assert planned.role == M6LockedModelRole.PROSECUTOR
    assert planned.attempt_index == snapshot.requests[0].request.attempt_index == 0
    assert planned.response_ref is not None
    assert planned.response_ref.artifact_id == snapshot.responses[0].response.response_id
    assert planned.response_ref.document_sha256 == snapshot.responses[0].document_sha256
    assert planned.response_ref.content_sha256 == snapshot.responses[0].response.content_sha256
    assert planned.response_ref.size_bytes == snapshot.responses[0].response.size_bytes
    assert plan.planned_calls == tuple(sorted(plan.planned_calls, key=lambda item: item.sort_key))
    assert plan.planned_refs == tuple(sorted(plan.planned_refs, key=lambda ref: ref.sort_key))
    assert len({ref.physical_key for ref in plan.planned_refs}) == len(plan.planned_refs)
    assert all(
        ref.source == M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL for ref in plan.planned_refs
    )
    assert plan.declared_physical_bytes == sum(ref.size_bytes for ref in plan.planned_refs)
    assert 0 < plan.declared_physical_bytes <= MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES


def test_m4_planner_projects_all_seven_model_ref_kinds_across_terminal_paths(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
    failure_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    response_case, response_snapshot = response_authority
    failure_case, failure_snapshot = failure_authority

    response_plan = plan_m6_m4_observed_model_call_closures(
        source_case=response_case,
        snapshot=response_snapshot,
    )
    failure_plan = plan_m6_m4_observed_model_call_closures(
        source_case=failure_case,
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
    assert failure_plan.planned_calls[0].result_kind == M6LockedModelCallResultKind.FAILURE
    assert failure_plan.planned_calls[0].failure_ref is not None
    assert failure_plan.planned_calls[0].response_ref is None


def test_m4_two_phase_and_compatibility_interfaces_preserve_empty_graph(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    empty_snapshot = _reroot(
        snapshot,
        requests=(),
        responses=(),
        caches=(),
        usages=(),
        parse_receipts=(),
        role_outputs=(),
        failures=(),
    )
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=empty_snapshot,
    )
    verifier = _RawVerifier(RuntimeError("must not be called"))

    observed = resolve_m6_m4_observed_model_call_physical_plan(
        source_case=source_case,
        snapshot=empty_snapshot,
        plan=plan,
        raw_response_verifier=verifier,
    )
    compatible = resolve_m6_m4_observed_model_call_closures(
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


def test_m4_two_phase_resolver_returns_exact_observed_refinement(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    verifier = _RawVerifier()

    observed = resolve_m6_m4_observed_model_call_physical_plan(
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


def test_m4_two_phase_resolver_preserves_roles_attempts_cache_and_compatibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_case, snapshot = _four_call_authority(tmp_path, monkeypatch)
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    phase_verifier = _RawVerifier()
    compatible_verifier = _RawVerifier()

    observed = resolve_m6_m4_observed_model_call_physical_plan(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        raw_response_verifier=phase_verifier,
    )
    compatible = resolve_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=compatible_verifier,
    )

    prosecutors = tuple(
        item for item in plan.planned_calls if item.role == M6LockedModelRole.PROSECUTOR
    )
    assert len(plan.planned_calls) == len(snapshot.requests) == 4
    assert {item.role for item in plan.planned_calls} == {
        M6LockedModelRole.PROSECUTOR,
        M6LockedModelRole.DEFENDER,
        M6LockedModelRole.JUDGE,
    }
    assert {item.attempt_index for item in prosecutors} == {0, 1}
    assert all(
        item.result_kind == M6LockedModelCallResultKind.RESPONSE for item in plan.planned_calls
    )
    assert all(item.cache_ref is not None for item in plan.planned_calls)
    assert observed == compatible
    assert tuple(item.artifact_refs for item in observed) == tuple(
        item.artifact_refs for item in plan.planned_calls
    )
    assert len(phase_verifier.calls) == len(snapshot.responses) == 4
    assert len(compatible_verifier.calls) == len(snapshot.responses) == 4


def test_m4_two_phase_resolver_rejects_mutated_plan_before_raw(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    object.__setattr__(plan, "declared_physical_bytes", plan.declared_physical_bytes + 1)
    verifier = _RawVerifier(RuntimeError("must not be called"))

    error = _resolve_plan_error(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        verifier=verifier,
    )

    assert error.code == M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID
    assert verifier.calls == []


def test_m4_two_phase_resolver_rejects_nested_scope_spoof_before_raw(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    object.__setattr__(plan.planned_calls[0], "case_id", "foreign-case")
    verifier = _RawVerifier(RuntimeError("must not be called"))

    error = _resolve_plan_error(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        verifier=verifier,
    )

    assert error.code == M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID
    assert verifier.calls == []


def test_m4_two_phase_resolver_rejects_nested_ref_spoof_before_raw(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    object.__setattr__(
        plan.planned_calls[0].request_ref,
        "artifact_id",
        "forged-request-ref",
    )
    verifier = _RawVerifier(RuntimeError("must not be called"))

    error = _resolve_plan_error(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        verifier=verifier,
    )

    assert error.code == M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID
    assert verifier.calls == []


def test_m4_two_phase_resolver_rejects_late_authority_drift_before_raw(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    response = snapshot.responses[0].response
    usage = snapshot.usages[0].receipt
    changed_response = response.model_copy(update={"latency_ms": response.latency_ms + 1})
    changed_usage = usage.model_copy(update={"latency_ms": changed_response.latency_ms})
    drifted_snapshot = _reroot(
        snapshot,
        responses=(
            M6M4ModelResponseAuthorityDocument(
                response=changed_response,
                document_sha256=_document_sha256(changed_response),
            ),
        ),
        usages=(
            M6M4ModelUsageAuthorityDocument(
                receipt=changed_usage,
                document_sha256=_document_sha256(changed_usage),
            ),
        ),
    )
    drifted_plan = plan_m6_m4_observed_model_call_closures(
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
    assert error.code == M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID
    assert verifier.calls == []


def test_m4_two_phase_resolver_rechecks_budget_before_first_raw(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_case, snapshot = response_authority
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    monkeypatch.setattr(
        resolver_module,
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

    assert error.code == M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_BUDGET_EXCEEDED
    assert verifier.calls == []


def test_m4_two_phase_resolver_cannot_accept_typed_error_spoof_from_verifier(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )
    spoof = M6M4ModelPhysicalResolutionError(
        M6M4ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH
    )

    error = _resolve_plan_error(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        verifier=_RawVerifier(spoof),
    )

    assert error.code == M6M4ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED
    assert error.__cause__ is None
    assert error.__context__ is None


def test_all_m4_public_failures_have_fresh_payload_free_tracebacks(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    secret = "secret raw payload from M4 external verifier"
    source_case, snapshot = response_authority
    plan = plan_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
    )

    with pytest.raises(M6M4ModelPhysicalResolutionError) as plan_raised:
        plan_m6_m4_observed_model_call_closures(
            source_case=source_case,
            snapshot=replace(snapshot, case_id="foreign-case"),
        )
    resolve_failure = _resolve_plan_error(
        source_case=source_case,
        snapshot=snapshot,
        plan=plan,
        verifier=_RawVerifier(RuntimeError(secret)),
    )
    with pytest.raises(M6M4ModelPhysicalResolutionError) as compatible_raised:
        resolve_m6_m4_observed_model_call_closures(
            source_case=source_case,
            snapshot=snapshot,
            raw_response_verifier=_RawVerifier(RuntimeError(secret)),
        )

    assert plan_raised.value.code == M6M4ModelPhysicalResolutionErrorCode.AUTHORITY_ASSEMBLY_FAILED
    assert resolve_failure.code == M6M4ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED
    assert (
        compatible_raised.value.code
        == M6M4ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED
    )
    _assert_payload_free_public_failure(plan_raised.value, secret="foreign-case")
    _assert_payload_free_public_failure(resolve_failure, secret=secret)
    _assert_payload_free_public_failure(compatible_raised.value, secret=secret)


def test_resolver_rebuilds_complete_m4_response_closure_from_observed_bytes(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    verifier = _RawVerifier()

    (observed,) = resolve_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=verifier,
    )

    request = snapshot.requests[0].request
    response = snapshot.responses[0].response
    cache = snapshot.caches[0].entry
    receipt = snapshot.parse_receipts[0].receipt
    output = snapshot.role_outputs[0].output
    usage = snapshot.usages[0].receipt
    refs = {item.kind: item for item in observed.artifact_refs}
    documents = {
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST: request,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE: cache,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT: receipt,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT: output,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT: usage,
    }
    artifact_ids = {
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST: request.request_id,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE: cache.cache_entry_id,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT: receipt.parse_receipt_id,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT: output.output_id,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT: usage.usage_receipt_id,
    }

    assert observed.source_identity_sha256 == snapshot.source_identity_sha256
    assert observed.run_id == source_case.run_id
    assert observed.case_id == source_case.case_id
    assert observed.manifest_id == source_case.manifest_id
    assert observed.layer == M6LockedModelCallLayer.HEARING
    assert observed.role == M6LockedModelRole.PROSECUTOR
    assert observed.attempt_index == request.attempt_index == 0
    assert observed.timeout_ms == int(request.budget.timeout_seconds * 1_000)
    assert observed.execution_model_manifest_id == request.model_manifest_id
    assert observed.result_kind == M6LockedModelCallResultKind.RESPONSE
    assert set(refs) == {
        *documents,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
    }
    for kind, document in documents.items():
        canonical = canonical_json(document.model_dump(mode="json"))
        assert refs[kind].artifact_id == artifact_ids[kind]
        assert refs[kind].document_sha256 == _sha(canonical)
        assert refs[kind].content_sha256 == refs[kind].document_sha256
        assert refs[kind].size_bytes == len(canonical.encode("utf-8"))
    response_ref = refs[M6UpgradePhysicalArtifactKind.MODEL_RESPONSE]
    assert response_ref.artifact_id == response.response_id
    assert response_ref.document_sha256 == snapshot.responses[0].document_sha256
    assert response_ref.content_sha256 == response.content_sha256
    assert response_ref.size_bytes == response.size_bytes
    assert observed.failure_ref is None
    assert all(
        item.source == M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
        for item in observed.artifact_refs
    )
    assert not hasattr(observed, "provider_invoked")
    assert verifier.calls == [(source_case.run_id, request, response)]


def test_resolver_uses_actual_m4_usage_receipt_identity(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    (observed,) = resolve_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=_RawVerifier(),
    )

    assert observed.usage_receipt_ref is not None
    assert observed.usage_receipt_ref.artifact_id == snapshot.usages[0].receipt.usage_receipt_id
    assert observed.usage_receipt_ref.artifact_id != snapshot.requests[0].request.request_id


def test_resolver_preserves_response_parse_without_fabricating_output(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    response = snapshot.responses[0].response
    payload = snapshot.parse_receipts[0].receipt.model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    payload.update(
        {
            "status": ModelParseStatus.REPAIR_REQUIRED,
            "defects": (
                ProceduralDefect(
                    code=ProceduralDefectCode.MALFORMED_STRUCTURE,
                    origin=ProceduralDefectOrigin.PARSER,
                    reason_code=ProceduralReasonCode.MALFORMED_JSON,
                    artifact_ref=ArtifactRef(
                        kind=ArtifactKind.MODEL_RESPONSE,
                        artifact_id=response.response_id,
                    ),
                    field=ProceduralField.JSON_ROOT,
                ),
            ),
            "parsed_payload_sha256": None,
            "repair_request_id": _sha("future M4 repair request"),
        }
    )
    receipt = HearingModelParseReceipt.model_validate(payload)
    authority = _reroot(
        snapshot,
        parse_receipts=(
            M6M4ModelParseReceiptAuthorityDocument(
                receipt=receipt,
                document_sha256=_document_sha256(receipt),
            ),
        ),
        role_outputs=(),
    )

    (observed,) = resolve_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=authority,
        raw_response_verifier=_RawVerifier(),
    )

    assert observed.result_kind == M6LockedModelCallResultKind.RESPONSE
    assert observed.response_ref is not None
    assert observed.cache_ref is not None
    assert observed.parse_receipt_ref is not None
    assert observed.usage_receipt_ref is not None
    assert observed.parsed_output_ref is None
    assert observed.failure_ref is None


def test_resolver_rebuilds_failure_only_closure_without_raw_read(
    failure_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = failure_authority
    verifier = _RawVerifier(RuntimeError("must not read raw"))

    (observed,) = resolve_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=verifier,
    )

    request = snapshot.requests[0].request
    failure = snapshot.failures[0].authority
    assert observed.result_kind == M6LockedModelCallResultKind.FAILURE
    assert observed.request_ref.artifact_id == request.request_id
    assert observed.failure_ref is not None
    assert observed.failure_ref.artifact_id == failure.authority_id
    assert observed.response_ref is None
    assert observed.cache_ref is None
    assert observed.parse_receipt_ref is None
    assert observed.parsed_output_ref is None
    assert observed.usage_receipt_ref is None
    assert verifier.calls == []


def test_resolver_returns_exact_stable_full_case_call_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_case, snapshot = _four_call_authority(tmp_path, monkeypatch)
    first_verifier = _RawVerifier()
    second_verifier = _RawVerifier()

    first = resolve_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=first_verifier,
    )
    second = resolve_m6_m4_observed_model_call_closures(
        source_case=source_case,
        snapshot=snapshot,
        raw_response_verifier=second_verifier,
    )

    expected = {
        *(
            (M6UpgradePhysicalArtifactKind.MODEL_REQUEST, item.request.request_id)
            for item in snapshot.requests
        ),
        *(
            (M6UpgradePhysicalArtifactKind.MODEL_RESPONSE, item.response.response_id)
            for item in snapshot.responses
        ),
        *(
            (M6UpgradePhysicalArtifactKind.MODEL_CACHE, item.entry.cache_entry_id)
            for item in snapshot.caches
        ),
        *(
            (M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT, item.receipt.parse_receipt_id)
            for item in snapshot.parse_receipts
        ),
        *(
            (M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT, item.output.output_id)
            for item in snapshot.role_outputs
        ),
        *(
            (M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT, item.receipt.usage_receipt_id)
            for item in snapshot.usages
        ),
        *(
            (M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE, item.authority.authority_id)
            for item in snapshot.failures
        ),
    }
    actual = {(ref.kind, ref.artifact_id) for item in first for ref in item.artifact_refs}
    prosecutor = tuple(item for item in first if item.role == M6LockedModelRole.PROSECUTOR)

    assert len(first) == len(snapshot.requests) == 4
    assert first == second
    assert first == tuple(sorted(first, key=lambda item: item.sort_key))
    assert len({item.request_ref.artifact_id for item in first}) == len(first)
    assert {item.attempt_index for item in prosecutor} == {0, 1}
    assert actual == expected
    assert len(first_verifier.calls) == len(snapshot.responses) == 4
    assert len(second_verifier.calls) == len(snapshot.responses) == 4


@pytest.mark.parametrize(
    ("returned", "expected"),
    (
        (
            RuntimeError("secret raw payload"),
            M6M4ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED,
        ),
        (object(), M6M4ModelPhysicalResolutionErrorCode.RAW_RESPONSE_NOT_EXACT),
    ),
)
def test_resolver_converts_raw_verifier_failures_to_payload_free_error(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
    returned: object,
    expected: M6M4ModelPhysicalResolutionErrorCode,
) -> None:
    source_case, snapshot = response_authority

    assert _error_code(source_case, snapshot, _RawVerifier(returned)) == expected


def test_resolver_rejects_raw_verifier_response_that_is_not_exact(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    changed = snapshot.responses[0].response.model_copy(update={"latency_ms": 20})

    assert (
        _error_code(source_case, snapshot, _RawVerifier(changed))
        == M6M4ModelPhysicalResolutionErrorCode.RAW_RESPONSE_NOT_EXACT
    )


def test_resolver_rejects_empty_raw_response_before_verifier(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    empty = snapshot.responses[0].response.model_copy(update={"size_bytes": 0})
    authority = _reroot(
        snapshot,
        responses=(
            M6M4ModelResponseAuthorityDocument(
                response=empty,
                document_sha256=_document_sha256(empty),
            ),
        ),
    )
    verifier = _RawVerifier()

    assert (
        _error_code(source_case, authority, verifier)
        == M6M4ModelPhysicalResolutionErrorCode.RAW_RESPONSE_EMPTY
    )
    assert verifier.calls == []


def test_resolver_wraps_missing_duplicate_scope_usage_cost_and_retry_drift(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    original_usage = snapshot.usages[0].receipt
    cost_payload = original_usage.model_dump(mode="python", exclude_computed_fields=True)
    cost_payload["estimated_cost"] = original_usage.estimated_cost + 0.25
    cost_drift = HearingUsageReceipt.model_validate(cost_payload)
    response_payload = snapshot.responses[0].response.model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    response_payload["role"] = "DEFENDER"
    crossed_response = HearingModelResponse.model_validate(response_payload)
    retry_payload = original_usage.model_dump(mode="python", exclude_computed_fields=True)
    retry_payload["retry_count"] = original_usage.retry_count + 1
    retry_drift = HearingUsageReceipt.model_validate(retry_payload)

    authorities = (
        _reroot(snapshot, responses=()),
        replace(snapshot, requests=(snapshot.requests[0], snapshot.requests[0])),
        replace(snapshot, case_id="foreign-case"),
        _reroot(
            snapshot,
            responses=(
                M6M4ModelResponseAuthorityDocument(
                    response=crossed_response,
                    document_sha256=_document_sha256(crossed_response),
                ),
            ),
        ),
        _reroot(
            snapshot,
            usages=(
                M6M4ModelUsageAuthorityDocument(
                    receipt=cost_drift,
                    document_sha256=_document_sha256(cost_drift),
                ),
            ),
        ),
        # The trusted readonly M4 scan compares receipt retry_count with the
        # durable claim takeover_count and surfaces any drift as a failed
        # snapshot.  The resolver must preserve that precondition fail-closed.
        replace(
            _reroot(
                snapshot,
                usages=(
                    M6M4ModelUsageAuthorityDocument(
                        receipt=retry_drift,
                        document_sha256=_document_sha256(retry_drift),
                    ),
                ),
            ),
            authority_failure_count=1,
        ),
        replace(
            snapshot,
            responses=(
                replace(snapshot.responses[0], document_sha256=_sha("forged response doc")),
            ),
        ),
    )

    for authority in authorities:
        verifier = _RawVerifier()
        assert (
            _error_code(source_case, authority, verifier)
            == M6M4ModelPhysicalResolutionErrorCode.AUTHORITY_ASSEMBLY_FAILED
        )
        assert verifier.calls == []


def test_resolver_preflights_full_case_declared_bytes_before_any_raw_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_case, snapshot = _four_call_authority(tmp_path, monkeypatch)
    canonical_groups = (
        tuple(item.request for item in snapshot.requests),
        tuple(item.entry for item in snapshot.caches),
        tuple(item.receipt for item in snapshot.parse_receipts),
        tuple(item.output for item in snapshot.role_outputs),
        tuple(item.authority for item in snapshot.failures),
        tuple(item.receipt for item in snapshot.usages),
    )
    declared = sum(
        len(canonical_json(document.model_dump(mode="json")).encode("utf-8"))
        for group in canonical_groups
        for document in group
    ) + sum(item.response.size_bytes for item in snapshot.responses)
    assert declared > 1
    monkeypatch.setattr(
        resolver_module,
        "MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES",
        declared - 1,
    )
    verifier = _RawVerifier()

    assert (
        _error_code(source_case, snapshot, verifier)
        == M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_BUDGET_EXCEEDED
    )
    assert verifier.calls == []


def test_resolver_rejects_invalid_boundary_arguments(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    assert (
        _error_code(object(), snapshot, _RawVerifier())
        == M6M4ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT
    )
    assert (
        _error_code(source_case, object(), _RawVerifier())
        == M6M4ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT
    )
    assert (
        _error_code(source_case, snapshot, object())
        == M6M4ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT
    )
