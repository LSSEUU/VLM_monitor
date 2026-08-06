"""Pure contract tests for bounded M4 SQLite metadata-plan primitives."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, is_dataclass, replace
from importlib import import_module
from typing import cast

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan as subject
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan import (
    MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES,
    MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES,
    MAX_M6_SQLITE_M4_MODEL_PHYSICAL_TOTAL_BYTES,
    MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP,
    M6SQLiteM4CallGeneration,
    M6SQLiteM4CallGraphPlan,
    M6SQLiteM4ClaimStatus,
    M6SQLiteM4DocumentRoute,
    M6SQLiteM4DocumentSlot,
    M6SQLiteM4FailureClosureKind,
    M6SQLiteM4HearingModelManifestBinding,
    M6SQLiteM4HistoricalFailureBinding,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4ModelDocumentsPlan,
    M6SQLiteM4RoleModelManifestBinding,
    M6SQLiteM4SelectedPackBinding,
    M6SQLiteM4SupportDocumentCommitmentKind,
    M6SQLiteM4SupportDocumentRoute,
    M6SQLiteM4SupportDocumentSlot,
    M6SQLiteM4SupportRoute,
    M6SQLiteM4SupportSlot,
)
from labcourt.contracts.audit import AuditEntry, AuditEntryDraft
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    ModelParseStatus,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_execution_observation import M6UpgradeObservedModelCall
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.storage import ArtifactRef

_KIND_BY_ROUTE = {
    M6SQLiteM4DocumentRoute.MODEL_REQUEST: M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
    M6SQLiteM4DocumentRoute.MODEL_RESPONSE: M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
    M6SQLiteM4DocumentRoute.MODEL_CACHE_ENTRY: M6UpgradePhysicalArtifactKind.MODEL_CACHE,
    M6SQLiteM4DocumentRoute.MODEL_PARSE_RECEIPT: (
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT
    ),
    M6SQLiteM4DocumentRoute.ROLE_OUTPUT: M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
    M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE: (M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE),
    M6SQLiteM4DocumentRoute.MODEL_USAGE: M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
}


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _physical_ref(
    route: M6SQLiteM4DocumentRoute,
    *,
    artifact_id: str,
    document_sha256: str,
    document_bytes: int,
) -> M6UpgradePhysicalArtifactRef:
    kind = _KIND_BY_ROUTE[route]
    response = route == M6SQLiteM4DocumentRoute.MODEL_RESPONSE
    return M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        kind=kind,
        artifact_id=artifact_id,
        document_sha256=document_sha256,
        content_sha256=_sha("raw response") if response else document_sha256,
        size_bytes=79 if response else document_bytes,
    )


def _document_slot(
    route: M6SQLiteM4DocumentRoute,
    *,
    rowid: int = 1,
    document_bytes: int = 23,
    artifact_id: str | None = None,
    document_sha256: str | None = None,
    physical_bytes: int | None = None,
) -> M6SQLiteM4DocumentSlot:
    artifact_id = artifact_id or _sha(f"artifact {route.value} {rowid}")
    document_sha256 = document_sha256 or _sha(f"document {route.value} {rowid}")
    return M6SQLiteM4DocumentSlot(
        route=route,
        rowid=rowid,
        artifact_id=artifact_id,
        document_sha256=document_sha256,
        document_bytes=document_bytes,
        index_identity_sha256=_sha(f"index {route.value} {rowid}"),
        physical_ref=(
            _physical_ref(
                route,
                artifact_id=artifact_id,
                document_sha256=document_sha256,
                document_bytes=(physical_bytes if physical_bytes is not None else document_bytes),
            )
            if route in _KIND_BY_ROUTE
            else None
        ),
    )


def _historical(
    *,
    closure_kind: M6SQLiteM4FailureClosureKind = M6SQLiteM4FailureClosureKind.INITIAL_BACKLOG,
    completion_receipt_id: str | None = None,
    backlog_version: int = 1,
) -> M6SQLiteM4HistoricalFailureBinding:
    return M6SQLiteM4HistoricalFailureBinding(
        request_id=_sha("request"),
        claim_takeover_count=0,
        authority_id=_sha("failure authority"),
        hearing_id=_sha("hearing"),
        cycle_scope_id=_sha("cycle"),
        cycle_scope_sha256=_sha("cycle body"),
        case_id=_sha("case"),
        role=M6LockedModelRole.PROSECUTOR,
        source_checkpoint_id=_sha("checkpoint"),
        source_checkpoint_sha256=_sha("checkpoint body"),
        source_checkpoint_version=1,
        backlog_item_id=_sha("backlog"),
        backlog_version=backlog_version,
        retry_generation=0,
        closure_kind=closure_kind,
        completion_receipt_id=completion_receipt_id,
        closure_case_revision=2,
        closure_audit_sequence=2,
        closure_audit_entry_hash=_sha("audit"),
        rowid=7,
        document_sha256=_sha("historical document"),
        document_bytes=41,
        index_identity_sha256=_sha("historical index"),
    )


def _document_sha256(document: object) -> str:
    assert hasattr(document, "model_dump")
    return _sha(canonical_json(document.model_dump(mode="json")))


@dataclass(frozen=True, slots=True)
class _CaseAuthority:
    case: Case
    revision: int
    audit: AuditEntry
    binding: M6UpgradeCandidateCaseBinding
    pack: M6SQLiteM4SelectedPackBinding


def _case_authority() -> _CaseAuthority:
    fixture = import_module("tests.unit.test_m6_model_call_authority")
    case = cast(Case, fixture._response_snapshot()[0])
    pack = case.evidence_packs[0]
    case_sha256 = _document_sha256(case)
    revision = 2
    audit = AuditEntryDraft(
        run_id=case.run_id,
        sequence=2,
        actor=AuditActorRole.SYSTEM,
        action=AuditAction.CASE_STATE_CHANGED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case.case_id),
        before_sha256=_sha("prior case"),
        after_sha256=case_sha256,
        manifest_id=case.manifest_id,
        recorded_at="2026-08-04T08:09:10.000011Z",
        prev_entry_hash=_sha("prior audit"),
    ).seal()
    binding = M6UpgradeCandidateCaseBinding(
        case_id=case.case_id,
        case_revision=revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=audit.sequence,
        case_audit_entry_hash=audit.entry_hash,
    )
    return _CaseAuthority(
        case=case,
        revision=revision,
        audit=audit,
        binding=binding,
        pack=M6SQLiteM4SelectedPackBinding(
            rowid=90,
            pack_id=pack.pack_id,
            version=pack.version,
            document_sha256=_document_sha256(pack),
            created_audit_sequence=1,
            index_identity_sha256=_sha("selected pack index"),
        ),
    )


def _hearing_binding(
    hearing_id: str, model_manifest_id: str
) -> M6SQLiteM4HearingModelManifestBinding:
    return M6SQLiteM4HearingModelManifestBinding(
        hearing_id=hearing_id,
        hearing_prompt_bundle_sha256=_sha("prompt bundle"),
        role_bindings=tuple(
            M6SQLiteM4RoleModelManifestBinding(
                role=role,
                model_manifest_id=(
                    model_manifest_id if role == M6LockedModelRole.PROSECUTOR else _sha(role.value)
                ),
            )
            for role in (
                M6LockedModelRole.PROSECUTOR,
                M6LockedModelRole.DEFENDER,
                M6LockedModelRole.JUDGE,
            )
        ),
    )


def _observation(
    *,
    attempt_index: int = 0,
    result_kind: M6LockedModelCallResultKind = M6LockedModelCallResultKind.RESPONSE,
) -> M6UpgradeObservedModelCall:
    return M6UpgradeObservedModelCall(
        request_id=_sha("request" if attempt_index == 0 else "repair request"),
        layer=M6LockedModelCallLayer.HEARING,
        role=M6LockedModelRole.PROSECUTOR,
        attempt_index=attempt_index,
        result_kind=result_kind,
        provider_invoked=True,
    )


def _response_graph(
    authority: _CaseAuthority,
    *,
    attempt_index: int = 0,
    parse_status: ModelParseStatus = ModelParseStatus.PARSED,
    repair_request_id: str | None = None,
    ordinal: int = 1,
    claim_takeover_count: int = 0,
) -> M6SQLiteM4CallGraphPlan:
    observation = _observation(attempt_index=attempt_index)
    base = ordinal * 20
    model_manifest_id = _sha("prosecutor model")
    role_output = (
        _document_slot(M6SQLiteM4DocumentRoute.ROLE_OUTPUT, rowid=base + 6)
        if parse_status == ModelParseStatus.PARSED
        else None
    )
    return M6SQLiteM4CallGraphPlan(
        observation=observation,
        hearing_id=_sha("hearing"),
        cycle_scope_id=_sha("cycle"),
        cycle_scope_sha256=_sha("cycle body"),
        cycle_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        evidence_pack_id=authority.pack.pack_id,
        evidence_pack_version=authority.pack.version,
        retrieval_receipt_id=_sha("retrieval"),
        retrieval_commitment_sha256=_sha("retrieval body"),
        purpose="ROLE_CALL" if attempt_index == 0 else "STRUCTURE_REPAIR",
        call_generation=M6SQLiteM4CallGeneration.INITIAL,
        backlog_item_id=None,
        retry_generation=0,
        model_manifest_id=model_manifest_id,
        claim_status=M6SQLiteM4ClaimStatus.COMPLETED,
        claim_takeover_count=claim_takeover_count,
        request=_document_slot(
            M6SQLiteM4DocumentRoute.MODEL_REQUEST,
            rowid=base + 1,
            artifact_id=observation.request_id,
        ),
        response=_document_slot(M6SQLiteM4DocumentRoute.MODEL_RESPONSE, rowid=base + 2),
        cache_request=_document_slot(
            M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST,
            rowid=base + 3,
            artifact_id=observation.request_id,
        ),
        cache=_document_slot(M6SQLiteM4DocumentRoute.MODEL_CACHE_ENTRY, rowid=base + 4),
        parse_receipt=_document_slot(
            M6SQLiteM4DocumentRoute.MODEL_PARSE_RECEIPT,
            rowid=base + 5,
        ),
        role_output=role_output,
        usage=_document_slot(M6SQLiteM4DocumentRoute.MODEL_USAGE, rowid=base + 7),
        parse_status=parse_status,
        repair_request_id=repair_request_id,
    )


def _failure_graph(
    authority: _CaseAuthority,
    *,
    claim_takeover_count: int = 0,
) -> M6SQLiteM4CallGraphPlan:
    observation = _observation(result_kind=M6LockedModelCallResultKind.FAILURE)
    return M6SQLiteM4CallGraphPlan(
        observation=observation,
        hearing_id=_sha("hearing"),
        cycle_scope_id=_sha("cycle"),
        cycle_scope_sha256=_sha("cycle body"),
        cycle_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        evidence_pack_id=authority.pack.pack_id,
        evidence_pack_version=authority.pack.version,
        retrieval_receipt_id=_sha("retrieval"),
        retrieval_commitment_sha256=_sha("retrieval body"),
        purpose="ROLE_CALL",
        call_generation=M6SQLiteM4CallGeneration.INITIAL,
        backlog_item_id=None,
        retry_generation=0,
        model_manifest_id=_sha("prosecutor model"),
        claim_status=M6SQLiteM4ClaimStatus.ACTIVE,
        claim_takeover_count=claim_takeover_count,
        request=_document_slot(
            M6SQLiteM4DocumentRoute.MODEL_REQUEST,
            rowid=201,
            artifact_id=observation.request_id,
        ),
        failure=_document_slot(M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE, rowid=202),
    )


def _support_pair(
    row_route: M6SQLiteM4SupportRoute,
    document_route: M6SQLiteM4SupportDocumentRoute,
    *,
    rowid: int,
    artifact_id: str,
    body_commitment_sha256: str,
) -> tuple[M6SQLiteM4SupportSlot, M6SQLiteM4SupportDocumentSlot]:
    index_identity = _sha(f"support index {row_route.value} {rowid}")
    return (
        M6SQLiteM4SupportSlot(
            route=row_route,
            rowid=rowid,
            identity=artifact_id,
            index_identity_sha256=index_identity,
        ),
        M6SQLiteM4SupportDocumentSlot(
            route=document_route,
            rowid=rowid,
            artifact_id=artifact_id,
            body_commitment_sha256=body_commitment_sha256,
            document_bytes=17,
            index_identity_sha256=index_identity,
        ),
    )


def _plan(
    graph: M6SQLiteM4CallGraphPlan,
    *,
    additional_graphs: tuple[M6SQLiteM4CallGraphPlan, ...] = (),
    historical_failures: tuple[M6SQLiteM4HistoricalFailureBinding, ...] = (),
    extra_support: tuple[tuple[M6SQLiteM4SupportSlot, M6SQLiteM4SupportDocumentSlot], ...] = (),
) -> M6SQLiteM4ModelDocumentsPlan:
    authority = _case_authority()
    pairs = (
        _support_pair(
            M6SQLiteM4SupportRoute.HEARING_SESSION,
            M6SQLiteM4SupportDocumentRoute.HEARING_SESSION,
            rowid=1,
            artifact_id=graph.hearing_id,
            body_commitment_sha256=_sha("hearing body"),
        ),
        _support_pair(
            M6SQLiteM4SupportRoute.HEARING_CYCLE,
            M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE,
            rowid=2,
            artifact_id=graph.cycle_scope_id,
            body_commitment_sha256=graph.cycle_scope_sha256,
        ),
        _support_pair(
            M6SQLiteM4SupportRoute.PRECEDENT_RETRIEVAL,
            M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL,
            rowid=3,
            artifact_id=graph.retrieval_receipt_id,
            body_commitment_sha256=graph.retrieval_commitment_sha256,
        ),
        *extra_support,
    )
    support = tuple(sorted((pair[0] for pair in pairs), key=lambda value: value.sort_key))
    documents = tuple(sorted((pair[1] for pair in pairs), key=lambda value: value.sort_key))
    graphs = tuple(sorted((graph, *additional_graphs), key=lambda value: value.sort_key))
    observations = tuple(value.observation for value in graphs)
    return M6SQLiteM4ModelDocumentsPlan(
        run_id=authority.case.run_id,
        case_id=authority.case.case_id,
        manifest_id=authority.case.manifest_id,
        selected_case_binding=authority.binding,
        selected_case=authority.case,
        selected_case_revision=authority.revision,
        selected_case_audit=authority.audit,
        hearing_model_bindings=(_hearing_binding(graph.hearing_id, graph.model_manifest_id),),
        selected_packs=(authority.pack,),
        observed_model_calls=observations,
        call_graphs=graphs,
        historical_failures=historical_failures,
        support_slots=support,
        support_document_slots=documents,
    )


def test_m4_contract_has_eight_canonical_routes_but_only_seven_physical_routes() -> None:
    slots = tuple(
        _document_slot(route, rowid=index + 1)
        for index, route in enumerate(M6SQLiteM4DocumentRoute)
    )

    assert len(M6SQLiteM4DocumentRoute) == 8
    assert len(_KIND_BY_ROUTE) == 7
    assert tuple(item.route for item in sorted(slots, key=lambda item: item.sort_key)) == tuple(
        M6SQLiteM4DocumentRoute
    )
    cache_request = next(
        item for item in slots if item.route == M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST
    )
    assert cache_request.physical_ref is None
    assert {item.physical_ref.kind for item in slots if item.physical_ref is not None} == set(
        _KIND_BY_ROUTE.values()
    )


def test_response_raw_size_is_independent_but_other_physical_sizes_are_canonical() -> None:
    response = _document_slot(M6SQLiteM4DocumentRoute.MODEL_RESPONSE)
    assert response.physical_ref is not None
    assert response.physical_ref.size_bytes == 79 != response.document_bytes

    request = _document_slot(M6SQLiteM4DocumentRoute.MODEL_REQUEST)
    assert request.physical_ref is not None
    with pytest.raises(ValueError, match="sizes differ"):
        replace(
            request,
            physical_ref=request.physical_ref.model_copy(
                update={"size_bytes": request.document_bytes + 1}
            ),
        )


def test_cache_request_is_never_physical_and_physical_routes_require_a_ref() -> None:
    cache_request = _document_slot(M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST)
    request_ref = _document_slot(M6SQLiteM4DocumentRoute.MODEL_REQUEST).physical_ref
    assert request_ref is not None
    with pytest.raises(ValueError, match="not a physical"):
        replace(cache_request, physical_ref=request_ref)
    with pytest.raises(TypeError, match="physical_ref"):
        replace(_document_slot(M6SQLiteM4DocumentRoute.MODEL_REQUEST), physical_ref=None)


@pytest.mark.parametrize(
    ("mutation", "replacement"),
    (
        ("source", M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL),
        ("kind", M6UpgradePhysicalArtifactKind.MODEL_RESPONSE),
        ("artifact_id", _sha("other artifact")),
        ("document_sha256", _sha("other document")),
    ),
)
def test_document_slot_rejects_crossed_physical_identity(
    mutation: str,
    replacement: object,
) -> None:
    slot = _document_slot(M6SQLiteM4DocumentRoute.MODEL_REQUEST)
    assert slot.physical_ref is not None
    updates = {mutation: replacement}
    if mutation == "document_sha256":
        updates["content_sha256"] = replacement
    crossed = slot.physical_ref.model_copy(update=updates)
    with pytest.raises((TypeError, ValueError)):
        replace(slot, physical_ref=crossed)


def test_role_manifest_binding_requires_the_exact_three_hearing_roles() -> None:
    bindings = tuple(
        M6SQLiteM4RoleModelManifestBinding(role=role, model_manifest_id=_sha(role.value))
        for role in (
            M6LockedModelRole.JUDGE,
            M6LockedModelRole.PROSECUTOR,
            M6LockedModelRole.DEFENDER,
        )
    )
    assert tuple(item.role for item in sorted(bindings, key=lambda item: item.sort_key)) == (
        M6LockedModelRole.PROSECUTOR,
        M6LockedModelRole.DEFENDER,
        M6LockedModelRole.JUDGE,
    )
    with pytest.raises(ValueError, match="role"):
        M6SQLiteM4RoleModelManifestBinding(
            role=M6LockedModelRole.SCREENING,
            model_manifest_id=_sha("screening"),
        )
    with pytest.raises(ValueError, match="SHA-256"):
        M6SQLiteM4RoleModelManifestBinding(
            role=M6LockedModelRole.JUDGE,
            model_manifest_id="not-a-hash",
        )


def test_support_rows_and_route_typed_bodies_are_non_physical_stable_commitments() -> None:
    support = M6SQLiteM4SupportSlot(
        route=M6SQLiteM4SupportRoute.HEARING_CHECKPOINT,
        rowid=4,
        identity=_sha("checkpoint"),
        index_identity_sha256=_sha("checkpoint index"),
    )
    body = M6SQLiteM4SupportDocumentSlot(
        route=M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT,
        rowid=4,
        artifact_id=_sha("checkpoint"),
        body_commitment_sha256=_sha("checkpoint body"),
        document_bytes=31,
        index_identity_sha256=_sha("checkpoint index"),
    )

    assert support.sort_key[0] >= 0
    assert body.sort_key[0] >= 0
    assert not hasattr(support, "physical_ref")
    assert not hasattr(body, "physical_ref")
    assert len(M6SQLiteM4SupportRoute) == 19
    assert len(M6SQLiteM4SupportDocumentRoute) == 12
    assert body.commitment_kind == M6SQLiteM4SupportDocumentCommitmentKind.SEMANTIC_DOCUMENT
    semantic = {
        M6SQLiteM4SupportDocumentRoute.HEARING_SESSION,
        M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE,
        M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL,
        M6SQLiteM4SupportDocumentRoute.HEARING_ROUND,
        M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT,
    }
    assert {
        route
        for route, kind in subject._SUPPORT_DOCUMENT_COMMITMENT_KIND.items()
        if kind == M6SQLiteM4SupportDocumentCommitmentKind.SEMANTIC_DOCUMENT
    } == semantic
    assert {
        route
        for route, kind in subject._SUPPORT_DOCUMENT_COMMITMENT_KIND.items()
        if kind == M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT
    } == set(M6SQLiteM4SupportDocumentRoute) - semantic


def test_historical_failure_is_explicitly_non_physical_for_both_closure_kinds() -> None:
    initial = _historical()
    retry = _historical(
        closure_kind=M6SQLiteM4FailureClosureKind.RETRY_FAILURE,
        completion_receipt_id=_sha("completion"),
        backlog_version=3,
    )

    assert initial.route == retry.route == M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE
    assert initial.sort_key < replace(retry, claim_takeover_count=2).sort_key
    assert not hasattr(initial, "physical_ref")
    assert not hasattr(retry, "physical_ref")
    with pytest.raises(ValueError, match="cannot have completion"):
        _historical(completion_receipt_id=_sha("forbidden"))
    with pytest.raises(ValueError, match="completion receipt"):
        _historical(
            closure_kind=M6SQLiteM4FailureClosureKind.RETRY_FAILURE,
            backlog_version=2,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("rowid", True),
        ("rowid", 0),
        ("document_bytes", True),
        ("document_bytes", 0),
        ("document_bytes", MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES + 1),
        ("artifact_id", "f" * 63),
        ("document_sha256", "G" * 64),
        ("index_identity_sha256", "secret-row"),
    ),
)
def test_document_commitments_reject_invalid_scalar_shapes(field: str, value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        replace(_document_slot(M6SQLiteM4DocumentRoute.MODEL_REQUEST), **{field: value})


def test_document_cap_and_budget_constants_are_exact() -> None:
    maximum = _document_slot(
        M6SQLiteM4DocumentRoute.MODEL_REQUEST,
        document_bytes=MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES,
    )
    assert maximum.document_bytes == 64 * 1024 * 1024
    assert MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP == 256
    assert MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES == 256 * 1024 * 1024
    assert MAX_M6_SQLITE_M4_MODEL_PHYSICAL_TOTAL_BYTES == 256 * 1024 * 1024


def test_plan_primitives_are_frozen_slotted_and_deep_controls_reject_subclasses() -> None:
    slot = _document_slot(M6SQLiteM4DocumentRoute.MODEL_REQUEST)
    assert is_dataclass(slot)
    assert not hasattr(slot, "__dict__")

    class _DocumentSlotSubclass(M6SQLiteM4DocumentSlot):
        pass

    spoof = _DocumentSlotSubclass(
        route=slot.route,
        rowid=slot.rowid,
        artifact_id=slot.artifact_id,
        document_sha256=slot.document_sha256,
        document_bytes=slot.document_bytes,
        index_identity_sha256=slot.index_identity_sha256,
        physical_ref=slot.physical_ref,
    )
    with pytest.raises(TypeError, match="exact"):
        subject._controlled_document_slot(spoof)
    assert subject._controlled_document_slot(slot) == slot


def test_failure_codes_and_private_failure_preserve_only_a_closed_reason() -> None:
    assert {item.value for item in M6SQLiteM4ModelDocumentFailureCode} == {
        "INVALID_ARGUMENT",
        "TRANSACTION_REQUIRED",
        "SCOPE_NOT_FOUND",
        "SCOPE_MISMATCH",
        "CASE_BINDING_MISMATCH",
        "OBSERVATION_CLOSURE_MISMATCH",
        "ROW_LIMIT_EXCEEDED",
        "DOCUMENT_TOO_LARGE",
        "DOCUMENT_INVALID",
        "INDEX_BINDING_MISMATCH",
        "PHYSICAL_PLAN_INVALID",
        "DATABASE_REJECTED",
    }
    failure = subject._M6SQLiteM4MetadataFailure(
        M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID
    )
    assert failure.reason_code == M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID
    assert str(failure) == "DOCUMENT_INVALID"


def test_complete_response_plan_closes_scope_refs_budgets_and_stable_digest() -> None:
    authority = _case_authority()
    graph = _response_graph(authority)
    first = _plan(graph)
    second = _plan(graph)

    assert first == second
    assert first.plan_identity_sha256 == second.plan_identity_sha256
    assert subject._plan_is_consistent(first)
    assert first.observed_model_calls == (graph.observation,)
    assert first.document_slots == tuple(
        sorted(graph.document_slots, key=lambda value: value.sort_key)
    )
    assert first.planned_artifact_refs == tuple(
        sorted(graph.artifact_refs, key=lambda value: value.sort_key)
    )
    assert first.planned_document_bytes == sum(
        value.document_bytes for value in (*graph.document_slots, *first.support_document_slots)
    )
    assert first.planned_physical_bytes == sum(value.size_bytes for value in graph.artifact_refs)
    assert {value.source for value in first.planned_artifact_refs} == {
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
    }


def test_empty_m4_call_plan_is_exactly_empty_but_still_bound_to_selected_case() -> None:
    authority = _case_authority()
    plan = M6SQLiteM4ModelDocumentsPlan(
        run_id=authority.case.run_id,
        case_id=authority.case.case_id,
        manifest_id=authority.case.manifest_id,
        selected_case_binding=authority.binding,
        selected_case=authority.case,
        selected_case_revision=authority.revision,
        selected_case_audit=authority.audit,
        hearing_model_bindings=(),
        selected_packs=(),
        observed_model_calls=(),
        call_graphs=(),
        historical_failures=(),
        support_slots=(),
        support_document_slots=(),
    )

    assert plan.document_slots == ()
    assert plan.planned_artifact_refs == ()
    assert plan.planned_document_bytes == plan.planned_physical_bytes == 0
    assert subject._plan_is_consistent(plan)


def test_failure_plan_contains_only_request_and_current_failure_physical_refs() -> None:
    authority = _case_authority()
    graph = _failure_graph(authority)
    plan = _plan(graph)

    assert {value.kind for value in plan.planned_artifact_refs} == {
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
    }
    assert graph.claim_status == M6SQLiteM4ClaimStatus.ACTIVE
    assert graph.response is graph.cache is graph.usage is None


def test_plan_rejects_missing_extra_or_wrong_role_model_closure() -> None:
    authority = _case_authority()
    graph = _response_graph(authority)
    valid = _plan(graph)
    wrong_observation = graph.observation.model_copy(update={"request_id": _sha("foreign")})

    with pytest.raises(ValueError, match="bidirectionally"):
        replace(valid, observed_model_calls=(wrong_observation,))
    with pytest.raises(ValueError, match="role model manifest"):
        replace(
            valid,
            hearing_model_bindings=(
                _hearing_binding(graph.hearing_id, _sha("wrong prosecutor model")),
            ),
        )
    with pytest.raises(ValueError, match="exact call-graph hearing"):
        replace(valid, hearing_model_bindings=())


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"cycle_index": 2}, "cycle counters"),
        ({"purpose": "STRUCTURE_REPAIR"}, "purpose"),
        ({"claim_status": M6SQLiteM4ClaimStatus.ACTIVE}, "response call graph"),
        ({"call_generation": M6SQLiteM4CallGeneration.BACKLOG}, "backlog call"),
        ({"retry_generation": True}, "retry generation"),
        ({"claim_takeover_count": True}, "claim epoch"),
    ),
)
def test_call_graph_rejects_scope_generation_and_terminal_drift(
    changes: dict[str, object],
    message: str,
) -> None:
    graph = _response_graph(_case_authority())
    with pytest.raises((TypeError, ValueError), match=message):
        replace(graph, **changes)


def test_primary_repair_pointer_requires_one_exact_attempt_one_successor() -> None:
    authority = _case_authority()
    repair_observation = _observation(attempt_index=1)
    primary = _response_graph(
        authority,
        parse_status=ModelParseStatus.REPAIR_REQUIRED,
        repair_request_id=repair_observation.request_id,
        ordinal=1,
    )
    repair = _response_graph(authority, attempt_index=1, ordinal=2)
    plan = _plan(primary, additional_graphs=(repair,))

    assert len(plan.call_graphs) == 2
    with pytest.raises(ValueError, match="repair pointer"):
        replace(plan, call_graphs=(primary,), observed_model_calls=(primary.observation,))


def test_sparse_older_failure_epochs_are_historical_not_physical() -> None:
    authority = _case_authority()
    graph = _response_graph(authority, claim_takeover_count=3)
    historical = replace(
        _historical(),
        request_id=graph.observation.request_id,
        claim_takeover_count=1,
        case_id=authority.case.case_id,
        hearing_id=graph.hearing_id,
        cycle_scope_id=graph.cycle_scope_id,
        cycle_scope_sha256=graph.cycle_scope_sha256,
        role=graph.observation.role,
    )
    plan = _plan(graph, historical_failures=(historical,))

    assert plan.historical_failures == (historical,)
    assert historical.document_bytes < plan.planned_document_bytes
    assert historical.authority_id not in {
        value.artifact_id for value in plan.planned_artifact_refs
    }
    with pytest.raises(ValueError, match="precede"):
        _plan(
            graph,
            historical_failures=(
                replace(historical, claim_takeover_count=graph.claim_takeover_count),
            ),
        )
    with pytest.raises(ValueError, match="precede"):
        _plan(
            graph,
            historical_failures=(replace(historical, closure_case_revision=3),),
        )


def test_retry_history_requires_exact_completion_support_body() -> None:
    authority = _case_authority()
    graph = _response_graph(authority, claim_takeover_count=2)
    completion_id = _sha("completion")
    historical = replace(
        _historical(
            closure_kind=M6SQLiteM4FailureClosureKind.RETRY_FAILURE,
            completion_receipt_id=completion_id,
            backlog_version=3,
        ),
        request_id=graph.observation.request_id,
        claim_takeover_count=1,
        case_id=authority.case.case_id,
        hearing_id=graph.hearing_id,
        cycle_scope_id=graph.cycle_scope_id,
        cycle_scope_sha256=graph.cycle_scope_sha256,
        role=graph.observation.role,
    )
    completion = _support_pair(
        M6SQLiteM4SupportRoute.BACKLOG_COMPLETION_RECEIPT,
        M6SQLiteM4SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT,
        rowid=8,
        artifact_id=completion_id,
        body_commitment_sha256=_sha("completion body"),
    )
    plan = _plan(
        graph,
        historical_failures=(historical,),
        extra_support=(completion,),
    )
    assert completion_id in {value.artifact_id for value in plan.support_document_slots}
    with pytest.raises(ValueError, match="completion support"):
        _plan(graph, historical_failures=(historical,))


def test_document_bearing_support_rows_and_bodies_are_bidirectionally_exact() -> None:
    plan = _plan(_response_graph(_case_authority()))
    with pytest.raises(ValueError, match="rows and bodies"):
        replace(plan, support_document_slots=plan.support_document_slots[:-1])
    drifted = replace(
        plan.support_document_slots[0],
        index_identity_sha256=_sha("drifted support index"),
    )
    with pytest.raises(ValueError, match="rows and bodies"):
        replace(
            plan,
            support_document_slots=tuple(
                sorted(
                    (drifted, *plan.support_document_slots[1:]),
                    key=lambda value: value.sort_key,
                )
            ),
        )


def test_plan_digest_deep_rebuild_detects_nested_and_derived_mutation() -> None:
    plan = _plan(_response_graph(_case_authority()))
    assert subject._plan_is_consistent(plan)
    object.__setattr__(plan, "planned_document_bytes", plan.planned_document_bytes + 1)
    assert not subject._plan_is_consistent(plan)


def test_hearing_model_matrix_allows_shared_model_but_requires_exact_three_roles() -> None:
    shared = _sha("shared model")
    binding = M6SQLiteM4HearingModelManifestBinding(
        hearing_id=_sha("shared hearing"),
        hearing_prompt_bundle_sha256=_sha("shared prompt"),
        role_bindings=tuple(
            M6SQLiteM4RoleModelManifestBinding(role=role, model_manifest_id=shared)
            for role in (
                M6LockedModelRole.PROSECUTOR,
                M6LockedModelRole.DEFENDER,
                M6LockedModelRole.JUDGE,
            )
        ),
    )
    assert binding.model_manifest_id_for(M6LockedModelRole.JUDGE) == shared
    with pytest.raises(ValueError, match="exactly"):
        replace(binding, role_bindings=binding.role_bindings[:-1])
