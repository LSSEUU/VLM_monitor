from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from importlib import import_module
from typing import cast

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_m3_model_plan as subject
from labcourt.contracts.audit import AuditEntry, AuditEntryDraft
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ArtifactKind, AuditAction, AuditActorRole
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedModelCall,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.storage import ArtifactRef

_MODEL_MANIFEST_ID = hashlib.sha256(b"m3-model-manifest").hexdigest()
_PHYSICAL_KIND_BY_ROUTE = {
    subject.M6SQLiteM3DocumentRoute.MODEL_REQUEST: (M6UpgradePhysicalArtifactKind.MODEL_REQUEST),
    subject.M6SQLiteM3DocumentRoute.MODEL_RESPONSE: (M6UpgradePhysicalArtifactKind.MODEL_RESPONSE),
    subject.M6SQLiteM3DocumentRoute.MODEL_CACHE_ENTRY: (M6UpgradePhysicalArtifactKind.MODEL_CACHE),
    subject.M6SQLiteM3DocumentRoute.MODEL_PARSE_RECEIPT: (
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT
    ),
    subject.M6SQLiteM3DocumentRoute.PARSED_SCREENING_OUTPUT: (
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT
    ),
    subject.M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE: (
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE
    ),
    subject.M6SQLiteM3DocumentRoute.MODEL_USAGE: (
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT
    ),
}


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_sha256(document: object) -> str:
    assert hasattr(document, "model_dump")
    payload = document.model_dump(mode="json")
    return _sha(canonical_json(payload))


@dataclass(frozen=True, slots=True)
class _CaseAuthority:
    case: Case
    revision: int
    audit: AuditEntry
    binding: M6UpgradeCandidateCaseBinding
    packs: tuple[subject.M6SQLiteM3SelectedPackBinding, ...]


def _case_with_pack_count(pack_count: int) -> Case:
    if pack_count not in {1, 2}:
        raise ValueError("test Case helper supports one or two packs")
    fixture = import_module("tests.unit.test_m6_model_call_authority")
    base = cast(Case, fixture._response_snapshot()[0])
    if pack_count == 1:
        return base
    first = base.evidence_packs[0]
    payload = first.model_dump(mode="json", exclude_computed_fields=True)
    payload["version"] = 2
    second = EvidencePack.model_validate(payload)
    case_payload = base.model_dump(mode="json", exclude_computed_fields=True)
    case_payload["evidence_packs"] = (
        first.model_dump(mode="json"),
        second.model_dump(mode="json"),
    )
    return Case.model_validate(case_payload)


def _case_authority(*, pack_count: int = 1) -> _CaseAuthority:
    case = _case_with_pack_count(pack_count)
    case_sha256 = _document_sha256(case)
    revision = pack_count + 1
    audit_sequence = pack_count + 1
    audit = AuditEntryDraft(
        run_id=case.run_id,
        sequence=audit_sequence,
        actor=AuditActorRole.SYSTEM,
        action=AuditAction.CASE_STATE_CHANGED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case.case_id),
        before_sha256=_sha("case-before-selected-revision"),
        after_sha256=case_sha256,
        manifest_id=case.manifest_id,
        recorded_at="2026-08-04T08:09:10.000011Z",
        prev_entry_hash=_sha("previous-audit-entry"),
    ).seal()
    binding = M6UpgradeCandidateCaseBinding(
        case_id=case.case_id,
        case_revision=revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=audit.sequence,
        case_audit_entry_hash=audit.entry_hash,
    )
    packs = tuple(
        subject.M6SQLiteM3SelectedPackBinding(
            rowid=index,
            pack_id=pack.pack_id,
            version=pack.version,
            document_sha256=_document_sha256(pack),
            created_audit_sequence=index,
            index_identity_sha256=_sha(f"pack-index:{index}"),
        )
        for index, pack in enumerate(case.evidence_packs, start=1)
    )
    return _CaseAuthority(
        case=case,
        revision=revision,
        audit=audit,
        binding=binding,
        packs=packs,
    )


def _slot(
    route: subject.M6SQLiteM3DocumentRoute,
    *,
    label: str,
    rowid: int,
    artifact_id: str | None = None,
    document_bytes: int = 1,
    physical_bytes: int | None = None,
) -> subject.M6SQLiteM3DocumentSlot:
    artifact_id = artifact_id or _sha(f"artifact:{label}")
    document_sha256 = _sha(f"document:{label}")
    physical_kind = _PHYSICAL_KIND_BY_ROUTE.get(route)
    physical_ref = None
    if physical_kind is not None:
        size_bytes = document_bytes if physical_bytes is None else physical_bytes
        physical_ref = M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
            kind=physical_kind,
            artifact_id=artifact_id,
            document_sha256=document_sha256,
            content_sha256=(
                _sha(f"raw-content:{label}")
                if route == subject.M6SQLiteM3DocumentRoute.MODEL_RESPONSE
                else document_sha256
            ),
            size_bytes=size_bytes,
        )
    return subject.M6SQLiteM3DocumentSlot(
        route=route,
        rowid=rowid,
        artifact_id=artifact_id,
        document_sha256=document_sha256,
        document_bytes=document_bytes,
        index_identity_sha256=_sha(f"index:{label}"),
        physical_ref=physical_ref,
    )


def _observation(
    label: str,
    *,
    attempt_index: int,
    result_kind: M6LockedModelCallResultKind,
) -> M6UpgradeObservedModelCall:
    return M6UpgradeObservedModelCall(
        request_id=_sha(f"request:{label}"),
        layer=M6LockedModelCallLayer.SCREENING,
        role=M6LockedModelRole.SCREENING,
        attempt_index=attempt_index,
        result_kind=result_kind,
        provider_invoked=True,
    )


def _response_graph(
    authority: _CaseAuthority,
    label: str,
    ordinal: int,
    *,
    attempt_index: int = 0,
    pack_version: int = 1,
    parse_status: str = "PARSED",
    repair_request_id: str | None = None,
    response_document_bytes: int = 1,
    response_physical_bytes: int | None = None,
    claim_takeover_count: int = 0,
) -> subject.M6SQLiteM3CallGraphPlan:
    observation = _observation(
        label,
        attempt_index=attempt_index,
        result_kind=M6LockedModelCallResultKind.RESPONSE,
    )
    pack = authority.packs[pack_version - 1]
    base_rowid = ordinal * 16
    parsed_output = (
        _slot(
            subject.M6SQLiteM3DocumentRoute.PARSED_SCREENING_OUTPUT,
            label=f"{label}:parsed-output",
            rowid=base_rowid + 6,
        )
        if parse_status == "PARSED"
        else None
    )
    return subject.M6SQLiteM3CallGraphPlan(
        observation=observation,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        purpose="SCREENING" if attempt_index == 0 else "STRUCTURE_REPAIR",
        model_manifest_id=_MODEL_MANIFEST_ID,
        claim_takeover_count=claim_takeover_count,
        request=_slot(
            subject.M6SQLiteM3DocumentRoute.MODEL_REQUEST,
            label=f"{label}:request",
            rowid=base_rowid + 1,
            artifact_id=observation.request_id,
        ),
        response=_slot(
            subject.M6SQLiteM3DocumentRoute.MODEL_RESPONSE,
            label=f"{label}:response",
            rowid=base_rowid + 2,
            document_bytes=response_document_bytes,
            physical_bytes=response_physical_bytes,
        ),
        cache_request=_slot(
            subject.M6SQLiteM3DocumentRoute.MODEL_CACHE_REQUEST,
            label=f"{label}:cache-request",
            rowid=base_rowid + 3,
        ),
        cache=_slot(
            subject.M6SQLiteM3DocumentRoute.MODEL_CACHE_ENTRY,
            label=f"{label}:cache",
            rowid=base_rowid + 4,
        ),
        parse_receipt=_slot(
            subject.M6SQLiteM3DocumentRoute.MODEL_PARSE_RECEIPT,
            label=f"{label}:parse-receipt",
            rowid=base_rowid + 5,
        ),
        parsed_output=parsed_output,
        usage=_slot(
            subject.M6SQLiteM3DocumentRoute.MODEL_USAGE,
            label=f"{label}:usage",
            rowid=base_rowid + 7,
        ),
        parse_status=parse_status,
        repair_request_id=repair_request_id,
    )


def _failure_graph(
    authority: _CaseAuthority,
    label: str,
    ordinal: int,
    *,
    attempt_index: int = 0,
    pack_version: int = 1,
    request_rowid: int | None = None,
    failure_rowid: int | None = None,
    failure_artifact_id: str | None = None,
    claim_takeover_count: int = 0,
) -> subject.M6SQLiteM3CallGraphPlan:
    observation = _observation(
        label,
        attempt_index=attempt_index,
        result_kind=M6LockedModelCallResultKind.FAILURE,
    )
    pack = authority.packs[pack_version - 1]
    base_rowid = ordinal * 16
    return subject.M6SQLiteM3CallGraphPlan(
        observation=observation,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        purpose="SCREENING" if attempt_index == 0 else "STRUCTURE_REPAIR",
        model_manifest_id=_MODEL_MANIFEST_ID,
        claim_takeover_count=claim_takeover_count,
        request=_slot(
            subject.M6SQLiteM3DocumentRoute.MODEL_REQUEST,
            label=f"{label}:request",
            rowid=request_rowid or base_rowid + 1,
            artifact_id=observation.request_id,
        ),
        failure=_slot(
            subject.M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE,
            label=f"{label}:failure",
            rowid=failure_rowid or base_rowid + 2,
            artifact_id=failure_artifact_id,
        ),
    )


def _support(
    route: subject.M6SQLiteM3SupportRoute,
    index: int,
    *,
    rowid: int | None = None,
    identity: str | None = None,
) -> subject.M6SQLiteM3SupportSlot:
    identity = identity or f"support-{index:04d}"
    return subject.M6SQLiteM3SupportSlot(
        route=route,
        rowid=rowid or index + 1,
        identity=identity,
        index_identity_sha256=_sha(f"support-index:{route}:{index}"),
    )


def _support_document(
    index: int,
    *,
    rowid: int | None = None,
    artifact_id: str | None = None,
    document_bytes: int = 1,
    index_identity_sha256: str | None = None,
) -> subject.M6SQLiteM3SupportDocumentSlot:
    return subject.M6SQLiteM3SupportDocumentSlot(
        route=subject.M6SQLiteM3SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT,
        rowid=rowid or index + 1,
        artifact_id=artifact_id or _sha(f"completion-receipt:{index}"),
        document_sha256=_sha(f"completion-receipt-document:{index}"),
        document_bytes=document_bytes,
        index_identity_sha256=(index_identity_sha256 or _sha(f"completion-receipt-index:{index}")),
    )


def _receipt_support_pair(
    index: int,
    *,
    rowid: int | None = None,
    document_bytes: int = 1,
) -> tuple[subject.M6SQLiteM3SupportSlot, subject.M6SQLiteM3SupportDocumentSlot]:
    document = _support_document(
        index,
        rowid=rowid,
        document_bytes=document_bytes,
    )
    support = _support(
        subject.M6SQLiteM3SupportRoute.BACKLOG_COMPLETION_RECEIPT,
        index,
        rowid=document.rowid,
        identity=document.artifact_id,
    )
    return support, document


def _historical_failure(
    graph: subject.M6SQLiteM3CallGraphPlan,
    claim_takeover_count: int,
    *,
    rowid: int | None = None,
    authority_id: str | None = None,
    document_bytes: int = 1,
    index_identity_sha256: str | None = None,
) -> subject.M6SQLiteM3HistoricalFailureBinding:
    return subject.M6SQLiteM3HistoricalFailureBinding(
        request_id=graph.observation.request_id,
        claim_takeover_count=claim_takeover_count,
        authority_id=(
            authority_id
            or _sha(f"historical-authority:{graph.observation.request_id}:{claim_takeover_count}")
        ),
        backlog_item_id=_sha(f"historical-backlog:{graph.observation.request_id}"),
        backlog_version=claim_takeover_count + 1,
        closure_kind=("INITIAL_BACKLOG" if claim_takeover_count == 0 else "RETRY_FAILURE"),
        closure_case_revision=claim_takeover_count + 1,
        rowid=rowid or 10_000 + claim_takeover_count,
        document_sha256=_sha(
            f"historical-document:{graph.observation.request_id}:{claim_takeover_count}"
        ),
        document_bytes=document_bytes,
        index_identity_sha256=(
            index_identity_sha256
            or _sha(f"historical-index:{graph.observation.request_id}:{claim_takeover_count}")
        ),
    )


def _plan(
    authority: _CaseAuthority,
    graphs: tuple[subject.M6SQLiteM3CallGraphPlan, ...] = (),
    *,
    selected_packs: tuple[subject.M6SQLiteM3SelectedPackBinding, ...] | None = None,
    support_slots: tuple[subject.M6SQLiteM3SupportSlot, ...] = (),
    support_document_slots: tuple[subject.M6SQLiteM3SupportDocumentSlot, ...] = (),
    historical_failures: tuple[subject.M6SQLiteM3HistoricalFailureBinding, ...] = (),
) -> subject.M6SQLiteM3ModelDocumentsPlan:
    graphs = tuple(sorted(graphs, key=lambda item: item.sort_key))
    if selected_packs is None:
        graph_pack_keys = {
            (graph.evidence_pack_id, graph.evidence_pack_version) for graph in graphs
        }
        selected_packs = tuple(
            pack for pack in authority.packs if (pack.pack_id, pack.version) in graph_pack_keys
        )
    return subject.M6SQLiteM3ModelDocumentsPlan(
        run_id=authority.case.run_id,
        case_id=authority.case.case_id,
        manifest_id=authority.case.manifest_id,
        model_manifest_id=_MODEL_MANIFEST_ID,
        selected_case_binding=authority.binding,
        selected_case=authority.case,
        selected_case_revision=authority.revision,
        selected_case_audit=authority.audit,
        selected_packs=selected_packs,
        observed_model_calls=tuple(graph.observation for graph in graphs),
        call_graphs=graphs,
        historical_failures=tuple(sorted(historical_failures, key=lambda item: item.sort_key)),
        support_slots=tuple(sorted(support_slots, key=lambda item: item.sort_key)),
        support_document_slots=tuple(
            sorted(support_document_slots, key=lambda item: item.sort_key)
        ),
    )


def _rebuild(plan: subject.M6SQLiteM3ModelDocumentsPlan) -> None:
    subject.M6SQLiteM3ModelDocumentsPlan(
        run_id=plan.run_id,
        case_id=plan.case_id,
        manifest_id=plan.manifest_id,
        model_manifest_id=plan.model_manifest_id,
        selected_case_binding=plan.selected_case_binding,
        selected_case=plan.selected_case,
        selected_case_revision=plan.selected_case_revision,
        selected_case_audit=plan.selected_case_audit,
        selected_packs=plan.selected_packs,
        observed_model_calls=plan.observed_model_calls,
        call_graphs=plan.call_graphs,
        historical_failures=plan.historical_failures,
        support_slots=plan.support_slots,
        support_document_slots=plan.support_document_slots,
    )


def test_plan_accepts_response_and_failure_graphs() -> None:
    authority = _case_authority()
    response = _response_graph(
        authority,
        "valid-response",
        1,
        response_document_bytes=3,
        response_physical_bytes=11,
    )
    failure = _failure_graph(authority, "valid-failure", 2)

    plan = _plan(authority, (response, failure))

    assert len(plan.document_slots) == 9
    assert len(plan.planned_artifact_refs) == 8
    assert plan.planned_document_bytes == 11
    assert plan.planned_physical_bytes == 18
    assert subject._plan_is_consistent(plan)


def test_plan_accepts_multiple_independent_primary_repair_groups() -> None:
    authority = _case_authority(pack_count=2)
    first_repair = _response_graph(
        authority,
        "repair-one",
        3,
        attempt_index=1,
        pack_version=1,
    )
    second_repair = _response_graph(
        authority,
        "repair-two",
        4,
        attempt_index=1,
        pack_version=2,
        parse_status="INVALID_FINAL",
    )
    first_primary = _response_graph(
        authority,
        "primary-one",
        1,
        pack_version=1,
        parse_status="REPAIR_REQUIRED",
        repair_request_id=first_repair.observation.request_id,
    )
    second_primary = _response_graph(
        authority,
        "primary-two",
        2,
        pack_version=2,
        parse_status="REPAIR_REQUIRED",
        repair_request_id=second_repair.observation.request_id,
    )

    plan = _plan(
        authority,
        (second_repair, first_primary, first_repair, second_primary),
    )

    assert plan.selected_packs == authority.packs
    assert tuple(item.attempt_index for item in plan.observed_model_calls) == (0, 0, 1, 1)
    assert subject._plan_is_consistent(plan)


@pytest.mark.parametrize("target", ["slot", "ref", "case", "binding", "audit"])
def test_nested_object_setattr_tampering_is_rejected_by_rebuild_and_consistency(
    target: str,
) -> None:
    authority = _case_authority()
    plan = _plan(authority, (_response_graph(authority, f"tamper-{target}", 1),))

    if target == "slot":
        object.__setattr__(plan.call_graphs[0].request, "document_bytes", -1)
    elif target == "ref":
        response_ref = plan.call_graphs[0].response
        assert response_ref is not None and response_ref.physical_ref is not None
        object.__setattr__(
            response_ref.physical_ref,
            "size_bytes",
            subject.MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES + 1,
        )
    elif target == "case":
        object.__setattr__(plan.selected_case, "manifest_id", _sha("foreign-manifest"))
    elif target == "binding":
        object.__setattr__(
            plan.selected_case_binding,
            "case_document_sha256",
            _sha("foreign-case-document"),
        )
    else:
        object.__setattr__(
            plan.selected_case_audit,
            "after_sha256",
            _sha("foreign-audit-after"),
        )

    with pytest.raises((TypeError, ValueError)):
        _rebuild(plan)
    assert not subject._plan_is_consistent(plan)


def test_plan_level_object_setattr_tampering_breaks_consistency() -> None:
    authority = _case_authority()
    plan = _plan(authority, (_failure_graph(authority, "plan-tamper", 1),))

    object.__setattr__(plan, "planned_document_bytes", plan.planned_document_bytes + 1)

    assert not subject._plan_is_consistent(plan)


@pytest.mark.parametrize(
    ("field_name", "tampered_value"),
    [
        ("request_id", "not-a-sha256"),
        ("claim_takeover_count", -1),
        ("authority_id", "not-a-sha256"),
        ("backlog_item_id", "not-a-sha256"),
        ("rowid", 0),
        ("document_sha256", "not-a-sha256"),
        ("document_bytes", -1),
        ("index_identity_sha256", "not-a-sha256"),
    ],
)
def test_historical_failure_deep_tamper_breaks_rebuild_and_consistency(
    field_name: str,
    tampered_value: int | str,
) -> None:
    authority = _case_authority()
    graph = _response_graph(
        authority,
        "historical-deep-tamper",
        1,
        claim_takeover_count=1,
    )
    history = _historical_failure(graph, 0)
    plan = _plan(authority, (graph,), historical_failures=(history,))

    object.__setattr__(plan.historical_failures[0], field_name, tampered_value)

    with pytest.raises((TypeError, ValueError)):
        _rebuild(plan)
    assert not subject._plan_is_consistent(plan)


def test_historical_failure_counts_toward_canonical_budget_and_digest_only() -> None:
    authority = _case_authority()
    graph = _response_graph(
        authority,
        "historical-canonical-only",
        1,
        claim_takeover_count=1,
    )
    baseline = _plan(authority, (graph,))
    history = _historical_failure(graph, 0, document_bytes=23)

    with_history = _plan(
        authority,
        (graph,),
        historical_failures=(history,),
    )

    assert with_history.planned_document_bytes == baseline.planned_document_bytes + 23
    assert with_history.planned_artifact_refs == baseline.planned_artifact_refs
    assert with_history.planned_physical_bytes == baseline.planned_physical_bytes
    assert with_history.plan_identity_sha256 != baseline.plan_identity_sha256
    assert with_history.historical_failures[0].route == (
        subject.M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE
    )
    assert not hasattr(with_history.historical_failures[0], "physical_ref")


def test_historical_failure_documents_enforce_the_total_canonical_budget() -> None:
    authority = _case_authority()
    graph = _response_graph(
        authority,
        "historical-total-budget",
        1,
        claim_takeover_count=4,
    )
    graph_bytes = sum(slot.document_bytes for slot in graph.document_slots)
    per_document = subject.MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES
    histories = tuple(
        _historical_failure(
            graph,
            epoch,
            document_bytes=(per_document if epoch < 3 else per_document - graph_bytes),
        )
        for epoch in range(4)
    )

    boundary = _plan(authority, (graph,), historical_failures=histories)

    assert boundary.planned_document_bytes == (subject.MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES)
    with pytest.raises(ValueError):
        _plan(
            authority,
            (graph,),
            historical_failures=(
                *histories[:-1],
                replace(
                    histories[-1],
                    document_bytes=histories[-1].document_bytes + 1,
                ),
            ),
        )


@pytest.mark.parametrize(
    "duplicate",
    ["rowid", "authority", "epoch", "terminal_rowid", "terminal_authority"],
)
def test_plan_rejects_duplicate_historical_failure_identity(duplicate: str) -> None:
    authority = _case_authority()
    graph = _failure_graph(
        authority,
        "historical-duplicate",
        1,
        claim_takeover_count=2,
    )
    first = _historical_failure(graph, 0, rowid=81)
    second = _historical_failure(graph, 1, rowid=82)
    assert graph.failure is not None
    if duplicate == "rowid":
        second = replace(second, rowid=first.rowid)
    elif duplicate == "authority":
        second = replace(second, authority_id=first.authority_id)
    elif duplicate == "epoch":
        second = replace(second, claim_takeover_count=first.claim_takeover_count)
    elif duplicate == "terminal_rowid":
        second = replace(second, rowid=graph.failure.rowid)
    else:
        second = replace(second, authority_id=graph.failure.artifact_id)

    with pytest.raises(ValueError):
        _plan(
            authority,
            (graph,),
            historical_failures=(first, second),
        )


def test_historical_failure_route_accepts_256_and_rejects_257_documents() -> None:
    authority = _case_authority()
    graph = _failure_graph(
        authority,
        "historical-route-limit",
        1,
        claim_takeover_count=256,
    )
    histories = tuple(_historical_failure(graph, epoch) for epoch in range(256))

    boundary = _plan(
        authority,
        (graph,),
        historical_failures=histories[:-1],
    )

    assert len(boundary.historical_failures) == 255
    assert (
        len(boundary.historical_failures)
        + sum(
            slot.route == subject.M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE
            for slot in boundary.document_slots
        )
        == subject.MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
    )
    with pytest.raises(ValueError):
        _plan(authority, (graph,), historical_failures=histories)


def test_multiple_historical_failures_are_canonically_ordered() -> None:
    authority = _case_authority()
    graph = _response_graph(
        authority,
        "historical-order",
        1,
        claim_takeover_count=3,
    )
    histories = tuple(_historical_failure(graph, epoch) for epoch in range(3))

    plan = _plan(
        authority,
        (graph,),
        historical_failures=tuple(reversed(histories)),
    )

    assert tuple(value.claim_takeover_count for value in plan.historical_failures) == (0, 1, 2)
    with pytest.raises(ValueError):
        replace(plan, historical_failures=tuple(reversed(plan.historical_failures)))


@pytest.mark.parametrize("relationship", ["orphan", "same_epoch", "future_epoch"])
def test_historical_failure_must_bind_an_older_terminal_claim_epoch(
    relationship: str,
) -> None:
    authority = _case_authority()
    graph = _response_graph(
        authority,
        "historical-epoch-closure",
        1,
        claim_takeover_count=1,
    )
    history = _historical_failure(graph, 0)
    if relationship == "orphan":
        history = replace(history, request_id=_sha("orphan-historical-request"))
    elif relationship == "same_epoch":
        history = replace(history, claim_takeover_count=1)
    else:
        history = replace(history, claim_takeover_count=2)

    with pytest.raises(ValueError):
        _plan(authority, (graph,), historical_failures=(history,))


def test_plan_accepts_256_calls_and_rejects_257_calls_or_route_rows() -> None:
    authority = _case_authority()
    graphs = tuple(
        _failure_graph(authority, f"bounded-call-{index:03d}", index + 1)
        for index in range(subject.MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP + 1)
    )

    boundary = _plan(authority, graphs[:-1])

    assert len(boundary.call_graphs) == subject.MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
    assert (
        sum(
            slot.route == subject.M6SQLiteM3DocumentRoute.MODEL_REQUEST
            for slot in boundary.document_slots
        )
        == subject.MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
    )
    with pytest.raises(ValueError):
        _plan(authority, graphs)


def test_support_limit_is_per_route_and_rejects_the_257th_row() -> None:
    limit = subject.MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
    authority = _case_authority()
    run_slots = tuple(
        _support(subject.M6SQLiteM3SupportRoute.RUN, index) for index in range(limit + 1)
    )
    case_slots = tuple(
        _support(subject.M6SQLiteM3SupportRoute.CASE_VERSION, index + limit + 1)
        for index in range(limit)
    )

    boundary = _plan(authority, support_slots=run_slots[:-1] + case_slots)

    assert len(boundary.support_slots) == limit * 2
    with pytest.raises(ValueError):
        _plan(authority, support_slots=run_slots + case_slots)


def test_completion_receipt_support_document_accepts_256_and_rejects_257() -> None:
    limit = subject.MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
    authority = _case_authority()
    pairs = tuple(_receipt_support_pair(index) for index in range(limit + 1))
    support_slots = tuple(pair[0] for pair in pairs)
    document_slots = tuple(pair[1] for pair in pairs)

    boundary = _plan(
        authority,
        support_slots=support_slots[:-1],
        support_document_slots=document_slots[:-1],
    )

    assert len(boundary.support_document_slots) == limit
    with pytest.raises(ValueError):
        _plan(
            authority,
            support_slots=support_slots[:-1],
            support_document_slots=document_slots,
        )


@pytest.mark.parametrize("duplicate", ["rowid", "artifact_id", "index_identity"])
def test_plan_rejects_duplicate_completion_receipt_document_commitment(
    duplicate: str,
) -> None:
    authority = _case_authority()
    first_support, first_document = _receipt_support_pair(1, rowid=51)
    second_support, second_document = _receipt_support_pair(2, rowid=52)
    if duplicate == "rowid":
        second_document = replace(second_document, rowid=first_document.rowid)
    elif duplicate == "artifact_id":
        second_document = replace(
            second_document,
            artifact_id=first_document.artifact_id,
        )
    else:
        second_document = replace(
            second_document,
            index_identity_sha256=first_document.index_identity_sha256,
        )

    with pytest.raises(ValueError):
        _plan(
            authority,
            support_slots=(first_support, second_support),
            support_document_slots=(first_document, second_document),
        )


@pytest.mark.parametrize("closure", ["missing_document", "extra_document", "mismatch"])
def test_completion_receipt_support_and_document_commitments_close_exactly(
    closure: str,
) -> None:
    authority = _case_authority()
    support, document = _receipt_support_pair(1, rowid=61)
    support_slots = () if closure == "extra_document" else (support,)
    document_slots = () if closure == "missing_document" else (document,)
    if closure == "mismatch":
        document_slots = (replace(document, artifact_id=_sha("foreign-receipt")),)

    with pytest.raises(ValueError):
        _plan(
            authority,
            support_slots=support_slots,
            support_document_slots=document_slots,
        )


@pytest.mark.parametrize(
    ("field_name", "tampered_value"),
    [
        ("rowid", 0),
        ("artifact_id", "not-a-sha256"),
        ("document_sha256", "not-a-sha256"),
        ("document_bytes", -1),
        ("index_identity_sha256", "not-a-sha256"),
    ],
)
def test_completion_receipt_document_deep_tamper_breaks_rebuild_and_consistency(
    field_name: str,
    tampered_value: int | str,
) -> None:
    authority = _case_authority()
    support, document = _receipt_support_pair(1)
    plan = _plan(
        authority,
        support_slots=(support,),
        support_document_slots=(document,),
    )

    object.__setattr__(plan.support_document_slots[0], field_name, tampered_value)

    with pytest.raises((TypeError, ValueError)):
        _rebuild(plan)
    assert not subject._plan_is_consistent(plan)


def test_plan_rejects_duplicate_document_route_rowid() -> None:
    authority = _case_authority()
    first = _failure_graph(authority, "rowid-one", 1, request_rowid=91)
    second = _failure_graph(authority, "rowid-two", 2, request_rowid=91)

    with pytest.raises(ValueError):
        _plan(authority, (first, second))


def test_plan_rejects_duplicate_document_route_artifact_identity() -> None:
    authority = _case_authority()
    shared_artifact_id = _sha("shared-failure-artifact")
    first = _failure_graph(
        authority,
        "artifact-one",
        1,
        failure_artifact_id=shared_artifact_id,
    )
    second = _failure_graph(
        authority,
        "artifact-two",
        2,
        failure_artifact_id=shared_artifact_id,
    )

    with pytest.raises(ValueError):
        _plan(authority, (first, second))


@pytest.mark.parametrize("duplicate", ["rowid", "identity"])
def test_plan_rejects_duplicate_support_route_commitment(duplicate: str) -> None:
    authority = _case_authority()
    first = _support(subject.M6SQLiteM3SupportRoute.RUN, 1, rowid=41, identity="run-one")
    second = _support(
        subject.M6SQLiteM3SupportRoute.RUN,
        2,
        rowid=41 if duplicate == "rowid" else 42,
        identity="run-one" if duplicate == "identity" else "run-two",
    )

    with pytest.raises(ValueError):
        _plan(authority, support_slots=(first, second))


def test_plan_rejects_duplicate_selected_pack_key() -> None:
    authority = _case_authority()
    graph = _failure_graph(authority, "duplicate-pack-key", 1)

    with pytest.raises(ValueError):
        _plan(
            authority,
            (graph,),
            selected_packs=(authority.packs[0], authority.packs[0]),
        )


def test_plan_rejects_duplicate_selected_pack_rowid() -> None:
    authority = _case_authority(pack_count=2)
    first_graph = _failure_graph(authority, "pack-rowid-one", 1, pack_version=1)
    second_graph = _failure_graph(authority, "pack-rowid-two", 2, pack_version=2)
    second_pack = replace(authority.packs[1], rowid=authority.packs[0].rowid)

    with pytest.raises(ValueError):
        _plan(
            authority,
            (first_graph, second_graph),
            selected_packs=(authority.packs[0], second_pack),
        )


def test_plan_rejects_duplicate_selected_pack_index_identity() -> None:
    authority = _case_authority(pack_count=2)
    first_graph = _failure_graph(authority, "pack-index-one", 1, pack_version=1)
    second_graph = _failure_graph(authority, "pack-index-two", 2, pack_version=2)
    second_pack = replace(
        authority.packs[1],
        index_identity_sha256=authority.packs[0].index_identity_sha256,
    )

    with pytest.raises(ValueError):
        _plan(
            authority,
            (first_graph, second_graph),
            selected_packs=(authority.packs[0], second_pack),
        )


def test_plan_rejects_call_graph_pack_absent_from_selected_subset() -> None:
    authority = _case_authority()
    graph = _failure_graph(authority, "foreign-graph-pack", 1)
    foreign_graph = replace(graph, evidence_pack_version=2)

    with pytest.raises(ValueError):
        _plan(
            authority,
            (foreign_graph,),
            selected_packs=authority.packs,
        )


def test_plan_rejects_selected_pack_not_referenced_by_any_call_graph() -> None:
    authority = _case_authority(pack_count=2)
    graph = _failure_graph(authority, "unreferenced-pack", 1, pack_version=1)

    with pytest.raises(ValueError):
        _plan(authority, (graph,), selected_packs=authority.packs)


def test_plan_rejects_primary_repair_pointer_without_target() -> None:
    authority = _case_authority()
    primary = _response_graph(
        authority,
        "missing-repair-target",
        1,
        parse_status="REPAIR_REQUIRED",
        repair_request_id=_sha("missing-request"),
    )

    with pytest.raises(ValueError):
        _plan(authority, (primary,))


def test_plan_rejects_primary_repair_pointer_to_attempt_zero() -> None:
    authority = _case_authority()
    target = _response_graph(authority, "attempt-zero-target", 2)
    primary = _response_graph(
        authority,
        "attempt-zero-source",
        1,
        parse_status="REPAIR_REQUIRED",
        repair_request_id=target.observation.request_id,
    )

    with pytest.raises(ValueError):
        _plan(authority, (primary, target))


def test_plan_accepts_failure_as_the_unique_attempt_one_repair_closure() -> None:
    authority = _case_authority()
    target = _failure_graph(
        authority,
        "failure-repair-target",
        2,
        attempt_index=1,
    )
    primary = _response_graph(
        authority,
        "failure-repair-source",
        1,
        parse_status="REPAIR_REQUIRED",
        repair_request_id=target.observation.request_id,
    )

    plan = _plan(authority, (primary, target))

    assert plan.call_graphs[1].observation.result_kind == M6LockedModelCallResultKind.FAILURE
    assert subject._plan_is_consistent(plan)


def test_failure_call_cannot_claim_a_repair_pointer() -> None:
    authority = _case_authority()
    failure = _failure_graph(authority, "failure-with-repair", 1)

    with pytest.raises(ValueError):
        replace(failure, repair_request_id=_sha("forbidden-repair"))


def test_attempt_one_response_cannot_request_a_third_attempt() -> None:
    authority = _case_authority()

    with pytest.raises(ValueError):
        _response_graph(
            authority,
            "third-attempt-request",
            1,
            attempt_index=1,
            parse_status="REPAIR_REQUIRED",
            repair_request_id=_sha("forbidden-third-attempt"),
        )


def test_plan_rejects_repair_target_from_another_pack() -> None:
    authority = _case_authority(pack_count=2)
    target = _response_graph(
        authority,
        "foreign-pack-target",
        2,
        attempt_index=1,
        pack_version=2,
    )
    primary = _response_graph(
        authority,
        "foreign-pack-source",
        1,
        pack_version=1,
        parse_status="REPAIR_REQUIRED",
        repair_request_id=target.observation.request_id,
    )

    with pytest.raises(ValueError):
        _plan(authority, (primary, target))


def test_plan_rejects_repair_with_two_primary_predecessors() -> None:
    authority = _case_authority()
    target = _response_graph(authority, "shared-repair-target", 3, attempt_index=1)
    first = _response_graph(
        authority,
        "shared-repair-source-one",
        1,
        parse_status="REPAIR_REQUIRED",
        repair_request_id=target.observation.request_id,
    )
    second = _response_graph(
        authority,
        "shared-repair-source-two",
        2,
        parse_status="REPAIR_REQUIRED",
        repair_request_id=target.observation.request_id,
    )

    with pytest.raises(ValueError):
        _plan(authority, (first, second, target))


def test_plan_rejects_orphan_attempt_one() -> None:
    authority = _case_authority()
    orphan = _response_graph(authority, "orphan-repair", 1, attempt_index=1)

    with pytest.raises(ValueError):
        _plan(authority, (orphan,))


def test_model_response_document_accepts_exact_per_document_budget() -> None:
    route = subject.M6SQLiteM3DocumentRoute.MODEL_RESPONSE

    slot = _slot(
        route,
        label="response-document-boundary",
        rowid=1,
        document_bytes=subject.MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES,
        physical_bytes=1,
    )

    assert slot.document_bytes == subject.MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES
    assert slot.physical_ref is not None and slot.physical_ref.size_bytes == 1
    with pytest.raises(ValueError):
        _slot(
            route,
            label="response-document-overflow",
            rowid=2,
            document_bytes=subject.MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES + 1,
            physical_bytes=1,
        )


def test_plan_enforces_total_document_budget_using_response_json_lengths() -> None:
    authority = _case_authority()
    per_document = subject.MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES
    graphs = tuple(
        _response_graph(
            authority,
            f"document-total-{index}",
            index + 1,
            response_document_bytes=(per_document if index < 3 else per_document - 24),
            response_physical_bytes=1,
        )
        for index in range(4)
    )

    boundary = _plan(authority, graphs)

    assert boundary.planned_document_bytes == (subject.MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES)
    overflowing_last = _response_graph(
        authority,
        "document-total-3",
        4,
        response_document_bytes=per_document - 23,
        response_physical_bytes=1,
    )
    with pytest.raises(ValueError):
        _plan(authority, (*graphs[:-1], overflowing_last))


def test_completion_receipt_documents_count_toward_the_canonical_total_budget() -> None:
    authority = _case_authority()
    per_document = subject.MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES
    pairs = tuple(_receipt_support_pair(index, document_bytes=per_document) for index in range(4))

    boundary = _plan(
        authority,
        support_slots=tuple(pair[0] for pair in pairs),
        support_document_slots=tuple(pair[1] for pair in pairs),
    )

    assert boundary.planned_document_bytes == (subject.MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES)
    extra_support, extra_document = _receipt_support_pair(4, document_bytes=1)
    with pytest.raises(ValueError):
        _plan(
            authority,
            support_slots=(*tuple(pair[0] for pair in pairs), extra_support),
            support_document_slots=(
                *tuple(pair[1] for pair in pairs),
                extra_document,
            ),
        )


def test_completion_receipt_document_never_creates_a_physical_artifact_ref() -> None:
    authority = _case_authority()
    graph = _response_graph(authority, "receipt-has-no-physical-ref", 1)
    baseline = _plan(authority, (graph,))
    support, document = _receipt_support_pair(1, document_bytes=17)

    with_receipt = _plan(
        authority,
        (graph,),
        support_slots=(support,),
        support_document_slots=(document,),
    )

    assert with_receipt.planned_document_bytes == baseline.planned_document_bytes + 17
    assert with_receipt.planned_artifact_refs == baseline.planned_artifact_refs
    assert with_receipt.planned_physical_bytes == baseline.planned_physical_bytes
    assert not hasattr(with_receipt.support_document_slots[0], "physical_ref")


def test_plan_enforces_raw_response_physical_budget_independently() -> None:
    authority = _case_authority()
    raw_boundary = subject.MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES - 5
    graph = _response_graph(
        authority,
        "raw-response-budget",
        1,
        response_document_bytes=1,
        response_physical_bytes=raw_boundary,
    )

    boundary = _plan(authority, (graph,))

    assert boundary.planned_document_bytes == 7
    assert boundary.planned_physical_bytes == (subject.MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES)
    overflowing = _response_graph(
        authority,
        "raw-response-overflow",
        1,
        response_document_bytes=1,
        response_physical_bytes=raw_boundary + 1,
    )
    with pytest.raises(ValueError):
        _plan(authority, (overflowing,))
