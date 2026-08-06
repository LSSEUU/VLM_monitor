"""Pure contract tests for the M6 acquisition metadata-only plan."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, is_dataclass, replace

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_plan as subject
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_plan import (
    MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES,
    MAX_M6_SQLITE_ACQUISITION_DOCUMENT_TOTAL_BYTES,
    MAX_M6_SQLITE_ACQUISITION_ITEMS,
    MAX_M6_SQLITE_ACQUISITION_PHYSICAL_TOTAL_BYTES,
    MAX_M6_SQLITE_ACQUISITION_SELECTED_PACKS,
    MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS,
    MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE,
    MAX_M6_SQLITE_ACQUISITION_SUPPORT_TOTAL_BYTES,
    M6SQLiteAcquisitionClaimState,
    M6SQLiteAcquisitionClosurePlan,
    M6SQLiteAcquisitionCompletedClaimSlot,
    M6SQLiteAcquisitionDocumentCommitmentKind,
    M6SQLiteAcquisitionDocumentsPlan,
    M6SQLiteAcquisitionManifestSlot,
    M6SQLiteAcquisitionPackTransitionBinding,
    M6SQLiteAcquisitionPhysicalRoute,
    M6SQLiteAcquisitionPlanFailureCode,
    M6SQLiteAcquisitionSelectedPackBinding,
    M6SQLiteAcquisitionSupportDocumentRoute,
    M6SQLiteAcquisitionSupportDocumentSlot,
    M6SQLiteAcquisitionSupportRoute,
    M6SQLiteAcquisitionSupportSlot,
    M6SQLiteAcquisitionToolResultBinding,
    M6SQLiteAcquisitionUpstreamM4Binding,
)
from labcourt.contracts.audit import AuditEntry, AuditEntryDraft
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
)
from labcourt.contracts.evidence import EvidencePack, ToolResult
from labcourt.contracts.m6_replay_locked import MAX_M6_LOCKED_TOOL_RESULTS_PER_CASE
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.storage import ArtifactRef
from tests.unit.test_m4_evidence_authority import _execution, _finalize
from tests.unit.test_m6_acquisition_projection import _base_pack

_UPSTREAM_PLAN_ID = "e" * 64
_HEARING_ID = "f" * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_identity(document: object) -> tuple[str, int]:
    assert hasattr(document, "model_dump")
    canonical = canonical_json(document.model_dump(mode="json"))
    encoded = canonical.encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


@dataclass(frozen=True, slots=True)
class _SelectedAuthority:
    case: Case
    revision: int
    audit: AuditEntry
    binding: M6UpgradeCandidateCaseBinding


def _selected_authority(case: Case) -> _SelectedAuthority:
    case_sha256, _case_bytes = _document_identity(case)
    revision = len(case.evidence_packs) + 4
    audit = AuditEntryDraft(
        run_id=case.run_id,
        sequence=revision,
        actor=AuditActorRole.SYSTEM,
        action=AuditAction.CASE_STATE_CHANGED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case.case_id),
        before_sha256=_sha("selected Case predecessor"),
        after_sha256=case_sha256,
        manifest_id=case.manifest_id,
        recorded_at="2026-08-04T12:13:14.000015Z",
        prev_entry_hash=_sha("selected Case previous audit"),
    ).seal()
    return _SelectedAuthority(
        case=case,
        revision=revision,
        audit=audit,
        binding=M6UpgradeCandidateCaseBinding(
            case_id=case.case_id,
            case_revision=revision,
            case_document_sha256=case_sha256,
            case_audit_sequence=audit.sequence,
            case_audit_entry_hash=audit.entry_hash,
        ),
    )


def _case_with_one_acquisition() -> Case:
    first = _base_pack("run-acquisition-plan")
    execution = _execution(first, AcquisitionAction.TRACK_CONFIDENCE_CURVE)
    update = _finalize(first, execution)
    return Case(
        run_id=first.run_id,
        status=CaseStatus.EVIDENCE_READY,
        event=first.event,
        evidence_packs=(first, update.pack),
        manifest_id=first.manifest_id,
    )


def _case_with_two_acquisitions() -> Case:
    first = _base_pack("run-acquisition-plan-two")
    first_execution = _execution(first, AcquisitionAction.TRACK_CONFIDENCE_CURVE)
    first_update = _finalize(first, first_execution)
    second_execution = _execution(
        first_update.pack,
        AcquisitionAction.REQUEST_MORE_FRAMES,
        receipts=(first_update.receipt,),
        prior_acquisitions=1,
    )
    second_update = _finalize(
        first_update.pack,
        second_execution,
        receipts=(first_update.receipt,),
    )
    return Case(
        run_id=first.run_id,
        status=CaseStatus.EVIDENCE_READY,
        event=first.event,
        evidence_packs=(first, first_update.pack, second_update.pack),
        manifest_id=first.manifest_id,
    )


def _pack_binding(pack: EvidencePack) -> M6SQLiteAcquisitionSelectedPackBinding:
    digest, size = _document_identity(pack)
    return M6SQLiteAcquisitionSelectedPackBinding(
        rowid=pack.version * 10,
        pack_id=pack.pack_id,
        version=pack.version,
        document_sha256=digest,
        document_bytes=size,
        created_audit_sequence=pack.version,
        index_identity_sha256=_sha(f"pack index {pack.pack_id}"),
    )


def _support_pair(
    authority: _SelectedAuthority,
    *,
    route: M6SQLiteAcquisitionSupportRoute,
    artifact_id: str,
    ordinal: int,
    body_sha256: str | None = None,
    document_bytes: int = 31,
) -> tuple[M6SQLiteAcquisitionSupportSlot, M6SQLiteAcquisitionSupportDocumentSlot]:
    index_identity_sha256 = _sha(f"index {route.value} {artifact_id}")
    relational = M6SQLiteAcquisitionSupportSlot(
        route=route,
        run_id=authority.case.run_id,
        case_id=authority.case.case_id,
        hearing_id=_HEARING_ID,
        rowid=ordinal,
        artifact_id=artifact_id,
        index_identity_sha256=index_identity_sha256,
    )
    document = M6SQLiteAcquisitionSupportDocumentSlot(
        route=M6SQLiteAcquisitionSupportDocumentRoute[route.name],
        run_id=authority.case.run_id,
        case_id=authority.case.case_id,
        hearing_id=_HEARING_ID,
        rowid=ordinal,
        artifact_id=artifact_id,
        body_commitment_sha256=body_sha256 or _sha(f"body {route.value} {artifact_id}"),
        document_bytes=document_bytes,
        index_identity_sha256=index_identity_sha256,
    )
    return relational, document


def _output_support_slot(
    authority: _SelectedAuthority,
    *,
    route: M6SQLiteAcquisitionSupportRoute,
    artifact_id: str,
    ordinal: int,
) -> M6SQLiteAcquisitionSupportSlot:
    return M6SQLiteAcquisitionSupportSlot(
        route=route,
        run_id=authority.case.run_id,
        case_id=authority.case.case_id,
        hearing_id=_HEARING_ID,
        rowid=ordinal,
        artifact_id=artifact_id,
        index_identity_sha256=_sha(f"index {route.value} {artifact_id}"),
    )


def _added_result(previous: EvidencePack, resulting: EvidencePack) -> ToolResult:
    previous_ids = {item.tool_result_id for item in previous.tool_results}
    added = tuple(
        item for item in resulting.tool_results if item.tool_result_id not in previous_ids
    )
    assert len(added) == 1
    return added[0]


def _closure(
    authority: _SelectedAuthority,
    *,
    result_pack_version: int,
    row_base: int,
    include_round: bool = False,
) -> M6SQLiteAcquisitionClosurePlan:
    previous = authority.case.evidence_packs[result_pack_version - 2]
    resulting = authority.case.evidence_packs[result_pack_version - 1]
    result = _added_result(previous, resulting)
    request_id = _sha(f"request {result.tool_result_id}")
    publication_id = _sha(f"publication {result.tool_result_id}")
    receipt_id = _sha(f"receipt {result.tool_result_id}")
    derivation_id = _sha(f"derivation {result.tool_result_id}")
    checkpoint_id = _sha(f"checkpoint {result.tool_result_id}")
    round_id = _sha(f"round {result.tool_result_id}") if include_round else None
    transition_audit_hash = _sha(f"audit {result.tool_result_id}")
    transition_case_version_id = _sha(f"case version {result.tool_result_id}")
    request_sha256 = _sha(f"request document {result.tool_result_id}")
    request_bytes = 43

    required = (
        _support_pair(
            authority,
            route=M6SQLiteAcquisitionSupportRoute.ACQUISITION_REQUEST,
            artifact_id=request_id,
            ordinal=row_base + 1,
            body_sha256=request_sha256,
            document_bytes=request_bytes,
        ),
        _support_pair(
            authority,
            route=M6SQLiteAcquisitionSupportRoute.EXECUTION_PUBLICATION,
            artifact_id=publication_id,
            ordinal=row_base + 2,
        ),
        _support_pair(
            authority,
            route=M6SQLiteAcquisitionSupportRoute.TOOL_EXECUTION_RECEIPT,
            artifact_id=receipt_id,
            ordinal=row_base + 3,
        ),
        _support_pair(
            authority,
            route=M6SQLiteAcquisitionSupportRoute.EVIDENCE_PACK_DERIVATION,
            artifact_id=derivation_id,
            ordinal=row_base + 4,
        ),
        _support_pair(
            authority,
            route=M6SQLiteAcquisitionSupportRoute.HEARING_CHECKPOINT,
            artifact_id=checkpoint_id,
            ordinal=row_base + 5,
        ),
        _support_pair(
            authority,
            route=M6SQLiteAcquisitionSupportRoute.CASE_VERSION,
            artifact_id=transition_case_version_id,
            ordinal=row_base + 6,
        ),
        _support_pair(
            authority,
            route=M6SQLiteAcquisitionSupportRoute.AUDIT_ENTRY,
            artifact_id=transition_audit_hash,
            ordinal=row_base + 7,
        ),
    )
    optional_round = (
        (
            _support_pair(
                authority,
                route=M6SQLiteAcquisitionSupportRoute.HEARING_ROUND,
                artifact_id=round_id,
                ordinal=row_base + 8,
            ),
        )
        if round_id is not None
        else ()
    )
    output_slots = tuple(
        _output_support_slot(
            authority,
            route={
                ArtifactKind.FRAME: M6SQLiteAcquisitionSupportRoute.OUTPUT_FRAME,
                ArtifactKind.DETECTION: M6SQLiteAcquisitionSupportRoute.OUTPUT_DETECTION,
                ArtifactKind.CROP: M6SQLiteAcquisitionSupportRoute.OUTPUT_CROP,
            }[ref.kind],
            artifact_id=ref.artifact_id,
            ordinal=row_base + 20 + index,
        )
        for index, ref in enumerate(result.output_refs)
        if ref.kind in {ArtifactKind.FRAME, ArtifactKind.DETECTION, ArtifactKind.CROP}
    )
    document_pairs = (*required, *optional_round)
    support = tuple(
        sorted(
            (*(pair[0] for pair in document_pairs), *output_slots),
            key=lambda value: value.sort_key,
        )
    )
    support_documents = tuple(
        sorted((pair[1] for pair in document_pairs), key=lambda value: value.sort_key)
    )
    manifest = M6SQLiteAcquisitionManifestSlot(
        run_id=authority.case.run_id,
        case_id=authority.case.case_id,
        hearing_id=_HEARING_ID,
        rowid=row_base + 30,
        execution_manifest_id=result.execution_manifest_id,
        acquisition_request_id=request_id,
        action=result.action,
        component_manifest_id=_sha(f"component manifest {result.execution_manifest_id}"),
        model_manifest_id=None,
        manifest_id=authority.case.manifest_id,
        document_sha256=_sha(f"manifest document {result.execution_manifest_id}"),
        document_bytes=47,
        index_identity_sha256=_sha(f"manifest index {result.execution_manifest_id}"),
    )
    return M6SQLiteAcquisitionClosurePlan(
        run_id=authority.case.run_id,
        case_id=authority.case.case_id,
        manifest_id=authority.case.manifest_id,
        acquisition_request_id=request_id,
        execution_publication_id=publication_id,
        tool_receipt_id=receipt_id,
        derivation_id=derivation_id,
        checkpoint_id=checkpoint_id,
        round_id=round_id,
        upstream_m4=M6SQLiteAcquisitionUpstreamM4Binding(
            upstream_m4_model_plan_identity_sha256=_UPSTREAM_PLAN_ID,
            run_id=authority.case.run_id,
            case_id=authority.case.case_id,
            hearing_id=_HEARING_ID,
            hearing_rowid=50,
            hearing_support_index_identity_sha256=_sha("hearing support index"),
            cycle_scope_id=_sha(f"cycle {result_pack_version}"),
            cycle_scope_sha256=_sha(f"cycle body {result_pack_version}"),
            cycle_rowid=row_base + 51,
            cycle_support_index_identity_sha256=_sha(f"cycle index {result_pack_version}"),
            judge_output_id=_sha(f"judge output {result_pack_version}"),
            judge_output_document_sha256=_sha(f"judge output body {result_pack_version}"),
            judge_output_rowid=row_base + 52,
            judge_output_index_identity_sha256=_sha(f"judge output index {result_pack_version}"),
        ),
        manifest=manifest,
        claim=M6SQLiteAcquisitionCompletedClaimSlot(
            run_id=authority.case.run_id,
            case_id=authority.case.case_id,
            hearing_id=_HEARING_ID,
            rowid=row_base + 31,
            acquisition_request_id=request_id,
            execution_publication_id=publication_id,
            execution_mode=AcquisitionExecutionMode.PURE,
            idempotency_key=request_id,
            owner_token_sha256=_sha(f"owner {request_id}"),
            owner_fence=1,
            status=M6SQLiteAcquisitionClaimState.COMPLETED,
            request_document_sha256=request_sha256,
            request_document_bytes=request_bytes,
            claim_document_sha256=_sha(f"claim document {request_id}"),
            claim_document_bytes=53,
            index_identity_sha256=_sha(f"claim index {request_id}"),
        ),
        tool_result=M6SQLiteAcquisitionToolResultBinding(
            tool_result=result,
            origin_pack_id=resulting.pack_id,
            origin_pack_version=resulting.version,
        ),
        pack_transition=M6SQLiteAcquisitionPackTransitionBinding(
            previous_pack=_pack_binding(previous),
            resulting_pack=_pack_binding(resulting),
            added_tool_result_id=result.tool_result_id,
            first_occurrence_pack_id=resulting.pack_id,
            first_occurrence_pack_version=resulting.version,
            transition_case_revision=resulting.version,
            transition_case_version_id=transition_case_version_id,
            transition_audit_sequence=resulting.version,
            transition_audit_entry_hash=transition_audit_hash,
        ),
        support_slots=support,
        support_document_slots=support_documents,
    )


def _plan(case: Case, *, include_round: bool = False) -> M6SQLiteAcquisitionDocumentsPlan:
    authority = _selected_authority(case)
    closures = tuple(
        _closure(
            authority,
            result_pack_version=version,
            row_base=version * 100,
            include_round=include_round,
        )
        for version in range(2, len(case.evidence_packs) + 1)
    )
    refs = tuple(ref for closure in closures for ref in closure.artifact_refs)
    observations = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                    kind=ref.kind,
                    artifact_id=ref.artifact_id,
                    usage=M6UpgradeArtifactUsage.PRODUCED,
                )
                for ref in refs
            ),
            key=lambda value: value.sort_key,
        )
    )
    return M6SQLiteAcquisitionDocumentsPlan(
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        upstream_m4_model_plan_identity_sha256=_UPSTREAM_PLAN_ID,
        selected_case_binding=authority.binding,
        selected_case=case,
        selected_case_revision=authority.revision,
        selected_case_audit=authority.audit,
        observed_artifacts=observations,
        closures=closures,
    )


def test_budget_aliases_and_closed_failure_codes_are_exact() -> None:
    assert MAX_M6_SQLITE_ACQUISITION_ITEMS == MAX_M6_LOCKED_TOOL_RESULTS_PER_CASE == 64
    assert MAX_M6_SQLITE_ACQUISITION_SELECTED_PACKS == 65
    assert MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS == 20_000
    assert MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE == 20_000
    assert MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES == 64 * 1024 * 1024
    assert MAX_M6_SQLITE_ACQUISITION_SUPPORT_TOTAL_BYTES == 256 * 1024 * 1024
    assert MAX_M6_SQLITE_ACQUISITION_DOCUMENT_TOTAL_BYTES == 256 * 1024 * 1024
    assert (
        MAX_M6_SQLITE_ACQUISITION_PHYSICAL_TOTAL_BYTES
        == MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES
        == 256 * 1024 * 1024
    )
    assert {item.value for item in M6SQLiteAcquisitionPlanFailureCode} == {
        "INVALID_ARGUMENT",
        "TRANSACTION_REQUIRED",
        "SCOPE_NOT_FOUND",
        "SCOPE_MISMATCH",
        "CASE_BINDING_MISMATCH",
        "INVENTORY_MISMATCH",
        "UNSUPPORTED_ACQUISITION_STATE",
        "POST_CUT_AUTHORITY",
        "ROW_LIMIT_EXCEEDED",
        "DOCUMENT_TOO_LARGE",
        "SUPPORT_BUDGET_EXCEEDED",
        "PHYSICAL_BUDGET_EXCEEDED",
        "DOCUMENT_INVALID",
        "INDEX_BINDING_MISMATCH",
        "CLOSURE_MISMATCH",
        "PHYSICAL_PLAN_INVALID",
        "DATABASE_REJECTED",
    }
    failure = subject._M6SQLiteAcquisitionMetadataFailure(
        M6SQLiteAcquisitionPlanFailureCode.POST_CUT_AUTHORITY
    )
    assert failure.reason_code == M6SQLiteAcquisitionPlanFailureCode.POST_CUT_AUTHORITY
    assert str(failure) == "POST_CUT_AUTHORITY"


def test_plan_exposes_only_manifest_and_deduplicated_tool_result_physical_refs() -> None:
    plan = _plan(_case_with_one_acquisition())
    closure = plan.closures[0]
    refs = {ref.kind: ref for ref in plan.planned_artifact_refs}
    result_canonical = canonical_json(closure.tool_result.tool_result.model_dump(mode="json"))

    assert set(refs) == {
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
    }
    assert all(
        ref.source == M6UpgradePhysicalArtifactSource.M4_ACQUISITION for ref in refs.values()
    )
    assert closure.manifest.route == M6SQLiteAcquisitionPhysicalRoute.TOOL_EXECUTION_MANIFEST
    assert closure.tool_result.route == M6SQLiteAcquisitionPhysicalRoute.TOOL_RESULT
    assert refs[M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST] == (
        closure.manifest.physical_ref
    )
    result_ref = refs[M6UpgradePhysicalArtifactKind.TOOL_RESULT]
    assert result_ref == closure.tool_result.physical_ref
    assert result_ref.document_sha256 == _sha(result_canonical)
    assert result_ref.content_sha256 == result_ref.document_sha256
    assert result_ref.size_bytes == len(result_canonical.encode("utf-8"))
    assert not hasattr(closure.claim, "physical_ref")
    assert not hasattr(closure.pack_transition, "physical_ref")
    assert all(not hasattr(slot, "physical_ref") for slot in closure.support_slots)
    assert all(not hasattr(slot, "physical_ref") for slot in closure.support_document_slots)


def test_plan_exactly_joins_observation_routes_usage_and_upstream_m4_identity() -> None:
    plan = _plan(_case_with_one_acquisition())
    assert len(plan.observed_artifacts) == 2
    assert {(item.source, item.kind, item.usage) for item in plan.observed_artifacts} == {
        (
            M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
            M6UpgradeArtifactUsage.PRODUCED,
        ),
        (
            M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            M6UpgradePhysicalArtifactKind.TOOL_RESULT,
            M6UpgradeArtifactUsage.PRODUCED,
        ),
    }
    assert plan.closures[0].upstream_m4.upstream_m4_model_plan_identity_sha256 == (
        plan.upstream_m4_model_plan_identity_sha256
    )
    assert subject._plan_is_consistent(plan)
    assert plan.plan_identity_sha256 == _plan(_case_with_one_acquisition()).plan_identity_sha256


def test_tool_result_output_existence_is_bounded_relational_support_only() -> None:
    plan = _plan(_case_with_one_acquisition())
    closure = plan.closures[0]
    output_routes = {
        ArtifactKind.FRAME: M6SQLiteAcquisitionSupportRoute.OUTPUT_FRAME,
        ArtifactKind.DETECTION: M6SQLiteAcquisitionSupportRoute.OUTPUT_DETECTION,
        ArtifactKind.CROP: M6SQLiteAcquisitionSupportRoute.OUTPUT_CROP,
    }
    expected = {
        (output_routes[ref.kind], ref.artifact_id)
        for ref in closure.tool_result.tool_result.output_refs
        if ref.kind in output_routes
    }
    actual = {
        slot.identity_key
        for slot in closure.support_slots
        if slot.route in set(output_routes.values())
    }

    assert actual == expected
    assert not {route.name for route in output_routes.values()} & {
        route.name for route in M6SQLiteAcquisitionSupportDocumentRoute
    }
    assert {observation.artifact_id for observation in plan.observed_artifacts}.isdisjoint(
        {artifact_id for _route, artifact_id in actual}
    )


def test_relational_support_has_frozen_total_and_per_route_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(_case_with_one_acquisition())
    monkeypatch.setattr(
        subject,
        "MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS",
        len(plan.support_slots) - 1,
    )
    with pytest.raises(ValueError, match="total row limit"):
        replace(plan)

    monkeypatch.setattr(
        subject,
        "MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS",
        MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS,
    )
    monkeypatch.setattr(subject, "MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE", 0)
    with pytest.raises(ValueError, match="per-route limit"):
        replace(plan)


def test_missing_extra_or_wrong_acquisition_observation_fails_closed() -> None:
    plan = _plan(_case_with_one_acquisition())
    manifest_observation = next(
        item
        for item in plan.observed_artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST
    )
    with pytest.raises(ValueError, match="observations"):
        replace(plan, observed_artifacts=plan.observed_artifacts[:-1])
    with pytest.raises(ValueError, match="produced"):
        replace(
            plan,
            observed_artifacts=tuple(
                sorted(
                    (
                        manifest_observation.model_copy(
                            update={"usage": M6UpgradeArtifactUsage.CONSUMED}
                        ),
                        *(item for item in plan.observed_artifacts if item != manifest_observation),
                    ),
                    key=lambda value: value.sort_key,
                )
            ),
        )
    extra = manifest_observation.model_copy(update={"artifact_id": _sha("extra manifest")})
    with pytest.raises(ValueError, match="observations"):
        replace(
            plan,
            observed_artifacts=tuple(
                sorted((*plan.observed_artifacts, extra), key=lambda value: value.sort_key)
            ),
        )


def test_cumulative_pack_history_deduplicates_old_tool_results_by_id() -> None:
    case = _case_with_two_acquisitions()
    first_result_id = case.evidence_packs[1].tool_results[0].tool_result_id
    assert first_result_id in {item.tool_result_id for item in case.evidence_packs[2].tool_results}

    plan = _plan(case)
    tool_refs = tuple(
        ref
        for ref in plan.planned_artifact_refs
        if ref.kind == M6UpgradePhysicalArtifactKind.TOOL_RESULT
    )

    assert len(plan.closures) == 2
    assert len(plan.selected_pack_bindings) == 3
    assert len(tool_refs) == 2
    assert len({ref.artifact_id for ref in tool_refs}) == 2
    assert sum(ref.artifact_id == first_result_id for ref in tool_refs) == 1
    with pytest.raises(ValueError, match="exactly cover"):
        replace(plan, closures=plan.closures[:-1])


def test_pack_transition_freezes_first_occurrence_and_rejects_post_cut_authority() -> None:
    plan = _plan(_case_with_one_acquisition())
    closure = plan.closures[0]
    transition = closure.pack_transition
    assert transition.resulting_pack.version == transition.previous_pack.version + 1
    assert transition.first_occurrence_pack_id == transition.resulting_pack.pack_id
    assert transition.added_tool_result_id == closure.tool_result.tool_result.tool_result_id

    with pytest.raises(ValueError, match="first occurrence"):
        replace(transition, first_occurrence_pack_id=transition.previous_pack.pack_id)
    with pytest.raises(ValueError, match="positive"):
        replace(transition, transition_audit_sequence=0)

    post_cut_sequence = plan.selected_case_audit.sequence + 1
    post_cut_pack = replace(
        transition.resulting_pack,
        created_audit_sequence=post_cut_sequence,
    )
    post_cut_transition = replace(
        transition,
        resulting_pack=post_cut_pack,
        transition_audit_sequence=post_cut_sequence,
    )
    post_cut_closure = replace(closure, pack_transition=post_cut_transition)
    with pytest.raises(ValueError, match="selected Case authority"):
        replace(plan, closures=(post_cut_closure,))


def test_success_plan_requires_completed_claim_full_support_and_dual_request_commitment() -> None:
    closure = _plan(_case_with_one_acquisition()).closures[0]
    request_slot = next(
        item
        for item in closure.support_document_slots
        if item.route == M6SQLiteAcquisitionSupportDocumentRoute.ACQUISITION_REQUEST
    )
    assert request_slot.body_commitment_sha256 == closure.claim.request_document_sha256
    assert request_slot.document_bytes == closure.claim.request_document_bytes

    with pytest.raises(ValueError, match="completed"):
        replace(closure.claim, status=M6SQLiteAcquisitionClaimState.ACTIVE)
    with pytest.raises(ValueError, match="mandatory support"):
        replace(
            closure,
            support_slots=tuple(
                item
                for item in closure.support_slots
                if item.route != M6SQLiteAcquisitionSupportRoute.EXECUTION_PUBLICATION
            ),
        )
    changed_request = replace(
        request_slot,
        body_commitment_sha256=_sha("different request copy"),
    )
    with pytest.raises(ValueError, match="request copy"):
        replace(
            closure,
            support_document_slots=tuple(
                sorted(
                    (
                        changed_request,
                        *(item for item in closure.support_document_slots if item != request_slot),
                    ),
                    key=lambda value: value.sort_key,
                )
            ),
        )


def test_round_is_optional_checkpoint_is_mandatory_and_commitment_meaning_is_explicit() -> None:
    without_round = _plan(_case_with_one_acquisition())
    with_round = _plan(_case_with_one_acquisition(), include_round=True)
    assert without_round.closures[0].round_id is None
    assert all(
        slot.route != M6SQLiteAcquisitionSupportRoute.HEARING_ROUND
        for slot in without_round.support_slots
    )
    assert with_round.closures[0].round_id is not None
    round_slot = next(
        slot
        for slot in with_round.support_document_slots
        if slot.route == M6SQLiteAcquisitionSupportDocumentRoute.HEARING_ROUND
    )
    checkpoint = next(
        slot
        for slot in with_round.support_document_slots
        if slot.route == M6SQLiteAcquisitionSupportDocumentRoute.HEARING_CHECKPOINT
    )
    request = next(
        slot
        for slot in with_round.support_document_slots
        if slot.route == M6SQLiteAcquisitionSupportDocumentRoute.ACQUISITION_REQUEST
    )
    assert round_slot.commitment_kind == M6SQLiteAcquisitionDocumentCommitmentKind.SEMANTIC_DOCUMENT
    assert checkpoint.commitment_kind == (
        M6SQLiteAcquisitionDocumentCommitmentKind.SEMANTIC_DOCUMENT
    )
    assert request.commitment_kind == (M6SQLiteAcquisitionDocumentCommitmentKind.CANONICAL_DOCUMENT)
    assert with_round.planned_document_bytes - without_round.planned_document_bytes == (
        round_slot.document_bytes
    )


def test_document_and_physical_budgets_count_each_frozen_body_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(_case_with_two_acquisitions())
    expected_support = (
        sum(slot.document_bytes for slot in plan.support_document_slots)
        + sum(
            closure.claim.request_document_bytes + closure.claim.claim_document_bytes
            for closure in plan.closures
        )
        + sum(pack.document_bytes for pack in plan.selected_pack_bindings)
    )
    expected_documents = expected_support + sum(
        closure.manifest.document_bytes for closure in plan.closures
    )
    assert plan.planned_support_bytes == expected_support
    assert plan.planned_document_bytes == expected_documents
    assert plan.planned_physical_bytes == sum(ref.size_bytes for ref in plan.planned_artifact_refs)

    monkeypatch.setattr(
        subject,
        "MAX_M6_SQLITE_ACQUISITION_DOCUMENT_TOTAL_BYTES",
        plan.planned_document_bytes - 1,
    )
    with pytest.raises(ValueError, match="planned documents"):
        replace(plan)


def test_per_document_cap_scope_duplicate_and_deep_mutation_fail_closed() -> None:
    plan = _plan(_case_with_one_acquisition())
    closure = plan.closures[0]
    support = closure.support_document_slots[0]
    with pytest.raises(ValueError, match="document budget"):
        replace(support, document_bytes=MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES + 1)
    crossed_support = replace(support, run_id="foreign-run")
    with pytest.raises(ValueError, match="scope"):
        replace(
            closure,
            support_document_slots=tuple(
                crossed_support if item == support else item
                for item in closure.support_document_slots
            ),
        )

    duplicate = replace(
        closure.support_slots[1],
        route=closure.support_slots[0].route,
        artifact_id=closure.support_slots[0].artifact_id,
    )
    with pytest.raises(ValueError, match="unique"):
        replace(
            closure,
            support_slots=tuple(
                sorted(
                    (closure.support_slots[0], duplicate, *closure.support_slots[2:]),
                    key=lambda value: value.sort_key,
                )
            ),
        )

    assert is_dataclass(plan)
    assert not hasattr(plan, "__dict__")
    assert subject._plan_is_consistent(plan)
    object.__setattr__(plan, "planned_physical_bytes", plan.planned_physical_bytes + 1)
    assert not subject._plan_is_consistent(plan)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda closure: object.__setattr__(
            closure.upstream_m4,
            "judge_output_rowid",
            closure.upstream_m4.judge_output_rowid + 1,
        ),
        lambda closure: object.__setattr__(
            closure.support_document_slots[0],
            "body_commitment_sha256",
            _sha("mutated support body"),
        ),
        lambda closure: object.__setattr__(
            closure.pack_transition,
            "transition_audit_entry_hash",
            _sha("mutated transition audit"),
        ),
        lambda closure: object.__setattr__(
            closure.tool_result,
            "physical_ref",
            closure.tool_result.physical_ref.model_copy(
                update={
                    "document_sha256": _sha("mutated ToolResult ref"),
                    "content_sha256": _sha("mutated ToolResult ref"),
                }
            ),
        ),
        lambda closure: object.__setattr__(
            closure.manifest,
            "component_manifest_id",
            _sha("mutated component manifest pin"),
        ),
        lambda closure: object.__setattr__(
            closure.manifest,
            "model_manifest_id",
            _sha("mutated model manifest pin"),
        ),
    ),
)
def test_nested_plan_mutation_invalidates_the_frozen_plan_identity(
    mutate: object,
) -> None:
    plan = _plan(_case_with_one_acquisition())
    assert callable(mutate)
    mutate(plan.closures[0])
    assert not subject._plan_is_consistent(plan)


def test_upstream_plan_identity_and_manifest_metadata_are_digest_inputs() -> None:
    plan = _plan(_case_with_one_acquisition())
    closure = plan.closures[0]
    changed_manifest = replace(
        closure.manifest,
        document_sha256=_sha("changed manifest document"),
    )
    changed_closure = replace(closure, manifest=changed_manifest)
    changed = replace(plan, closures=(changed_closure,))
    assert changed.plan_identity_sha256 != plan.plan_identity_sha256

    changed_component = replace(
        closure,
        manifest=replace(
            closure.manifest,
            component_manifest_id=_sha("changed component manifest pin"),
        ),
    )
    changed_model = replace(
        closure,
        manifest=replace(
            closure.manifest,
            model_manifest_id=_sha("new nullable model manifest pin"),
        ),
    )
    assert replace(plan, closures=(changed_component,)).plan_identity_sha256 != (
        plan.plan_identity_sha256
    )
    assert replace(plan, closures=(changed_model,)).plan_identity_sha256 != (
        plan.plan_identity_sha256
    )

    crossed_upstream = replace(
        closure.upstream_m4,
        upstream_m4_model_plan_identity_sha256=_sha("another upstream M4 plan"),
    )
    crossed_closure = replace(closure, upstream_m4=crossed_upstream)
    with pytest.raises(ValueError, match="upstream M4 scope"):
        replace(plan, closures=(crossed_closure,))


def test_manifest_component_and_nullable_model_pins_are_strict_sha256() -> None:
    manifest = _plan(_case_with_one_acquisition()).closures[0].manifest
    with pytest.raises(ValueError, match="component manifest_id"):
        replace(manifest, component_manifest_id="not-a-component-digest")
    with pytest.raises(ValueError, match="model manifest_id"):
        replace(manifest, model_manifest_id="not-a-model-digest")

    pinned = replace(manifest, model_manifest_id=_sha("valid model manifest pin"))
    assert pinned.component_manifest_id == manifest.component_manifest_id
    assert pinned.model_manifest_id == _sha("valid model manifest pin")


def test_shared_upstream_m4_identity_cannot_drift_or_cross_rows() -> None:
    plan = _plan(_case_with_two_acquisitions())
    first, second = plan.closures
    drifted_hearing = replace(
        second.upstream_m4,
        hearing_rowid=second.upstream_m4.hearing_rowid + 1,
    )
    with pytest.raises(ValueError, match="conflicting metadata"):
        replace(plan, closures=(first, replace(second, upstream_m4=drifted_hearing)))

    crossed_cycle = replace(
        second.upstream_m4,
        cycle_rowid=first.upstream_m4.cycle_rowid,
    )
    with pytest.raises(ValueError, match="cross authority identities"):
        replace(plan, closures=(first, replace(second, upstream_m4=crossed_cycle)))
