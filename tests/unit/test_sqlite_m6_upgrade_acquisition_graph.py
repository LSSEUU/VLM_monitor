"""Adversarial graph tests for M6 acquisition metadata planning."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, replace
from typing import cast

import pytest

from labcourt.adapters.storage._sqlite_m6_live_read_cut import M6LiveReader
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_graph import (
    build_acquisition_closures,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_plan import (
    M6SQLiteAcquisitionClosurePlan,
    M6SQLiteAcquisitionPlanFailureCode,
    _M6SQLiteAcquisitionMetadataFailure,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_rows import (
    M6SQLiteAcquisitionHearingSupportRows,
    M6SQLiteAcquisitionOutputSupportRows,
    M6SQLiteAcquisitionPrimaryRows,
    M6SQLiteAcquisitionTransitionSupportRows,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseAuthorityDocument,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4CallGeneration,
    M6SQLiteM4CallGraphPlan,
    M6SQLiteM4ClaimStatus,
    M6SQLiteM4DocumentRoute,
    M6SQLiteM4ModelDocumentsPlan,
    M6SQLiteM4SelectedPackBinding,
    M6SQLiteM4SupportDocumentRoute,
    M6SQLiteM4SupportRoute,
)
from labcourt.contracts.audit import AuditEntryDraft
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
    ModelParseStatus,
)
from labcourt.contracts.hearing_persistence import EvidencePackDerivation
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeObservedModelCall,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.storage import ArtifactRef
from tests.unit.test_m4_evidence_authority import _execution, _finalize
from tests.unit.test_m6_acquisition_projection import _base_pack, _publication
from tests.unit.test_sqlite_m6_upgrade_m4_model_plan import (
    _document_slot,
    _hearing_binding,
    _support_pair,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document(value: object) -> tuple[str, int]:
    assert hasattr(value, "model_dump")
    payload = canonical_json(value.model_dump(mode="json"))
    encoded = payload.encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _row(**values: object) -> sqlite3.Row:
    return cast(sqlite3.Row, values)


def _reader() -> M6LiveReader:
    # SQLite 3.43+ length projections keep this graph slice body-free, so the
    # graph never invokes the capability in these unit fixtures.
    return object.__new__(M6LiveReader)


@dataclass(frozen=True, slots=True)
class _Fixture:
    run_id: str
    case_id: str
    manifest_id: str
    selected: M6SQLiteCaseAuthorityDocument
    observations: tuple[M6UpgradeObservedArtifactIdentity, ...]
    upstream: M6SQLiteM4ModelDocumentsPlan
    primary: M6SQLiteAcquisitionPrimaryRows
    hearing: M6SQLiteAcquisitionHearingSupportRows
    transition: M6SQLiteAcquisitionTransitionSupportRows
    outputs: M6SQLiteAcquisitionOutputSupportRows

    def build(self) -> tuple[M6SQLiteAcquisitionClosurePlan, ...]:
        return build_acquisition_closures(
            _reader(),
            run_id=self.run_id,
            case_id=self.case_id,
            manifest_id=self.manifest_id,
            selected_case_authority=self.selected,
            observed_acquisition_artifacts=self.observations,
            upstream_m4_model_plan=self.upstream,
            primary_rows=self.primary,
            hearing_rows=self.hearing,
            transition_rows=self.transition,
            output_rows=self.outputs,
        )


def _selected(
    case: Case,
    *,
    revision: int = 2,
    before_sha256: str | None = None,
) -> M6SQLiteCaseAuthorityDocument:
    canonical_case = canonical_json(case.model_dump(mode="json"))
    case_sha256 = hashlib.sha256(canonical_case.encode("utf-8")).hexdigest()
    audit = AuditEntryDraft(
        run_id=case.run_id,
        sequence=revision,
        actor=AuditActorRole.SYSTEM,
        action=AuditAction.EVIDENCE_PACK_PUBLISHED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case.case_id),
        before_sha256=before_sha256 or _sha("case predecessor"),
        after_sha256=case_sha256,
        manifest_id=case.manifest_id,
        recorded_at="2026-08-04T12:13:14.000015Z",
        prev_entry_hash=_sha("previous audit"),
    ).seal()
    from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding

    binding = M6UpgradeCandidateCaseBinding(
        case_id=case.case_id,
        case_revision=revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=audit.sequence,
        case_audit_entry_hash=audit.entry_hash,
    )
    return M6SQLiteCaseAuthorityDocument(
        candidate_case_binding=binding,
        case=case,
        canonical_case_document=canonical_case,
        audit_entry=audit,
        canonical_audit_document=canonical_json(audit.model_dump(mode="json")),
    )


def _upstream_plan(
    selected: M6SQLiteCaseAuthorityDocument,
    *,
    hearing_id: str,
    cycle_id: str,
    cycle_sha256: str,
    source_request_id: str,
    source_response_id: str,
    judge_output_id: str,
) -> M6SQLiteM4ModelDocumentsPlan:
    pack = selected.case.evidence_packs[0]
    pack_sha256, _ = _document(pack)
    selected_pack = M6SQLiteM4SelectedPackBinding(
        rowid=10,
        pack_id=pack.pack_id,
        version=pack.version,
        document_sha256=pack_sha256,
        created_audit_sequence=1,
        index_identity_sha256=_sha("M4 selected pack index"),
    )
    observation = M6UpgradeObservedModelCall(
        request_id=source_request_id,
        layer=M6LockedModelCallLayer.HEARING,
        role=M6LockedModelRole.JUDGE,
        attempt_index=0,
        result_kind=M6LockedModelCallResultKind.RESPONSE,
        provider_invoked=True,
    )
    judge_model_id = _sha(M6LockedModelRole.JUDGE.value)
    graph = M6SQLiteM4CallGraphPlan(
        observation=observation,
        hearing_id=hearing_id,
        cycle_scope_id=cycle_id,
        cycle_scope_sha256=cycle_sha256,
        cycle_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        retrieval_receipt_id=_sha("retrieval"),
        retrieval_commitment_sha256=_sha("retrieval document"),
        purpose="ROLE_CALL",
        call_generation=M6SQLiteM4CallGeneration.INITIAL,
        backlog_item_id=None,
        retry_generation=0,
        model_manifest_id=judge_model_id,
        claim_status=M6SQLiteM4ClaimStatus.COMPLETED,
        claim_takeover_count=0,
        request=_document_slot(
            M6SQLiteM4DocumentRoute.MODEL_REQUEST,
            rowid=21,
            artifact_id=source_request_id,
        ),
        response=_document_slot(
            M6SQLiteM4DocumentRoute.MODEL_RESPONSE,
            rowid=22,
            artifact_id=source_response_id,
        ),
        cache_request=_document_slot(
            M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST,
            rowid=23,
            artifact_id=source_request_id,
        ),
        cache=_document_slot(M6SQLiteM4DocumentRoute.MODEL_CACHE_ENTRY, rowid=24),
        parse_receipt=_document_slot(
            M6SQLiteM4DocumentRoute.MODEL_PARSE_RECEIPT,
            rowid=25,
        ),
        role_output=_document_slot(
            M6SQLiteM4DocumentRoute.ROLE_OUTPUT,
            rowid=26,
            artifact_id=judge_output_id,
        ),
        usage=_document_slot(M6SQLiteM4DocumentRoute.MODEL_USAGE, rowid=27),
        parse_status=ModelParseStatus.PARSED,
    )
    hearing_pair = _support_pair(
        M6SQLiteM4SupportRoute.HEARING_SESSION,
        M6SQLiteM4SupportDocumentRoute.HEARING_SESSION,
        rowid=31,
        artifact_id=hearing_id,
        body_commitment_sha256=_sha("hearing document"),
    )
    cycle_pair = _support_pair(
        M6SQLiteM4SupportRoute.HEARING_CYCLE,
        M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE,
        rowid=32,
        artifact_id=cycle_id,
        body_commitment_sha256=cycle_sha256,
    )
    retrieval_pair = _support_pair(
        M6SQLiteM4SupportRoute.PRECEDENT_RETRIEVAL,
        M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL,
        rowid=33,
        artifact_id=graph.retrieval_receipt_id,
        body_commitment_sha256=graph.retrieval_commitment_sha256,
    )
    pairs = (hearing_pair, cycle_pair, retrieval_pair)
    return M6SQLiteM4ModelDocumentsPlan(
        run_id=selected.case.run_id,
        case_id=selected.case.case_id,
        manifest_id=selected.case.manifest_id,
        selected_case_binding=selected.candidate_case_binding,
        selected_case=selected.case,
        selected_case_revision=selected.candidate_case_binding.case_revision,
        selected_case_audit=selected.audit_entry,
        hearing_model_bindings=(_hearing_binding(hearing_id, _sha("unused prosecutor")),),
        selected_packs=(selected_pack,),
        observed_model_calls=(observation,),
        call_graphs=(graph,),
        support_slots=tuple(sorted((pair[0] for pair in pairs), key=lambda item: item.sort_key)),
        support_document_slots=tuple(
            sorted((pair[1] for pair in pairs), key=lambda item: item.sort_key)
        ),
    )


def _fixture(
    *,
    action: AcquisitionAction = AcquisitionAction.TRACK_CONFIDENCE_CURVE,
) -> _Fixture:
    run_id = f"run-acquisition-graph-{action.value.lower()}"
    previous = _base_pack(run_id)
    execution = _execution(previous, action)
    update = _finalize(previous, execution)
    previous_case = Case(
        run_id=run_id,
        status=CaseStatus.DELIBERATING,
        event=previous.event,
        evidence_packs=(previous,),
        manifest_id=previous.manifest_id,
    )
    previous_case_sha, previous_case_bytes = _document(previous_case)
    case = Case(
        run_id=run_id,
        status=CaseStatus.DELIBERATING,
        event=previous.event,
        evidence_packs=(previous, update.pack),
        manifest_id=previous.manifest_id,
        timeline=(
            TimelineEntry(
                sequence=0,
                action=AuditAction.CASE_STATE_CHANGED.value,
                stage="HEARING",
                object_ref=update.receipt.receipt_id,
                details={
                    "action": action.value,
                    "evidence_pack_id": update.pack.pack_id,
                    "evidence_pack_version": update.pack.version,
                    "tool_receipt_id": update.receipt.receipt_id,
                },
            ),
        ),
    )
    selected = _selected(case, before_sha256=previous_case_sha)
    request = execution.request
    manifest = execution.execution_manifest
    result = execution.tool_result
    publication = _publication(execution)
    receipt = update.receipt
    cycle_id = _sha("acquisition cycle")
    cycle_sha256 = _sha("acquisition cycle document")
    derivation = EvidencePackDerivation(
        run_id=run_id,
        case_id=case.case_id,
        hearing_session_id=request.hearing_session_id,
        source_cycle_scope_id=cycle_id,
        source_cycle_scope_sha256=cycle_sha256,
        previous_evidence_pack_id=previous.pack_id,
        previous_evidence_pack_version=previous.version,
        new_evidence_pack_id=update.pack.pack_id,
        new_evidence_pack_version=update.pack.version,
        tool_execution_receipt_id=receipt.receipt_id,
        manifest_id=case.manifest_id,
    )
    request_sha, request_bytes = _document(request)
    manifest_sha, manifest_bytes = _document(manifest)
    publication_sha, publication_bytes = _document(publication)
    receipt_sha, receipt_bytes = _document(receipt)
    derivation_sha, derivation_bytes = _document(derivation)
    previous_sha, previous_bytes = _document(previous)
    resulting_sha, resulting_bytes = _document(update.pack)
    claim_sha = _sha("claim document")
    checkpoint_id = _sha("acquisition pending checkpoint")
    checkpoint_sha = _sha("acquisition pending checkpoint document")
    validated_sha, _ = _document(request.validated_parameters)

    request_row = _row(
        document_rowid=101,
        run_id=run_id,
        acquisition_request_id=request.request_id,
        hearing_id=request.hearing_session_id,
        cycle_scope_id=cycle_id,
        cycle_scope_sha256=cycle_sha256,
        case_id=case.case_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        evidence_pack_id=previous.pack_id,
        evidence_pack_version=previous.version,
        judge_output_id=request.source_judge_output_id,
        source_model_request_id=request.source_model_request_ref.artifact_id,
        source_model_response_id=request.source_model_response_ref.artifact_id,
        action=request.action.value,
        validated_parameters_sha256=validated_sha,
        manifest_id=case.manifest_id,
        document_sha256=request_sha,
        request_document_type="text",
        request_document_bytes=request_bytes,
    )
    claim_row = _row(
        document_rowid=102,
        run_id=run_id,
        acquisition_request_id=request.request_id,
        request_document_sha256=request_sha,
        case_id=case.case_id,
        hearing_id=request.hearing_session_id,
        execution_mode=AcquisitionExecutionMode.PURE.value,
        idempotency_key=request.request_id,
        status="COMPLETED",
        owner_token_sha256=publication.claim_owner_sha256,
        owner_fence=publication.claim_fence,
        lease_expires_at=None,
        execution_publication_id=publication.publication_id,
        created_at="2026-08-04T12:13:14.000015Z",
        updated_at="2026-08-04T12:13:14.000016Z",
        document_sha256=claim_sha,
        claim_request_document_type="text",
        claim_request_document_bytes=request_bytes,
        claim_document_type="text",
        claim_document_bytes=41,
    )
    manifest_row = _row(
        document_rowid=103,
        run_id=run_id,
        execution_manifest_id=manifest.execution_manifest_id,
        case_id=case.case_id,
        hearing_id=request.hearing_session_id,
        acquisition_request_id=request.request_id,
        action=request.action.value,
        tool_id=manifest.tool_id,
        tool_revision=manifest.tool_revision,
        parameters_schema_sha256=manifest.parameters_schema_sha256,
        component_manifest_id=manifest.component_manifest_id,
        model_manifest_id=manifest.model_manifest_id,
        manifest_id=case.manifest_id,
        document_sha256=manifest_sha,
        manifest_document_type="text",
        manifest_document_bytes=manifest_bytes,
    )
    publication_row = _row(
        document_rowid=104,
        run_id=run_id,
        execution_publication_id=publication.publication_id,
        acquisition_request_id=request.request_id,
        request_document_sha256=request_sha,
        case_id=case.case_id,
        hearing_id=request.hearing_session_id,
        execution_manifest_id=manifest.execution_manifest_id,
        tool_result_id=result.tool_result_id,
        execution_mode=publication.execution_mode.value,
        idempotency_key=publication.idempotency_key,
        claim_owner_sha256=publication.claim_owner_sha256,
        claim_fence=publication.claim_fence,
        document_sha256=publication_sha,
        publication_document_type="text",
        publication_document_bytes=publication_bytes,
    )
    receipt_row = _row(
        document_rowid=105,
        run_id=run_id,
        receipt_id=receipt.receipt_id,
        acquisition_request_id=request.request_id,
        hearing_id=request.hearing_session_id,
        cycle_scope_id=cycle_id,
        cycle_scope_sha256=cycle_sha256,
        case_id=case.case_id,
        action=request.action.value,
        execution_manifest_id=manifest.execution_manifest_id,
        tool_result_id=result.tool_result_id,
        resulting_pack_id=update.pack.pack_id,
        resulting_pack_version=update.pack.version,
        document_sha256=receipt_sha,
        receipt_document_type="text",
        receipt_document_bytes=receipt_bytes,
    )
    derivation_row = _row(
        document_rowid=106,
        run_id=run_id,
        derivation_id=derivation.derivation_id,
        hearing_id=request.hearing_session_id,
        source_cycle_scope_id=cycle_id,
        source_cycle_scope_sha256=cycle_sha256,
        case_id=case.case_id,
        previous_pack_id=previous.pack_id,
        previous_pack_version=previous.version,
        new_pack_id=update.pack.pack_id,
        new_pack_version=update.pack.version,
        tool_receipt_id=receipt.receipt_id,
        manifest_id=case.manifest_id,
        document_sha256=derivation_sha,
        derivation_document_type="text",
        derivation_document_bytes=derivation_bytes,
    )
    pack_rows = (
        _row(
            document_rowid=107,
            run_id=run_id,
            pack_id=previous.pack_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
            version=previous.version,
            complete=int(previous.complete),
            pack_input_sha256=previous.pack_input_sha256,
            closure_input_sha256=previous.closure_input_sha256,
            document_sha256=previous_sha,
            created_audit_sequence=1,
            pack_document_type="text",
            pack_document_bytes=previous_bytes,
        ),
        _row(
            document_rowid=108,
            run_id=run_id,
            pack_id=update.pack.pack_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
            version=update.pack.version,
            complete=int(update.pack.complete),
            pack_input_sha256=update.pack.pack_input_sha256,
            closure_input_sha256=update.pack.closure_input_sha256,
            document_sha256=resulting_sha,
            created_audit_sequence=2,
            pack_document_type="text",
            pack_document_bytes=resulting_bytes,
        ),
    )
    checkpoint_row = _row(
        support_rowid=109,
        run_id=run_id,
        checkpoint_id=checkpoint_id,
        checkpoint_sha256=checkpoint_sha,
        hearing_id=request.hearing_session_id,
        hearing_sha256=_sha("hearing document"),
        cycle_scope_id=cycle_id,
        cycle_scope_sha256=cycle_sha256,
        case_id=case.case_id,
        version=1,
        phase="ACQUISITION_PENDING",
        judge_cycle=1,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        cycle_pack_id=previous.pack_id,
        cycle_pack_version=previous.version,
        current_pack_id=previous.pack_id,
        current_pack_version=previous.version,
        previous_checkpoint_id=None,
        previous_checkpoint_sha256=None,
        previous_phase="JUDGE_PENDING",
        initial_trigger_review_id=None,
        cycle_trigger_review_id=None,
        retrieval_receipt_id=_sha("retrieval"),
        retrieval_receipt_sha256=_sha("retrieval document"),
        prosecutor_output_id=None,
        defender_output_id=None,
        judge_output_id=request.source_judge_output_id,
        acquisition_request_id=request.request_id,
        tool_receipt_id=None,
        procedural_review_id=None,
        human_review_receipt_id=None,
        human_review_receipt_sha256=None,
        human_review_reason=None,
        manifest_id=case.manifest_id,
        body_commitment_sha256=checkpoint_sha,
        support_document_type="text",
        support_document_bytes=37,
    )
    audit = selected.audit_entry
    previous_case_row = _row(
        support_rowid=112,
        run_id=run_id,
        case_id=case.case_id,
        revision=1,
        status=previous_case.status.value,
        document_sha256=previous_case_sha,
        audit_sequence=1,
        body_commitment_sha256=previous_case_sha,
        support_document_type="text",
        support_document_bytes=previous_case_bytes,
    )
    case_row = _row(
        support_rowid=110,
        run_id=run_id,
        case_id=case.case_id,
        revision=2,
        status=case.status.value,
        document_sha256=selected.case_document_sha256,
        audit_sequence=2,
        body_commitment_sha256=selected.case_document_sha256,
        support_document_type="text",
        support_document_bytes=len(selected.canonical_case_document.encode("utf-8")),
    )
    audit_row = _row(
        support_rowid=111,
        run_id=run_id,
        sequence=audit.sequence,
        manifest_id=case.manifest_id,
        actor=audit.actor,
        action=audit.action.value,
        object_kind=audit.object_ref.kind.value,
        object_id=audit.object_ref.artifact_id,
        before_sha256=audit.before_sha256,
        after_sha256=audit.after_sha256,
        recorded_at=audit.recorded_at,
        prev_entry_hash=audit.prev_entry_hash,
        entry_hash=audit.entry_hash,
        document_sha256=selected.audit_document_sha256,
        body_commitment_sha256=selected.audit_document_sha256,
        support_document_type="text",
        support_document_bytes=len(selected.canonical_audit_document.encode("utf-8")),
    )

    frame_rows = tuple(
        _row(
            support_rowid=200 + index,
            run_id=run_id,
            frame_id=frame.frame_id,
            manifest_id=case.manifest_id,
            camera_id=frame.camera_id,
            stream_id=frame.stream_id,
            frame_index=frame.frame_index,
            fps_num=frame.fps_num,
            fps_den=frame.fps_den,
            width=frame.width,
            height=frame.height,
            content_sha256=frame.content_sha256,
            document_sha256=_document(frame)[0],
        )
        for index, frame in enumerate(execution.output_objects.frames)
    )
    upstream = _upstream_plan(
        selected,
        hearing_id=request.hearing_session_id,
        cycle_id=cycle_id,
        cycle_sha256=cycle_sha256,
        source_request_id=request.source_model_request_ref.artifact_id,
        source_response_id=request.source_model_response_ref.artifact_id,
        judge_output_id=request.source_judge_output_id,
    )
    observations = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                    kind=M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
                    artifact_id=manifest.execution_manifest_id,
                    usage=M6UpgradeArtifactUsage.PRODUCED,
                ),
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                    kind=M6UpgradePhysicalArtifactKind.TOOL_RESULT,
                    artifact_id=result.tool_result_id,
                    usage=M6UpgradeArtifactUsage.PRODUCED,
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    return _Fixture(
        run_id=run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        selected=selected,
        observations=observations,
        upstream=upstream,
        primary=M6SQLiteAcquisitionPrimaryRows(
            requests=(request_row,),
            claims=(claim_row,),
            manifests=(manifest_row,),
            publications=(publication_row,),
            receipts=(receipt_row,),
            derivations=(derivation_row,),
            packs=pack_rows,
        ),
        hearing=M6SQLiteAcquisitionHearingSupportRows(
            checkpoints=(checkpoint_row,),
            rounds=(),
        ),
        transition=M6SQLiteAcquisitionTransitionSupportRows(
            case_versions=(previous_case_row, case_row),
            audits=(audit_row,),
        ),
        outputs=M6SQLiteAcquisitionOutputSupportRows(
            frames=frame_rows,
            detections=(),
            crops=(),
        ),
    )


def _fails(value: _Fixture) -> M6SQLiteAcquisitionPlanFailureCode:
    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as caught:
        value.build()
    return caught.value.reason_code


def test_normalized_completed_acquisition_without_round_builds_one_closure() -> None:
    fixture = _fixture()
    closures = fixture.build()
    assert len(closures) == 1
    assert closures[0].round_id is None
    assert (
        closures[0].acquisition_request_id == fixture.primary.requests[0]["acquisition_request_id"]
    )
    assert (
        closures[0].manifest.component_manifest_id
        == fixture.primary.manifests[0]["component_manifest_id"]
    )
    assert (
        closures[0].manifest.model_manifest_id == fixture.primary.manifests[0]["model_manifest_id"]
    )


@pytest.mark.parametrize("column", ("component_manifest_id", "model_manifest_id"))
def test_manifest_runtime_pin_must_be_strict_sha256(column: str) -> None:
    fixture = _fixture()
    manifest = dict(fixture.primary.manifests[0])
    manifest[column] = "not-a-sha256"
    fixture = replace(
        fixture,
        primary=replace(
            fixture.primary,
            manifests=(_row(**manifest),),
        ),
    )

    assert _fails(fixture) == M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH


def test_pending_claim_fails_closed() -> None:
    fixture = _fixture()
    pending_claim = dict(fixture.primary.claims[0])
    pending_claim.update(
        status="ACTIVE",
        lease_expires_at="2026-08-04T12:14:14.000015Z",
        execution_publication_id=None,
    )
    fixture = replace(
        fixture,
        primary=replace(
            fixture.primary,
            claims=(_row(**pending_claim),),
        ),
    )
    assert _fails(fixture) == M6SQLiteAcquisitionPlanFailureCode.UNSUPPORTED_ACQUISITION_STATE


def test_reverse_orphan_publication_without_request_fails_closed() -> None:
    fixture = _fixture()
    fixture = replace(fixture, primary=replace(fixture.primary, requests=()))
    assert _fails(fixture) in {
        M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH,
        M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH,
    }


def test_complete_post_cut_graph_is_excluded_from_selected_closures() -> None:
    fixture = _fixture()
    # A second complete graph anchored by a future result pack must not change
    # the selected-cut closure.  The production graph owns the full structural
    # check; this fixture clones the already-normalized one-to-one relations.
    suffix = "post-cut"
    request = dict(fixture.primary.requests[0])
    request.update(
        document_rowid=401,
        acquisition_request_id=_sha(f"request {suffix}"),
        evidence_pack_id=fixture.primary.packs[-1]["pack_id"],
        evidence_pack_version=2,
    )
    claim = dict(fixture.primary.claims[0])
    publication = dict(fixture.primary.publications[0])
    manifest = dict(fixture.primary.manifests[0])
    receipt = dict(fixture.primary.receipts[0])
    derivation = dict(fixture.primary.derivations[0])
    new_pack = dict(fixture.primary.packs[-1])
    publication_id = _sha(f"publication {suffix}")
    execution_manifest_id = _sha(f"manifest {suffix}")
    tool_result_id = _sha(f"result {suffix}")
    receipt_id = _sha(f"receipt {suffix}")
    pack_id = _sha(f"pack {suffix}")
    claim.update(
        document_rowid=402,
        acquisition_request_id=request["acquisition_request_id"],
        idempotency_key=request["acquisition_request_id"],
        execution_publication_id=publication_id,
    )
    manifest.update(
        document_rowid=403,
        acquisition_request_id=request["acquisition_request_id"],
        execution_manifest_id=execution_manifest_id,
    )
    publication.update(
        document_rowid=404,
        acquisition_request_id=request["acquisition_request_id"],
        idempotency_key=request["acquisition_request_id"],
        execution_publication_id=publication_id,
        execution_manifest_id=execution_manifest_id,
        tool_result_id=tool_result_id,
    )
    receipt.update(
        document_rowid=405,
        acquisition_request_id=request["acquisition_request_id"],
        execution_manifest_id=execution_manifest_id,
        tool_result_id=tool_result_id,
        receipt_id=receipt_id,
        resulting_pack_id=pack_id,
        resulting_pack_version=3,
    )
    derivation.update(
        document_rowid=406,
        derivation_id=_sha(f"derivation {suffix}"),
        previous_pack_id=fixture.primary.packs[-1]["pack_id"],
        previous_pack_version=2,
        new_pack_id=pack_id,
        new_pack_version=3,
        tool_receipt_id=receipt_id,
    )
    new_pack.update(
        document_rowid=407,
        pack_id=pack_id,
        version=3,
        created_audit_sequence=3,
        document_sha256=_sha(f"pack document {suffix}"),
    )
    checkpoint = dict(fixture.hearing.checkpoints[0])
    checkpoint.update(
        support_rowid=408,
        checkpoint_id=_sha(f"checkpoint {suffix}"),
        checkpoint_sha256=_sha(f"checkpoint document {suffix}"),
        body_commitment_sha256=_sha(f"checkpoint document {suffix}"),
        acquisition_request_id=request["acquisition_request_id"],
        cycle_pack_id=request["evidence_pack_id"],
        cycle_pack_version=request["evidence_pack_version"],
        current_pack_id=request["evidence_pack_id"],
        current_pack_version=request["evidence_pack_version"],
    )
    fixture = replace(
        fixture,
        primary=M6SQLiteAcquisitionPrimaryRows(
            requests=(*fixture.primary.requests, _row(**request)),
            claims=(*fixture.primary.claims, _row(**claim)),
            manifests=(*fixture.primary.manifests, _row(**manifest)),
            publications=(*fixture.primary.publications, _row(**publication)),
            receipts=(*fixture.primary.receipts, _row(**receipt)),
            derivations=(*fixture.primary.derivations, _row(**derivation)),
            packs=(*fixture.primary.packs, _row(**new_pack)),
        ),
        hearing=replace(
            fixture.hearing,
            checkpoints=(*fixture.hearing.checkpoints, _row(**checkpoint)),
        ),
    )
    closures = fixture.build()
    assert len(closures) == 1
    assert closures[0].acquisition_request_id != request["acquisition_request_id"]


def test_upstream_judge_request_response_and_output_must_all_belong_to_m4_plan() -> None:
    fixture = _fixture()
    drifted = dict(fixture.primary.requests[0])
    drifted.update(
        judge_output_id=_sha("drifted Judge output"),
        source_model_request_id=_sha("drifted source request"),
        source_model_response_id=_sha("drifted source response"),
    )
    fixture = replace(
        fixture,
        primary=replace(fixture.primary, requests=(_row(**drifted),)),
    )
    assert _fails(fixture) in {
        M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH,
        M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH,
    }


def test_missing_acquisition_pending_checkpoint_fails_closed() -> None:
    fixture = _fixture()
    fixture = replace(fixture, hearing=replace(fixture.hearing, checkpoints=()))
    assert _fails(fixture) in {
        M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH,
        M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH,
    }


def test_typed_tool_result_outputs_require_targeted_relational_rows() -> None:
    fixture = _fixture(action=AcquisitionAction.REQUEST_MORE_FRAMES)
    assert fixture.outputs.frames
    assert len(fixture.build()) == 1
    missing = replace(fixture, outputs=replace(fixture.outputs, frames=()))
    assert _fails(missing) in {
        M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH,
        M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH,
    }


@pytest.mark.parametrize("missing", ("case_versions", "audits"))
def test_transition_case_and_audit_support_are_both_mandatory(missing: str) -> None:
    fixture = _fixture()
    transition = replace(fixture.transition, **{missing: ()})
    assert _fails(replace(fixture, transition=transition)) in {
        M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH,
        M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH,
    }
