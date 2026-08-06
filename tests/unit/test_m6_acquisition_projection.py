"""Adversarial tests for locked M6 acquisition semantic projection."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import BaseModel

from labcourt.adapters.storage.readonly_m6_acquisition_authority import (
    ReadonlyM6AcquisitionAuthorityRepository,
)
from labcourt.application.m6_acquisition_projection import (
    M6AcquisitionProjectionError,
    M6AcquisitionProjectionErrorCode,
    resolve_m6_locked_acquisitions,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    ArtifactKind,
    CaseStatus,
)
from labcourt.contracts.evidence import (
    EvidencePack,
    EvidencePackDraft,
    RequestMoreFramesParameters,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing_acquisition import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
)
from labcourt.contracts.hearing_persistence import EvidencePackDerivation
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot, M6RegressionStage
from labcourt.contracts.m6_replay_locked import (
    M6LockedToolResultInput,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
)
from labcourt.domain.evidence_authority import AcquisitionExecution
from labcourt.domain.m6_model_reference_authority import (
    M6CaseModelReferenceAuthority,
)
from labcourt.domain.m6_procedural_gate_authority import M6CaseProceduralGateAuthority
from labcourt.domain.m6_semantic_projection import (
    M6ResolvedAcquisition,
    M6ResolvedPerception,
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
)
from labcourt.ports.m6_acquisition_authority import (
    M6ValidatedM4ReplayAuthoritySnapshot,
)
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument
from tests.unit.test_m4_evidence_authority import (
    _close,
    _execution,
    _finalize,
    _pack,
)


def _document_sha256(document: BaseModel) -> str:
    return hashlib.sha256(
        canonical_json(document.model_dump(mode="json")).encode("utf-8")
    ).hexdigest()


def _empty_gate_authority(
    case: Case,
    *,
    source_identity_sha256: str,
) -> M6CaseProceduralGateAuthority:
    return M6CaseProceduralGateAuthority(
        source_identity_sha256=source_identity_sha256,
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
    )


def _authority_ref(
    kind: M6ReplayAuthorityKind,
    artifact_id: str,
    document: BaseModel,
) -> M6ReplayAuthorityRef:
    return M6ReplayAuthorityRef(
        kind=kind,
        artifact_id=artifact_id,
        document_sha256=_document_sha256(document),
    )


def _base_pack(run_id: str) -> EvidencePack:
    reference = _pack()
    if reference.run_id == run_id:
        return reference
    payload = reference.model_dump(mode="json", exclude_computed_fields=True)
    payload.pop("closure_report")
    payload["run_id"] = run_id
    return _close(EvidencePackDraft.model_validate(payload))


def _publication(
    execution: AcquisitionExecution,
    *,
    frame_content_sha256: str | None = None,
    owner_sha256: str = "a" * 64,
    fence: int = 1,
) -> AcquisitionExecutionPublication:
    frames = execution.output_objects.frames
    if frame_content_sha256 is not None:
        assert len(frames) == 1
        frames = (frames[0].model_copy(update={"content_sha256": frame_content_sha256}),)
    return AcquisitionExecutionPublication(
        request=execution.request,
        execution_manifest=execution.execution_manifest,
        tool_result=execution.tool_result,
        frames=frames,
        crops=execution.output_objects.crops,
        objective_facts=execution.output_objects.objective_facts,
        detections=execution.output_objects.detections,
        crop_request=execution.crop_request,
        execution_mode=AcquisitionExecutionMode.PURE,
        idempotency_key=execution.request.request_id,
        claim_owner_sha256=owner_sha256,
        claim_fence=fence,
    )


def _m4_document(
    kind: M4ProjectionArtifactKind,
    artifact_id: str,
    document: BaseModel,
) -> M6HistoricalAuthorityDocument:
    return M6HistoricalAuthorityDocument(
        kind=kind,
        artifact_id=artifact_id,
        canonical_document=canonical_json(document.model_dump(mode="json")),
    )


def _perception(case: Case) -> M6ResolvedPerception:
    frame_id = f"{case.event.camera_id}:{case.event.stream_id}:{case.event.trigger_frame}"
    camera_id, stream_id, frame_index = frame_id.split(":")
    frame = FrameRef(
        camera_id=camera_id,
        stream_id=stream_id,
        frame_index=int(frame_index),
        fps_num=30,
        fps_den=1,
        width=1920,
        height=1080,
        content_sha256=hashlib.sha256(frame_id.encode("utf-8")).hexdigest(),
    )
    detections_by_id: dict[str, Detection] = {}
    for pack in case.evidence_packs:
        for crop in pack.crops:
            for ref in crop.source_refs:
                if ref.kind != ArtifactKind.DETECTION:
                    continue
                detection = Detection(
                    detection_id=ref.artifact_id,
                    frame_id=crop.frame_id,
                    label="fixture-source-object",
                    bbox=crop.bbox,
                    score=1.0,
                    track_ref=crop.primary_track_ref,
                    model_manifest_id=case.manifest_id,
                )
                previous = detections_by_id.get(ref.artifact_id)
                if previous is not None:
                    assert previous == detection
                detections_by_id[ref.artifact_id] = detection
    return M6ResolvedPerception(
        frames=(frame,),
        detections=tuple(sorted(detections_by_id.values(), key=lambda item: item.detection_id)),
    )


def _empty_model_reference_authority(
    case: Case,
    *,
    source_identity_sha256: str,
) -> M6CaseModelReferenceAuthority:
    return M6CaseModelReferenceAuthority(
        source_identity_sha256=source_identity_sha256,
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        screening_bindings=(),
        verdict_bindings=(),
    )


def _bundle(
    *,
    run_id: str = "run-m4",
    action: AcquisitionAction = AcquisitionAction.TRACK_CONFIDENCE_CURVE,
    parameters: object | None = None,
    frame_content_sha256: str | None = None,
    owner_sha256: str = "a" * 64,
    fence: int = 1,
) -> tuple[
    Case,
    M6ValidatedM4ReplayAuthoritySnapshot,
    M6LockedToolResultInput,
]:
    previous = _base_pack(run_id)
    execution = _execution(previous, action, parameters=parameters)
    update = _finalize(previous, execution)
    publication = _publication(
        execution,
        frame_content_sha256=frame_content_sha256,
        owner_sha256=owner_sha256,
        fence=fence,
    )
    receipt = update.receipt
    derivation = EvidencePackDerivation(
        run_id=run_id,
        case_id=previous.case_id,
        hearing_session_id=execution.request.hearing_session_id,
        source_cycle_scope_id="b" * 64,
        source_cycle_scope_sha256="c" * 64,
        previous_evidence_pack_id=previous.pack_id,
        previous_evidence_pack_version=previous.version,
        new_evidence_pack_id=update.pack.pack_id,
        new_evidence_pack_version=update.pack.version,
        tool_execution_receipt_id=receipt.receipt_id,
        manifest_id=previous.manifest_id,
    )
    case = Case(
        run_id=run_id,
        status=CaseStatus.EVIDENCE_READY,
        event=previous.event,
        evidence_packs=(previous, update.pack),
        manifest_id=previous.manifest_id,
    )
    locked = M6LockedToolResultInput(
        tool_result_id=execution.tool_result.tool_result_id,
        tool_result_document_sha256=_document_sha256(execution.tool_result),
        acquisition_request_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_ACQUISITION_REQUEST,
            execution.request.request_id,
            execution.request,
        ),
        execution_manifest_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_TOOL_EXECUTION_MANIFEST,
            execution.execution_manifest.execution_manifest_id,
            execution.execution_manifest,
        ),
        execution_publication_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_ACQUISITION_PUBLICATION,
            publication.publication_id,
            publication,
        ),
        tool_receipt_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_TOOL_EXECUTION_RECEIPT,
            receipt.receipt_id,
            receipt,
        ),
        evidence_pack_derivation_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_EVIDENCE_PACK_DERIVATION,
            derivation.derivation_id,
            derivation,
        ),
        resulting_evidence_pack_ref=_authority_ref(
            M6ReplayAuthorityKind.EVIDENCE_PACK,
            update.pack.pack_id,
            update.pack,
        ),
    )
    documents = tuple(
        sorted(
            (
                _m4_document(
                    M4ProjectionArtifactKind.ACQUISITION_REQUEST,
                    execution.request.request_id,
                    execution.request,
                ),
                _m4_document(
                    M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST,
                    execution.execution_manifest.execution_manifest_id,
                    execution.execution_manifest,
                ),
                _m4_document(
                    M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION,
                    publication.publication_id,
                    publication,
                ),
                _m4_document(
                    M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
                    receipt.receipt_id,
                    receipt,
                ),
                _m4_document(
                    M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION,
                    derivation.derivation_id,
                    derivation,
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    snapshot = M6ValidatedM4ReplayAuthoritySnapshot(
        source_identity_sha256="d" * 64,
        run_id=run_id,
        documents=documents,
    )
    return case, snapshot, locked


def _snapshot(
    case: Case,
    authority: M6ValidatedM4ReplayAuthoritySnapshot,
    locked: M6LockedToolResultInput,
):
    acquisitions = resolve_m6_locked_acquisitions(
        source_case=case,
        snapshot=authority,
        locked_tool_results=(locked,),
    )
    return build_m6_case_replay_snapshot(
        context=M6VerifiedProjectionContext(
            case=case,
            perception=_perception(case),
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=_empty_model_reference_authority(
                case,
                source_identity_sha256=authority.source_identity_sha256,
            ),
            procedural_gate_authority=_empty_gate_authority(
                case,
                source_identity_sha256=authority.source_identity_sha256,
            ),
            acquisitions=acquisitions,
        ),
        sample_id="acquisition-sample",
        source_case_revision=1,
    )


def _changed_stages(
    baseline: M6CaseReplaySnapshot,
    candidate: M6CaseReplaySnapshot,
) -> tuple[M6RegressionStage, ...]:
    return tuple(
        candidate_root.stage
        for baseline_root, candidate_root in zip(
            baseline.stage_roots,
            candidate.stage_roots,
            strict=True,
        )
        if baseline_root != candidate_root
    )


def test_cross_run_acquisition_ids_resolve_to_identical_content_semantics() -> None:
    baseline_case, baseline_authority, baseline_locked = _bundle(run_id="run-m4")
    candidate_case, candidate_authority, candidate_locked = _bundle(run_id="candidate-run")

    baseline = _snapshot(baseline_case, baseline_authority, baseline_locked)
    candidate = _snapshot(candidate_case, candidate_authority, candidate_locked)

    assert candidate_locked.tool_result_id != baseline_locked.tool_result_id
    assert candidate.source_case_document_sha256 != baseline.source_case_document_sha256
    assert candidate.stage_roots == baseline.stage_roots
    assert candidate.semantic_case_hash == baseline.semantic_case_hash


def test_case_without_acquisition_remains_a_valid_empty_projection() -> None:
    pack = _base_pack("run-m4")
    case = Case(
        run_id=pack.run_id,
        status=CaseStatus.EVIDENCE_READY,
        event=pack.event,
        evidence_packs=(pack,),
        manifest_id=pack.manifest_id,
    )
    authority = M6ValidatedM4ReplayAuthoritySnapshot(
        source_identity_sha256="d" * 64,
        run_id=case.run_id,
        documents=(),
    )

    assert (
        resolve_m6_locked_acquisitions(
            source_case=case,
            snapshot=authority,
            locked_tool_results=(),
        )
        == ()
    )


def test_readonly_adapter_rejects_forged_case_before_snapshot_access(
    tmp_path: Path,
) -> None:
    case, _authority, _locked = _bundle()
    forged = Case.model_validate(case.model_dump(mode="json", exclude_computed_fields=True))
    object.__setattr__(forged, "run_id", "")
    repository = ReadonlyM6AcquisitionAuthorityRepository(tmp_path / "missing.sqlite3")

    with (
        patch.object(
            ReadonlyM6AcquisitionAuthorityRepository,
            "load_validated_snapshot",
            autospec=True,
        ) as load,
        pytest.raises(M6AcquisitionProjectionError) as raised,
    ):
        repository.resolve(source_case=forged, locked_tool_results=())

    assert raised.value.code == M6AcquisitionProjectionErrorCode.INVALID_ARGUMENT
    load.assert_not_called()


def test_publication_owner_fence_and_raw_publication_id_are_not_semantic() -> None:
    case, baseline_authority, baseline_locked = _bundle()
    candidate_case, candidate_authority, candidate_locked = _bundle(
        owner_sha256="e" * 64,
        fence=9,
    )

    baseline = _snapshot(case, baseline_authority, baseline_locked)
    candidate = _snapshot(candidate_case, candidate_authority, candidate_locked)

    assert (
        candidate_locked.execution_publication_ref.artifact_id
        != baseline_locked.execution_publication_ref.artifact_id
    )
    assert candidate.stage_roots == baseline.stage_roots


def test_acquisition_parameter_change_moves_only_hearing() -> None:
    baseline_case, baseline_authority, baseline_locked = _bundle(
        action=AcquisitionAction.REQUEST_MORE_FRAMES
    )
    changed_parameters = RequestMoreFramesParameters(
        action=AcquisitionAction.REQUEST_MORE_FRAMES,
        camera_id=baseline_case.event.camera_id,
        stream_id=baseline_case.event.stream_id,
        start_frame=92,
        end_frame_exclusive=93,
    )
    candidate_case, candidate_authority, candidate_locked = _bundle(
        action=AcquisitionAction.REQUEST_MORE_FRAMES,
        parameters=changed_parameters,
    )

    baseline = _snapshot(baseline_case, baseline_authority, baseline_locked)
    candidate = _snapshot(candidate_case, candidate_authority, candidate_locked)

    assert _changed_stages(baseline, candidate) == (M6RegressionStage.HEARING,)


def test_new_evidence_content_change_moves_only_hearing() -> None:
    baseline_case, baseline_authority, baseline_locked = _bundle(
        action=AcquisitionAction.REQUEST_MORE_FRAMES,
        frame_content_sha256="1" * 64,
    )
    candidate_case, candidate_authority, candidate_locked = _bundle(
        action=AcquisitionAction.REQUEST_MORE_FRAMES,
        frame_content_sha256="2" * 64,
    )

    baseline = _snapshot(baseline_case, baseline_authority, baseline_locked)
    candidate = _snapshot(candidate_case, candidate_authority, candidate_locked)

    assert _changed_stages(baseline, candidate) == (M6RegressionStage.HEARING,)


def test_missing_and_extra_acquisition_documents_fail_closed() -> None:
    case, authority, locked = _bundle()
    missing = M6ValidatedM4ReplayAuthoritySnapshot(
        source_identity_sha256=authority.source_identity_sha256,
        run_id=authority.run_id,
        documents=tuple(
            item
            for item in authority.documents
            if item.kind != M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST
        ),
    )
    with pytest.raises(M6AcquisitionProjectionError) as missing_error:
        resolve_m6_locked_acquisitions(
            source_case=case,
            snapshot=missing,
            locked_tool_results=(locked,),
        )
    assert missing_error.value.code == M6AcquisitionProjectionErrorCode.DOCUMENT_MISSING

    original_request = next(
        item
        for item in authority.documents
        if item.kind == M4ProjectionArtifactKind.ACQUISITION_REQUEST
    )
    parsed = AcquisitionRequest.model_validate_json(original_request.canonical_document)
    extra_request = parsed.model_copy(
        update={
            "request_payload": parsed.request_payload.model_copy(
                update={"reason_summary": "Another bounded acquisition intent."}
            )
        }
    )
    extra_document = _m4_document(
        M4ProjectionArtifactKind.ACQUISITION_REQUEST,
        extra_request.request_id,
        extra_request,
    )
    extra = M6ValidatedM4ReplayAuthoritySnapshot(
        source_identity_sha256=authority.source_identity_sha256,
        run_id=authority.run_id,
        documents=tuple(
            sorted((*authority.documents, extra_document), key=lambda item: item.sort_key)
        ),
    )
    with pytest.raises(M6AcquisitionProjectionError) as extra_error:
        resolve_m6_locked_acquisitions(
            source_case=case,
            snapshot=extra,
            locked_tool_results=(locked,),
        )
    assert extra_error.value.code == M6AcquisitionProjectionErrorCode.EXTRA_AUTHORITY_DOCUMENT


def test_foreign_and_forged_acquisition_authority_fail_closed() -> None:
    case, authority, locked = _bundle()
    foreign = M6ValidatedM4ReplayAuthoritySnapshot(
        source_identity_sha256=authority.source_identity_sha256,
        run_id="foreign-run",
        documents=authority.documents,
    )
    with pytest.raises(M6AcquisitionProjectionError) as foreign_error:
        resolve_m6_locked_acquisitions(
            source_case=case,
            snapshot=foreign,
            locked_tool_results=(locked,),
        )
    assert foreign_error.value.code == M6AcquisitionProjectionErrorCode.SNAPSHOT_RUN_MISMATCH

    forged_ref = locked.execution_manifest_ref.model_construct(
        kind=locked.execution_manifest_ref.kind,
        artifact_id=locked.execution_manifest_ref.artifact_id,
        document_sha256="f" * 64,
    )
    forged = M6LockedToolResultInput.model_construct(
        tool_result_id=locked.tool_result_id,
        tool_result_document_sha256=locked.tool_result_document_sha256,
        acquisition_request_ref=locked.acquisition_request_ref,
        execution_manifest_ref=forged_ref,
        execution_publication_ref=locked.execution_publication_ref,
        tool_receipt_ref=locked.tool_receipt_ref,
        evidence_pack_derivation_ref=locked.evidence_pack_derivation_ref,
        resulting_evidence_pack_ref=locked.resulting_evidence_pack_ref,
    )
    with pytest.raises(M6AcquisitionProjectionError) as forged_error:
        resolve_m6_locked_acquisitions(
            source_case=case,
            snapshot=authority,
            locked_tool_results=(forged,),
        )
    assert forged_error.value.code in {
        M6AcquisitionProjectionErrorCode.INVALID_ARGUMENT,
        M6AcquisitionProjectionErrorCode.CLOSURE_INVALID,
    }


def test_context_rejects_missing_or_extra_resolved_tool_authority() -> None:
    case, authority, locked = _bundle()
    resolved = resolve_m6_locked_acquisitions(
        source_case=case,
        snapshot=authority,
        locked_tool_results=(locked,),
    )

    with pytest.raises(ValueError, match="exactly cover Case ToolResults"):
        M6VerifiedProjectionContext(
            case=case,
            perception=_perception(case),
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=_empty_model_reference_authority(
                case,
                source_identity_sha256=authority.source_identity_sha256,
            ),
            procedural_gate_authority=_empty_gate_authority(
                case,
                source_identity_sha256=authority.source_identity_sha256,
            ),
        )

    assert isinstance(resolved[0], M6ResolvedAcquisition)
    projection = canonical_json(resolved[0].semantic_projection())
    forbidden_operational_values = (
        locked.tool_result_id,
        locked.acquisition_request_ref.artifact_id,
        locked.execution_manifest_ref.artifact_id,
        locked.execution_publication_ref.artifact_id,
        locked.tool_receipt_ref.artifact_id,
        locked.evidence_pack_derivation_ref.artifact_id,
        locked.resulting_evidence_pack_ref.artifact_id,
        resolved[0].request.run_id,
        resolved[0].request.case_id,
        resolved[0].request.hearing_session_id,
        resolved[0].execution_manifest.component_manifest_id,
        resolved[0].publication.claim_owner_sha256,
    )
    assert all(value not in projection for value in forbidden_operational_values)
