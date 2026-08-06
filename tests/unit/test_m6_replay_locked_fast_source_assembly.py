from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from labcourt.application.m6_replay_locked_fast_source import (
    M6ReplayLockedFastSourceError,
    M6ReplayLockedFastSourceErrorCode,
    assemble_m6_replay_locked_fast_terminal_source,
)
from labcourt.application.m6_source_authority import (
    M6ValidatedSourceAuthority,
    assemble_m6_validated_source_authority,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_source_authority import (
    M6GateCurrentClosureBasis,
    M6GateCurrentClosureReceipt,
    M6ReplayInputAuthority,
)
from labcourt.ports.m6_perception import (
    M6DetectionAuthorityDocument,
    M6FrameAuthorityDocument,
    M6PerceptionAuthoritySnapshot,
)
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
)
from tests.unit.test_m6_model_call_authority import _response_snapshot
from tests.unit.test_m6_model_reference_authority import _repair_snapshot
from tests.unit.test_m6_replay_locked_execution_scope import _inputs
from tests.unit.test_m6_replay_locked_fast_source import _terminal_source
from tests.unit.test_m6_source_authority import _bundle, _verification


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document(value: object) -> tuple[str, str]:
    raw = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    return raw, _sha(raw)


def _assembly_inputs(
    m3_snapshot: object | None = None,
) -> tuple[
    M6ReplayInputClosureAuthority,
    M6PerceptionAuthoritySnapshot,
    object,
    M6ValidatedSourceAuthority,
    object,
]:
    execution = _inputs()
    config = execution["locked_config"]
    manifest = execution["locked_manifest"]
    m3 = m3_snapshot or _repair_snapshot()
    base = _terminal_source(
        gate_config=config.procedural_gate,  # type: ignore[union-attr]
        alert_config=config.alerts,  # type: ignore[union-attr]
        m3_snapshot=m3,  # type: ignore[arg-type]
    )
    case = base.projection_context.case
    pack = case.evidence_packs[0]
    review = case.procedural_reviews[0]
    source_gate = base.projection_context.procedural_gate_authority.inputs[0]
    report_source = _bundle()
    validated_report_source = assemble_m6_validated_source_authority(
        closure=report_source.closure,
        snapshot=report_source.snapshot,
        config=report_source.config,
    )
    report = validated_report_source.source_validation_report
    report_raw, report_sha = _document(report)
    assert report_raw
    case_raw, case_sha = _document(case)
    manifest_raw, manifest_sha = _document(manifest)
    receipt = M6GateCurrentClosureReceipt(
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        review_version=review.version,
        source_review_id=review.review_id,
        source_review_document_sha256=_document(review)[1],
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        evidence_pack_document_sha256=_document(pack)[1],
        basis=M6GateCurrentClosureBasis.CURRENT_PRIVACY_CROP_REVERIFIED,
        current_closure=source_gate.current_closure,
        crop_verifications=tuple(_verification(crop) for crop in pack.crops),
    )
    source_m4_root = report.predecessor_report.authority_root_sha256
    authority = M6ReplayInputAuthority(
        sample_id=base.closure.sample_id,
        source_run_id=case.run_id,
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_document_sha256=case_sha,
        source_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        source_manifest_document_sha256=manifest_sha,
        source_config_sha256=config.config_sha256,  # type: ignore[union-attr]
        source_m4_authority_root_sha256=source_m4_root,
        source_m5_authority_root_sha256=report.authority_root_sha256,
        source_validation_report_id=report.report_id,
        source_validation_report_document_sha256=report_sha,
        frame_inventory_root_sha256=base.closure.frame_inventory_root_sha256,
        detection_inventory_root_sha256=(base.closure.detection_inventory_root_sha256),
        model_call_inventory_root_sha256=(base.closure.model_call_inventory_root_sha256),
        embedding_inventory_root_sha256=(base.closure.embedding_inventory_root_sha256),
        tool_result_inventory_root_sha256=(base.closure.tool_result_inventory_root_sha256),
        historical_causal_cut_id=base.closure.historical_cut.causal_cut_id,
        gate_current_closures=(receipt,),
    )
    closure = M6ReplayInputClosureAuthority.model_validate(
        {
            **base.closure.model_dump(mode="json", exclude_computed_fields=True),
            "source_case_document_sha256": case_sha,
            "source_manifest_document_sha256": manifest_sha,
            "input_authority_id": authority.input_authority_id,
            "input_authority_document_sha256": (authority.input_authority_document_sha256),
            "source_validation_report_id": report.report_id,
            "source_validation_report_document_sha256": report_sha,
        }
    )
    identity = m3.source_identity_sha256
    source = M6ValidatedSourceAuthority(
        source_identity_sha256=identity,
        input_authority=authority,
        source_validation_report=report,
        source_case=case,
        source_manifest=manifest,  # type: ignore[arg-type]
    )
    frame_documents = []
    for frame in base.projection_context.perception.frames:
        raw, document_sha = _document(frame)
        assert frame.content_sha256 is not None
        frame_documents.append(
            M6FrameAuthorityDocument(
                run_id=case.run_id,
                manifest_id=case.manifest_id,
                frame_id=frame.frame_id,
                content_sha256=frame.content_sha256,
                canonical_document=raw,
                document_sha256=document_sha,
            )
        )
    detection_documents = []
    for detection in base.projection_context.perception.detections:
        raw, document_sha = _document(detection)
        detection_documents.append(
            M6DetectionAuthorityDocument(
                run_id=case.run_id,
                manifest_id=case.manifest_id,
                detection_id=detection.detection_id,
                frame_id=detection.frame_id,
                model_manifest_id=detection.model_manifest_id,
                canonical_document=raw,
                document_sha256=document_sha,
            )
        )
    perception = M6PerceptionAuthoritySnapshot(
        source_identity_sha256=identity,
        run_id=case.run_id,
        manifest_id=case.manifest_id,
        manifest_canonical_document=manifest_raw,
        manifest_document_sha256=manifest_sha,
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_canonical_document=case_raw,
        source_case_document_sha256=case_sha,
        frames=tuple(frame_documents),
        detections=tuple(detection_documents),
    )
    sealed = M6ReplayLockedFastTerminalSource(
        source_identity_sha256=identity,
        closure=closure,
        projection_context=base.projection_context,
        source_snapshot=base.source_snapshot,
    )
    assert sealed.closure == closure
    return closure, perception, m3, source, config


def test_assembler_rebuilds_repair_history_gate_and_artifact_bounds() -> None:
    closure, perception, m3, source, config = _assembly_inputs()

    assembled = assemble_m6_replay_locked_fast_terminal_source(
        closure=closure,
        perception_snapshot=perception,
        m3_snapshot=m3,
        source_authority=source,
        config=config,
    )

    gate = assembled.projection_context.procedural_gate_authority.inputs[0]
    assert assembled.closure == closure
    assert len(assembled.projection_context.model_responses) == 2
    assert {bound.artifact_ref.kind.value for bound in gate.artifact_bounds} == {
        "CROP",
        "FRAME",
    }
    assert gate.rebuild_review() == assembled.projection_context.case.procedural_reviews[0]


def test_assembler_accepts_one_direct_terminal_parse() -> None:
    _case, direct = _response_snapshot()
    closure, perception, m3, source, config = _assembly_inputs(direct)

    assembled = assemble_m6_replay_locked_fast_terminal_source(
        closure=closure,
        perception_snapshot=perception,
        m3_snapshot=m3,
        source_authority=source,
        config=config,
    )

    assert len(assembled.projection_context.model_responses) == 1
    assert len(assembled.projection_context.case.verdicts[0].model_response_refs) == 1


def test_assembler_rejects_a_cross_snapshot_m3_graft() -> None:
    closure, perception, m3, source, config = _assembly_inputs()
    foreign_m3 = replace(m3, source_identity_sha256="f" * 64)

    with pytest.raises(M6ReplayLockedFastSourceError) as raised:
        assemble_m6_replay_locked_fast_terminal_source(
            closure=closure,
            perception_snapshot=perception,
            m3_snapshot=foreign_m3,
            source_authority=source,
            config=config,
        )

    assert raised.value.code == M6ReplayLockedFastSourceErrorCode.SNAPSHOT_IDENTITY_MISMATCH


def test_assembler_rejects_an_incomplete_repair_receipt_history() -> None:
    closure, perception, m3, source, config = _assembly_inputs()
    incomplete = replace(m3, parse_receipts=m3.parse_receipts[1:])

    with pytest.raises(M6ReplayLockedFastSourceError) as raised:
        assemble_m6_replay_locked_fast_terminal_source(
            closure=closure,
            perception_snapshot=perception,
            m3_snapshot=incomplete,
            source_authority=source,
            config=config,
        )

    assert raised.value.code == M6ReplayLockedFastSourceErrorCode.MODEL_CALL_CLOSURE_MISMATCH
