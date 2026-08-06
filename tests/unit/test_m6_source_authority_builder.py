from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from labcourt.application.m6_source_authority import assemble_m6_validated_source_authority
from labcourt.application.m6_source_authority_builder import (
    M6SourceAuthorityBuildError,
    M6SourceAuthorityBuildErrorCode,
    build_m6_sealed_source_bundle,
)
from labcourt.application.m6_source_authority_sealing import M6SealedGateSource
from labcourt.contracts.cases import Case
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6LockedDetectionInput
from labcourt.contracts.m6_source_authority import M6ReplayInputAuthority
from labcourt.contracts.m6_source_authority_store import M6SourceAuthorityDocumentKind
from labcourt.contracts.manifests import RunManifest
from labcourt.ports.m6_source_authority import M6SourceAuthoritySnapshot
from labcourt.ports.m6_source_authority_builder import M6ReplayInputSelection
from tests.unit.test_m6_source_authority import _Bundle, _bundle

_UNSET = object()


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _inputs(
    source: _Bundle,
) -> tuple[
    M6ReplayInputSelection,
    M6SealedGateSource,
    RunManifest,
    M5ArtifactValidationReport,
]:
    case = Case.model_validate_json(source.snapshot.source_case_canonical_document)
    manifest = RunManifest.model_validate_json(source.snapshot.source_manifest_canonical_document)
    report = M5ArtifactValidationReport.model_validate_json(
        source.snapshot.source_validation_report_canonical_document
    )
    authority = M6ReplayInputAuthority.model_validate_json(
        source.snapshot.input_authority_canonical_document
    )
    selection = M6ReplayInputSelection(
        sample_id=source.closure.sample_id,
        source_run_id=source.closure.source_run_id,
        source_case_id=source.closure.source_case_id or "",
        source_case_revision=source.closure.source_case_revision or 0,
        frames=source.closure.frames,
        detections=source.closure.detections,
        model_calls=source.closure.model_calls,
        embeddings=source.closure.embeddings,
        tool_results=source.closure.tool_results,
        historical_cut=source.closure.historical_cut,
    )
    gate_source = M6SealedGateSource(
        source_case=case,
        source_case_revision=selection.source_case_revision,
        source_case_document_sha256=source.snapshot.source_case_document_sha256,
        audit_head_sequence=source.snapshot.audit_head_sequence,
        audit_head_hash=source.snapshot.audit_head_hash,
        gate_current_closures=authority.gate_current_closures,
    )
    return selection, gate_source, manifest, report


def _assert_error(
    code: M6SourceAuthorityBuildErrorCode,
    source: _Bundle,
    *,
    selection: object = _UNSET,
    gate_source: object = _UNSET,
) -> None:
    default_selection, default_gate, manifest, report = _inputs(source)
    with pytest.raises(M6SourceAuthorityBuildError) as raised:
        build_m6_sealed_source_bundle(
            selection=default_selection if selection is _UNSET else selection,
            gate_source=default_gate if gate_source is _UNSET else gate_source,
            source_manifest=manifest,
            source_validation_report=report,
            config=source.config,
        )
    assert raised.value.code == code


def test_builds_final_non_circular_closure_catalog_and_five_document_seal() -> None:
    source = _bundle()
    selection, gate_source, manifest, report = _inputs(source)

    result = build_m6_sealed_source_bundle(
        selection=selection,
        gate_source=gate_source,
        source_manifest=manifest,
        source_validation_report=report,
        config=source.config,
    )

    assert result.replay_input_closure.input_authority_id == (
        result.replay_input_authority.input_authority_id
    )
    assert result.replay_input_closure.input_authority_document_sha256 == (
        result.replay_input_authority.input_authority_document_sha256
    )
    assert len(result.seal.entries) == 5
    authority_entry = next(
        item
        for item in result.seal.entries
        if item.kind == M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY
    )
    assert authority_entry.content_sha256 == _sha(result.replay_input_authority_document)
    assert authority_entry.declared_document_sha256 == (
        result.replay_input_authority.input_authority_document_sha256
    )
    assert authority_entry.content_sha256 != authority_entry.declared_document_sha256

    validated = assemble_m6_validated_source_authority(
        closure=result.replay_input_closure,
        snapshot=M6SourceAuthoritySnapshot(
            source_identity_sha256=_sha("test-source-identity"),
            input_authority_canonical_document=result.replay_input_authority_document,
            source_validation_report_canonical_document=(result.source_validation_report_document),
            source_case_canonical_document=result.source_case_document,
            source_case_document_sha256=result.seal.source_case_document_sha256,
            source_manifest_canonical_document=result.source_manifest_document,
            source_manifest_document_sha256=result.seal.source_manifest_document_sha256,
            source_m4_authority_root_sha256=result.seal.source_m4_authority_root_sha256,
            source_m5_authority_root_sha256=result.seal.source_m5_authority_root_sha256,
            audit_head_sequence=result.seal.audit_head_sequence,
            audit_head_hash=result.seal.audit_head_hash,
        ),
        config=source.config,
    )
    assert validated.input_authority == result.replay_input_authority


def test_rejects_selection_with_detection_outside_frame_inventory() -> None:
    source = _bundle()
    selection, _, _, _ = _inputs(source)
    unknown = M6LockedDetectionInput(
        detection_id="det-unknown",
        frame_id="cam-unknown:stream-unknown:999",
        document_sha256=_sha("unknown-detection-document"),
        model_manifest_id=_sha("unknown-detector-manifest"),
    )
    invalid = replace(selection, detections=(unknown,))

    _assert_error(
        M6SourceAuthorityBuildErrorCode.INPUT_SELECTION_INVALID,
        source,
        selection=invalid,
    )


def test_rejects_source_revision_or_atomic_case_snapshot_mismatch() -> None:
    source = _bundle()
    selection, gate_source, _, _ = _inputs(source)
    wrong_revision = replace(selection, source_case_revision=selection.source_case_revision + 1)
    _assert_error(
        M6SourceAuthorityBuildErrorCode.SOURCE_SCOPE_MISMATCH,
        source,
        selection=wrong_revision,
    )

    wrong_case = replace(
        gate_source,
        source_case_document_sha256=_sha("wrong-case-document"),
    )
    _assert_error(
        M6SourceAuthorityBuildErrorCode.SOURCE_CASE_SNAPSHOT_MISMATCH,
        source,
        gate_source=wrong_case,
    )


def test_rejects_failed_or_head_mismatched_validation_chain() -> None:
    failed = _bundle(failed_m2=True)
    _assert_error(M6SourceAuthorityBuildErrorCode.SOURCE_VALIDATION_CHAIN_INVALID, failed)

    source = _bundle()
    _, gate_source, _, _ = _inputs(source)
    wrong_head = replace(gate_source, audit_head_hash=_sha("other-audit-head"))
    _assert_error(
        M6SourceAuthorityBuildErrorCode.SOURCE_VALIDATION_CHAIN_INVALID,
        source,
        gate_source=wrong_head,
    )


@pytest.mark.parametrize("invalid", [None, "selection", object()])
def test_rejects_untyped_selection(invalid: object) -> None:
    _assert_error(M6SourceAuthorityBuildErrorCode.INVALID_ARGUMENT, _bundle(), selection=invalid)
