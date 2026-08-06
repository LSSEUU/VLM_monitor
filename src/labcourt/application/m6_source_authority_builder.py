"""Build the final replay closure, source catalog, and immutable seal."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_source_authority import (
    M6SourceAuthorityError,
    assemble_m6_validated_source_authority,
)
from labcourt.application.m6_source_authority_sealing import M6SealedGateSource
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_source_authority import M6ReplayInputAuthority
from labcourt.contracts.m6_source_authority_store import (
    M6SourceAuthorityDocumentEntry,
    M6SourceAuthorityDocumentKind,
    M6SourceAuthoritySeal,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_source_authority import M6SourceAuthoritySnapshot
from labcourt.ports.m6_source_authority_builder import M6ReplayInputSelection

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6SourceAuthorityBuildErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INPUT_SELECTION_INVALID = "INPUT_SELECTION_INVALID"
    SOURCE_SCOPE_MISMATCH = "SOURCE_SCOPE_MISMATCH"
    SOURCE_CASE_SNAPSHOT_MISMATCH = "SOURCE_CASE_SNAPSHOT_MISMATCH"
    SOURCE_VALIDATION_FAILED = "SOURCE_VALIDATION_FAILED"
    SOURCE_VALIDATION_CHAIN_INVALID = "SOURCE_VALIDATION_CHAIN_INVALID"
    PRODUCER_INVARIANT_VIOLATION = "PRODUCER_INVARIANT_VIOLATION"


class M6SourceAuthorityBuildError(LabCourtError):
    """The source documents could not produce one complete M6 authority bundle."""

    def __init__(self, code: M6SourceAuthorityBuildErrorCode) -> None:
        if not isinstance(code, M6SourceAuthorityBuildErrorCode):
            raise TypeError("code must be an M6SourceAuthorityBuildErrorCode")
        self.code = code
        super().__init__(f"M6 source authority build failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6SealedSourceBundle:
    replay_input_closure: M6ReplayInputClosureAuthority
    replay_input_authority: M6ReplayInputAuthority
    source_validation_report: M5ArtifactValidationReport
    source_case: Case
    source_manifest: RunManifest
    seal: M6SourceAuthoritySeal
    replay_input_closure_document: str
    replay_input_authority_document: str
    source_validation_report_document: str
    source_case_document: str
    source_manifest_document: str

    def document_for(self, kind: M6SourceAuthorityDocumentKind) -> str:
        documents = {
            M6SourceAuthorityDocumentKind.REPLAY_INPUT_CLOSURE: (
                self.replay_input_closure_document
            ),
            M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY: (
                self.replay_input_authority_document
            ),
            M6SourceAuthorityDocumentKind.SOURCE_VALIDATION_REPORT: (
                self.source_validation_report_document
            ),
            M6SourceAuthorityDocumentKind.SOURCE_CASE: self.source_case_document,
            M6SourceAuthorityDocumentKind.SOURCE_MANIFEST: self.source_manifest_document,
        }
        if not isinstance(kind, M6SourceAuthorityDocumentKind):
            raise TypeError("kind must be an M6SourceAuthorityDocumentKind")
        return documents[kind]

    @property
    def seal_document(self) -> str:
        return canonical_json(self.seal.model_dump(mode="json"))


def _fail(code: M6SourceAuthorityBuildErrorCode) -> NoReturn:
    raise M6SourceAuthorityBuildError(code)


def _canonical_model(
    value: object,
    model_type: type[_ModelT],
    code: M6SourceAuthorityBuildErrorCode,
) -> _ModelT:
    if not isinstance(value, model_type):
        _fail(M6SourceAuthorityBuildErrorCode.INVALID_ARGUMENT)
    try:
        controlled = model_type.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(code)
    if controlled != value:
        _fail(code)
    return controlled


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _document_sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _inventory_roots(selection: M6ReplayInputSelection) -> dict[str, str]:
    return {
        "frame": sha256_hex(
            ["m6-locked-frame-inventory", 1, [item.frame_input_id for item in selection.frames]]
        ),
        "detection": sha256_hex(
            [
                "m6-locked-detection-inventory",
                1,
                [item.detection_input_id for item in selection.detections],
            ]
        ),
        "model_call": sha256_hex(
            [
                "m6-locked-model-call-inventory",
                1,
                [item.model_call_input_id for item in selection.model_calls],
            ]
        ),
        "embedding": sha256_hex(
            [
                "m6-locked-embedding-inventory",
                1,
                [item.embedding_input_id for item in selection.embeddings],
            ]
        ),
        "tool_result": sha256_hex(
            [
                "m6-locked-tool-result-inventory",
                1,
                [item.tool_result_input_id for item in selection.tool_results],
            ]
        ),
    }


def _entry(
    *,
    kind: M6SourceAuthorityDocumentKind,
    artifact_id: str,
    declared_document_sha256: str,
    document: str,
) -> M6SourceAuthorityDocumentEntry:
    payload = document.encode("utf-8")
    return M6SourceAuthorityDocumentEntry(
        kind=kind,
        artifact_id=artifact_id,
        declared_document_sha256=declared_document_sha256,
        content_sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
    )


def build_m6_sealed_source_bundle(
    *,
    selection: object,
    gate_source: object,
    source_manifest: object,
    source_validation_report: object,
    config: object,
) -> M6SealedSourceBundle:
    """Bind non-circular replay inputs to one exact passing M0--M5 source cut."""

    if not isinstance(selection, M6ReplayInputSelection) or not isinstance(
        gate_source, M6SealedGateSource
    ):
        _fail(M6SourceAuthorityBuildErrorCode.INVALID_ARGUMENT)
    manifest = _canonical_model(
        source_manifest,
        RunManifest,
        M6SourceAuthorityBuildErrorCode.SOURCE_SCOPE_MISMATCH,
    )
    report = _canonical_model(
        source_validation_report,
        M5ArtifactValidationReport,
        M6SourceAuthorityBuildErrorCode.SOURCE_VALIDATION_FAILED,
    )
    controlled_config = _canonical_model(
        config,
        AppConfig,
        M6SourceAuthorityBuildErrorCode.SOURCE_SCOPE_MISMATCH,
    )
    case = _canonical_model(
        gate_source.source_case,
        Case,
        M6SourceAuthorityBuildErrorCode.SOURCE_CASE_SNAPSHOT_MISMATCH,
    )
    case_document = _document(case)
    manifest_document = _document(manifest)
    report_document = _document(report)
    if (
        selection.source_run_id != case.run_id
        or selection.source_case_id != case.case_id
        or selection.source_case_revision != gate_source.source_case_revision
        or manifest.manifest_id != case.manifest_id
        or manifest.config_sha256 != controlled_config.config_sha256
        or report.run_id != case.run_id
        or report.manifest_id != manifest.manifest_id
        or report.config_sha256 != controlled_config.config_sha256
    ):
        _fail(M6SourceAuthorityBuildErrorCode.SOURCE_SCOPE_MISMATCH)
    if _document_sha256(case_document) != gate_source.source_case_document_sha256:
        _fail(M6SourceAuthorityBuildErrorCode.SOURCE_CASE_SNAPSHOT_MISMATCH)
    if not report.passed or not isinstance(report.predecessor_report, M4ArtifactValidationReport):
        _fail(M6SourceAuthorityBuildErrorCode.SOURCE_VALIDATION_FAILED)
    m4_report = report.predecessor_report
    m3_report = m4_report.m3_report
    m2_report = m3_report.m2_report
    if (
        not m4_report.passed
        or not m3_report.passed
        or not m2_report.passed
        or m4_report.authority_root_sha256 is None
        or report.authority_root_sha256 is None
        or m2_report.audit_head_sequence != gate_source.audit_head_sequence
        or m2_report.audit_head_hash != gate_source.audit_head_hash
    ):
        _fail(M6SourceAuthorityBuildErrorCode.SOURCE_VALIDATION_CHAIN_INVALID)

    roots = _inventory_roots(selection)
    report_sha256 = _document_sha256(report_document)
    manifest_sha256 = _document_sha256(manifest_document)
    try:
        input_authority = M6ReplayInputAuthority(
            sample_id=selection.sample_id,
            source_run_id=selection.source_run_id,
            source_case_id=selection.source_case_id,
            source_case_revision=selection.source_case_revision,
            source_case_document_sha256=gate_source.source_case_document_sha256,
            source_manifest_id=manifest.manifest_id,
            source_manifest_document_sha256=manifest_sha256,
            source_config_sha256=controlled_config.config_sha256,
            source_m4_authority_root_sha256=m4_report.authority_root_sha256,
            source_m5_authority_root_sha256=report.authority_root_sha256,
            source_validation_report_id=report.report_id,
            source_validation_report_document_sha256=report_sha256,
            frame_inventory_root_sha256=roots["frame"],
            detection_inventory_root_sha256=roots["detection"],
            model_call_inventory_root_sha256=roots["model_call"],
            embedding_inventory_root_sha256=roots["embedding"],
            tool_result_inventory_root_sha256=roots["tool_result"],
            historical_causal_cut_id=selection.historical_cut.causal_cut_id,
            gate_current_closures=gate_source.gate_current_closures,
        )
        closure = M6ReplayInputClosureAuthority(
            sample_id=selection.sample_id,
            source_run_id=selection.source_run_id,
            source_case_id=selection.source_case_id,
            source_case_revision=selection.source_case_revision,
            source_case_document_sha256=gate_source.source_case_document_sha256,
            source_manifest_id=manifest.manifest_id,
            source_manifest_document_sha256=manifest_sha256,
            input_authority_id=input_authority.input_authority_id,
            input_authority_document_sha256=input_authority.input_authority_document_sha256,
            source_validation_report_id=report.report_id,
            source_validation_report_document_sha256=report_sha256,
            frames=selection.frames,
            detections=selection.detections,
            model_calls=selection.model_calls,
            embeddings=selection.embeddings,
            tool_results=selection.tool_results,
            historical_cut=selection.historical_cut,
        )
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise M6SourceAuthorityBuildError(
            M6SourceAuthorityBuildErrorCode.INPUT_SELECTION_INVALID
        ) from exc

    authority_document = _document(input_authority)
    closure_document = _document(closure)
    entries = tuple(
        sorted(
            (
                _entry(
                    kind=M6SourceAuthorityDocumentKind.REPLAY_INPUT_CLOSURE,
                    artifact_id=closure.replay_input_closure_authority_id,
                    declared_document_sha256=closure.replay_input_closure_document_sha256,
                    document=closure_document,
                ),
                _entry(
                    kind=M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY,
                    artifact_id=input_authority.input_authority_id,
                    declared_document_sha256=input_authority.input_authority_document_sha256,
                    document=authority_document,
                ),
                _entry(
                    kind=M6SourceAuthorityDocumentKind.SOURCE_VALIDATION_REPORT,
                    artifact_id=report.report_id,
                    declared_document_sha256=report_sha256,
                    document=report_document,
                ),
                _entry(
                    kind=M6SourceAuthorityDocumentKind.SOURCE_CASE,
                    artifact_id=case.case_id,
                    declared_document_sha256=gate_source.source_case_document_sha256,
                    document=case_document,
                ),
                _entry(
                    kind=M6SourceAuthorityDocumentKind.SOURCE_MANIFEST,
                    artifact_id=manifest.manifest_id,
                    declared_document_sha256=manifest_sha256,
                    document=manifest_document,
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    seal = M6SourceAuthoritySeal(
        sample_id=selection.sample_id,
        source_run_id=selection.source_run_id,
        source_case_id=selection.source_case_id,
        source_case_revision=selection.source_case_revision,
        source_case_document_sha256=gate_source.source_case_document_sha256,
        source_manifest_id=manifest.manifest_id,
        source_manifest_document_sha256=manifest_sha256,
        source_config_sha256=controlled_config.config_sha256,
        source_m4_authority_root_sha256=m4_report.authority_root_sha256,
        source_m5_authority_root_sha256=report.authority_root_sha256,
        audit_head_sequence=gate_source.audit_head_sequence,
        audit_head_hash=gate_source.audit_head_hash,
        replay_input_authority_id=input_authority.input_authority_id,
        replay_input_authority_document_sha256=(input_authority.input_authority_document_sha256),
        replay_input_closure_authority_id=closure.replay_input_closure_authority_id,
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
        source_validation_report_id=report.report_id,
        source_validation_report_document_sha256=report_sha256,
        entries=entries,
    )
    snapshot = M6SourceAuthoritySnapshot(
        source_identity_sha256=sha256_hex(
            ["m6-source-authority-builder-validation", 1, seal.seal_id]
        ),
        input_authority_canonical_document=authority_document,
        source_validation_report_canonical_document=report_document,
        source_case_canonical_document=case_document,
        source_case_document_sha256=gate_source.source_case_document_sha256,
        source_manifest_canonical_document=manifest_document,
        source_manifest_document_sha256=manifest_sha256,
        source_m4_authority_root_sha256=m4_report.authority_root_sha256,
        source_m5_authority_root_sha256=report.authority_root_sha256,
        audit_head_sequence=gate_source.audit_head_sequence,
        audit_head_hash=gate_source.audit_head_hash,
    )
    try:
        assemble_m6_validated_source_authority(
            closure=closure,
            snapshot=snapshot,
            config=controlled_config,
        )
    except M6SourceAuthorityError as exc:
        raise M6SourceAuthorityBuildError(
            M6SourceAuthorityBuildErrorCode.PRODUCER_INVARIANT_VIOLATION
        ) from exc
    return M6SealedSourceBundle(
        replay_input_closure=closure,
        replay_input_authority=input_authority,
        source_validation_report=report,
        source_case=case,
        source_manifest=manifest,
        seal=seal,
        replay_input_closure_document=closure_document,
        replay_input_authority_document=authority_document,
        source_validation_report_document=report_document,
        source_case_document=case_document,
        source_manifest_document=manifest_document,
    )


__all__ = [
    "M6SealedSourceBundle",
    "M6SourceAuthorityBuildError",
    "M6SourceAuthorityBuildErrorCode",
    "build_m6_sealed_source_bundle",
]
