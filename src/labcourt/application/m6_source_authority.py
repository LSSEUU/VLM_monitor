"""Validate and dereference the sealed M6 source-input authority."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_source_authority import (
    M6GateCurrentClosureBasis,
    M6GateCurrentClosureReceipt,
    M6ReplayInputAuthority,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification, ClosureReport
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_source_authority import M6SourceAuthoritySnapshot

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6SourceAuthorityErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INPUT_AUTHORITY_DOCUMENT_INVALID = "INPUT_AUTHORITY_DOCUMENT_INVALID"
    INPUT_AUTHORITY_BINDING_MISMATCH = "INPUT_AUTHORITY_BINDING_MISMATCH"
    SOURCE_VALIDATION_REPORT_INVALID = "SOURCE_VALIDATION_REPORT_INVALID"
    SOURCE_VALIDATION_CHAIN_INVALID = "SOURCE_VALIDATION_CHAIN_INVALID"
    SOURCE_SNAPSHOT_HEAD_MISMATCH = "SOURCE_SNAPSHOT_HEAD_MISMATCH"
    SOURCE_AUTHORITY_ROOT_MISMATCH = "SOURCE_AUTHORITY_ROOT_MISMATCH"
    SOURCE_DOCUMENT_INVALID = "SOURCE_DOCUMENT_INVALID"
    SOURCE_SCOPE_MISMATCH = "SOURCE_SCOPE_MISMATCH"
    GATE_CLOSURE_COVERAGE_MISMATCH = "GATE_CLOSURE_COVERAGE_MISMATCH"
    CURRENT_CLOSURE_AUTHORITY_INVALID = "CURRENT_CLOSURE_AUTHORITY_INVALID"
    CURRENT_MEDIA_VERIFICATION_MISMATCH = "CURRENT_MEDIA_VERIFICATION_MISMATCH"


class M6SourceAuthorityError(LabCourtError):
    """A sealed source-input authority could not be proven exactly."""

    def __init__(self, code: M6SourceAuthorityErrorCode) -> None:
        if not isinstance(code, M6SourceAuthorityErrorCode):
            raise TypeError("code must be an M6SourceAuthorityErrorCode")
        self.code = code
        super().__init__(f"M6 source authority validation failed: {code.value}")


def _fail(code: M6SourceAuthorityErrorCode) -> NoReturn:
    raise M6SourceAuthorityError(code)


def _canonical_document_sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _typed_canonical_document(
    document: str,
    model_type: type[_ModelT],
    error_code: M6SourceAuthorityErrorCode,
) -> _ModelT:
    try:
        value = model_type.model_validate_json(document)
        if canonical_json(value.model_dump(mode="json")) != document:
            _fail(error_code)
        return value
    except M6SourceAuthorityError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(error_code)


def _typed_config(value: object) -> AppConfig:
    if not isinstance(value, AppConfig):
        _fail(M6SourceAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        controlled = AppConfig.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SourceAuthorityErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6SourceAuthorityErrorCode.INVALID_ARGUMENT)
    return controlled


def _document_sha256(value: BaseModel) -> str:
    return hashlib.sha256(canonical_json(value.model_dump(mode="json")).encode("utf-8")).hexdigest()


def _expected_current_closure(pack: EvidencePack) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    refs = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
    return ClosureReport(
        run_id=pack.run_id,
        root_ref=root,
        manifest_id=pack.manifest_id,
        input_sha256=pack.closure_input_sha256,
        checked_refs=tuple(refs[key] for key in sorted(refs)),
    )


def _verification_matches_crop(
    verification: ArtifactVerification,
    crop: Crop,
) -> bool:
    return (
        verification.artifact_ref == ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
        and verification.status == VerificationStatus.CURRENT_MEDIA_VERIFIED
        and verification.availability == MediaAvailability.AVAILABLE
        and verification.media_type == crop.media_type
        and verification.expected_source_pixel_sha256 == crop.source_media_sha256
        and verification.actual_source_pixel_sha256 is None
        and verification.expected_output_pixel_sha256 == crop.pixel_sha256
        and verification.actual_output_pixel_sha256 == crop.pixel_sha256
        and verification.expected_media_sha256 == crop.media_sha256
        and verification.actual_media_sha256 == crop.media_sha256
        and verification.expected_width == crop.output_width
        and verification.actual_width == crop.output_width
        and verification.expected_height == crop.output_height
        and verification.actual_height == crop.output_height
        and verification.expected_size_bytes == crop.size_bytes
        and verification.actual_size_bytes == crop.size_bytes
        and verification.reason_code is None
    )


@dataclass(frozen=True, slots=True)
class M6ValidatedSourceAuthority:
    """Canonical source documents whose report chain and Gate receipts agree."""

    source_identity_sha256: str
    input_authority: M6ReplayInputAuthority
    source_validation_report: M5ArtifactValidationReport
    source_case: Case
    source_manifest: RunManifest

    def receipt_for_review(self, review_id: str) -> M6GateCurrentClosureReceipt:
        matches = tuple(
            item
            for item in self.input_authority.gate_current_closures
            if item.source_review_id == review_id
        )
        if len(matches) != 1:
            raise ValueError("validated M6 source authority lacks one exact Gate receipt")
        return matches[0]


def _validate_closure_binding(
    *,
    closure: M6ReplayInputClosureAuthority,
    authority: M6ReplayInputAuthority,
    source_case: Case,
    source_manifest: RunManifest,
    config: AppConfig,
) -> None:
    if (
        closure.sample_id != authority.sample_id
        or closure.source_run_id != authority.source_run_id
        or closure.source_case_id != authority.source_case_id
        or closure.source_case_revision != authority.source_case_revision
        or closure.source_case_document_sha256 != authority.source_case_document_sha256
        or closure.source_manifest_id != authority.source_manifest_id
        or closure.source_manifest_document_sha256 != authority.source_manifest_document_sha256
        or closure.input_authority_id != authority.input_authority_id
        or closure.input_authority_document_sha256 != authority.input_authority_document_sha256
        or closure.source_validation_report_id != authority.source_validation_report_id
        or closure.source_validation_report_document_sha256
        != authority.source_validation_report_document_sha256
        or closure.frame_inventory_root_sha256 != authority.frame_inventory_root_sha256
        or closure.detection_inventory_root_sha256 != authority.detection_inventory_root_sha256
        or closure.model_call_inventory_root_sha256 != authority.model_call_inventory_root_sha256
        or closure.embedding_inventory_root_sha256 != authority.embedding_inventory_root_sha256
        or closure.tool_result_inventory_root_sha256 != authority.tool_result_inventory_root_sha256
        or closure.historical_cut.causal_cut_id != authority.historical_causal_cut_id
    ):
        _fail(M6SourceAuthorityErrorCode.INPUT_AUTHORITY_BINDING_MISMATCH)
    if (
        source_case.run_id != authority.source_run_id
        or source_case.case_id != authority.source_case_id
        or source_case.manifest_id != authority.source_manifest_id
        or source_manifest.manifest_id != authority.source_manifest_id
        or source_manifest.config_sha256 != authority.source_config_sha256
        or config.config_sha256 != authority.source_config_sha256
    ):
        _fail(M6SourceAuthorityErrorCode.SOURCE_SCOPE_MISMATCH)


def _validate_report_chain(
    *,
    report: M5ArtifactValidationReport,
    authority: M6ReplayInputAuthority,
    snapshot: M6SourceAuthoritySnapshot,
    manifest: RunManifest,
) -> None:
    if (
        report.report_id != authority.source_validation_report_id
        or _canonical_document_sha256(snapshot.source_validation_report_canonical_document)
        != authority.source_validation_report_document_sha256
        or report.run_id != authority.source_run_id
        or report.manifest_id != authority.source_manifest_id
        or report.config_sha256 != authority.source_config_sha256
        or not report.passed
        or not isinstance(report.predecessor_report, M4ArtifactValidationReport)
    ):
        _fail(M6SourceAuthorityErrorCode.SOURCE_VALIDATION_REPORT_INVALID)
    m4_report = report.predecessor_report
    m3_report = m4_report.m3_report
    m2_report = m3_report.m2_report
    if not (m4_report.passed and m3_report.passed and m2_report.passed):
        _fail(M6SourceAuthorityErrorCode.SOURCE_VALIDATION_CHAIN_INVALID)
    if (
        m2_report.manifest_id != manifest.manifest_id
        or m2_report.audit_head_sequence is None
        or m2_report.audit_head_hash is None
        or m2_report.audit_head_sequence != snapshot.audit_head_sequence
        or m2_report.audit_head_hash != snapshot.audit_head_hash
    ):
        _fail(M6SourceAuthorityErrorCode.SOURCE_SNAPSHOT_HEAD_MISMATCH)
    if (
        snapshot.m4_authority_failure_count
        or snapshot.m5_authority_failure_count
        or authority.source_m4_authority_root_sha256 != snapshot.source_m4_authority_root_sha256
        or authority.source_m5_authority_root_sha256 != snapshot.source_m5_authority_root_sha256
        or m4_report.authority_root_sha256 != snapshot.source_m4_authority_root_sha256
        or report.authority_root_sha256 != snapshot.source_m5_authority_root_sha256
    ):
        _fail(M6SourceAuthorityErrorCode.SOURCE_AUTHORITY_ROOT_MISMATCH)


def _validate_gate_receipts(
    *,
    authority: M6ReplayInputAuthority,
    source_case: Case,
) -> None:
    reviews = {item.review_id: item for item in source_case.procedural_reviews}
    receipts = {item.source_review_id: item for item in authority.gate_current_closures}
    if set(reviews) != set(receipts):
        _fail(M6SourceAuthorityErrorCode.GATE_CLOSURE_COVERAGE_MISMATCH)
    packs = {(item.pack_id, item.version): item for item in source_case.evidence_packs}
    for review_id, review in reviews.items():
        receipt = receipts[review_id]
        pack = packs.get((review.evidence_pack_id, review.evidence_pack_version))
        if (
            pack is None
            or receipt.review_version != review.version
            or receipt.source_review_document_sha256 != _document_sha256(review)
            or receipt.evidence_pack_id != review.evidence_pack_id
            or receipt.evidence_pack_version != review.evidence_pack_version
            or receipt.evidence_pack_document_sha256 != _document_sha256(pack)
        ):
            _fail(M6SourceAuthorityErrorCode.GATE_CLOSURE_COVERAGE_MISMATCH)
        if receipt.current_closure != _expected_current_closure(pack):
            _fail(M6SourceAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)
        verifications = {item.artifact_ref.artifact_id: item for item in receipt.crop_verifications}
        crops = {item.crop_id: item for item in pack.crops}
        if not crops:
            if receipt.basis != M6GateCurrentClosureBasis.SEMANTIC_ONLY_NO_CROPS or verifications:
                _fail(M6SourceAuthorityErrorCode.CURRENT_MEDIA_VERIFICATION_MISMATCH)
            continue
        if (
            receipt.basis != M6GateCurrentClosureBasis.CURRENT_PRIVACY_CROP_REVERIFIED
            or set(verifications) != set(crops)
            or any(
                crop.availability != MediaAvailability.AVAILABLE
                or not _verification_matches_crop(verifications[crop_id], crop)
                for crop_id, crop in crops.items()
            )
        ):
            _fail(M6SourceAuthorityErrorCode.CURRENT_MEDIA_VERIFICATION_MISMATCH)


def assemble_m6_validated_source_authority(
    *,
    closure: object,
    snapshot: object,
    config: object,
) -> M6ValidatedSourceAuthority:
    """Resolve both opaque closure references and validate their complete chain."""

    if not isinstance(closure, M6ReplayInputClosureAuthority) or not isinstance(
        snapshot, M6SourceAuthoritySnapshot
    ):
        _fail(M6SourceAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        controlled_closure = M6ReplayInputClosureAuthority.model_validate(
            closure.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SourceAuthorityErrorCode.INVALID_ARGUMENT)
    if controlled_closure != closure:
        _fail(M6SourceAuthorityErrorCode.INVALID_ARGUMENT)
    controlled_config = _typed_config(config)
    authority = _typed_canonical_document(
        snapshot.input_authority_canonical_document,
        M6ReplayInputAuthority,
        M6SourceAuthorityErrorCode.INPUT_AUTHORITY_DOCUMENT_INVALID,
    )
    report = _typed_canonical_document(
        snapshot.source_validation_report_canonical_document,
        M5ArtifactValidationReport,
        M6SourceAuthorityErrorCode.SOURCE_VALIDATION_REPORT_INVALID,
    )
    source_case = _typed_canonical_document(
        snapshot.source_case_canonical_document,
        Case,
        M6SourceAuthorityErrorCode.SOURCE_DOCUMENT_INVALID,
    )
    source_manifest = _typed_canonical_document(
        snapshot.source_manifest_canonical_document,
        RunManifest,
        M6SourceAuthorityErrorCode.SOURCE_DOCUMENT_INVALID,
    )
    if (
        _canonical_document_sha256(snapshot.source_case_canonical_document)
        != snapshot.source_case_document_sha256
        or snapshot.source_case_document_sha256 != authority.source_case_document_sha256
        or _canonical_document_sha256(snapshot.source_manifest_canonical_document)
        != snapshot.source_manifest_document_sha256
        or snapshot.source_manifest_document_sha256 != authority.source_manifest_document_sha256
    ):
        _fail(M6SourceAuthorityErrorCode.SOURCE_DOCUMENT_INVALID)
    _validate_closure_binding(
        closure=controlled_closure,
        authority=authority,
        source_case=source_case,
        source_manifest=source_manifest,
        config=controlled_config,
    )
    _validate_report_chain(
        report=report,
        authority=authority,
        snapshot=snapshot,
        manifest=source_manifest,
    )
    _validate_gate_receipts(authority=authority, source_case=source_case)
    return M6ValidatedSourceAuthority(
        source_identity_sha256=snapshot.source_identity_sha256,
        input_authority=authority,
        source_validation_report=report,
        source_case=source_case,
        source_manifest=source_manifest,
    )


__all__ = [
    "M6SourceAuthorityError",
    "M6SourceAuthorityErrorCode",
    "M6ValidatedSourceAuthority",
    "assemble_m6_validated_source_authority",
]
