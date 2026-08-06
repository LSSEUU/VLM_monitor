from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from pydantic import BaseModel

from labcourt.application.m6_source_authority import (
    M6SourceAuthorityError,
    M6SourceAuthorityErrorCode,
    assemble_m6_validated_source_authority,
)
from labcourt.config_loader import load_config
from labcourt.contracts.artifact_validation import (
    ArtifactValidationArea,
    ArtifactValidationIssue,
    ArtifactValidationIssueCode,
    ArtifactValidationReport,
    M3ArtifactValidationReport,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.m4_artifact_validation import (
    M4ArtifactValidationCounts,
    M4ArtifactValidationReport,
)
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import (
    M6LockedFrameInput,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.m6_source_authority import (
    M6GateCurrentClosureBasis,
    M6GateCurrentClosureReceipt,
    M6ReplayInputAuthority,
)
from labcourt.contracts.storage import (
    ArtifactRef,
    ArtifactVerification,
    ClosureReport,
)
from labcourt.ports.m6_source_authority import M6SourceAuthoritySnapshot
from tests.contract.test_m5_precedent_usage_contracts import _ready_case
from tests.unit.test_m6_perception_authority import _manifest

ROOT = Path(__file__).parents[2]


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_sha256(value: BaseModel) -> str:
    return _sha(canonical_json(value.model_dump(mode="json")))


def _current_closure(pack: EvidencePack, *, input_sha256: str | None = None) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    refs = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
    return ClosureReport(
        run_id=pack.run_id,
        root_ref=root,
        manifest_id=pack.manifest_id,
        input_sha256=input_sha256 or pack.closure_input_sha256,
        checked_refs=tuple(refs[key] for key in sorted(refs)),
    )


def _verification(crop: Crop, *, wrong_content: bool = False) -> ArtifactVerification:
    output_sha256 = _sha("wrong-output") if wrong_content else crop.pixel_sha256
    return ArtifactVerification(
        artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
        status=VerificationStatus.CURRENT_MEDIA_VERIFIED,
        availability=MediaAvailability.AVAILABLE,
        media_type=crop.media_type,
        expected_source_pixel_sha256=crop.source_media_sha256,
        expected_output_pixel_sha256=output_sha256,
        actual_output_pixel_sha256=output_sha256,
        expected_media_sha256=crop.media_sha256,
        actual_media_sha256=crop.media_sha256,
        expected_width=crop.output_width,
        actual_width=crop.output_width,
        expected_height=crop.output_height,
        actual_height=crop.output_height,
        expected_size_bytes=crop.size_bytes,
        actual_size_bytes=crop.size_bytes,
    )


@dataclass(frozen=True)
class _Bundle:
    closure: M6ReplayInputClosureAuthority
    snapshot: M6SourceAuthoritySnapshot
    config: object


def _bundle(
    *,
    include_receipt: bool = True,
    predecessor: bool = True,
    failed_m2: bool = False,
    wrong_closure: bool = False,
    wrong_media: bool = False,
) -> _Bundle:
    case, _ = _ready_case(())
    assert len(case.procedural_reviews) == 1
    review = case.procedural_reviews[0]
    pack = next(
        item
        for item in case.evidence_packs
        if (item.pack_id, item.version) == (review.evidence_pack_id, review.evidence_pack_version)
    )
    assert pack.crops
    assert all(item.availability == MediaAvailability.AVAILABLE for item in pack.crops)
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest, manifest_document = _manifest()
    assert manifest.manifest_id == case.manifest_id
    assert manifest.config_sha256 == config.config_sha256
    case_document = canonical_json(case.model_dump(mode="json"))
    m4_root = _sha("m4-authority-root")
    m5_root = _sha("m5-authority-root")
    audit_head_hash = _sha("audit-head")
    m2_issues = (
        (
            ArtifactValidationIssue(
                code=ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
                area=ArtifactValidationArea.AUTHORITY,
            ),
        )
        if failed_m2
        else ()
    )
    m2_report = ArtifactValidationReport(
        run_id=case.run_id,
        manifest_id=case.manifest_id,
        audit_head_sequence=7,
        audit_head_hash=audit_head_hash,
        issues=m2_issues,
    )
    m3_report = M3ArtifactValidationReport(run_id=case.run_id, m2_report=m2_report)
    m4_report = M4ArtifactValidationReport(
        run_id=case.run_id,
        m3_report=m3_report,
        authority_root_sha256=m4_root,
        counts=(
            M4ArtifactValidationCounts(
                embedded_m3_issues=1,
                embedded_m3_superseded_issues=1,
            )
            if failed_m2
            else M4ArtifactValidationCounts()
        ),
    )
    report = M5ArtifactValidationReport(
        run_id=case.run_id,
        manifest_id=case.manifest_id,
        config_sha256=config.config_sha256,
        predecessor_report=m4_report if predecessor else None,
        authority_root_sha256=m5_root,
    )
    report_document = canonical_json(report.model_dump(mode="json"))
    receipts: tuple[M6GateCurrentClosureReceipt, ...] = ()
    if include_receipt:
        receipts = (
            M6GateCurrentClosureReceipt(
                run_id=case.run_id,
                case_id=case.case_id,
                manifest_id=case.manifest_id,
                review_version=review.version,
                source_review_id=review.review_id,
                source_review_document_sha256=_document_sha256(review),
                evidence_pack_id=pack.pack_id,
                evidence_pack_version=pack.version,
                evidence_pack_document_sha256=_document_sha256(pack),
                basis=M6GateCurrentClosureBasis.CURRENT_PRIVACY_CROP_REVERIFIED,
                current_closure=_current_closure(
                    pack,
                    input_sha256=_sha("wrong-closure") if wrong_closure else None,
                ),
                crop_verifications=tuple(
                    sorted(
                        (_verification(item, wrong_content=wrong_media) for item in pack.crops),
                        key=lambda item: item.artifact_ref.sort_key,
                    )
                ),
            ),
        )
    provisional = M6ReplayInputClosureAuthority(
        sample_id="sample-source-authority",
        source_run_id=case.run_id,
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_document_sha256=_sha(case_document),
        source_manifest_id=case.manifest_id,
        source_manifest_document_sha256=_sha(manifest_document),
        input_authority_id=_sha("provisional-input-id"),
        input_authority_document_sha256=_sha("provisional-input-document"),
        source_validation_report_id=report.report_id,
        source_validation_report_document_sha256=_sha(report_document),
        frames=(
            M6LockedFrameInput(
                frame_id=pack.crops[0].frame_id,
                document_sha256=_sha("frame-document"),
                content_sha256=_sha("frame-content"),
            ),
        ),
    )
    input_authority = M6ReplayInputAuthority(
        sample_id=provisional.sample_id,
        source_run_id=case.run_id,
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_document_sha256=provisional.source_case_document_sha256 or "",
        source_manifest_id=case.manifest_id,
        source_manifest_document_sha256=provisional.source_manifest_document_sha256,
        source_config_sha256=config.config_sha256,
        source_m4_authority_root_sha256=m4_root,
        source_m5_authority_root_sha256=m5_root,
        source_validation_report_id=report.report_id,
        source_validation_report_document_sha256=_sha(report_document),
        frame_inventory_root_sha256=provisional.frame_inventory_root_sha256,
        detection_inventory_root_sha256=provisional.detection_inventory_root_sha256,
        model_call_inventory_root_sha256=provisional.model_call_inventory_root_sha256,
        embedding_inventory_root_sha256=provisional.embedding_inventory_root_sha256,
        tool_result_inventory_root_sha256=provisional.tool_result_inventory_root_sha256,
        historical_causal_cut_id=provisional.historical_cut.causal_cut_id,
        gate_current_closures=receipts,
    )
    closure = M6ReplayInputClosureAuthority.model_validate(
        {
            **provisional.model_dump(mode="json", exclude_computed_fields=True),
            "input_authority_id": input_authority.input_authority_id,
            "input_authority_document_sha256": (input_authority.input_authority_document_sha256),
        }
    )
    snapshot = M6SourceAuthoritySnapshot(
        source_identity_sha256=_sha("immutable-snapshot"),
        input_authority_canonical_document=canonical_json(input_authority.model_dump(mode="json")),
        source_validation_report_canonical_document=report_document,
        source_case_canonical_document=case_document,
        source_case_document_sha256=_sha(case_document),
        source_manifest_canonical_document=manifest_document,
        source_manifest_document_sha256=_sha(manifest_document),
        source_m4_authority_root_sha256=m4_root,
        source_m5_authority_root_sha256=m5_root,
        audit_head_sequence=7,
        audit_head_hash=audit_head_hash,
    )
    return _Bundle(closure=closure, snapshot=snapshot, config=config)


def _assert_error(code: M6SourceAuthorityErrorCode, bundle: _Bundle) -> None:
    with pytest.raises(M6SourceAuthorityError) as raised:
        assemble_m6_validated_source_authority(
            closure=bundle.closure,
            snapshot=bundle.snapshot,
            config=bundle.config,
        )
    assert raised.value.code == code


def test_validates_both_referenced_documents_and_exact_gate_closure() -> None:
    bundle = _bundle()

    result = assemble_m6_validated_source_authority(
        closure=bundle.closure,
        snapshot=bundle.snapshot,
        config=bundle.config,
    )

    review = result.source_case.procedural_reviews[0]
    receipt = result.receipt_for_review(review.review_id)
    assert result.source_identity_sha256 == bundle.snapshot.source_identity_sha256
    assert receipt.source_review_id == review.review_id
    assert receipt.current_closure.passed is True


def test_rejects_noncanonical_or_unbound_input_authority_document() -> None:
    bundle = _bundle()
    _assert_error(
        M6SourceAuthorityErrorCode.INPUT_AUTHORITY_DOCUMENT_INVALID,
        replace(
            bundle,
            snapshot=replace(
                bundle.snapshot,
                input_authority_canonical_document=(
                    f"{bundle.snapshot.input_authority_canonical_document} "
                ),
            ),
        ),
    )
    _assert_error(
        M6SourceAuthorityErrorCode.INPUT_AUTHORITY_BINDING_MISMATCH,
        replace(
            bundle,
            closure=bundle.closure.model_copy(update={"input_authority_id": _sha("foreign-input")}),
        ),
    )


def test_requires_complete_passing_m5_to_m2_validation_chain() -> None:
    _assert_error(
        M6SourceAuthorityErrorCode.SOURCE_VALIDATION_REPORT_INVALID,
        _bundle(predecessor=False),
    )
    _assert_error(
        M6SourceAuthorityErrorCode.SOURCE_VALIDATION_CHAIN_INVALID,
        _bundle(failed_m2=True),
    )


def test_requires_exact_snapshot_head_and_authority_roots() -> None:
    bundle = _bundle()
    _assert_error(
        M6SourceAuthorityErrorCode.SOURCE_SNAPSHOT_HEAD_MISMATCH,
        replace(
            bundle,
            snapshot=replace(bundle.snapshot, audit_head_sequence=8),
        ),
    )
    _assert_error(
        M6SourceAuthorityErrorCode.SOURCE_AUTHORITY_ROOT_MISMATCH,
        replace(
            bundle,
            snapshot=replace(
                bundle.snapshot,
                source_m4_authority_root_sha256=_sha("foreign-m4-root"),
            ),
        ),
    )


def test_requires_exact_review_coverage_and_current_closure_value() -> None:
    _assert_error(
        M6SourceAuthorityErrorCode.GATE_CLOSURE_COVERAGE_MISMATCH,
        _bundle(include_receipt=False),
    )
    _assert_error(
        M6SourceAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID,
        _bundle(wrong_closure=True),
    )


def test_rejects_self_consistent_media_receipt_that_differs_from_pack() -> None:
    _assert_error(
        M6SourceAuthorityErrorCode.CURRENT_MEDIA_VERIFICATION_MISMATCH,
        _bundle(wrong_media=True),
    )
