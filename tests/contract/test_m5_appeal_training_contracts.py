from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.appeals import Appeal
from labcourt.contracts.enums import (
    AppealStatus,
    ArtifactKind,
    CaseStatus,
    CropSource,
    DatasetFormat,
    EvidenceClass,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PrecedentSource,
    PrecedentStatus,
    PrivacyPolicy,
    PrivacyReasonCode,
    RetentionHoldKind,
    TrainingLabelQuality,
    VerdictDecision,
    VerificationStatus,
    ViolationType,
)
from labcourt.contracts.evidence import Crop, PrivacyReceipt
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_appeals import (
    MAX_M5_APPEAL_TRAINING_LABELS,
    AffectedCitationReport,
    AffectedPrecedentCitation,
    AppealResolutionCommand,
    AppealResolutionPrecedentSnapshot,
    AppealResolutionSideEffectIntent,
    AppealSubmissionCommand,
    AppealVersionAuthority,
    AutomaticPrecedentAppealAuthority,
    ClosedCaseAppealAuthority,
    M5AppealResolutionCommitReceipt,
)
from labcourt.contracts.m5_training import (
    CocoDatasetExportCommand,
    DatasetExportReport,
    TrainingCropAuthority,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.contracts.training import DatasetArtifact, TrainingLabel

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _crop() -> Crop:
    detection_ref = ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id="detection-1")
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="camera-1:stream-1:10")
    refs = (detection_ref, frame_ref)
    return Crop(
        frame_id=frame_ref.artifact_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=80),
        source_refs=refs,
        local_path="runs/run-1/media/focus.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=SHA_A,
        pixel_sha256=SHA_B,
        media_sha256=SHA_C,
        output_width=100,
        output_height=80,
        size_bytes=512,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="privacy-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=refs,
            fill_rgb=(0, 0, 0),
        ),
    )


def _verification(crop: Crop, *, media_sha256: str | None = None) -> ArtifactVerification:
    media_hash = media_sha256 or crop.media_sha256
    return ArtifactVerification(
        artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
        status=VerificationStatus.VERIFIED,
        availability=MediaAvailability.AVAILABLE,
        media_type=MediaType.IMAGE_PNG,
        expected_source_pixel_sha256=crop.source_media_sha256,
        actual_source_pixel_sha256=crop.source_media_sha256,
        expected_output_pixel_sha256=crop.pixel_sha256,
        actual_output_pixel_sha256=crop.pixel_sha256,
        expected_media_sha256=media_hash,
        actual_media_sha256=media_hash,
        expected_width=crop.output_width,
        actual_width=crop.output_width,
        expected_height=crop.output_height,
        actual_height=crop.output_height,
        expected_size_bytes=crop.size_bytes,
        actual_size_bytes=crop.size_bytes,
    )


def training_crop_authority() -> TrainingCropAuthority:
    crop = _crop()
    return TrainingCropAuthority(
        run_id="run-1",
        case_id="case-1",
        crop=crop,
        verification=_verification(crop),
        detector_manifest_id=SHA_D,
        manifest_id=SHA_E,
        rule_version="rules-v1",
    )


def closed_case_authority() -> ClosedCaseAppealAuthority:
    citation = AffectedPrecedentCitation(
        source_citation_id=SHA_C,
        citing_case_id="citing-case-1",
        precedent_id="automatic-1",
        similarity_score=0.8,
    )
    return ClosedCaseAppealAuthority(
        run_id="run-1",
        case_id="case-1",
        case_revision=7,
        case_status=CaseStatus.CLOSED,
        verdict_id=SHA_A,
        verdict_version=1,
        verdict_sha256=SHA_B,
        final_decision=VerdictDecision.ESTABLISHED,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        automatic_precedents=(
            AutomaticPrecedentAppealAuthority(
                precedent_id="automatic-1",
                precedent_authority_id=SHA_E,
                precedent_revision=1,
                status=PrecedentStatus.ACTIVE,
                decision_direction=VerdictDecision.ESTABLISHED,
                source_case_id="case-1",
                citations=(citation,),
            ),
        ),
        detector_manifest_id=SHA_C,
        text_embedding_manifest_id=SHA_A,
        visual_embedding_manifest_id=SHA_B,
        manifest_id=SHA_D,
        config_sha256=SHA_E,
        rule_version="rules-v1",
    )


def test_frozen_m0_appeal_and_training_wire_fields_are_unchanged() -> None:
    assert tuple(Appeal.model_fields) == (
        "appeal_id",
        "case_id",
        "status",
        "reason",
        "submitted_by",
        "reviewer_id",
        "resolution_summary",
        "resolved_decision",
    )
    assert tuple(TrainingLabel.model_fields) == (
        "label_id",
        "case_id",
        "crop_id",
        "bbox",
        "label_name",
        "label_value",
        "quality",
        "source",
        "reviewer_id",
        "rule_version",
        "detector_manifest_id",
        "excluded_reason",
    )
    assert tuple(DatasetArtifact.model_fields) == (
        "dataset_id",
        "format",
        "relative_path",
        "content_sha256",
        "label_count",
        "minimum_quality",
        "rule_version",
    )


def test_closed_case_authority_and_citation_report_are_content_addressed() -> None:
    authority = closed_case_authority()
    restored = ClosedCaseAppealAuthority.model_validate(authority.model_dump(mode="json"))
    assert restored == authority
    assert restored.authority_sha256 == authority.authority_sha256

    tampered = authority.model_dump(mode="json")
    tampered["authority_sha256"] = SHA_E
    with pytest.raises(ValidationError, match="authority hash"):
        ClosedCaseAppealAuthority.model_validate(tampered)

    precedent = authority.automatic_precedents[0]
    report = AffectedCitationReport(
        revoked_precedent_ids=(precedent.precedent_id,),
        citations=precedent.citations,
    )
    assert AffectedCitationReport.model_validate(report.model_dump(mode="json")) == report

    snapshot = AppealResolutionPrecedentSnapshot(
        run_id=authority.run_id,
        case_id=authority.case_id,
        automatic_precedents=authority.automatic_precedents,
    )
    assert (
        AppealResolutionPrecedentSnapshot.model_validate(snapshot.model_dump(mode="json"))
        == snapshot
    )
    tampered_snapshot = snapshot.model_dump(mode="json")
    tampered_snapshot["snapshot_sha256"] = SHA_A
    with pytest.raises(ValidationError, match="snapshot hash"):
        AppealResolutionPrecedentSnapshot.model_validate(tampered_snapshot)


def test_closed_case_authority_rejects_cross_case_or_direction_precedents() -> None:
    authority = closed_case_authority()
    payload = authority.model_dump(mode="python", exclude_computed_fields=True)
    payload["automatic_precedents"][0]["source_case_id"] = "other-case"
    with pytest.raises(ValidationError, match="closed Case authority"):
        ClosedCaseAppealAuthority.model_validate(payload)


def test_distinct_persisted_citation_identities_never_collapse() -> None:
    citations = tuple(
        sorted(
            (
                AffectedPrecedentCitation(
                    source_citation_id=source_id,
                    citing_case_id="same-case",
                    precedent_id="automatic-1",
                    similarity_score=2.5,
                )
                for source_id in (SHA_A, SHA_B)
            ),
            key=lambda item: item.sort_key,
        )
    )
    precedent = AutomaticPrecedentAppealAuthority(
        precedent_id="automatic-1",
        precedent_authority_id=SHA_E,
        precedent_revision=2,
        status=PrecedentStatus.ACTIVE,
        decision_direction=VerdictDecision.ESTABLISHED,
        source_case_id="case-1",
        citations=citations,
    )
    snapshot = AppealResolutionPrecedentSnapshot(
        run_id="run-1",
        case_id="case-1",
        automatic_precedents=(precedent,),
    )

    assert len(snapshot.automatic_precedents[0].citations) == 2
    assert len({item.citation_id for item in citations}) == 2
    assert (
        snapshot.snapshot_sha256
        == AppealResolutionPrecedentSnapshot.model_validate(
            snapshot.model_dump(mode="json")
        ).snapshot_sha256
    )


def test_m5_appeal_case_revisions_are_strictly_positive() -> None:
    payload = closed_case_authority().model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    payload["case_revision"] = 0
    with pytest.raises(ValidationError):
        ClosedCaseAppealAuthority.model_validate(payload)

    with pytest.raises(ValidationError):
        AppealSubmissionCommand(
            run_id="run-1",
            case_id="case-1",
            appeal_id="appeal-1",
            expected_case_revision=0,
            expected_case_authority_sha256=SHA_A,
            reason="human review requested",
            submitted_by="subject-1",
        )

    with pytest.raises(ValidationError):
        AppealVersionAuthority(
            run_id="run-1",
            appeal=Appeal(
                appeal_id="appeal-1",
                case_id="case-1",
                status=AppealStatus.SUBMITTED,
                reason="human review requested",
                submitted_by="subject-1",
            ),
            version=1,
            source_case_authority=closed_case_authority(),
            source_case_revision=0,
            source_case_authority_sha256=SHA_A,
            source_verdict_id=SHA_B,
            source_verdict_version=1,
            source_verdict_sha256=SHA_C,
            source_decision=VerdictDecision.ESTABLISHED,
            text_embedding_manifest_id=SHA_A,
            visual_embedding_manifest_id=SHA_B,
            manifest_id=SHA_D,
            rule_version="rules-v1",
        )


def test_appeal_resolution_label_collections_have_a_hard_contract_bound() -> None:
    label = TrainingLabel(
        label_id=SHA_A,
        case_id="case-1",
        crop_id=SHA_B,
        bbox=BBoxXYXY(x1=0, y1=0, x2=10, y2=10),
        label_name="reviewed_fact",
        label_value=True,
        quality=TrainingLabelQuality.HUMAN_CONFIRMED,
        source="appeal-review:appeal-1",
        reviewer_id="reviewer-1",
        rule_version="rules-v1",
        detector_manifest_id=SHA_C,
    )
    oversized = [label] * (MAX_M5_APPEAL_TRAINING_LABELS + 1)

    with pytest.raises(ValidationError) as command_error:
        AppealResolutionCommand(
            run_id="run-1",
            case_id="case-1",
            appeal_id="appeal-1",
            expected_appeal_authority_sha256=SHA_D,
            status=AppealStatus.UPHELD,
            reviewer_id="reviewer-1",
            resolution_summary="The human reviewer upheld the original decision.",
            resolved_decision=VerdictDecision.ESTABLISHED,
            training_labels=oversized,
        )
    assert any(
        error["loc"] == ("training_labels",) and error["type"] == "too_long"
        for error in command_error.value.errors()
    )

    serialized = {
        "training_labels": [label.model_dump(mode="json")] * (MAX_M5_APPEAL_TRAINING_LABELS + 1)
    }
    with pytest.raises(ValidationError) as intent_error:
        AppealResolutionSideEffectIntent.model_validate(serialized)
    assert any(
        error["loc"] == ("training_labels",) and error["type"] == "too_long"
        for error in intent_error.value.errors()
    )


def _appeal_commit_receipt() -> M5AppealResolutionCommitReceipt:
    return M5AppealResolutionCommitReceipt(
        run_id="run-1",
        resolution_intent_id=SHA_A,
        resolution_document_sha256=SHA_B,
        appeal_id="appeal-1",
        appeal_authority_sha256=SHA_C,
        case_id="case-1",
        source_case_revision=8,
        resulting_case_revision=11,
        resulting_case_document_sha256=SHA_D,
        verdict_rescission_ids=(SHA_E,),
        alert_rescission_ids=("1" * 64,),
        precedent_revocation_receipt_ids=("2" * 64,),
        replacement_precedent_authority_id="3" * 64,
        training_label_ids=("label-1",),
        affected_citation_report_sha256="4" * 64,
        manifest_id="5" * 64,
    )


def test_appeal_commit_receipt_binds_complete_stable_effect_inventory() -> None:
    receipt = _appeal_commit_receipt()
    serialized = receipt.model_dump(mode="json")
    base = receipt.model_dump(
        mode="json",
        exclude={"effect_root_sha256", "receipt_id"},
    )

    assert M5AppealResolutionCommitReceipt.model_validate(serialized) == receipt
    assert len(receipt.effect_root_sha256) == 64
    assert len(receipt.receipt_id) == 64
    for claim in ("effect_root_sha256", "receipt_id"):
        attacked = dict(serialized)
        attacked[claim] = "f" * 64
        with pytest.raises(ValidationError, match=claim):
            M5AppealResolutionCommitReceipt.model_validate(attacked)

    with pytest.raises(ValidationError, match="three-step appeal chain"):
        M5AppealResolutionCommitReceipt.model_validate({**base, "resulting_case_revision": 10})
    with pytest.raises(ValidationError, match="overturned appeal commit"):
        M5AppealResolutionCommitReceipt.model_validate({**base, "training_label_ids": ()})
    with pytest.raises(ValidationError, match="upheld appeal commit"):
        M5AppealResolutionCommitReceipt.model_validate(
            {**base, "replacement_precedent_authority_id": None}
        )
    with pytest.raises(ValidationError, match="stable order"):
        M5AppealResolutionCommitReceipt.model_validate(
            {**base, "alert_rescission_ids": ("b" * 64, "a" * 64)}
        )


def test_upheld_appeal_commit_receipt_has_no_overturn_only_roots() -> None:
    receipt = M5AppealResolutionCommitReceipt.model_validate(
        {
            **_appeal_commit_receipt().model_dump(
                mode="json",
                exclude={"effect_root_sha256", "receipt_id"},
            ),
            "verdict_rescission_ids": (),
            "alert_rescission_ids": (),
            "precedent_revocation_receipt_ids": (),
            "replacement_precedent_authority_id": None,
            "training_label_ids": ("human-label-1",),
        }
    )

    assert receipt.verdict_rescission_ids == ()
    assert receipt.precedent_revocation_receipt_ids == ()
    assert receipt.replacement_precedent_authority_id is None


def test_training_crop_authority_binds_verified_hashes_and_serialized_identity() -> None:
    authority = training_crop_authority()
    restored = TrainingCropAuthority.model_validate(authority.model_dump(mode="json"))
    assert restored == authority

    crop = authority.crop
    with pytest.raises(ValidationError, match="integrity verification"):
        TrainingCropAuthority(
            run_id=authority.run_id,
            case_id=authority.case_id,
            crop=crop,
            verification=_verification(crop, media_sha256=SHA_D),
            detector_manifest_id=authority.detector_manifest_id,
            manifest_id=authority.manifest_id,
            rule_version=authority.rule_version,
        )


def test_export_command_and_report_reject_path_and_accounting_tampering() -> None:
    command = CocoDatasetExportCommand(
        run_id="run-1",
        relative_path="datasets/reviewed.coco.json",
        detector_manifest_id=SHA_C,
        manifest_id=SHA_D,
        rule_version="rules-v1",
        purpose="DETECTOR_TRAINING_FROM_REVIEWED_LABELS",
        retention_hold_kind=RetentionHoldKind.GOLD_SET,
        retention_policy_version="m5-gold-set-retention-v1",
        retention_period="UNTIL_EXPLICIT_RELEASE",
    )
    assert CocoDatasetExportCommand.model_validate(command.model_dump(mode="json")) == command
    missing_retention = command.model_dump(mode="json", exclude={"retention_period"})
    with pytest.raises(ValidationError, match="retention_period"):
        CocoDatasetExportCommand.model_validate(missing_retention)
    with pytest.raises(ValidationError):
        command.model_copy(update={"relative_path": "../outside.json"})

    dataset = DatasetArtifact(
        dataset_id=SHA_A,
        format=DatasetFormat.COCO,
        relative_path=command.relative_path,
        content_sha256=SHA_B,
        label_count=0,
        minimum_quality=TrainingLabelQuality.HUMAN_CONFIRMED,
        rule_version=command.rule_version,
    )
    report = DatasetExportReport(
        command_id=command.command_id,
        run_id=command.run_id,
        dataset=dataset,
        requested_relative_path=command.relative_path,
        detector_manifest_id=command.detector_manifest_id,
        manifest_id=command.manifest_id,
        rule_version=command.rule_version,
        purpose=command.purpose,
        retention_hold_kind=command.retention_hold_kind,
        retention_policy_version=command.retention_policy_version,
        retention_period=command.retention_period,
        max_input_labels=command.max_input_labels,
        max_content_bytes=command.max_content_bytes,
        input_label_count=0,
        weak_auto_count=0,
        consensus_reviewed_count=0,
        excluded_reason_count=0,
        exported_image_count=0,
        exported_category_count=0,
        content_size_bytes=2,
    )
    assert DatasetExportReport.model_validate(report.model_dump(mode="json")) == report
    with pytest.raises(ValidationError, match="command ID is not canonical"):
        report.model_copy(update={"command_id": SHA_D})
    with pytest.raises(ValidationError, match="account for every input"):
        report.model_copy(update={"input_label_count": 1})


def test_m5_contract_enums_preserve_required_effect_values() -> None:
    assert PrecedentSource.APPEAL_OVERTURN.value == "APPEAL_OVERTURN"
    assert PrecedentStatus.REVOKED.value == "REVOKED"
    assert AppealStatus.OVERTURNED.value == "OVERTURNED"
    assert TrainingLabelQuality.APPEAL_CONFIRMED.value == "APPEAL_CONFIRMED"
