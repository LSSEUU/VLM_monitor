from __future__ import annotations

import hashlib
import json

import pytest

from labcourt.application.dataset_export import (
    DatasetExportError,
    DatasetExportFailureCode,
    build_coco_dataset,
)
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PrivacyPolicy,
    PrivacyReasonCode,
    RetentionHoldKind,
    TrainingLabelQuality,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, PrivacyReceipt
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_training import CocoDatasetExportCommand, TrainingCropAuthority
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.contracts.training import TrainingLabel

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _crop_authority(index: int) -> TrainingCropAuthority:
    detection = ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id=f"detection-{index}")
    frame = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=f"camera:stream:{index}")
    refs = (detection, frame)
    pixel_hash = f"{index:x}" * 64
    media_hash = f"{index + 4:x}" * 64
    crop = Crop(
        frame_id=frame.artifact_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=80),
        source_refs=refs,
        local_path=f"runs/run-1/media/focus-{index}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=SHA_A,
        pixel_sha256=pixel_hash,
        media_sha256=media_hash,
        output_width=100,
        output_height=80,
        size_bytes=500 + index,
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
    verification = ArtifactVerification(
        artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
        status=VerificationStatus.VERIFIED,
        availability=MediaAvailability.AVAILABLE,
        media_type=MediaType.IMAGE_PNG,
        expected_source_pixel_sha256=crop.source_media_sha256,
        actual_source_pixel_sha256=crop.source_media_sha256,
        expected_output_pixel_sha256=crop.pixel_sha256,
        actual_output_pixel_sha256=crop.pixel_sha256,
        expected_media_sha256=crop.media_sha256,
        actual_media_sha256=crop.media_sha256,
        expected_width=crop.output_width,
        actual_width=crop.output_width,
        expected_height=crop.output_height,
        actual_height=crop.output_height,
        expected_size_bytes=crop.size_bytes,
        actual_size_bytes=crop.size_bytes,
    )
    return TrainingCropAuthority(
        run_id="run-1",
        case_id=f"case-{index}",
        crop=crop,
        verification=verification,
        detector_manifest_id=SHA_C,
        manifest_id=SHA_D,
        rule_version="rules-v1",
    )


def _label(
    label_id: str,
    quality: TrainingLabelQuality,
    crop: TrainingCropAuthority,
    *,
    label_name: str = "goggles",
    excluded_reason: str | None = None,
) -> TrainingLabel:
    return TrainingLabel(
        label_id=label_id,
        case_id=crop.case_id,
        crop_id=crop.crop.crop_id,
        bbox=BBoxXYXY(x1=10, y1=12, x2=30, y2=40),
        label_name=label_name,
        label_value=True,
        quality=quality,
        source="reviewed-case",
        reviewer_id=(
            "reviewer-1"
            if quality
            in {TrainingLabelQuality.HUMAN_CONFIRMED, TrainingLabelQuality.APPEAL_CONFIRMED}
            else None
        ),
        rule_version="rules-v1",
        detector_manifest_id=SHA_C,
        excluded_reason=excluded_reason,
    )


def _command(**updates: object) -> CocoDatasetExportCommand:
    payload: dict[str, object] = {
        "run_id": "run-1",
        "relative_path": "datasets/reviewed.coco.json",
        "detector_manifest_id": SHA_C,
        "manifest_id": SHA_D,
        "rule_version": "rules-v1",
        "purpose": "DETECTOR_TRAINING_FROM_REVIEWED_LABELS",
        "retention_hold_kind": RetentionHoldKind.GOLD_SET,
        "retention_policy_version": "m5-gold-set-retention-v1",
        "retention_period": "UNTIL_EXPLICIT_RELEASE",
    }
    payload.update(updates)
    return CocoDatasetExportCommand.model_validate(payload)


def test_default_export_is_deterministic_and_quarantines_non_human_labels() -> None:
    crop_1 = _crop_authority(1)
    crop_2 = _crop_authority(2)
    labels = (
        _label("weak-1", TrainingLabelQuality.WEAK_AUTO, crop_1),
        _label("appeal-1", TrainingLabelQuality.APPEAL_CONFIRMED, crop_2, label_name="gloves"),
        _label("consensus-1", TrainingLabelQuality.CONSENSUS_REVIEWED, crop_1),
        _label("human-1", TrainingLabelQuality.HUMAN_CONFIRMED, crop_1),
        _label(
            "excluded-1",
            TrainingLabelQuality.HUMAN_CONFIRMED,
            crop_1,
            excluded_reason="privacy-review-pending",
        ),
    )
    built = build_coco_dataset(
        command=_command(),
        labels=labels,
        crop_authorities=(crop_2, crop_1),
    )
    replay = build_coco_dataset(
        command=_command(),
        labels=tuple(reversed(labels)),
        crop_authorities=(crop_1, crop_2),
    )
    assert replay.content == built.content
    assert replay.report == built.report
    assert hashlib.sha256(built.content).hexdigest() == built.report.dataset.content_sha256
    assert built.report.exported_label_ids == ("appeal-1", "human-1")
    assert built.report.quarantined_label_ids == (
        "consensus-1",
        "excluded-1",
        "weak-1",
    )
    assert built.report.weak_auto_count == 1
    assert built.report.consensus_reviewed_count == 1
    assert built.report.excluded_reason_count == 1

    payload = json.loads(built.content)
    assert [item["labcourt_label_id"] for item in payload["annotations"]] == [
        "appeal-1",
        "human-1",
    ]
    assert len(payload["images"]) == 2
    assert [item["name"] for item in payload["categories"]] == ["gloves", "goggles"]
    assert payload["labcourt"]["manifest_id"] == SHA_D


@pytest.mark.parametrize(
    ("update", "reason_code"),
    [
        (
            {"bbox": BBoxXYXY(x1=0, y1=0, x2=101, y2=80)},
            DatasetExportFailureCode.LABEL_BBOX_OUTSIDE_CROP,
        ),
        (
            {"detector_manifest_id": SHA_B},
            DatasetExportFailureCode.LABEL_MANIFEST_MISMATCH,
        ),
        ({"rule_version": "rules-v2"}, DatasetExportFailureCode.LABEL_RULE_MISMATCH),
        ({"reviewer_id": None}, DatasetExportFailureCode.REVIEW_AUTHORITY_MISSING),
    ],
)
def test_selected_label_requires_exact_crop_geometry_manifest_rule_and_reviewer(
    update: dict[str, object],
    reason_code: DatasetExportFailureCode,
) -> None:
    crop = _crop_authority(1)
    label = _label("human-1", TrainingLabelQuality.HUMAN_CONFIRMED, crop).model_copy(update=update)
    with pytest.raises(DatasetExportError) as failure:
        build_coco_dataset(
            command=_command(),
            labels=(label,),
            crop_authorities=(crop,),
        )
    assert failure.value.reason_code == reason_code


def test_selected_label_requires_a_verified_crop_authority() -> None:
    crop = _crop_authority(1)
    label = _label("human-1", TrainingLabelQuality.HUMAN_CONFIRMED, crop)
    with pytest.raises(DatasetExportError) as failure:
        build_coco_dataset(command=_command(), labels=(label,), crop_authorities=())
    assert failure.value.reason_code == DatasetExportFailureCode.CROP_AUTHORITY_MISSING


def test_export_enforces_input_and_content_budgets() -> None:
    crop = _crop_authority(1)
    labels = (
        _label("human-1", TrainingLabelQuality.HUMAN_CONFIRMED, crop),
        _label("human-2", TrainingLabelQuality.HUMAN_CONFIRMED, crop),
    )
    with pytest.raises(DatasetExportError) as input_failure:
        build_coco_dataset(
            command=_command(max_input_labels=1),
            labels=labels,
            crop_authorities=(crop,),
        )
    assert input_failure.value.reason_code == DatasetExportFailureCode.INPUT_LABEL_BUDGET_EXCEEDED

    with pytest.raises(DatasetExportError) as content_failure:
        build_coco_dataset(
            command=_command(max_content_bytes=1),
            labels=(labels[0],),
            crop_authorities=(crop,),
        )
    assert content_failure.value.reason_code == DatasetExportFailureCode.CONTENT_BUDGET_EXCEEDED
