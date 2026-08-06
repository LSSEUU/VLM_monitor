from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PrivacyPolicy,
    PrivacyReasonCode,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, PrivacyReceipt
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_training import TrainingCropAuthority
from labcourt.contracts.m5_training_history import (
    M5_TRAINING_CAUSAL_GENESIS_SHA256,
    MAX_M5_DATASET_SNAPSHOT_CROPS,
    MAX_M5_DATASET_SNAPSHOT_LABELS,
    MAX_M5_TRAINING_CAUSAL_EVENTS,
    M5DatasetCropSnapshotAuthority,
    M5DatasetLabelSnapshotReceipt,
    M5DatasetLabelSnapshotRole,
    M5DatasetRegistrationSnapshotAuthority,
    M5TrainingCausalEvent,
    M5TrainingCausalEventKind,
    M5TrainingCausalWatermark,
    m5_dataset_crop_inventory_root_sha256,
    m5_dataset_label_inventory_root_sha256,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification

RUN_ID = "run-1"
DATASET_ID = "dataset-1"
REPORT_ID = "d" * 64
COMMAND_ID = "e" * 64
MANIFEST_ID = "a" * 64
DETECTOR_MANIFEST_ID = "b" * 64
REPORT_DOCUMENT_SHA256 = "c" * 64
RULE_VERSION = "rules-v1"


def _training_crop_authority(index: int = 10) -> TrainingCropAuthority:
    digest_offset = index % 10
    source_sha256 = f"{digest_offset:x}" * 64
    pixel_sha256 = f"{(digest_offset + 1) % 16:x}" * 64
    media_sha256 = f"{(digest_offset + 2) % 16:x}" * 64
    frame = ArtifactRef(
        kind=ArtifactKind.FRAME,
        artifact_id=f"camera-1:stream-1:{index}",
    )
    detection = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id=f"detection-{index}",
    )
    refs = (detection, frame)
    crop = Crop(
        frame_id=frame.artifact_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=80),
        source_refs=refs,
        local_path=f"runs/{RUN_ID}/media/focus-{index}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=source_sha256,
        pixel_sha256=pixel_sha256,
        media_sha256=media_sha256,
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
        run_id=RUN_ID,
        case_id=f"case-{index}",
        crop=crop,
        verification=verification,
        detector_manifest_id=DETECTOR_MANIFEST_ID,
        manifest_id=MANIFEST_ID,
        rule_version=RULE_VERSION,
    )


def _label_event(
    *,
    label_id: str = "label-a",
    sequence: int = 1,
    previous: str = M5_TRAINING_CAUSAL_GENESIS_SHA256,
    source_id: str = "1" * 64,
) -> M5TrainingCausalEvent:
    return M5TrainingCausalEvent(
        run_id=RUN_ID,
        sequence=sequence,
        event_kind=M5TrainingCausalEventKind.TRAINING_LABEL_APPENDED,
        source_id=source_id,
        source_document_sha256="2" * 64,
        manifest_id=MANIFEST_ID,
        previous_event_sha256=previous,
        label_id=label_id,
    )


def _label_receipt(
    *,
    label_id: str = "label-a",
    role: M5DatasetLabelSnapshotRole = M5DatasetLabelSnapshotRole.EXPORTED,
    event: M5TrainingCausalEvent | None = None,
    authority_sha256: str = "3" * 64,
) -> M5DatasetLabelSnapshotReceipt:
    causal = event or _label_event(label_id=label_id)
    return M5DatasetLabelSnapshotReceipt(
        label_id=label_id,
        role=role,
        authority_sha256=authority_sha256,
        causal_event_id=causal.event_id,
        causal_event_sequence=causal.sequence,
        causal_event_sha256=causal.event_sha256,
    )


def _crop_snapshot(index: int = 10) -> M5DatasetCropSnapshotAuthority:
    return M5DatasetCropSnapshotAuthority(
        run_id=RUN_ID,
        dataset_id=DATASET_ID,
        report_id=REPORT_ID,
        crop_authority=_training_crop_authority(index),
        case_revision=7,
        case_document_sha256="4" * 64,
        evidence_pack_id="5" * 64,
        evidence_pack_version=2,
        evidence_pack_document_sha256="6" * 64,
    )


def _watermark(event: M5TrainingCausalEvent | None = None) -> M5TrainingCausalWatermark:
    causal = event or _label_event()
    return M5TrainingCausalWatermark(
        run_id=RUN_ID,
        sequence=causal.sequence,
        event_id=causal.event_id,
        event_sha256=causal.event_sha256,
    )


def _registration(
    *,
    causal_cut: M5TrainingCausalWatermark | None = None,
    label_count: int = 1,
    crop_count: int = 1,
    label_root: str | None = None,
    crop_root: str | None = None,
) -> M5DatasetRegistrationSnapshotAuthority:
    label_receipts = (_label_receipt(),) if label_count else ()
    crop_authorities = (_crop_snapshot(),) if crop_count else ()
    return M5DatasetRegistrationSnapshotAuthority(
        run_id=RUN_ID,
        dataset_id=DATASET_ID,
        report_id=REPORT_ID,
        command_id=COMMAND_ID,
        report_document_sha256=REPORT_DOCUMENT_SHA256,
        causal_cut=causal_cut or _watermark(),
        label_count=label_count,
        label_inventory_root_sha256=label_root
        or m5_dataset_label_inventory_root_sha256(
            run_id=RUN_ID,
            dataset_id=DATASET_ID,
            report_id=REPORT_ID,
            receipts=label_receipts,
        ),
        crop_count=crop_count,
        crop_inventory_root_sha256=crop_root
        or m5_dataset_crop_inventory_root_sha256(
            run_id=RUN_ID,
            dataset_id=DATASET_ID,
            report_id=REPORT_ID,
            authorities=crop_authorities,
        ),
        manifest_id=MANIFEST_ID,
        rule_version=RULE_VERSION,
        detector_manifest_id=DETECTOR_MANIFEST_ID,
    )


def test_training_causal_event_round_trip_and_computed_claims_are_fail_closed() -> None:
    event = _label_event()
    serialized = event.model_dump(mode="json")

    assert M5TrainingCausalEvent.model_validate(serialized) == event
    assert len(event.source_identity) == len(event.event_id) == len(event.event_sha256) == 64
    for claim in ("source_identity", "event_id", "event_sha256"):
        attacked = dict(serialized)
        attacked[claim] = "f" * 64
        with pytest.raises(ValidationError, match=claim):
            M5TrainingCausalEvent.model_validate(attacked)


def test_training_causal_event_enforces_genesis_sequence_and_kind_matrix() -> None:
    first = _label_event()
    later = _label_event(sequence=2, previous=first.event_sha256)
    commit = M5TrainingCausalEvent(
        run_id=RUN_ID,
        sequence=2,
        event_kind=M5TrainingCausalEventKind.DATASET_REGISTRATION_COMMITTED,
        source_id="7" * 64,
        source_document_sha256="8" * 64,
        manifest_id=MANIFEST_ID,
        previous_event_sha256=first.event_sha256,
    )

    assert later.previous_event_sha256 == first.event_sha256
    assert commit.label_id is None
    with pytest.raises(ValidationError, match="requires label_id"):
        first.model_copy(update={"label_id": None})
    with pytest.raises(ValidationError, match="must not claim label_id"):
        commit.model_copy(update={"label_id": "label-a"})
    with pytest.raises(ValidationError, match="genesis predecessor"):
        first.model_copy(update={"previous_event_sha256": "9" * 64})
    with pytest.raises(ValidationError, match="must not use the genesis"):
        later.model_copy(update={"previous_event_sha256": M5_TRAINING_CAUSAL_GENESIS_SHA256})
    with pytest.raises(ValidationError):
        first.model_copy(update={"sequence": MAX_M5_TRAINING_CAUSAL_EVENTS + 1})


def test_training_watermark_enforces_genesis_or_real_head_and_computed_id() -> None:
    genesis = M5TrainingCausalWatermark(
        run_id=RUN_ID,
        sequence=0,
        event_sha256=M5_TRAINING_CAUSAL_GENESIS_SHA256,
    )
    head = _watermark()

    assert genesis.event_id is None
    assert M5TrainingCausalWatermark.model_validate(head.model_dump(mode="json")) == head
    with pytest.raises(ValidationError, match="watermark_id"):
        M5TrainingCausalWatermark.model_validate(
            {**head.model_dump(mode="json"), "watermark_id": "f" * 64}
        )
    with pytest.raises(ValidationError, match="genesis without event_id"):
        genesis.model_copy(update={"event_id": "1" * 64})
    with pytest.raises(ValidationError, match="real causal head"):
        head.model_copy(update={"event_id": None})
    with pytest.raises(ValidationError, match="real causal head"):
        head.model_copy(update={"event_sha256": M5_TRAINING_CAUSAL_GENESIS_SHA256})


def test_label_receipt_is_content_addressed_and_event_position_sensitive() -> None:
    first = _label_receipt()
    later_event = _label_event(
        sequence=2,
        previous=_label_event().event_sha256,
    )
    later = _label_receipt(event=later_event)

    assert first.receipt_id != later.receipt_id
    assert M5DatasetLabelSnapshotReceipt.model_validate(first.model_dump(mode="json")) == first
    with pytest.raises(ValidationError, match="receipt_id"):
        M5DatasetLabelSnapshotReceipt.model_validate(
            {**first.model_dump(mode="json"), "receipt_id": "f" * 64}
        )
    with pytest.raises(ValidationError):
        first.model_copy(update={"causal_event_sequence": MAX_M5_TRAINING_CAUSAL_EVENTS + 1})


def test_label_inventory_root_is_order_independent_and_rejects_duplicates() -> None:
    first_event = _label_event()
    second_event = _label_event(
        label_id="label-b",
        sequence=2,
        previous=first_event.event_sha256,
        source_id="4" * 64,
    )
    first = _label_receipt(event=first_event)
    second = _label_receipt(
        label_id="label-b",
        role=M5DatasetLabelSnapshotRole.QUARANTINED,
        event=second_event,
        authority_sha256="5" * 64,
    )
    forward = m5_dataset_label_inventory_root_sha256(
        run_id=RUN_ID,
        dataset_id=DATASET_ID,
        report_id=REPORT_ID,
        receipts=(first, second),
    )
    reverse = m5_dataset_label_inventory_root_sha256(
        run_id=RUN_ID,
        dataset_id=DATASET_ID,
        report_id=REPORT_ID,
        receipts=(second, first),
    )

    assert forward == reverse
    assert forward != m5_dataset_label_inventory_root_sha256(
        run_id=RUN_ID,
        dataset_id=DATASET_ID,
        report_id=REPORT_ID,
        receipts=(
            first,
            second.model_copy(update={"role": M5DatasetLabelSnapshotRole.EXPORTED}),
        ),
    )
    with pytest.raises(ValueError, match="duplicate label IDs"):
        m5_dataset_label_inventory_root_sha256(
            run_id=RUN_ID,
            dataset_id=DATASET_ID,
            report_id=REPORT_ID,
            receipts=(first, first),
        )
    with pytest.raises(ValueError, match="hard limit"):
        m5_dataset_label_inventory_root_sha256(
            run_id=RUN_ID,
            dataset_id=DATASET_ID,
            report_id=REPORT_ID,
            receipts=(first,) * (MAX_M5_DATASET_SNAPSHOT_LABELS + 1),
        )


def test_crop_snapshot_binds_historical_case_pack_and_rejects_cross_run() -> None:
    authority = _crop_snapshot()
    serialized = authority.model_dump(mode="json")

    assert M5DatasetCropSnapshotAuthority.model_validate(serialized) == authority
    assert authority.model_copy(update={"case_revision": 8}).authority_id != (
        authority.authority_id
    )
    assert authority.model_copy(
        update={"evidence_pack_document_sha256": "7" * 64}
    ).authority_id != (authority.authority_id)
    with pytest.raises(ValidationError, match="authority_id"):
        M5DatasetCropSnapshotAuthority.model_validate({**serialized, "authority_id": "f" * 64})
    with pytest.raises(ValidationError, match="crosses run scope"):
        authority.model_copy(update={"run_id": "run-2"})


def test_crop_inventory_root_is_order_independent_scoped_and_unique() -> None:
    first = _crop_snapshot(10)
    second = _crop_snapshot(11)
    forward = m5_dataset_crop_inventory_root_sha256(
        run_id=RUN_ID,
        dataset_id=DATASET_ID,
        report_id=REPORT_ID,
        authorities=(first, second),
    )
    reverse = m5_dataset_crop_inventory_root_sha256(
        run_id=RUN_ID,
        dataset_id=DATASET_ID,
        report_id=REPORT_ID,
        authorities=(second, first),
    )

    assert forward == reverse
    with pytest.raises(ValueError, match="duplicate Crop IDs"):
        m5_dataset_crop_inventory_root_sha256(
            run_id=RUN_ID,
            dataset_id=DATASET_ID,
            report_id=REPORT_ID,
            authorities=(first, first),
        )
    with pytest.raises(ValueError, match="crosses snapshot scope"):
        m5_dataset_crop_inventory_root_sha256(
            run_id=RUN_ID,
            dataset_id="dataset-2",
            report_id=REPORT_ID,
            authorities=(first,),
        )
    with pytest.raises(ValueError, match="hard limit"):
        m5_dataset_crop_inventory_root_sha256(
            run_id=RUN_ID,
            dataset_id=DATASET_ID,
            report_id=REPORT_ID,
            authorities=(first,) * (MAX_M5_DATASET_SNAPSHOT_CROPS + 1),
        )


def test_registration_snapshot_header_is_fixed_size_scoped_and_content_addressed() -> None:
    authority = _registration()
    serialized = authority.model_dump(mode="json")

    assert "label_receipts" not in serialized
    assert "crop_authorities" not in serialized
    assert "report" not in serialized
    assert M5DatasetRegistrationSnapshotAuthority.model_validate(serialized) == authority
    assert authority.model_copy(update={"label_inventory_root_sha256": "f" * 64}).authority_id != (
        authority.authority_id
    )
    with pytest.raises(ValidationError, match="authority_id"):
        M5DatasetRegistrationSnapshotAuthority.model_validate(
            {**serialized, "authority_id": "f" * 64}
        )
    with pytest.raises(ValidationError, match="crosses causal run scope"):
        authority.model_copy(
            update={"causal_cut": authority.causal_cut.model_copy(update={"run_id": "run-2"})}
        )


def test_registration_snapshot_enforces_counts_genesis_and_canonical_empty_roots() -> None:
    genesis = M5TrainingCausalWatermark(
        run_id=RUN_ID,
        sequence=0,
        event_sha256=M5_TRAINING_CAUSAL_GENESIS_SHA256,
    )
    empty = _registration(
        causal_cut=genesis,
        label_count=0,
        crop_count=0,
    )

    assert empty.label_count == empty.crop_count == 0
    with pytest.raises(ValidationError, match="cannot use the genesis"):
        _registration(causal_cut=genesis)
    with pytest.raises(ValidationError, match="cannot exceed label count"):
        _registration(label_count=0, crop_count=1)
    with pytest.raises(ValidationError, match="canonical empty root"):
        empty.model_copy(update={"label_inventory_root_sha256": "f" * 64})
    with pytest.raises(ValidationError, match="canonical empty root"):
        empty.model_copy(update={"crop_inventory_root_sha256": "f" * 64})
    with pytest.raises(ValidationError):
        empty.model_copy(update={"label_count": MAX_M5_DATASET_SNAPSHOT_LABELS + 1})
    with pytest.raises(ValidationError):
        empty.model_copy(update={"crop_count": MAX_M5_DATASET_SNAPSHOT_CROPS + 1})
