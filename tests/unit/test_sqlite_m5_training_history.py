from __future__ import annotations

import sqlite3

import pytest

from labcourt.adapters.storage._sqlite_m5_training_history import (
    insert_m5_dataset_crop_snapshot,
    insert_m5_dataset_registration_snapshot,
    insert_m5_training_causal_event,
    list_m5_dataset_crop_snapshots,
    load_m5_dataset_registration_snapshot,
    load_m5_training_causal_events,
    require_m5_dataset_registration_marker,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.application.m5_training_history import (
    build_m5_dataset_registration_commit_event,
)
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
    M5DatasetCropSnapshotAuthority,
    M5DatasetRegistrationSnapshotAuthority,
    M5TrainingCausalEvent,
    M5TrainingCausalEventKind,
    M5TrainingCausalWatermark,
    m5_dataset_crop_inventory_root_sha256,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification

RUN_ID = "run-1"
DATASET_ID = "dataset-1"
REPORT_ID = "d" * 64
COMMAND_ID = "e" * 64
MANIFEST_ID = "a" * 64
DETECTOR_MANIFEST_ID = "b" * 64
RULE_VERSION = "rules-v1"


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE m5_training_causal_events (
            run_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            source_identity TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_document_sha256 TEXT NOT NULL,
            manifest_id TEXT NOT NULL,
            previous_event_sha256 TEXT NOT NULL,
            event_sha256 TEXT NOT NULL,
            label_id TEXT,
            event_json TEXT NOT NULL,
            document_sha256 TEXT NOT NULL,
            PRIMARY KEY (run_id, sequence)
        );
        CREATE TABLE dataset_registration_snapshots (
            run_id TEXT NOT NULL,
            authority_id TEXT NOT NULL,
            dataset_id TEXT NOT NULL,
            report_id TEXT NOT NULL,
            command_id TEXT NOT NULL,
            report_document_sha256 TEXT NOT NULL,
            causal_cut_sequence INTEGER NOT NULL,
            causal_cut_event_id TEXT,
            causal_cut_event_sha256 TEXT NOT NULL,
            label_count INTEGER NOT NULL,
            label_inventory_root_sha256 TEXT NOT NULL,
            crop_count INTEGER NOT NULL,
            crop_inventory_root_sha256 TEXT NOT NULL,
            manifest_id TEXT NOT NULL,
            rule_version TEXT NOT NULL,
            detector_manifest_id TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            document_sha256 TEXT NOT NULL,
            PRIMARY KEY (run_id, authority_id)
        );
        CREATE TABLE dataset_crop_snapshots (
            run_id TEXT NOT NULL,
            authority_id TEXT NOT NULL,
            registration_snapshot_authority_id TEXT NOT NULL,
            dataset_id TEXT NOT NULL,
            report_id TEXT NOT NULL,
            crop_id TEXT NOT NULL,
            crop_authority_sha256 TEXT NOT NULL,
            case_id TEXT NOT NULL,
            case_revision INTEGER NOT NULL,
            case_document_sha256 TEXT NOT NULL,
            evidence_pack_id TEXT NOT NULL,
            evidence_pack_version INTEGER NOT NULL,
            evidence_pack_document_sha256 TEXT NOT NULL,
            authority_json TEXT NOT NULL,
            document_sha256 TEXT NOT NULL,
            PRIMARY KEY (run_id, authority_id)
        );
        """
    )
    return connection


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


def _crop_snapshot() -> M5DatasetCropSnapshotAuthority:
    source_sha256 = "3" * 64
    pixel_sha256 = "4" * 64
    media_sha256 = "5" * 64
    frame = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="camera-1:stream-1:10")
    detection = ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id="detection-10")
    refs = (detection, frame)
    crop = Crop(
        frame_id=frame.artifact_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=80),
        source_refs=refs,
        local_path=f"runs/{RUN_ID}/media/focus-10.png",
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
    crop_authority = TrainingCropAuthority(
        run_id=RUN_ID,
        case_id="case-1",
        crop=crop,
        verification=verification,
        detector_manifest_id=DETECTOR_MANIFEST_ID,
        manifest_id=MANIFEST_ID,
        rule_version=RULE_VERSION,
    )
    return M5DatasetCropSnapshotAuthority(
        run_id=RUN_ID,
        dataset_id=DATASET_ID,
        report_id=REPORT_ID,
        crop_authority=crop_authority,
        case_revision=7,
        case_document_sha256="6" * 64,
        evidence_pack_id="7" * 64,
        evidence_pack_version=2,
        evidence_pack_document_sha256="8" * 64,
    )


def _snapshot(
    event: M5TrainingCausalEvent,
    crop: M5DatasetCropSnapshotAuthority,
) -> M5DatasetRegistrationSnapshotAuthority:
    return M5DatasetRegistrationSnapshotAuthority(
        run_id=RUN_ID,
        dataset_id=DATASET_ID,
        report_id=REPORT_ID,
        command_id=COMMAND_ID,
        report_document_sha256="9" * 64,
        causal_cut=M5TrainingCausalWatermark(
            run_id=RUN_ID,
            sequence=event.sequence,
            event_id=event.event_id,
            event_sha256=event.event_sha256,
        ),
        label_count=1,
        label_inventory_root_sha256="c" * 64,
        crop_count=1,
        crop_inventory_root_sha256=m5_dataset_crop_inventory_root_sha256(
            run_id=RUN_ID,
            dataset_id=DATASET_ID,
            report_id=REPORT_ID,
            authorities=(crop,),
        ),
        manifest_id=MANIFEST_ID,
        rule_version=RULE_VERSION,
        detector_manifest_id=DETECTOR_MANIFEST_ID,
    )


def _insert_complete_history(
    connection: sqlite3.Connection,
) -> tuple[
    M5TrainingCausalEvent,
    M5DatasetRegistrationSnapshotAuthority,
    M5DatasetCropSnapshotAuthority,
    M5TrainingCausalEvent,
]:
    event = _label_event()
    crop = _crop_snapshot()
    snapshot = _snapshot(event, crop)
    marker = build_m5_dataset_registration_commit_event(snapshot)
    connection.execute("BEGIN IMMEDIATE")
    insert_m5_training_causal_event(connection, event)
    insert_m5_dataset_registration_snapshot(connection, snapshot)
    insert_m5_dataset_crop_snapshot(connection, snapshot.authority_id, crop)
    insert_m5_training_causal_event(connection, marker)
    connection.commit()
    return event, snapshot, crop, marker


def test_training_history_sqlite_round_trip_ignores_future_legal_tail() -> None:
    connection = _connection()
    event, snapshot, crop, marker = _insert_complete_history(connection)

    assert load_m5_training_causal_events(connection, RUN_ID) == (event, marker)
    assert (
        load_m5_dataset_registration_snapshot(connection, RUN_ID, snapshot.authority_id) == snapshot
    )
    assert list_m5_dataset_crop_snapshots(connection, RUN_ID, snapshot.authority_id) == (crop,)
    assert require_m5_dataset_registration_marker(connection, snapshot) == marker

    tail = _label_event(
        label_id="label-tail",
        sequence=3,
        previous=marker.event_sha256,
        source_id="f" * 64,
    )
    connection.execute("BEGIN IMMEDIATE")
    insert_m5_training_causal_event(connection, tail)
    connection.commit()

    assert load_m5_training_causal_events(connection, RUN_ID) == (event, marker, tail)
    assert require_m5_dataset_registration_marker(connection, snapshot) == marker
    assert list_m5_dataset_crop_snapshots(connection, RUN_ID, snapshot.authority_id) == (crop,)


def test_training_history_insert_requires_caller_owned_transaction() -> None:
    connection = _connection()

    with pytest.raises(RepositoryIntegrityError, match="caller-owned transaction"):
        insert_m5_training_causal_event(connection, _label_event())


@pytest.mark.parametrize(
    ("table", "assignment", "message"),
    [
        (
            "m5_training_causal_events",
            "event_sha256 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
            "event indexes",
        ),
        (
            "dataset_registration_snapshots",
            "label_count = 0",
            "snapshot indexes",
        ),
        (
            "dataset_crop_snapshots",
            "case_revision = 8",
            "Crop snapshot indexes",
        ),
    ],
)
def test_training_history_loaders_reject_index_tampering(
    table: str,
    assignment: str,
    message: str,
) -> None:
    connection = _connection()
    _, snapshot, _, _ = _insert_complete_history(connection)
    connection.execute(f"UPDATE {table} SET {assignment}")

    with pytest.raises(RepositoryIntegrityError, match=message):
        if table == "m5_training_causal_events":
            load_m5_training_causal_events(connection, RUN_ID)
        elif table == "dataset_registration_snapshots":
            load_m5_dataset_registration_snapshot(connection, RUN_ID, snapshot.authority_id)
        else:
            list_m5_dataset_crop_snapshots(connection, RUN_ID, snapshot.authority_id)


def test_registration_marker_is_required_not_repaired() -> None:
    connection = _connection()
    event = _label_event()
    crop = _crop_snapshot()
    snapshot = _snapshot(event, crop)
    connection.execute("BEGIN IMMEDIATE")
    insert_m5_training_causal_event(connection, event)
    insert_m5_dataset_registration_snapshot(connection, snapshot)
    insert_m5_dataset_crop_snapshot(connection, snapshot.authority_id, crop)
    connection.commit()

    with pytest.raises(RepositoryIntegrityError, match="exact unique marker"):
        require_m5_dataset_registration_marker(connection, snapshot)


def test_crop_snapshot_closure_rejects_header_root_mismatch() -> None:
    connection = _connection()
    event = _label_event()
    crop = _crop_snapshot()
    snapshot = _snapshot(event, crop).model_copy(update={"crop_inventory_root_sha256": "f" * 64})
    connection.execute("BEGIN IMMEDIATE")
    insert_m5_training_causal_event(connection, event)
    insert_m5_dataset_registration_snapshot(connection, snapshot)

    with pytest.raises(RepositoryIntegrityError, match="root differs"):
        insert_m5_dataset_crop_snapshot(connection, snapshot.authority_id, crop)
    connection.rollback()
