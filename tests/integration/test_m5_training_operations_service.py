from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage._sqlite_m5_training_history import (
    insert_m5_training_causal_event,
    load_m5_training_causal_events,
)
from labcourt.adapters.storage.secure_dataset_publisher import (
    DatasetArtifactVerificationError,
    SecureDatasetArtifactVerifier,
)
from labcourt.adapters.storage.secure_workspace import (
    SecureWorkspace,
    create_owner_only_directory,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_repository import (
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.appeal_resolution import build_appeal_resolution_intent
from labcourt.application.dataset_export import BuiltCocoDataset, build_coco_dataset
from labcourt.application.m5_dataset_retention import m5_dataset_retention_holds
from labcourt.application.m5_human_labels import build_m5_appeal_training_labels
from labcourt.application.m5_training_history import build_m5_training_label_causal_event
from labcourt.application.m5_training_operations import (
    M5TrainingExportError,
    M5TrainingExportFailureCode,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import (
    AppealStatus,
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    RetentionHoldKind,
    TrainingLabelQuality,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, EvidencePackDraft
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_appeals import (
    AppealResolutionCommand,
    AppealReviewCommand,
    AppealSubmissionCommand,
)
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_training import (
    CocoDatasetExportCommand,
    TrainingCropAuthority,
)
from labcourt.contracts.m5_training_history import (
    M5_TRAINING_CAUSAL_GENESIS_SHA256,
    M5TrainingCausalEvent,
    M5TrainingCausalEventKind,
)
from labcourt.contracts.m5_training_provenance import M5TrainingLabelAuthority
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.training import TrainingLabel
from labcourt.domain.appeal_fsm import begin_appeal_review, submit_appeal
from labcourt.exceptions import ContractViolation
from labcourt.ports.pixels import rgb8_pixel_sha256
from labcourt.services.m5_training_operations import export_m5_training_dataset
from tests.integration.test_m3_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    RECORDED_AT,
    ROOT,
    RUN_ID,
    _draft,
    _manifest,
)
from tests.integration.test_m5_sqlite_alert_repository import (
    _automatic_precedent,
    _draft_for_manifest,
    _manifest_with_stream,
    _MutableClock,
    _prepare_ready_case,
)


@dataclass(frozen=True, slots=True)
class _PreparedTrainingRun:
    workspace_root: Path
    database: Path
    media_path: Path
    media_bytes: bytes
    crop: Crop
    manifest: RunManifest
    strong_label_id: str


def _reviewed_label(
    *,
    label_id: str,
    crop: Crop,
    quality: TrainingLabelQuality,
    excluded_reason: str | None = None,
) -> TrainingLabel:
    manifest = _manifest()
    return TrainingLabel(
        label_id=label_id,
        case_id=_draft(version=1, complete=True).case_id,
        crop_id=crop.crop_id,
        bbox=BBoxXYXY(x1=0, y1=0, x2=10, y2=10),
        label_name=f"reviewed-{label_id}",
        label_value=True,
        quality=quality,
        source="human-review" if quality == TrainingLabelQuality.HUMAN_CONFIRMED else "machine",
        reviewer_id=("reviewer-1" if quality == TrainingLabelQuality.HUMAN_CONFIRMED else None),
        rule_version=manifest.rule_version,
        detector_manifest_id=manifest.models["detector"].model_manifest_id,
        excluded_reason=excluded_reason,
    )


def _insert_training_label_row(
    connection: sqlite3.Connection,
    label: TrainingLabel,
    manifest_id: str,
) -> None:
    raw = canonical_json(label.model_dump(mode="json"))
    connection.execute(
        """
        INSERT INTO training_labels(
            run_id, label_id, case_id, crop_id, quality, source,
            reviewer_id, rule_version, detector_manifest_id, manifest_id,
            strong_provenance_id, label_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
        """,
        (
            RUN_ID,
            label.label_id,
            label.case_id,
            label.crop_id,
            label.quality.value,
            label.source,
            label.reviewer_id,
            label.rule_version,
            label.detector_manifest_id,
            manifest_id,
            raw,
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        ),
    )


def _insert_training_labels(database: Path, labels: tuple[TrainingLabel, ...]) -> None:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        manifest_row = connection.execute(
            "SELECT manifest_id FROM runs WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
        assert manifest_row is not None
        manifest_id = str(manifest_row[0])
        events = load_m5_training_causal_events(connection, RUN_ID)
        previous_event_sha256 = (
            events[-1].event_sha256 if events else M5_TRAINING_CAUSAL_GENESIS_SHA256
        )
        for label in labels:
            event = build_m5_training_label_causal_event(
                run_id=RUN_ID,
                manifest_id=manifest_id,
                authority=M5TrainingLabelAuthority(label=label),
                sequence=len(events) + 1,
                previous_event_sha256=previous_event_sha256,
            )
            insert_m5_training_causal_event(connection, event)
            events = (*events, event)
            previous_event_sha256 = event.event_sha256
            _insert_training_label_row(connection, label, manifest_id)
        connection.commit()


def _commit_upheld_training_label(
    repository: SQLiteM5Repository,
    *,
    case_id: str,
    crop: Crop,
) -> TrainingLabel:
    source = repository.load_closed_case_authority(RUN_ID, case_id)
    submitted = submit_appeal(
        source,
        AppealSubmissionCommand(
            run_id=RUN_ID,
            case_id=case_id,
            appeal_id="appeal-training-export-1",
            expected_case_revision=source.case_revision,
            expected_case_authority_sha256=source.authority_sha256,
            reason="Human review confirmed the original adjudication and label.",
            submitted_by="subject-training-export",
        ),
        None,
    )
    assert repository.append_appeal_version(submitted, None) == submitted
    reviewed = begin_appeal_review(
        submitted,
        AppealReviewCommand(
            run_id=RUN_ID,
            case_id=case_id,
            appeal_id=submitted.appeal.appeal_id,
            expected_appeal_authority_sha256=submitted.authority_sha256,
            reviewer_id="reviewer-training-export",
        ),
    )
    assert repository.append_appeal_version(reviewed, submitted.authority_sha256) == reviewed
    labels = build_m5_appeal_training_labels(
        appeal_authority=reviewed,
        terminal_status=AppealStatus.UPHELD,
        authored_inputs=(
            M5AppealTrainingLabelInput(
                crop_id=crop.crop_id,
                bbox=BBoxXYXY(x1=0, y1=0, x2=10, y2=10),
                label_name="reviewed-human-label",
                label_value=True,
            ),
        ),
    )
    command = AppealResolutionCommand(
        run_id=RUN_ID,
        case_id=case_id,
        appeal_id=reviewed.appeal.appeal_id,
        expected_appeal_authority_sha256=reviewed.authority_sha256,
        status=AppealStatus.UPHELD,
        reviewer_id="reviewer-training-export",
        resolution_summary="Human review upheld the original decision.",
        resolved_decision=source.final_decision,
        training_labels=labels,
    )
    intent = build_appeal_resolution_intent(
        case_authority=source,
        appeal_authority=reviewed,
        precedent_snapshot=repository.load_resolution_precedent_snapshot(RUN_ID, case_id),
        command=command,
    )
    assert repository.commit_resolution(intent) == intent
    return labels[0]


def _prepare_training_run(tmp_path: Path) -> _PreparedTrainingRun:
    workspace_root = tmp_path / "workspace"
    create_owner_only_directory(workspace_root)
    expected_manifest = _manifest_with_stream()
    base = _draft_for_manifest(expected_manifest)
    base_crop = base.crops[0]
    pixels = bytes((32, 64, 96)) * (base_crop.output_width * base_crop.output_height)
    media_bytes = encode_rgb_png(base_crop.output_width, base_crop.output_height, pixels)
    media_sha256 = hashlib.sha256(media_bytes).hexdigest()
    crop_payload = base_crop.model_dump(mode="json", exclude={"crop_id"})
    crop_payload.update(
        {
            "local_path": f"{RUN_ID}/frames/{media_sha256}.png",
            "pixel_sha256": rgb8_pixel_sha256(
                base_crop.output_width,
                base_crop.output_height,
                pixels,
            ),
            "media_sha256": media_sha256,
            "size_bytes": len(media_bytes),
        }
    )
    crop = Crop.model_validate(crop_payload)
    draft_payload = base.model_dump(mode="json", exclude_computed_fields=True)
    draft_payload["focus_crops"] = [crop.model_dump(mode="json")]
    draft = EvidencePackDraft.model_validate(draft_payload)

    config = load_config(ROOT / "configs" / "demo.yaml")
    with SecureWorkspace(
        workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        workspace.ensure_private_directory(RUN_ID)
        workspace.ensure_private_directory(f"{RUN_ID}/frames")
        workspace.create_new(crop.local_path or "", media_bytes, media_sha256)
    clock = _MutableClock()
    database, _, repository, ready, manifest, prepared_config = _prepare_ready_case(
        workspace_root,
        clock=clock,
        draft=draft,
    )
    assert manifest == expected_manifest
    assert prepared_config == config
    alert_authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    automatic = _automatic_precedent(ready, manifest, config, alert_authority)
    closed = repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        alert_authority,
        automatic,
    )
    assert closed.case.evidence_packs[-1].crops == (crop,)
    strong_label = _commit_upheld_training_label(
        repository,
        case_id=closed.case.case_id,
        crop=crop,
    )

    labels = tuple(
        sorted(
            (
                _reviewed_label(
                    label_id="weak-1",
                    crop=crop,
                    quality=TrainingLabelQuality.WEAK_AUTO,
                ),
                _reviewed_label(
                    label_id="consensus-1",
                    crop=crop,
                    quality=TrainingLabelQuality.CONSENSUS_REVIEWED,
                ),
                _reviewed_label(
                    label_id="excluded-1",
                    crop=crop,
                    quality=TrainingLabelQuality.WEAK_AUTO,
                    excluded_reason="privacy-review-pending",
                ),
            ),
            key=lambda item: item.label_id,
        )
    )
    _insert_training_labels(database, labels)
    assert crop.local_path is not None
    return _PreparedTrainingRun(
        workspace_root=workspace_root,
        database=database,
        media_path=workspace_root / Path(crop.local_path),
        media_bytes=media_bytes,
        crop=crop,
        manifest=manifest,
        strong_label_id=strong_label.label_id,
    )


def _export(prepared: _PreparedTrainingRun):
    return export_m5_training_dataset(
        config=load_config(ROOT / "configs" / "demo.yaml"),
        workspace_root=prepared.workspace_root,
        database_path=prepared.database,
        run_id=RUN_ID,
        relative_path=f"{RUN_ID}/datasets/reviewed.coco.json",
    )


def _direct_build(
    prepared: _PreparedTrainingRun,
    verifier: StoredPngVerifier,
    *,
    max_input_labels: int = 10_000,
) -> BuiltCocoDataset:
    manifest = prepared.manifest
    labels = SQLiteM5Repository(
        prepared.database,
        BUSY_TIMEOUT_MS,
        lambda: RECORDED_AT,
    ).list_training_labels(RUN_ID, 10_000)
    verification = verifier.verify_crop(prepared.crop)
    assert verification.status == VerificationStatus.CURRENT_MEDIA_VERIFIED
    authority = TrainingCropAuthority(
        run_id=RUN_ID,
        case_id=_draft(version=1, complete=True).case_id,
        crop=prepared.crop,
        verification=verification,
        detector_manifest_id=manifest.models["detector"].model_manifest_id,
        manifest_id=manifest.manifest_id,
        rule_version=manifest.rule_version,
    )
    return build_coco_dataset(
        command=CocoDatasetExportCommand(
            run_id=RUN_ID,
            relative_path=f"{RUN_ID}/datasets/direct-reviewed.coco.json",
            detector_manifest_id=manifest.models["detector"].model_manifest_id,
            manifest_id=manifest.manifest_id,
            rule_version=manifest.rule_version,
            purpose="DETECTOR_TRAINING_FROM_REVIEWED_LABELS",
            retention_hold_kind=RetentionHoldKind.GOLD_SET,
            retention_policy_version="m5-gold-set-retention-v1",
            retention_period="UNTIL_EXPLICIT_RELEASE",
            max_input_labels=max_input_labels,
        ),
        labels=labels,
        crop_authorities=(authority,),
    )


def _registration_state(database: Path) -> tuple[object, ...]:
    with sqlite3.connect(database) as connection:
        run_head = connection.execute(
            """
            SELECT revision, audit_head_sequence, audit_head_hash
            FROM runs WHERE run_id = ?
            """,
            (RUN_ID,),
        ).fetchone()
        assert run_head is not None
        return (
            connection.execute("SELECT COUNT(*) FROM m5_training_causal_events").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM dataset_registration_snapshots").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM dataset_crop_snapshots").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM dataset_artifacts").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM retention_holds").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM retention_hold_audit_links").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0],
            *run_head,
        )


def _stored_verifier(
    workspace: SecureWorkspace,
) -> StoredPngVerifier:
    config = load_config(ROOT / "configs" / "demo.yaml")
    return StoredPngVerifier(
        run_id=RUN_ID,
        workspace=workspace,
        max_media_bytes=config.storage.max_media_bytes,
        max_image_pixels=config.storage.max_image_pixels,
    )


def _publish_direct_dataset(
    workspace: SecureWorkspace,
    built: BuiltCocoDataset,
) -> None:
    parent = str(Path(built.report.dataset.relative_path).parent).replace("\\", "/")
    parts = tuple(part for part in parent.split("/") if part)
    for index in range(1, len(parts) + 1):
        workspace.ensure_private_directory("/".join(parts[:index]))
    workspace.create_new(
        built.report.dataset.relative_path,
        built.content,
        built.report.dataset.content_sha256,
    )


def test_service_verifies_current_png_publishes_without_media_copy_and_replays(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)

    first = _export(prepared)
    committed_state = _registration_state(prepared.database)
    replay = _export(prepared)

    assert replay == first
    assert _registration_state(prepared.database) == committed_state
    assert first.exported_label_ids == (prepared.strong_label_id,)
    assert first.quarantined_label_ids == ("consensus-1", "excluded-1", "weak-1")
    assert first.weak_auto_count == 2
    assert first.consensus_reviewed_count == 1
    assert first.excluded_reason_count == 1
    target = prepared.workspace_root / Path(first.dataset.relative_path)
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert [item["labcourt_label_id"] for item in payload["annotations"]] == [
        prepared.strong_label_id
    ]
    assert [item["file_name"] for item in payload["images"]] == [prepared.crop.local_path]
    assert prepared.media_path.read_bytes() == prepared.media_bytes
    assert tuple(prepared.workspace_root.rglob("*.png")) == (prepared.media_path,)
    with sqlite3.connect(prepared.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM dataset_artifacts").fetchone() == (1,)
        hold_row = connection.execute(
            """
            SELECT rh.hold_id, rh.target_kind, rh.target_id, rh.hold_kind,
                   rh.owner_kind, rh.owner_id, rh.active, rh.manifest_id,
                   rh.policy_version, links.created_audit_sequence,
                   links.released_audit_sequence
            FROM retention_holds AS rh
            JOIN retention_hold_audit_links AS links
              ON links.run_id = rh.run_id AND links.hold_id = rh.hold_id
            WHERE rh.run_id = ? AND rh.owner_kind = ? AND rh.owner_id = ?
            """,
            (RUN_ID, ArtifactKind.DATASET.value, first.dataset.dataset_id),
        ).fetchone()
        assert hold_row is not None
        expected_hold = m5_dataset_retention_holds(first)[0]
        assert hold_row[:9] == (
            expected_hold.hold_id,
            ArtifactKind.CROP.value,
            prepared.crop.crop_id,
            RetentionHoldKind.GOLD_SET.value,
            ArtifactKind.DATASET.value,
            first.dataset.dataset_id,
            1,
            first.manifest_id,
            first.retention_policy_version,
        )
        assert hold_row[10] is None
        audit_row = connection.execute(
            """
            SELECT actor, action, object_kind, object_id,
                   before_sha256, after_sha256, manifest_id
            FROM audit_entries WHERE run_id = ? AND sequence = ?
            """,
            (RUN_ID, hold_row[9]),
        ).fetchone()
        assert audit_row == (
            AuditActorRole.RETENTION.value,
            AuditAction.RETENTION_HOLD_CREATED.value,
            ArtifactKind.CROP.value,
            prepared.crop.crop_id,
            None,
            sha256_hex(expected_hold.model_dump(mode="json")),
            first.manifest_id,
        )


def test_direct_sql_strong_label_without_provenance_is_rejected_without_residue(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    forged = _reviewed_label(
        label_id="forged-human-without-provenance",
        crop=prepared.crop,
        quality=TrainingLabelQuality.HUMAN_CONFIRMED,
    )
    with sqlite3.connect(prepared.database) as connection:
        before = (
            connection.execute("SELECT COUNT(*) FROM training_labels").fetchone(),
            connection.execute(
                "SELECT COUNT(*) FROM strong_training_label_provenance_receipts"
            ).fetchone(),
        )

    with (
        pytest.raises(sqlite3.IntegrityError),
        sqlite3.connect(prepared.database) as connection,
    ):
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        manifest_row = connection.execute(
            "SELECT manifest_id FROM runs WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
        assert manifest_row is not None
        manifest_id = str(manifest_row[0])
        events = load_m5_training_causal_events(connection, RUN_ID)
        previous = events[-1].event_sha256 if events else M5_TRAINING_CAUSAL_GENESIS_SHA256
        forged_event = M5TrainingCausalEvent(
            run_id=RUN_ID,
            sequence=len(events) + 1,
            event_kind=M5TrainingCausalEventKind.TRAINING_LABEL_APPENDED,
            source_id=sha256_hex(["forged-unproven-label", forged.label_id]),
            source_document_sha256=sha256_hex(forged.model_dump(mode="json")),
            manifest_id=manifest_id,
            previous_event_sha256=previous,
            label_id=forged.label_id,
        )
        insert_m5_training_causal_event(connection, forged_event)
        _insert_training_label_row(connection, forged, manifest_id)

    with sqlite3.connect(prepared.database) as connection:
        after = (
            connection.execute("SELECT COUNT(*) FROM training_labels").fetchone(),
            connection.execute(
                "SELECT COUNT(*) FROM strong_training_label_provenance_receipts"
            ).fetchone(),
        )
        assert after == before
        assert connection.execute(
            "SELECT COUNT(*) FROM training_labels WHERE label_id = ?",
            (forged.label_id,),
        ).fetchone() == (0,)


def test_service_refuses_tampered_current_media_before_publish_or_registration(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    prepared.media_path.write_bytes(b"tampered-not-a-png")

    with pytest.raises(M5TrainingExportError) as failure:
        _export(prepared)

    assert failure.value.code == M5TrainingExportFailureCode.CURRENT_PACK_VERIFICATION_FAILED
    assert not (prepared.workspace_root / RUN_ID / "datasets").exists()
    with sqlite3.connect(prepared.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM dataset_artifacts").fetchone() == (0,)


def test_direct_registration_without_trusted_crop_verifier_is_write_free(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        built = _direct_build(prepared, _stored_verifier(workspace))
        _publish_direct_dataset(workspace, built)
        before = _registration_state(prepared.database)
        repository = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        with pytest.raises(ContractViolation, match="trusted current-Crop verifier"):
            repository.register_dataset_artifact(built.report, built.content)
        assert _registration_state(prepared.database) == before


def test_direct_registration_without_published_dataset_verifier_is_write_free(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        crop_verifier = _stored_verifier(workspace)
        built = _direct_build(prepared, crop_verifier)
        _publish_direct_dataset(workspace, built)
        before = _registration_state(prepared.database)
        repository = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=crop_verifier,
        )
        with pytest.raises(ContractViolation, match="published-dataset verifier"):
            repository.register_dataset_artifact(built.report, built.content)
        assert _registration_state(prepared.database) == before


@pytest.mark.parametrize("dataset_state", ["missing", "tampered"])
def test_direct_registration_requires_exact_dataset_file_before_any_write(
    tmp_path: Path,
    dataset_state: str,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        crop_verifier = _stored_verifier(workspace)
        built = _direct_build(prepared, crop_verifier)
        if dataset_state == "tampered":
            _publish_direct_dataset(workspace, built)
            target = prepared.workspace_root / Path(built.report.dataset.relative_path)
            target.write_bytes(b"different-published-dataset-bytes")
        before = _registration_state(prepared.database)
        repository = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=crop_verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        with pytest.raises(
            DatasetArtifactVerificationError,
            match=r"FILE_UNAVAILABLE|CONTENT_HASH_MISMATCH",
        ):
            repository.register_dataset_artifact(built.report, built.content)
        assert _registration_state(prepared.database) == before


def test_direct_registration_binds_supplied_content_to_published_exact_bytes(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        crop_verifier = _stored_verifier(workspace)
        built = _direct_build(prepared, crop_verifier)
        _publish_direct_dataset(workspace, built)
        changed = bytearray(built.content)
        changed[-2] = changed[-2] ^ 1
        before = _registration_state(prepared.database)
        repository = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=crop_verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        with pytest.raises(DatasetArtifactVerificationError, match="CONTENT_BYTES_MISMATCH"):
            repository.register_dataset_artifact(built.report, bytes(changed))
        assert _registration_state(prepared.database) == before


@pytest.mark.parametrize("tamper_kind", ["missing", "invalid-bytes", "changed-pixels"])
def test_direct_registration_physically_reverifies_crop_and_rolls_back(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        verifier = _stored_verifier(workspace)
        built = _direct_build(prepared, verifier)
        _publish_direct_dataset(workspace, built)
        before = _registration_state(prepared.database)
        if tamper_kind == "missing":
            prepared.media_path.unlink()
        elif tamper_kind == "invalid-bytes":
            prepared.media_path.write_bytes(b"tampered-not-a-png")
        else:
            changed_pixels = bytes((96, 64, 32)) * (
                prepared.crop.output_width * prepared.crop.output_height
            )
            prepared.media_path.write_bytes(
                encode_rgb_png(
                    prepared.crop.output_width,
                    prepared.crop.output_height,
                    changed_pixels,
                )
            )
        repository = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        with pytest.raises(ContractViolation, match=r"do not rebuild|failed trusted"):
            repository.register_dataset_artifact(built.report, built.content)
        assert _registration_state(prepared.database) == before


@pytest.mark.parametrize(
    "phase",
    [
        "dataset.register.after_snapshot",
        "dataset.register.after_snapshot_crops",
        "dataset.register.after_registration_marker",
        "dataset.register.after_artifact",
        "dataset.register.after_hold_audit",
        "dataset.register.after_hold",
        "dataset.register.after_hold_link",
        "dataset.register.after_holds",
        "dataset.register.before_commit",
    ],
)
def test_dataset_and_gold_set_hold_registration_is_one_fault_atomic_transaction(
    tmp_path: Path,
    phase: str,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")

    def fail_at(observed: str) -> None:
        if observed == phase:
            raise RuntimeError(f"injected {phase}")

    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        verifier = _stored_verifier(workspace)
        built = _direct_build(prepared, verifier)
        _publish_direct_dataset(workspace, built)
        before = _registration_state(prepared.database)
        repository = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
            fault_injector=fail_at,
        )
        with pytest.raises(RuntimeError, match=r"injected dataset\.register"):
            repository.register_dataset_artifact(built.report, built.content)
        assert _registration_state(prepared.database) == before


def test_registration_rejects_self_consistent_report_that_omits_durable_inventory(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    manifest = prepared.manifest
    forged = build_coco_dataset(
        command=CocoDatasetExportCommand(
            run_id=RUN_ID,
            relative_path=f"{RUN_ID}/datasets/forged-empty.coco.json",
            detector_manifest_id=manifest.models["detector"].model_manifest_id,
            manifest_id=manifest.manifest_id,
            rule_version=manifest.rule_version,
            purpose="DETECTOR_TRAINING_FROM_REVIEWED_LABELS",
            retention_hold_kind=RetentionHoldKind.GOLD_SET,
            retention_policy_version="m5-gold-set-retention-v1",
            retention_period="UNTIL_EXPLICIT_RELEASE",
        ),
        labels=(),
        crop_authorities=(),
    )
    config = load_config(ROOT / "configs" / "demo.yaml")
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        _publish_direct_dataset(workspace, forged)
        before = _registration_state(prepared.database)
        repository = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=_stored_verifier(workspace),
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        with pytest.raises(ContractViolation, match="do not rebuild"):
            repository.register_dataset_artifact(forged.report, forged.content)
        assert _registration_state(prepared.database) == before


def test_replay_ignores_legal_tail_label_added_after_registration_without_new_writes(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        verifier = _stored_verifier(workspace)
        built = _direct_build(prepared, verifier, max_input_labels=4)
        _publish_direct_dataset(workspace, built)
        repository = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        repository.register_dataset_artifact(built.report, built.content)
        _insert_training_labels(
            prepared.database,
            (
                _reviewed_label(
                    label_id="weak-tail",
                    crop=prepared.crop,
                    quality=TrainingLabelQuality.WEAK_AUTO,
                ),
            ),
        )
        before = _registration_state(prepared.database)
        restarted = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        assert (
            restarted.register_dataset_artifact(
                built.report,
                built.content,
            )
            == built.report.dataset
        )
        assert _registration_state(prepared.database) == before


@pytest.mark.parametrize("tamper_kind", ["missing", "released", "extra"])
def test_replay_requires_exact_active_dataset_hold_and_audit_closure(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        verifier = _stored_verifier(workspace)
        built = _direct_build(prepared, verifier)
        _publish_direct_dataset(workspace, built)
        repository = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        repository.register_dataset_artifact(built.report, built.content)
        expected_hold = m5_dataset_retention_holds(built.report)[0]
        retention = SQLiteEvidenceRepository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            verifier=verifier,
            clock=lambda: RECORDED_AT,
        )
        if tamper_kind == "released":
            retention.release_retention_hold(RUN_ID, expected_hold.hold_id)
        elif tamper_kind == "extra":
            retention.create_retention_hold(
                expected_hold.model_copy(
                    update={
                        "hold_id": sha256_hex(
                            ["test-extra-dataset-retention-hold", expected_hold.hold_id]
                        )
                    }
                )
            )
        else:
            with sqlite3.connect(prepared.database) as connection:
                connection.execute("DROP TRIGGER retention_hold_audit_links_no_delete")
                connection.execute("DROP TRIGGER retention_holds_no_delete")
                connection.execute(
                    "DELETE FROM retention_hold_audit_links WHERE run_id = ? AND hold_id = ?",
                    (RUN_ID, expected_hold.hold_id),
                )
                connection.execute(
                    "DELETE FROM retention_holds WHERE run_id = ? AND hold_id = ?",
                    (RUN_ID, expected_hold.hold_id),
                )
                connection.commit()

        before = _registration_state(prepared.database)
        restarted = SQLiteM5Repository(
            prepared.database,
            BUSY_TIMEOUT_MS,
            lambda: RECORDED_AT,
            training_crop_verifier=verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        with pytest.raises(RepositoryIntegrityError, match="retention hold"):
            restarted.register_dataset_artifact(built.report, built.content)
        assert _registration_state(prepared.database) == before
