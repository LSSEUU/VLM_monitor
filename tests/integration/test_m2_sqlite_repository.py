import hashlib
import shutil
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from labcourt.adapters.storage.sqlite_repository import (
    MigrationIntegrityError,
    MigrationRunner,
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
)
from labcourt.application.retention import RetentionCoordinator
from labcourt.contracts.audit import validate_audit_chain
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    CaseStatus,
    ClosureDefectCode,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PrivacyPolicy,
    PrivacyReasonCode,
    PurgeDisposition,
    PurgeReasonCode,
    PurgeRecoveryKind,
    RetentionHoldKind,
    VerificationStatus,
)
from labcourt.contracts.events import CandidateEvent, ObjectiveFact, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    EvidencePack,
    EvidencePackDraft,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import (
    ArtifactRef,
    ArtifactVerification,
    ClosureReport,
    PurgeItemResult,
    RetentionHold,
    ScopedArtifactRef,
)
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
    EvidenceMissing,
    ManifestMismatch,
    ProviderUnavailable,
)
from labcourt.ports.retention import PurgeLease, PurgeRecoveryCandidate

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"
MIGRATIONS = Path(__file__).parents[2] / "src" / "labcourt" / "adapters" / "storage" / "migrations"
RUN_ID = "run-01"
BUSY_TIMEOUT_MS = 5_000
RECORDED_AT = datetime(2026, 7, 27, 12, 34, 56, 123456, tzinfo=UTC)


class _Verifier:
    def __init__(self, status: VerificationStatus = VerificationStatus.VERIFIED) -> None:
        self._status = status

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        if crop.availability == MediaAvailability.PURGED_BY_RETENTION:
            return ArtifactVerification(
                artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
                status=VerificationStatus.PURGED_BY_RETENTION,
                availability=crop.availability,
                media_type=crop.media_type,
                expected_source_pixel_sha256=crop.source_media_sha256,
                expected_output_pixel_sha256=crop.pixel_sha256,
                expected_media_sha256=crop.media_sha256,
                expected_width=crop.output_width,
                expected_height=crop.output_height,
                expected_size_bytes=crop.size_bytes,
                reason_code="PURGED_BY_RETENTION",
            )
        actual_media_sha256 = crop.media_sha256
        if self._status == VerificationStatus.MEDIA_HASH_MISMATCH:
            actual_media_sha256 = "d" * 64
        actual_size_bytes = crop.size_bytes
        if self._status == VerificationStatus.SIZE_MISMATCH:
            actual_size_bytes += 1
        return ArtifactVerification(
            artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            status=self._status,
            availability=crop.availability,
            media_type=crop.media_type,
            expected_source_pixel_sha256=crop.source_media_sha256,
            actual_source_pixel_sha256=crop.source_media_sha256,
            expected_output_pixel_sha256=crop.pixel_sha256,
            actual_output_pixel_sha256=crop.pixel_sha256,
            expected_media_sha256=crop.media_sha256,
            actual_media_sha256=actual_media_sha256,
            expected_width=crop.output_width,
            actual_width=crop.output_width,
            expected_height=crop.output_height,
            actual_height=crop.output_height,
            expected_size_bytes=crop.size_bytes,
            actual_size_bytes=actual_size_bytes,
            reason_code=(
                "PRIVACY_REPLAY_MISMATCH"
                if self._status == VerificationStatus.PRIVACY_POLICY_VIOLATION
                else None
            ),
        )

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        del run_id, ref
        return False


class _ReferenceClaimingVerifier(_Verifier):
    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        del run_id, ref
        return True


def _clock() -> datetime:
    return RECORDED_AT


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _event() -> CandidateEvent:
    return CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )


def _frame() -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id="demo-ntsc",
        frame_index=90,
        fps_num=30,
        fps_den=1,
        width=640,
        height=480,
        content_sha256="a" * 64,
    )


def _detection(
    *,
    detection_id: str = "det-bottle-090",
    frame: FrameRef | None = None,
    model_manifest_id: str | None = None,
) -> Detection:
    source_frame = frame or _frame()
    return Detection(
        detection_id=detection_id,
        frame_id=source_frame.frame_id,
        label="reagent_bottle",
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        score=0.92,
        track_ref=_event().primary_track_ref,
        model_manifest_id=(model_manifest_id or _manifest().models["detector"].model_manifest_id),
    )


def _pack(*, version: int, complete: bool) -> EvidencePack:
    event = _event()
    frame = _frame()
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id)
    detection_ref = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id="det-bottle-090",
    )
    source_refs = tuple(sorted((detection_ref, frame_ref), key=lambda ref: ref.sort_key))
    crop = Crop(
        frame_id=frame.frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        source_refs=source_refs,
        local_path="frames/focus.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256="a" * 64,
        pixel_sha256="b" * 64,
        media_sha256="c" * 64,
        output_width=100,
        output_height=200,
        size_bytes=512,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="ppe-redaction-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
    )
    draft = EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=version,
        complete=complete,
        event=event,
        key_frame_ids=(frame.frame_id,),
        focus_crops=(crop,),
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=event.start_frame,
            end_frame_exclusive=event.end_frame_exclusive,
            observed_frame_count=event.end_frame_exclusive - event.start_frame,
        ),
        confirmation_record=event.confirmation,
        manifest_id=event.manifest_id,
    )
    report = ClosureReport(
        run_id=RUN_ID,
        root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )
    return EvidencePack.model_validate(
        {
            **draft.model_dump(mode="json", exclude_computed_fields=True),
            "closure_report": report.model_dump(mode="json"),
        }
    )


def _draft(*, version: int, complete: bool) -> EvidencePackDraft:
    pack = _pack(version=version, complete=complete)
    payload = pack.model_dump(mode="json", exclude_computed_fields=True)
    payload.pop("closure_report")
    return EvidencePackDraft.model_validate(payload)


def _draft_with_detection(
    *,
    detection_id: str = "det-bottle-090",
    version: int = 1,
    complete: bool = False,
) -> EvidencePackDraft:
    draft = _draft(version=version, complete=complete)
    crop = draft.focus_crops[0]
    detection_ref = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id=detection_id,
    )
    source_refs = tuple(
        sorted(
            (
                *(ref for ref in crop.source_refs if ref.kind != ArtifactKind.DETECTION),
                detection_ref,
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    privacy_receipt = crop.privacy_receipt.model_copy(update={"input_refs": source_refs})
    changed_crop = crop.model_copy(
        update={
            "source_refs": source_refs,
            "privacy_receipt": privacy_receipt,
        }
    )
    return draft.model_copy(update={"focus_crops": (changed_crop,)})


def _repository(
    tmp_path: Path,
    *,
    verifier: _Verifier | None = None,
    fault_injector: Callable[[str], None] | None = None,
) -> tuple[Path, SQLiteEvidenceRepository]:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=verifier or _Verifier(),
        clock=_clock,
        fault_injector=fault_injector,
    )
    repository.register_run(RUN_ID, _manifest())
    return database, repository


def _register_case(
    repository: SQLiteEvidenceRepository,
    *,
    include_detection: bool = True,
) -> None:
    repository.register_frame(RUN_ID, _frame())
    if include_detection:
        repository.register_detection(RUN_ID, _detection())
    repository.create_or_get_case(RUN_ID, _event())


def test_load_frame_returns_authoritative_dimensions_and_rejects_unknown(
    tmp_path: Path,
) -> None:
    _, repository = _repository(tmp_path)
    assert repository.load_run_manifest(RUN_ID) == _manifest()
    frame = _frame()
    repository.register_frame(RUN_ID, frame)

    assert repository.load_frame(RUN_ID, frame.frame_id) == frame
    with pytest.raises(ContractViolation, match="unknown frame"):
        repository.load_frame(RUN_ID, "cam-01:stream-01:999")


class _MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _retention_draft(
    *,
    version: int,
    complete: bool,
    as_subject: bool = False,
) -> EvidencePackDraft:
    payload = _draft(version=version, complete=complete).model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    crop = cast(list[dict[str, object]], payload["focus_crops"])[0]
    crop["local_path"] = f"{RUN_ID}/frames/{'c' * 64}.png"
    if as_subject:
        crop["source"] = CropSource.SUBJECT.value
        receipt = cast(dict[str, object], crop["privacy_receipt"])
        receipt["reason_code"] = PrivacyReasonCode.SUBJECT_FULL_REDACTION.value
        payload["subject_crops"] = [crop]
        payload["focus_crops"] = []
    return EvidencePackDraft.model_validate(payload)


def _multi_media_retention_draft(media_sha256s: tuple[str, ...]) -> EvidencePackDraft:
    base = _retention_draft(version=1, complete=True)
    template = base.focus_crops[0]
    crops: list[Crop] = []
    for offset, media_sha256 in enumerate(media_sha256s):
        payload = template.model_dump(mode="json", exclude_computed_fields=True)
        payload["bbox"] = {
            "x1": 10 + offset,
            "y1": 20,
            "x2": 110 + offset,
            "y2": 220,
        }
        payload["media_sha256"] = media_sha256
        payload["local_path"] = f"{RUN_ID}/frames/{media_sha256}.png"
        crops.append(Crop.model_validate(payload))
    ordered = tuple(sorted(crops, key=lambda crop: crop.crop_id))
    payload = base.model_dump(mode="json", exclude_computed_fields=True)
    payload["focus_crops"] = [crop.model_dump(mode="json") for crop in ordered]
    return EvidencePackDraft.model_validate(payload)


def _retention_repository(
    tmp_path: Path,
    *,
    clock: _MutableClock | None = None,
    fault_injector: Callable[[str], None] | None = None,
) -> tuple[Path, SQLiteEvidenceRepository, _MutableClock]:
    active_clock = clock or _MutableClock(RECORDED_AT)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=active_clock).apply_all()
    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=active_clock,
        fault_injector=fault_injector,
    )
    repository.register_run(RUN_ID, _manifest())
    _register_case(repository)
    return database, repository, active_clock


def _retention_hold(
    *,
    hold_id: str,
    kind: RetentionHoldKind,
    target_kind: ArtifactKind,
    target_id: str,
    owner_id: str,
    run_id: str = RUN_ID,
    manifest_id: str | None = None,
) -> RetentionHold:
    owner_kind = {
        RetentionHoldKind.APPEAL: ArtifactKind.APPEAL,
        RetentionHoldKind.GOLD_SET: ArtifactKind.DATASET,
        RetentionHoldKind.CHALLENGE_SET: ArtifactKind.DATASET,
        RetentionHoldKind.MANUAL_LEGAL_HOLD: ArtifactKind.CASE,
    }[kind]
    return RetentionHold(
        run_id=run_id,
        hold_id=hold_id,
        target_ref=ScopedArtifactRef(
            run_id=run_id,
            ref=ArtifactRef(kind=target_kind, artifact_id=target_id),
        ),
        kind=kind,
        owner_ref=ScopedArtifactRef(
            run_id=run_id,
            ref=ArtifactRef(kind=owner_kind, artifact_id=owner_id),
        ),
        manifest_id=manifest_id or _manifest().manifest_id,
        policy_version="retention-v1",
        reason_code="test-hold",
    )


def _retention_db_state(database: Path) -> tuple[object, ...]:
    connection = sqlite3.connect(database)
    try:
        media = connection.execute(
            """
            SELECT availability, local_path, purged_at
            FROM media_assets WHERE run_id = ? AND media_sha256 = ?
            """,
            (RUN_ID, "c" * 64),
        ).fetchone()
        attempts = connection.execute(
            """
            SELECT intent_audit_sequence, completion_audit_sequence,
                   completion_recovered, cleanup_acked_at, status
            FROM media_purge_attempts WHERE run_id = ? ORDER BY media_sha256
            """,
            (RUN_ID,),
        ).fetchall()
        head = connection.execute(
            """
            SELECT revision, audit_head_sequence, audit_head_hash
            FROM runs WHERE run_id = ?
            """,
            (RUN_ID,),
        ).fetchone()
        audit_count = connection.execute(
            "SELECT COUNT(*) FROM audit_entries WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
        hold_rows = connection.execute(
            """
            SELECT hold_id, active FROM retention_holds
            WHERE run_id = ? ORDER BY hold_id
            """,
            (RUN_ID,),
        ).fetchall()
        hold_links = connection.execute(
            """
            SELECT hold_id, created_audit_sequence, released_audit_sequence
            FROM retention_hold_audit_links
            WHERE run_id = ? ORDER BY hold_id
            """,
            (RUN_ID,),
        ).fetchall()
        return media, tuple(attempts), head, audit_count, tuple(hold_rows), tuple(hold_links)
    finally:
        connection.close()


def _purge_attempt_media(database: Path, status: str) -> tuple[str, ...]:
    connection = sqlite3.connect(database)
    try:
        return tuple(
            str(row[0])
            for row in connection.execute(
                """
                SELECT media_sha256 FROM media_purge_attempts
                WHERE run_id = ? AND status = ?
                ORDER BY intent_audit_sequence
                """,
                (RUN_ID, status),
            ).fetchall()
        )
    finally:
        connection.close()


def _counts(database: Path) -> dict[str, int]:
    connection = sqlite3.connect(database)
    try:
        return {
            table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "cases",
                "case_versions",
                "evidence_packs",
                "media_assets",
                "evidence_pack_crops",
                "audit_entries",
            )
        }
    finally:
        connection.close()


def test_migration_runner_is_idempotent_and_rejects_changed_sql(tmp_path: Path) -> None:
    copied = tmp_path / "migrations"
    shutil.copytree(MIGRATIONS, copied)
    database = tmp_path / "labcourt.sqlite3"
    runner = MigrationRunner(database, BUSY_TIMEOUT_MS, copied, _clock)

    assert runner.apply_all() == tuple(range(1, 19))
    assert runner.apply_all() == ()

    migration = copied / "0003_retention.sql"
    migration.write_text(
        migration.read_text(encoding="utf-8") + "\n-- forbidden mutation\n",
        encoding="utf-8",
    )
    with pytest.raises(MigrationIntegrityError, match="changed checksum"):
        runner.apply_all()


def test_detection_migration_upgrades_an_existing_m2_database(tmp_path: Path) -> None:
    copied = tmp_path / "migrations"
    copied.mkdir()
    shutil.copy2(MIGRATIONS / "0001_m2.sql", copied / "0001_m2.sql")
    database = tmp_path / "labcourt.sqlite3"

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied, _clock).apply_all() == (1,)
    shutil.copy2(
        MIGRATIONS / "0002_detections.sql",
        copied / "0002_detections.sql",
    )
    runner = MigrationRunner(database, BUSY_TIMEOUT_MS, copied, _clock)
    assert runner.apply_all() == (2,)
    assert runner.apply_all() == ()

    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'detections'"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,)]
    finally:
        connection.close()


def test_migration_runner_rejects_transaction_control_before_executing_sql(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    shutil.copytree(MIGRATIONS, copied)
    next_version = max(int(path.name[:4]) for path in copied.glob("[0-9][0-9][0-9][0-9]_*.sql")) + 1
    bad_migration = copied / f"{next_version:04d}_bad.sql"
    bad_migration.write_text(
        "CREATE TABLE leaked(value INTEGER);\nCOMMIT;\nSELECT no_such_function();\n",
        encoding="utf-8",
    )
    database = tmp_path / "labcourt.sqlite3"
    runner = MigrationRunner(database, BUSY_TIMEOUT_MS, copied, _clock)

    with pytest.raises(MigrationIntegrityError, match="forbidden top-level COMMIT"):
        runner.apply_all()

    connection = sqlite3.connect(database)
    try:
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'leaked'"
            ).fetchone()
            is None
        )
        assert (
            connection.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
            == []
        )
    finally:
        connection.close()


def test_failed_migration_rolls_back_its_schema_and_does_not_advance_version(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    shutil.copytree(MIGRATIONS, copied)
    next_version = max(int(path.name[:4]) for path in copied.glob("[0-9][0-9][0-9][0-9]_*.sql")) + 1
    (copied / f"{next_version:04d}_failure.sql").write_text(
        "CREATE TABLE rolled_back(value INTEGER);\nSELECT no_such_function();\n",
        encoding="utf-8",
    )
    database = tmp_path / "labcourt.sqlite3"

    with pytest.raises(
        MigrationIntegrityError,
        match=rf"{next_version:04d}_failure\.sql failed",
    ):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied, _clock).apply_all()

    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, next_version)]
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'rolled_back'"
            ).fetchone()
            is None
        )
    finally:
        connection.close()


def test_v7_casefold_run_conflict_rolls_back_the_entire_migration(tmp_path: Path) -> None:
    copied_v6 = tmp_path / "migrations-v6"
    copied_v6.mkdir()
    for version in range(1, 7):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, copied_v6 / source.name)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied_v6, _clock).apply_all() == (
        1,
        2,
        3,
        4,
        5,
        6,
    )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO run_manifests(
                manifest_id, schema_version, document_json,
                document_sha256, registered_at
            ) VALUES (?, '1.0', '{}', ?, ?)
            """,
            ("a" * 64, "b" * 64, "2026-07-27T12:34:56.123456Z"),
        )
        for run_id in ("run-case", "RUN-CASE"):
            connection.execute(
                """
                INSERT INTO runs(
                    run_id, manifest_id, revision,
                    audit_head_sequence, audit_head_hash, registered_at
                ) VALUES (?, ?, 0, -1, ?, ?)
                """,
                (
                    run_id,
                    "a" * 64,
                    "0" * 64,
                    "2026-07-27T12:34:56.123456Z",
                ),
            )
        connection.commit()
        before = connection.execute("SELECT * FROM runs ORDER BY run_id").fetchall()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    with pytest.raises(MigrationIntegrityError, match=r"0007_m3_authority_hardening\.sql failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,), (3,), (4,), (5,), (6,)]
        assert connection.execute("SELECT * FROM runs ORDER BY run_id").fetchall() == before
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert (
            connection.execute(
                """
            SELECT name FROM sqlite_master
            WHERE name IN (
                'm3_authority_hardening_preflight',
                'uq_runs_filesystem_identity_nocase',
                'runs_portable_filesystem_identity_insert',
                'backlog_item_versions_validate_transition'
            )
            """
            ).fetchall()
            == []
        )


def test_v6_repository_readers_and_writers_fail_closed_until_v7_is_installed(
    tmp_path: Path,
) -> None:
    copied_v6 = tmp_path / "migrations-v6"
    copied_v6.mkdir()
    for version in range(1, 7):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, copied_v6 / source.name)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied_v6, _clock).apply_all()
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock)

    with pytest.raises(MigrationIntegrityError, match=r"run MigrationRunner\.apply_all"):
        repository.pragma_settings()
    with pytest.raises(MigrationIntegrityError, match=r"run MigrationRunner\.apply_all"):
        repository.register_run(RUN_ID, _manifest())

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all() == (
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
    )
    repository.register_run(RUN_ID, _manifest())


def test_schema_pragmas_foreign_keys_and_append_only_triggers(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    _register_case(repository)

    assert repository.pragma_settings() == {
        "foreign_keys": 1,
        "journal_mode": "wal",
        "synchronous": 2,
        "busy_timeout": BUSY_TIMEOUT_MS,
        "trusted_schema": 0,
    }
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {
            "schema_migrations",
            "run_manifests",
            "runs",
            "frames",
            "cases",
            "case_versions",
            "evidence_packs",
            "media_assets",
            "evidence_pack_crops",
            "retention_holds",
            "retention_hold_audit_links",
            "retention_scan_cursors",
            "retention_recovery_cursors",
            "media_purge_attempts",
            "audit_entries",
            "detections",
            "backlog_completion_receipts",
        }.issubset(tables)
        backlog_version_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(backlog_item_versions)")
        }
        assert "retry_generation" in backlog_version_columns
        completion_triggers = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'trigger' AND tbl_name = 'backlog_completion_receipts'
                """
            )
        }
        assert completion_triggers == {
            "backlog_completion_receipts_validate_authority",
            "backlog_completion_receipts_no_replace",
            "backlog_completion_receipts_no_update",
            "backlog_completion_receipts_no_delete",
        }
        for table in tables - {"schema_migrations"}:
            foreign_keys = connection.execute(f"PRAGMA foreign_key_list({table})").fetchall()
            assert all(str(row[6]).upper() == "RESTRICT" for row in foreign_keys)

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE run_manifests SET schema_version = 'x'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM case_versions")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO schema_migrations(
                    version, name, sql_sha256, applied_at
                )
                SELECT version, name, ?, applied_at FROM schema_migrations WHERE version = 1
                """,
                ("f" * 64,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO case_versions
                SELECT * FROM case_versions WHERE run_id = ?
                """,
                (RUN_ID,),
            )
        assert (
            connection.execute(
                "SELECT sql_sha256 FROM schema_migrations WHERE version = 1"
            ).fetchone()[0]
            != "f" * 64
        )
        with pytest.raises(sqlite3.IntegrityError, match="audit head updates must be monotonic"):
            connection.execute(
                "UPDATE runs SET revision = revision + 1 WHERE run_id = ?",
                (RUN_ID,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM runs WHERE run_id = ?", (RUN_ID,))
    finally:
        connection.close()


def test_case_pack_idempotency_state_and_audit_chain(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    repository.register_frame(RUN_ID, _frame())
    repository.register_detection(RUN_ID, _detection())
    first_case = repository.create_or_get_case(RUN_ID, _event())
    replayed_case = repository.create_or_get_case(RUN_ID, _event())

    assert first_case == replayed_case
    assert first_case.revision == 1
    assert first_case.case.status == CaseStatus.CANDIDATE
    assert _counts(database)["audit_entries"] == 1

    incomplete = _pack(version=1, complete=False)
    first_publish = repository.publish_pack(RUN_ID, 1, _draft(version=1, complete=False))
    retry = repository.publish_pack(RUN_ID, 1, incomplete)
    assert first_publish.created is True
    assert retry.created is False
    assert retry.pack == first_publish.pack
    assert retry.case.revision == 2
    assert retry.case.case.status == CaseStatus.CANDIDATE
    assert _counts(database)["audit_entries"] == 2

    complete = _pack(version=2, complete=True)
    second_publish = repository.publish_pack(RUN_ID, 2, complete)
    assert second_publish.case.revision == 3
    assert second_publish.case.case.status == CaseStatus.EVIDENCE_READY
    assert [pack.version for pack in second_publish.case.case.evidence_packs] == [1, 2]

    entries = repository.list_audit_entries(RUN_ID)
    head = repository.get_audit_head(RUN_ID)
    assert [entry.sequence for entry in entries] == [0, 1, 2]
    assert validate_audit_chain(
        entries,
        expected_run_id=RUN_ID,
        expected_manifest_id=head.manifest_id,
        expected_head_sequence=head.sequence,
        expected_head_hash=head.entry_hash,
    ).passed
    assert repository.list_events(RUN_ID) == (_event(),)
    assert _counts(database) == {
        "cases": 1,
        "case_versions": 3,
        "evidence_packs": 2,
        "media_assets": 1,
        "evidence_pack_crops": 2,
        "audit_entries": 3,
    }


def test_stale_case_revision_rolls_back_with_typed_conflict(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    _register_case(repository)
    repository.publish_pack(RUN_ID, 1, _pack(version=1, complete=False))
    before = _counts(database)

    with pytest.raises(ConcurrentModification, match="revision"):
        repository.publish_pack(RUN_ID, 1, _pack(version=2, complete=True))

    assert _counts(database) == before
    assert repository.load_case(RUN_ID, derive_case_id(_event().event_id)).revision == 2


def test_concurrent_publish_has_one_winner_and_one_typed_conflict(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    _register_case(repository)
    repositories = (
        SQLiteEvidenceRepository(
            database,
            BUSY_TIMEOUT_MS,
            verifier=_Verifier(),
            clock=_clock,
        ),
        SQLiteEvidenceRepository(
            database,
            BUSY_TIMEOUT_MS,
            verifier=_Verifier(),
            clock=_clock,
        ),
    )
    packs = (
        _pack(version=1, complete=False),
        _pack(version=1, complete=True),
    )

    def publish(index: int) -> str:
        try:
            repositories[index].publish_pack(RUN_ID, 1, packs[index])
        except ConcurrentModification:
            return "conflict"
        return "published"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(publish, range(2)))

    assert sorted(outcomes) == ["conflict", "published"]
    assert _counts(database)["evidence_packs"] == 1
    assert _counts(database)["audit_entries"] == 2
    entries = repository.list_audit_entries(RUN_ID)
    assert [entry.sequence for entry in entries] == [0, 1]


@pytest.mark.parametrize(
    "fault_phase",
    [
        "publish.after_pack",
        "publish.after_media_assets",
        "publish.after_crop_links",
        "publish.after_audit",
        "publish.after_case_version",
        "publish.after_case_update",
        "publish.before_commit",
    ],
)
def test_publish_fault_rolls_back_case_pack_media_and_audit(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, setup_repository = _repository(tmp_path)
    _register_case(setup_repository)

    def fail_at(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected write failure")

    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=_clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="injected write failure"):
        repository.publish_pack(RUN_ID, 1, _pack(version=1, complete=False))

    assert _counts(database) == {
        "cases": 1,
        "case_versions": 1,
        "evidence_packs": 0,
        "media_assets": 0,
        "evidence_pack_crops": 0,
        "audit_entries": 1,
    }
    case = repository.load_case(RUN_ID, derive_case_id(_event().event_id))
    assert case.revision == 1
    assert case.case.status == CaseStatus.CANDIDATE
    assert repository.get_audit_head(RUN_ID).sequence == 0


def test_repository_ignores_claimed_passed_and_rechecks_physical_media(
    tmp_path: Path,
) -> None:
    database, repository = _repository(
        tmp_path,
        verifier=_Verifier(VerificationStatus.MEDIA_HASH_MISMATCH),
    )
    _register_case(repository)
    caller_claimed_pass = _pack(version=1, complete=True)
    assert caller_claimed_pass.closure_report.passed is True

    with pytest.raises(EvidenceMissing, match="MEDIA_HASH_MISMATCH"):
        repository.publish_pack(RUN_ID, 1, caller_claimed_pass)

    assert _counts(database)["evidence_packs"] == 0
    assert _counts(database)["audit_entries"] == 1


def test_current_closure_returns_typed_hash_and_retention_defects(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    _register_case(repository)
    published = repository.publish_pack(RUN_ID, 1, _draft(version=1, complete=True))

    current = repository.verify_current_pack(RUN_ID, published.pack.pack_id)
    assert current.passed is True
    assert current.root_ref == ArtifactRef(
        kind=ArtifactKind.EVIDENCE_PACK,
        artifact_id=published.pack.pack_id,
    )

    corrupted = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(VerificationStatus.MEDIA_HASH_MISMATCH),
        clock=_clock,
    ).verify_current_pack(RUN_ID, published.pack.pack_id)
    assert corrupted.passed is False
    assert [defect.code.value for defect in corrupted.defects] == ["MEDIA_HASH_MISMATCH"]

    wrong_size = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(VerificationStatus.SIZE_MISMATCH),
        clock=_clock,
    ).verify_current_pack(RUN_ID, published.pack.pack_id)
    assert wrong_size.passed is False
    assert [defect.code.value for defect in wrong_size.defects] == ["MEDIA_SIZE_MISMATCH"]
    assert wrong_size.defects[0].expected_size_bytes is not None
    assert wrong_size.defects[0].actual_size_bytes == (
        wrong_size.defects[0].expected_size_bytes + 1
    )

    privacy = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(VerificationStatus.PRIVACY_POLICY_VIOLATION),
        clock=_clock,
    ).verify_current_pack(RUN_ID, published.pack.pack_id)
    assert privacy.passed is False
    assert [defect.code.value for defect in privacy.defects] == ["PRIVACY_POLICY_VIOLATION"]

    connection = sqlite3.connect(database)
    try:
        # This section deliberately simulates an externally corrupted/tombstoned
        # database.  Legitimate retention is exercised through the repository below.
        connection.execute("DROP TRIGGER media_assets_controlled_retention_update")
        connection.execute(
            """
            UPDATE media_assets
            SET availability = ?
            WHERE run_id = ?
            """,
            (MediaAvailability.PURGING.value, RUN_ID),
        )
        connection.execute(
            """
            UPDATE media_assets
            SET availability = ?, local_path = NULL, purged_at = ?
            WHERE run_id = ?
            """,
            (
                MediaAvailability.PURGED_BY_RETENTION.value,
                RECORDED_AT.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                RUN_ID,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    retained = repository.verify_current_pack(RUN_ID, published.pack.pack_id)
    assert retained.passed is False
    assert [defect.code for defect in retained.defects] == [
        ClosureDefectCode.MEDIA_PURGED_BY_RETENTION
    ]
    assert [defect.reason_code for defect in retained.defects] == ["PURGED_BY_RETENTION"]


def test_detection_registration_is_run_scoped_append_only_and_idempotent(
    tmp_path: Path,
) -> None:
    database, repository = _repository(tmp_path)
    repository.register_frame(RUN_ID, _frame())
    detection = _detection()

    repository.register_detection(RUN_ID, detection)
    repository.register_detection(RUN_ID, detection)

    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE detections SET label = 'changed'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM detections")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("INSERT OR REPLACE INTO detections SELECT * FROM detections")
    finally:
        connection.close()

    changed = detection.model_copy(update={"label": "different"})
    with pytest.raises(RepositoryIntegrityError, match="different canonical content"):
        repository.register_detection(RUN_ID, changed)

    wrong_model = _detection(
        detection_id="det-wrong-model",
        model_manifest_id=_manifest().models["pose"].model_manifest_id,
    )
    with pytest.raises(ManifestMismatch, match="detector manifest"):
        repository.register_detection(RUN_ID, wrong_model)

    missing_frame = _detection(
        detection_id="det-missing-frame",
        frame=_frame().model_copy(update={"frame_index": 89}),
    )
    with pytest.raises(EvidenceMissing, match="frame is not registered"):
        repository.register_detection(RUN_ID, missing_frame)


def test_detection_reference_is_resolved_from_same_run_frame_and_manifest(
    tmp_path: Path,
) -> None:
    _, repository = _repository(tmp_path)
    _register_case(repository)
    detection = _detection()
    repository.register_detection(RUN_ID, detection)

    published = repository.publish_pack(
        RUN_ID,
        1,
        _draft_with_detection(complete=True),
    )

    assert published.created is True
    assert repository.verify_current_pack(RUN_ID, published.pack.pack_id).passed is True


def test_detection_reference_rejects_cross_run_and_wrong_frame(tmp_path: Path) -> None:
    _, repository = _repository(tmp_path)
    repository.register_run("run-02", _manifest())
    repository.register_frame("run-02", _frame())
    repository.register_detection("run-02", _detection())
    _register_case(repository, include_detection=False)

    with pytest.raises(EvidenceMissing, match="CROSS_RUN_REFERENCE"):
        repository.publish_pack(RUN_ID, 1, _draft_with_detection())

    frame_89 = _frame().model_copy(update={"frame_index": 89})
    repository.register_frame(RUN_ID, frame_89)
    repository.register_detection(
        RUN_ID,
        _detection(detection_id="det-bottle-089", frame=frame_89),
    )
    with pytest.raises(EvidenceMissing, match="IDENTITY_MISMATCH"):
        repository.publish_pack(
            RUN_ID,
            1,
            _draft_with_detection(detection_id="det-bottle-089"),
        )


def test_detection_reference_cannot_be_forged_by_the_external_verifier(
    tmp_path: Path,
) -> None:
    _, repository = _repository(tmp_path, verifier=_ReferenceClaimingVerifier())
    _register_case(repository, include_detection=False)

    with pytest.raises(EvidenceMissing, match="MISSING_REFERENCE"):
        repository.publish_pack(RUN_ID, 1, _draft_with_detection())


def test_detection_index_tamper_is_rejected_during_closure(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    _register_case(repository)
    repository.register_detection(RUN_ID, _detection())

    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TRIGGER detections_no_update")
        connection.execute(
            "UPDATE detections SET detector_manifest_id = ? WHERE run_id = ?",
            (_manifest().models["pose"].model_manifest_id, RUN_ID),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="detection index"):
        repository.publish_pack(RUN_ID, 1, _draft_with_detection())


def test_detection_objective_source_requires_the_pinned_detector_manifest(
    tmp_path: Path,
) -> None:
    _, repository = _repository(tmp_path)
    _register_case(repository)
    detection = _detection()
    repository.register_detection(RUN_ID, detection)
    draft = _draft_with_detection()
    detection_fact = ObjectiveFact(
        fact_id="fact-detection-score",
        kind="DETECTION_SCORE",
        value=0.92,
        source_ref=ArtifactRef(
            kind=ArtifactKind.DETECTION,
            artifact_id=detection.detection_id,
        ),
        source_manifest_id=_manifest().models["pose"].model_manifest_id,
    )
    facts = tuple(sorted((*draft.objective_facts, detection_fact), key=lambda fact: fact.fact_id))

    with pytest.raises(EvidenceMissing, match="MANIFEST_MISMATCH"):
        repository.publish_pack(
            RUN_ID,
            1,
            draft.model_copy(update={"objective_facts": facts}),
        )

    correct_fact = detection_fact.model_copy(
        update={"source_manifest_id": detection.model_manifest_id}
    )
    correct_facts = tuple(
        sorted((*draft.objective_facts, correct_fact), key=lambda fact: fact.fact_id)
    )
    published = repository.publish_pack(
        RUN_ID,
        1,
        draft.model_copy(update={"objective_facts": correct_facts}),
    )
    assert published.created is True


def test_repository_rejects_cross_stream_and_out_of_window_source_frames(
    tmp_path: Path,
) -> None:
    _, repository = _repository(tmp_path)
    _register_case(repository)
    for frame in (
        FrameRef(
            camera_id="cam-02",
            stream_id="other",
            frame_index=90,
            fps_num=30,
            fps_den=1,
            width=640,
            height=480,
            content_sha256="a" * 64,
        ),
        FrameRef(
            camera_id="cam-01",
            stream_id="demo-ntsc",
            frame_index=92,
            fps_num=30,
            fps_den=1,
            width=640,
            height=480,
            content_sha256="a" * 64,
        ),
    ):
        repository.register_frame(RUN_ID, frame)

    for extra_frame_id, code in (
        ("cam-02:other:90", "CROSS_STREAM_FRAME"),
        ("cam-01:demo-ntsc:92", "FRAME_OUTSIDE_WINDOW"),
    ):
        draft = _draft(version=1, complete=False)
        crop = draft.focus_crops[0]
        refs = tuple(
            sorted(
                (
                    *crop.source_refs,
                    ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=extra_frame_id),
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        changed_crop = crop.model_copy(update={"source_refs": refs})
        changed_draft = draft.model_copy(update={"focus_crops": (changed_crop,)})

        with pytest.raises(EvidenceMissing, match=code):
            repository.publish_pack(RUN_ID, 1, changed_draft)


def test_repository_rejects_crop_track_and_manifest_version_mismatches(
    tmp_path: Path,
) -> None:
    _, repository = _repository(tmp_path)
    _register_case(repository)
    draft = _draft(version=1, complete=False)
    crop = draft.focus_crops[0]

    wrong_track = crop.model_copy(update={"primary_track_ref": "cam-01:epoch-01:other"})
    with pytest.raises(EvidenceMissing, match="TRACK_MISMATCH"):
        repository.publish_pack(
            RUN_ID,
            1,
            draft.model_copy(update={"focus_crops": (wrong_track,)}),
        )

    wrong_encoding = crop.model_copy(update={"encoding_version": "png-v2"})
    with pytest.raises(ManifestMismatch, match="encoding version"):
        repository.publish_pack(
            RUN_ID,
            1,
            draft.model_copy(update={"focus_crops": (wrong_encoding,)}),
        )

    wrong_receipt = crop.privacy_receipt.model_copy(update={"transform_version": "privacy-v2"})
    wrong_transform = crop.model_copy(update={"privacy_receipt": wrong_receipt})
    with pytest.raises(ManifestMismatch, match="privacy transform version"):
        repository.publish_pack(
            RUN_ID,
            1,
            draft.model_copy(update={"focus_crops": (wrong_transform,)}),
        )


def test_repository_rejects_a_stale_mutable_case_head(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    _register_case(repository)
    first = repository.publish_pack(RUN_ID, 1, _pack(version=1, complete=False))
    repository.publish_pack(RUN_ID, 2, _pack(version=2, complete=True))

    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TRIGGER cases_monotonic_update")
        connection.execute(
            """
            UPDATE cases
            SET current_revision = 2, status = ?,
                latest_pack_id = ?, latest_pack_version = 1
            WHERE run_id = ? AND case_id = ?
            """,
            (
                CaseStatus.CANDIDATE.value,
                first.pack.pack_id,
                RUN_ID,
                first.case.case.case_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="latest immutable version"):
        repository.load_case(RUN_ID, first.case.case.case_id)


def test_repository_rejects_a_repointed_case_creation_audit(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    _register_case(repository)
    published = repository.publish_pack(RUN_ID, 1, _pack(version=1, complete=False))

    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TRIGGER cases_monotonic_update")
        connection.execute(
            """
            UPDATE cases SET created_audit_sequence = 1
            WHERE run_id = ? AND case_id = ?
            """,
            (RUN_ID, published.case.case.case_id),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="creation audit"):
        repository.load_case(RUN_ID, published.case.case.case_id)


def test_repository_rejects_an_inconsistent_run_revision_and_audit_head(
    tmp_path: Path,
) -> None:
    database, repository = _repository(tmp_path)
    repository.create_or_get_case(RUN_ID, _event())

    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("DROP TRIGGER runs_monotonic_head_update")
        connection.execute("DROP TRIGGER runs_m6_audit_head_matches_entry")
        connection.execute(
            "UPDATE runs SET revision = revision + 41 WHERE run_id = ?",
            (RUN_ID,),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="revision and audit head"):
        repository.get_audit_head(RUN_ID)


def test_run_manifest_binding_and_audit_head_are_sql_monotonic(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    other_manifest = _manifest().model_copy(update={"rule_version": "laboratory-v2"})
    repository.register_run("run-02", other_manifest)

    connection = sqlite3.connect(database)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="run identity is immutable"):
            connection.execute(
                "UPDATE runs SET manifest_id = ? WHERE run_id = ?",
                (other_manifest.manifest_id, RUN_ID),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be replaced"):
            connection.execute(
                "INSERT OR REPLACE INTO runs SELECT * FROM runs WHERE run_id = ?",
                (RUN_ID,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute("DELETE FROM runs WHERE run_id = ?", (RUN_ID,))
    finally:
        connection.close()


@pytest.mark.parametrize("run_id", ("run-01.", "CON", "nul.json", "COM1.data"))
def test_register_run_rejects_nonportable_filesystem_identity(
    tmp_path: Path,
    run_id: str,
) -> None:
    database, repository = _repository(tmp_path)
    before = _counts(database)

    with pytest.raises(ContractViolation, match="portable filesystem identity"):
        repository.register_run(run_id, _manifest())

    assert _counts(database) == before


def test_run_filesystem_identity_is_ascii_case_insensitive_in_api_and_sql(
    tmp_path: Path,
) -> None:
    database, repository = _repository(tmp_path)
    repository.register_run("run-case", _manifest())

    with pytest.raises(ContractViolation, match="existing filesystem identity"):
        repository.register_run("RUN-CASE", _manifest())

    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE constraint failed"):
            connection.execute(
                """
                INSERT INTO runs(
                    run_id, manifest_id, revision,
                    audit_head_sequence, audit_head_hash, registered_at
                )
                SELECT 'RUN-CASE', manifest_id, 0, -1, ?, registered_at
                FROM runs WHERE run_id = 'run-case'
                """,
                ("0" * 64,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="portable filesystem identity"):
            connection.execute(
                """
                INSERT INTO runs(
                    run_id, manifest_id, revision,
                    audit_head_sequence, audit_head_hash, registered_at
                )
                SELECT 'NUL.json', manifest_id, 0, -1, ?, registered_at
                FROM runs WHERE run_id = 'run-case'
                """,
                ("0" * 64,),
            )


def test_identical_semantic_ids_are_isolated_by_run_scope(tmp_path: Path) -> None:
    _, repository = _repository(tmp_path)
    repository.register_run("run-02", _manifest())

    first = repository.create_or_get_case(RUN_ID, _event())
    second = repository.create_or_get_case("run-02", _event())

    assert first.case.case_id == second.case.case_id
    assert repository.list_events(RUN_ID) == repository.list_events("run-02")
    assert repository.get_audit_head(RUN_ID).sequence == 0
    assert repository.get_audit_head("run-02").sequence == 0


def test_case_creation_rejects_an_event_rule_outside_the_run_manifest(
    tmp_path: Path,
) -> None:
    database, repository = _repository(tmp_path)
    wrong_rule = _event().model_copy(update={"rule_version": "wrong-v9"})

    with pytest.raises(ManifestMismatch, match="rule_version"):
        repository.create_or_get_case(RUN_ID, wrong_rule)

    assert _counts(database)["cases"] == 0
    assert _counts(database)["case_versions"] == 0
    assert _counts(database)["audit_entries"] == 0


def test_event_listing_rejects_event_documents_repointed_between_cases(
    tmp_path: Path,
) -> None:
    database, repository = _repository(tmp_path)
    first = repository.create_or_get_case(RUN_ID, _event())
    second_event = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    second = repository.create_or_get_case(RUN_ID, second_event)

    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TRIGGER cases_monotonic_update")
        connection.execute(
            """
            UPDATE cases
            SET event_json = (
                    SELECT event_json FROM cases WHERE run_id = ? AND case_id = ?
                ),
                event_sha256 = (
                    SELECT event_sha256 FROM cases WHERE run_id = ? AND case_id = ?
                )
            WHERE run_id = ? AND case_id = ?
            """,
            (
                RUN_ID,
                second.case.case_id,
                RUN_ID,
                second.case.case_id,
                RUN_ID,
                first.case.case_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="case head"):
        repository.list_events(RUN_ID)


def test_repository_revalidates_manifest_and_case_version_index_columns(
    tmp_path: Path,
) -> None:
    database, repository = _repository(tmp_path)
    repository.register_frame(RUN_ID, _frame())
    repository.register_detection(RUN_ID, _detection())
    case = repository.create_or_get_case(RUN_ID, _event())
    repository.publish_pack(RUN_ID, case.revision, _draft(version=1, complete=False))

    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TRIGGER case_versions_no_update")
        connection.execute(
            """
            UPDATE case_versions SET status = ?
            WHERE run_id = ? AND case_id = ? AND revision = 1
            """,
            (CaseStatus.HUMAN_REVIEW.value, RUN_ID, case.case.case_id),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="case version index"):
        repository.load_case(RUN_ID, case.case.case_id)

    second_workspace = tmp_path / "manifest-index"
    second_workspace.mkdir()
    second_database = second_workspace / "labcourt.sqlite3"
    MigrationRunner(second_database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    second_repository = SQLiteEvidenceRepository(
        second_database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=_clock,
    )
    second_repository.register_run(RUN_ID, _manifest())
    connection = sqlite3.connect(second_database)
    try:
        connection.execute("DROP TRIGGER run_manifests_no_update")
        connection.execute("UPDATE run_manifests SET schema_version = 'corrupt'")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="manifest index"):
        second_repository.create_or_get_case(RUN_ID, _event())


def test_retention_uses_latest_shared_pack_audit_and_recovers_cleanup(
    tmp_path: Path,
) -> None:
    database, repository, clock = _retention_repository(tmp_path)
    first = repository.publish_pack(
        RUN_ID,
        1,
        _retention_draft(version=1, complete=False),
    )
    first_crop_id = first.pack.focus_crops[0].crop_id
    first_publication_at = clock.value

    clock.value = RECORDED_AT + timedelta(days=10)
    second = repository.publish_pack(
        RUN_ID,
        2,
        _retention_draft(version=2, complete=True, as_subject=True),
    )
    second_crop_id = second.pack.subject_crops[0].crop_id
    assert first_crop_id != second_crop_id
    assert first.pack.focus_crops[0].media_sha256 == second.pack.subject_crops[0].media_sha256

    assert (
        repository.list_expirable_media(
            RUN_ID,
            first_publication_at + timedelta(days=5),
            10,
        )
        == ()
    )
    assert repository.list_expirable_media(RUN_ID, clock.value, 10) == ("c" * 64,)

    connection = sqlite3.connect(database)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="controlled retention transition"):
            connection.execute(
                """
                UPDATE media_assets SET availability = 'PURGING'
                WHERE run_id = ? AND media_sha256 = ?
                """,
                (RUN_ID, "c" * 64),
            )
        connection.rollback()
    finally:
        connection.close()

    lease = repository.begin_media_purge(
        RUN_ID,
        "c" * 64,
        clock.value,
        "retention-v1",
    )
    assert isinstance(lease, PurgeLease)
    assert lease.crop_refs == tuple(
        sorted(
            (
                ArtifactRef(kind=ArtifactKind.CROP, artifact_id=first_crop_id),
                ArtifactRef(kind=ArtifactKind.CROP, artifact_id=second_crop_id),
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    assert _purge_attempt_media(database, "PURGING") == (lease.media_sha256,)
    assert repository.list_expirable_media(RUN_ID, clock.value, 10) == ()

    connection = sqlite3.connect(database)
    try:
        row = connection.execute(
            """
            SELECT available_state_json, available_state_sha256,
                   purging_state_json, purging_state_sha256
            FROM media_purge_attempts
            WHERE run_id = ? AND media_sha256 = ?
            """,
            (RUN_ID, "c" * 64),
        ).fetchone()
        assert row is not None
        available_state_sha256 = str(row[1])
        purging_state_sha256 = str(row[3])
        assert hashlib.sha256(str(row[0]).encode("utf-8")).hexdigest() == row[1]
        assert hashlib.sha256(str(row[2]).encode("utf-8")).hexdigest() == row[3]
        assert row[1] != row[3]
    finally:
        connection.close()
    intent_audit = repository.list_audit_entries(RUN_ID)[lease.intent_audit_sequence]
    assert intent_audit.actor == "RETENTION"
    assert intent_audit.action == AuditAction.MEDIA_PURGE_REQUESTED
    assert intent_audit.before_sha256 == available_state_sha256
    assert intent_audit.after_sha256 == purging_state_sha256

    result = repository.complete_media_purge(
        RUN_ID,
        lease.media_sha256,
        lease.intent_audit_sequence,
        False,
    )
    assert result.disposition == PurgeDisposition.PURGED
    assert result.reason_code == PurgeReasonCode.EXPIRED_AND_PURGED
    assert result.previous_availability == MediaAvailability.AVAILABLE
    assert result.crop_refs == lease.crop_refs
    assert _purge_attempt_media(database, "PURGING") == ()
    assert _purge_attempt_media(database, "PURGED_CLEANUP_PENDING") == (lease.media_sha256,)

    current = repository.verify_current_pack(RUN_ID, second.pack.pack_id)
    assert current.passed is False
    assert tuple(defect.code for defect in current.defects) == (
        ClosureDefectCode.MEDIA_PURGED_BY_RETENTION,
    )
    connection = sqlite3.connect(database)
    try:
        media_row = connection.execute(
            """
            SELECT media_sha256, local_path, availability, purged_at
            FROM media_assets WHERE run_id = ? AND media_sha256 = ?
            """,
            (RUN_ID, "c" * 64),
        ).fetchone()
        assert media_row is not None
        assert media_row[0] == "c" * 64
        assert media_row[1] is None
        assert media_row[2] == MediaAvailability.PURGED_BY_RETENTION.value
        assert media_row[3] is not None
    finally:
        connection.close()

    before_cleanup_audits = repository.list_audit_entries(RUN_ID)
    repository.mark_trash_cleaned(RUN_ID, lease.media_sha256, lease.intent_audit_sequence)
    repository.mark_trash_cleaned(RUN_ID, lease.media_sha256, lease.intent_audit_sequence)
    assert _purge_attempt_media(database, "PURGED_CLEANUP_PENDING") == ()
    assert repository.list_audit_entries(RUN_ID) == before_cleanup_audits
    assert before_cleanup_audits[-1].actor == "RETENTION"
    assert before_cleanup_audits[-1].action == AuditAction.PURGED_BY_RETENTION
    head = repository.get_audit_head(RUN_ID)
    assert validate_audit_chain(
        before_cleanup_audits,
        expected_run_id=RUN_ID,
        expected_manifest_id=head.manifest_id,
        expected_head_sequence=head.sequence,
        expected_head_hash=head.entry_hash,
    ).passed


def test_all_typed_holds_block_expired_media_then_release_idempotently(
    tmp_path: Path,
) -> None:
    _, repository, clock = _retention_repository(tmp_path)
    published = repository.publish_pack(
        RUN_ID,
        1,
        _retention_draft(version=1, complete=True),
    )
    media_sha256 = published.pack.focus_crops[0].media_sha256
    crop_id = published.pack.focus_crops[0].crop_id
    case_id = published.case.case.case_id
    holds = (
        _retention_hold(
            hold_id="hold-appeal",
            kind=RetentionHoldKind.APPEAL,
            target_kind=ArtifactKind.MEDIA,
            target_id=media_sha256,
            owner_id="appeal-01",
        ),
        _retention_hold(
            hold_id="hold-gold",
            kind=RetentionHoldKind.GOLD_SET,
            target_kind=ArtifactKind.CROP,
            target_id=crop_id,
            owner_id="gold-dataset",
        ),
        _retention_hold(
            hold_id="hold-challenge",
            kind=RetentionHoldKind.CHALLENGE_SET,
            target_kind=ArtifactKind.CROP,
            target_id=crop_id,
            owner_id="challenge-dataset",
        ),
        _retention_hold(
            hold_id="hold-manual",
            kind=RetentionHoldKind.MANUAL_LEGAL_HOLD,
            target_kind=ArtifactKind.MEDIA,
            target_id=media_sha256,
            owner_id=case_id,
        ),
    )
    created_sequences = tuple(repository.create_retention_hold(hold) for hold in holds)
    assert tuple(repository.create_retention_hold(hold) for hold in holds) == created_sequences

    retained = repository.begin_media_purge(
        RUN_ID,
        media_sha256,
        clock.value,
        "retention-v1",
    )
    assert not isinstance(retained, PurgeLease)
    assert retained.reason_code == PurgeReasonCode.ACTIVE_RETENTION_HOLD
    assert retained.hold_kinds == tuple(
        sorted((hold.kind for hold in holds), key=lambda kind: kind.value)
    )
    assert retained.audit_sequences == ()

    released_sequences = tuple(
        repository.release_retention_hold(RUN_ID, hold.hold_id) for hold in holds
    )
    assert (
        tuple(repository.release_retention_hold(RUN_ID, hold.hold_id) for hold in holds)
        == released_sequences
    )
    lease = repository.begin_media_purge(
        RUN_ID,
        media_sha256,
        clock.value,
        "retention-v1",
    )
    assert isinstance(lease, PurgeLease)

    for target_kind, target_id in (
        (ArtifactKind.MEDIA, media_sha256),
        (ArtifactKind.CROP, crop_id),
    ):
        late_hold = _retention_hold(
            hold_id=f"late-{target_kind.value.lower()}",
            kind=RetentionHoldKind.APPEAL,
            target_kind=target_kind,
            target_id=target_id,
            owner_id="appeal-late",
        )
        with pytest.raises(ConcurrentModification, match="after media purge intent"):
            repository.create_retention_hold(late_hold)


def test_retention_cursor_prevents_a_held_prefix_larger_than_limit_from_starving_tail(
    tmp_path: Path,
) -> None:
    _, repository, clock = _retention_repository(tmp_path)
    media_ids = tuple(character * 64 for character in ("1", "2", "3", "4"))
    repository.publish_pack(
        RUN_ID,
        1,
        _multi_media_retention_draft(media_ids),
    )
    for index, media_sha256 in enumerate(media_ids[:3]):
        repository.create_retention_hold(
            _retention_hold(
                hold_id=f"prefix-hold-{index}",
                kind=RetentionHoldKind.APPEAL,
                target_kind=ArtifactKind.MEDIA,
                target_id=media_sha256,
                owner_id=f"appeal-prefix-{index}",
            )
        )

    first_page = repository.list_expirable_media(RUN_ID, clock.value, 2)
    assert first_page == media_ids[:2]
    first_results = tuple(
        repository.begin_media_purge(
            RUN_ID,
            media_sha256,
            clock.value,
            "retention-v1",
        )
        for media_sha256 in first_page
    )
    assert all(
        isinstance(result, PurgeItemResult)
        and result.reason_code == PurgeReasonCode.ACTIVE_RETENTION_HOLD
        for result in first_results
    )

    second_page = repository.list_expirable_media(RUN_ID, clock.value, 2)
    assert second_page == media_ids[2:]
    held = repository.begin_media_purge(
        RUN_ID,
        second_page[0],
        clock.value,
        "retention-v1",
    )
    tail = repository.begin_media_purge(
        RUN_ID,
        second_page[1],
        clock.value,
        "retention-v1",
    )
    assert isinstance(held, PurgeItemResult)
    assert held.reason_code == PurgeReasonCode.ACTIVE_RETENTION_HOLD
    assert isinstance(tail, PurgeLease)


def test_retention_cursor_wraps_only_after_an_empty_tail_page(tmp_path: Path) -> None:
    _, repository, clock = _retention_repository(tmp_path)
    media_ids = tuple(character * 64 for character in ("1", "2", "3"))
    repository.publish_pack(
        RUN_ID,
        1,
        _multi_media_retention_draft(media_ids),
    )

    assert repository.list_expirable_media(RUN_ID, clock.value, 2) == media_ids[:2]
    assert repository.list_expirable_media(RUN_ID, clock.value, 2) == media_ids[2:]
    assert repository.list_expirable_media(RUN_ID, clock.value, 2) == media_ids[:2]


def test_retention_cursor_corruption_fails_closed(tmp_path: Path) -> None:
    database, repository, clock = _retention_repository(tmp_path)
    repository.publish_pack(
        RUN_ID,
        1,
        _multi_media_retention_draft(("1" * 64, "2" * 64)),
    )
    assert repository.list_expirable_media(RUN_ID, clock.value, 1) == ("1" * 64,)

    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            """
            UPDATE retention_scan_cursors SET last_media_sha256 = ? WHERE run_id = ?
            """,
            ("not-a-sha256", RUN_ID),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="scan cursor is invalid"):
        repository.list_expirable_media(RUN_ID, clock.value, 1)


def test_concurrent_retention_scans_serialize_into_distinct_stable_pages(
    tmp_path: Path,
) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    media_ids = tuple(character * 64 for character in ("1", "2", "3", "4"))
    setup.publish_pack(
        RUN_ID,
        1,
        _multi_media_retention_draft(media_ids),
    )
    audits_before = setup.list_audit_entries(RUN_ID)
    repositories = tuple(
        SQLiteEvidenceRepository(
            database,
            BUSY_TIMEOUT_MS,
            verifier=_Verifier(),
            clock=clock,
        )
        for _ in range(2)
    )

    def scan(index: int) -> tuple[str, ...]:
        return repositories[index].list_expirable_media(RUN_ID, clock.value, 2)

    with ThreadPoolExecutor(max_workers=2) as executor:
        pages = tuple(executor.map(scan, range(2)))
    assert set(pages) == {media_ids[:2], media_ids[2:]}
    assert len({media_sha256 for page in pages for media_sha256 in page}) == 4
    assert all(page == tuple(sorted(page)) for page in pages)
    assert setup.list_audit_entries(RUN_ID) == audits_before

    connection = sqlite3.connect(database)
    try:
        states = connection.execute(
            """
            SELECT media_sha256, availability FROM media_assets
            WHERE run_id = ? ORDER BY media_sha256
            """,
            (RUN_ID,),
        ).fetchall()
        assert states == [
            (media_sha256, MediaAvailability.AVAILABLE.value) for media_sha256 in media_ids
        ]
    finally:
        connection.close()


def test_recovery_claim_cursor_persists_across_processes_and_wraps_by_intent(
    tmp_path: Path,
) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    media_a, media_b = "1" * 64, "2" * 64
    setup.publish_pack(
        RUN_ID,
        1,
        _multi_media_retention_draft((media_a, media_b)),
    )
    cleanup_lease = setup.begin_media_purge(
        RUN_ID,
        media_a,
        clock.value,
        "retention-v1",
    )
    assert isinstance(cleanup_lease, PurgeLease)
    completed = setup.complete_media_purge(
        RUN_ID,
        media_a,
        cleanup_lease.intent_audit_sequence,
        False,
    )
    incomplete_lease = setup.begin_media_purge(
        RUN_ID,
        media_b,
        clock.value,
        "retention-v1",
    )
    assert isinstance(incomplete_lease, PurgeLease)
    audits_before = setup.list_audit_entries(RUN_ID)

    first_process = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
    )
    assert first_process.claim_next_recovery(RUN_ID) == PurgeRecoveryCandidate(
        kind=PurgeRecoveryKind.TRASH_CLEANUP,
        lease=cleanup_lease,
        completion_audit_sequence=completed.audit_sequences[1],
    )

    second_process = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
    )
    assert second_process.claim_next_recovery(RUN_ID) == PurgeRecoveryCandidate(
        kind=PurgeRecoveryKind.INCOMPLETE_PURGE,
        lease=incomplete_lease,
    )
    assert second_process.claim_next_recovery(RUN_ID) == PurgeRecoveryCandidate(
        kind=PurgeRecoveryKind.TRASH_CLEANUP,
        lease=cleanup_lease,
        completion_audit_sequence=completed.audit_sequences[1],
    )
    assert setup.list_audit_entries(RUN_ID) == audits_before


def test_max_one_recovery_survives_restart_past_poisoned_cleanup(tmp_path: Path) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    media_a, media_b = "1" * 64, "2" * 64
    setup.publish_pack(RUN_ID, 1, _multi_media_retention_draft((media_a, media_b)))
    cleanup_lease = setup.begin_media_purge(
        RUN_ID,
        media_a,
        clock.value,
        "retention-v1",
    )
    assert isinstance(cleanup_lease, PurgeLease)
    setup.complete_media_purge(
        RUN_ID,
        media_a,
        cleanup_lease.intent_audit_sequence,
        False,
    )
    incomplete_lease = setup.begin_media_purge(
        RUN_ID,
        media_b,
        clock.value,
        "retention-v1",
    )
    assert isinstance(incomplete_lease, PurgeLease)

    class PoisonedCleanupFileOps:
        def stage_for_purge(self, lease: PurgeLease) -> None:
            assert lease == incomplete_lease

        def destroy_purged(self, lease: PurgeLease) -> None:
            if lease == cleanup_lease:
                raise ProviderUnavailable("private cleanup provider detail")

    file_ops = PoisonedCleanupFileOps()
    first = RetentionCoordinator(
        repository=setup,
        file_ops=file_ops,
        max_items=1,
    ).recover(RUN_ID)
    assert len(first) == 1
    assert first[0].reason_code == PurgeReasonCode.TRASH_CLEANUP_FAILED
    assert "private" not in first[0].model_dump_json()

    restarted = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
    )
    second = RetentionCoordinator(
        repository=restarted,
        file_ops=file_ops,
        max_items=1,
    ).recover(RUN_ID)
    assert len(second) == 1
    assert second[0].media_ref.artifact_id == media_b
    assert second[0].reason_code == PurgeReasonCode.RECOVERED_PURGE_COMPLETED
    assert _purge_attempt_media(database, "PURGING") == ()


def test_concurrent_recovery_claims_are_distinct_until_cursor_wrap(tmp_path: Path) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    media_ids = ("1" * 64, "2" * 64)
    setup.publish_pack(RUN_ID, 1, _multi_media_retention_draft(media_ids))
    leases = tuple(
        setup.begin_media_purge(RUN_ID, media_sha256, clock.value, "retention-v1")
        for media_sha256 in media_ids
    )
    assert all(isinstance(lease, PurgeLease) for lease in leases)
    repositories = tuple(
        SQLiteEvidenceRepository(
            database,
            BUSY_TIMEOUT_MS,
            verifier=_Verifier(),
            clock=clock,
        )
        for _ in range(2)
    )

    def claim(index: int) -> PurgeRecoveryCandidate | None:
        return repositories[index].claim_next_recovery(RUN_ID)

    with ThreadPoolExecutor(max_workers=2) as executor:
        claimed = tuple(executor.map(claim, range(2)))

    assert all(candidate is not None for candidate in claimed)
    assert {candidate.lease.media_sha256 for candidate in claimed if candidate is not None} == set(
        media_ids
    )
    assert all(
        candidate is not None and candidate.kind == PurgeRecoveryKind.INCOMPLETE_PURGE
        for candidate in claimed
    )


@pytest.mark.parametrize(
    "fault_phase",
    [
        "retention.recovery_claim.after_cursor",
        "retention.recovery_claim.before_commit",
    ],
)
def test_recovery_claim_fault_rolls_back_cursor(fault_phase: str, tmp_path: Path) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    setup.publish_pack(RUN_ID, 1, _retention_draft(version=1, complete=True))
    lease = setup.begin_media_purge(RUN_ID, "c" * 64, clock.value, "retention-v1")
    assert isinstance(lease, PurgeLease)

    def fail_at(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected recovery claim crash")

    faulted = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="recovery claim crash"):
        faulted.claim_next_recovery(RUN_ID)

    assert setup.claim_next_recovery(RUN_ID) == PurgeRecoveryCandidate(
        kind=PurgeRecoveryKind.INCOMPLETE_PURGE,
        lease=lease,
    )


def test_recovery_cursor_corruption_fails_closed(tmp_path: Path) -> None:
    database, repository, clock = _retention_repository(tmp_path)
    repository.publish_pack(RUN_ID, 1, _retention_draft(version=1, complete=True))
    lease = repository.begin_media_purge(
        RUN_ID,
        "c" * 64,
        clock.value,
        "retention-v1",
    )
    assert isinstance(lease, PurgeLease)
    assert repository.claim_next_recovery(RUN_ID) is not None

    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            """
            UPDATE retention_recovery_cursors
            SET last_intent_audit_sequence = ?
            WHERE run_id = ?
            """,
            (lease.intent_audit_sequence + 10_000, RUN_ID),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="has no purge attempt"):
        repository.claim_next_recovery(RUN_ID)


def test_media_reference_query_is_run_scoped_and_fails_closed_on_broken_link(
    tmp_path: Path,
) -> None:
    database, repository, _ = _retention_repository(tmp_path)
    media_sha256 = "c" * 64
    assert repository.media_is_referenced(RUN_ID, media_sha256) is False
    assert repository.media_is_referenced(RUN_ID, "d" * 64) is False

    repository.publish_pack(
        RUN_ID,
        1,
        _retention_draft(version=1, complete=True),
    )
    assert repository.media_is_referenced(RUN_ID, media_sha256) is True

    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TRIGGER evidence_pack_crops_no_update")
        connection.execute(
            """
            UPDATE evidence_pack_crops SET pack_id = ?
            WHERE run_id = ? AND media_sha256 = ?
            """,
            ("d" * 64, RUN_ID, media_sha256),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="no audited pack publication"):
        repository.media_is_referenced(RUN_ID, media_sha256)


def test_retention_hold_rejects_manifest_target_owner_and_run_mismatches(
    tmp_path: Path,
) -> None:
    _, repository, _ = _retention_repository(tmp_path)
    published = repository.publish_pack(
        RUN_ID,
        1,
        _retention_draft(version=1, complete=True),
    )
    media_sha256 = published.pack.focus_crops[0].media_sha256

    wrong_manifest = _retention_hold(
        hold_id="wrong-manifest",
        kind=RetentionHoldKind.APPEAL,
        target_kind=ArtifactKind.MEDIA,
        target_id=media_sha256,
        owner_id="appeal-01",
        manifest_id="d" * 64,
    )
    with pytest.raises(ManifestMismatch, match="run manifest"):
        repository.create_retention_hold(wrong_manifest)

    missing_owner = _retention_hold(
        hold_id="missing-owner",
        kind=RetentionHoldKind.MANUAL_LEGAL_HOLD,
        target_kind=ArtifactKind.MEDIA,
        target_id=media_sha256,
        owner_id="00000000-0000-4000-8000-000000000001",
    )
    with pytest.raises(ContractViolation, match="owner case does not exist"):
        repository.create_retention_hold(missing_owner)

    repository.register_run("run-02", _manifest())
    cross_run_target = _retention_hold(
        hold_id="cross-run-target",
        kind=RetentionHoldKind.APPEAL,
        target_kind=ArtifactKind.MEDIA,
        target_id=media_sha256,
        owner_id="appeal-02",
        run_id="run-02",
    )
    with pytest.raises(ContractViolation, match="unknown media in run run-02"):
        repository.create_retention_hold(cross_run_target)


@pytest.mark.parametrize(
    "fault_phase",
    [
        "retention.begin.after_media_update",
        "retention.begin.after_audit",
        "retention.begin.after_attempt",
        "retention.begin.before_commit",
    ],
)
def test_retention_intent_faults_roll_back_media_attempt_audit_and_head(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    setup.publish_pack(RUN_ID, 1, _retention_draft(version=1, complete=True))
    before = _retention_db_state(database)

    def fail_at(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected retention intent fault")

    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="injected retention intent"):
        repository.begin_media_purge(
            RUN_ID,
            "c" * 64,
            clock.value,
            "retention-v1",
        )
    assert _retention_db_state(database) == before


@pytest.mark.parametrize(
    "fault_phase",
    [
        "retention.complete.after_media_update",
        "retention.complete.after_audit",
        "retention.complete.after_attempt",
        "retention.complete.before_commit",
    ],
)
def test_retention_completion_faults_remain_forward_recoverable(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    setup.publish_pack(RUN_ID, 1, _retention_draft(version=1, complete=True))
    lease = setup.begin_media_purge(RUN_ID, "c" * 64, clock.value, "retention-v1")
    assert isinstance(lease, PurgeLease)
    before = _retention_db_state(database)

    def fail_at(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected retention completion fault")

    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="injected retention completion"):
        repository.complete_media_purge(
            RUN_ID,
            lease.media_sha256,
            lease.intent_audit_sequence,
            True,
        )
    assert _retention_db_state(database) == before
    assert _purge_attempt_media(database, "PURGING") == (lease.media_sha256,)

    recovered = setup.complete_media_purge(
        RUN_ID,
        lease.media_sha256,
        lease.intent_audit_sequence,
        True,
    )
    assert recovered.reason_code == PurgeReasonCode.RECOVERED_PURGE_COMPLETED
    assert recovered.previous_availability == MediaAvailability.PURGING


@pytest.mark.parametrize(
    "fault_phase",
    [
        "retention.hold_create.after_audit",
        "retention.hold_create.after_hold",
        "retention.hold_create.after_link",
        "retention.hold_create.before_commit",
    ],
)
def test_retention_hold_creation_faults_roll_back_hold_link_audit_and_head(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    published = setup.publish_pack(
        RUN_ID,
        1,
        _retention_draft(version=1, complete=True),
    )
    hold = _retention_hold(
        hold_id="faulted-hold",
        kind=RetentionHoldKind.APPEAL,
        target_kind=ArtifactKind.MEDIA,
        target_id=published.pack.focus_crops[0].media_sha256,
        owner_id="appeal-fault",
    )
    before = _retention_db_state(database)

    def fail_at(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected retention hold creation fault")

    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="hold creation"):
        repository.create_retention_hold(hold)
    assert _retention_db_state(database) == before


@pytest.mark.parametrize(
    "fault_phase",
    [
        "retention.hold_release.after_audit",
        "retention.hold_release.after_hold",
        "retention.hold_release.after_link",
        "retention.hold_release.before_commit",
    ],
)
def test_retention_hold_release_faults_roll_back_active_state_link_and_audit(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    published = setup.publish_pack(
        RUN_ID,
        1,
        _retention_draft(version=1, complete=True),
    )
    hold = _retention_hold(
        hold_id="release-fault-hold",
        kind=RetentionHoldKind.APPEAL,
        target_kind=ArtifactKind.MEDIA,
        target_id=published.pack.focus_crops[0].media_sha256,
        owner_id="appeal-release-fault",
    )
    setup.create_retention_hold(hold)
    before = _retention_db_state(database)

    def fail_at(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected retention hold release fault")

    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="hold release"):
        repository.release_retention_hold(RUN_ID, hold.hold_id)
    assert _retention_db_state(database) == before
    released = setup.release_retention_hold(RUN_ID, hold.hold_id)
    assert setup.release_retention_hold(RUN_ID, hold.hold_id) == released


@pytest.mark.parametrize(
    "fault_phase",
    ["retention.cleanup.after_ack", "retention.cleanup.before_commit"],
)
def test_retention_cleanup_ack_faults_leave_retryable_lease_without_new_audit(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    setup.publish_pack(RUN_ID, 1, _retention_draft(version=1, complete=True))
    lease = setup.begin_media_purge(RUN_ID, "c" * 64, clock.value, "retention-v1")
    assert isinstance(lease, PurgeLease)
    setup.complete_media_purge(
        RUN_ID,
        lease.media_sha256,
        lease.intent_audit_sequence,
        False,
    )
    before = _retention_db_state(database)

    def fail_at(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected retention cleanup acknowledgement fault")

    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="cleanup acknowledgement"):
        repository.mark_trash_cleaned(
            RUN_ID,
            lease.media_sha256,
            lease.intent_audit_sequence,
        )
    assert _retention_db_state(database) == before
    assert _purge_attempt_media(database, "PURGED_CLEANUP_PENDING") == (lease.media_sha256,)


def test_concurrent_retention_intent_and_completion_are_single_transition(
    tmp_path: Path,
) -> None:
    database, setup, clock = _retention_repository(tmp_path)
    setup.publish_pack(RUN_ID, 1, _retention_draft(version=1, complete=True))
    repositories = tuple(
        SQLiteEvidenceRepository(
            database,
            BUSY_TIMEOUT_MS,
            verifier=_Verifier(),
            clock=clock,
        )
        for _ in range(2)
    )

    def begin(index: int) -> PurgeLease | PurgeItemResult:
        return repositories[index].begin_media_purge(
            RUN_ID,
            "c" * 64,
            clock.value,
            "retention-v1",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        decisions = tuple(executor.map(begin, range(2)))
    leases = tuple(item for item in decisions if isinstance(item, PurgeLease))
    recoveries = tuple(item for item in decisions if not isinstance(item, PurgeLease))
    assert len(leases) == 1
    assert len(recoveries) == 1
    assert recoveries[0].reason_code == PurgeReasonCode.PURGE_ALREADY_IN_PROGRESS
    lease = leases[0]

    def complete(index: int) -> PurgeItemResult:
        return repositories[index].complete_media_purge(
            RUN_ID,
            lease.media_sha256,
            lease.intent_audit_sequence,
            False,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(complete, range(2)))
    assert results[0] == results[1]
    actions = tuple(entry.action for entry in setup.list_audit_entries(RUN_ID))
    assert actions.count(AuditAction.MEDIA_PURGE_REQUESTED) == 1
    assert actions.count(AuditAction.PURGED_BY_RETENTION) == 1
