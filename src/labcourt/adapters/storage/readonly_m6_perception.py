"""Read exact M6 perception authority from one immutable SQLite snapshot."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m6_perception_authority import (
    M6PerceptionAuthorityError,
    M6PerceptionAuthorityErrorCode,
    assemble_m6_resolved_perception,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import parse_frame_id
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.ports.m6_perception import (
    M6DetectionAuthorityDocument,
    M6FrameAuthorityDocument,
    M6PerceptionAuthoritySnapshot,
)

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity
from .readonly_sqlite import ReadOnlySnapshotError

_QUERY_ID_CHUNK = 400
_MAX_PERCEPTION_DOCUMENT_BYTES = 1024 * 1024
_REQUIRED_TABLES = frozenset(
    {
        "schema_migrations",
        "run_manifests",
        "runs",
        "cases",
        "case_versions",
        "frames",
        "detections",
    }
)


def _fail(code: M6PerceptionAuthorityErrorCode) -> NoReturn:
    raise M6PerceptionAuthorityError(code)


def _row_str(row: sqlite3.Row, key: str) -> str:
    value = row[key]
    if not isinstance(value, str):
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
    return value


def _row_int(row: sqlite3.Row, key: str) -> int:
    value = row[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
    return value


def _document_sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _require_document_budget(document: str) -> None:
    if len(document.encode("utf-8")) > _MAX_PERCEPTION_DOCUMENT_BYTES:
        raise ReadOnlySnapshotError("DATABASE_DOCUMENT_BUDGET_EXCEEDED")


def _chunks(values: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    return tuple(
        values[index : index + _QUERY_ID_CHUNK] for index in range(0, len(values), _QUERY_ID_CHUNK)
    )


class ReadonlyM6PerceptionAuthorityRepository:
    """Resolve only closure-listed rows without a provider or writable cache."""

    __slots__ = ("_snapshot",)

    def __init__(self, snapshot: str | Path) -> None:
        self._snapshot = Path(snapshot).absolute()

    def read_authority_snapshot(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6PerceptionAuthoritySnapshot:
        controlled_closure = self._validate_closure(closure)
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{self._snapshot.as_uri()}?mode=ro&immutable=1",
                uri=True,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            self._require_schema(connection)
            manifest, manifest_document, manifest_document_sha256 = self._read_manifest(
                connection,
                controlled_closure,
            )
            (
                source_case_document,
                source_case_document_sha256,
            ) = self._read_source_case(connection, controlled_closure)
            frames = self._read_frames(connection, controlled_closure)
            detections = self._read_detections(
                connection,
                controlled_closure,
                manifest,
            )
            connection.commit()
        except M6PerceptionAuthorityError:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise
        except (sqlite3.Error, IndexError, KeyError):
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID") from None
        finally:
            if connection is not None:
                connection.close()
        if capture_m6_readonly_snapshot_identity(self._snapshot) != before:
            raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_M6_PERCEPTION_READ")
        return M6PerceptionAuthoritySnapshot(
            source_identity_sha256=before.identity_sha256,
            run_id=controlled_closure.source_run_id,
            manifest_id=controlled_closure.source_manifest_id,
            manifest_canonical_document=manifest_document,
            manifest_document_sha256=manifest_document_sha256,
            source_case_id=controlled_closure.source_case_id,
            source_case_revision=controlled_closure.source_case_revision,
            source_case_canonical_document=source_case_document,
            source_case_document_sha256=source_case_document_sha256,
            frames=frames,
            detections=detections,
        )

    def assemble(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ResolvedPerception:
        authority = self.read_authority_snapshot(closure)
        return assemble_m6_resolved_perception(
            closure=closure,
            snapshot=authority,
        )

    @staticmethod
    def _validate_closure(
        closure: object,
    ) -> M6ReplayInputClosureAuthority:
        if not isinstance(closure, M6ReplayInputClosureAuthority):
            _fail(M6PerceptionAuthorityErrorCode.INVALID_ARGUMENT)
        try:
            canonical = M6ReplayInputClosureAuthority.model_validate(
                closure.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (TypeError, ValueError, ValidationError):
            _fail(M6PerceptionAuthorityErrorCode.INVALID_ARGUMENT)
        if canonical != closure:
            _fail(M6PerceptionAuthorityErrorCode.INVALID_ARGUMENT)
        return canonical

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        if len(integrity_rows) != 1 or integrity_rows[0][0] != "ok":
            raise ReadOnlySnapshotError("DATABASE_INTEGRITY_INVALID")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ReadOnlySnapshotError("DATABASE_FOREIGN_KEY_INVALID")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
            if isinstance(row[0], str)
        }
        versions = {
            int(row[0])
            for row in connection.execute(
                "SELECT version FROM schema_migrations WHERE version IN (1, 2)"
            ).fetchall()
            if isinstance(row[0], int) and not isinstance(row[0], bool)
        }
        if not _REQUIRED_TABLES.issubset(tables) or versions != {1, 2}:
            raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")

    @staticmethod
    def _read_manifest(
        connection: sqlite3.Connection,
        closure: M6ReplayInputClosureAuthority,
    ) -> tuple[RunManifest, str, str]:
        row = connection.execute(
            """
            SELECT r.run_id, r.manifest_id,
                   rm.schema_version, rm.document_json, rm.document_sha256
            FROM runs AS r
            JOIN run_manifests AS rm ON rm.manifest_id = r.manifest_id
            WHERE r.run_id = ?
            """,
            (closure.source_run_id,),
        ).fetchone()
        if row is None or _row_str(row, "manifest_id") != closure.source_manifest_id:
            _fail(M6PerceptionAuthorityErrorCode.SNAPSHOT_SCOPE_MISMATCH)
        raw = _row_str(row, "document_json")
        stored_sha256 = _row_str(row, "document_sha256")
        _require_document_budget(raw)
        try:
            manifest = RunManifest.model_validate_json(raw)
        except (TypeError, ValueError, ValidationError):
            _fail(M6PerceptionAuthorityErrorCode.SOURCE_MANIFEST_INVALID)
        if (
            _row_str(row, "run_id") != closure.source_run_id
            or _row_str(row, "schema_version") != manifest.schema_version
            or manifest.manifest_id != closure.source_manifest_id
            or canonical_json(manifest.model_dump(mode="json")) != raw
            or _document_sha256(raw) != stored_sha256
            or stored_sha256 != closure.source_manifest_document_sha256
        ):
            _fail(M6PerceptionAuthorityErrorCode.SOURCE_MANIFEST_INVALID)
        return manifest, raw, stored_sha256

    @staticmethod
    def _read_source_case(
        connection: sqlite3.Connection,
        closure: M6ReplayInputClosureAuthority,
    ) -> tuple[str | None, str | None]:
        if closure.source_case_id is None:
            return None, None
        row = connection.execute(
            """
            SELECT run_id, case_id, revision, status, case_json, document_sha256
            FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (
                closure.source_run_id,
                closure.source_case_id,
                closure.source_case_revision,
            ),
        ).fetchone()
        if row is None:
            foreign = connection.execute(
                """
                SELECT 1 FROM case_versions
                WHERE run_id <> ? AND case_id = ? AND revision = ? LIMIT 1
                """,
                (
                    closure.source_run_id,
                    closure.source_case_id,
                    closure.source_case_revision,
                ),
            ).fetchone()
            if foreign is not None:
                _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)
            _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)
        raw = _row_str(row, "case_json")
        stored_sha256 = _row_str(row, "document_sha256")
        _require_document_budget(raw)
        try:
            source_case = Case.model_validate_json(raw)
        except (TypeError, ValueError, ValidationError):
            _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)
        if (
            _row_str(row, "run_id") != closure.source_run_id
            or _row_str(row, "case_id") != closure.source_case_id
            or _row_int(row, "revision") != closure.source_case_revision
            or _row_str(row, "status") != source_case.status.value
            or source_case.run_id != closure.source_run_id
            or source_case.case_id != closure.source_case_id
            or source_case.manifest_id != closure.source_manifest_id
            or canonical_json(source_case.model_dump(mode="json")) != raw
            or _document_sha256(raw) != stored_sha256
            or stored_sha256 != closure.source_case_document_sha256
        ):
            _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)
        return raw, stored_sha256

    @classmethod
    def _read_frames(
        cls,
        connection: sqlite3.Connection,
        closure: M6ReplayInputClosureAuthority,
    ) -> tuple[M6FrameAuthorityDocument, ...]:
        requested_ids = tuple(item.frame_id for item in closure.frames)
        rows: list[sqlite3.Row] = []
        for chunk in _chunks(requested_ids):
            placeholders = ", ".join("?" for _value in chunk)
            rows.extend(
                connection.execute(
                    f"""
                    SELECT run_id, frame_id, manifest_id, camera_id, stream_id,
                           frame_index, fps_num, fps_den, width, height,
                           content_sha256, document_json, document_sha256
                    FROM frames
                    WHERE run_id = ? AND frame_id IN ({placeholders})
                    """,
                    (closure.source_run_id, *chunk),
                ).fetchall()
            )
        observed_ids = {_row_str(row, "frame_id") for row in rows}
        cls._reject_foreign_missing(
            connection,
            table="frames",
            id_column="frame_id",
            run_id=closure.source_run_id,
            missing_ids=tuple(sorted(set(requested_ids) - observed_ids)),
            code=M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_SCOPE_MISMATCH,
        )
        documents: list[M6FrameAuthorityDocument] = []
        for row in rows:
            raw = _row_str(row, "document_json")
            stored_sha256 = _row_str(row, "document_sha256")
            _require_document_budget(raw)
            try:
                frame = FrameRef.model_validate_json(raw)
            except (TypeError, ValueError, ValidationError):
                _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_DOCUMENT_INVALID)
            indexed = (
                _row_str(row, "frame_id"),
                _row_str(row, "camera_id"),
                _row_str(row, "stream_id"),
                _row_int(row, "frame_index"),
                _row_int(row, "fps_num"),
                _row_int(row, "fps_den"),
                _row_int(row, "width"),
                _row_int(row, "height"),
                _row_str(row, "content_sha256"),
            )
            expected = (
                frame.frame_id,
                frame.camera_id,
                frame.stream_id,
                frame.frame_index,
                frame.fps_num,
                frame.fps_den,
                frame.width,
                frame.height,
                frame.content_sha256,
            )
            if (
                _row_str(row, "run_id") != closure.source_run_id
                or _row_str(row, "manifest_id") != closure.source_manifest_id
                or indexed != expected
                or frame.content_sha256 is None
                or canonical_json(frame.model_dump(mode="json")) != raw
                or _document_sha256(raw) != stored_sha256
            ):
                _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_DOCUMENT_INVALID)
            content_sha256 = frame.content_sha256
            assert content_sha256 is not None
            documents.append(
                M6FrameAuthorityDocument(
                    run_id=closure.source_run_id,
                    manifest_id=closure.source_manifest_id,
                    frame_id=frame.frame_id,
                    content_sha256=content_sha256,
                    canonical_document=raw,
                    document_sha256=stored_sha256,
                )
            )
        return tuple(sorted(documents, key=lambda item: parse_frame_id(item.frame_id)))

    @classmethod
    def _read_detections(
        cls,
        connection: sqlite3.Connection,
        closure: M6ReplayInputClosureAuthority,
        manifest: RunManifest,
    ) -> tuple[M6DetectionAuthorityDocument, ...]:
        requested_ids = tuple(item.detection_id for item in closure.detections)
        rows: list[sqlite3.Row] = []
        for chunk in _chunks(requested_ids):
            placeholders = ", ".join("?" for _value in chunk)
            rows.extend(
                connection.execute(
                    f"""
                    SELECT run_id, detection_id, frame_id, manifest_id,
                           detector_manifest_id, label,
                           document_json, document_sha256
                    FROM detections
                    WHERE run_id = ? AND detection_id IN ({placeholders})
                    """,
                    (closure.source_run_id, *chunk),
                ).fetchall()
            )
        observed_ids = {_row_str(row, "detection_id") for row in rows}
        cls._reject_foreign_missing(
            connection,
            table="detections",
            id_column="detection_id",
            run_id=closure.source_run_id,
            missing_ids=tuple(sorted(set(requested_ids) - observed_ids)),
            code=M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_SCOPE_MISMATCH,
        )
        detector_manifest = manifest.models.get("detector")
        if detector_manifest is None:
            _fail(M6PerceptionAuthorityErrorCode.SOURCE_MANIFEST_INVALID)
        documents: list[M6DetectionAuthorityDocument] = []
        for row in rows:
            raw = _row_str(row, "document_json")
            stored_sha256 = _row_str(row, "document_sha256")
            _require_document_budget(raw)
            try:
                detection = Detection.model_validate_json(raw)
            except (TypeError, ValueError, ValidationError):
                _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_DOCUMENT_INVALID)
            if (
                _row_str(row, "run_id") != closure.source_run_id
                or _row_str(row, "manifest_id") != closure.source_manifest_id
                or _row_str(row, "detection_id") != detection.detection_id
                or _row_str(row, "frame_id") != detection.frame_id
                or _row_str(row, "detector_manifest_id") != detection.model_manifest_id
                or detection.model_manifest_id != detector_manifest.model_manifest_id
                or _row_str(row, "label") != detection.label
                or canonical_json(detection.model_dump(mode="json")) != raw
                or _document_sha256(raw) != stored_sha256
            ):
                _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_DOCUMENT_INVALID)
            documents.append(
                M6DetectionAuthorityDocument(
                    run_id=closure.source_run_id,
                    manifest_id=closure.source_manifest_id,
                    detection_id=detection.detection_id,
                    frame_id=detection.frame_id,
                    model_manifest_id=detection.model_manifest_id,
                    canonical_document=raw,
                    document_sha256=stored_sha256,
                )
            )
        return tuple(
            sorted(
                documents,
                key=lambda item: (parse_frame_id(item.frame_id), item.detection_id),
            )
        )

    @staticmethod
    def _reject_foreign_missing(
        connection: sqlite3.Connection,
        *,
        table: str,
        id_column: str,
        run_id: str,
        missing_ids: tuple[str, ...],
        code: M6PerceptionAuthorityErrorCode,
    ) -> None:
        for chunk in _chunks(missing_ids):
            placeholders = ", ".join("?" for _value in chunk)
            foreign = connection.execute(
                f"""
                SELECT 1 FROM "{table}"
                WHERE run_id <> ? AND "{id_column}" IN ({placeholders}) LIMIT 1
                """,
                (run_id, *chunk),
            ).fetchone()
            if foreign is not None:
                _fail(code)


__all__ = ["ReadonlyM6PerceptionAuthorityRepository"]
