"""SQLite persistence for additive M8 evaluation and live-ingest authorities."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_evaluation import (
    MAX_M8_EVALUATION_ASSETS,
    MAX_M8_EVALUATION_REPETITIONS,
    M8CaptureSegmentV1,
    M8EvaluationCampaignV1,
    M8EvaluationGroundTruthV1,
    M8EvaluationMediaAssetV1,
    M8EvaluationRunV1,
    M8LiveIngestSessionV1,
)
from labcourt.exceptions import ConcurrentModification, EvidenceMissing

from .sqlite_m8_operations_repository import M8_MIGRATIONS
from .sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _row_int,
    _row_str,
    _validate_busy_timeout,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_MAX_RUNS = MAX_M8_EVALUATION_ASSETS * MAX_M8_EVALUATION_REPETITIONS
_REQUIRED_OBJECTS = frozenset(
    {
        "m8_evaluation_media_assets",
        "m8_evaluation_ground_truth_versions",
        "m8_evaluation_campaign_versions",
        "m8_evaluation_run_versions",
        "m8_live_ingest_session_versions",
        "m8_capture_segments",
        "idx_m8_evaluation_runs_campaign_state",
        "m8_evaluation_ground_truth_validate_contiguous",
        "m8_evaluation_campaign_validate_contiguous",
        "m8_evaluation_run_validate_contiguous",
        "m8_live_ingest_session_validate_contiguous",
    }
)


def _document(model: BaseModel) -> tuple[str, str]:
    raw = canonical_json(model.model_dump(mode="json", exclude_computed_fields=True))
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_document(
    row: sqlite3.Row,
    model_type: type[_ModelT],
    json_column: str,
) -> _ModelT:
    raw = _row_str(row, json_column)
    expected = _row_str(row, "document_sha256")
    if hashlib.sha256(raw.encode("utf-8")).hexdigest() != expected:
        raise RepositoryIntegrityError("M8 evaluation document hash mismatch")
    try:
        model = model_type.model_validate_json(raw)
    except ValidationError as error:
        raise RepositoryIntegrityError("M8 evaluation document is invalid") from error
    serialized = model.model_dump(mode="json", exclude_computed_fields=True)
    if model_type is M8EvaluationRunV1:
        stored = json.loads(raw)
        if not isinstance(stored, dict):
            raise RepositoryIntegrityError("M8 evaluation run document is not an object")
        for additive_field in (
            "m4_case_status",
            "hearing_eligibility",
            "l5_status",
            "route_reason_code",
        ):
            if additive_field not in stored and serialized.get(additive_field) is None:
                serialized.pop(additive_field, None)
    if canonical_json(serialized) != raw:
        raise RepositoryIntegrityError("M8 evaluation document is not canonical")
    return model


class SQLiteM8EvaluationRepository:
    """Append-only, restart-safe media, campaign, run, and live session repository."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        if (
            not isinstance(repository_manifest_id, str)
            or len(repository_manifest_id) != 64
            or any(character not in "0123456789abcdef" for character in repository_manifest_id)
        ):
            raise ValueError("M8 evaluation repository manifest must be lowercase SHA-256")
        self.repository_manifest_id = repository_manifest_id
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8EvaluationRepository:
        MigrationRunner(
            database_path,
            busy_timeout_ms,
            migrations_path=M8_MIGRATIONS,
        ).apply_all()
        return cls(database_path, busy_timeout_ms, repository_manifest_id)

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = _open_connection(
            self._database_path,
            self._busy_timeout_ms,
            allow_create=False,
        )
        try:
            connection.execute("BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(
                self._database_path,
                self._busy_timeout_ms,
                allow_create=False,
            )
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException as error:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            if isinstance(error, sqlite3.OperationalError) and _is_sqlite_concurrency_error(error):
                raise ConcurrentModification("M8 evaluation writer lock unavailable") from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        try:
            migration = connection.execute(
                "SELECT name FROM schema_migrations WHERE version = 16"
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError("M8 evaluation migration ledger is invalid") from error
        if migration is None or _row_str(migration, "name") != "m8_evaluation":
            raise RepositoryIntegrityError("M8 evaluation migration 0016 is absent")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _REQUIRED_OBJECTS)
                ),
                tuple(sorted(_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 evaluation persistence layout is incomplete")

    def put_media(self, asset: M8EvaluationMediaAssetV1) -> M8EvaluationMediaAssetV1:
        if not isinstance(asset, M8EvaluationMediaAssetV1):
            raise TypeError("M8 evaluation media publication requires a typed asset")
        raw, digest = _document(asset)
        with self._immediate() as connection:
            existing = connection.execute(
                "SELECT * FROM m8_evaluation_media_assets WHERE asset_id = ?",
                (asset.asset_id,),
            ).fetchone()
            if existing is not None:
                loaded = _load_document(existing, M8EvaluationMediaAssetV1, "asset_json")
                if loaded == asset:
                    return loaded
                raise ConcurrentModification("M8 evaluation media identity already exists")
            connection.execute(
                """
                INSERT INTO m8_evaluation_media_assets(
                    asset_id, media_sha256, relative_path, document_sha256, asset_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (asset.asset_id, asset.media_sha256, asset.relative_path, digest, raw),
            )
        return asset

    def get_media(self, asset_id: str) -> M8EvaluationMediaAssetV1:
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_evaluation_media_assets WHERE asset_id = ?",
                (asset_id,),
            ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 evaluation media asset is absent")
        return _load_document(row, M8EvaluationMediaAssetV1, "asset_json")

    def list_media(self) -> tuple[M8EvaluationMediaAssetV1, ...]:
        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM m8_evaluation_media_assets ORDER BY asset_id LIMIT ?",
                (MAX_M8_EVALUATION_ASSETS + 1,),
            ).fetchall()
        if len(rows) > MAX_M8_EVALUATION_ASSETS:
            raise RepositoryIntegrityError("M8 evaluation media inventory exceeds its bound")
        return tuple(_load_document(row, M8EvaluationMediaAssetV1, "asset_json") for row in rows)

    def put_ground_truth(
        self,
        truth: M8EvaluationGroundTruthV1,
        expected_prior_revision: int | None,
    ) -> M8EvaluationGroundTruthV1:
        if not isinstance(truth, M8EvaluationGroundTruthV1):
            raise TypeError("M8 evaluation label publication requires typed ground truth")
        raw, digest = _document(truth)
        with self._immediate() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM m8_evaluation_media_assets WHERE asset_id = ?",
                    (truth.asset_id,),
                ).fetchone()
                is None
            ):
                raise EvidenceMissing("M8 evaluation label media asset is absent")
            existing = connection.execute(
                "SELECT * FROM m8_evaluation_ground_truth_versions WHERE ground_truth_id = ?",
                (truth.ground_truth_id,),
            ).fetchone()
            if existing is not None:
                loaded = _load_document(existing, M8EvaluationGroundTruthV1, "ground_truth_json")
                if loaded == truth and (
                    expected_prior_revision == truth.revision - 1
                    or (truth.revision == 1 and expected_prior_revision is None)
                ):
                    return loaded
                raise ConcurrentModification("M8 evaluation ground truth already exists")
            prior = connection.execute(
                """
                SELECT revision FROM m8_evaluation_ground_truth_versions
                WHERE asset_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (truth.asset_id,),
            ).fetchone()
            observed = _row_int(prior, "revision") if prior is not None else None
            if observed != expected_prior_revision or truth.revision != (observed or 0) + 1:
                raise ConcurrentModification("M8 evaluation ground-truth revision is stale")
            connection.execute(
                """
                INSERT INTO m8_evaluation_ground_truth_versions(
                    ground_truth_id, asset_id, revision, review_state,
                    document_sha256, ground_truth_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    truth.ground_truth_id,
                    truth.asset_id,
                    truth.revision,
                    truth.review_state.value,
                    digest,
                    raw,
                ),
            )
        return truth

    def get_current_ground_truth(self, asset_id: str) -> M8EvaluationGroundTruthV1:
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_evaluation_ground_truth_versions
                WHERE asset_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (asset_id,),
            ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 evaluation ground truth is absent")
        return _load_document(row, M8EvaluationGroundTruthV1, "ground_truth_json")

    def list_current_ground_truth(self) -> tuple[M8EvaluationGroundTruthV1, ...]:
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT current.* FROM m8_evaluation_ground_truth_versions AS current
                JOIN (
                    SELECT asset_id, MAX(revision) AS revision
                    FROM m8_evaluation_ground_truth_versions GROUP BY asset_id
                ) AS latest
                ON latest.asset_id = current.asset_id AND latest.revision = current.revision
                ORDER BY current.asset_id LIMIT ?
                """,
                (MAX_M8_EVALUATION_ASSETS + 1,),
            ).fetchall()
        if len(rows) > MAX_M8_EVALUATION_ASSETS:
            raise RepositoryIntegrityError("M8 evaluation truth inventory exceeds its bound")
        return tuple(
            _load_document(row, M8EvaluationGroundTruthV1, "ground_truth_json") for row in rows
        )

    def put_campaign(
        self,
        campaign: M8EvaluationCampaignV1,
        expected_prior_revision: int | None,
    ) -> M8EvaluationCampaignV1:
        if not isinstance(campaign, M8EvaluationCampaignV1):
            raise TypeError("M8 evaluation campaign publication requires a typed campaign")
        return self._put_versioned(
            table="m8_evaluation_campaign_versions",
            identity_column="campaign_id",
            identity=campaign.campaign_id,
            revision=campaign.revision,
            state=campaign.state.value,
            json_column="campaign_json",
            model=campaign,
            model_type=M8EvaluationCampaignV1,
            expected_prior_revision=expected_prior_revision,
            extra_columns=(),
            extra_values=(),
        )

    def get_campaign(self, campaign_id: str) -> M8EvaluationCampaignV1:
        return self._get_current(
            "m8_evaluation_campaign_versions",
            "campaign_id",
            campaign_id,
            "campaign_json",
            M8EvaluationCampaignV1,
        )

    def list_campaigns(self) -> tuple[M8EvaluationCampaignV1, ...]:
        return self._list_current(
            "m8_evaluation_campaign_versions",
            "campaign_id",
            "campaign_json",
            M8EvaluationCampaignV1,
            MAX_M8_EVALUATION_ASSETS,
        )

    def put_run(
        self,
        run: M8EvaluationRunV1,
        expected_prior_revision: int | None,
    ) -> M8EvaluationRunV1:
        if not isinstance(run, M8EvaluationRunV1):
            raise TypeError("M8 evaluation run publication requires a typed run")
        return self._put_versioned(
            table="m8_evaluation_run_versions",
            identity_column="run_id",
            identity=run.run_id,
            revision=run.revision,
            state=run.state.value,
            json_column="run_json",
            model=run,
            model_type=M8EvaluationRunV1,
            expected_prior_revision=expected_prior_revision,
            extra_columns=("campaign_id", "asset_id"),
            extra_values=(run.campaign_id, run.source.asset_id),
        )

    def get_run(self, run_id: str) -> M8EvaluationRunV1:
        return self._get_current(
            "m8_evaluation_run_versions",
            "run_id",
            run_id,
            "run_json",
            M8EvaluationRunV1,
        )

    def list_runs(self) -> tuple[M8EvaluationRunV1, ...]:
        return self._list_current(
            "m8_evaluation_run_versions",
            "run_id",
            "run_json",
            M8EvaluationRunV1,
            _MAX_RUNS,
        )

    def put_live_session(
        self,
        session: M8LiveIngestSessionV1,
        expected_prior_revision: int | None,
    ) -> M8LiveIngestSessionV1:
        if not isinstance(session, M8LiveIngestSessionV1):
            raise TypeError("M8 live ingest publication requires a typed session")
        return self._put_versioned(
            table="m8_live_ingest_session_versions",
            identity_column="session_id",
            identity=session.session_id,
            revision=session.revision,
            state=session.state.value,
            json_column="session_json",
            model=session,
            model_type=M8LiveIngestSessionV1,
            expected_prior_revision=expected_prior_revision,
            extra_columns=(),
            extra_values=(),
        )

    def get_live_session(self, session_id: str) -> M8LiveIngestSessionV1:
        return self._get_current(
            "m8_live_ingest_session_versions",
            "session_id",
            session_id,
            "session_json",
            M8LiveIngestSessionV1,
        )

    def put_capture_segment(self, segment: M8CaptureSegmentV1) -> M8CaptureSegmentV1:
        if not isinstance(segment, M8CaptureSegmentV1):
            raise TypeError("M8 capture persistence requires a typed segment")
        raw, digest = _document(segment)
        with self._immediate() as connection:
            existing = connection.execute(
                "SELECT * FROM m8_capture_segments WHERE segment_id = ?",
                (segment.segment_id,),
            ).fetchone()
            if existing is not None:
                loaded = _load_document(existing, M8CaptureSegmentV1, "segment_json")
                if loaded == segment:
                    return loaded
                raise ConcurrentModification("M8 capture segment already exists")
            connection.execute(
                """
                INSERT INTO m8_capture_segments(
                    segment_id, session_id, asset_id, document_sha256, segment_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (segment.segment_id, segment.session_id, segment.asset.asset_id, digest, raw),
            )
        return segment

    def _put_versioned(
        self,
        *,
        table: str,
        identity_column: str,
        identity: str,
        revision: int,
        state: str,
        json_column: str,
        model: _ModelT,
        model_type: type[_ModelT],
        expected_prior_revision: int | None,
        extra_columns: tuple[str, ...],
        extra_values: tuple[str, ...],
    ) -> _ModelT:
        raw, digest = _document(model)
        with self._immediate() as connection:
            existing = connection.execute(
                f"SELECT * FROM {table} WHERE {identity_column} = ? AND revision = ?",
                (identity, revision),
            ).fetchone()
            if existing is not None:
                loaded = _load_document(existing, model_type, json_column)
                if loaded == model and (
                    expected_prior_revision == revision - 1
                    or (revision == 1 and expected_prior_revision is None)
                ):
                    return loaded
                raise ConcurrentModification("M8 evaluation authority revision already exists")
            prior = connection.execute(
                f"SELECT revision FROM {table} WHERE {identity_column} = ? "
                "ORDER BY revision DESC LIMIT 1",
                (identity,),
            ).fetchone()
            observed = _row_int(prior, "revision") if prior is not None else None
            if observed != expected_prior_revision or revision != (observed or 0) + 1:
                raise ConcurrentModification("M8 evaluation authority revision is stale")
            columns = (
                identity_column,
                "revision",
                *extra_columns,
                "state",
                "document_sha256",
                json_column,
            )
            values = (identity, revision, *extra_values, state, digest, raw)
            connection.execute(
                f"INSERT INTO {table}({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _value in values)})",
                values,
            )
        return model

    def _get_current(
        self,
        table: str,
        identity_column: str,
        identity: str,
        json_column: str,
        model_type: type[_ModelT],
    ) -> _ModelT:
        with self._read() as connection:
            row = connection.execute(
                f"SELECT * FROM {table} WHERE {identity_column} = ? ORDER BY revision DESC LIMIT 1",
                (identity,),
            ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 evaluation authority is absent")
        return _load_document(row, model_type, json_column)

    def _list_current(
        self,
        table: str,
        identity_column: str,
        json_column: str,
        model_type: type[_ModelT],
        limit: int,
    ) -> tuple[_ModelT, ...]:
        with self._read() as connection:
            rows = connection.execute(
                f"""
                SELECT current.* FROM {table} AS current
                JOIN (
                    SELECT {identity_column}, MAX(revision) AS revision
                    FROM {table} GROUP BY {identity_column}
                ) AS latest
                ON latest.{identity_column} = current.{identity_column}
                AND latest.revision = current.revision
                ORDER BY current.{identity_column} LIMIT ?
                """,
                (limit + 1,),
            ).fetchall()
        if len(rows) > limit:
            raise RepositoryIntegrityError("M8 evaluation authority inventory exceeds its bound")
        return tuple(_load_document(row, model_type, json_column) for row in rows)


__all__ = ["SQLiteM8EvaluationRepository"]
