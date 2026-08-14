"""Append-only SQLite persistence for additive M8 shadow calibration."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_calibration import (
    M8CalibrationArtifactV1,
    M8CalibrationDatasetManifestV1,
    M8CalibrationReportV1,
    M8DetectorScoreObservationV1,
    M8EventRiskAssessmentV1,
    M8EvidenceQualityAssessmentV1,
)
from labcourt.exceptions import ConcurrentModification, EvidenceMissing

from .sqlite_m8_operations_repository import M8_MIGRATIONS
from .sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _row_str,
    _validate_busy_timeout,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_MAX_CALIBRATION_AUTHORITIES = 10_000
_REQUIRED_OBJECTS = frozenset(
    {
        "m8_calibration_dataset_manifests",
        "m8_calibration_artifacts",
        "m8_calibration_reports",
        "m8_detector_score_observations",
        "m8_evidence_quality_assessments",
        "m8_event_risk_assessments",
        "idx_m8_calibration_artifacts_dataset",
        "idx_m8_calibration_reports_artifact",
        "idx_m8_detector_scores_run",
        "idx_m8_evidence_quality_run",
        "idx_m8_event_risk_run",
    }
)


def _document(model: BaseModel) -> tuple[str, str]:
    raw = canonical_json(model.model_dump(mode="json", exclude_computed_fields=True))
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load(row: sqlite3.Row, model_type: type[_ModelT], column: str) -> _ModelT:
    raw = _row_str(row, column)
    if hashlib.sha256(raw.encode("utf-8")).hexdigest() != _row_str(row, "document_sha256"):
        raise RepositoryIntegrityError("M8 calibration document hash mismatch")
    try:
        model = model_type.model_validate_json(raw)
    except ValidationError as error:
        raise RepositoryIntegrityError("M8 calibration document is invalid") from error
    if canonical_json(model.model_dump(mode="json", exclude_computed_fields=True)) != raw:
        raise RepositoryIntegrityError("M8 calibration document is not canonical")
    return model


class SQLiteM8CalibrationRepository:
    """Persist immutable datasets, JSON parameters, reports, and shadow scores."""

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
            raise ValueError("M8 calibration repository manifest must be lowercase SHA-256")
        self.repository_manifest_id = repository_manifest_id
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8CalibrationRepository:
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
                raise ConcurrentModification("M8 calibration writer lock unavailable") from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        try:
            migration = connection.execute(
                "SELECT name FROM schema_migrations WHERE version = 15"
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError("M8 calibration migration ledger is invalid") from error
        if migration is None or _row_str(migration, "name") != "m8_calibration":
            raise RepositoryIntegrityError("M8 calibration migration 0015 is absent")
        placeholders = ",".join("?" for _name in _REQUIRED_OBJECTS)
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                f"SELECT name FROM sqlite_master WHERE name IN ({placeholders})",
                tuple(sorted(_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 calibration persistence layout is incomplete")

    def put_dataset(
        self, manifest: M8CalibrationDatasetManifestV1
    ) -> M8CalibrationDatasetManifestV1:
        return self._put(
            table="m8_calibration_dataset_manifests",
            identity_column="dataset_manifest_id",
            identity=manifest.dataset_manifest_id,
            json_column="dataset_json",
            model=manifest,
            model_type=M8CalibrationDatasetManifestV1,
            extra_columns=(),
            extra_values=(),
        )

    def get_dataset(self, dataset_manifest_id: str) -> M8CalibrationDatasetManifestV1:
        return self._get(
            "m8_calibration_dataset_manifests",
            "dataset_manifest_id",
            dataset_manifest_id,
            "dataset_json",
            M8CalibrationDatasetManifestV1,
        )

    def list_datasets(self) -> tuple[M8CalibrationDatasetManifestV1, ...]:
        return self._list(
            "m8_calibration_dataset_manifests",
            "dataset_json",
            M8CalibrationDatasetManifestV1,
        )

    def get_latest_dataset(self) -> M8CalibrationDatasetManifestV1:
        return self._latest(
            "m8_calibration_dataset_manifests",
            "dataset_json",
            M8CalibrationDatasetManifestV1,
        )

    def put_artifact(self, artifact: M8CalibrationArtifactV1) -> M8CalibrationArtifactV1:
        with self._read() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM m8_calibration_dataset_manifests WHERE dataset_manifest_id = ?",
                    (artifact.dataset_manifest_id,),
                ).fetchone()
                is None
            ):
                raise EvidenceMissing("M8 calibration artifact dataset is absent")
        return self._put(
            table="m8_calibration_artifacts",
            identity_column="artifact_id",
            identity=artifact.artifact_id,
            json_column="artifact_json",
            model=artifact,
            model_type=M8CalibrationArtifactV1,
            extra_columns=("dataset_manifest_id", "detector_model_manifest_id"),
            extra_values=(artifact.dataset_manifest_id, artifact.detector_model_manifest_id),
        )

    def get_artifact(self, artifact_id: str) -> M8CalibrationArtifactV1:
        return self._get(
            "m8_calibration_artifacts",
            "artifact_id",
            artifact_id,
            "artifact_json",
            M8CalibrationArtifactV1,
        )

    def list_artifacts(
        self, dataset_manifest_id: str | None = None
    ) -> tuple[M8CalibrationArtifactV1, ...]:
        return self._list(
            "m8_calibration_artifacts",
            "artifact_json",
            M8CalibrationArtifactV1,
            filter_column=("dataset_manifest_id" if dataset_manifest_id is not None else None),
            filter_value=dataset_manifest_id,
        )

    def get_latest_artifact(
        self, dataset_manifest_id: str | None = None
    ) -> M8CalibrationArtifactV1:
        return self._latest(
            "m8_calibration_artifacts",
            "artifact_json",
            M8CalibrationArtifactV1,
            filter_column=("dataset_manifest_id" if dataset_manifest_id is not None else None),
            filter_value=dataset_manifest_id,
        )

    def put_report(self, report: M8CalibrationReportV1) -> M8CalibrationReportV1:
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_calibration_artifacts WHERE artifact_id = ?",
                (report.artifact_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 calibration report artifact is absent")
            artifact = _load(row, M8CalibrationArtifactV1, "artifact_json")
            if artifact.dataset_manifest_id != report.dataset_manifest_id:
                raise ConcurrentModification("M8 calibration report changed its dataset binding")
        return self._put(
            table="m8_calibration_reports",
            identity_column="report_id",
            identity=report.report_id,
            json_column="report_json",
            model=report,
            model_type=M8CalibrationReportV1,
            extra_columns=("artifact_id", "dataset_manifest_id"),
            extra_values=(report.artifact_id, report.dataset_manifest_id),
        )

    def get_report(self, report_id: str) -> M8CalibrationReportV1:
        return self._get(
            "m8_calibration_reports",
            "report_id",
            report_id,
            "report_json",
            M8CalibrationReportV1,
        )

    def list_reports(self, artifact_id: str | None = None) -> tuple[M8CalibrationReportV1, ...]:
        return self._list(
            "m8_calibration_reports",
            "report_json",
            M8CalibrationReportV1,
            filter_column=("artifact_id" if artifact_id is not None else None),
            filter_value=artifact_id,
        )

    def get_latest_report(self, artifact_id: str | None = None) -> M8CalibrationReportV1:
        return self._latest(
            "m8_calibration_reports",
            "report_json",
            M8CalibrationReportV1,
            filter_column=("artifact_id" if artifact_id is not None else None),
            filter_value=artifact_id,
        )

    def put_detector_observation(
        self, observation: M8DetectorScoreObservationV1
    ) -> M8DetectorScoreObservationV1:
        return self._put(
            table="m8_detector_score_observations",
            identity_column="observation_id",
            identity=observation.observation_id,
            json_column="observation_json",
            model=observation,
            model_type=M8DetectorScoreObservationV1,
            extra_columns=("run_id", "asset_id", "detector_model_manifest_id"),
            extra_values=(
                observation.run_id,
                observation.asset_id,
                observation.detector_model_manifest_id,
            ),
        )

    def get_detector_observation(self, observation_id: str) -> M8DetectorScoreObservationV1:
        return self._get(
            "m8_detector_score_observations",
            "observation_id",
            observation_id,
            "observation_json",
            M8DetectorScoreObservationV1,
        )

    def list_detector_observations(self, run_id: str) -> tuple[M8DetectorScoreObservationV1, ...]:
        return self._list(
            "m8_detector_score_observations",
            "observation_json",
            M8DetectorScoreObservationV1,
            filter_column="run_id",
            filter_value=run_id,
        )

    def put_evidence_assessment(
        self, assessment: M8EvidenceQualityAssessmentV1
    ) -> M8EvidenceQualityAssessmentV1:
        if assessment.artifact_id is not None:
            with self._read() as connection:
                if (
                    connection.execute(
                        "SELECT 1 FROM m8_calibration_artifacts WHERE artifact_id = ?",
                        (assessment.artifact_id,),
                    ).fetchone()
                    is None
                ):
                    raise EvidenceMissing("M8 evidence-quality artifact is absent")
        return self._put(
            table="m8_evidence_quality_assessments",
            identity_column="assessment_id",
            identity=assessment.assessment_id,
            json_column="assessment_json",
            model=assessment,
            model_type=M8EvidenceQualityAssessmentV1,
            extra_columns=("run_id", "asset_id", "mode", "artifact_id"),
            extra_values=(
                assessment.run_id,
                assessment.asset_id,
                assessment.mode.value,
                assessment.artifact_id,
            ),
        )

    def get_evidence_assessment(self, assessment_id: str) -> M8EvidenceQualityAssessmentV1:
        return self._get(
            "m8_evidence_quality_assessments",
            "assessment_id",
            assessment_id,
            "assessment_json",
            M8EvidenceQualityAssessmentV1,
        )

    def get_latest_evidence_assessment(self, run_id: str) -> M8EvidenceQualityAssessmentV1:
        return self._latest(
            "m8_evidence_quality_assessments",
            "assessment_json",
            M8EvidenceQualityAssessmentV1,
            filter_column="run_id",
            filter_value=run_id,
        )

    def put_event_assessment(self, assessment: M8EventRiskAssessmentV1) -> M8EventRiskAssessmentV1:
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_evidence_quality_assessments WHERE assessment_id = ?",
                (assessment.evidence_quality_assessment_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 event-risk evidence assessment is absent")
            evidence = _load(row, M8EvidenceQualityAssessmentV1, "assessment_json")
            if evidence.run_id != assessment.run_id or evidence.asset_id != assessment.asset_id:
                raise ConcurrentModification(
                    "M8 event-risk assessment changed its evidence-quality scope"
                )
        return self._put(
            table="m8_event_risk_assessments",
            identity_column="assessment_id",
            identity=assessment.assessment_id,
            json_column="assessment_json",
            model=assessment,
            model_type=M8EventRiskAssessmentV1,
            extra_columns=(
                "run_id",
                "asset_id",
                "evidence_quality_assessment_id",
                "mode",
                "artifact_id",
            ),
            extra_values=(
                assessment.run_id,
                assessment.asset_id,
                assessment.evidence_quality_assessment_id,
                assessment.mode.value,
                assessment.artifact_id,
            ),
        )

    def get_event_assessment(self, assessment_id: str) -> M8EventRiskAssessmentV1:
        return self._get(
            "m8_event_risk_assessments",
            "assessment_id",
            assessment_id,
            "assessment_json",
            M8EventRiskAssessmentV1,
        )

    def get_latest_event_assessment(self, run_id: str) -> M8EventRiskAssessmentV1:
        return self._latest(
            "m8_event_risk_assessments",
            "assessment_json",
            M8EventRiskAssessmentV1,
            filter_column="run_id",
            filter_value=run_id,
        )

    def _put(
        self,
        *,
        table: str,
        identity_column: str,
        identity: str,
        json_column: str,
        model: _ModelT,
        model_type: type[_ModelT],
        extra_columns: tuple[str, ...],
        extra_values: tuple[object, ...],
    ) -> _ModelT:
        if not isinstance(model, model_type):
            raise TypeError("M8 calibration persistence requires its exact typed document")
        raw, digest = _document(model)
        with self._immediate() as connection:
            row = connection.execute(
                f"SELECT * FROM {table} WHERE {identity_column} = ?",
                (identity,),
            ).fetchone()
            if row is not None:
                loaded = _load(row, model_type, json_column)
                if loaded == model:
                    return loaded
                raise ConcurrentModification("M8 calibration identity already exists")
            columns = (identity_column, *extra_columns, "document_sha256", json_column)
            placeholders = ",".join("?" for _column in columns)
            connection.execute(
                f"INSERT INTO {table}({','.join(columns)}) VALUES ({placeholders})",
                (identity, *extra_values, digest, raw),
            )
        return model

    def _get(
        self,
        table: str,
        identity_column: str,
        identity: str,
        json_column: str,
        model_type: type[_ModelT],
    ) -> _ModelT:
        with self._read() as connection:
            row = connection.execute(
                f"SELECT * FROM {table} WHERE {identity_column} = ?",
                (identity,),
            ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 calibration authority is absent")
        return _load(row, model_type, json_column)

    def _list(
        self,
        table: str,
        json_column: str,
        model_type: type[_ModelT],
        *,
        filter_column: str | None = None,
        filter_value: str | None = None,
    ) -> tuple[_ModelT, ...]:
        where = f"WHERE {filter_column} = ?" if filter_column is not None else ""
        parameters: tuple[object, ...] = (
            (filter_value, _MAX_CALIBRATION_AUTHORITIES + 1)
            if filter_column is not None
            else (_MAX_CALIBRATION_AUTHORITIES + 1,)
        )
        with self._read() as connection:
            rows = connection.execute(
                f"SELECT * FROM {table} {where} ORDER BY rowid LIMIT ?",
                parameters,
            ).fetchall()
        if len(rows) > _MAX_CALIBRATION_AUTHORITIES:
            raise RepositoryIntegrityError("M8 calibration authority inventory exceeds its bound")
        return tuple(_load(row, model_type, json_column) for row in rows)

    def _latest(
        self,
        table: str,
        json_column: str,
        model_type: type[_ModelT],
        *,
        filter_column: str | None = None,
        filter_value: str | None = None,
    ) -> _ModelT:
        where = f"WHERE {filter_column} = ?" if filter_column is not None else ""
        parameters: tuple[object, ...] = (filter_value,) if filter_column is not None else ()
        with self._read() as connection:
            row = connection.execute(
                f"SELECT * FROM {table} {where} ORDER BY rowid DESC LIMIT 1",
                parameters,
            ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 calibration latest authority is absent")
        return _load(row, model_type, json_column)


__all__ = ["SQLiteM8CalibrationRepository"]
