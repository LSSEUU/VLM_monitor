"""Read-only reconstruction of the immutable M5 SQLite authority graph."""

from __future__ import annotations

import hashlib
import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TypeVar

from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertPolicyAuthority,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationBudget,
    M5ArtifactValidationIssueCode,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m5_training import DatasetExportReport, TrainingCropAuthority
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.training import TrainingLabel

from ._readonly_m5_artifact_codec import (
    M5_AUTHORITY_DOCUMENT_COLUMNS,
    M5_TABLE_SPECS,
    M5DocumentFailure,
    M5IndexFailure,
    M5Record,
    load_m5_record,
)
from .readonly_sqlite import ReadOnlySnapshotError
from .sqlite_schema import M5_AUTHORITY_TABLES, m5_authority_installed

TransactionResultT = TypeVar("TransactionResultT")
MAX_M5_RUN_MANIFEST_BYTES = 16 * 1024 * 1024


class M5AuthorityFailureType(StrEnum):
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_MISMATCH = "INDEX_MISMATCH"
    REFERENCE_INVALID = "REFERENCE_INVALID"
    HEAD_INVALID = "HEAD_INVALID"


class M5DatasetRetentionFailureType(StrEnum):
    HOLD_MISSING = "HOLD_MISSING"
    HOLD_EXTRA = "HOLD_EXTRA"
    HOLD_RELEASED = "HOLD_RELEASED"
    HOLD_OWNER_MISMATCH = "HOLD_OWNER_MISMATCH"
    HOLD_DOCUMENT_MISMATCH = "HOLD_DOCUMENT_MISMATCH"
    AUDIT_LINK_INVALID = "AUDIT_LINK_INVALID"
    ORPHAN_APPEAL_HOLD = "ORPHAN_APPEAL_HOLD"
    ORPHAN_DATASET_HOLD = "ORPHAN_DATASET_HOLD"


@dataclass(frozen=True, slots=True)
class M5ArtifactAuthorityFailure:
    failure_type: M5AuthorityFailureType
    authority_kind: M5AuthorityKind
    record_identity_sha256: str
    artifact_id: str | None
    reason_code: str


@dataclass(frozen=True, slots=True)
class M5DatasetRetentionFailure:
    failure_type: M5DatasetRetentionFailureType
    hold_identity_sha256: str
    dataset_id: str | None
    reason_code: str


@dataclass(frozen=True, slots=True)
class M5TrainingCaseAuthority:
    case_id: str
    revision: int
    document_sha256: str
    case: Case


@dataclass(frozen=True, slots=True)
class M5DatasetHistoricalAuthority:
    """Immutable label and Crop authority cut used by one registered dataset."""

    dataset_id: str
    registration_snapshot_authority_id: str
    labels: tuple[TrainingLabel, ...]
    crop_authorities: tuple[TrainingCropAuthority, ...]


@dataclass(frozen=True, slots=True)
class M5AlertPolicyCooldownHistorySource:
    """One validated prior cooldown and the close that wrote it."""

    revision: int
    writer_close_audit_sequence: int
    writer_close_audit_entry_hash: str
    writer_alert_policy_authority_id: str
    authority: AlertCooldownAuthority
    authority_canonical_document: str


@dataclass(frozen=True, slots=True)
class M5AlertPolicyCooldownHistoryInventory:
    """One shared, revision-ordered cooldown history for a validated key."""

    key_id: str
    rows: tuple[M5AlertPolicyCooldownHistorySource, ...]


@dataclass(frozen=True, slots=True)
class M5AlertPolicyCausalSource:
    """A validated READY -> CLOSED policy cut into one shared history inventory."""

    source_case_revision: int
    source_case_document_sha256: str
    source_case: Case
    source_case_canonical_document: str
    closing_case_revision: int
    closing_case_document_sha256: str
    closing_case: Case
    closing_case_canonical_document: str
    alert_policy: AlertPolicyAuthority
    alert_policy_canonical_document: str
    closing_audit_entry: AuditEntry
    closing_audit_entry_canonical_document: str
    cooldown_history_key_id: str | None
    cooldown_eligible_history_count: int


@dataclass(frozen=True, slots=True)
class M5ValidatedDocument:
    kind: M5AuthorityKind
    artifact_id: str
    canonical_document: str

    @property
    def document_sha256(self) -> str:
        return hashlib.sha256(self.canonical_document.encode()).hexdigest()

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.kind.value, self.artifact_id)


@dataclass(frozen=True, slots=True)
class M5CaseAuthorityRoot:
    case_id: str
    current_case_revision: int
    current_case_sha256: str
    current_case_status: str
    alert_authority_id: str | None
    current_precedent_authority_ids: tuple[str, ...]
    current_appeal_authority_sha256: str | None
    resolution_intent_id: str | None
    root_sha256: str


@dataclass(frozen=True, slots=True)
class M5TraversedInventory:
    authority_kind: M5AuthorityKind
    count: int


@dataclass(frozen=True, slots=True)
class M5ArtifactAuthoritySnapshot:
    run_id: str
    manifest_id: str
    config_sha256: str
    traversed: tuple[M5TraversedInventory, ...]
    documents: tuple[M5ValidatedDocument, ...]
    case_roots: tuple[M5CaseAuthorityRoot, ...]
    failures: tuple[M5ArtifactAuthorityFailure, ...]
    training_labels: tuple[TrainingLabel, ...]
    dataset_reports: tuple[DatasetExportReport, ...]
    training_cases: tuple[M5TrainingCaseAuthority, ...]
    dataset_histories: tuple[M5DatasetHistoricalAuthority, ...]
    dataset_retention_failures: tuple[M5DatasetRetentionFailure, ...]
    dataset_retention_hold_count: int
    orphan_retention_hold_count: int
    retention_rows: int
    retention_bytes: int
    max_retention_record_bytes: int
    retention_root_sha256: str
    authority_bytes: int
    max_authority_record_bytes: int
    alert_policy_causal_sources: tuple[M5AlertPolicyCausalSource, ...] = ()
    alert_policy_cooldown_history_inventories: tuple[
        M5AlertPolicyCooldownHistoryInventory,
        ...,
    ] = ()

    @property
    def authority_root_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json(
                [
                    "m5-authority-snapshot",
                    3,
                    self.run_id,
                    self.manifest_id,
                    self.config_sha256,
                    self.retention_root_sha256,
                    [
                        [item.kind.value, item.artifact_id, item.document_sha256]
                        for item in self.documents
                    ],
                    [[root.case_id, root.root_sha256] for root in self.case_roots],
                ]
            ).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class M5ArtifactAuthorityPreflight:
    run_id: str
    manifest: RunManifest
    traversed: tuple[M5TraversedInventory, ...]
    authority_rows: int
    authority_bytes: int
    max_authority_record_bytes: int
    retention_rows: int
    retention_bytes: int
    max_retention_record_bytes: int
    retention_hold_rows: int
    retention_link_rows: int
    retention_audit_rows: int

    @property
    def manifest_id(self) -> str:
        return self.manifest.manifest_id

    @property
    def config_sha256(self) -> str:
        return self.manifest.config_sha256

    @property
    def has_authority(self) -> bool:
        return self.authority_rows > 0


@dataclass(frozen=True, slots=True)
class _RetentionPreflight:
    rows: int
    bytes: int
    max_record_bytes: int
    hold_rows: int
    link_rows: int
    audit_rows: int


class M5AuthorityBudgetExceeded(ReadOnlySnapshotError):
    """SQL preflight proved that authority cannot be safely materialized."""

    def __init__(
        self,
        preflight: M5ArtifactAuthorityPreflight,
        issue_codes: tuple[M5ArtifactValidationIssueCode, ...],
    ) -> None:
        self.preflight = preflight
        self.issue_codes = issue_codes
        super().__init__("M5_AUTHORITY_BUDGET_EXCEEDED")


class ReadonlyM5ArtifactRepository:
    """Validate every M5 row and the full reference graph from one snapshot."""

    __slots__ = ("_budget", "_config", "_immutable", "_snapshot")

    def __init__(
        self,
        snapshot: str | Path,
        *,
        config: AppConfig,
        budget: M5ArtifactValidationBudget | None = None,
        immutable: bool = False,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be a fully resolved AppConfig")
        if not isinstance(immutable, bool):
            raise TypeError("immutable must be a bool")
        self._snapshot = Path(snapshot).absolute()
        self._config = AppConfig.model_validate(config.model_dump(mode="json"))
        self._budget = budget or M5ArtifactValidationBudget()
        self._immutable = immutable

    def preflight(self, run_id: str) -> M5ArtifactAuthorityPreflight:
        controlled = require_reference_token(run_id, "M5 artifact preflight run_id")
        return self._read_transaction(
            lambda connection: self._preflight_connection(connection, controlled)
        )

    def has_authority(self, run_id: str) -> bool:
        """Detect every durable M5 root without decoding a document."""

        controlled = require_reference_token(run_id, "M5 authority applicability run_id")

        def detect(connection: sqlite3.Connection) -> bool:
            tables = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
                if isinstance(row[0], str)
            }
            for spec in M5_TABLE_SPECS:
                if spec.table not in tables:
                    continue
                if (
                    connection.execute(
                        f'SELECT 1 FROM "{spec.table}" WHERE run_id = ? LIMIT 1',
                        (controlled,),
                    ).fetchone()
                    is not None
                ):
                    return True
            if "retention_holds" not in tables:
                return False
            return (
                connection.execute(
                    """
                SELECT 1
                FROM retention_holds
                WHERE run_id = ? AND owner_kind IN ('APPEAL', 'DATASET')
                LIMIT 1
                """,
                    (controlled,),
                ).fetchone()
                is not None
            )

        return self._read_transaction(detect)

    def scan(self, run_id: str) -> M5ArtifactAuthoritySnapshot:
        controlled = require_reference_token(run_id, "M5 artifact scan run_id")
        return self._read_transaction(
            lambda connection: self._scan_connection(connection, controlled)
        )

    def _read_transaction(
        self,
        operation: Callable[[sqlite3.Connection], TransactionResultT],
    ) -> TransactionResultT:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{self._snapshot.as_uri()}?mode=ro{'&immutable=1' if self._immutable else ''}",
                uri=True,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            result = operation(connection)
            connection.commit()
            return result
        except ReadOnlySnapshotError:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise
        except (sqlite3.Error, IndexError, KeyError, TypeError, ValueError):
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID") from None
        finally:
            if connection is not None:
                connection.close()

    def _scan_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> M5ArtifactAuthoritySnapshot:
        from ._readonly_m5_artifact_relations import M5ArtifactReferenceValidator

        preflight = self._preflight_connection(connection, run_id)
        exceeded = self._budget_issue_codes(preflight)
        if exceeded:
            raise M5AuthorityBudgetExceeded(preflight, exceeded)
        manifest = preflight.manifest
        manifest_id = manifest.manifest_id
        failures: list[M5ArtifactAuthorityFailure] = []
        counts: Counter[M5AuthorityKind] = Counter()
        records: dict[M5AuthorityKind, list[M5Record]] = {kind: [] for kind in M5AuthorityKind}
        expected_counts = {item.authority_kind: item.count for item in preflight.traversed}
        streamed_rows = 0
        for spec in M5_TABLE_SPECS:
            expected_count = expected_counts[spec.kind]
            cursor = connection.execute(
                f'SELECT * FROM "{spec.table}" WHERE run_id = ? ORDER BY {spec.order_by} LIMIT ?',
                (run_id, expected_count + 1),
            )
            table_rows = 0
            for row in cursor:
                table_rows += 1
                streamed_rows += 1
                if (
                    table_rows > expected_count
                    or streamed_rows > self._budget.max_authority_records
                ):
                    raise ReadOnlySnapshotError("M5_AUTHORITY_CHANGED_AFTER_PREFLIGHT")
                raw_id = row[spec.id_column]
                artifact_id = raw_id if isinstance(raw_id, str) else None
                identity = _row_identity(spec.table, raw_id, row)
                try:
                    record = load_m5_record(row, spec, manifest_id)
                except M5DocumentFailure as error:
                    failures.append(
                        M5ArtifactAuthorityFailure(
                            M5AuthorityFailureType.DOCUMENT_INVALID,
                            spec.kind,
                            identity,
                            artifact_id,
                            error.reason_code,
                        )
                    )
                    continue
                except M5IndexFailure as error:
                    failures.append(
                        M5ArtifactAuthorityFailure(
                            M5AuthorityFailureType.INDEX_MISMATCH,
                            spec.kind,
                            identity,
                            artifact_id,
                            error.reason_code,
                        )
                    )
                    continue
                records[spec.kind].append(record)
            if table_rows != expected_count:
                raise ReadOnlySnapshotError("M5_AUTHORITY_CHANGED_AFTER_PREFLIGHT")
            counts[spec.kind] = table_rows

        relation = M5ArtifactReferenceValidator().validate(
            connection=connection,
            run_id=run_id,
            manifest=manifest,
            config=self._config,
            records=records,
            budget=self._budget,
            retention_hold_rows=preflight.retention_hold_rows,
            retention_link_rows=preflight.retention_link_rows,
            retention_audit_rows=preflight.retention_audit_rows,
        )
        failures.extend(relation.failures)
        documents = tuple(
            sorted(
                (
                    M5ValidatedDocument(record.kind, record.artifact_id, record.canonical_document)
                    for kind_records in records.values()
                    for record in kind_records
                ),
                key=lambda item: item.sort_key,
            )
        )
        return M5ArtifactAuthoritySnapshot(
            run_id=run_id,
            manifest_id=manifest_id,
            config_sha256=manifest.config_sha256,
            traversed=tuple(
                M5TraversedInventory(kind, counts[kind])
                for kind in sorted(M5AuthorityKind, key=lambda item: item.value)
            ),
            documents=documents,
            case_roots=relation.case_roots,
            failures=tuple(
                sorted(
                    set(failures),
                    key=lambda item: (
                        item.authority_kind.value,
                        item.record_identity_sha256,
                        item.failure_type.value,
                        item.reason_code,
                    ),
                )
            ),
            training_labels=relation.training_labels,
            dataset_reports=relation.dataset_reports,
            training_cases=relation.training_cases,
            dataset_histories=relation.dataset_histories,
            dataset_retention_failures=relation.dataset_retention_failures,
            dataset_retention_hold_count=relation.dataset_retention_hold_count,
            orphan_retention_hold_count=relation.orphan_retention_hold_count,
            retention_rows=preflight.retention_rows,
            retention_bytes=preflight.retention_bytes,
            max_retention_record_bytes=preflight.max_retention_record_bytes,
            retention_root_sha256=relation.retention_root_sha256,
            authority_bytes=preflight.authority_bytes,
            max_authority_record_bytes=preflight.max_authority_record_bytes,
            alert_policy_causal_sources=relation.alert_policy_causal_sources,
            alert_policy_cooldown_history_inventories=(
                relation.alert_policy_cooldown_history_inventories
            ),
        )

    def _preflight_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> M5ArtifactAuthorityPreflight:
        self._require_schema(connection, run_id)
        manifest = self._load_run_manifest(connection, run_id)
        counts: Counter[M5AuthorityKind] = Counter()
        total_bytes = 0
        maximum_bytes = 0
        for spec in M5_TABLE_SPECS:
            columns = M5_AUTHORITY_DOCUMENT_COLUMNS[spec.table]
            row_bytes = " + ".join(
                f'COALESCE(length(CAST("{column}" AS BLOB)), 0)' for column in columns
            )
            row = connection.execute(
                f"SELECT COUNT(*) AS row_count, "
                f"COALESCE(MAX({row_bytes}), 0) AS max_record_bytes, "
                f"COALESCE(SUM({row_bytes}), 0) AS total_bytes "
                f'FROM "{spec.table}" WHERE run_id = ?',
                (run_id,),
            ).fetchone()
            if row is None:
                raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
            count = _nonnegative_sql_integer(row["row_count"])
            table_maximum = _nonnegative_sql_integer(row["max_record_bytes"])
            table_total = _nonnegative_sql_integer(row["total_bytes"])
            counts[spec.kind] = count
            maximum_bytes = max(maximum_bytes, table_maximum)
            total_bytes += table_total
        traversed = tuple(
            M5TraversedInventory(kind, counts[kind])
            for kind in sorted(M5AuthorityKind, key=lambda item: item.value)
        )
        retention = _retention_preflight(connection, run_id)
        return M5ArtifactAuthorityPreflight(
            run_id=run_id,
            manifest=manifest,
            traversed=traversed,
            authority_rows=sum(item.count for item in traversed),
            authority_bytes=total_bytes,
            max_authority_record_bytes=maximum_bytes,
            retention_rows=retention.rows,
            retention_bytes=retention.bytes,
            max_retention_record_bytes=retention.max_record_bytes,
            retention_hold_rows=retention.hold_rows,
            retention_link_rows=retention.link_rows,
            retention_audit_rows=retention.audit_rows,
        )

    def _load_run_manifest(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> RunManifest:
        row = connection.execute(
            """
            SELECT
                r.manifest_id AS linked_manifest_id,
                m.manifest_id AS indexed_manifest_id,
                m.schema_version AS indexed_schema_version,
                m.document_sha256,
                length(CAST(m.document_json AS BLOB)) AS document_bytes
            FROM runs AS r
            LEFT JOIN run_manifests AS m ON m.manifest_id = r.manifest_id
            WHERE r.run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            raise ReadOnlySnapshotError("RUN_MISSING")
        values = tuple(
            row[key]
            for key in (
                "linked_manifest_id",
                "indexed_manifest_id",
                "indexed_schema_version",
                "document_sha256",
            )
        )
        if any(not isinstance(value, str) for value in values):
            raise ReadOnlySnapshotError("RUN_MANIFEST_INVALID")
        linked_manifest_id, indexed_manifest_id, indexed_schema, claimed_sha256 = values
        document_bytes = _nonnegative_sql_integer(row["document_bytes"])
        if document_bytes > MAX_M5_RUN_MANIFEST_BYTES:
            raise ReadOnlySnapshotError("RUN_MANIFEST_BYTES_BUDGET_EXCEEDED")
        document_row = connection.execute(
            "SELECT document_json FROM run_manifests WHERE manifest_id = ?",
            (indexed_manifest_id,),
        ).fetchone()
        if document_row is None or not isinstance(document_row["document_json"], str):
            raise ReadOnlySnapshotError("RUN_MANIFEST_INVALID")
        raw = str(document_row["document_json"])
        raw_bytes = raw.encode("utf-8")
        if len(raw_bytes) != document_bytes:
            raise ReadOnlySnapshotError("RUN_MANIFEST_CHANGED_AFTER_PREFLIGHT")
        if hashlib.sha256(raw_bytes).hexdigest() != claimed_sha256:
            raise ReadOnlySnapshotError("RUN_MANIFEST_HASH_MISMATCH")
        try:
            manifest = RunManifest.model_validate_json(raw)
        except ValueError:
            raise ReadOnlySnapshotError("RUN_MANIFEST_INVALID") from None
        if (
            canonical_json(manifest.model_dump(mode="json")) != raw
            or manifest.manifest_id != linked_manifest_id
            or manifest.manifest_id != indexed_manifest_id
            or manifest.schema_version != indexed_schema
        ):
            raise ReadOnlySnapshotError("RUN_MANIFEST_INDEX_MISMATCH")
        self._require_config_manifest_binding(manifest)
        return manifest

    def _require_config_manifest_binding(self, manifest: RunManifest) -> None:
        config = self._config
        checks = {
            "schema_version": manifest.schema_version == config.schema_version,
            "config_sha256": manifest.config_sha256 == config.config_sha256,
            "rule_version": manifest.rule_version == config.rule_version,
            "reproducibility_mode": (
                manifest.reproducibility_mode == config.run.reproducibility_mode
            ),
            "random_seed": manifest.random_seed == config.run.random_seed,
            "storage_boundary": manifest.storage_boundary == config.run.storage_boundary,
            "privacy_transform_version": (
                manifest.privacy_transform_version == config.evidence.privacy_transform_version
            ),
            "image_encoding_version": (
                manifest.image_encoding_version == config.evidence.encoding_version
            ),
        }
        detector = manifest.models["detector"]
        configured_detector = config.perception.detector_manifest
        checks["detector"] = (
            detector == configured_detector
            if configured_detector is not None
            else (
                detector.provider == config.perception.provider
                and detector.model == config.perception.detector.model_id
            )
        )
        role_profiles = {
            "screening": config.screening.provider_profile,
            "prosecutor": config.hearing.prosecutor_profile,
            "defender": config.hearing.defender_profile,
            "judge": config.hearing.judge_profile,
        }
        for component, profile_name in role_profiles.items():
            model = manifest.models[component]
            profile = config.providers[profile_name]
            checks[f"model.{component}"] = (
                model.provider,
                model.model,
                model.revision,
                model.quantization,
            ) == (
                profile.provider,
                profile.model,
                profile.revision,
                profile.quantization,
            )
        if not all(checks.values()):
            raise ReadOnlySnapshotError("CONFIG_MANIFEST_MISMATCH")

    def _budget_issue_codes(
        self,
        preflight: M5ArtifactAuthorityPreflight,
    ) -> tuple[M5ArtifactValidationIssueCode, ...]:
        codes: list[M5ArtifactValidationIssueCode] = []
        if preflight.authority_rows > self._budget.max_authority_records:
            codes.append(M5ArtifactValidationIssueCode.AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED)
        if preflight.max_authority_record_bytes > self._budget.max_authority_record_bytes:
            codes.append(M5ArtifactValidationIssueCode.AUTHORITY_RECORD_BYTES_BUDGET_EXCEEDED)
        if preflight.authority_bytes > self._budget.max_authority_total_bytes:
            codes.append(M5ArtifactValidationIssueCode.AUTHORITY_TOTAL_BYTES_BUDGET_EXCEEDED)
        if preflight.retention_rows > self._budget.max_retention_records:
            codes.append(M5ArtifactValidationIssueCode.RETENTION_RECORD_COUNT_BUDGET_EXCEEDED)
        if preflight.max_retention_record_bytes > self._budget.max_retention_record_bytes:
            codes.append(M5ArtifactValidationIssueCode.RETENTION_RECORD_BYTES_BUDGET_EXCEEDED)
        if preflight.retention_bytes > self._budget.max_retention_total_bytes:
            codes.append(M5ArtifactValidationIssueCode.RETENTION_TOTAL_BYTES_BUDGET_EXCEEDED)
        return tuple(codes)

    @staticmethod
    def _require_schema(connection: sqlite3.Connection, run_id: str) -> None:
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if len(integrity) != 1 or integrity[0][0] != "ok":
            raise ReadOnlySnapshotError("DATABASE_INTEGRITY_INVALID")
        foreign_key_violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if any(
            not _is_target_m5_authority_fk_violation(connection, row, run_id)
            for row in foreign_key_violations
        ):
            raise ReadOnlySnapshotError("DATABASE_FOREIGN_KEY_INVALID")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
            if isinstance(row[0], str)
        }
        if not M5_AUTHORITY_TABLES.issubset(tables) or not m5_authority_installed(connection):
            raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")


def _is_target_m5_authority_fk_violation(
    connection: sqlite3.Connection,
    violation: sqlite3.Row,
    run_id: str,
) -> bool:
    """Route only target-run M5 graph breaks to the typed relation validator."""

    child_table = violation[0]
    child_rowid = violation[1]
    parent_table = violation[2]
    if (
        not isinstance(child_table, str)
        or child_table not in M5_AUTHORITY_TABLES
        or not isinstance(parent_table, str)
        or parent_table not in M5_AUTHORITY_TABLES
        or not isinstance(child_rowid, int)
        or isinstance(child_rowid, bool)
    ):
        return False
    row = connection.execute(
        f'SELECT run_id FROM "{child_table}" WHERE rowid = ?',
        (child_rowid,),
    ).fetchone()
    return row is not None and row[0] == run_id


def _row_identity(table: str, artifact_id: object, row: sqlite3.Row) -> str:
    columns = frozenset(row.keys())
    revision = row["revision"] if "revision" in columns else None
    version = row["version"] if "version" in columns else None
    return hashlib.sha256(
        canonical_json(["m5-artifact-row", 1, table, artifact_id, revision, version]).encode()
    ).hexdigest()


def _retention_preflight(
    connection: sqlite3.Connection,
    run_id: str,
) -> _RetentionPreflight:
    hold_columns = (
        "run_id",
        "hold_id",
        "target_kind",
        "target_id",
        "hold_kind",
        "owner_kind",
        "owner_id",
        "active",
        "manifest_id",
        "policy_version",
        "reason_code",
        "hold_json",
        "document_sha256",
    )
    link_columns = (
        "run_id",
        "hold_id",
        "created_audit_sequence",
        "released_audit_sequence",
    )
    audit_columns = (
        "run_id",
        "sequence",
        "manifest_id",
        "actor",
        "action",
        "object_kind",
        "object_id",
        "before_sha256",
        "after_sha256",
        "recorded_at",
        "prev_entry_hash",
        "entry_hash",
        "entry_json",
        "document_sha256",
    )
    hold_summary = _sql_size_summary(
        connection,
        table_expression="retention_holds AS source",
        alias="source",
        columns=hold_columns,
        where_expression="source.run_id = ?",
        parameters=(run_id,),
    )
    link_summary = _sql_size_summary(
        connection,
        table_expression="retention_hold_audit_links AS source",
        alias="source",
        columns=link_columns,
        where_expression="source.run_id = ?",
        parameters=(run_id,),
    )
    audit_summary = _sql_size_summary(
        connection,
        table_expression=(
            "audit_entries AS source JOIN ("
            "SELECT run_id, created_audit_sequence AS sequence "
            "FROM retention_hold_audit_links WHERE run_id = ? "
            "UNION SELECT run_id, released_audit_sequence AS sequence "
            "FROM retention_hold_audit_links "
            "WHERE run_id = ? AND released_audit_sequence IS NOT NULL"
            ") AS linked ON linked.run_id = source.run_id "
            "AND linked.sequence = source.sequence"
        ),
        alias="source",
        columns=audit_columns,
        where_expression="source.run_id = ?",
        parameters=(run_id, run_id, run_id),
    )
    summaries = (hold_summary, link_summary, audit_summary)
    return _RetentionPreflight(
        rows=sum(item[0] for item in summaries),
        bytes=sum(item[2] for item in summaries),
        max_record_bytes=max(item[1] for item in summaries),
        hold_rows=hold_summary[0],
        link_rows=link_summary[0],
        audit_rows=audit_summary[0],
    )


def _sql_size_summary(
    connection: sqlite3.Connection,
    *,
    table_expression: str,
    alias: str,
    columns: tuple[str, ...],
    where_expression: str,
    parameters: tuple[object, ...],
) -> tuple[int, int, int]:
    row_bytes = " + ".join(
        f'COALESCE(length(CAST({alias}."{column}" AS BLOB)), 0)' for column in columns
    )
    row = connection.execute(
        f"SELECT COUNT(*) AS row_count, "
        f"COALESCE(MAX({row_bytes}), 0) AS max_record_bytes, "
        f"COALESCE(SUM({row_bytes}), 0) AS total_bytes "
        f"FROM {table_expression} WHERE {where_expression}",
        parameters,
    ).fetchone()
    if row is None:
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
    return (
        _nonnegative_sql_integer(row["row_count"]),
        _nonnegative_sql_integer(row["max_record_bytes"]),
        _nonnegative_sql_integer(row["total_bytes"]),
    )


def _nonnegative_sql_integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
    return value


__all__ = [
    "M5AlertPolicyCausalSource",
    "M5AlertPolicyCooldownHistoryInventory",
    "M5AlertPolicyCooldownHistorySource",
    "M5ArtifactAuthorityFailure",
    "M5ArtifactAuthorityPreflight",
    "M5ArtifactAuthoritySnapshot",
    "M5AuthorityBudgetExceeded",
    "M5AuthorityFailureType",
    "M5CaseAuthorityRoot",
    "M5DatasetHistoricalAuthority",
    "M5DatasetRetentionFailure",
    "M5DatasetRetentionFailureType",
    "M5TrainingCaseAuthority",
    "M5TraversedInventory",
    "M5ValidatedDocument",
    "ReadonlyM5ArtifactRepository",
]
