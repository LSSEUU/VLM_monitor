"""Read the complete M6 regression source scope from one private SQLite snapshot."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.audit import validate_audit_chain
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m5_appeals import AppealVersionAuthority
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationInventoryCount,
    M5ArtifactValidationReport,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_regression_dataset import (
    M6RegressionRequiredSource,
    M6RegressionRunScopeObservation,
)

from ._m6_snapshot_identity import (
    capture_m6_readonly_snapshot_identity,
)
from .readonly_m5_artifacts import (
    M5ArtifactAuthoritySnapshot,
    M5ValidatedDocument,
    ReadonlyM5ArtifactRepository,
)
from .readonly_sqlite import ReadOnlySnapshotError
from .sqlite_repository import _audit_entry_from_row


@dataclass(frozen=True, slots=True)
class M6RegressionSourceScopeBudget:
    max_cases: int = 100_000
    max_audit_entries: int = 1_000_000
    max_document_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        for value, label in (
            (self.max_cases, "max_cases"),
            (self.max_audit_entries, "max_audit_entries"),
            (self.max_document_bytes, "max_document_bytes"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")


class M6RegressionSourceScopeReadErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_CHANGED = "SNAPSHOT_CHANGED"
    DATABASE_INVALID = "DATABASE_INVALID"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    RUN_NOT_FOUND = "RUN_NOT_FOUND"
    M5_AUTHORITY_INVALID = "M5_AUTHORITY_INVALID"
    M5_REPORT_INVALID = "M5_REPORT_INVALID"
    AUDIT_CHAIN_INVALID = "AUDIT_CHAIN_INVALID"
    CASE_INVENTORY_INVALID = "CASE_INVENTORY_INVALID"
    APPEAL_HISTORY_INVALID = "APPEAL_HISTORY_INVALID"
    SOURCE_SCOPE_EMPTY = "SOURCE_SCOPE_EMPTY"


class M6RegressionSourceScopeReadError(LabCourtError):
    """The authoritative regression source universe could not be observed."""

    def __init__(self, code: M6RegressionSourceScopeReadErrorCode) -> None:
        if not isinstance(code, M6RegressionSourceScopeReadErrorCode):
            raise TypeError("code must be an M6RegressionSourceScopeReadErrorCode")
        self.code = code
        super().__init__(f"M6 regression source scope read failed: {code.value}")


def _fail(code: M6RegressionSourceScopeReadErrorCode) -> NoReturn:
    raise M6RegressionSourceScopeReadError(code)


def _row_str(row: sqlite3.Row, key: str) -> str:
    value = row[key]
    if not isinstance(value, str):
        _fail(M6RegressionSourceScopeReadErrorCode.DATABASE_INVALID)
    return value


def _row_int(row: sqlite3.Row, key: str) -> int:
    value = row[key]
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(M6RegressionSourceScopeReadErrorCode.DATABASE_INVALID)
    return value


def _canonical_report(
    value: object,
    document: object,
) -> M5ArtifactValidationReport:
    if not isinstance(value, M5ArtifactValidationReport) or not isinstance(document, str):
        _fail(M6RegressionSourceScopeReadErrorCode.INVALID_ARGUMENT)
    try:
        report = M5ArtifactValidationReport.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6RegressionSourceScopeReadErrorCode.M5_REPORT_INVALID)
    if report != value or canonical_json(report.model_dump(mode="json")) != document:
        _fail(M6RegressionSourceScopeReadErrorCode.M5_REPORT_INVALID)
    return report


def _require_report_matches_snapshot(
    report: M5ArtifactValidationReport,
    snapshot: M5ArtifactAuthoritySnapshot,
) -> None:
    expected_inventories = tuple(
        M5ArtifactValidationInventoryCount(
            authority_kind=item.authority_kind,
            authoritative_count=item.count,
        )
        for item in snapshot.traversed
    )
    counts = report.counts
    if (
        not report.passed
        or snapshot.failures
        or report.run_id != snapshot.run_id
        or report.manifest_id != snapshot.manifest_id
        or report.config_sha256 != snapshot.config_sha256
        or report.authority_root_sha256 != snapshot.authority_root_sha256
        or counts.authority_rows != sum(item.count for item in snapshot.traversed)
        or counts.validated_authority_documents != len(snapshot.documents)
        or counts.authority_failures != 0
        or counts.case_roots != len(snapshot.case_roots)
        or counts.inventories != expected_inventories
    ):
        _fail(M6RegressionSourceScopeReadErrorCode.M5_REPORT_INVALID)


def _canonical_case(
    row: sqlite3.Row,
    *,
    run_id: str,
    case_id: str,
    max_document_bytes: int,
) -> Case:
    raw = _row_str(row, "case_json")
    if len(raw.encode("utf-8")) > max_document_bytes:
        _fail(M6RegressionSourceScopeReadErrorCode.BUDGET_EXCEEDED)
    try:
        case = Case.model_validate_json(raw)
    except (TypeError, ValueError, ValidationError):
        _fail(M6RegressionSourceScopeReadErrorCode.CASE_INVENTORY_INVALID)
    observed_sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if (
        canonical_json(case.model_dump(mode="json")) != raw
        or observed_sha256 != _row_str(row, "document_sha256")
        or case.run_id != run_id
        or case.case_id != case_id
        or case.status.value != _row_str(row, "case_status")
    ):
        _fail(M6RegressionSourceScopeReadErrorCode.CASE_INVENTORY_INVALID)
    return case


def _appeal_authorities(
    documents: tuple[M5ValidatedDocument, ...],
) -> tuple[AppealVersionAuthority, ...]:
    values: list[AppealVersionAuthority] = []
    for document in documents:
        if document.kind != M5AuthorityKind.APPEAL:
            continue
        try:
            authority = AppealVersionAuthority.model_validate_json(document.canonical_document)
        except (TypeError, ValueError, ValidationError):
            _fail(M6RegressionSourceScopeReadErrorCode.APPEAL_HISTORY_INVALID)
        if canonical_json(authority.model_dump(mode="json")) != document.canonical_document:
            _fail(M6RegressionSourceScopeReadErrorCode.APPEAL_HISTORY_INVALID)
        values.append(authority)
    return tuple(values)


class ReadonlyM6RegressionSourceScopeRepository:
    """Enumerate every executable historical source Case in one run."""

    __slots__ = ("_budget", "_config", "_snapshot")

    def __init__(
        self,
        snapshot: str | Path,
        *,
        config: AppConfig,
        budget: M6RegressionSourceScopeBudget | None = None,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be a fully resolved AppConfig")
        self._snapshot = Path(snapshot).absolute()
        self._config = AppConfig.model_validate(config.model_dump(mode="json"))
        self._budget = budget or M6RegressionSourceScopeBudget()

    def observe(
        self,
        run_id: str,
        *,
        m5_validation_report: object,
        m5_validation_report_document: object,
    ) -> M6RegressionRunScopeObservation:
        from labcourt.contracts.references import require_reference_token

        try:
            controlled_run_id = require_reference_token(run_id, "M6 source scope run_id")
        except (TypeError, ValueError):
            _fail(M6RegressionSourceScopeReadErrorCode.INVALID_ARGUMENT)
        report = _canonical_report(
            m5_validation_report,
            m5_validation_report_document,
        )
        try:
            before = capture_m6_readonly_snapshot_identity(self._snapshot)
            snapshot = ReadonlyM5ArtifactRepository(
                self._snapshot,
                config=self._config,
            ).scan(controlled_run_id)
            observation = self._read_scope(
                controlled_run_id,
                report,
                str(m5_validation_report_document),
                snapshot,
                before.identity_sha256,
            )
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except M6RegressionSourceScopeReadError:
            raise
        except ReadOnlySnapshotError as exc:
            raise M6RegressionSourceScopeReadError(
                M6RegressionSourceScopeReadErrorCode.DATABASE_INVALID
            ) from exc
        except (sqlite3.Error, OSError, TypeError, ValueError, ValidationError) as exc:
            raise M6RegressionSourceScopeReadError(
                M6RegressionSourceScopeReadErrorCode.DATABASE_INVALID
            ) from exc
        if after != before:
            _fail(M6RegressionSourceScopeReadErrorCode.SNAPSHOT_CHANGED)
        return observation

    def _read_scope(
        self,
        run_id: str,
        report: M5ArtifactValidationReport,
        report_document: str,
        snapshot: M5ArtifactAuthoritySnapshot,
        source_identity_sha256: str,
    ) -> M6RegressionRunScopeObservation:
        _require_report_matches_snapshot(report, snapshot)
        connection = sqlite3.connect(
            f"{self._snapshot.as_uri()}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            run_row = connection.execute(
                """
                SELECT manifest_id, audit_head_sequence, audit_head_hash
                FROM runs WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if run_row is None:
                _fail(M6RegressionSourceScopeReadErrorCode.RUN_NOT_FOUND)
            manifest_id = _row_str(run_row, "manifest_id")
            head_sequence = _row_int(run_row, "audit_head_sequence")
            head_hash = _row_str(run_row, "audit_head_hash")
            if manifest_id != snapshot.manifest_id:
                _fail(M6RegressionSourceScopeReadErrorCode.M5_AUTHORITY_INVALID)
            self._validate_audit(
                connection,
                run_id=run_id,
                manifest_id=manifest_id,
                head_sequence=head_sequence,
                head_hash=head_hash,
            )
            required_sources = self._required_sources(
                connection,
                run_id=run_id,
                manifest_id=manifest_id,
                snapshot=snapshot,
            )
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        if not required_sources:
            _fail(M6RegressionSourceScopeReadErrorCode.SOURCE_SCOPE_EMPTY)
        return M6RegressionRunScopeObservation(
            source_identity_sha256=source_identity_sha256,
            source_run_id=run_id,
            audit_head_sequence=head_sequence,
            audit_head_hash=head_hash,
            m5_validation_report=report,
            m5_validation_report_document=report_document,
            required_sources=required_sources,
        )

    def _validate_audit(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        manifest_id: str,
        head_sequence: int,
        head_hash: str,
    ) -> None:
        expected_count = head_sequence + 1
        if expected_count < 0 or expected_count > self._budget.max_audit_entries:
            _fail(M6RegressionSourceScopeReadErrorCode.BUDGET_EXCEEDED)
        rows = connection.execute(
            """
            SELECT * FROM audit_entries
            WHERE run_id = ? ORDER BY sequence LIMIT ?
            """,
            (run_id, expected_count + 1),
        ).fetchall()
        if len(rows) != expected_count:
            _fail(M6RegressionSourceScopeReadErrorCode.AUDIT_CHAIN_INVALID)
        entries = tuple(_audit_entry_from_row(row) for row in rows)
        chain = validate_audit_chain(
            entries,
            expected_run_id=run_id,
            expected_manifest_id=manifest_id,
            expected_head_sequence=head_sequence,
            expected_head_hash=head_hash,
        )
        if not chain.passed:
            _fail(M6RegressionSourceScopeReadErrorCode.AUDIT_CHAIN_INVALID)

    def _required_sources(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        manifest_id: str,
        snapshot: M5ArtifactAuthoritySnapshot,
    ) -> tuple[M6RegressionRequiredSource, ...]:
        if len(snapshot.case_roots) > self._budget.max_cases:
            _fail(M6RegressionSourceScopeReadErrorCode.BUDGET_EXCEEDED)
        rows = connection.execute(
            """
            SELECT c.case_id, c.current_revision, c.status AS indexed_status,
                   c.manifest_id AS indexed_manifest_id,
                   cv.status AS case_status, cv.case_json, cv.document_sha256
            FROM cases AS c
            JOIN case_versions AS cv
              ON cv.run_id = c.run_id
             AND cv.case_id = c.case_id
             AND cv.revision = c.current_revision
            WHERE c.run_id = ?
            ORDER BY c.case_id
            LIMIT ?
            """,
            (run_id, self._budget.max_cases + 1),
        ).fetchall()
        if len(rows) > self._budget.max_cases or len(rows) != len(snapshot.case_roots):
            _fail(M6RegressionSourceScopeReadErrorCode.CASE_INVENTORY_INVALID)
        roots = {item.case_id: item for item in snapshot.case_roots}
        if len(roots) != len(snapshot.case_roots):
            _fail(M6RegressionSourceScopeReadErrorCode.CASE_INVENTORY_INVALID)
        appeals = _appeal_authorities(snapshot.documents)
        required: list[M6RegressionRequiredSource] = []
        for row in rows:
            case_id = _row_str(row, "case_id")
            current = _canonical_case(
                row,
                run_id=run_id,
                case_id=case_id,
                max_document_bytes=self._budget.max_document_bytes,
            )
            current_revision = _row_int(row, "current_revision")
            root = roots.get(case_id)
            if (
                root is None
                or _row_str(row, "indexed_status") != current.status.value
                or _row_str(row, "indexed_manifest_id") != manifest_id
                or current.manifest_id != manifest_id
                or root.current_case_revision != current_revision
                or root.current_case_sha256 != _row_str(row, "document_sha256")
                or root.current_case_status != current.status.value
            ):
                _fail(M6RegressionSourceScopeReadErrorCode.CASE_INVENTORY_INVALID)
            if current.status == CaseStatus.CLOSED:
                if root.current_appeal_authority_sha256 is not None:
                    _fail(M6RegressionSourceScopeReadErrorCode.APPEAL_HISTORY_INVALID)
                required.append(
                    M6RegressionRequiredSource(
                        source_run_id=run_id,
                        source_case_id=case_id,
                        source_case_revision=current_revision,
                        source_case_document_sha256=_row_str(row, "document_sha256"),
                        source_manifest_id=manifest_id,
                    )
                )
                continue
            if current.status not in {CaseStatus.APPEALED, CaseStatus.APPEAL_RESOLVED}:
                continue
            matching = tuple(
                item
                for item in appeals
                if item.appeal.case_id == case_id
                and item.authority_sha256 == root.current_appeal_authority_sha256
            )
            if len(matching) != 1:
                _fail(M6RegressionSourceScopeReadErrorCode.APPEAL_HISTORY_INVALID)
            source = matching[0].source_case_authority
            historical_row = connection.execute(
                """
                SELECT status AS case_status, case_json, document_sha256
                FROM case_versions
                WHERE run_id = ? AND case_id = ? AND revision = ?
                """,
                (run_id, case_id, source.case_revision),
            ).fetchone()
            if historical_row is None:
                _fail(M6RegressionSourceScopeReadErrorCode.APPEAL_HISTORY_INVALID)
            historical = _canonical_case(
                historical_row,
                run_id=run_id,
                case_id=case_id,
                max_document_bytes=self._budget.max_document_bytes,
            )
            if (
                historical.status != CaseStatus.CLOSED
                or historical.manifest_id != manifest_id
                or historical.final_decision != source.final_decision
                or source.run_id != run_id
                or source.case_id != case_id
                or source.manifest_id != manifest_id
            ):
                _fail(M6RegressionSourceScopeReadErrorCode.APPEAL_HISTORY_INVALID)
            required.append(
                M6RegressionRequiredSource(
                    source_run_id=run_id,
                    source_case_id=case_id,
                    source_case_revision=source.case_revision,
                    source_case_document_sha256=_row_str(
                        historical_row,
                        "document_sha256",
                    ),
                    source_manifest_id=manifest_id,
                )
            )
        return tuple(sorted(required, key=lambda item: item.sort_key))


__all__ = [
    "M6RegressionSourceScopeBudget",
    "M6RegressionSourceScopeReadError",
    "M6RegressionSourceScopeReadErrorCode",
    "ReadonlyM6RegressionSourceScopeRepository",
]
