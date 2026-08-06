"""SQLite authority, immutable migrations, and transactional M2 evidence writes."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from pydantic import BaseModel, ValidationError

from labcourt.contracts.audit import (
    AUDIT_GENESIS_HASH,
    AuditEntry,
    AuditEntryDraft,
    validate_audit_chain,
)
from labcourt.contracts.backlog import BacklogItem, BacklogLeaseIdentity
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection, FrameBundle
from labcourt.contracts.enums import (
    AcquisitionExecutionMode,
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
    ClosureDefectCode,
    CropSource,
    EvidenceFailureCode,
    MediaAvailability,
    MediaType,
    PurgeDisposition,
    PurgeReasonCode,
    PurgeRecoveryKind,
    RetentionHoldKind,
    VerificationStatus,
)
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.evidence import Crop, EvidencePack, EvidencePackDraft
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    HearingBacklogRetryOutcome,
    HearingCheckpoint,
    HearingCycleScope,
    HearingHumanReviewReceipt,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingRecord,
    HearingReworkReceipt,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingUsageReceipt,
    HearingVerdictBinding,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import (
    parse_frame_id,
    require_portable_run_id,
    require_reference_token,
)
from labcourt.contracts.storage import (
    ArtifactRef,
    ArtifactVerification,
    ClosureDefect,
    ClosureReport,
    PurgeItemResult,
    RetentionHold,
)
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.evidence_authority import EvidenceAuthority
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
    CreationClosureFailed,
    EvidenceMissing,
    ManifestMismatch,
)
from labcourt.ports.evidence_repository import (
    AuditHead,
    CaseSnapshot,
    EvidenceVerifier,
    PublishResult,
)
from labcourt.ports.hearing_backlog import (
    HearingBacklogEnqueueCommit,
    HearingBacklogEnqueueIntent,
    HearingBacklogRetryAuthority,
    HearingBacklogRetryCommit,
    HearingModelCallFailureIntent,
)
from labcourt.ports.hearing_model_response_recovery import HearingModelCallRecoveryScan
from labcourt.ports.hearing_repository import (
    AcquisitionExecutionClaim,
    AcquisitionExecutionCommit,
    AcquisitionPublishResult,
    HearingBudgetUsage,
    HearingHumanReviewResult,
    HearingModelCallClaim,
    HearingReworkResult,
    HearingStartResult,
    HearingVerdictReviewResult,
)
from labcourt.ports.hearing_vlm import HearingRawModelResponseVerifier
from labcourt.ports.m6_source_authority_sealing import (
    M6CurrentPackObservation,
    M6GateSourceObservation,
)
from labcourt.ports.retention import PurgeLease, PurgeRecoveryCandidate

from ._sqlite_migration_contract_functions import (
    register_migration_contract_functions,
)
from ._sqlite_read_session import SQLiteReadSession
from .sqlite_authority import AuthorityFaultHook, SQLiteAuthorityError, SQLiteAuthorityGuard
from .sqlite_case_transitions import (
    case_transition_audit,
    evidence_failure_code,
    evidence_failure_timeline_entry,
)
from .sqlite_schema import m3_authority_hardening_installed, m4_hearing_authority_installed

if TYPE_CHECKING:
    from .sqlite_hearing_recovery import SQLiteHearingModelCallRecoveryRepository
    from .sqlite_hearing_repository import SQLiteHearingRepository

_MIGRATION_FILE = re.compile(r"^(?P<version>[0-9]{4})_(?P<name>[a-z0-9_]+)\.sql$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_MEDIA_STATE_SCHEMA_VERSION = "LCJ-MEDIA-STATE-1"
_SQL_KEYWORD = re.compile(r"[A-Za-z]+")
_FORBIDDEN_MIGRATION_KEYWORDS = frozenset(
    {
        "ATTACH",
        "BEGIN",
        "COMMIT",
        "DETACH",
        "END",
        "PRAGMA",
        "RELEASE",
        "ROLLBACK",
        "SAVEPOINT",
        "VACUUM",
    }
)
_BOOTSTRAP_SQL = """
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE,
    sql_sha256 TEXT NOT NULL
        CHECK (length(sql_sha256) = 64 AND sql_sha256 NOT GLOB '*[^0-9a-f]*'),
    applied_at TEXT NOT NULL
) STRICT
"""

Clock = Callable[[], datetime]
FaultInjector = Callable[[str], None]


class MigrationIntegrityError(ContractViolation):
    """The installed migration history is absent, modified, or malformed."""


class RepositoryIntegrityError(ContractViolation):
    """Persisted state or a content-addressed identity is internally inconsistent."""


class _UnavailableHearingRawResponseVerifier:
    """Fail closed when a general repository was not given filesystem authority."""

    __slots__ = ()

    def verify_raw_response(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelResponse:
        del run_id, request, response
        raise ContractViolation(
            "hearing response recovery completion requires a raw response verifier"
        )


_UNAVAILABLE_HEARING_RAW_RESPONSE_VERIFIER = _UnavailableHearingRawResponseVerifier()


@dataclass(frozen=True, slots=True)
class _Migration:
    version: int
    name: str
    sql: str
    sql_sha256: str


@dataclass(frozen=True, slots=True)
class _LoadedCase:
    snapshot: CaseSnapshot
    document_sha256: str
    audit_action: AuditAction


@dataclass(frozen=True, slots=True)
class _MediaState:
    run_id: str
    media_sha256: str
    manifest_id: str
    local_path: str | None
    availability: MediaAvailability
    pixel_sha256: str
    width: int
    height: int
    size_bytes: int
    media_type: MediaType
    encoding_version: str
    ttl_expires_at: str | None
    purged_at: str | None

    def document(self) -> tuple[str, str]:
        return _payload_document(
            {
                "schema_version": _MEDIA_STATE_SCHEMA_VERSION,
                "run_id": self.run_id,
                "media_sha256": self.media_sha256,
                "manifest_id": self.manifest_id,
                "local_path": self.local_path,
                "availability": self.availability.value,
                "pixel_sha256": self.pixel_sha256,
                "width": self.width,
                "height": self.height,
                "size_bytes": self.size_bytes,
                "media_type": self.media_type.value,
                "encoding_version": self.encoding_version,
                "ttl_expires_at": self.ttl_expires_at,
                "purged_at": self.purged_at,
            }
        )


@dataclass(frozen=True, slots=True)
class _PurgeAttempt:
    lease: PurgeLease
    manifest_id: str
    policy_version: str
    expires_before: str
    requested_at: str
    available_state_json: str
    available_state_sha256: str
    purging_state_json: str
    purging_state_sha256: str
    purged_state_json: str | None
    purged_state_sha256: str | None
    completion_audit_sequence: int | None
    completion_recovered: bool | None
    cleanup_acked_at: str | None
    status: str


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _canonical_utc_timestamp(value: datetime, name: str) -> str:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC).strftime(_UTC_TIMESTAMP_FORMAT)


def _parse_utc_timestamp(value: str, name: str) -> datetime:
    if not isinstance(value, str):
        raise RepositoryIntegrityError(f"{name} must contain text")
    try:
        parsed = datetime.strptime(value, _UTC_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        raise RepositoryIntegrityError(f"{name} is not a canonical UTC timestamp") from None
    if parsed.strftime(_UTC_TIMESTAMP_FORMAT) != value:
        raise RepositoryIntegrityError(f"{name} is not a canonical UTC timestamp")
    return parsed


def _utc_timestamp(clock: Clock) -> str:
    try:
        return _canonical_utc_timestamp(clock(), "repository clock")
    except (TypeError, ValueError) as exc:
        raise ContractViolation("repository clock must return a timezone-aware datetime") from exc


def _validate_busy_timeout(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= 60_000:
        raise ValueError("busy_timeout_ms must be an integer in [1, 60000]")
    return value


def _is_sqlite_concurrency_error(error: sqlite3.OperationalError) -> bool:
    error_code = getattr(error, "sqlite_errorcode", None)
    if isinstance(error_code, int) and error_code & 0xFF in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }:
        return True
    message = str(error).lower()
    return "database is locked" in message or "database table is locked" in message


class _AuthorityConnection(sqlite3.Connection):
    """A SQLite connection that owns its filesystem authority guard until close."""

    _authority_guard: SQLiteAuthorityGuard | None = None

    def bind_authority_guard(self, guard: SQLiteAuthorityGuard) -> None:
        if self._authority_guard is not None:
            raise RuntimeError("SQLite authority guard is already bound")
        self._authority_guard = guard

    def close(self) -> None:
        guard = self._authority_guard
        self._authority_guard = None
        failure: BaseException | None = None
        if guard is not None:
            try:
                guard.checkpoint("sqlite_authority.before_sqlite_close")
            except BaseException as error:
                failure = error
        try:
            super().close()
        except BaseException as error:
            if failure is None:
                failure = error
        finally:
            if guard is not None:
                try:
                    guard.close()
                except BaseException as error:
                    if failure is None:
                        failure = error
        if failure is not None:
            raise failure


def _open_connection(
    database_path: Path,
    busy_timeout_ms: int,
    *,
    allow_create: bool,
    authority_fault_hook: AuthorityFaultHook | None = None,
) -> sqlite3.Connection:
    guard = SQLiteAuthorityGuard(
        database_path,
        allow_create=allow_create,
        fault_hook=authority_fault_hook,
    )
    guard.__enter__()
    connection: _AuthorityConnection | None = None
    try:
        guard.checkpoint("sqlite_authority.before_sqlite_open")
        try:
            connection = sqlite3.connect(
                f"{guard.database_path.as_uri()}?mode=rw",
                uri=True,
                timeout=busy_timeout_ms / 1000,
                isolation_level=None,
                factory=_AuthorityConnection,
            )
        except sqlite3.Error:
            raise SQLiteAuthorityError("DATABASE_SQLITE_OPEN_FAILED") from None
        connection.bind_authority_guard(guard)
    except BaseException:
        if connection is not None:
            connection.close()
        else:
            guard.close()
        raise
    connection.row_factory = sqlite3.Row
    try:
        connection.enable_load_extension(False)
        connection.execute("PRAGMA foreign_keys = ON")
        journal_mode = cast(str, connection.execute("PRAGMA journal_mode = WAL").fetchone()[0])
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA recursive_triggers = ON")
        observed = {
            "foreign_keys": cast(int, connection.execute("PRAGMA foreign_keys").fetchone()[0]),
            "journal_mode": journal_mode.lower(),
            "synchronous": cast(int, connection.execute("PRAGMA synchronous").fetchone()[0]),
            "busy_timeout": cast(int, connection.execute("PRAGMA busy_timeout").fetchone()[0]),
            "trusted_schema": cast(
                int,
                connection.execute("PRAGMA trusted_schema").fetchone()[0],
            ),
            "recursive_triggers": cast(
                int,
                connection.execute("PRAGMA recursive_triggers").fetchone()[0],
            ),
        }
        expected = {
            "foreign_keys": 1,
            "journal_mode": "wal",
            "synchronous": 2,
            "busy_timeout": busy_timeout_ms,
            "trusted_schema": 0,
            "recursive_triggers": 1,
        }
        if observed != expected:
            raise RepositoryIntegrityError(
                f"SQLite connection PRAGMA verification failed: {observed!r}"
            )
        guard.checkpoint("sqlite_authority.after_sqlite_open")
    except BaseException:
        connection.close()
        raise
    return connection


def _iter_sql_statements(script: str) -> Iterator[str]:
    pending: list[str] = []
    for line in script.splitlines(keepends=True):
        pending.append(line)
        candidate = "".join(pending)
        if sqlite3.complete_statement(candidate):
            statement = candidate.strip()
            if statement:
                yield statement
            pending.clear()
    trailing = "".join(pending)
    if trailing.strip() and _leading_sql_body(trailing):
        raise MigrationIntegrityError("migration ends with an incomplete SQL statement")


def _leading_sql_body(statement: str) -> str:
    remainder = statement.lstrip()
    while remainder.startswith(("--", "/*")):
        if remainder.startswith("--"):
            newline = remainder.find("\n")
            if newline < 0:
                return ""
            remainder = remainder[newline + 1 :].lstrip()
            continue
        comment_end = remainder.find("*/", 2)
        if comment_end < 0:
            raise MigrationIntegrityError("migration contains an unterminated SQL comment")
        remainder = remainder[comment_end + 2 :].lstrip()
    return remainder


def _leading_sql_keyword(statement: str) -> str:
    """Return a statement's top-level keyword after leading SQL comments."""

    remainder = _leading_sql_body(statement)
    match = _SQL_KEYWORD.match(remainder)
    if match is None:
        raise MigrationIntegrityError("migration statement has no SQL keyword")
    return match.group(0).upper()


def _validated_migration_statements(script: str, filename: str) -> tuple[str, ...]:
    statements = tuple(_iter_sql_statements(script))
    if not statements:
        raise MigrationIntegrityError(f"migration contains no SQL statements: {filename}")
    for statement in statements:
        keyword = _leading_sql_keyword(statement)
        if keyword in _FORBIDDEN_MIGRATION_KEYWORDS:
            raise MigrationIntegrityError(
                f"migration {filename} contains forbidden top-level {keyword} statement"
            )
    return statements


def _document(model: BaseModel) -> tuple[str, str]:
    document = canonical_json(model.model_dump(mode="json"))
    digest = hashlib.sha256(document.encode("utf-8")).hexdigest()
    return document, digest


def _contract_document(model: BaseModel) -> str:
    """Canonical JSON including computed contract identities."""

    return canonical_json(model.model_dump(mode="json"))


def _verify_contract_document(raw: str, model: BaseModel) -> None:
    if raw != _contract_document(model):
        raise RepositoryIntegrityError("stored JSON is not the canonical contract document")


def _payload_document(payload: object) -> tuple[str, str]:
    document = canonical_json(payload)
    return document, hashlib.sha256(document.encode("utf-8")).hexdigest()


def _artifact_refs_document(refs: tuple[ArtifactRef, ...]) -> tuple[str, str]:
    return _payload_document([ref.model_dump(mode="json") for ref in refs])


def _retention_hold_state_document(hold: RetentionHold, *, active: bool) -> tuple[str, str]:
    payload = hold.model_dump(mode="json")
    payload["active"] = active
    return _payload_document(payload)


def _stable_unique_defects(defects: Iterable[ClosureDefect]) -> tuple[ClosureDefect, ...]:
    by_key = {defect.sort_key: defect for defect in defects}
    return tuple(by_key[key] for key in sorted(by_key))


def _verify_document(raw: str, expected_sha256: str, model: BaseModel) -> None:
    canonical, actual_sha256 = _document(model)
    if raw != canonical:
        raise RepositoryIntegrityError("stored JSON is not the canonical contract document")
    if actual_sha256 != expected_sha256:
        raise RepositoryIntegrityError("stored JSON document hash does not match its bytes")


def _row_str(row: sqlite3.Row, key: str) -> str:
    value = row[key]
    if not isinstance(value, str):
        raise RepositoryIntegrityError(f"database column {key} must contain text")
    return value


def _row_int(row: sqlite3.Row, key: str) -> int:
    value = row[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise RepositoryIntegrityError(f"database column {key} must contain an integer")
    return value


def _row_optional_str(row: sqlite3.Row, key: str) -> str | None:
    value = row[key]
    if value is not None and not isinstance(value, str):
        raise RepositoryIntegrityError(f"database column {key} must contain text or null")
    return value


def _row_optional_int(row: sqlite3.Row, key: str) -> int | None:
    value = row[key]
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
        raise RepositoryIntegrityError(f"database column {key} must contain an integer or null")
    return value


def _unchecked_audit_entry_from_row(row: sqlite3.Row) -> AuditEntry:
    raw = _row_str(row, "entry_json")
    entry = AuditEntry.model_validate_json(raw)
    _verify_document(raw, _row_str(row, "document_sha256"), entry)
    indexed = (
        _row_str(row, "run_id"),
        _row_int(row, "sequence"),
        _row_str(row, "manifest_id"),
        _row_str(row, "actor"),
        _row_str(row, "action"),
        _row_str(row, "object_kind"),
        _row_str(row, "object_id"),
        _row_optional_str(row, "before_sha256"),
        _row_optional_str(row, "after_sha256"),
        _row_str(row, "recorded_at"),
        _row_str(row, "prev_entry_hash"),
        _row_str(row, "entry_hash"),
    )
    expected = (
        entry.run_id,
        entry.sequence,
        entry.manifest_id,
        entry.actor,
        entry.action.value,
        entry.object_ref.kind.value,
        entry.object_ref.artifact_id,
        entry.before_sha256,
        entry.after_sha256,
        entry.recorded_at,
        entry.prev_entry_hash,
        entry.entry_hash,
    )
    if indexed != expected:
        raise RepositoryIntegrityError("audit index columns do not match the stored entry")
    return entry


def _audit_entry_from_row(row: sqlite3.Row) -> AuditEntry:
    sequence_label = "unknown"
    try:
        sequence_label = str(_row_int(row, "sequence"))
        return _unchecked_audit_entry_from_row(row)
    except (RepositoryIntegrityError, ValidationError) as exc:
        raise RepositoryIntegrityError(
            f"audit entry at sequence {sequence_label} failed stored-document validation"
        ) from exc


def _case_version_from_row(
    row: sqlite3.Row,
    *,
    run_id: str,
    case_id: str,
    json_key: str,
    sha256_key: str,
    status_key: str,
) -> tuple[Case, str]:
    raw = _row_str(row, json_key)
    case = Case.model_validate_json(raw)
    document_sha256 = _row_str(row, sha256_key)
    _verify_document(raw, document_sha256, case)
    if (
        case.run_id != run_id
        or case.case_id != case_id
        or case.status.value != _row_str(row, status_key)
    ):
        raise RepositoryIntegrityError(
            "case version index columns do not match its canonical document"
        )
    return case, document_sha256


class MigrationRunner:
    """Apply ordered immutable SQL files and verify every previously applied checksum."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        migrations_path: str | Path | None = None,
        clock: Clock | None = None,
        *,
        authority_fault_hook: AuthorityFaultHook | None = None,
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        self._migrations_path = (
            Path(migrations_path)
            if migrations_path is not None
            else Path(__file__).with_name("migrations")
        )
        self._clock = clock or _default_clock
        self._authority_fault_hook = authority_fault_hook

    def apply_all(self) -> tuple[int, ...]:
        migrations = self._load_migrations()
        connection = _open_connection(
            self._database_path,
            self._busy_timeout_ms,
            allow_create=True,
            authority_fault_hook=self._authority_fault_hook,
        )
        try:
            register_migration_contract_functions(connection)
            self._bootstrap(connection)
            applied_rows = connection.execute(
                "SELECT version, name, sql_sha256 FROM schema_migrations ORDER BY version"
            ).fetchall()
            by_version = {migration.version: migration for migration in migrations}
            for row in applied_rows:
                version = _row_int(row, "version")
                installed = by_version.get(version)
                if installed is None:
                    raise MigrationIntegrityError(
                        f"applied migration {version:04d} is missing from the repository"
                    )
                if (
                    _row_str(row, "name") != installed.name
                    or _row_str(row, "sql_sha256") != installed.sql_sha256
                ):
                    raise MigrationIntegrityError(
                        f"applied migration {version:04d}_{installed.name}.sql changed checksum"
                    )

            applied_versions = {_row_int(row, "version") for row in applied_rows}
            pending_statements = {
                migration.version: _validated_migration_statements(
                    migration.sql,
                    f"{migration.version:04d}_{migration.name}.sql",
                )
                for migration in migrations
                if migration.version not in applied_versions
            }
            newly_applied: list[int] = []
            for migration in migrations:
                if migration.version in applied_versions:
                    continue
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    concurrent = connection.execute(
                        """
                        SELECT name, sql_sha256 FROM schema_migrations
                        WHERE version = ?
                        """,
                        (migration.version,),
                    ).fetchone()
                    if concurrent is not None:
                        if (
                            _row_str(concurrent, "name") != migration.name
                            or _row_str(concurrent, "sql_sha256") != migration.sql_sha256
                        ):
                            raise MigrationIntegrityError(
                                f"applied migration {migration.version:04d}_"
                                f"{migration.name}.sql changed checksum"
                            )
                        connection.commit()
                        continue
                    for statement in pending_statements[migration.version]:
                        connection.execute(statement)
                    connection.execute(
                        """
                        INSERT INTO schema_migrations(version, name, sql_sha256, applied_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            migration.version,
                            migration.name,
                            migration.sql_sha256,
                            _utc_timestamp(self._clock),
                        ),
                    )
                    connection.commit()
                except BaseException as exc:
                    if connection.in_transaction:
                        connection.rollback()
                    if isinstance(exc, sqlite3.DatabaseError):
                        raise MigrationIntegrityError(
                            f"migration {migration.version:04d}_{migration.name}.sql failed"
                        ) from exc
                    raise
                newly_applied.append(migration.version)
            return tuple(newly_applied)
        finally:
            connection.close()

    def _bootstrap(self, connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")
        try:
            existing = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                ("schema_migrations",),
            ).fetchone()
            if existing is None:
                connection.execute(_BOOTSTRAP_SQL)
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise

    def _load_migrations(self) -> tuple[_Migration, ...]:
        if not self._migrations_path.is_dir():
            raise MigrationIntegrityError(
                f"migration directory does not exist: {self._migrations_path}"
            )
        migrations: list[_Migration] = []
        for path in sorted(self._migrations_path.glob("*.sql")):
            match = _MIGRATION_FILE.fullmatch(path.name)
            if match is None:
                raise MigrationIntegrityError(f"invalid migration filename: {path.name}")
            raw = path.read_bytes()
            try:
                sql = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise MigrationIntegrityError(
                    f"migration is not valid UTF-8: {path.name}"
                ) from None
            migrations.append(
                _Migration(
                    version=int(match.group("version")),
                    name=match.group("name"),
                    sql=sql,
                    sql_sha256=hashlib.sha256(raw).hexdigest(),
                )
            )
        if not migrations:
            raise MigrationIntegrityError("no SQL migrations were found")
        versions = tuple(migration.version for migration in migrations)
        if versions != tuple(range(1, len(versions) + 1)):
            raise MigrationIntegrityError("migration versions must be contiguous and start at 0001")
        names = tuple(migration.name for migration in migrations)
        if len(names) != len(set(names)):
            raise MigrationIntegrityError("migration names must be unique")
        return tuple(migrations)


class SQLiteEvidenceRepository:
    """Multi-run SQLite authority using one immediate transaction per state change."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        verifier: EvidenceVerifier | None = None,
        clock: Clock | None = None,
        fault_injector: FaultInjector | None = None,
        *,
        hearing_raw_response_verifier: HearingRawModelResponseVerifier | None = None,
    ) -> None:
        if hearing_raw_response_verifier is not None and not callable(
            getattr(hearing_raw_response_verifier, "verify_raw_response", None)
        ):
            raise TypeError("hearing_raw_response_verifier must implement verify_raw_response")
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        self._verifier = verifier
        self._clock = clock or _default_clock
        self._fault_injector = fault_injector
        self._hearing_raw_response_verifier = hearing_raw_response_verifier

    def register_run(self, run_id: str, manifest: RunManifest) -> None:
        require_reference_token(run_id, "repository run_id")
        try:
            require_portable_run_id(run_id, "repository run_id")
        except ValueError as exc:
            raise ContractViolation(
                "repository run_id is not a portable filesystem identity"
            ) from exc
        validated = RunManifest.model_validate(manifest.model_dump(mode="json"))
        manifest_json, manifest_sha256 = _document(validated)
        recorded_at = _utc_timestamp(self._clock)
        with self._immediate() as connection:
            existing_manifest = connection.execute(
                """
                SELECT document_json, document_sha256
                FROM run_manifests WHERE manifest_id = ?
                """,
                (validated.manifest_id,),
            ).fetchone()
            if existing_manifest is None:
                connection.execute(
                    """
                    INSERT INTO run_manifests(
                        manifest_id, schema_version, document_json,
                        document_sha256, registered_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        validated.manifest_id,
                        validated.schema_version,
                        manifest_json,
                        manifest_sha256,
                        recorded_at,
                    ),
                )
            elif (
                _row_str(existing_manifest, "document_json") != manifest_json
                or _row_str(existing_manifest, "document_sha256") != manifest_sha256
            ):
                raise RepositoryIntegrityError(
                    "manifest_id already exists with different canonical content"
                )
            self._fault("register_run.after_manifest")

            existing_run = connection.execute(
                """
                SELECT run_id, manifest_id
                FROM runs
                WHERE run_id = ? COLLATE NOCASE
                """,
                (run_id,),
            ).fetchone()
            if existing_run is not None:
                if _row_str(existing_run, "run_id") != run_id:
                    raise ContractViolation(
                        "repository run_id conflicts with an existing filesystem identity"
                    )
                if _row_str(existing_run, "manifest_id") != validated.manifest_id:
                    raise ManifestMismatch("run_id is already bound to another manifest")
                return
            connection.execute(
                """
                INSERT INTO runs(
                    run_id, manifest_id, revision,
                    audit_head_sequence, audit_head_hash, registered_at
                ) VALUES (?, ?, 0, -1, ?, ?)
                """,
                (run_id, validated.manifest_id, AUDIT_GENESIS_HASH, recorded_at),
            )
            self._fault("register_run.after_run")
            self._fault("register_run.before_commit")

    def register_frame(self, run_id: str, frame: FrameRef) -> None:
        require_reference_token(run_id, "repository run_id")
        validated = FrameRef.model_validate(frame.model_dump(mode="json"))
        if validated.content_sha256 is None:
            raise ContractViolation("persisted frames require decoded RGB8 content_sha256")
        frame_json, frame_sha256 = _document(validated)
        with self._immediate() as connection:
            manifest = self._load_run_manifest(connection, run_id)
            stream = next(
                (
                    item
                    for item in manifest.streams
                    if (item.camera_id, item.stream_id)
                    == (validated.camera_id, validated.stream_id)
                ),
                None,
            )
            if manifest.streams and stream is None:
                raise ManifestMismatch("frame stream is absent from the run manifest")
            if stream is not None and (
                validated.fps_num != stream.fps_num
                or validated.fps_den != stream.fps_den
                or validated.width != stream.width
                or validated.height != stream.height
                or validated.frame_index >= stream.frame_count
            ):
                raise ManifestMismatch("frame metadata does not match the pinned stream manifest")
            existing = connection.execute(
                """
                SELECT document_json, document_sha256
                FROM frames WHERE run_id = ? AND frame_id = ?
                """,
                (run_id, validated.frame_id),
            ).fetchone()
            if existing is not None:
                if (
                    _row_str(existing, "document_json") != frame_json
                    or _row_str(existing, "document_sha256") != frame_sha256
                ):
                    raise RepositoryIntegrityError(
                        "frame_id already exists with different canonical content"
                    )
                return
            connection.execute(
                """
                INSERT INTO frames(
                    run_id, frame_id, manifest_id, camera_id, stream_id,
                    frame_index, fps_num, fps_den, width, height,
                    content_sha256, document_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    validated.frame_id,
                    manifest.manifest_id,
                    validated.camera_id,
                    validated.stream_id,
                    validated.frame_index,
                    validated.fps_num,
                    validated.fps_den,
                    validated.width,
                    validated.height,
                    validated.content_sha256,
                    frame_json,
                    frame_sha256,
                ),
            )
            self._fault("register_frame.after_frame")
            self._fault("register_frame.before_commit")

    def register_detection(self, run_id: str, detection: Detection) -> None:
        require_reference_token(run_id, "repository run_id")
        validated = Detection.model_validate(detection.model_dump(mode="json"))
        try:
            ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id=validated.detection_id)
        except ValidationError as exc:
            raise ContractViolation(
                "persisted detection_id must be an anonymous reference token"
            ) from exc
        detection_json, detection_sha256 = _document(validated)
        with self._immediate() as connection:
            manifest = self._load_run_manifest(connection, run_id)
            detector_manifest_id = manifest.models["detector"].model_manifest_id
            if validated.model_manifest_id != detector_manifest_id:
                raise ManifestMismatch(
                    "detection model_manifest_id does not match the run detector manifest"
                )
            frame = self._load_frame(connection, run_id, validated.frame_id)
            if frame is None:
                raise EvidenceMissing(
                    f"detection frame is not registered in run {run_id}: {validated.frame_id}"
                )
            try:
                FrameBundle(frame=frame, detections=(validated,))
            except ValidationError as exc:
                raise ContractViolation(
                    "detection geometry or track binding is invalid for its frame"
                ) from exc
            existing = self._load_detection(
                connection,
                run_id,
                validated.detection_id,
            )
            if existing is not None:
                if existing != validated:
                    raise RepositoryIntegrityError(
                        "detection_id already exists with different canonical content"
                    )
                return
            connection.execute(
                """
                INSERT INTO detections(
                    run_id, detection_id, frame_id, manifest_id,
                    detector_manifest_id, label,
                    document_json, document_sha256, registered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    validated.detection_id,
                    validated.frame_id,
                    manifest.manifest_id,
                    validated.model_manifest_id,
                    validated.label,
                    detection_json,
                    detection_sha256,
                    _utc_timestamp(self._clock),
                ),
            )
            self._fault("register_detection.after_detection")
            self._fault("register_detection.before_commit")

    def create_or_get_case(self, run_id: str, event: CandidateEvent) -> CaseSnapshot:
        require_reference_token(run_id, "repository run_id")
        validated_event = CandidateEvent.model_validate(event.model_dump(mode="json"))
        event_json, event_sha256 = _document(validated_event)
        with self._immediate() as connection:
            head = self._validated_head(connection, run_id)
            if validated_event.manifest_id != head.manifest_id:
                raise ManifestMismatch("event does not use the run manifest")
            manifest = self._load_run_manifest(connection, run_id)
            if validated_event.rule_version != manifest.rule_version:
                raise ManifestMismatch("event rule_version does not match the run manifest")
            existing = connection.execute(
                """
                SELECT case_id, event_json, event_sha256
                FROM cases WHERE run_id = ? AND event_id = ?
                """,
                (run_id, validated_event.event_id),
            ).fetchone()
            if existing is not None:
                if (
                    _row_str(existing, "event_json") != event_json
                    or _row_str(existing, "event_sha256") != event_sha256
                ):
                    raise RepositoryIntegrityError(
                        "event_id already exists with different canonical content"
                    )
                return self._load_case(connection, run_id, _row_str(existing, "case_id")).snapshot

            case = Case(
                run_id=run_id,
                status=CaseStatus.CANDIDATE,
                event=validated_event,
                manifest_id=head.manifest_id,
            )
            case_json, case_sha256 = _document(case)
            sequence = head.sequence + 1
            connection.execute(
                """
                INSERT INTO cases(
                    run_id, case_id, event_id, manifest_id, status,
                    current_revision, latest_pack_id, latest_pack_version,
                    event_json, event_sha256, created_audit_sequence
                ) VALUES (?, ?, ?, ?, ?, 1, NULL, NULL, ?, ?, ?)
                """,
                (
                    run_id,
                    case.case_id,
                    validated_event.event_id,
                    head.manifest_id,
                    case.status.value,
                    event_json,
                    event_sha256,
                    sequence,
                ),
            )
            self._fault("create_case.after_case")
            audit, _ = self._append_audit(
                connection,
                head,
                action=AuditAction.CASE_CREATED,
                object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case.case_id),
                before_sha256=None,
                after_sha256=case_sha256,
            )
            self._fault("create_case.after_audit")
            connection.execute(
                """
                INSERT INTO case_versions(
                    run_id, case_id, revision, status,
                    case_json, document_sha256, audit_sequence
                ) VALUES (?, ?, 1, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    case.case_id,
                    case.status.value,
                    case_json,
                    case_sha256,
                    audit.sequence,
                ),
            )
            self._fault("create_case.after_case_version")
            self._fault("create_case.before_commit")
            return CaseSnapshot(case=case, revision=1)

    def publish_pack(
        self,
        run_id: str,
        expected_revision: int,
        pack: EvidencePackDraft,
    ) -> PublishResult:
        require_reference_token(run_id, "repository run_id")
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision must be a positive integer")
        incoming_payload = pack.model_dump(mode="json", exclude_computed_fields=True)
        incoming_payload.pop("closure_report", None)
        draft = EvidencePackDraft.model_validate(incoming_payload)
        if draft.run_id != run_id:
            raise ContractViolation("evidence pack belongs to another run")

        with self._immediate() as connection:
            loaded = self._load_case(connection, run_id, draft.case_id)
            if draft.event != loaded.snapshot.case.event:
                raise ContractViolation("evidence pack event does not match the persisted case")
            existing = connection.execute(
                """
                SELECT pack_id FROM evidence_packs
                WHERE run_id = ? AND case_id = ? AND pack_input_sha256 = ?
                """,
                (run_id, draft.case_id, draft.pack_input_sha256),
            ).fetchone()
            if existing is not None:
                stored_pack = self._load_pack(
                    connection,
                    run_id,
                    _row_str(existing, "pack_id"),
                )
                if (
                    stored_pack.pack_input_sha256 != draft.pack_input_sha256
                    or stored_pack.pack_id != draft.pack_id
                ):
                    raise RepositoryIntegrityError(
                        "idempotency index does not match the requested pack identity"
                    )
                current = self._load_case(connection, run_id, draft.case_id).snapshot
                return PublishResult(case=current, pack=stored_pack, created=False)

            if loaded.snapshot.revision != expected_revision:
                raise ConcurrentModification(
                    f"case revision is {loaded.snapshot.revision}, expected {expected_revision}"
                )
            next_pack_version = cast(
                int,
                connection.execute(
                    """
                    SELECT COALESCE(MAX(version), 0) + 1
                    FROM evidence_packs WHERE run_id = ? AND case_id = ?
                    """,
                    (run_id, draft.case_id),
                ).fetchone()[0],
            )
            if draft.version != next_pack_version:
                raise ConcurrentModification(
                    f"next evidence pack version is {next_pack_version}, got {draft.version}"
                )
            validated_pack = self._rebuild_and_verify_closure(connection, draft)
            if validated_pack.pack_id != draft.pack_id:
                raise RepositoryIntegrityError("revalidated pack identity changed unexpectedly")

            new_status = (
                CaseStatus.EVIDENCE_READY if validated_pack.complete else CaseStatus.CANDIDATE
            )
            new_case = loaded.snapshot.case.model_copy(
                update={
                    "status": new_status,
                    "evidence_packs": (*loaded.snapshot.case.evidence_packs, validated_pack),
                }
            )
            new_revision = loaded.snapshot.revision + 1
            pack_json, pack_sha256 = _document(validated_pack)
            case_json, case_sha256 = _document(new_case)
            head = self._validated_head(connection, run_id)
            sequence = head.sequence + 1

            collision = connection.execute(
                """
                SELECT document_sha256 FROM evidence_packs
                WHERE run_id = ? AND pack_id = ?
                """,
                (run_id, validated_pack.pack_id),
            ).fetchone()
            if collision is not None:
                raise RepositoryIntegrityError(
                    "pack_id already exists without the matching idempotency input"
                )
            connection.execute(
                """
                INSERT INTO evidence_packs(
                    run_id, pack_id, case_id, manifest_id, version, complete,
                    pack_input_sha256, closure_input_sha256,
                    pack_json, document_sha256, created_audit_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    validated_pack.pack_id,
                    validated_pack.case_id,
                    validated_pack.manifest_id,
                    validated_pack.version,
                    int(validated_pack.complete),
                    validated_pack.pack_input_sha256,
                    validated_pack.closure_input_sha256,
                    pack_json,
                    pack_sha256,
                    sequence,
                ),
            )
            self._fault("publish.after_pack")
            self._store_media_assets(connection, validated_pack)
            self._fault("publish.after_media_assets")
            self._store_crop_links(connection, validated_pack)
            self._fault("publish.after_crop_links")
            audit, _ = self._append_audit(
                connection,
                head,
                action=AuditAction.EVIDENCE_PACK_PUBLISHED,
                object_ref=ArtifactRef(
                    kind=ArtifactKind.CASE,
                    artifact_id=validated_pack.case_id,
                ),
                before_sha256=loaded.document_sha256,
                after_sha256=case_sha256,
            )
            self._fault("publish.after_audit")
            connection.execute(
                """
                INSERT INTO case_versions(
                    run_id, case_id, revision, status,
                    case_json, document_sha256, audit_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    new_case.case_id,
                    new_revision,
                    new_status.value,
                    case_json,
                    case_sha256,
                    audit.sequence,
                ),
            )
            self._fault("publish.after_case_version")
            cursor = connection.execute(
                """
                UPDATE cases
                SET status = ?, current_revision = ?,
                    latest_pack_id = ?, latest_pack_version = ?
                WHERE run_id = ? AND case_id = ? AND current_revision = ?
                """,
                (
                    new_status.value,
                    new_revision,
                    validated_pack.pack_id,
                    validated_pack.version,
                    run_id,
                    validated_pack.case_id,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrentModification("case revision changed during evidence publication")
            self._fault("publish.after_case_update")
            self._fault("publish.before_commit")
            return PublishResult(
                case=CaseSnapshot(case=new_case, revision=new_revision),
                pack=validated_pack,
                created=True,
            )

    def record_evidence_failure(
        self,
        run_id: str,
        expected_revision: int,
        case_id: str,
        failure_code: EvidenceFailureCode,
    ) -> CaseSnapshot:
        """Atomically escalate a controlled evidence failure to human review."""

        require_reference_token(run_id, "repository run_id")
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision must be a positive integer")
        if not isinstance(failure_code, EvidenceFailureCode):
            raise TypeError("failure_code must be an EvidenceFailureCode")
        case_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case_id)

        with self._immediate() as connection:
            loaded = self._load_case(connection, run_id, case_id)
            head = self._validated_head(connection, run_id)
            case = loaded.snapshot.case
            revision = loaded.snapshot.revision
            last_failure_code = (
                evidence_failure_code(case.timeline[-1], case_id=case_id) if case.timeline else None
            )
            latest_is_evidence_failure = (
                loaded.audit_action == AuditAction.CASE_STATE_CHANGED
                and case.status == CaseStatus.HUMAN_REVIEW
                and last_failure_code is not None
            )
            if latest_is_evidence_failure:
                if last_failure_code != failure_code:
                    raise ConcurrentModification(
                        "case already records a different latest evidence failure"
                    )
                if expected_revision not in {revision - 1, revision}:
                    raise ConcurrentModification(
                        f"case revision is {revision}, expected {expected_revision}"
                    )
                return loaded.snapshot
            if revision != expected_revision:
                raise ConcurrentModification(
                    f"case revision is {revision}, expected {expected_revision}"
                )

            timeline_entry = evidence_failure_timeline_entry(
                sequence=len(case.timeline),
                case_id=case_id,
                failure_code=failure_code,
            )
            new_case = case.model_copy(
                update={
                    "status": CaseStatus.HUMAN_REVIEW,
                    "timeline": (*case.timeline, timeline_entry),
                }
            )
            new_revision = revision + 1
            case_json, case_sha256 = _document(new_case)
            audit, _ = self._append_audit(
                connection,
                head,
                action=AuditAction.CASE_STATE_CHANGED,
                object_ref=case_ref,
                before_sha256=loaded.document_sha256,
                after_sha256=case_sha256,
            )
            self._fault("record_evidence_failure.after_audit")
            connection.execute(
                """
                INSERT INTO case_versions(
                    run_id, case_id, revision, status,
                    case_json, document_sha256, audit_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    case_id,
                    new_revision,
                    CaseStatus.HUMAN_REVIEW.value,
                    case_json,
                    case_sha256,
                    audit.sequence,
                ),
            )
            self._fault("record_evidence_failure.after_case_version")
            cursor = connection.execute(
                """
                UPDATE cases
                SET status = ?, current_revision = ?
                WHERE run_id = ? AND case_id = ? AND current_revision = ?
                """,
                (
                    CaseStatus.HUMAN_REVIEW.value,
                    new_revision,
                    run_id,
                    case_id,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrentModification(
                    "case revision changed during evidence failure recording"
                )
            self._fault("record_evidence_failure.after_case_update")
            self._fault("record_evidence_failure.before_commit")
            return CaseSnapshot(case=new_case, revision=new_revision)

    def list_expirable_media(
        self,
        run_id: str,
        expires_before: datetime,
        limit: int,
    ) -> tuple[str, ...]:
        """List available media whose latest audited pack publication is at/before cutoff.

        ``media_assets.ttl_expires_at`` is intentionally not consulted in M2.  The
        coordinator derives ``expires_before`` from the pinned retention configuration,
        while SQLite supplies the auditable last-use time shared by every linked pack.
        """

        require_reference_token(run_id, "retention run_id")
        cutoff = _canonical_utc_timestamp(expires_before, "expires_before")
        self._require_retention_limit(limit)
        with self._immediate() as connection:
            self._validated_head(connection, run_id)
            cursor_row = connection.execute(
                """
                SELECT last_media_sha256 FROM retention_scan_cursors WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            after_sha256 = (
                _row_str(cursor_row, "last_media_sha256") if cursor_row is not None else None
            )
            if after_sha256 is not None and _SHA256.fullmatch(after_sha256) is None:
                raise RepositoryIntegrityError("retention scan cursor is invalid")
            rows = self._expirable_media_page(
                connection,
                run_id=run_id,
                cutoff=cutoff,
                limit=limit,
                after_sha256=after_sha256,
            )
            if not rows and after_sha256 is not None:
                rows = self._expirable_media_page(
                    connection,
                    run_id=run_id,
                    cutoff=cutoff,
                    limit=limit,
                    after_sha256=None,
                )
            media_ids: list[str] = []
            for row in rows:
                media_sha256 = _row_str(row, "media_sha256")
                if _SHA256.fullmatch(media_sha256) is None:
                    raise RepositoryIntegrityError("media index contains an invalid SHA-256")
                observed = _parse_utc_timestamp(
                    _row_str(row, "latest_published_at"),
                    "latest media publication audit time",
                )
                if observed > _parse_utc_timestamp(cutoff, "retention cutoff"):
                    raise RepositoryIntegrityError(
                        "SQLite returned media newer than the retention cutoff"
                    )
                self._load_media_state(connection, run_id, media_sha256)
                media_ids.append(media_sha256)
            if media_ids:
                if cursor_row is None:
                    connection.execute(
                        """
                        INSERT INTO retention_scan_cursors(run_id, last_media_sha256)
                        VALUES (?, ?)
                        """,
                        (run_id, media_ids[-1]),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE retention_scan_cursors SET last_media_sha256 = ?
                        WHERE run_id = ?
                        """,
                        (media_ids[-1], run_id),
                    )
            return tuple(media_ids)

    def media_is_referenced(self, run_id: str, media_sha256: str) -> bool:
        """Return whether one run-scoped media hash has a valid persisted pack reference."""

        require_reference_token(run_id, "orphan-reference run_id")
        self._require_media_sha256(media_sha256)
        connection = self._connection()
        try:
            self._validated_head(connection, run_id)
            media_row = connection.execute(
                """
                SELECT 1 FROM media_assets
                WHERE run_id = ? AND media_sha256 = ?
                """,
                (run_id, media_sha256),
            ).fetchone()
            reference_row = connection.execute(
                """
                SELECT 1 FROM evidence_pack_crops
                WHERE run_id = ? AND media_sha256 = ?
                LIMIT 1
                """,
                (run_id, media_sha256),
            ).fetchone()
            if media_row is None:
                if reference_row is not None:
                    raise RepositoryIntegrityError(
                        "media reference exists without its run-scoped media index"
                    )
                return False

            self._load_media_state(connection, run_id, media_sha256)
            self._crop_refs_for_media(connection, run_id, media_sha256)
            self._latest_media_publication_at(connection, run_id, media_sha256)
            return True
        finally:
            connection.close()

    def begin_media_purge(
        self,
        run_id: str,
        media_sha256: str,
        expires_before: datetime,
        policy_version: str,
    ) -> PurgeLease | PurgeItemResult:
        """Atomically authorize AVAILABLE -> PURGING and seal its intent audit."""

        require_reference_token(run_id, "retention run_id")
        self._require_media_sha256(media_sha256)
        cutoff = _canonical_utc_timestamp(expires_before, "expires_before")
        require_reference_token(policy_version, "retention policy_version")
        with self._immediate() as connection:
            head = self._validated_head(connection, run_id)
            state = self._load_media_state(connection, run_id, media_sha256)
            crop_refs = self._crop_refs_for_media(connection, run_id, media_sha256)
            attempt = self._load_purge_attempt(connection, run_id, media_sha256)

            if state.availability == MediaAvailability.PURGING:
                if attempt is None or attempt.status != "PURGING":
                    raise RepositoryIntegrityError(
                        "PURGING media is not bound to an incomplete purge attempt"
                    )
                self._require_attempt_matches_state(attempt, state, purged=False)
                return self._recovery_required_result(attempt)
            if state.availability == MediaAvailability.PURGED_BY_RETENTION:
                if attempt is None or attempt.status == "PURGING":
                    raise RepositoryIntegrityError(
                        "purged media is not bound to a completed purge attempt"
                    )
                self._require_attempt_matches_state(attempt, state, purged=True)
                return self._already_purged_result(attempt)
            if attempt is not None:
                raise RepositoryIntegrityError(
                    "available media unexpectedly has a persisted purge attempt"
                )

            latest_publication = self._latest_media_publication_at(
                connection,
                run_id,
                media_sha256,
            )
            if latest_publication > _parse_utc_timestamp(cutoff, "retention cutoff"):
                return self._retained_result(
                    run_id,
                    media_sha256,
                    crop_refs,
                    PurgeReasonCode.RETENTION_NOT_EXPIRED,
                )
            hold_kinds = self._active_hold_kinds(
                connection,
                run_id,
                media_sha256,
                crop_refs,
            )
            if hold_kinds:
                return self._retained_result(
                    run_id,
                    media_sha256,
                    crop_refs,
                    PurgeReasonCode.ACTIVE_RETENTION_HOLD,
                    hold_kinds=hold_kinds,
                )

            available_json, available_sha256 = state.document()
            source_relative_path = state.local_path
            if source_relative_path is None:
                raise RepositoryIntegrityError("available media has no canonical source locator")
            purging_state = replace(state, availability=MediaAvailability.PURGING)
            purging_json, purging_sha256 = purging_state.document()
            intent_sequence = head.sequence + 1
            requested_at = _utc_timestamp(self._clock)
            lease = PurgeLease(
                run_id=run_id,
                media_sha256=media_sha256,
                source_relative_path=source_relative_path,
                trash_relative_path=f".trash/{run_id}/{media_sha256}.png",
                crop_refs=crop_refs,
                intent_audit_sequence=intent_sequence,
            )
            crop_refs_json, crop_refs_sha256 = _artifact_refs_document(crop_refs)
            connection.execute(
                """
                INSERT INTO media_purge_attempts(
                    run_id, media_sha256, intent_audit_sequence, manifest_id,
                    policy_version, expires_before, requested_at,
                    source_relative_path, trash_relative_path,
                    crop_refs_json, crop_refs_sha256,
                    available_state_json, available_state_sha256,
                    purging_state_json, purging_state_sha256,
                    purged_state_json, purged_state_sha256,
                    completion_audit_sequence, completion_recovered,
                    cleanup_acked_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          NULL, NULL, NULL, NULL, NULL, 'PURGING')
                """,
                (
                    run_id,
                    media_sha256,
                    intent_sequence,
                    head.manifest_id,
                    policy_version,
                    cutoff,
                    requested_at,
                    lease.source_relative_path,
                    lease.trash_relative_path,
                    crop_refs_json,
                    crop_refs_sha256,
                    available_json,
                    available_sha256,
                    purging_json,
                    purging_sha256,
                ),
            )
            self._fault("retention.begin.after_attempt")
            cursor = connection.execute(
                """
                UPDATE media_assets
                SET availability = ?
                WHERE run_id = ? AND media_sha256 = ? AND availability = ?
                """,
                (
                    MediaAvailability.PURGING.value,
                    run_id,
                    media_sha256,
                    MediaAvailability.AVAILABLE.value,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrentModification("media availability changed during purge intent")
            self._fault("retention.begin.after_media_update")
            persisted_purging = self._load_media_state(connection, run_id, media_sha256)
            if persisted_purging.document() != (purging_json, purging_sha256):
                raise RepositoryIntegrityError("purging media state changed during intent")
            audit, _ = self._append_audit(
                connection,
                head,
                action=AuditAction.MEDIA_PURGE_REQUESTED,
                object_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=media_sha256),
                before_sha256=available_sha256,
                after_sha256=purging_sha256,
                actor=AuditActorRole.RETENTION,
                recorded_at=requested_at,
            )
            if audit.sequence != intent_sequence:
                raise ConcurrentModification("purge intent audit sequence changed")
            self._fault("retention.begin.after_audit")
            self._fault("retention.begin.before_commit")
            return lease

    def complete_media_purge(
        self,
        run_id: str,
        media_sha256: str,
        intent_audit_sequence: int,
        recovered: bool,
    ) -> PurgeItemResult:
        """Atomically complete PURGING -> PURGED_BY_RETENTION and seal its audit."""

        require_reference_token(run_id, "retention run_id")
        self._require_media_sha256(media_sha256)
        self._require_audit_sequence(intent_audit_sequence, "intent_audit_sequence")
        if not isinstance(recovered, bool):
            raise TypeError("recovered must be a boolean")
        with self._immediate() as connection:
            head = self._validated_head(connection, run_id)
            attempt = self._load_purge_attempt(
                connection,
                run_id,
                media_sha256,
                intent_audit_sequence=intent_audit_sequence,
            )
            if attempt is None:
                raise ContractViolation("unknown purge intent for media")
            state = self._load_media_state(connection, run_id, media_sha256)
            if attempt.status != "PURGING":
                self._require_attempt_matches_state(attempt, state, purged=True)
                if attempt.completion_recovered != recovered:
                    raise ConcurrentModification(
                        "purge completion was already committed with another recovery mode"
                    )
                return self._completed_purge_result(attempt)
            if state.availability != MediaAvailability.PURGING:
                raise RepositoryIntegrityError(
                    "incomplete purge attempt does not select PURGING media"
                )
            self._require_attempt_matches_state(attempt, state, purged=False)

            purged_at = _utc_timestamp(self._clock)
            cursor = connection.execute(
                """
                UPDATE media_assets
                SET availability = ?, local_path = NULL, purged_at = ?
                WHERE run_id = ? AND media_sha256 = ? AND availability = ?
                """,
                (
                    MediaAvailability.PURGED_BY_RETENTION.value,
                    purged_at,
                    run_id,
                    media_sha256,
                    MediaAvailability.PURGING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrentModification("media availability changed during purge completion")
            self._fault("retention.complete.after_media_update")
            purged_state = self._load_media_state(connection, run_id, media_sha256)
            purged_json, purged_sha256 = purged_state.document()
            audit, _ = self._append_audit(
                connection,
                head,
                action=AuditAction.PURGED_BY_RETENTION,
                object_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=media_sha256),
                before_sha256=attempt.purging_state_sha256,
                after_sha256=purged_sha256,
                actor=AuditActorRole.RETENTION,
            )
            self._fault("retention.complete.after_audit")
            cursor = connection.execute(
                """
                UPDATE media_purge_attempts
                SET purged_state_json = ?, purged_state_sha256 = ?,
                    completion_audit_sequence = ?, completion_recovered = ?,
                    status = 'PURGED_CLEANUP_PENDING'
                WHERE run_id = ? AND media_sha256 = ?
                  AND intent_audit_sequence = ? AND status = 'PURGING'
                """,
                (
                    purged_json,
                    purged_sha256,
                    audit.sequence,
                    int(recovered),
                    run_id,
                    media_sha256,
                    intent_audit_sequence,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrentModification("purge attempt changed during completion")
            self._fault("retention.complete.after_attempt")
            self._fault("retention.complete.before_commit")
            completed = self._load_purge_attempt(
                connection,
                run_id,
                media_sha256,
                intent_audit_sequence=intent_audit_sequence,
            )
            if completed is None:
                raise RepositoryIntegrityError("completed purge attempt disappeared")
            return self._completed_purge_result(completed)

    def claim_next_recovery(self, run_id: str) -> PurgeRecoveryCandidate | None:
        """Atomically advance the durable run cursor and claim one recovery phase."""

        require_reference_token(run_id, "retention run_id")
        with self._immediate() as connection:
            self._validated_head(connection, run_id)
            cursor_row = connection.execute(
                """
                SELECT last_intent_audit_sequence
                FROM retention_recovery_cursors
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            after_sequence: int | None = None
            if cursor_row is not None:
                after_sequence = _row_int(cursor_row, "last_intent_audit_sequence")
                if after_sequence < 0:
                    raise RepositoryIntegrityError("retention recovery cursor is invalid")
                cursor_target = connection.execute(
                    """
                    SELECT 1 FROM media_purge_attempts
                    WHERE run_id = ? AND intent_audit_sequence = ?
                    """,
                    (run_id, after_sequence),
                ).fetchone()
                if cursor_target is None:
                    raise RepositoryIntegrityError("retention recovery cursor has no purge attempt")

            attempt = self._next_recovery_attempt(
                connection,
                run_id=run_id,
                after_sequence=after_sequence,
            )
            if attempt is None and after_sequence is not None:
                attempt = self._next_recovery_attempt(
                    connection,
                    run_id=run_id,
                    after_sequence=None,
                )
            if attempt is None:
                return None

            if attempt.status == "PURGING":
                kind = PurgeRecoveryKind.INCOMPLETE_PURGE
                completion_audit_sequence = None
                state = self._load_media_state(
                    connection,
                    run_id,
                    attempt.lease.media_sha256,
                )
                self._require_attempt_matches_state(attempt, state, purged=False)
            elif attempt.status == "PURGED_CLEANUP_PENDING":
                kind = PurgeRecoveryKind.TRASH_CLEANUP
                completion_audit_sequence = attempt.completion_audit_sequence
                state = self._load_media_state(
                    connection,
                    run_id,
                    attempt.lease.media_sha256,
                )
                self._require_attempt_matches_state(attempt, state, purged=True)
            else:
                raise RepositoryIntegrityError(
                    "retention scheduler selected a non-recoverable purge attempt"
                )

            if cursor_row is None:
                connection.execute(
                    """
                    INSERT INTO retention_recovery_cursors(
                        run_id, last_intent_audit_sequence
                    ) VALUES (?, ?)
                    """,
                    (run_id, attempt.lease.intent_audit_sequence),
                )
            else:
                connection.execute(
                    """
                    UPDATE retention_recovery_cursors
                    SET last_intent_audit_sequence = ?
                    WHERE run_id = ?
                    """,
                    (attempt.lease.intent_audit_sequence, run_id),
                )
            self._fault("retention.recovery_claim.after_cursor")
            candidate = PurgeRecoveryCandidate(
                kind=kind,
                lease=attempt.lease,
                completion_audit_sequence=completion_audit_sequence,
            )
            self._fault("retention.recovery_claim.before_commit")
            return candidate

    def mark_trash_cleaned(
        self,
        run_id: str,
        media_sha256: str,
        intent_audit_sequence: int,
    ) -> None:
        """Acknowledge cleanup without adding a second business/audit transition."""

        require_reference_token(run_id, "retention run_id")
        self._require_media_sha256(media_sha256)
        self._require_audit_sequence(intent_audit_sequence, "intent_audit_sequence")
        with self._immediate() as connection:
            self._validated_head(connection, run_id)
            attempt = self._load_purge_attempt(
                connection,
                run_id,
                media_sha256,
                intent_audit_sequence=intent_audit_sequence,
            )
            if attempt is None:
                raise ContractViolation("unknown purge intent for trash cleanup")
            if attempt.status == "TRASH_CLEANED":
                return
            if attempt.status != "PURGED_CLEANUP_PENDING":
                raise ConcurrentModification("trash cannot be acknowledged before purge completion")
            state = self._load_media_state(connection, run_id, media_sha256)
            self._require_attempt_matches_state(attempt, state, purged=True)
            cursor = connection.execute(
                """
                UPDATE media_purge_attempts
                SET cleanup_acked_at = ?, status = 'TRASH_CLEANED'
                WHERE run_id = ? AND media_sha256 = ?
                  AND intent_audit_sequence = ?
                  AND status = 'PURGED_CLEANUP_PENDING'
                """,
                (
                    _utc_timestamp(self._clock),
                    run_id,
                    media_sha256,
                    intent_audit_sequence,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrentModification("purge cleanup state changed during acknowledgement")
            self._fault("retention.cleanup.after_ack")
            self._fault("retention.cleanup.before_commit")

    def create_retention_hold(self, hold: RetentionHold) -> int:
        validated = RetentionHold.model_validate(hold.model_dump(mode="json"))
        hold_json, hold_sha256 = _document(validated)
        with self._immediate() as connection:
            head = self._validated_head(connection, validated.run_id)
            if validated.manifest_id != head.manifest_id:
                raise ManifestMismatch("retention hold does not use the run manifest")
            existing = self._load_retention_hold(
                connection,
                validated.run_id,
                validated.hold_id,
                required=False,
            )
            if existing is not None:
                existing_hold, active, created_sequence, _ = existing
                if existing_hold != validated:
                    raise RepositoryIntegrityError(
                        "hold_id already exists with different canonical content"
                    )
                if not active:
                    raise ConcurrentModification("released retention hold cannot be reactivated")
                return created_sequence

            self._require_hold_target_and_owner(connection, validated)
            audit, _ = self._append_audit(
                connection,
                head,
                action=AuditAction.RETENTION_HOLD_CREATED,
                object_ref=validated.target_ref.ref,
                before_sha256=None,
                after_sha256=hold_sha256,
                actor=AuditActorRole.RETENTION,
            )
            self._fault("retention.hold_create.after_audit")
            connection.execute(
                """
                INSERT INTO retention_holds(
                    run_id, hold_id, target_kind, target_id,
                    hold_kind, owner_kind, owner_id, active,
                    manifest_id, policy_version, reason_code,
                    hold_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    validated.run_id,
                    validated.hold_id,
                    validated.target_ref.ref.kind.value,
                    validated.target_ref.ref.artifact_id,
                    validated.kind.value,
                    validated.owner_ref.ref.kind.value,
                    validated.owner_ref.ref.artifact_id,
                    validated.manifest_id,
                    validated.policy_version,
                    validated.reason_code,
                    hold_json,
                    hold_sha256,
                ),
            )
            self._fault("retention.hold_create.after_hold")
            connection.execute(
                """
                INSERT INTO retention_hold_audit_links(
                    run_id, hold_id, created_audit_sequence, released_audit_sequence
                ) VALUES (?, ?, ?, NULL)
                """,
                (validated.run_id, validated.hold_id, audit.sequence),
            )
            self._fault("retention.hold_create.after_link")
            self._fault("retention.hold_create.before_commit")
            return audit.sequence

    def release_retention_hold(self, run_id: str, hold_id: str) -> int:
        require_reference_token(run_id, "retention run_id")
        require_reference_token(hold_id, "retention hold_id")
        with self._immediate() as connection:
            head = self._validated_head(connection, run_id)
            loaded = self._load_retention_hold(connection, run_id, hold_id, required=True)
            assert loaded is not None
            hold, active, _, released_sequence = loaded
            if not active:
                if released_sequence is None:
                    raise RepositoryIntegrityError("released hold has no release audit link")
                return released_sequence
            active_json, active_sha256 = _retention_hold_state_document(hold, active=True)
            if active_json != canonical_json(hold.model_dump(mode="json")):
                raise RepositoryIntegrityError("active hold state is not canonical")
            _, released_sha256 = _retention_hold_state_document(hold, active=False)
            audit, _ = self._append_audit(
                connection,
                head,
                action=AuditAction.RETENTION_HOLD_RELEASED,
                object_ref=hold.target_ref.ref,
                before_sha256=active_sha256,
                after_sha256=released_sha256,
                actor=AuditActorRole.RETENTION,
            )
            self._fault("retention.hold_release.after_audit")
            cursor = connection.execute(
                """
                UPDATE retention_hold_audit_links SET released_audit_sequence = ?
                WHERE run_id = ? AND hold_id = ? AND released_audit_sequence IS NULL
                """,
                (audit.sequence, run_id, hold_id),
            )
            if cursor.rowcount != 1:
                raise ConcurrentModification("retention hold release link changed")
            self._fault("retention.hold_release.after_link")
            cursor = connection.execute(
                """
                UPDATE retention_holds SET active = 0
                WHERE run_id = ? AND hold_id = ? AND active = 1
                """,
                (run_id, hold_id),
            )
            if cursor.rowcount != 1:
                raise ConcurrentModification("retention hold changed during release")
            self._fault("retention.hold_release.after_hold")
            self._fault("retention.hold_release.before_commit")
            return audit.sequence

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot:
        require_reference_token(run_id, "repository run_id")
        connection = self._connection()
        try:
            return self._load_case(connection, run_id, case_id).snapshot
        finally:
            connection.close()

    def load_run_manifest(self, run_id: str) -> RunManifest:
        """Load the single authoritative manifest registered for a run."""

        require_reference_token(run_id, "repository run_id")
        connection = self._connection()
        try:
            return self._load_run_manifest(connection, run_id)
        finally:
            connection.close()

    def load_pack(self, run_id: str, pack_id: str) -> EvidencePack:
        require_reference_token(run_id, "repository run_id")
        if _SHA256.fullmatch(pack_id) is None:
            raise ValueError("pack_id must be a lowercase SHA-256 digest")
        connection = self._connection()
        try:
            return self._load_pack(connection, run_id, pack_id)
        finally:
            connection.close()

    def load_frame(self, run_id: str, frame_id: str) -> FrameRef:
        """Load one authoritative frame, including its local pixel dimensions."""

        require_reference_token(run_id, "repository run_id")
        parse_frame_id(frame_id)
        connection = self._connection()
        try:
            frame = self._load_frame(connection, run_id, frame_id)
            if frame is None:
                raise ContractViolation("unknown frame")
            return frame
        finally:
            connection.close()

    def verify_current_pack(self, run_id: str, pack_id: str) -> ClosureReport:
        """Rebuild closure against current DB locators, availability, and physical bytes."""

        require_reference_token(run_id, "repository run_id")
        if _SHA256.fullmatch(pack_id) is None:
            raise ValueError("pack_id must be a lowercase SHA-256 digest")
        connection = self._connection()
        try:
            connection.execute("BEGIN")
            self._validated_head(connection, run_id)
            pack = self._load_pack(connection, run_id, pack_id)
            payload = pack.model_dump(mode="json", exclude_computed_fields=True)
            payload.pop("closure_report")
            draft = EvidencePackDraft.model_validate(payload)
            self._require_manifest_bindings(connection, draft)
            defects = list(self._semantic_closure_defects(connection, draft))
            if draft.crops and self._verifier is None:
                defects.extend(
                    ClosureDefect(
                        code=ClosureDefectCode.MEDIA_MISSING,
                        artifact_ref=ArtifactRef(
                            kind=ArtifactKind.CROP,
                            artifact_id=crop.crop_id,
                        ),
                        reason_code="VERIFIER_UNAVAILABLE",
                    )
                    for crop in draft.crops
                )
            else:
                defects.extend(self._physical_closure_defects(draft))
            ordered_defects = _stable_unique_defects(defects)
            root_ref = ArtifactRef(
                kind=ArtifactKind.EVIDENCE_PACK,
                artifact_id=pack.pack_id,
            )
            checked = {ref.sort_key: ref for ref in draft.expected_closure_refs()}
            checked[root_ref.sort_key] = root_ref
            report = ClosureReport(
                run_id=run_id,
                root_ref=root_ref,
                manifest_id=draft.manifest_id,
                input_sha256=draft.closure_input_sha256,
                checked_refs=tuple(checked[key] for key in sorted(checked)),
                defects=ordered_defects,
            )
            connection.commit()
            return report
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def observe_m6_gate_source(
        self,
        run_id: str,
        case_id: str,
        source_case_revision: int | None = None,
    ) -> M6GateSourceObservation:
        """Observe one exact Case revision while blocking retention transitions.

        ``BEGIN IMMEDIATE`` is intentional even though this method does not mutate
        SQLite. Retention also acquires the writer lock before AVAILABLE -> PURGING,
        so the historical Case, current locators, physical Crop reads, and current
        audit head form one non-interleavable observation. The lock is released
        before the result leaves the repository.
        """

        require_reference_token(run_id, "M6 source authority run_id")
        require_reference_token(case_id, "M6 source authority case_id")
        if source_case_revision is not None and (
            not isinstance(source_case_revision, int)
            or isinstance(source_case_revision, bool)
            or source_case_revision <= 0
        ):
            raise ValueError("source_case_revision must be a positive integer or None")
        with self._immediate() as connection:
            connection.execute("PRAGMA query_only = ON")
            head = self._validated_head(connection, run_id)
            loaded = (
                self._load_case(connection, run_id, case_id)
                if source_case_revision is None
                else self._load_case_revision(
                    connection,
                    run_id,
                    case_id,
                    source_case_revision,
                )
            )
            case = loaded.snapshot.case
            packs = {(item.pack_id, item.version): item for item in case.evidence_packs}
            reviewed_keys = tuple(
                sorted(
                    {
                        (item.evidence_pack_id, item.evidence_pack_version)
                        for item in case.procedural_reviews
                    }
                )
            )
            verification_cache: dict[str, tuple[Crop, ArtifactVerification]] = {}
            observations: list[M6CurrentPackObservation] = []
            for key in reviewed_keys:
                pack = packs.get(key)
                if pack is None:
                    raise RepositoryIntegrityError(
                        "procedural review references a missing current evidence pack"
                    )
                payload = pack.model_dump(mode="json", exclude_computed_fields=True)
                payload.pop("closure_report")
                draft = EvidencePackDraft.model_validate(payload)
                self._require_manifest_bindings(connection, draft)
                defects = list(self._semantic_closure_defects(connection, draft))
                verifications: tuple[ArtifactVerification, ...] = ()
                if draft.crops and self._verifier is None:
                    defects.extend(
                        ClosureDefect(
                            code=ClosureDefectCode.MEDIA_MISSING,
                            artifact_ref=ArtifactRef(
                                kind=ArtifactKind.CROP,
                                artifact_id=crop.crop_id,
                            ),
                            reason_code="VERIFIER_UNAVAILABLE",
                        )
                        for crop in draft.crops
                    )
                else:
                    physical_defects, verifications = self._physical_closure_observation(
                        draft,
                        verification_cache=verification_cache,
                    )
                    defects.extend(physical_defects)
                root_ref = ArtifactRef(
                    kind=ArtifactKind.EVIDENCE_PACK,
                    artifact_id=pack.pack_id,
                )
                checked = {ref.sort_key: ref for ref in draft.expected_closure_refs()}
                checked[root_ref.sort_key] = root_ref
                observations.append(
                    M6CurrentPackObservation(
                        pack=pack,
                        current_closure=ClosureReport(
                            run_id=run_id,
                            root_ref=root_ref,
                            manifest_id=draft.manifest_id,
                            input_sha256=draft.closure_input_sha256,
                            checked_refs=tuple(checked[item] for item in sorted(checked)),
                            defects=_stable_unique_defects(defects),
                        ),
                        crop_verifications=verifications,
                    )
                )
            return M6GateSourceObservation(
                source_case=case,
                source_case_revision=loaded.snapshot.revision,
                source_case_document_sha256=loaded.document_sha256,
                audit_head_sequence=head.sequence,
                audit_head_hash=head.entry_hash,
                packs=tuple(observations),
            )

    def list_events(self, run_id: str) -> tuple[CandidateEvent, ...]:
        require_reference_token(run_id, "repository run_id")
        connection = self._connection()
        try:
            self._head(connection, run_id)
            rows = connection.execute(
                """
                SELECT case_id
                FROM cases WHERE run_id = ?
                ORDER BY created_audit_sequence, case_id
                """,
                (run_id,),
            ).fetchall()
            return tuple(
                self._load_case(connection, run_id, _row_str(row, "case_id")).snapshot.case.event
                for row in rows
            )
        finally:
            connection.close()

    def list_audit_entries(self, run_id: str) -> tuple[AuditEntry, ...]:
        require_reference_token(run_id, "repository run_id")
        connection = self._connection()
        try:
            self._head(connection, run_id)
            rows = connection.execute(
                """
                SELECT * FROM audit_entries
                WHERE run_id = ? ORDER BY sequence
                """,
                (run_id,),
            ).fetchall()
            return tuple(_audit_entry_from_row(row) for row in rows)
        finally:
            connection.close()

    def get_audit_head(self, run_id: str) -> AuditHead:
        require_reference_token(run_id, "repository run_id")
        connection = self._connection()
        try:
            return self._head(connection, run_id)
        finally:
            connection.close()

    def _hearing_repository(self) -> SQLiteHearingRepository:
        from .sqlite_hearing_repository import SQLiteHearingRepository

        return SQLiteHearingRepository(self)

    def _hearing_recovery_repository(
        self,
    ) -> SQLiteHearingModelCallRecoveryRepository:
        from .sqlite_hearing_recovery import SQLiteHearingModelCallRecoveryRepository

        verifier = self._hearing_raw_response_verifier or _UNAVAILABLE_HEARING_RAW_RESPONSE_VERIFIER
        return SQLiteHearingModelCallRecoveryRepository(self, verifier)

    def scan_hearing_model_call_recovery_candidates(
        self,
        run_id: str,
        max_items: int,
    ) -> HearingModelCallRecoveryScan:
        return self._hearing_recovery_repository().scan_hearing_model_call_recovery_candidates(
            run_id,
            max_items,
        )

    def complete_expired_hearing_model_call_from_recovery(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
        observed_lease_expires_at: datetime,
        observed_takeover_count: int,
    ) -> HearingModelCacheEntry:
        return (
            self._hearing_recovery_repository().complete_expired_hearing_model_call_from_recovery(
                run_id,
                request,
                response,
                observed_lease_expires_at,
                observed_takeover_count,
            )
        )

    def load_hearing_model_cache_entry_for_recovery(
        self,
        run_id: str,
        request: HearingModelRequest,
    ) -> HearingModelCacheEntry | None:
        return self._hearing_recovery_repository().load_hearing_model_cache_entry_for_recovery(
            run_id,
            request,
        )

    def load_hearing_model_response_for_request(
        self,
        run_id: str,
        request_id: str,
    ) -> HearingModelResponse | None:
        return self._hearing_recovery_repository().load_hearing_model_response_for_request(
            run_id,
            request_id,
        )

    def commit_hearing_backlog(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        intent: HearingBacklogEnqueueIntent,
    ) -> HearingBacklogEnqueueCommit:
        return self._hearing_repository().commit_hearing_backlog(
            run_id,
            expected_case_revision,
            expected_audit_head,
            intent,
        )

    def lease_next_hearing_backlog(
        self,
        run_id: str,
        lease_owner_sha256: str,
        lease_expires_at: datetime,
    ) -> BacklogItem | None:
        return self._hearing_repository().lease_next_hearing_backlog(
            run_id,
            lease_owner_sha256,
            lease_expires_at,
        )

    def load_hearing_backlog_retry_authority(
        self,
        run_id: str,
        lease: BacklogLeaseIdentity,
    ) -> HearingBacklogRetryAuthority:
        return self._hearing_repository().load_hearing_backlog_retry_authority(
            run_id,
            lease,
        )

    def commit_hearing_backlog_retry(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        outcome: HearingBacklogRetryOutcome,
        model_call_failure: HearingModelCallFailureIntent | None = None,
    ) -> HearingBacklogRetryCommit:
        return self._hearing_repository().commit_hearing_backlog_retry(
            run_id,
            expected_case_revision,
            expected_audit_head,
            outcome,
            model_call_failure,
        )

    def reclaim_expired_hearing_backlog(
        self,
        run_id: str,
        not_after: datetime,
        limit: int,
    ) -> tuple[HearingBacklogRetryCommit, ...]:
        return self._hearing_repository().reclaim_expired_hearing_backlog(
            run_id,
            not_after,
            limit,
        )

    def start_hearing(
        self,
        run_id: str,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> None:
        self._hearing_repository().start_hearing(run_id, session, cycle_scope, checkpoint)

    def begin_hearing_case(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> HearingStartResult:
        return self._hearing_repository().begin_hearing_case(
            run_id,
            expected_case_revision,
            expected_audit_head,
            session,
            cycle_scope,
            checkpoint,
        )

    def append_hearing_cycle(self, run_id: str, cycle_scope: HearingCycleScope) -> None:
        self._hearing_repository().append_hearing_cycle(run_id, cycle_scope)

    def append_hearing_checkpoint(self, run_id: str, checkpoint: HearingCheckpoint) -> None:
        self._hearing_repository().append_hearing_checkpoint(run_id, checkpoint)

    def append_precedent_retrieval(
        self,
        run_id: str,
        receipt: HearingPrecedentRetrievalReceipt,
    ) -> None:
        self._hearing_repository().append_precedent_retrieval(run_id, receipt)

    def claim_hearing_model_call(
        self,
        run_id: str,
        request: HearingModelRequest,
        owner_token: str,
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> HearingModelCallClaim:
        return self._hearing_repository().claim_hearing_model_call(
            run_id,
            request,
            owner_token,
            backlog_lease,
        )

    def complete_hearing_model_call(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
        usage: HearingUsageReceipt,
        owner_token: str,
    ) -> HearingModelCacheEntry:
        return self._hearing_repository().complete_hearing_model_call(
            run_id,
            request,
            response,
            usage,
            owner_token,
        )

    def append_hearing_parse_receipt(
        self,
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput | None = None,
    ) -> HearingModelParseReceipt:
        return self._hearing_repository().append_hearing_parse_receipt(receipt, output)

    def complete_hearing_round(self, run_id: str, hearing_round: HearingRound) -> None:
        self._hearing_repository().complete_hearing_round(run_id, hearing_round)

    def commit_hearing_verdict_review(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        verdict: Verdict,
        binding: HearingVerdictBinding,
        review: ProceduralReview,
        checkpoint: HearingCheckpoint,
    ) -> HearingVerdictReviewResult:
        return self._hearing_repository().commit_hearing_verdict_review(
            run_id,
            expected_case_revision,
            expected_audit_head,
            verdict,
            binding,
            review,
            checkpoint,
        )

    def begin_hearing_rework(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        receipt: HearingReworkReceipt,
        cycle_scope: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> HearingReworkResult:
        return self._hearing_repository().begin_hearing_rework(
            run_id,
            expected_case_revision,
            expected_audit_head,
            receipt,
            cycle_scope,
            checkpoint,
        )

    def commit_hearing_human_review(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        receipt: HearingHumanReviewReceipt,
        checkpoint: HearingCheckpoint,
    ) -> HearingHumanReviewResult:
        return self._hearing_repository().commit_hearing_human_review(
            run_id,
            expected_case_revision,
            expected_audit_head,
            receipt,
            checkpoint,
        )

    def claim_acquisition_execution(
        self,
        run_id: str,
        request: AcquisitionRequest,
        execution_mode: AcquisitionExecutionMode,
        owner_token: str,
    ) -> AcquisitionExecutionClaim:
        return self._hearing_repository().claim_acquisition_execution(
            run_id, request, execution_mode, owner_token
        )

    def claim_acquisition_recovery(
        self,
        run_id: str,
        request: AcquisitionRequest,
        observed_owner_fence: int,
        owner_token: str,
    ) -> AcquisitionExecutionClaim:
        return self._hearing_repository().claim_acquisition_recovery(
            run_id, request, observed_owner_fence, owner_token
        )

    def complete_acquisition_execution(
        self,
        run_id: str,
        publication: AcquisitionExecutionPublication,
        owner_token: str,
    ) -> AcquisitionExecutionCommit:
        return self._hearing_repository().complete_acquisition_execution(
            run_id, publication, owner_token
        )

    def abandon_acquisition_execution(
        self,
        run_id: str,
        request: AcquisitionRequest,
        observed_owner_fence: int,
        owner_token: str,
    ) -> AcquisitionExecutionClaim:
        return self._hearing_repository().abandon_acquisition_execution(
            run_id, request, observed_owner_fence, owner_token
        )

    def load_acquisition_execution(
        self,
        run_id: str,
        request_id: str,
    ) -> AcquisitionExecutionPublication | None:
        return self._hearing_repository().load_acquisition_execution(run_id, request_id)

    def persist_acquisition_successor(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        request: AcquisitionRequest,
        publication: AcquisitionExecutionPublication,
    ) -> AcquisitionPublishResult:
        return self._hearing_repository().persist_acquisition_successor(
            run_id,
            expected_case_revision,
            expected_audit_head,
            request,
            publication,
        )

    def load_hearing_session(self, run_id: str, hearing_id: str) -> HearingSession:
        return self._hearing_repository().load_hearing_session(run_id, hearing_id)

    def load_active_hearing(self, run_id: str, case_id: str) -> HearingSession | None:
        return self._hearing_repository().load_active_hearing(run_id, case_id)

    def load_latest_hearing_checkpoint(
        self,
        run_id: str,
        hearing_id: str,
    ) -> HearingCheckpoint:
        return self._hearing_repository().load_latest_hearing_checkpoint(run_id, hearing_id)

    def list_hearing_cycles(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingCycleScope, ...]:
        return self._hearing_repository().list_hearing_cycles(run_id, hearing_id)

    def list_hearing_rounds(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingRound, ...]:
        return self._hearing_repository().list_hearing_rounds(run_id, hearing_id)

    def load_hearing_record(
        self,
        run_id: str,
        hearing_id: str,
    ) -> HearingRecord | None:
        return self._hearing_repository().load_hearing_record(run_id, hearing_id)

    def load_hearing_budget_usage(
        self,
        run_id: str,
        hearing_id: str,
    ) -> HearingBudgetUsage:
        return self._hearing_repository().load_hearing_budget_usage(run_id, hearing_id)

    def list_hearing_model_requests(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelRequest, ...]:
        return self._hearing_repository().list_hearing_model_requests(run_id, hearing_id)

    def list_hearing_model_responses(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelResponse, ...]:
        return self._hearing_repository().list_hearing_model_responses(run_id, hearing_id)

    def list_hearing_parse_receipts(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelParseReceipt, ...]:
        return self._hearing_repository().list_hearing_parse_receipts(run_id, hearing_id)

    def list_hearing_role_outputs(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingRoleOutput, ...]:
        return self._hearing_repository().list_hearing_role_outputs(run_id, hearing_id)

    def list_hearing_usage_receipts(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingUsageReceipt, ...]:
        return self._hearing_repository().list_hearing_usage_receipts(run_id, hearing_id)

    def list_hearing_failure_authorities(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelCallFailureAuthority, ...]:
        return self._hearing_repository().list_hearing_failure_authorities(
            run_id,
            hearing_id,
        )

    def load_hearing_evidence_authority(
        self,
        run_id: str,
        hearing_id: str,
        current_pack_id: str,
    ) -> EvidenceAuthority:
        return self._hearing_repository().load_hearing_evidence_authority(
            run_id,
            hearing_id,
            current_pack_id,
        )

    def load_hearing_cycle(self, run_id: str, cycle_id: str) -> HearingCycleScope:
        return self._hearing_repository().load_hearing_cycle(run_id, cycle_id)

    def load_precedent_retrieval(
        self,
        run_id: str,
        receipt_id: str,
    ) -> HearingPrecedentRetrievalReceipt:
        return self._hearing_repository().load_precedent_retrieval(run_id, receipt_id)

    def load_hearing_checkpoint(
        self,
        run_id: str,
        checkpoint_id: str,
    ) -> HearingCheckpoint:
        return self._hearing_repository().load_hearing_checkpoint(run_id, checkpoint_id)

    def load_hearing_round(self, run_id: str, round_id: str) -> HearingRound:
        return self._hearing_repository().load_hearing_round(run_id, round_id)

    def load_hearing_model_request(
        self,
        run_id: str,
        request_id: str,
    ) -> HearingModelRequest:
        return self._hearing_repository().load_hearing_model_request(run_id, request_id)

    def load_hearing_model_response(
        self,
        run_id: str,
        response_id: str,
    ) -> HearingModelResponse:
        return self._hearing_repository().load_hearing_model_response(run_id, response_id)

    def load_hearing_model_cache_entry(
        self,
        run_id: str,
        cache_key: str,
    ) -> HearingModelCacheEntry | None:
        return self._hearing_repository().load_hearing_model_cache_entry(run_id, cache_key)

    def load_hearing_parse_receipt(
        self,
        run_id: str,
        parse_receipt_id: str,
    ) -> HearingModelParseReceipt:
        return self._hearing_repository().load_hearing_parse_receipt(
            run_id,
            parse_receipt_id,
        )

    def load_hearing_role_output(
        self,
        run_id: str,
        output_id: str,
    ) -> HearingRoleOutput:
        return self._hearing_repository().load_hearing_role_output(run_id, output_id)

    def load_hearing_usage_receipt(
        self,
        run_id: str,
        usage_receipt_id: str,
    ) -> HearingUsageReceipt:
        return self._hearing_repository().load_hearing_usage_receipt(
            run_id,
            usage_receipt_id,
        )

    def pragma_settings(self) -> dict[str, int | str]:
        """Return the verified settings of a fresh repository connection."""

        connection = self._connection()
        try:
            return {
                "foreign_keys": cast(
                    int,
                    connection.execute("PRAGMA foreign_keys").fetchone()[0],
                ),
                "journal_mode": cast(
                    str,
                    connection.execute("PRAGMA journal_mode").fetchone()[0],
                ).lower(),
                "synchronous": cast(
                    int,
                    connection.execute("PRAGMA synchronous").fetchone()[0],
                ),
                "busy_timeout": cast(
                    int,
                    connection.execute("PRAGMA busy_timeout").fetchone()[0],
                ),
                "trusted_schema": cast(
                    int,
                    connection.execute("PRAGMA trusted_schema").fetchone()[0],
                ),
            }
        finally:
            connection.close()

    @contextmanager
    def _immediate(self, *, require_m4: bool = False) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connection(
                require_hardening=True,
                require_m4=require_m4,
            )
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException as exc:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            if isinstance(exc, sqlite3.OperationalError) and _is_sqlite_concurrency_error(exc):
                raise ConcurrentModification("SQLite writer lock could not be acquired") from exc
            raise
        finally:
            if connection is not None:
                connection.close()

    def _connection(
        self,
        *,
        require_hardening: bool = False,
        require_m4: bool = False,
    ) -> sqlite3.Connection:
        connection = _open_connection(
            self._database_path,
            self._busy_timeout_ms,
            allow_create=False,
            authority_fault_hook=self._fault_injector,
        )
        try:
            migrated = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'schema_migrations'
                """
            ).fetchone()
            business_tables = {
                _row_str(row, "name")
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'table' AND name IN (
                        'runs', 'detections', 'media_purge_attempts',
                        'retention_hold_audit_links', 'retention_scan_cursors',
                        'retention_recovery_cursors'
                    )
                    """
                ).fetchall()
            }
            hardened = migrated is not None and m3_authority_hardening_installed(connection)
            m4_hardened = migrated is not None and m4_hearing_authority_installed(connection)
            migration_versions = {
                _row_int(row, "version")
                for row in connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                ).fetchall()
            }
            legacy_m2_reader = not require_hardening and migration_versions == {1, 2, 3}
            if (
                migrated is None
                or business_tables
                != {
                    "runs",
                    "detections",
                    "media_purge_attempts",
                    "retention_hold_audit_links",
                    "retention_scan_cursors",
                    "retention_recovery_cursors",
                }
                or (not hardened and not legacy_m2_reader)
                or (require_m4 and not m4_hardened)
            ):
                raise MigrationIntegrityError(
                    "SQLite schema is not migrated; run MigrationRunner.apply_all() first"
                )
        except BaseException:
            connection.close()
            raise
        return connection

    @staticmethod
    def _require_retention_limit(limit: int) -> None:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10_000:
            raise ValueError("retention limit must be an integer in [1, 10000]")

    @staticmethod
    def _require_media_sha256(media_sha256: str) -> None:
        if not isinstance(media_sha256, str) or _SHA256.fullmatch(media_sha256) is None:
            raise ValueError("media_sha256 must be a lowercase SHA-256 digest")

    @staticmethod
    def _require_audit_sequence(sequence: int, name: str) -> None:
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise ValueError(f"{name} must be a non-negative integer")

    def _load_media_state(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        media_sha256: str,
    ) -> _MediaState:
        row = connection.execute(
            """
            SELECT ma.*, r.manifest_id AS run_manifest_id
            FROM media_assets AS ma
            JOIN runs AS r ON r.run_id = ma.run_id
            WHERE ma.run_id = ? AND ma.media_sha256 = ?
            """,
            (run_id, media_sha256),
        ).fetchone()
        if row is None:
            raise ContractViolation(f"unknown media in run {run_id}: {media_sha256}")
        manifest_id = _row_str(row, "manifest_id")
        if manifest_id != _row_str(row, "run_manifest_id"):
            raise RepositoryIntegrityError("media manifest differs from its run manifest")
        indexed_sha256 = _row_str(row, "media_sha256")
        if indexed_sha256 != media_sha256 or _SHA256.fullmatch(indexed_sha256) is None:
            raise RepositoryIntegrityError("media index contains an invalid content hash")
        pixel_sha256 = _row_str(row, "pixel_sha256")
        if _SHA256.fullmatch(pixel_sha256) is None:
            raise RepositoryIntegrityError("media pixel hash is invalid")
        try:
            availability = MediaAvailability(_row_str(row, "availability"))
            media_type = MediaType(_row_str(row, "media_type"))
        except ValueError as exc:
            raise RepositoryIntegrityError("media state contains an unknown enum value") from exc
        local_path = _row_optional_str(row, "local_path")
        purged_at = _row_optional_str(row, "purged_at")
        ttl_expires_at = _row_optional_str(row, "ttl_expires_at")
        if ttl_expires_at is not None:
            # Kept only as validated legacy metadata.  M2 eligibility is latest pack use.
            _parse_utc_timestamp(ttl_expires_at, "media ttl_expires_at")
        expected_path = f"{run_id}/frames/{media_sha256}.png"
        if availability in {MediaAvailability.AVAILABLE, MediaAvailability.PURGING}:
            if local_path != expected_path or purged_at is not None:
                raise RepositoryIntegrityError(
                    "available or purging media does not use its canonical locator"
                )
        elif local_path is not None or purged_at is None:
            raise RepositoryIntegrityError("purged media retained a locator or lost purge time")
        if purged_at is not None:
            _parse_utc_timestamp(purged_at, "media purged_at")
        width = _row_int(row, "width")
        height = _row_int(row, "height")
        size_bytes = _row_int(row, "size_bytes")
        if min(width, height, size_bytes) <= 0:
            raise RepositoryIntegrityError("media dimensions and size must be positive")
        encoding_version = _row_str(row, "encoding_version")
        if not encoding_version:
            raise RepositoryIntegrityError("media encoding version cannot be empty")
        return _MediaState(
            run_id=run_id,
            media_sha256=media_sha256,
            manifest_id=manifest_id,
            local_path=local_path,
            availability=availability,
            pixel_sha256=pixel_sha256,
            width=width,
            height=height,
            size_bytes=size_bytes,
            media_type=media_type,
            encoding_version=encoding_version,
            ttl_expires_at=ttl_expires_at,
            purged_at=purged_at,
        )

    @staticmethod
    def _crop_refs_for_media(
        connection: sqlite3.Connection,
        run_id: str,
        media_sha256: str,
    ) -> tuple[ArtifactRef, ...]:
        rows = connection.execute(
            """
            SELECT DISTINCT crop_id
            FROM evidence_pack_crops
            WHERE run_id = ? AND media_sha256 = ?
            ORDER BY crop_id
            """,
            (run_id, media_sha256),
        ).fetchall()
        refs = tuple(
            ArtifactRef(kind=ArtifactKind.CROP, artifact_id=_row_str(row, "crop_id"))
            for row in rows
        )
        if not refs:
            raise RepositoryIntegrityError("retention media has no crop references")
        return refs

    @staticmethod
    def _expirable_media_page(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        cutoff: str,
        limit: int,
        after_sha256: str | None,
    ) -> list[sqlite3.Row]:
        if after_sha256 is None:
            return connection.execute(
                """
                SELECT ma.media_sha256,
                       MAX(ae.recorded_at) AS latest_published_at
                FROM media_assets AS ma
                JOIN evidence_pack_crops AS epc
                  ON epc.run_id = ma.run_id
                 AND epc.media_sha256 = ma.media_sha256
                JOIN evidence_packs AS ep
                  ON ep.run_id = epc.run_id
                 AND ep.pack_id = epc.pack_id
                JOIN audit_entries AS ae
                  ON ae.run_id = ep.run_id
                 AND ae.sequence = ep.created_audit_sequence
                WHERE ma.run_id = ?
                  AND ma.availability = 'AVAILABLE'
                  AND ae.action = 'EVIDENCE_PACK_PUBLISHED'
                GROUP BY ma.media_sha256
                HAVING MAX(ae.recorded_at) <= ?
                ORDER BY ma.media_sha256
                LIMIT ?
                """,
                (run_id, cutoff, limit),
            ).fetchall()
        return connection.execute(
            """
            SELECT ma.media_sha256,
                   MAX(ae.recorded_at) AS latest_published_at
            FROM media_assets AS ma
            JOIN evidence_pack_crops AS epc
              ON epc.run_id = ma.run_id
             AND epc.media_sha256 = ma.media_sha256
            JOIN evidence_packs AS ep
              ON ep.run_id = epc.run_id
             AND ep.pack_id = epc.pack_id
            JOIN audit_entries AS ae
              ON ae.run_id = ep.run_id
             AND ae.sequence = ep.created_audit_sequence
            WHERE ma.run_id = ?
              AND ma.media_sha256 > ?
              AND ma.availability = 'AVAILABLE'
              AND ae.action = 'EVIDENCE_PACK_PUBLISHED'
            GROUP BY ma.media_sha256
            HAVING MAX(ae.recorded_at) <= ?
            ORDER BY ma.media_sha256
            LIMIT ?
            """,
            (run_id, after_sha256, cutoff, limit),
        ).fetchall()

    def _latest_media_publication_at(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        media_sha256: str,
    ) -> datetime:
        rows = connection.execute(
            """
            SELECT DISTINCT ae.*,
                   ep.case_id AS pack_case_id,
                   ep.manifest_id AS pack_manifest_id,
                   ma.manifest_id AS media_manifest_id
            FROM media_assets AS ma
            JOIN evidence_pack_crops AS epc
              ON epc.run_id = ma.run_id
             AND epc.media_sha256 = ma.media_sha256
            JOIN evidence_packs AS ep
              ON ep.run_id = epc.run_id
             AND ep.pack_id = epc.pack_id
            JOIN audit_entries AS ae
              ON ae.run_id = ep.run_id
             AND ae.sequence = ep.created_audit_sequence
            WHERE ma.run_id = ? AND ma.media_sha256 = ?
            ORDER BY ae.recorded_at, ae.sequence
            """,
            (run_id, media_sha256),
        ).fetchall()
        if not rows:
            raise RepositoryIntegrityError("retention media has no audited pack publication")
        timestamps: list[datetime] = []
        for row in rows:
            entry = _audit_entry_from_row(row)
            case_id = _row_str(row, "pack_case_id")
            manifest_id = _row_str(row, "pack_manifest_id")
            if (
                entry.actor != AuditActorRole.EVIDENCE.value
                or entry.action != AuditAction.EVIDENCE_PACK_PUBLISHED
                or entry.object_ref != ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case_id)
                or entry.manifest_id != manifest_id
                or manifest_id != _row_str(row, "media_manifest_id")
            ):
                raise RepositoryIntegrityError(
                    "media pack link is not bound to a valid publication audit"
                )
            timestamps.append(
                _parse_utc_timestamp(entry.recorded_at, "pack publication audit time")
            )
        return max(timestamps)

    def _load_purge_attempt(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        media_sha256: str,
        *,
        intent_audit_sequence: int | None = None,
    ) -> _PurgeAttempt | None:
        if intent_audit_sequence is None:
            row = connection.execute(
                """
                SELECT * FROM media_purge_attempts
                WHERE run_id = ? AND media_sha256 = ?
                """,
                (run_id, media_sha256),
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT * FROM media_purge_attempts
                WHERE run_id = ? AND media_sha256 = ? AND intent_audit_sequence = ?
                """,
                (run_id, media_sha256, intent_audit_sequence),
            ).fetchone()
        if row is None:
            return None
        intent_sequence = _row_int(row, "intent_audit_sequence")
        crop_refs_raw = _row_str(row, "crop_refs_json")
        crop_refs_sha256 = _row_str(row, "crop_refs_sha256")
        try:
            parsed_refs = json.loads(crop_refs_raw)
            if not isinstance(parsed_refs, list):
                raise ValueError
            crop_refs = tuple(ArtifactRef.model_validate(item) for item in parsed_refs)
        except (json.JSONDecodeError, ValidationError, ValueError, TypeError) as exc:
            raise RepositoryIntegrityError("purge attempt crop references are invalid") from exc
        expected_refs_json, expected_refs_sha256 = _artifact_refs_document(crop_refs)
        if crop_refs_raw != expected_refs_json or crop_refs_sha256 != expected_refs_sha256:
            raise RepositoryIntegrityError(
                "purge attempt crop references are not canonical or match-addressed"
            )
        lease = PurgeLease(
            run_id=run_id,
            media_sha256=media_sha256,
            source_relative_path=_row_str(row, "source_relative_path"),
            trash_relative_path=_row_str(row, "trash_relative_path"),
            crop_refs=crop_refs,
            intent_audit_sequence=intent_sequence,
        )
        manifest_id = _row_str(row, "manifest_id")
        policy_version = _row_str(row, "policy_version")
        require_reference_token(policy_version, "persisted retention policy_version")
        expires_before = _row_str(row, "expires_before")
        requested_at = _row_str(row, "requested_at")
        _parse_utc_timestamp(expires_before, "purge cutoff")
        _parse_utc_timestamp(requested_at, "purge requested_at")
        available_state_json = _row_str(row, "available_state_json")
        available_state_sha256 = _row_str(row, "available_state_sha256")
        purging_state_json = _row_str(row, "purging_state_json")
        purging_state_sha256 = _row_str(row, "purging_state_sha256")
        purged_state_json = _row_optional_str(row, "purged_state_json")
        purged_state_sha256 = _row_optional_str(row, "purged_state_sha256")
        self._validate_media_state_document(
            available_state_json,
            available_state_sha256,
            run_id=run_id,
            media_sha256=media_sha256,
            manifest_id=manifest_id,
            availability=MediaAvailability.AVAILABLE,
        )
        self._validate_media_state_document(
            purging_state_json,
            purging_state_sha256,
            run_id=run_id,
            media_sha256=media_sha256,
            manifest_id=manifest_id,
            availability=MediaAvailability.PURGING,
        )
        if (purged_state_json is None) != (purged_state_sha256 is None):
            raise RepositoryIntegrityError("purged state document/hash must be present together")
        if purged_state_json is not None and purged_state_sha256 is not None:
            self._validate_media_state_document(
                purged_state_json,
                purged_state_sha256,
                run_id=run_id,
                media_sha256=media_sha256,
                manifest_id=manifest_id,
                availability=MediaAvailability.PURGED_BY_RETENTION,
            )

        intent_row = connection.execute(
            "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (run_id, intent_sequence),
        ).fetchone()
        if intent_row is None:
            raise RepositoryIntegrityError("purge attempt has no intent audit")
        intent = _audit_entry_from_row(intent_row)
        if (
            intent.actor != AuditActorRole.RETENTION.value
            or intent.action != AuditAction.MEDIA_PURGE_REQUESTED
            or intent.object_ref != ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=media_sha256)
            or intent.manifest_id != manifest_id
            or intent.before_sha256 != available_state_sha256
            or intent.after_sha256 != purging_state_sha256
            or intent.recorded_at != requested_at
        ):
            raise RepositoryIntegrityError("purge attempt is not bound to its intent audit")

        completion_sequence = _row_optional_int(row, "completion_audit_sequence")
        completion_value = _row_optional_int(row, "completion_recovered")
        completion_recovered = None if completion_value is None else bool(completion_value)
        if completion_value not in {None, 0, 1}:
            raise RepositoryIntegrityError("purge completion recovery flag is invalid")
        if completion_sequence is not None:
            completion_row = connection.execute(
                "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
                (run_id, completion_sequence),
            ).fetchone()
            if completion_row is None:
                raise RepositoryIntegrityError("purge completion has no audit entry")
            completion = _audit_entry_from_row(completion_row)
            if (
                completion.actor != AuditActorRole.RETENTION.value
                or completion.action != AuditAction.PURGED_BY_RETENTION
                or completion.object_ref
                != ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=media_sha256)
                or completion.manifest_id != manifest_id
                or completion.before_sha256 != purging_state_sha256
                or completion.after_sha256 != purged_state_sha256
            ):
                raise RepositoryIntegrityError("purge attempt is not bound to its completion audit")
        cleanup_acked_at = _row_optional_str(row, "cleanup_acked_at")
        if cleanup_acked_at is not None:
            _parse_utc_timestamp(cleanup_acked_at, "purge cleanup_acked_at")
        status = _row_str(row, "status")
        expected_matrix = {
            "PURGING": (False, False, False),
            "PURGED_CLEANUP_PENDING": (True, True, False),
            "TRASH_CLEANED": (True, True, True),
        }
        expected = expected_matrix.get(status)
        observed = (
            purged_state_json is not None,
            completion_sequence is not None and completion_recovered is not None,
            cleanup_acked_at is not None,
        )
        if expected is None or observed != expected:
            raise RepositoryIntegrityError("purge attempt status matrix is inconsistent")
        return _PurgeAttempt(
            lease=lease,
            manifest_id=manifest_id,
            policy_version=policy_version,
            expires_before=expires_before,
            requested_at=requested_at,
            available_state_json=available_state_json,
            available_state_sha256=available_state_sha256,
            purging_state_json=purging_state_json,
            purging_state_sha256=purging_state_sha256,
            purged_state_json=purged_state_json,
            purged_state_sha256=purged_state_sha256,
            completion_audit_sequence=completion_sequence,
            completion_recovered=completion_recovered,
            cleanup_acked_at=cleanup_acked_at,
            status=status,
        )

    @staticmethod
    def _validate_media_state_document(
        raw: str,
        expected_sha256: str,
        *,
        run_id: str,
        media_sha256: str,
        manifest_id: str,
        availability: MediaAvailability,
    ) -> None:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RepositoryIntegrityError("media state document is invalid JSON") from exc
        canonical, actual_sha256 = _payload_document(payload)
        if canonical != raw or actual_sha256 != expected_sha256:
            raise RepositoryIntegrityError(
                "media state document is not canonical or match-addressed"
            )
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "run_id",
            "media_sha256",
            "manifest_id",
            "local_path",
            "availability",
            "pixel_sha256",
            "width",
            "height",
            "size_bytes",
            "media_type",
            "encoding_version",
            "ttl_expires_at",
            "purged_at",
        }:
            raise RepositoryIntegrityError("media state document has an invalid field set")
        if (
            payload["schema_version"] != _MEDIA_STATE_SCHEMA_VERSION
            or payload["run_id"] != run_id
            or payload["media_sha256"] != media_sha256
            or payload["manifest_id"] != manifest_id
            or payload["availability"] != availability.value
        ):
            raise RepositoryIntegrityError("media state document scope or state is inconsistent")

    @staticmethod
    def _require_attempt_matches_state(
        attempt: _PurgeAttempt,
        state: _MediaState,
        *,
        purged: bool,
    ) -> None:
        state_json, state_sha256 = state.document()
        expected_json = attempt.purged_state_json if purged else attempt.purging_state_json
        expected_sha256 = attempt.purged_state_sha256 if purged else attempt.purging_state_sha256
        if state_json != expected_json or state_sha256 != expected_sha256:
            raise RepositoryIntegrityError(
                "current media state does not match its persisted purge transition"
            )

    def _next_recovery_attempt(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        after_sequence: int | None,
    ) -> _PurgeAttempt | None:
        if after_sequence is None:
            row = connection.execute(
                """
                SELECT media_sha256, intent_audit_sequence
                FROM media_purge_attempts
                WHERE run_id = ?
                  AND status IN ('PURGING', 'PURGED_CLEANUP_PENDING')
                ORDER BY intent_audit_sequence
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT media_sha256, intent_audit_sequence
                FROM media_purge_attempts
                WHERE run_id = ?
                  AND status IN ('PURGING', 'PURGED_CLEANUP_PENDING')
                  AND intent_audit_sequence > ?
                ORDER BY intent_audit_sequence
                LIMIT 1
                """,
                (run_id, after_sequence),
            ).fetchone()
        if row is None:
            return None
        media_sha256 = _row_str(row, "media_sha256")
        intent_audit_sequence = _row_int(row, "intent_audit_sequence")
        attempt = self._load_purge_attempt(
            connection,
            run_id,
            media_sha256,
            intent_audit_sequence=intent_audit_sequence,
        )
        if attempt is None or attempt.status not in {
            "PURGING",
            "PURGED_CLEANUP_PENDING",
        }:
            raise RepositoryIntegrityError("purge recovery scheduler index is inconsistent")
        return attempt

    @staticmethod
    def _retained_result(
        run_id: str,
        media_sha256: str,
        crop_refs: tuple[ArtifactRef, ...],
        reason_code: PurgeReasonCode,
        *,
        hold_kinds: tuple[RetentionHoldKind, ...] = (),
    ) -> PurgeItemResult:
        return PurgeItemResult(
            run_id=run_id,
            media_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=media_sha256),
            crop_refs=crop_refs,
            disposition=PurgeDisposition.RETAINED,
            reason_code=reason_code,
            previous_availability=MediaAvailability.AVAILABLE,
            current_availability=MediaAvailability.AVAILABLE,
            hold_kinds=hold_kinds,
        )

    @staticmethod
    def _recovery_required_result(attempt: _PurgeAttempt) -> PurgeItemResult:
        return PurgeItemResult(
            run_id=attempt.lease.run_id,
            media_ref=ArtifactRef(
                kind=ArtifactKind.MEDIA,
                artifact_id=attempt.lease.media_sha256,
            ),
            crop_refs=attempt.lease.crop_refs,
            disposition=PurgeDisposition.RECOVERY_REQUIRED,
            reason_code=PurgeReasonCode.PURGE_ALREADY_IN_PROGRESS,
            previous_availability=MediaAvailability.PURGING,
            current_availability=MediaAvailability.PURGING,
            audit_sequences=(attempt.lease.intent_audit_sequence,),
        )

    @staticmethod
    def _completed_purge_result(attempt: _PurgeAttempt) -> PurgeItemResult:
        if attempt.completion_audit_sequence is None or attempt.completion_recovered is None:
            raise RepositoryIntegrityError("completed purge attempt lacks completion facts")
        recovered = attempt.completion_recovered
        return PurgeItemResult(
            run_id=attempt.lease.run_id,
            media_ref=ArtifactRef(
                kind=ArtifactKind.MEDIA,
                artifact_id=attempt.lease.media_sha256,
            ),
            crop_refs=attempt.lease.crop_refs,
            disposition=PurgeDisposition.PURGED,
            reason_code=(
                PurgeReasonCode.RECOVERED_PURGE_COMPLETED
                if recovered
                else PurgeReasonCode.EXPIRED_AND_PURGED
            ),
            previous_availability=(
                MediaAvailability.PURGING if recovered else MediaAvailability.AVAILABLE
            ),
            current_availability=MediaAvailability.PURGED_BY_RETENTION,
            audit_sequences=(
                attempt.lease.intent_audit_sequence,
                attempt.completion_audit_sequence,
            ),
        )

    @staticmethod
    def _already_purged_result(attempt: _PurgeAttempt) -> PurgeItemResult:
        audit_sequences = [attempt.lease.intent_audit_sequence]
        if attempt.completion_audit_sequence is not None:
            audit_sequences.append(attempt.completion_audit_sequence)
        return PurgeItemResult(
            run_id=attempt.lease.run_id,
            media_ref=ArtifactRef(
                kind=ArtifactKind.MEDIA,
                artifact_id=attempt.lease.media_sha256,
            ),
            crop_refs=attempt.lease.crop_refs,
            disposition=PurgeDisposition.RETAINED,
            reason_code=PurgeReasonCode.ALREADY_PURGED,
            previous_availability=MediaAvailability.PURGED_BY_RETENTION,
            current_availability=MediaAvailability.PURGED_BY_RETENTION,
            audit_sequences=tuple(audit_sequences),
        )

    def _active_hold_kinds(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        media_sha256: str,
        crop_refs: tuple[ArtifactRef, ...],
    ) -> tuple[RetentionHoldKind, ...]:
        crop_ids = {ref.artifact_id for ref in crop_refs}
        rows = connection.execute(
            """
            SELECT hold_id
            FROM retention_holds
            WHERE run_id = ? AND active = 1
              AND (
                  (target_kind = 'MEDIA' AND target_id = ?)
                  OR (
                      target_kind = 'CROP'
                      AND EXISTS (
                          SELECT 1 FROM evidence_pack_crops AS epc
                          WHERE epc.run_id = retention_holds.run_id
                            AND epc.media_sha256 = ?
                            AND epc.crop_id = retention_holds.target_id
                      )
                  )
              )
            ORDER BY hold_id
            """,
            (run_id, media_sha256, media_sha256),
        ).fetchall()
        kinds: set[RetentionHoldKind] = set()
        for row in rows:
            loaded = self._load_retention_hold(
                connection,
                run_id,
                _row_str(row, "hold_id"),
                required=True,
            )
            assert loaded is not None
            hold, active, _, _ = loaded
            if not active:
                raise RepositoryIntegrityError("active hold index selected a released hold")
            if hold.target_ref.ref.kind == ArtifactKind.CROP and (
                hold.target_ref.ref.artifact_id not in crop_ids
            ):
                raise RepositoryIntegrityError("crop hold index selected another media object")
            kinds.add(hold.kind)
        return tuple(sorted(kinds, key=lambda item: item.value))

    def _load_retention_hold(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        hold_id: str,
        *,
        required: bool,
    ) -> tuple[RetentionHold, bool, int, int | None] | None:
        row = connection.execute(
            """
            SELECT rh.*, links.created_audit_sequence, links.released_audit_sequence
            FROM retention_holds AS rh
            LEFT JOIN retention_hold_audit_links AS links
              ON links.run_id = rh.run_id AND links.hold_id = rh.hold_id
            WHERE rh.run_id = ? AND rh.hold_id = ?
            """,
            (run_id, hold_id),
        ).fetchone()
        if row is None:
            if required:
                raise ContractViolation(f"unknown retention hold in run {run_id}: {hold_id}")
            return None
        hold_raw = _row_str(row, "hold_json")
        try:
            hold = RetentionHold.model_validate_json(hold_raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored retention hold contract is invalid") from exc
        _verify_document(hold_raw, _row_str(row, "document_sha256"), hold)
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "hold_id"),
            _row_str(row, "target_kind"),
            _row_str(row, "target_id"),
            _row_str(row, "hold_kind"),
            _row_str(row, "owner_kind"),
            _row_str(row, "owner_id"),
            _row_str(row, "manifest_id"),
            _row_str(row, "policy_version"),
            _row_optional_str(row, "reason_code"),
        )
        expected = (
            hold.run_id,
            hold.hold_id,
            hold.target_ref.ref.kind.value,
            hold.target_ref.ref.artifact_id,
            hold.kind.value,
            hold.owner_ref.ref.kind.value,
            hold.owner_ref.ref.artifact_id,
            hold.manifest_id,
            hold.policy_version,
            hold.reason_code,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("retention hold index differs from its document")
        active_value = _row_int(row, "active")
        if active_value not in {0, 1}:
            raise RepositoryIntegrityError("retention hold active flag is invalid")
        active = bool(active_value)
        created_sequence = _row_optional_int(row, "created_audit_sequence")
        released_sequence = _row_optional_int(row, "released_audit_sequence")
        if created_sequence is None:
            raise RepositoryIntegrityError("retention hold has no creation audit link")
        active_json, active_sha256 = _retention_hold_state_document(hold, active=True)
        if active_json != hold_raw:
            raise RepositoryIntegrityError("retention hold active state is not canonical")
        created_row = connection.execute(
            "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (run_id, created_sequence),
        ).fetchone()
        if created_row is None:
            raise RepositoryIntegrityError("retention hold has no creation audit")
        created = _audit_entry_from_row(created_row)
        if (
            created.actor != AuditActorRole.RETENTION.value
            or created.action != AuditAction.RETENTION_HOLD_CREATED
            or created.object_ref != hold.target_ref.ref
            or created.before_sha256 is not None
            or created.after_sha256 != active_sha256
            or created.manifest_id != hold.manifest_id
        ):
            raise RepositoryIntegrityError("retention hold is not bound to its creation audit")
        if active:
            if released_sequence is not None:
                raise RepositoryIntegrityError("active retention hold has a release audit")
        else:
            if released_sequence is None:
                raise RepositoryIntegrityError("released retention hold has no release audit")
            released_row = connection.execute(
                "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
                (run_id, released_sequence),
            ).fetchone()
            if released_row is None:
                raise RepositoryIntegrityError("retention hold release audit is missing")
            released = _audit_entry_from_row(released_row)
            _, inactive_sha256 = _retention_hold_state_document(hold, active=False)
            if (
                released.actor != AuditActorRole.RETENTION.value
                or released.action != AuditAction.RETENTION_HOLD_RELEASED
                or released.object_ref != hold.target_ref.ref
                or released.before_sha256 != active_sha256
                or released.after_sha256 != inactive_sha256
                or released.manifest_id != hold.manifest_id
            ):
                raise RepositoryIntegrityError("retention hold is not bound to its release audit")
        return hold, active, created_sequence, released_sequence

    def _require_hold_target_and_owner(
        self,
        connection: sqlite3.Connection,
        hold: RetentionHold,
    ) -> None:
        media_ids: tuple[str, ...]
        if hold.target_ref.ref.kind == ArtifactKind.MEDIA:
            media_ids = (hold.target_ref.ref.artifact_id,)
        else:
            rows = connection.execute(
                """
                SELECT DISTINCT media_sha256
                FROM evidence_pack_crops
                WHERE run_id = ? AND crop_id = ?
                ORDER BY media_sha256
                """,
                (hold.run_id, hold.target_ref.ref.artifact_id),
            ).fetchall()
            media_ids = tuple(_row_str(row, "media_sha256") for row in rows)
            if not media_ids:
                raise ContractViolation("retention hold target crop does not exist in its run")
        for media_sha256 in media_ids:
            state = self._load_media_state(connection, hold.run_id, media_sha256)
            if state.availability != MediaAvailability.AVAILABLE:
                raise ConcurrentModification(
                    "retention hold cannot be created after media purge intent"
                )
            if self._load_purge_attempt(connection, hold.run_id, media_sha256) is not None:
                raise RepositoryIntegrityError(
                    "available hold target unexpectedly has a purge attempt"
                )

        if hold.owner_ref.ref.kind == ArtifactKind.CASE:
            row = connection.execute(
                """
                SELECT manifest_id FROM cases WHERE run_id = ? AND case_id = ?
                """,
                (hold.run_id, hold.owner_ref.ref.artifact_id),
            ).fetchone()
            if row is None:
                raise ContractViolation("manual retention hold owner case does not exist")
            if _row_str(row, "manifest_id") != hold.manifest_id:
                raise ManifestMismatch("retention hold owner case uses another manifest")
        # APPEAL and DATASET owner tables arrive in M5.  Their typed kind, anonymous
        # token, run scope, and manifest binding are still fully validated by M2's
        # immutable RetentionHold document; existence cannot be invented in M2.

    def _load_run_manifest(self, connection: sqlite3.Connection, run_id: str) -> RunManifest:
        row = connection.execute(
            """
            SELECT rm.manifest_id, rm.schema_version,
                   rm.document_json, rm.document_sha256
            FROM runs AS r
            JOIN run_manifests AS rm ON rm.manifest_id = r.manifest_id
            WHERE r.run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            raise ContractViolation(f"unknown run_id: {run_id}")
        raw = _row_str(row, "document_json")
        manifest = RunManifest.model_validate_json(raw)
        _verify_document(raw, _row_str(row, "document_sha256"), manifest)
        if manifest.manifest_id != _row_str(
            row, "manifest_id"
        ) or manifest.schema_version != _row_str(row, "schema_version"):
            raise RepositoryIntegrityError(
                "manifest index columns do not match its canonical document"
            )
        return manifest

    def _load_frame(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        frame_id: str,
    ) -> FrameRef | None:
        row = connection.execute(
            """
            SELECT frame_id, manifest_id, camera_id, stream_id, frame_index,
                   fps_num, fps_den, width, height, content_sha256,
                   document_json, document_sha256
            FROM frames WHERE run_id = ? AND frame_id = ?
            """,
            (run_id, frame_id),
        ).fetchone()
        if row is None:
            return None
        raw = _row_str(row, "document_json")
        try:
            frame = FrameRef.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                f"frame {frame_id} has an invalid stored contract document"
            ) from exc
        _verify_document(raw, _row_str(row, "document_sha256"), frame)
        manifest = self._load_run_manifest(connection, run_id)
        indexed = (
            _row_str(row, "frame_id"),
            _row_str(row, "manifest_id"),
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
            manifest.manifest_id,
            frame.camera_id,
            frame.stream_id,
            frame.frame_index,
            frame.fps_num,
            frame.fps_den,
            frame.width,
            frame.height,
            frame.content_sha256,
        )
        if indexed != expected or frame.frame_id != frame_id:
            raise RepositoryIntegrityError(
                "frame index columns do not match its canonical document"
            )
        stream = next(
            (
                item
                for item in manifest.streams
                if (item.camera_id, item.stream_id) == (frame.camera_id, frame.stream_id)
            ),
            None,
        )
        if manifest.streams and (
            stream is None
            or frame.fps_num != stream.fps_num
            or frame.fps_den != stream.fps_den
            or frame.width != stream.width
            or frame.height != stream.height
            or frame.frame_index >= stream.frame_count
        ):
            raise RepositoryIntegrityError("stored frame differs from its pinned stream manifest")
        return frame

    def _load_detection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        detection_id: str,
    ) -> Detection | None:
        row = connection.execute(
            """
            SELECT detection_id, frame_id, manifest_id,
                   detector_manifest_id, label,
                   document_json, document_sha256
            FROM detections WHERE run_id = ? AND detection_id = ?
            """,
            (run_id, detection_id),
        ).fetchone()
        if row is None:
            return None
        raw = _row_str(row, "document_json")
        try:
            detection = Detection.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                f"detection {detection_id} has an invalid stored contract document"
            ) from exc
        _verify_document(raw, _row_str(row, "document_sha256"), detection)
        manifest = self._load_run_manifest(connection, run_id)
        detector_manifest_id = manifest.models["detector"].model_manifest_id
        if (
            detection.detection_id != detection_id
            or detection.detection_id != _row_str(row, "detection_id")
            or detection.frame_id != _row_str(row, "frame_id")
            or manifest.manifest_id != _row_str(row, "manifest_id")
            or detection.model_manifest_id != _row_str(row, "detector_manifest_id")
            or detection.model_manifest_id != detector_manifest_id
            or detection.label != _row_str(row, "label")
        ):
            raise RepositoryIntegrityError(
                "detection index or manifest binding does not match its canonical document"
            )
        frame = self._load_frame(connection, run_id, detection.frame_id)
        if frame is None:
            raise RepositoryIntegrityError("detection references a missing frame")
        try:
            FrameBundle(frame=frame, detections=(detection,))
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                "detection geometry or track binding is invalid for its stored frame"
            ) from exc
        return detection

    def _head(self, connection: SQLiteReadSession, run_id: str) -> AuditHead:
        row = connection.execute(
            """
            SELECT manifest_id, revision, audit_head_sequence, audit_head_hash
            FROM runs WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            raise ContractViolation(f"unknown run_id: {run_id}")
        run_revision = _row_int(row, "revision")
        sequence = _row_int(row, "audit_head_sequence")
        entry_hash = _row_str(row, "audit_head_hash")
        if run_revision != sequence + 1 or ((sequence == -1) != (entry_hash == AUDIT_GENESIS_HASH)):
            raise RepositoryIntegrityError("run revision and audit head are inconsistent")
        return AuditHead(
            run_id=run_id,
            manifest_id=_row_str(row, "manifest_id"),
            run_revision=run_revision,
            sequence=sequence,
            entry_hash=entry_hash,
        )

    def _validated_head(self, connection: SQLiteReadSession, run_id: str) -> AuditHead:
        head = self._head(connection, run_id)
        rows = connection.execute(
            """
            SELECT * FROM audit_entries
            WHERE run_id = ? ORDER BY sequence
            """,
            (run_id,),
        ).fetchall()
        entries = [_audit_entry_from_row(row) for row in rows]
        report = validate_audit_chain(
            tuple(entries),
            expected_run_id=run_id,
            expected_manifest_id=head.manifest_id,
            expected_head_sequence=head.sequence,
            expected_head_hash=head.entry_hash,
        )
        if not report.passed:
            raise RepositoryIntegrityError(
                "cannot append to an invalid audit chain at sequence "
                f"{report.failure_sequence}: {report.failure_reason}"
            )
        return head

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        head: AuditHead,
        *,
        action: AuditAction,
        object_ref: ArtifactRef,
        before_sha256: str | None,
        after_sha256: str | None,
        actor: AuditActorRole = AuditActorRole.EVIDENCE,
        recorded_at: str | None = None,
    ) -> tuple[AuditEntry, AuditHead]:
        entry = AuditEntryDraft(
            run_id=head.run_id,
            sequence=head.sequence + 1,
            actor=actor.value,
            action=action,
            object_ref=object_ref,
            before_sha256=before_sha256,
            after_sha256=after_sha256,
            manifest_id=head.manifest_id,
            recorded_at=recorded_at or _utc_timestamp(self._clock),
            prev_entry_hash=head.entry_hash,
        ).seal()
        entry_json, entry_sha256 = _document(entry)
        connection.execute(
            """
            INSERT INTO audit_entries(
                run_id, sequence, manifest_id, actor, action,
                object_kind, object_id, before_sha256, after_sha256,
                recorded_at, prev_entry_hash, entry_hash,
                entry_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.run_id,
                entry.sequence,
                entry.manifest_id,
                entry.actor,
                entry.action.value,
                entry.object_ref.kind.value,
                entry.object_ref.artifact_id,
                entry.before_sha256,
                entry.after_sha256,
                entry.recorded_at,
                entry.prev_entry_hash,
                entry.entry_hash,
                entry_json,
                entry_sha256,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE runs
            SET revision = ?, audit_head_sequence = ?, audit_head_hash = ?
            WHERE run_id = ? AND revision = ?
              AND audit_head_sequence = ? AND audit_head_hash = ?
            """,
            (
                head.run_revision + 1,
                entry.sequence,
                entry.entry_hash,
                head.run_id,
                head.run_revision,
                head.sequence,
                head.entry_hash,
            ),
        )
        if cursor.rowcount != 1:
            raise ConcurrentModification("run audit head changed during transaction")
        return entry, AuditHead(
            run_id=head.run_id,
            manifest_id=head.manifest_id,
            run_revision=head.run_revision + 1,
            sequence=entry.sequence,
            entry_hash=entry.entry_hash,
        )

    def _load_case(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        case_id: str,
    ) -> _LoadedCase:
        row = connection.execute(
            """
            SELECT c.current_revision, c.status, c.manifest_id,
                   c.latest_pack_id, c.latest_pack_version,
                   c.event_id, c.event_json, c.event_sha256,
                   c.created_audit_sequence,
                   cv.status AS case_version_status,
                   cv.case_json, cv.document_sha256, cv.audit_sequence,
                   (
                       SELECT MAX(cv2.revision)
                       FROM case_versions AS cv2
                       WHERE cv2.run_id = c.run_id AND cv2.case_id = c.case_id
                   ) AS max_revision
            FROM cases AS c
            JOIN case_versions AS cv
              ON cv.run_id = c.run_id
             AND cv.case_id = c.case_id
             AND cv.revision = c.current_revision
            WHERE c.run_id = ? AND c.case_id = ?
            """,
            (run_id, case_id),
        ).fetchone()
        if row is None:
            raise ContractViolation(f"unknown case in run {run_id}: {case_id}")
        case, document_sha256 = _case_version_from_row(
            row,
            run_id=run_id,
            case_id=case_id,
            json_key="case_json",
            sha256_key="document_sha256",
            status_key="case_version_status",
        )
        revision = _row_int(row, "current_revision")
        if revision != _row_int(row, "max_revision"):
            raise RepositoryIntegrityError("case head does not select its latest immutable version")
        event_raw = _row_str(row, "event_json")
        persisted_event = CandidateEvent.model_validate_json(event_raw)
        _verify_document(event_raw, _row_str(row, "event_sha256"), persisted_event)
        manifest = self._load_run_manifest(connection, run_id)
        if persisted_event.rule_version != manifest.rule_version:
            raise RepositoryIntegrityError("case event rule_version differs from its run manifest")
        if (
            case.run_id != run_id
            or case.case_id != case_id
            or case.status.value != _row_str(row, "status")
            or case.manifest_id != _row_str(row, "manifest_id")
            or case.event != persisted_event
            or case.event.event_id != _row_str(row, "event_id")
        ):
            raise RepositoryIntegrityError("case head does not match its immutable version")
        latest_pack_id = _row_optional_str(row, "latest_pack_id")
        latest_pack_version = _row_optional_int(row, "latest_pack_version")
        expected_latest_pack = (
            (case.evidence_packs[-1].pack_id, case.evidence_packs[-1].version)
            if case.evidence_packs
            else (None, None)
        )
        if (latest_pack_id, latest_pack_version) != expected_latest_pack:
            raise RepositoryIntegrityError("case head does not identify its latest evidence pack")

        creation_audit_row = connection.execute(
            """
            SELECT ae.*, cv.status AS created_case_status,
                   cv.case_json AS created_case_json,
                   cv.document_sha256 AS created_case_sha256
            FROM case_versions AS cv
            JOIN audit_entries AS ae
              ON ae.run_id = cv.run_id AND ae.sequence = cv.audit_sequence
            WHERE cv.run_id = ? AND cv.case_id = ? AND cv.revision = 1
              AND cv.audit_sequence = ?
            """,
            (run_id, case_id, _row_int(row, "created_audit_sequence")),
        ).fetchone()
        if creation_audit_row is None:
            raise RepositoryIntegrityError("case has no creation audit entry")
        _, created_case_sha256 = _case_version_from_row(
            creation_audit_row,
            run_id=run_id,
            case_id=case_id,
            json_key="created_case_json",
            sha256_key="created_case_sha256",
            status_key="created_case_status",
        )
        creation_audit = _audit_entry_from_row(creation_audit_row)
        if (
            creation_audit.action != AuditAction.CASE_CREATED
            or creation_audit.object_ref != ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case_id)
            or creation_audit.before_sha256 is not None
            or creation_audit.after_sha256 != created_case_sha256
        ):
            raise RepositoryIntegrityError("case is not bound to its creation audit entry")

        audit_row = connection.execute(
            "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (run_id, _row_int(row, "audit_sequence")),
        ).fetchone()
        if audit_row is None:
            raise RepositoryIntegrityError("case version has no audit entry")
        audit = _audit_entry_from_row(audit_row)
        expected_action = AuditAction.CASE_CREATED
        expected_object_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case_id)
        previous_sha256: str | None = None
        if revision > 1:
            previous = connection.execute(
                """
                SELECT status AS previous_case_status,
                       case_json AS previous_case_json,
                       document_sha256 AS previous_case_sha256
                FROM case_versions
                WHERE run_id = ? AND case_id = ? AND revision = ?
                """,
                (run_id, case_id, revision - 1),
            ).fetchone()
            if previous is None:
                raise RepositoryIntegrityError("case version history is not contiguous")
            previous_case, previous_sha256 = _case_version_from_row(
                previous,
                run_id=run_id,
                case_id=case_id,
                json_key="previous_case_json",
                sha256_key="previous_case_sha256",
                status_key="previous_case_status",
            )
            transition_audit = case_transition_audit(previous_case, case)
            if transition_audit is None:
                raise RepositoryIntegrityError(
                    "case version contains an unsupported or inconsistent state transition"
                )
            expected_action, expected_object_ref = transition_audit
        if (
            audit.action != expected_action
            or audit.object_ref != expected_object_ref
            or audit.before_sha256 != previous_sha256
            or audit.after_sha256 != document_sha256
        ):
            raise RepositoryIntegrityError("case version is not bound to its audit entry")
        materialized_packs = tuple(
            self._load_pack(connection, run_id, pack.pack_id) for pack in case.evidence_packs
        )
        if materialized_packs != case.evidence_packs:
            case = case.model_copy(update={"evidence_packs": materialized_packs})
        return _LoadedCase(
            snapshot=CaseSnapshot(case=case, revision=revision),
            document_sha256=document_sha256,
            audit_action=audit.action,
        )

    def _load_case_revision(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        case_id: str,
        revision: int,
    ) -> _LoadedCase:
        """Load and audit one immutable historical Case revision.

        The current head is validated first so a historical row cannot be read
        from a detached, truncated, or non-canonical Case history.
        """

        if not isinstance(revision, int) or isinstance(revision, bool) or revision <= 0:
            raise ValueError("source_case_revision must be a positive integer")
        current = self._load_case(connection, run_id, case_id)
        if revision == current.snapshot.revision:
            return current
        if revision > current.snapshot.revision:
            raise ContractViolation(f"unknown Case revision in run {run_id}: {case_id}@{revision}")

        row = connection.execute(
            """
            SELECT revision, status AS case_version_status,
                   case_json, document_sha256, audit_sequence
            FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (run_id, case_id, revision),
        ).fetchone()
        if row is None or _row_int(row, "revision") != revision:
            raise RepositoryIntegrityError("Case version history is not contiguous")
        case, document_sha256 = _case_version_from_row(
            row,
            run_id=run_id,
            case_id=case_id,
            json_key="case_json",
            sha256_key="document_sha256",
            status_key="case_version_status",
        )
        current_case = current.snapshot.case
        if (
            case.run_id != run_id
            or case.case_id != case_id
            or case.manifest_id != current_case.manifest_id
            or case.event != current_case.event
        ):
            raise RepositoryIntegrityError("historical Case revision differs from its head scope")

        audit_row = connection.execute(
            "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (run_id, _row_int(row, "audit_sequence")),
        ).fetchone()
        if audit_row is None:
            raise RepositoryIntegrityError("historical Case version has no audit entry")
        audit = _audit_entry_from_row(audit_row)
        expected_action = AuditAction.CASE_CREATED
        expected_object_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case_id)
        previous_sha256: str | None = None
        if revision > 1:
            previous_row = connection.execute(
                """
                SELECT status AS previous_case_status,
                       case_json AS previous_case_json,
                       document_sha256 AS previous_case_sha256
                FROM case_versions
                WHERE run_id = ? AND case_id = ? AND revision = ?
                """,
                (run_id, case_id, revision - 1),
            ).fetchone()
            if previous_row is None:
                raise RepositoryIntegrityError("Case version history is not contiguous")
            previous_case, previous_sha256 = _case_version_from_row(
                previous_row,
                run_id=run_id,
                case_id=case_id,
                json_key="previous_case_json",
                sha256_key="previous_case_sha256",
                status_key="previous_case_status",
            )
            transition_audit = case_transition_audit(previous_case, case)
            if transition_audit is None:
                raise RepositoryIntegrityError(
                    "historical Case version contains an unsupported state transition"
                )
            expected_action, expected_object_ref = transition_audit
        if (
            audit.action != expected_action
            or audit.object_ref != expected_object_ref
            or audit.before_sha256 != previous_sha256
            or audit.after_sha256 != document_sha256
        ):
            raise RepositoryIntegrityError(
                "historical Case version is not bound to its audit entry"
            )

        materialized_packs = tuple(
            self._load_pack(connection, run_id, pack.pack_id) for pack in case.evidence_packs
        )
        if materialized_packs != case.evidence_packs:
            raise RepositoryIntegrityError(
                "historical Case evidence packs differ from their immutable documents"
            )
        return _LoadedCase(
            snapshot=CaseSnapshot(case=case, revision=revision),
            document_sha256=document_sha256,
            audit_action=audit.action,
        )

    def _load_pack(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        pack_id: str,
    ) -> EvidencePack:
        row = connection.execute(
            """
            SELECT pack_json, document_sha256, case_id, manifest_id, version,
                   complete, pack_input_sha256, closure_input_sha256,
                   created_audit_sequence
            FROM evidence_packs WHERE run_id = ? AND pack_id = ?
            """,
            (run_id, pack_id),
        ).fetchone()
        if row is None:
            raise ContractViolation(f"unknown evidence pack in run {run_id}: {pack_id}")
        raw = _row_str(row, "pack_json")
        pack = EvidencePack.model_validate_json(raw)
        _verify_document(raw, _row_str(row, "document_sha256"), pack)
        if (
            pack.run_id != run_id
            or pack.pack_id != pack_id
            or pack.case_id != _row_str(row, "case_id")
            or pack.manifest_id != _row_str(row, "manifest_id")
            or pack.version != _row_int(row, "version")
            or int(pack.complete) != _row_int(row, "complete")
            or pack.pack_input_sha256 != _row_str(row, "pack_input_sha256")
            or pack.closure_input_sha256 != _row_str(row, "closure_input_sha256")
        ):
            raise RepositoryIntegrityError("pack index columns do not match its document")

        created_audit_sequence = _row_int(row, "created_audit_sequence")
        publication_row = connection.execute(
            """
            SELECT ae.*, cv.revision,
                   cv.status AS publication_case_status,
                   cv.case_json AS publication_case_json,
                   cv.document_sha256 AS publication_case_sha256
            FROM case_versions AS cv
            JOIN audit_entries AS ae
              ON ae.run_id = cv.run_id AND ae.sequence = cv.audit_sequence
            WHERE cv.run_id = ? AND cv.case_id = ? AND cv.audit_sequence = ?
            """,
            (run_id, pack.case_id, created_audit_sequence),
        ).fetchone()
        if publication_row is None:
            raise RepositoryIntegrityError("evidence pack has no publishing case version")
        publication_case, publication_sha256 = _case_version_from_row(
            publication_row,
            run_id=run_id,
            case_id=pack.case_id,
            json_key="publication_case_json",
            sha256_key="publication_case_sha256",
            status_key="publication_case_status",
        )
        publication_audit = _audit_entry_from_row(publication_row)
        prior_row = connection.execute(
            """
            SELECT status AS prior_case_status,
                   case_json AS prior_case_json,
                   document_sha256 AS prior_case_sha256
            FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (run_id, pack.case_id, _row_int(publication_row, "revision") - 1),
        ).fetchone()
        if prior_row is None:
            raise RepositoryIntegrityError("publishing case version has no predecessor")
        _, prior_sha256 = _case_version_from_row(
            prior_row,
            run_id=run_id,
            case_id=pack.case_id,
            json_key="prior_case_json",
            sha256_key="prior_case_sha256",
            status_key="prior_case_status",
        )
        if (
            not publication_case.evidence_packs
            or publication_case.evidence_packs[-1] != pack
            or publication_audit.action != AuditAction.EVIDENCE_PACK_PUBLISHED
            or publication_audit.object_ref
            != ArtifactRef(kind=ArtifactKind.CASE, artifact_id=pack.case_id)
            or publication_audit.after_sha256 != publication_sha256
            or publication_audit.before_sha256 != prior_sha256
        ):
            raise RepositoryIntegrityError("evidence pack is not bound to its publishing audit")
        media_rows = connection.execute(
            """
            SELECT epc.crop_id, epc.media_sha256, epc.role, epc.ordinal,
                   epc.crop_json, epc.document_sha256 AS crop_document_sha256,
                   ma.manifest_id AS media_manifest_id,
                   ma.local_path, ma.availability, ma.pixel_sha256,
                   ma.width, ma.height, ma.size_bytes, ma.media_type,
                   ma.encoding_version
            FROM evidence_pack_crops AS epc
            JOIN media_assets AS ma
              ON ma.run_id = epc.run_id AND ma.media_sha256 = epc.media_sha256
            WHERE epc.run_id = ? AND epc.pack_id = ?
            """,
            (run_id, pack_id),
        ).fetchall()
        expected_crops = {
            (role, ordinal): crop
            for role, crops in (
                ("panorama", pack.panorama_crops),
                ("subject", pack.subject_crops),
                ("focus", pack.focus_crops),
                ("temporal", pack.temporal_crops),
            )
            for ordinal, crop in enumerate(crops)
        }
        locations: dict[str, tuple[object, str]] = {}
        for media_row in media_rows:
            role_and_ordinal = (
                _row_str(media_row, "role"),
                _row_int(media_row, "ordinal"),
            )
            expected_crop = expected_crops.get(role_and_ordinal)
            if expected_crop is None:
                raise RepositoryIntegrityError("pack crop link has an unknown role or ordinal")
            crop_raw = _row_str(media_row, "crop_json")
            linked_crop = Crop.model_validate_json(crop_raw)
            _verify_document(
                crop_raw,
                _row_str(media_row, "crop_document_sha256"),
                linked_crop,
            )
            if (
                linked_crop != expected_crop
                or _row_str(media_row, "crop_id") != expected_crop.crop_id
                or _row_str(media_row, "media_sha256") != expected_crop.media_sha256
                or _row_str(media_row, "media_manifest_id") != pack.manifest_id
                or _row_str(media_row, "pixel_sha256") != expected_crop.pixel_sha256
                or _row_int(media_row, "width") != expected_crop.output_width
                or _row_int(media_row, "height") != expected_crop.output_height
                or _row_int(media_row, "size_bytes") != expected_crop.size_bytes
                or _row_str(media_row, "media_type") != expected_crop.media_type.value
                or _row_str(media_row, "encoding_version") != expected_crop.encoding_version
            ):
                raise RepositoryIntegrityError(
                    "pack crop or media index does not match its canonical document"
                )
            crop_id = expected_crop.crop_id
            if crop_id in locations:
                raise RepositoryIntegrityError("pack contains duplicate crop-to-media links")
            locations[crop_id] = (
                media_row["local_path"],
                _row_str(media_row, "availability"),
            )
        if len(locations) != len(pack.crops):
            raise RepositoryIntegrityError("pack crop-to-media links are incomplete")
        if not locations:
            return pack
        payload = pack.model_dump(mode="json", exclude_computed_fields=True)
        for field_name in (
            "panorama_crops",
            "subject_crops",
            "focus_crops",
            "temporal_crops",
        ):
            crops = cast(list[dict[str, object]], payload[field_name])
            stored_crops = cast(tuple[Crop, ...], getattr(pack, field_name))
            if len(crops) != len(stored_crops):
                raise RepositoryIntegrityError("pack crop collection changed during load")
            for stored_crop, crop_payload in zip(stored_crops, crops, strict=True):
                local_path, availability = locations[stored_crop.crop_id]
                if local_path is not None and not isinstance(local_path, str):
                    raise RepositoryIntegrityError("media local_path must contain text or null")
                crop_payload["local_path"] = local_path
                crop_payload["availability"] = availability
        payload["pack_id"] = pack.pack_id
        return EvidencePack.model_validate(payload)

    def _rebuild_and_verify_closure(
        self,
        connection: sqlite3.Connection,
        draft: EvidencePackDraft,
    ) -> EvidencePack:
        self._require_manifest_bindings(connection, draft)
        defects = list(self._semantic_closure_defects(connection, draft))
        defects.extend(self._physical_closure_defects(draft))
        ordered_defects = _stable_unique_defects(defects)
        report = ClosureReport(
            run_id=draft.run_id,
            root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
            manifest_id=draft.manifest_id,
            input_sha256=draft.closure_input_sha256,
            checked_refs=draft.expected_closure_refs(),
            defects=ordered_defects,
        )
        if not report.passed:
            raise CreationClosureFailed(tuple(defect.code for defect in report.defects))
        payload = draft.model_dump(mode="json", exclude_computed_fields=True)
        payload["closure_report"] = report.model_dump(mode="json")
        payload["pack_id"] = draft.pack_id
        return EvidencePack.model_validate(payload)

    def _require_manifest_bindings(
        self,
        connection: sqlite3.Connection,
        draft: EvidencePackDraft,
    ) -> None:
        head = self._head(connection, draft.run_id)
        if draft.manifest_id != head.manifest_id:
            raise ManifestMismatch("evidence pack does not use the run manifest")
        manifest = self._load_run_manifest(connection, draft.run_id)
        if draft.event.rule_version != manifest.rule_version:
            raise ManifestMismatch("event rule_version does not match the run manifest")
        if any(
            crop.privacy_receipt.transform_version != manifest.privacy_transform_version
            for crop in draft.crops
        ):
            raise ManifestMismatch("crop privacy transform version does not match the run manifest")
        if any(crop.encoding_version != manifest.image_encoding_version for crop in draft.crops):
            raise ManifestMismatch("crop image encoding version does not match the run manifest")

    def _semantic_closure_defects(
        self,
        connection: sqlite3.Connection,
        draft: EvidencePackDraft,
    ) -> tuple[ClosureDefect, ...]:
        manifest = self._load_run_manifest(connection, draft.run_id)
        model_manifest_ids = {model.model_manifest_id for model in manifest.models.values()}
        m4_execution_manifest_ids: frozenset[str] = frozenset()
        m4_predecessor_pack_ids: frozenset[str] = frozenset()
        if draft.tool_results:
            (
                m4_execution_manifest_ids,
                m4_predecessor_pack_ids,
            ) = self._hearing_repository()._load_pack_closure_authority(
                connection,
                draft,
            )
        allowed_manifest_ids = (
            model_manifest_ids | {manifest.manifest_id} | set(m4_execution_manifest_ids)
        )
        crop_ids = {crop.crop_id for crop in draft.crops}
        media_ids = {crop.media_sha256 for crop in draft.crops}
        fact_ids = {fact.fact_id for fact in draft.objective_facts}
        tool_ids = {result.tool_result_id for result in draft.tool_results}
        objective_sources = {fact.source_ref.sort_key for fact in draft.objective_facts}
        tool_inputs = {ref.sort_key for result in draft.tool_results for ref in result.input_refs}
        tool_outputs = {ref.sort_key for result in draft.tool_results for ref in result.output_refs}
        frame_ids = {
            ref.artifact_id
            for ref in draft.expected_closure_refs()
            if ref.kind == ArtifactKind.FRAME
        }
        detection_ids = {
            ref.artifact_id
            for ref in draft.expected_closure_refs()
            if ref.kind == ArtifactKind.DETECTION
        }
        detections: dict[str, Detection] = {}
        cross_run_detection_ids: set[str] = set()
        for detection_id in sorted(detection_ids):
            detection = self._load_detection(connection, draft.run_id, detection_id)
            if detection is None:
                cross_run = connection.execute(
                    """
                    SELECT 1 FROM detections
                    WHERE run_id <> ? AND detection_id = ? LIMIT 1
                    """,
                    (draft.run_id, detection_id),
                ).fetchone()
                if cross_run is not None:
                    cross_run_detection_ids.add(detection_id)
                continue
            detections[detection_id] = detection
            frame_ids.add(detection.frame_id)
        frames: dict[str, FrameRef] = {}
        for frame_id in sorted(frame_ids):
            frame = self._load_frame(connection, draft.run_id, frame_id)
            if frame is not None:
                frames[frame_id] = frame

        defects: list[ClosureDefect] = []
        event_ref = ArtifactRef(kind=ArtifactKind.EVENT, artifact_id=draft.event.event_id)
        for frame_id, frame in frames.items():
            frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id)
            if (frame.camera_id, frame.stream_id) != (
                draft.event.camera_id,
                draft.event.stream_id,
            ):
                defects.append(
                    ClosureDefect(
                        code=ClosureDefectCode.CROSS_STREAM_FRAME,
                        artifact_ref=frame_ref,
                        related_ref=event_ref,
                    )
                )
            if not (
                draft.track_summary.start_frame
                <= frame.frame_index
                < draft.track_summary.end_frame_exclusive
            ):
                defects.append(
                    ClosureDefect(
                        code=ClosureDefectCode.FRAME_OUTSIDE_WINDOW,
                        artifact_ref=frame_ref,
                        frame_index=frame.frame_index,
                        start_frame=draft.track_summary.start_frame,
                        end_frame_exclusive=draft.track_summary.end_frame_exclusive,
                    )
                )
        for ref in draft.expected_closure_refs():
            exists = False
            if ref.kind == ArtifactKind.CASE:
                exists = ref.artifact_id == draft.case_id
            elif ref.kind == ArtifactKind.EVENT:
                exists = ref.artifact_id == draft.event.event_id
            elif ref.kind == ArtifactKind.MANIFEST:
                exists = ref.artifact_id in allowed_manifest_ids
            elif ref.kind == ArtifactKind.FRAME:
                exists = ref.artifact_id in frames
            elif ref.kind == ArtifactKind.DETECTION:
                exists = ref.artifact_id in detections
            elif ref.kind == ArtifactKind.CROP:
                exists = ref.artifact_id in crop_ids
            elif ref.kind == ArtifactKind.MEDIA:
                exists = ref.artifact_id in media_ids
            elif ref.kind == ArtifactKind.OBJECTIVE_FACT:
                exists = ref.artifact_id in fact_ids
            elif ref.kind == ArtifactKind.TOOL_RESULT:
                exists = ref.artifact_id in tool_ids
            elif ref.kind == ArtifactKind.EVIDENCE_PACK:
                exists = ref.artifact_id in m4_predecessor_pack_ids
            elif self._verifier is not None:
                exists = self._verifier.reference_exists(draft.run_id, ref)
            if exists:
                continue
            if ref.kind == ArtifactKind.DETECTION and ref.artifact_id in cross_run_detection_ids:
                defects.append(
                    ClosureDefect(
                        code=ClosureDefectCode.CROSS_RUN_REFERENCE,
                        artifact_ref=ref,
                        related_ref=ArtifactRef(
                            kind=ArtifactKind.CASE,
                            artifact_id=draft.case_id,
                        ),
                    )
                )
                continue
            code = ClosureDefectCode.MISSING_REFERENCE
            if ref.sort_key in objective_sources:
                code = ClosureDefectCode.OBJECTIVE_SOURCE_MISSING
            elif ref.sort_key in tool_inputs:
                code = ClosureDefectCode.TOOL_INPUT_MISSING
            elif ref.sort_key in tool_outputs:
                code = ClosureDefectCode.TOOL_OUTPUT_MISSING
            defects.append(ClosureDefect(code=code, artifact_ref=ref))

        for crop in draft.crops:
            source_frame = frames.get(crop.frame_id)
            if source_frame is None:
                continue
            crop_ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
            for source_ref in crop.source_refs:
                if source_ref.kind != ArtifactKind.DETECTION:
                    continue
                detection = detections.get(source_ref.artifact_id)
                if detection is not None and detection.frame_id != crop.frame_id:
                    defects.append(
                        ClosureDefect(
                            code=ClosureDefectCode.IDENTITY_MISMATCH,
                            artifact_ref=source_ref,
                            related_ref=ArtifactRef(
                                kind=ArtifactKind.FRAME,
                                artifact_id=crop.frame_id,
                            ),
                            field="frame_id",
                        )
                    )
            if (
                crop.source != CropSource.PANORAMA
                and crop.primary_track_ref != draft.event.primary_track_ref
            ):
                defects.append(
                    ClosureDefect(
                        code=ClosureDefectCode.TRACK_MISMATCH,
                        artifact_ref=crop_ref,
                        role=crop.source.value,
                    )
                )
            if not crop.bbox.is_within(source_frame.width, source_frame.height):
                defects.append(
                    ClosureDefect(
                        code=ClosureDefectCode.BBOX_OUT_OF_BOUNDS,
                        artifact_ref=crop_ref,
                        related_ref=ArtifactRef(
                            kind=ArtifactKind.FRAME,
                            artifact_id=source_frame.frame_id,
                        ),
                    )
                )
            if source_frame.content_sha256 != crop.source_media_sha256:
                if source_frame.content_sha256 is None:
                    defects.append(
                        ClosureDefect(
                            code=ClosureDefectCode.MISSING_REFERENCE,
                            artifact_ref=ArtifactRef(
                                kind=ArtifactKind.FRAME,
                                artifact_id=source_frame.frame_id,
                            ),
                        )
                    )
                else:
                    defects.append(
                        ClosureDefect(
                            code=ClosureDefectCode.SOURCE_HASH_MISMATCH,
                            artifact_ref=crop_ref,
                            related_ref=ArtifactRef(
                                kind=ArtifactKind.FRAME,
                                artifact_id=source_frame.frame_id,
                            ),
                            expected_sha256=crop.source_media_sha256,
                            actual_sha256=source_frame.content_sha256,
                        )
                    )
        for fact in draft.objective_facts:
            if fact.source_ref.kind != ArtifactKind.DETECTION:
                continue
            detection = detections.get(fact.source_ref.artifact_id)
            if detection is not None and fact.source_manifest_id != detection.model_manifest_id:
                defects.append(
                    ClosureDefect(
                        code=ClosureDefectCode.MANIFEST_MISMATCH,
                        artifact_ref=ArtifactRef(
                            kind=ArtifactKind.OBJECTIVE_FACT,
                            artifact_id=fact.fact_id,
                        ),
                        related_ref=fact.source_ref,
                        expected_sha256=detection.model_manifest_id,
                        actual_sha256=fact.source_manifest_id,
                    )
                )
        return tuple(defects)

    def _physical_closure_defects(
        self,
        draft: EvidencePackDraft,
    ) -> tuple[ClosureDefect, ...]:
        defects, _ = self._physical_closure_observation(draft)
        return defects

    def _physical_closure_observation(
        self,
        draft: EvidencePackDraft,
        *,
        verification_cache: dict[str, tuple[Crop, ArtifactVerification]] | None = None,
    ) -> tuple[tuple[ClosureDefect, ...], tuple[ArtifactVerification, ...]]:
        if not draft.crops:
            return (), ()
        if self._verifier is None:
            raise EvidenceMissing("physical crop verification is required before publication")
        defects: list[ClosureDefect] = []
        verifications: list[ArtifactVerification] = []
        for crop in draft.crops:
            cached = (
                verification_cache.get(crop.crop_id) if verification_cache is not None else None
            )
            if cached is None:
                raw_verification = self._verifier.verify_crop(crop)
                verification = ArtifactVerification.model_validate(
                    raw_verification.model_dump(mode="json")
                )
                if verification_cache is not None:
                    verification_cache[crop.crop_id] = (crop, verification)
            else:
                cached_crop, verification = cached
                if cached_crop != crop:
                    raise RepositoryIntegrityError(
                        "one Crop identity has conflicting reviewed-pack content"
                    )
            expected_refs = {
                (ArtifactKind.CROP, crop.crop_id),
                (ArtifactKind.MEDIA, crop.media_sha256),
            }
            if (
                (verification.artifact_ref.kind, verification.artifact_ref.artifact_id)
                not in expected_refs
                or verification.expected_source_pixel_sha256 != crop.source_media_sha256
                or verification.expected_output_pixel_sha256 != crop.pixel_sha256
                or verification.expected_media_sha256 != crop.media_sha256
                or verification.expected_width != crop.output_width
                or verification.expected_height != crop.output_height
                or verification.expected_size_bytes != crop.size_bytes
                or verification.media_type != crop.media_type
                or verification.availability != crop.availability
            ):
                raise RepositoryIntegrityError(
                    "physical verifier returned expectations for another crop"
                )
            verifications.append(verification)
            defect = self._verification_defect(crop, verification)
            if defect is not None:
                defects.append(defect)
        return tuple(defects), tuple(
            sorted(verifications, key=lambda item: item.artifact_ref.sort_key)
        )

    @staticmethod
    def _verification_defect(
        crop: Crop,
        verification: ArtifactVerification,
    ) -> ClosureDefect | None:
        if verification.status in {
            VerificationStatus.VERIFIED,
            VerificationStatus.CURRENT_MEDIA_VERIFIED,
        }:
            return None
        ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
        if verification.status == VerificationStatus.SOURCE_HASH_MISMATCH:
            assert verification.actual_source_pixel_sha256 is not None
            return ClosureDefect(
                code=ClosureDefectCode.SOURCE_HASH_MISMATCH,
                artifact_ref=ref,
                expected_sha256=verification.expected_source_pixel_sha256,
                actual_sha256=verification.actual_source_pixel_sha256,
            )
        if verification.status == VerificationStatus.PIXEL_HASH_MISMATCH:
            assert verification.actual_output_pixel_sha256 is not None
            return ClosureDefect(
                code=ClosureDefectCode.PIXEL_HASH_MISMATCH,
                artifact_ref=ref,
                expected_sha256=verification.expected_output_pixel_sha256,
                actual_sha256=verification.actual_output_pixel_sha256,
            )
        if verification.status == VerificationStatus.MEDIA_HASH_MISMATCH:
            assert verification.actual_media_sha256 is not None
            return ClosureDefect(
                code=ClosureDefectCode.MEDIA_HASH_MISMATCH,
                artifact_ref=ref,
                expected_sha256=verification.expected_media_sha256,
                actual_sha256=verification.actual_media_sha256,
            )
        if verification.status == VerificationStatus.SIZE_MISMATCH:
            assert verification.actual_size_bytes is not None
            return ClosureDefect(
                code=ClosureDefectCode.MEDIA_SIZE_MISMATCH,
                artifact_ref=ref,
                expected_size_bytes=verification.expected_size_bytes,
                actual_size_bytes=verification.actual_size_bytes,
            )
        if verification.status == VerificationStatus.DIMENSION_MISMATCH:
            assert verification.actual_width is not None
            assert verification.actual_height is not None
            return ClosureDefect(
                code=ClosureDefectCode.MEDIA_DIMENSION_MISMATCH,
                artifact_ref=ref,
                expected_width=verification.expected_width,
                actual_width=verification.actual_width,
                expected_height=verification.expected_height,
                actual_height=verification.actual_height,
            )
        if verification.status == VerificationStatus.PRIVACY_POLICY_VIOLATION:
            assert verification.reason_code is not None
            return ClosureDefect(
                code=ClosureDefectCode.PRIVACY_POLICY_VIOLATION,
                artifact_ref=ref,
                reason_code=verification.reason_code,
            )
        status_codes = {
            VerificationStatus.PATH_BOUNDARY_VIOLATION: (ClosureDefectCode.PATH_BOUNDARY_VIOLATION),
            VerificationStatus.UNSAFE_LINK: ClosureDefectCode.UNSAFE_LINK,
            VerificationStatus.NOT_REGULAR_FILE: ClosureDefectCode.NOT_REGULAR_FILE,
            VerificationStatus.PURGED_BY_RETENTION: (ClosureDefectCode.MEDIA_PURGED_BY_RETENTION),
        }
        code = status_codes.get(verification.status, ClosureDefectCode.MEDIA_MISSING)
        return ClosureDefect(
            code=code,
            artifact_ref=ref,
            reason_code=verification.status.value,
        )

    def _store_media_assets(
        self,
        connection: sqlite3.Connection,
        pack: EvidencePack,
    ) -> None:
        for crop in pack.crops:
            expected = (
                crop.local_path,
                crop.availability.value,
                crop.pixel_sha256,
                crop.output_width,
                crop.output_height,
                crop.size_bytes,
                crop.media_type.value,
                crop.encoding_version,
            )
            existing = connection.execute(
                """
                SELECT local_path, availability, pixel_sha256, width, height,
                       size_bytes, media_type, encoding_version
                FROM media_assets WHERE run_id = ? AND media_sha256 = ?
                """,
                (pack.run_id, crop.media_sha256),
            ).fetchone()
            if existing is not None:
                observed = (
                    existing["local_path"],
                    _row_str(existing, "availability"),
                    _row_str(existing, "pixel_sha256"),
                    _row_int(existing, "width"),
                    _row_int(existing, "height"),
                    _row_int(existing, "size_bytes"),
                    _row_str(existing, "media_type"),
                    _row_str(existing, "encoding_version"),
                )
                if observed != expected:
                    raise RepositoryIntegrityError(
                        "media_sha256 already exists with different metadata"
                    )
                continue
            path_collision = connection.execute(
                """
                SELECT media_sha256 FROM media_assets
                WHERE run_id = ? AND local_path = ?
                """,
                (pack.run_id, crop.local_path),
            ).fetchone()
            if path_collision is not None:
                raise RepositoryIntegrityError(
                    "media locator already exists with a different content hash"
                )
            connection.execute(
                """
                INSERT INTO media_assets(
                    run_id, media_sha256, manifest_id, local_path, availability,
                    pixel_sha256, width, height, size_bytes,
                    media_type, encoding_version, ttl_expires_at, purged_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    pack.run_id,
                    crop.media_sha256,
                    pack.manifest_id,
                    crop.local_path,
                    crop.availability.value,
                    crop.pixel_sha256,
                    crop.output_width,
                    crop.output_height,
                    crop.size_bytes,
                    crop.media_type.value,
                    crop.encoding_version,
                ),
            )

    @staticmethod
    def _store_crop_links(
        connection: sqlite3.Connection,
        pack: EvidencePack,
    ) -> None:
        collections = (
            ("panorama", pack.panorama_crops),
            ("subject", pack.subject_crops),
            ("focus", pack.focus_crops),
            ("temporal", pack.temporal_crops),
        )
        for role, crops in collections:
            for ordinal, crop in enumerate(crops):
                crop_json, crop_sha256 = _document(crop)
                connection.execute(
                    """
                    INSERT INTO evidence_pack_crops(
                        run_id, pack_id, crop_id, media_sha256,
                        role, ordinal, crop_json, document_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        pack.run_id,
                        pack.pack_id,
                        crop.crop_id,
                        crop.media_sha256,
                        role,
                        ordinal,
                        crop_json,
                        crop_sha256,
                    ),
                )

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)


__all__ = [
    "MigrationIntegrityError",
    "MigrationRunner",
    "RepositoryIntegrityError",
    "SQLiteEvidenceRepository",
]
