"""Linear two-connection read cut for M6 live WAL verification.

Connection A owns the writer slot before connection B fixes a committed read
snapshot.  Every entered object is an opaque, revocable handle: raw SQLite
connections and cursors remain owned by private brokers for the whole cut.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path
from types import TracebackType
from typing import Literal, NoReturn, SupportsIndex, TypeAlias, TypeGuard, cast, final
from weakref import WeakKeyDictionary, finalize

from labcourt.exceptions import ContractViolation, LabCourtError

from .sqlite_repository import (
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _validate_busy_timeout,
)


class M6LiveReadCutFailureCode(StrEnum):
    """Payload-free failure reasons for the internal live read-cut boundary."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    WRITER_REJECTED = "WRITER_REJECTED"
    WRITER_LOCK_UNAVAILABLE = "WRITER_LOCK_UNAVAILABLE"
    READER_REJECTED = "READER_REJECTED"
    READ_BEFORE_SELECTION_CLOSE = "READ_BEFORE_SELECTION_CLOSE"
    WRITE_BEFORE_READ_CLOSE = "WRITE_BEFORE_READ_CLOSE"
    CAPABILITY_REJECTED = "CAPABILITY_REJECTED"
    PHASE_ALREADY_CONSUMED = "PHASE_ALREADY_CONSUMED"
    CUT_INCOMPLETE = "CUT_INCOMPLETE"


class M6LiveReadCutError(ContractViolation):
    """A live committed read cut could not preserve its linear state."""

    def __init__(self, reason_code: M6LiveReadCutFailureCode) -> None:
        if not isinstance(reason_code, M6LiveReadCutFailureCode):
            raise TypeError("reason_code must be an M6LiveReadCutFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 live read cut failed: {reason_code.value}")


class M6LiveDocumentColumn(StrEnum):
    """Closed BLOB-length routes available to the sealed reader."""

    FRAME_DOCUMENT = "frames.document_json"
    DETECTION_DOCUMENT = "detections.document_json"
    EVIDENCE_PACK_DOCUMENT = "evidence_packs.pack_json"
    CASE_ROOT_EVENT_DOCUMENT = "cases.event_json"
    CASE_VERSION_DOCUMENT = "case_versions.case_json"
    AUDIT_ENTRY_DOCUMENT = "audit_entries.entry_json"
    M3_MODEL_REQUEST_DOCUMENT = "model_call_claims.request_json"
    M3_MODEL_RESPONSE_DOCUMENT = "model_responses.response_json"
    M3_MODEL_CACHE_REQUEST_DOCUMENT = "model_cache.request_json"
    M3_MODEL_CACHE_ENTRY_DOCUMENT = "model_cache.entry_json"
    M3_MODEL_PARSE_RECEIPT_DOCUMENT = "model_parse_receipts.receipt_json"
    M3_PARSED_SCREENING_OUTPUT_DOCUMENT = "parsed_screening_outputs.output_json"
    M3_MODEL_CALL_FAILURE_DOCUMENT = "model_call_failure_authorities.authority_json"
    M3_MODEL_USAGE_DOCUMENT = "model_call_usage_accounting.usage_json"
    M3_BACKLOG_COMPLETION_RECEIPT_DOCUMENT = "backlog_completion_receipts.receipt_json"
    M4_MODEL_REQUEST_DOCUMENT = "m4_model_call_claims.request_json"
    M4_MODEL_RESPONSE_DOCUMENT = "m4_model_responses.response_json"
    M4_MODEL_CACHE_REQUEST_DOCUMENT = "m4_model_cache.request_json"
    M4_MODEL_CACHE_ENTRY_DOCUMENT = "m4_model_cache.entry_json"
    M4_MODEL_PARSE_RECEIPT_DOCUMENT = "m4_model_parse_receipts.receipt_json"
    M4_ROLE_OUTPUT_DOCUMENT = "m4_parsed_hearing_outputs.output_json"
    M4_MODEL_CALL_FAILURE_DOCUMENT = "m4_model_call_failure_authorities.authority_json"
    M4_MODEL_USAGE_DOCUMENT = "m4_hearing_usage_receipts.usage_json"
    M4_HEARING_SESSION_DOCUMENT = "m4_hearings.hearing_json"
    M4_HEARING_CYCLE_DOCUMENT = "m4_hearing_cycles.cycle_json"
    M4_PRECEDENT_RETRIEVAL_DOCUMENT = "m4_precedent_retrieval_receipts.receipt_json"
    M4_HEARING_ROUND_DOCUMENT = "m4_hearing_rounds.round_json"
    M4_HEARING_CHECKPOINT_DOCUMENT = "m4_hearing_checkpoints.checkpoint_json"
    M4_HEARING_VERDICT_BINDING_DOCUMENT = "m4_hearing_verdict_bindings.binding_json"
    M4_VERDICT_DOCUMENT = "verdicts.verdict_json"
    M4_PROCEDURAL_REVIEW_DOCUMENT = "procedural_reviews.review_json"
    M4_BACKLOG_ITEM_DOCUMENT = "backlog_items.initial_json"
    M4_BACKLOG_ITEM_VERSION_DOCUMENT = "backlog_item_versions.item_json"
    M4_BACKLOG_RETRY_OUTCOME_DOCUMENT = "m4_hearing_backlog_retry_outcomes.outcome_json"
    M4_BACKLOG_COMPLETION_RECEIPT_DOCUMENT = "m4_backlog_completion_receipts.receipt_json"
    M4_STRICT_PARSE_FAILURE_ATTEMPT_DOCUMENT = (
        "m4_hearing_strict_parse_failure_attempts.attempt_json"
    )
    M4_STRICT_PARSE_FAILURE_PROOF_DOCUMENT = "m4_hearing_strict_parse_failure_proofs.proof_json"
    M4_HEARING_HUMAN_REVIEW_RECEIPT_DOCUMENT = "m4_hearing_human_review_receipts.receipt_json"
    M4_ACQUISITION_REQUEST_DOCUMENT = "m4_acquisition_requests.request_json"
    M4_ACQUISITION_CLAIM_REQUEST_DOCUMENT = "m4_acquisition_execution_claims.request_json"
    M4_ACQUISITION_CLAIM_DOCUMENT = "m4_acquisition_execution_claims.claim_json"
    M4_TOOL_EXECUTION_MANIFEST_DOCUMENT = "m4_tool_execution_manifests.manifest_json"
    M4_ACQUISITION_PUBLICATION_DOCUMENT = "m4_acquisition_execution_publications.publication_json"
    M4_TOOL_EXECUTION_RECEIPT_DOCUMENT = "m4_tool_execution_receipts.receipt_json"
    M4_EVIDENCE_PACK_DERIVATION_DOCUMENT = "m4_evidence_pack_derivations.derivation_json"
    M5_PRECEDENT_EMBEDDING_DOCUMENT = "precedent_embeddings.embedding_json"
    M5_PRECEDENT_AUTHORITY_DOCUMENT = "precedents.authority_json"
    M5_PRECEDENT_EXPOSURE_DOCUMENT = "m5_precedent_exposures.exposure_json"


class _Phase(Enum):
    READY_FOR_SELECTION = "READY_FOR_SELECTION"
    SELECTING = "SELECTING"
    READY_FOR_READ = "READY_FOR_READ"
    READING = "READING"
    READY_FOR_WRITE = "READY_FOR_WRITE"
    WRITING = "WRITING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    CLOSED = "CLOSED"


class _CapabilityMode(Enum):
    SELECTOR = "SELECTOR"
    READER = "READER"
    WRITER = "WRITER"


def _error(code: M6LiveReadCutFailureCode) -> M6LiveReadCutError:
    return M6LiveReadCutError(code)


def _raise(code: M6LiveReadCutFailureCode) -> NoReturn:
    # Callers invoke this only after leaving the underlying except block.  That
    # keeps both __cause__ and __context__ free of SQLite/runtime payloads.
    raise _error(code)


_SQLITE_SCHEMA_ACTIONS = frozenset(
    {
        sqlite3.SQLITE_ALTER_TABLE,
        sqlite3.SQLITE_ANALYZE,
        sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_CREATE_TEMP_INDEX,
        sqlite3.SQLITE_CREATE_TEMP_TABLE,
        sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
        sqlite3.SQLITE_CREATE_TEMP_VIEW,
        sqlite3.SQLITE_CREATE_TRIGGER,
        sqlite3.SQLITE_CREATE_VIEW,
        sqlite3.SQLITE_CREATE_VTABLE,
        sqlite3.SQLITE_DROP_INDEX,
        sqlite3.SQLITE_DROP_TABLE,
        sqlite3.SQLITE_DROP_TEMP_INDEX,
        sqlite3.SQLITE_DROP_TEMP_TABLE,
        sqlite3.SQLITE_DROP_TEMP_TRIGGER,
        sqlite3.SQLITE_DROP_TEMP_VIEW,
        sqlite3.SQLITE_DROP_TRIGGER,
        sqlite3.SQLITE_DROP_VIEW,
        sqlite3.SQLITE_DROP_VTABLE,
        sqlite3.SQLITE_REINDEX,
    }
)
_SQLITE_TRANSACTION_ACTIONS = frozenset(
    {
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_DETACH,
        sqlite3.SQLITE_SAVEPOINT,
        sqlite3.SQLITE_TRANSACTION,
    }
)
_SQLITE_SAFE_READ_PRAGMAS = frozenset(
    {
        "foreign_keys",
        "journal_mode",
        "query_only",
        "recursive_triggers",
        "synchronous",
        "trusted_schema",
    }
)
_SQLITE_READER_ALLOWED_ACTIONS = frozenset(
    {
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_SELECT,
    }
)
_DOCUMENT_COLUMN_ROUTES = {
    M6LiveDocumentColumn.FRAME_DOCUMENT: ("frames", "document_json"),
    M6LiveDocumentColumn.DETECTION_DOCUMENT: ("detections", "document_json"),
    M6LiveDocumentColumn.EVIDENCE_PACK_DOCUMENT: ("evidence_packs", "pack_json"),
    M6LiveDocumentColumn.CASE_ROOT_EVENT_DOCUMENT: ("cases", "event_json"),
    M6LiveDocumentColumn.CASE_VERSION_DOCUMENT: ("case_versions", "case_json"),
    M6LiveDocumentColumn.AUDIT_ENTRY_DOCUMENT: ("audit_entries", "entry_json"),
    M6LiveDocumentColumn.M3_MODEL_REQUEST_DOCUMENT: (
        "model_call_claims",
        "request_json",
    ),
    M6LiveDocumentColumn.M3_MODEL_RESPONSE_DOCUMENT: (
        "model_responses",
        "response_json",
    ),
    M6LiveDocumentColumn.M3_MODEL_CACHE_REQUEST_DOCUMENT: (
        "model_cache",
        "request_json",
    ),
    M6LiveDocumentColumn.M3_MODEL_CACHE_ENTRY_DOCUMENT: (
        "model_cache",
        "entry_json",
    ),
    M6LiveDocumentColumn.M3_MODEL_PARSE_RECEIPT_DOCUMENT: (
        "model_parse_receipts",
        "receipt_json",
    ),
    M6LiveDocumentColumn.M3_PARSED_SCREENING_OUTPUT_DOCUMENT: (
        "parsed_screening_outputs",
        "output_json",
    ),
    M6LiveDocumentColumn.M3_MODEL_CALL_FAILURE_DOCUMENT: (
        "model_call_failure_authorities",
        "authority_json",
    ),
    M6LiveDocumentColumn.M3_MODEL_USAGE_DOCUMENT: (
        "model_call_usage_accounting",
        "usage_json",
    ),
    M6LiveDocumentColumn.M3_BACKLOG_COMPLETION_RECEIPT_DOCUMENT: (
        "backlog_completion_receipts",
        "receipt_json",
    ),
    M6LiveDocumentColumn.M4_MODEL_REQUEST_DOCUMENT: (
        "m4_model_call_claims",
        "request_json",
    ),
    M6LiveDocumentColumn.M4_MODEL_RESPONSE_DOCUMENT: (
        "m4_model_responses",
        "response_json",
    ),
    M6LiveDocumentColumn.M4_MODEL_CACHE_REQUEST_DOCUMENT: (
        "m4_model_cache",
        "request_json",
    ),
    M6LiveDocumentColumn.M4_MODEL_CACHE_ENTRY_DOCUMENT: (
        "m4_model_cache",
        "entry_json",
    ),
    M6LiveDocumentColumn.M4_MODEL_PARSE_RECEIPT_DOCUMENT: (
        "m4_model_parse_receipts",
        "receipt_json",
    ),
    M6LiveDocumentColumn.M4_ROLE_OUTPUT_DOCUMENT: (
        "m4_parsed_hearing_outputs",
        "output_json",
    ),
    M6LiveDocumentColumn.M4_MODEL_CALL_FAILURE_DOCUMENT: (
        "m4_model_call_failure_authorities",
        "authority_json",
    ),
    M6LiveDocumentColumn.M4_MODEL_USAGE_DOCUMENT: (
        "m4_hearing_usage_receipts",
        "usage_json",
    ),
    M6LiveDocumentColumn.M4_HEARING_SESSION_DOCUMENT: (
        "m4_hearings",
        "hearing_json",
    ),
    M6LiveDocumentColumn.M4_HEARING_CYCLE_DOCUMENT: (
        "m4_hearing_cycles",
        "cycle_json",
    ),
    M6LiveDocumentColumn.M4_PRECEDENT_RETRIEVAL_DOCUMENT: (
        "m4_precedent_retrieval_receipts",
        "receipt_json",
    ),
    M6LiveDocumentColumn.M4_HEARING_ROUND_DOCUMENT: (
        "m4_hearing_rounds",
        "round_json",
    ),
    M6LiveDocumentColumn.M4_HEARING_CHECKPOINT_DOCUMENT: (
        "m4_hearing_checkpoints",
        "checkpoint_json",
    ),
    M6LiveDocumentColumn.M4_HEARING_VERDICT_BINDING_DOCUMENT: (
        "m4_hearing_verdict_bindings",
        "binding_json",
    ),
    M6LiveDocumentColumn.M4_VERDICT_DOCUMENT: (
        "verdicts",
        "verdict_json",
    ),
    M6LiveDocumentColumn.M4_PROCEDURAL_REVIEW_DOCUMENT: (
        "procedural_reviews",
        "review_json",
    ),
    M6LiveDocumentColumn.M4_BACKLOG_ITEM_DOCUMENT: (
        "backlog_items",
        "initial_json",
    ),
    M6LiveDocumentColumn.M4_BACKLOG_ITEM_VERSION_DOCUMENT: (
        "backlog_item_versions",
        "item_json",
    ),
    M6LiveDocumentColumn.M4_BACKLOG_RETRY_OUTCOME_DOCUMENT: (
        "m4_hearing_backlog_retry_outcomes",
        "outcome_json",
    ),
    M6LiveDocumentColumn.M4_BACKLOG_COMPLETION_RECEIPT_DOCUMENT: (
        "m4_backlog_completion_receipts",
        "receipt_json",
    ),
    M6LiveDocumentColumn.M4_STRICT_PARSE_FAILURE_ATTEMPT_DOCUMENT: (
        "m4_hearing_strict_parse_failure_attempts",
        "attempt_json",
    ),
    M6LiveDocumentColumn.M4_STRICT_PARSE_FAILURE_PROOF_DOCUMENT: (
        "m4_hearing_strict_parse_failure_proofs",
        "proof_json",
    ),
    M6LiveDocumentColumn.M4_HEARING_HUMAN_REVIEW_RECEIPT_DOCUMENT: (
        "m4_hearing_human_review_receipts",
        "receipt_json",
    ),
    M6LiveDocumentColumn.M4_ACQUISITION_REQUEST_DOCUMENT: (
        "m4_acquisition_requests",
        "request_json",
    ),
    M6LiveDocumentColumn.M4_ACQUISITION_CLAIM_REQUEST_DOCUMENT: (
        "m4_acquisition_execution_claims",
        "request_json",
    ),
    M6LiveDocumentColumn.M4_ACQUISITION_CLAIM_DOCUMENT: (
        "m4_acquisition_execution_claims",
        "claim_json",
    ),
    M6LiveDocumentColumn.M4_TOOL_EXECUTION_MANIFEST_DOCUMENT: (
        "m4_tool_execution_manifests",
        "manifest_json",
    ),
    M6LiveDocumentColumn.M4_ACQUISITION_PUBLICATION_DOCUMENT: (
        "m4_acquisition_execution_publications",
        "publication_json",
    ),
    M6LiveDocumentColumn.M4_TOOL_EXECUTION_RECEIPT_DOCUMENT: (
        "m4_tool_execution_receipts",
        "receipt_json",
    ),
    M6LiveDocumentColumn.M4_EVIDENCE_PACK_DERIVATION_DOCUMENT: (
        "m4_evidence_pack_derivations",
        "derivation_json",
    ),
    M6LiveDocumentColumn.M5_PRECEDENT_EMBEDDING_DOCUMENT: (
        "precedent_embeddings",
        "embedding_json",
    ),
    M6LiveDocumentColumn.M5_PRECEDENT_AUTHORITY_DOCUMENT: (
        "precedents",
        "authority_json",
    ),
    M6LiveDocumentColumn.M5_PRECEDENT_EXPOSURE_DOCUMENT: (
        "m5_precedent_exposures",
        "exposure_json",
    ),
}
if set(_DOCUMENT_COLUMN_ROUTES) != set(M6LiveDocumentColumn) or len(
    set(_DOCUMENT_COLUMN_ROUTES.values())
) != len(_DOCUMENT_COLUMN_ROUTES):
    raise RuntimeError("M6 live document-column routes must be exhaustive and unique")
_STORAGE_FAILURES = (Exception,)


class _OpaqueToken:
    __slots__ = ("__weakref__",)


class _OpaqueHandle:
    """Non-copyable facade whose only direct referent is an opaque token."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, token: _OpaqueToken) -> None:
        if type(token) is not _OpaqueToken:
            raise TypeError("M6 live handle requires an opaque token")
        self.__token = token

    def __copy__(self) -> NoReturn:
        raise TypeError("M6 live handles cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("M6 live handles cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("M6 live handles cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("M6 live handles cannot be serialized")


def _handle_token(handle: _OpaqueHandle) -> _OpaqueToken:
    return cast(
        _OpaqueToken,
        object.__getattribute__(handle, "_OpaqueHandle__token"),
    )


@dataclass(slots=True)
class _CursorRecord:
    cursor: sqlite3.Cursor


@dataclass(frozen=True, slots=True)
class _OperationOutcome:
    value: object = None
    failure_code: M6LiveReadCutFailureCode | None = None
    exhausted: bool = False


def _outcome_value(outcome: _OperationOutcome) -> object:
    if outcome.failure_code is not None:
        _raise(outcome.failure_code)
    return outcome.value


class _M6SQLiteCapabilityBroker:
    """Private owner for one raw connection and all cursors it returns."""

    __slots__ = (
        "_active",
        "_authorization_rejected",
        "_capability_fatal",
        "_cleanup_failed",
        "_connection",
        "_cursors",
        "_denied_actions",
        "_mode",
        "_reader_fatal",
    )

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        mode: _CapabilityMode,
        denied_actions: frozenset[int],
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            code = (
                M6LiveReadCutFailureCode.READER_REJECTED
                if mode == _CapabilityMode.READER
                else M6LiveReadCutFailureCode.CAPABILITY_REJECTED
            )
            _raise(code)
        self._connection = connection
        self._mode = mode
        self._denied_actions = denied_actions
        self._cursors: dict[_OpaqueToken, _CursorRecord] = {}
        self._active = True
        self._authorization_rejected = False
        self._capability_fatal = False
        self._cleanup_failed = False
        self._reader_fatal = False
        setup_failed = False
        try:
            connection.set_authorizer(self._authorize)
        except _STORAGE_FAILURES:
            setup_failed = True
        if setup_failed:
            self._active = False
            self._mark_reader_fatal()
            _raise(self._storage_failure_code())

    @property
    def mode(self) -> _CapabilityMode:
        return self._mode

    @property
    def reader_fatal(self) -> bool:
        return self._reader_fatal

    def _mark_reader_fatal(self) -> None:
        if self._mode == _CapabilityMode.READER:
            self._reader_fatal = True

    def _mark_capability_fatal(self) -> None:
        self._capability_fatal = True
        self._mark_reader_fatal()

    def _storage_failure_code(self) -> M6LiveReadCutFailureCode:
        if self._mode == _CapabilityMode.READER:
            return M6LiveReadCutFailureCode.READER_REJECTED
        return M6LiveReadCutFailureCode.CAPABILITY_REJECTED

    def _authorize(
        self,
        action: int,
        argument_one: str | None,
        argument_two: str | None,
        _database_name: str | None,
        _trigger_name: str | None,
    ) -> int:
        allowed = self._active
        function_name = (argument_two or argument_one or "").lower()
        if self._mode == _CapabilityMode.READER:
            allowed = (
                allowed
                and action in _SQLITE_READER_ALLOWED_ACTIONS
                and not (action == sqlite3.SQLITE_FUNCTION and function_name == "load_extension")
            )
        elif action == sqlite3.SQLITE_PRAGMA:
            pragma = (argument_one or "").lower()
            allowed = allowed and argument_two is None and pragma in _SQLITE_SAFE_READ_PRAGMAS
        elif action in self._denied_actions or (
            action == sqlite3.SQLITE_FUNCTION and function_name == "load_extension"
        ):
            allowed = False
        if allowed:
            return sqlite3.SQLITE_OK
        self._authorization_rejected = True
        self._mark_capability_fatal()
        return sqlite3.SQLITE_DENY

    def _require_usable(self) -> None:
        if not self._active:
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        if self._reader_fatal or self._capability_fatal:
            _raise(self._storage_failure_code())

    def _invalid_argument(self) -> NoReturn:
        self._mark_capability_fatal()
        _raise(M6LiveReadCutFailureCode.CAPABILITY_REJECTED)

    def execute(
        self,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object],
    ) -> M6LiveCursor:
        self._require_usable()
        if (
            type(statement) is not str
            or not statement.strip()
            or type(parameters) not in {tuple, dict}
        ):
            self._invalid_argument()
        self._authorization_rejected = False
        raw_cursor: sqlite3.Cursor | None = None
        failed = False
        try:
            raw_cursor = self._connection.execute(statement, parameters)
        except _STORAGE_FAILURES:
            failed = True
        if failed:
            authorization_rejected = self._authorization_rejected
            if authorization_rejected:
                self._mark_capability_fatal()
            else:
                self._mark_capability_fatal()
            code = (
                M6LiveReadCutFailureCode.CAPABILITY_REJECTED
                if authorization_rejected
                else self._storage_failure_code()
            )
            _raise(code)
        assert raw_cursor is not None
        return self._register_cursor(raw_cursor)

    def executemany(
        self,
        statement: str,
        parameters: Iterable[tuple[object, ...] | dict[str, object]],
    ) -> M6LiveCursor:
        self._require_usable()
        if (
            self._mode == _CapabilityMode.READER
            or type(statement) is not str
            or not statement.strip()
        ):
            self._invalid_argument()
        self._authorization_rejected = False
        raw_cursor: sqlite3.Cursor | None = None
        failed = False
        try:
            raw_cursor = self._connection.executemany(statement, parameters)
        except _STORAGE_FAILURES:
            failed = True
        if failed:
            if self._authorization_rejected:
                self._mark_capability_fatal()
            else:
                self._mark_capability_fatal()
            code = (
                M6LiveReadCutFailureCode.CAPABILITY_REJECTED
                if self._authorization_rejected
                else self._storage_failure_code()
            )
            _raise(code)
        assert raw_cursor is not None
        return self._register_cursor(raw_cursor)

    def _register_cursor(self, raw_cursor: sqlite3.Cursor) -> M6LiveCursor:
        token = _OpaqueToken()
        self._cursors[token] = _CursorRecord(raw_cursor)
        _CURSOR_BROKERS[token] = self
        cursor = _new_cursor(token)
        finalize(cursor, _abandon_cursor, token)
        return cursor

    def abandon_cursor(self, token: _OpaqueToken) -> None:
        record = self._cursors.pop(token, None)
        if record is None:
            return
        try:
            record.cursor.close()
        except _STORAGE_FAILURES:
            self._cleanup_failed = True
            self._mark_capability_fatal()

    def in_transaction(self) -> bool:
        self._require_usable()
        value = False
        failed = False
        try:
            value = self._connection.in_transaction
        except _STORAGE_FAILURES:
            failed = True
        if failed or (self._mode == _CapabilityMode.READER and not value):
            self._mark_capability_fatal()
            _raise(self._storage_failure_code())
        return value

    def _cursor_record(self, token: _OpaqueToken) -> _CursorRecord:
        self._require_usable()
        record = self._cursors.get(token)
        if record is None:
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        return record

    def cursor_fetchone(self, token: _OpaqueToken) -> sqlite3.Row | None:
        record = self._cursor_record(token)
        value: object = None
        failed = False
        try:
            value = record.cursor.fetchone()
        except _STORAGE_FAILURES:
            failed = True
        if failed:
            self._mark_capability_fatal()
            _raise(self._storage_failure_code())
        return cast(sqlite3.Row | None, value)

    def cursor_fetchall(self, token: _OpaqueToken) -> list[sqlite3.Row]:
        record = self._cursor_record(token)
        value: list[sqlite3.Row] = []
        failed = False
        try:
            value = cast(list[sqlite3.Row], record.cursor.fetchall())
        except _STORAGE_FAILURES:
            failed = True
        if failed:
            self._mark_capability_fatal()
            _raise(self._storage_failure_code())
        return value

    def cursor_fetchmany(
        self,
        token: _OpaqueToken,
        size: int | None,
    ) -> list[sqlite3.Row]:
        record = self._cursor_record(token)
        if size is not None and (type(size) is not int or size < 0):
            self._invalid_argument()
        value: list[sqlite3.Row] = []
        failed = False
        try:
            value = cast(
                list[sqlite3.Row],
                record.cursor.fetchmany() if size is None else record.cursor.fetchmany(size),
            )
        except _STORAGE_FAILURES:
            failed = True
        if failed:
            self._mark_capability_fatal()
            _raise(self._storage_failure_code())
        return value

    def cursor_next(self, token: _OpaqueToken) -> sqlite3.Row:
        record = self._cursor_record(token)
        try:
            return cast(sqlite3.Row, next(record.cursor))
        except StopIteration:
            raise
        except _STORAGE_FAILURES:
            pass
        self._mark_capability_fatal()
        _raise(self._storage_failure_code())

    def cursor_close(self, token: _OpaqueToken) -> None:
        record = self._cursor_record(token)
        failed = False
        try:
            record.cursor.close()
        except _STORAGE_FAILURES:
            failed = True
        if failed:
            self._mark_capability_fatal()
            _raise(self._storage_failure_code())
        del self._cursors[token]

    def document_octet_length(
        self,
        column: M6LiveDocumentColumn,
        rowid: int,
    ) -> int:
        self._require_usable()
        if (
            self._mode != _CapabilityMode.READER
            or type(column) is not M6LiveDocumentColumn
            or type(rowid) is not int
            or rowid <= 0
        ):
            self._invalid_argument()
        table_name, column_name = _DOCUMENT_COLUMN_ROUTES[column]
        blob: sqlite3.Blob | None = None
        size = 0
        failed = False
        try:
            blob = self._connection.blobopen(
                table_name,
                column_name,
                rowid,
                readonly=True,
            )
        except _STORAGE_FAILURES:
            failed = True
        if blob is not None:
            try:
                size = len(blob)
            except _STORAGE_FAILURES:
                failed = True
            try:
                blob.close()
            except _STORAGE_FAILURES:
                failed = True
        if failed:
            self._mark_capability_fatal()
            _raise(M6LiveReadCutFailureCode.READER_REJECTED)
        return size

    def revoke(self) -> M6LiveReadCutFailureCode | None:
        if not self._active:
            return self._storage_failure_code() if self._cleanup_failed else None
        self._active = False
        failed = self._cleanup_failed or self._capability_fatal
        for record in tuple(self._cursors.values()):
            try:
                record.cursor.close()
            except _STORAGE_FAILURES:
                failed = True
        self._cursors.clear()
        try:
            self._connection.set_authorizer(None)
        except _STORAGE_FAILURES:
            failed = True
        if not failed:
            return None
        self._cleanup_failed = True
        self._mark_capability_fatal()
        return self._storage_failure_code()


_CAPABILITY_BROKERS: WeakKeyDictionary[_OpaqueToken, _M6SQLiteCapabilityBroker] = (
    WeakKeyDictionary()
)
_CURSOR_BROKERS: WeakKeyDictionary[_OpaqueToken, _M6SQLiteCapabilityBroker] = WeakKeyDictionary()


def _abandon_cursor(token: _OpaqueToken) -> None:
    broker = _CURSOR_BROKERS.pop(token, None)
    if broker is not None:
        broker.abandon_cursor(token)


def _capability_broker(
    handle: _OpaqueHandle,
    expected_mode: _CapabilityMode,
) -> _M6SQLiteCapabilityBroker:
    broker = _CAPABILITY_BROKERS.get(_handle_token(handle))
    if broker is None or broker.mode != expected_mode:
        _raise(M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
    return broker


def _cursor_broker(cursor: M6LiveCursor) -> tuple[_M6SQLiteCapabilityBroker, _OpaqueToken]:
    token = _handle_token(cursor)
    broker = _CURSOR_BROKERS.get(token)
    if broker is None:
        _raise(M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
    return broker, token


def _unexpected_capability_failure(
    broker: _M6SQLiteCapabilityBroker | None,
) -> M6LiveReadCutFailureCode:
    if broker is None:
        return M6LiveReadCutFailureCode.CAPABILITY_REJECTED
    broker._mark_capability_fatal()
    return broker._storage_failure_code()


def _capture_capability_execute(
    handle: _OpaqueHandle,
    mode: _CapabilityMode,
    statement: str,
    parameters: tuple[object, ...]
    | dict[str, object]
    | Iterable[tuple[object, ...] | dict[str, object]],
    *,
    many: bool,
) -> _OperationOutcome:
    broker: _M6SQLiteCapabilityBroker | None = None
    failure_code: M6LiveReadCutFailureCode | None = None
    try:
        broker = _capability_broker(handle, mode)
        if many:
            cursor = broker.executemany(
                statement,
                cast(Iterable[tuple[object, ...] | dict[str, object]], parameters),
            )
        else:
            cursor = broker.execute(
                statement,
                cast(tuple[object, ...] | dict[str, object], parameters),
            )
    except M6LiveReadCutError as exc:
        failure_code = exc.reason_code
    except Exception:
        failure_code = _unexpected_capability_failure(broker)
    if failure_code is not None:
        return _OperationOutcome(failure_code=failure_code)
    return _OperationOutcome(value=cursor)


def _capture_capability_in_transaction(
    handle: _OpaqueHandle,
    mode: _CapabilityMode,
) -> _OperationOutcome:
    broker: _M6SQLiteCapabilityBroker | None = None
    failure_code: M6LiveReadCutFailureCode | None = None
    try:
        broker = _capability_broker(handle, mode)
        value = broker.in_transaction()
    except M6LiveReadCutError as exc:
        failure_code = exc.reason_code
    except Exception:
        failure_code = _unexpected_capability_failure(broker)
    if failure_code is not None:
        return _OperationOutcome(failure_code=failure_code)
    return _OperationOutcome(value=value)


def _revoke_capability(
    handle: _OpaqueHandle,
    mode: _CapabilityMode,
) -> M6LiveReadCutFailureCode | None:
    broker: _M6SQLiteCapabilityBroker | None = None
    try:
        broker = _capability_broker(handle, mode)
        return broker.revoke()
    except M6LiveReadCutError as exc:
        return exc.reason_code
    except Exception:
        return _unexpected_capability_failure(broker)


def _capture_document_octet_length(
    reader: M6LiveReader,
    column: M6LiveDocumentColumn,
    rowid: int,
) -> _OperationOutcome:
    broker: _M6SQLiteCapabilityBroker | None = None
    failure_code: M6LiveReadCutFailureCode | None = None
    try:
        broker = _capability_broker(reader, _CapabilityMode.READER)
        value = broker.document_octet_length(column, rowid)
    except M6LiveReadCutError as exc:
        failure_code = exc.reason_code
    except Exception:
        failure_code = _unexpected_capability_failure(broker)
    if failure_code is not None:
        return _OperationOutcome(failure_code=failure_code)
    return _OperationOutcome(value=value)


def _capture_cursor_operation(
    cursor: M6LiveCursor,
    operation: str,
    size: int | None = None,
) -> _OperationOutcome:
    broker: _M6SQLiteCapabilityBroker | None = None
    failure_code: M6LiveReadCutFailureCode | None = None
    exhausted = False
    value: object = None
    try:
        broker, token = _cursor_broker(cursor)
        if operation == "fetchone":
            value = broker.cursor_fetchone(token)
        elif operation == "fetchall":
            value = broker.cursor_fetchall(token)
        elif operation == "fetchmany":
            value = broker.cursor_fetchmany(token, size)
        elif operation == "next":
            try:
                value = broker.cursor_next(token)
            except StopIteration:
                exhausted = True
        elif operation == "close":
            broker.cursor_close(token)
        else:
            failure_code = M6LiveReadCutFailureCode.CAPABILITY_REJECTED
    except M6LiveReadCutError as exc:
        failure_code = exc.reason_code
    except Exception:
        failure_code = _unexpected_capability_failure(broker)
    if failure_code is not None:
        return _OperationOutcome(failure_code=failure_code)
    return _OperationOutcome(value=value, exhausted=exhausted)


@final
class M6LiveCursor(_OpaqueHandle):
    """Revocable result cursor with no connection or raw-cursor reference."""

    __slots__ = ()

    def __init__(self, _token: object = None) -> None:
        del _token
        raise TypeError("M6 live cursors are created by a capability")

    def fetchone(self) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            _outcome_value(_capture_cursor_operation(self, "fetchone")),
        )

    def fetchall(self) -> list[sqlite3.Row]:
        return cast(
            list[sqlite3.Row],
            _outcome_value(_capture_cursor_operation(self, "fetchall")),
        )

    def fetchmany(self, size: int | None = None) -> list[sqlite3.Row]:
        outcome = _capture_cursor_operation(self, "fetchmany", size)
        del size
        return cast(
            list[sqlite3.Row],
            _outcome_value(outcome),
        )

    def close(self) -> None:
        _outcome_value(_capture_cursor_operation(self, "close"))

    def __iter__(self) -> M6LiveCursor:
        return self

    def __next__(self) -> sqlite3.Row:
        outcome = _capture_cursor_operation(self, "next")
        if outcome.exhausted:
            raise StopIteration
        return cast(sqlite3.Row, _outcome_value(outcome))


def _new_cursor(token: _OpaqueToken) -> M6LiveCursor:
    cursor = object.__new__(M6LiveCursor)
    _OpaqueHandle.__init__(cursor, token)
    return cursor


class _M6LiveSQLCapability(_OpaqueHandle):
    __slots__ = ()

    _MODE: _CapabilityMode

    def execute(
        self,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        outcome = _capture_capability_execute(
            self,
            self._MODE,
            statement,
            parameters,
            many=False,
        )
        del statement, parameters
        return cast(M6LiveCursor, _outcome_value(outcome))

    def executemany(
        self,
        statement: str,
        parameters: Iterable[tuple[object, ...] | dict[str, object]],
    ) -> M6LiveCursor:
        outcome = _capture_capability_execute(
            self,
            self._MODE,
            statement,
            parameters,
            many=True,
        )
        del statement, parameters
        return cast(M6LiveCursor, _outcome_value(outcome))

    @property
    def in_transaction(self) -> bool:
        return cast(
            bool,
            _outcome_value(_capture_capability_in_transaction(self, self._MODE)),
        )


@final
class M6LivePendingSelector(_M6LiveSQLCapability):
    """Read-only A capability used before B fixes its committed snapshot."""

    __slots__ = ()
    _MODE = _CapabilityMode.SELECTOR

    def __init__(self, _token: object = None) -> None:
        del _token
        raise TypeError("M6 live selectors are created by a committed read cut")


@final
class M6LiveWriter(_M6LiveSQLCapability):
    """Write capability that cannot end, replace, or escape A's transaction."""

    __slots__ = ()
    _MODE = _CapabilityMode.WRITER

    def __init__(self, _token: object = None) -> None:
        del _token
        raise TypeError("M6 live writers are created by a committed read cut")


def _new_pending_selector(connection: sqlite3.Connection) -> M6LivePendingSelector:
    broker = _M6SQLiteCapabilityBroker(
        connection,
        mode=_CapabilityMode.SELECTOR,
        denied_actions=(
            _SQLITE_SCHEMA_ACTIONS
            | _SQLITE_TRANSACTION_ACTIONS
            | frozenset(
                {
                    sqlite3.SQLITE_DELETE,
                    sqlite3.SQLITE_INSERT,
                    sqlite3.SQLITE_UPDATE,
                }
            )
        ),
    )
    token = _OpaqueToken()
    _CAPABILITY_BROKERS[token] = broker
    selector = object.__new__(M6LivePendingSelector)
    _OpaqueHandle.__init__(selector, token)
    return selector


def _new_writer(connection: sqlite3.Connection) -> M6LiveWriter:
    broker = _M6SQLiteCapabilityBroker(
        connection,
        mode=_CapabilityMode.WRITER,
        denied_actions=_SQLITE_SCHEMA_ACTIONS | _SQLITE_TRANSACTION_ACTIONS,
    )
    token = _OpaqueToken()
    _CAPABILITY_BROKERS[token] = broker
    writer = object.__new__(M6LiveWriter)
    _OpaqueHandle.__init__(writer, token)
    return writer


@final
class M6LiveReader(_OpaqueHandle):
    """Sealed B reader bound to one fixed committed transaction generation."""

    __slots__ = ()

    def __init__(self, _token: object = None) -> None:
        del _token
        raise TypeError("M6 live readers are created by a committed read cut")

    def execute(
        self,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        outcome = _capture_capability_execute(
            self,
            _CapabilityMode.READER,
            statement,
            parameters,
            many=False,
        )
        del statement, parameters
        return cast(M6LiveCursor, _outcome_value(outcome))

    @property
    def in_transaction(self) -> bool:
        return cast(
            bool,
            _outcome_value(_capture_capability_in_transaction(self, _CapabilityMode.READER)),
        )

    def document_octet_length(
        self,
        column: M6LiveDocumentColumn,
        rowid: int,
    ) -> int:
        outcome = _capture_document_octet_length(self, column, rowid)
        del column, rowid
        return cast(int, _outcome_value(outcome))


M6SQLiteReadSession: TypeAlias = sqlite3.Connection | M6LiveReader


def is_m6_sqlite_read_session(value: object) -> TypeGuard[M6SQLiteReadSession]:
    """Accept only raw trusted-test connections or the exact sealed reader."""

    return isinstance(value, sqlite3.Connection) or type(value) is M6LiveReader


def _new_reader(
    connection: sqlite3.Connection,
) -> tuple[M6LiveReader, _M6SQLiteCapabilityBroker]:
    broker = _M6SQLiteCapabilityBroker(
        connection,
        mode=_CapabilityMode.READER,
        denied_actions=frozenset(),
    )
    token = _OpaqueToken()
    _CAPABILITY_BROKERS[token] = broker
    reader = object.__new__(M6LiveReader)
    _OpaqueHandle.__init__(reader, token)
    return reader, broker


def _open_committed_reader(database: Path, busy_timeout_ms: int) -> sqlite3.Connection:
    connection: sqlite3.Connection | None = None
    recognized_failure = False
    unexpected: BaseException | None = None
    try:
        # This is a live WAL view.  ``immutable=1`` would be incorrect because it
        # can make SQLite ignore authority already committed to the WAL.
        connection = sqlite3.connect(
            f"{database.as_uri()}?mode=ro",
            uri=True,
            timeout=busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.enable_load_extension(False)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        observed = (
            int(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
            int(connection.execute("PRAGMA busy_timeout").fetchone()[0]),
            int(connection.execute("PRAGMA query_only").fetchone()[0]),
            int(connection.execute("PRAGMA trusted_schema").fetchone()[0]),
        )
        if observed != (1, busy_timeout_ms, 1, 0):
            raise RepositoryIntegrityError("M6 live reader PRAGMA verification failed")
        connection.execute("BEGIN")
        # BEGIN is deferred.  This first b-tree read fixes B's committed snapshot
        # before any verifier receives a handle.
        connection.execute(
            "SELECT rootpage FROM sqlite_schema ORDER BY rootpage LIMIT 1"
        ).fetchone()
        if not connection.in_transaction:
            raise RepositoryIntegrityError("M6 live reader did not establish a transaction")
    except BaseException as exc:
        recognized_failure = isinstance(
            exc,
            (sqlite3.Error, LabCourtError, OSError, RuntimeError, ValueError),
        )
        if not recognized_failure:
            unexpected = exc
    if recognized_failure or unexpected is not None:
        if connection is not None:
            with suppress(*_STORAGE_FAILURES):
                connection.close()
        if unexpected is not None:
            raise unexpected
        _raise(M6LiveReadCutFailureCode.READER_REJECTED)
    assert connection is not None
    return connection


def _rollback_and_close(connection: sqlite3.Connection) -> bool:
    """Attempt both cleanup steps; report whether either one failed."""

    failed = False
    in_transaction = False
    transaction_state_known = True
    try:
        in_transaction = connection.in_transaction
    except _STORAGE_FAILURES:
        failed = True
        transaction_state_known = False
    if in_transaction or not transaction_state_known:
        try:
            connection.rollback()
        except _STORAGE_FAILURES:
            failed = True
    try:
        connection.close()
    except _STORAGE_FAILURES:
        failed = True
    return failed


class _M6LiveCommittedReadCutOwner:
    """Unexposed owner of A, B, phase state, and active capability brokers."""

    __slots__ = (
        "_busy_timeout_ms",
        "_database",
        "_phase",
        "_reader_broker",
        "_reader_connection",
        "_selector_capability",
        "_writer_capability",
        "_writer_connection",
    )

    def __init__(
        self,
        writer: sqlite3.Connection,
        database: Path,
        busy_timeout_ms: int,
    ) -> None:
        self._writer_connection: sqlite3.Connection | None = writer
        self._database = database
        self._busy_timeout_ms = busy_timeout_ms
        self._reader_connection: sqlite3.Connection | None = None
        self._reader_broker: _M6SQLiteCapabilityBroker | None = None
        self._selector_capability: M6LivePendingSelector | None = None
        self._writer_capability: M6LiveWriter | None = None
        self._phase = _Phase.READY_FOR_SELECTION

    def _writer(self) -> sqlite3.Connection:
        if self._writer_connection is None:
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        return self._writer_connection

    def enter_selector(self) -> M6LivePendingSelector:
        if self._phase != _Phase.READY_FOR_SELECTION:
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        self._phase = _Phase.SELECTING
        try:
            capability = _new_pending_selector(self._writer())
        except M6LiveReadCutError:
            self._phase = _Phase.FAILED
            raise
        self._selector_capability = capability
        return capability

    def exit_selector(self, *, body_failed: bool) -> None:
        capability = self._selector_capability
        if capability is None or self._phase != _Phase.SELECTING:
            self._phase = _Phase.FAILED
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        if body_failed:
            self._phase = _Phase.FAILED
        revoke_failure = _revoke_capability(capability, _CapabilityMode.SELECTOR)
        self._selector_capability = None
        if body_failed:
            return
        if revoke_failure is not None:
            self._phase = _Phase.FAILED
            _raise(revoke_failure)
        self._phase = _Phase.READY_FOR_READ

    def enter_reader(self) -> M6LiveReader:
        if self._phase in {_Phase.READY_FOR_SELECTION, _Phase.SELECTING}:
            _raise(M6LiveReadCutFailureCode.READ_BEFORE_SELECTION_CLOSE)
        if self._phase != _Phase.READY_FOR_READ:
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        try:
            raw_reader = _open_committed_reader(self._database, self._busy_timeout_ms)
        except M6LiveReadCutError:
            self._phase = _Phase.FAILED
            raise
        self._reader_connection = raw_reader
        try:
            reader, broker = _new_reader(raw_reader)
        except M6LiveReadCutError:
            self._phase = _Phase.FAILED
            _rollback_and_close(raw_reader)
            self._reader_connection = None
            raise
        self._reader_broker = broker
        self._phase = _Phase.READING
        return reader

    def exit_reader(self, *, body_failed: bool) -> None:
        raw_reader = self._reader_connection
        broker = self._reader_broker
        if raw_reader is None or broker is None or self._phase != _Phase.READING:
            self._phase = _Phase.FAILED
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        if body_failed:
            self._phase = _Phase.FAILED
        if not body_failed and not broker.reader_fatal:
            with suppress(M6LiveReadCutError):
                broker.in_transaction()
        revoke_failure = broker.revoke()
        close_failed = _rollback_and_close(raw_reader)
        reader_failed = broker.reader_fatal or revoke_failure is not None or close_failed
        self._reader_broker = None
        self._reader_connection = None
        if body_failed:
            return
        if reader_failed:
            self._phase = _Phase.FAILED
            _raise(M6LiveReadCutFailureCode.READER_REJECTED)
        self._phase = _Phase.READY_FOR_WRITE

    def enter_writer(self) -> M6LiveWriter:
        if self._phase in {
            _Phase.READY_FOR_SELECTION,
            _Phase.SELECTING,
            _Phase.READY_FOR_READ,
            _Phase.READING,
        }:
            _raise(M6LiveReadCutFailureCode.WRITE_BEFORE_READ_CLOSE)
        if self._phase != _Phase.READY_FOR_WRITE:
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        raw_writer = self._writer()
        transaction_failed = False
        writer_in_transaction = False
        try:
            writer_in_transaction = raw_writer.in_transaction
        except _STORAGE_FAILURES:
            transaction_failed = True
        if transaction_failed or not writer_in_transaction:
            self._phase = _Phase.FAILED
            _raise(M6LiveReadCutFailureCode.WRITER_REJECTED)
        try:
            capability = _new_writer(raw_writer)
        except M6LiveReadCutError:
            self._phase = _Phase.FAILED
            raise
        self._writer_capability = capability
        self._phase = _Phase.WRITING
        return capability

    def exit_writer(self, *, body_failed: bool) -> None:
        capability = self._writer_capability
        raw_writer = self._writer_connection
        if capability is None or raw_writer is None or self._phase != _Phase.WRITING:
            self._phase = _Phase.FAILED
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        completion_failure: M6LiveReadCutFailureCode | None = None
        if body_failed:
            self._phase = _Phase.FAILED
        else:
            transaction_failed = False
            writer_in_transaction = False
            try:
                writer_in_transaction = raw_writer.in_transaction
            except _STORAGE_FAILURES:
                transaction_failed = True
            if transaction_failed or not writer_in_transaction:
                completion_failure = M6LiveReadCutFailureCode.WRITER_REJECTED
        revoke_failure = _revoke_capability(capability, _CapabilityMode.WRITER)
        self._writer_capability = None
        if body_failed:
            return
        if completion_failure is None:
            completion_failure = revoke_failure
        if completion_failure is not None:
            self._phase = _Phase.FAILED
            _raise(completion_failure)
        self._phase = _Phase.COMPLETE

    def finish(self) -> None:
        if self._phase != _Phase.COMPLETE or self._writer_capability is not None:
            self._phase = _Phase.FAILED
            _raise(M6LiveReadCutFailureCode.CUT_INCOMPLETE)
        raw_writer = self._writer()
        failed = False
        try:
            if not raw_writer.in_transaction:
                failed = True
            else:
                raw_writer.commit()
        except _STORAGE_FAILURES:
            failed = True
        if failed:
            self._phase = _Phase.FAILED
            _raise(M6LiveReadCutFailureCode.WRITER_REJECTED)
        self._phase = _Phase.CLOSED

    def abort(self) -> None:
        self._phase = _Phase.FAILED
        if self._reader_broker is not None:
            self._reader_broker.revoke()
            self._reader_broker = None
        if self._reader_connection is not None:
            _rollback_and_close(self._reader_connection)
            self._reader_connection = None
        if self._selector_capability is not None:
            _revoke_capability(self._selector_capability, _CapabilityMode.SELECTOR)
        if self._writer_capability is not None:
            _revoke_capability(self._writer_capability, _CapabilityMode.WRITER)
        self._selector_capability = None
        self._writer_capability = None
        raw_writer = self._writer_connection
        if raw_writer is not None:
            should_rollback = True
            with suppress(*_STORAGE_FAILURES):
                should_rollback = raw_writer.in_transaction
            if should_rollback:
                with suppress(*_STORAGE_FAILURES):
                    raw_writer.rollback()

    def close_writer(self) -> None:
        raw_writer = self._writer_connection
        self._writer_connection = None
        if raw_writer is None:
            return
        failed = False
        try:
            raw_writer.close()
        except _STORAGE_FAILURES:
            failed = True
        if failed:
            _raise(M6LiveReadCutFailureCode.WRITER_REJECTED)


_CUT_OWNERS: WeakKeyDictionary[_OpaqueToken, _M6LiveCommittedReadCutOwner] = WeakKeyDictionary()


def _cut_owner(cut: M6LiveCommittedReadCut) -> _M6LiveCommittedReadCutOwner:
    owner = _CUT_OWNERS.get(_handle_token(cut))
    if owner is None:
        _raise(M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
    return owner


@dataclass(slots=True)
class _M6LivePhaseContextRecord:
    owner: _M6LiveCommittedReadCutOwner
    mode: _CapabilityMode
    entered: bool = False
    exited: bool = False


_PHASE_CONTEXTS: WeakKeyDictionary[_OpaqueToken, _M6LivePhaseContextRecord] = WeakKeyDictionary()


def _phase_storage_failure_code(mode: _CapabilityMode) -> M6LiveReadCutFailureCode:
    if mode == _CapabilityMode.READER:
        return M6LiveReadCutFailureCode.READER_REJECTED
    if mode == _CapabilityMode.WRITER:
        return M6LiveReadCutFailureCode.WRITER_REJECTED
    return M6LiveReadCutFailureCode.CAPABILITY_REJECTED


def _abort_and_close_owner(owner: _M6LiveCommittedReadCutOwner) -> None:
    with suppress(Exception):
        owner.abort()
    with suppress(Exception):
        owner.close_writer()


def _capture_phase_enter(
    context: _OpaqueHandle,
    expected_mode: _CapabilityMode,
) -> _OperationOutcome:
    record: _M6LivePhaseContextRecord | None = None
    failure_code: M6LiveReadCutFailureCode | None = None
    unexpected = False
    started_enter = False
    value: object = None
    try:
        record = _PHASE_CONTEXTS.get(_handle_token(context))
        if record is None or record.mode != expected_mode:
            _raise(M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
        if record.entered or record.exited:
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        record.entered = True
        started_enter = True
        if expected_mode == _CapabilityMode.SELECTOR:
            value = record.owner.enter_selector()
        elif expected_mode == _CapabilityMode.READER:
            value = record.owner.enter_reader()
        else:
            value = record.owner.enter_writer()
    except M6LiveReadCutError as exc:
        failure_code = exc.reason_code
    except Exception:
        unexpected = True
        failure_code = _phase_storage_failure_code(expected_mode)
    if failure_code is not None:
        if record is not None and started_enter:
            record.exited = True
            if unexpected or failure_code in {
                M6LiveReadCutFailureCode.CAPABILITY_REJECTED,
                M6LiveReadCutFailureCode.READER_REJECTED,
                M6LiveReadCutFailureCode.WRITER_REJECTED,
            }:
                _abort_and_close_owner(record.owner)
        return _OperationOutcome(failure_code=failure_code)
    return _OperationOutcome(value=value)


def _capture_phase_exit(
    context: _OpaqueHandle,
    expected_mode: _CapabilityMode,
    *,
    body_failed: bool,
) -> _OperationOutcome:
    record: _M6LivePhaseContextRecord | None = None
    failure_code: M6LiveReadCutFailureCode | None = None
    unexpected = False
    try:
        record = _PHASE_CONTEXTS.get(_handle_token(context))
        if record is None or record.mode != expected_mode:
            _raise(M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
        if not record.entered or record.exited:
            _raise(M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
        record.exited = True
        if expected_mode == _CapabilityMode.SELECTOR:
            record.owner.exit_selector(body_failed=body_failed)
        elif expected_mode == _CapabilityMode.READER:
            record.owner.exit_reader(body_failed=body_failed)
        else:
            record.owner.exit_writer(body_failed=body_failed)
    except M6LiveReadCutError as exc:
        failure_code = exc.reason_code
    except Exception:
        unexpected = True
        failure_code = _phase_storage_failure_code(expected_mode)
    if unexpected and record is not None:
        _abort_and_close_owner(record.owner)
    if failure_code is not None:
        return _OperationOutcome(failure_code=failure_code)
    return _OperationOutcome()


def _abandon_phase_context(token: _OpaqueToken) -> None:
    record = _PHASE_CONTEXTS.pop(token, None)
    if record is None or not record.entered or record.exited:
        return
    record.exited = True
    with suppress(Exception):
        if record.mode == _CapabilityMode.SELECTOR:
            record.owner.exit_selector(body_failed=True)
        elif record.mode == _CapabilityMode.READER:
            record.owner.exit_reader(body_failed=True)
        else:
            record.owner.exit_writer(body_failed=True)
    _abort_and_close_owner(record.owner)


@final
class _M6LiveSelectorContext(_OpaqueHandle):
    __slots__ = ()

    def __enter__(self) -> M6LivePendingSelector:
        return cast(
            M6LivePendingSelector,
            _outcome_value(_capture_phase_enter(self, _CapabilityMode.SELECTOR)),
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> Literal[False]:
        outcome = _capture_phase_exit(
            self,
            _CapabilityMode.SELECTOR,
            body_failed=exc_type is not None,
        )
        if exc_type is None:
            _outcome_value(outcome)
        return False


@final
class _M6LiveReaderContext(_OpaqueHandle):
    __slots__ = ()

    def __enter__(self) -> M6LiveReader:
        return cast(
            M6LiveReader,
            _outcome_value(_capture_phase_enter(self, _CapabilityMode.READER)),
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> Literal[False]:
        outcome = _capture_phase_exit(
            self,
            _CapabilityMode.READER,
            body_failed=exc_type is not None,
        )
        if exc_type is None:
            _outcome_value(outcome)
        return False


@final
class _M6LiveWriterContext(_OpaqueHandle):
    __slots__ = ()

    def __enter__(self) -> M6LiveWriter:
        return cast(
            M6LiveWriter,
            _outcome_value(_capture_phase_enter(self, _CapabilityMode.WRITER)),
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> Literal[False]:
        outcome = _capture_phase_exit(
            self,
            _CapabilityMode.WRITER,
            body_failed=exc_type is not None,
        )
        if exc_type is None:
            _outcome_value(outcome)
        return False


def _new_phase_context(
    owner: _M6LiveCommittedReadCutOwner,
    mode: _CapabilityMode,
) -> _OpaqueHandle:
    token = _OpaqueToken()
    _PHASE_CONTEXTS[token] = _M6LivePhaseContextRecord(owner=owner, mode=mode)
    context_type: type[_OpaqueHandle]
    if mode == _CapabilityMode.SELECTOR:
        context_type = _M6LiveSelectorContext
    elif mode == _CapabilityMode.READER:
        context_type = _M6LiveReaderContext
    else:
        context_type = _M6LiveWriterContext
    context = object.__new__(context_type)
    _OpaqueHandle.__init__(context, token)
    finalize(context, _abandon_phase_context, token)
    return context


def _capture_phase_context_creation(
    cut: M6LiveCommittedReadCut,
    mode: _CapabilityMode,
) -> _OperationOutcome:
    owner: _M6LiveCommittedReadCutOwner | None = None
    try:
        owner = _cut_owner(cut)
        context = _new_phase_context(owner, mode)
    except M6LiveReadCutError as exc:
        return _OperationOutcome(failure_code=exc.reason_code)
    except Exception:
        if owner is not None:
            _abort_and_close_owner(owner)
        return _OperationOutcome(failure_code=_phase_storage_failure_code(mode))
    return _OperationOutcome(value=context)


@final
class M6LiveCommittedReadCut(_OpaqueHandle):
    """One-use opaque facade: select on A, verify on B, then write on A."""

    __slots__ = ()

    def __init__(self, _token: object = None) -> None:
        del _token
        raise TypeError("M6 live cuts are created by m6_live_committed_read_cut")

    def selector(self) -> _M6LiveSelectorContext:
        return cast(
            _M6LiveSelectorContext,
            _outcome_value(_capture_phase_context_creation(self, _CapabilityMode.SELECTOR)),
        )

    def reader(self) -> _M6LiveReaderContext:
        return cast(
            _M6LiveReaderContext,
            _outcome_value(_capture_phase_context_creation(self, _CapabilityMode.READER)),
        )

    def writer(self) -> _M6LiveWriterContext:
        return cast(
            _M6LiveWriterContext,
            _outcome_value(_capture_phase_context_creation(self, _CapabilityMode.WRITER)),
        )


def _new_cut(owner: _M6LiveCommittedReadCutOwner) -> M6LiveCommittedReadCut:
    token = _OpaqueToken()
    _CUT_OWNERS[token] = owner
    cut = object.__new__(M6LiveCommittedReadCut)
    _OpaqueHandle.__init__(cut, token)
    return cut


@dataclass(slots=True)
class _M6LiveCutContextRecord:
    database: Path
    busy_timeout_ms: int
    owner: _M6LiveCommittedReadCutOwner | None = None
    entered: bool = False
    exited: bool = False


_CUT_CONTEXTS: WeakKeyDictionary[_OpaqueToken, _M6LiveCutContextRecord] = WeakKeyDictionary()


def _capture_cut_enter(context: M6LiveCommittedReadCutContext) -> _OperationOutcome:
    record = _CUT_CONTEXTS.get(_handle_token(context))
    if record is None:
        return _OperationOutcome(failure_code=M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
    if record.entered or record.exited:
        return _OperationOutcome(failure_code=M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
    record.entered = True
    writer: sqlite3.Connection | None = None
    open_failure: M6LiveReadCutFailureCode | None = None
    try:
        writer = _open_connection(
            record.database,
            record.busy_timeout_ms,
            allow_create=False,
        )
        writer.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        try:
            is_concurrency_error = _is_sqlite_concurrency_error(exc)
        except Exception:
            is_concurrency_error = False
        open_failure = (
            M6LiveReadCutFailureCode.WRITER_LOCK_UNAVAILABLE
            if is_concurrency_error
            else M6LiveReadCutFailureCode.WRITER_REJECTED
        )
    except Exception:
        open_failure = M6LiveReadCutFailureCode.WRITER_REJECTED
    if open_failure is not None:
        record.exited = True
        if writer is not None:
            with suppress(*_STORAGE_FAILURES):
                writer.close()
        return _OperationOutcome(failure_code=open_failure)
    if writer is None:
        record.exited = True
        return _OperationOutcome(failure_code=M6LiveReadCutFailureCode.WRITER_REJECTED)
    try:
        owner = _M6LiveCommittedReadCutOwner(
            writer,
            record.database,
            record.busy_timeout_ms,
        )
        cut = _new_cut(owner)
    except Exception:
        with suppress(*_STORAGE_FAILURES):
            writer.rollback()
        with suppress(*_STORAGE_FAILURES):
            writer.close()
        record.exited = True
        return _OperationOutcome(failure_code=M6LiveReadCutFailureCode.WRITER_REJECTED)
    record.owner = owner
    return _OperationOutcome(value=cut)


def _capture_cut_exit(
    context: M6LiveCommittedReadCutContext,
    *,
    body_failed: bool,
) -> _OperationOutcome:
    record = _CUT_CONTEXTS.get(_handle_token(context))
    if record is None:
        return _OperationOutcome(failure_code=M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
    owner = record.owner
    if not record.entered or record.exited or owner is None:
        return _OperationOutcome(failure_code=M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED)
    record.exited = True
    failure_code: M6LiveReadCutFailureCode | None = None
    if body_failed:
        with suppress(Exception):
            owner.abort()
    else:
        try:
            owner.finish()
        except M6LiveReadCutError as exc:
            failure_code = exc.reason_code
        except Exception:
            failure_code = M6LiveReadCutFailureCode.WRITER_REJECTED
        if failure_code is not None:
            with suppress(Exception):
                owner.abort()
    try:
        owner.close_writer()
    except M6LiveReadCutError as exc:
        if not body_failed and failure_code is None:
            failure_code = exc.reason_code
    except Exception:
        if not body_failed and failure_code is None:
            failure_code = M6LiveReadCutFailureCode.WRITER_REJECTED
    record.owner = None
    if failure_code is not None:
        return _OperationOutcome(failure_code=failure_code)
    return _OperationOutcome()


def _abandon_cut_context(token: _OpaqueToken) -> None:
    record = _CUT_CONTEXTS.pop(token, None)
    if record is None or record.owner is None:
        return
    with suppress(Exception):
        record.owner.abort()
    with suppress(Exception):
        record.owner.close_writer()
    record.owner = None
    record.exited = True


@final
class M6LiveCommittedReadCutContext(_OpaqueHandle):
    """Opaque context handle that acquires and releases the two-connection cut."""

    __slots__ = ()

    def __init__(self, _token: object = None) -> None:
        del _token
        raise TypeError("M6 live cut contexts are created by m6_live_committed_read_cut")

    def __enter__(self) -> M6LiveCommittedReadCut:
        return cast(M6LiveCommittedReadCut, _outcome_value(_capture_cut_enter(self)))

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> Literal[False]:
        outcome = _capture_cut_exit(self, body_failed=exc_type is not None)
        if exc_type is None:
            _outcome_value(outcome)
        return False


def _new_cut_context(
    database: Path,
    busy_timeout_ms: int,
) -> M6LiveCommittedReadCutContext:
    token = _OpaqueToken()
    _CUT_CONTEXTS[token] = _M6LiveCutContextRecord(
        database=database,
        busy_timeout_ms=busy_timeout_ms,
    )
    context = object.__new__(M6LiveCommittedReadCutContext)
    _OpaqueHandle.__init__(context, token)
    finalize(context, _abandon_cut_context, token)
    return context


def _capture_cut_arguments(
    database_path: object,
    busy_timeout_ms: object,
) -> _OperationOutcome:
    if type(database_path) not in {str, type(Path())} or type(busy_timeout_ms) is not int:
        return _OperationOutcome(failure_code=M6LiveReadCutFailureCode.INVALID_ARGUMENT)
    try:
        controlled_timeout = _validate_busy_timeout(busy_timeout_ms)
        database = Path(cast(str | Path, database_path)).absolute()
    except Exception:
        return _OperationOutcome(failure_code=M6LiveReadCutFailureCode.INVALID_ARGUMENT)
    return _OperationOutcome(value=(database, controlled_timeout))


def m6_live_committed_read_cut(
    database_path: str | Path,
    busy_timeout_ms: int,
) -> M6LiveCommittedReadCutContext:
    """Hold A's writer slot across one committed B snapshot and one write phase."""

    outcome = _capture_cut_arguments(database_path, busy_timeout_ms)
    del database_path, busy_timeout_ms
    database, controlled_timeout = cast(tuple[Path, int], _outcome_value(outcome))
    return _new_cut_context(database, controlled_timeout)


__all__ = [
    "M6LiveCommittedReadCut",
    "M6LiveCommittedReadCutContext",
    "M6LiveCursor",
    "M6LiveDocumentColumn",
    "M6LivePendingSelector",
    "M6LiveReadCutError",
    "M6LiveReadCutFailureCode",
    "M6LiveReader",
    "M6LiveWriter",
    "M6SQLiteReadSession",
    "is_m6_sqlite_read_session",
    "m6_live_committed_read_cut",
]
