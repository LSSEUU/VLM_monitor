"""Canonical, read-only reconstruction of every durable M3 SQLite artifact.

This adapter only reads the private SQLite backup produced by
``readonly_sqlite_snapshot``.  Traversal is kept here while canonical row
decoding/index checks and cross-table authority validation live in focused
internal modules.  Malformed durable data is never repaired or normalized.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from pydantic import BaseModel

from labcourt.contracts.artifact_validation import M3ArtifactInventoryKind
from labcourt.contracts.backlog import BacklogCompletionReceipt, BacklogItem
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import UsageSummary
from labcourt.contracts.model_call_failures import ModelCallFailureAuthority
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import (
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningResult,
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.contracts.verdicts import ProceduralDefect, ProceduralReview, Verdict

from ._readonly_m3_artifact_codec import (
    _DocumentFailure,
    _DocumentLoader,
    _HeadRecord,
    _IndexFailure,
    _IndexValidator,
    _integer,
    _load_document,
    _load_request_document,
    _Record,
    _record_identity,
    _safe_artifact_id,
    _text,
    _validate_backlog_identity_index,
    _validate_backlog_version_index,
    _validate_cache_index,
    _validate_claim_index,
    _validate_completion_receipt_index,
    _validate_defect_index,
    _validate_failure_authority_index,
    _validate_parse_receipt_index,
    _validate_parsed_output_index,
    _validate_response_index,
    _validate_review_index,
    _validate_screening_index,
    _validate_usage_index,
    _validate_verdict_index,
)
from ._readonly_m3_artifact_relations import M3ArtifactReferenceValidator
from .readonly_sqlite import ReadOnlySnapshotError
from .sqlite_schema import (
    M3_REQUIRED_MIGRATION_VERSIONS,
    m3_authority_hardening_installed,
)


class M3AuthorityFailureType(StrEnum):
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_MISMATCH = "INDEX_MISMATCH"
    REFERENCE_INVALID = "REFERENCE_INVALID"


@dataclass(frozen=True, slots=True)
class M3ArtifactAuthorityFailure:
    failure_type: M3AuthorityFailureType
    inventory_kind: M3ArtifactInventoryKind
    record_identity_sha256: str
    artifact_id: str | None
    reason_code: str


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _validated_document_sha256(document: BaseModel) -> str:
    body = canonical_json(document.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _require_validated_record_identity(value: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_IDENTITY_INVALID")


def _require_validated_utc_timestamp(value: str) -> None:
    if not isinstance(value, str):
        raise ReadOnlySnapshotError("VALIDATED_USAGE_BINDING_INVALID")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        raise ReadOnlySnapshotError("VALIDATED_USAGE_BINDING_INVALID") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise ReadOnlySnapshotError("VALIDATED_USAGE_BINDING_INVALID")


@dataclass(frozen=True, slots=True)
class M3ValidatedModelCallRequest:
    request: VLMCallRequest
    record_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.request, (VLMRequest, StructureRepairRequest)):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        _require_validated_record_identity(self.record_identity_sha256)

    @property
    def document_sha256(self) -> str:
        return _validated_document_sha256(self.request)


@dataclass(frozen=True, slots=True)
class M3ValidatedModelCallFailureAuthority:
    authority: ModelCallFailureAuthority
    record_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.authority, ModelCallFailureAuthority):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        _require_validated_record_identity(self.record_identity_sha256)

    @property
    def document_sha256(self) -> str:
        return _validated_document_sha256(self.authority)


@dataclass(frozen=True, slots=True)
class M3ValidatedRawResponse:
    response: VLMResponse
    record_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.response, VLMResponse):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        _require_validated_record_identity(self.record_identity_sha256)

    @property
    def document_sha256(self) -> str:
        return _validated_document_sha256(self.response)


@dataclass(frozen=True, slots=True)
class M3ValidatedParsedScreeningOutput:
    output: ParsedScreeningOutput
    record_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.output, ParsedScreeningOutput):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        _require_validated_record_identity(self.record_identity_sha256)

    @property
    def document_sha256(self) -> str:
        return _validated_document_sha256(self.output)


@dataclass(frozen=True, slots=True)
class M3ValidatedModelParseReceipt:
    receipt: ModelParseReceipt
    record_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, ModelParseReceipt):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        _require_validated_record_identity(self.record_identity_sha256)

    @property
    def document_sha256(self) -> str:
        return _validated_document_sha256(self.receipt)


@dataclass(frozen=True, slots=True)
class M3ValidatedModelCacheEntry:
    request: VLMCallRequest
    entry: ModelCacheEntry
    record_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.request, (VLMRequest, StructureRepairRequest)) or not isinstance(
            self.entry,
            ModelCacheEntry,
        ):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        _require_validated_record_identity(self.record_identity_sha256)

    @property
    def request_document_sha256(self) -> str:
        return _validated_document_sha256(self.request)

    @property
    def document_sha256(self) -> str:
        return _validated_document_sha256(self.entry)


@dataclass(frozen=True, slots=True)
class M3ValidatedModelCallUsage:
    """Canonical usage document bound to the durable call and consumer row."""

    usage: UsageSummary
    request_id: str
    response_id: str
    case_id: str
    case_revision: int
    consumer_kind: str
    consumer_id: str
    accounted_at: str
    record_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.usage, UsageSummary):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        for value in (self.request_id, self.response_id, self.consumer_id):
            _require_validated_record_identity(value)
        if not isinstance(self.case_id, str) or not self.case_id:
            raise ReadOnlySnapshotError("VALIDATED_USAGE_BINDING_INVALID")
        if (
            not isinstance(self.case_revision, int)
            or isinstance(self.case_revision, bool)
            or self.case_revision <= 0
        ):
            raise ReadOnlySnapshotError("VALIDATED_USAGE_BINDING_INVALID")
        if self.consumer_kind not in {"SCREENING_RESULT", "BACKLOG_ITEM"}:
            raise ReadOnlySnapshotError("VALIDATED_USAGE_BINDING_INVALID")
        _require_validated_utc_timestamp(self.accounted_at)
        _require_validated_record_identity(self.record_identity_sha256)

    @property
    def document_sha256(self) -> str:
        return _validated_document_sha256(self.usage)


@dataclass(frozen=True, slots=True)
class M3TraversedInventory:
    inventory_kind: M3ArtifactInventoryKind
    count: int


@dataclass(frozen=True, slots=True)
class M3ArtifactAuthoritySnapshot:
    traversed: tuple[M3TraversedInventory, ...]
    raw_responses: tuple[M3ValidatedRawResponse, ...]
    failures: tuple[M3ArtifactAuthorityFailure, ...]
    model_call_requests: tuple[M3ValidatedModelCallRequest, ...] = ()
    model_call_failure_authorities: tuple[M3ValidatedModelCallFailureAuthority, ...] = ()
    parsed_outputs: tuple[M3ValidatedParsedScreeningOutput, ...] = ()
    parse_receipts: tuple[M3ValidatedModelParseReceipt, ...] = ()
    model_cache_entries: tuple[M3ValidatedModelCacheEntry, ...] = ()
    model_call_usages: tuple[M3ValidatedModelCallUsage, ...] = ()

    def __post_init__(self) -> None:
        typed_groups: tuple[tuple[object, type[object]], ...] = (
            (self.model_call_requests, M3ValidatedModelCallRequest),
            (
                self.model_call_failure_authorities,
                M3ValidatedModelCallFailureAuthority,
            ),
            (self.raw_responses, M3ValidatedRawResponse),
            (self.parsed_outputs, M3ValidatedParsedScreeningOutput),
            (self.parse_receipts, M3ValidatedModelParseReceipt),
            (self.model_cache_entries, M3ValidatedModelCacheEntry),
            (self.model_call_usages, M3ValidatedModelCallUsage),
        )
        for observations, expected_type in typed_groups:
            if not isinstance(observations, tuple) or any(
                not isinstance(item, expected_type) for item in observations
            ):
                raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")

        key_groups = (
            tuple(
                (item.request.request_id, item.record_identity_sha256)
                for item in self.model_call_requests
            ),
            tuple(
                (item.authority.authority_id, item.record_identity_sha256)
                for item in self.model_call_failure_authorities
            ),
            tuple(
                (item.response.response_id, item.record_identity_sha256)
                for item in self.raw_responses
            ),
            tuple(
                (item.output.parsed_output_id, item.record_identity_sha256)
                for item in self.parsed_outputs
            ),
            tuple(
                (item.receipt.parse_receipt_id, item.record_identity_sha256)
                for item in self.parse_receipts
            ),
            tuple(
                (item.entry.cache_entry_id, item.record_identity_sha256)
                for item in self.model_cache_entries
            ),
            tuple(
                (item.request_id, item.record_identity_sha256) for item in self.model_call_usages
            ),
        )
        for keys in key_groups:
            if (
                len(keys) != len(set(keys))
                or len(keys) != len({artifact_id for artifact_id, _identity in keys})
                or len(keys) != len({_identity for _artifact_id, _identity in keys})
            ):
                raise ReadOnlySnapshotError("DUPLICATE_VALIDATED_DOCUMENT")
            if keys != tuple(sorted(keys)):
                raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_ORDER_INVALID")


class ReadonlyM3ArtifactRepository:
    """Reconstruct M3 authority from a private, immutable SQLite snapshot."""

    __slots__ = ("_snapshot",)

    def __init__(self, snapshot: str | Path) -> None:
        self._snapshot = Path(snapshot).absolute()

    def scan(self, run_id: str) -> M3ArtifactAuthoritySnapshot:
        run_id = require_reference_token(run_id, "M3 artifact scan run_id")
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
            snapshot = self._scan_connection(connection, run_id)
            connection.commit()
            return snapshot
        except _IndexFailure:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise ReadOnlySnapshotError("DATABASE_AUTHORITY_INVALID") from None
        except (sqlite3.Error, IndexError):
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
    ) -> M3ArtifactAuthoritySnapshot:
        if not self._require_schema(connection):
            return M3ArtifactAuthoritySnapshot(
                traversed=tuple(M3TraversedInventory(kind, 0) for kind in M3ArtifactInventoryKind),
                raw_responses=(),
                failures=(),
            )
        failures: list[M3ArtifactAuthorityFailure] = []
        counts: Counter[M3ArtifactInventoryKind] = Counter()
        records: dict[M3ArtifactInventoryKind, list[_Record]] = {
            kind: [] for kind in M3ArtifactInventoryKind
        }
        cache_requests: dict[str, VLMCallRequest] = {}

        self._scan_claims(connection, run_id, counts, records, failures)
        self._scan_failure_authorities(connection, run_id, counts, records, failures)
        self._scan_responses(connection, run_id, counts, records, failures)
        self._scan_parsed_outputs(connection, run_id, counts, records, failures)
        self._scan_parse_receipts(connection, run_id, counts, records, failures)
        self._scan_cache(
            connection,
            run_id,
            counts,
            records,
            failures,
            cache_requests,
        )
        self._scan_usage(connection, run_id, counts, records, failures)
        self._scan_screenings(connection, run_id, counts, records, failures)
        self._scan_verdicts(connection, run_id, counts, records, failures)
        self._scan_reviews(connection, run_id, counts, records, failures)
        self._scan_defects(connection, run_id, counts, records, failures)
        self._scan_backlog_items(connection, run_id, counts, records, failures)
        self._scan_backlog_versions(connection, run_id, counts, records, failures)
        heads = self._scan_backlog_heads(connection, run_id, counts, failures)
        self._scan_backlog_completion_receipts(
            connection,
            run_id,
            counts,
            records,
            failures,
        )
        M3ArtifactReferenceValidator(self._reference_failure).validate(
            connection,
            run_id,
            records,
            heads,
            cache_requests,
            failures,
        )

        request_records = records[M3ArtifactInventoryKind.MODEL_CALL_CLAIM]
        model_call_requests = tuple(
            sorted(
                (
                    M3ValidatedModelCallRequest(
                        request=cast(VLMCallRequest, record.document),
                        record_identity_sha256=record.identity,
                    )
                    for record in request_records
                ),
                key=lambda item: (item.request.request_id, item.record_identity_sha256),
            )
        )
        failure_authority_records = records[M3ArtifactInventoryKind.MODEL_CALL_FAILURE_AUTHORITY]
        model_call_failure_authorities = tuple(
            sorted(
                (
                    M3ValidatedModelCallFailureAuthority(
                        authority=cast(ModelCallFailureAuthority, record.document),
                        record_identity_sha256=record.identity,
                    )
                    for record in failure_authority_records
                ),
                key=lambda item: (
                    item.authority.authority_id,
                    item.record_identity_sha256,
                ),
            )
        )
        response_records = records[M3ArtifactInventoryKind.MODEL_RESPONSE]
        raw_responses = tuple(
            sorted(
                (
                    M3ValidatedRawResponse(
                        response=cast(VLMResponse, record.document),
                        record_identity_sha256=record.identity,
                    )
                    for record in response_records
                ),
                key=lambda item: item.response.response_id,
            )
        )
        output_records = records[M3ArtifactInventoryKind.PARSED_SCREENING_OUTPUT]
        parsed_outputs = tuple(
            sorted(
                (
                    M3ValidatedParsedScreeningOutput(
                        output=cast(ParsedScreeningOutput, record.document),
                        record_identity_sha256=record.identity,
                    )
                    for record in output_records
                ),
                key=lambda item: (
                    item.output.parsed_output_id,
                    item.record_identity_sha256,
                ),
            )
        )
        receipt_records = records[M3ArtifactInventoryKind.MODEL_PARSE_RECEIPT]
        parse_receipts = tuple(
            sorted(
                (
                    M3ValidatedModelParseReceipt(
                        receipt=cast(ModelParseReceipt, record.document),
                        record_identity_sha256=record.identity,
                    )
                    for record in receipt_records
                ),
                key=lambda item: (
                    item.receipt.parse_receipt_id,
                    item.record_identity_sha256,
                ),
            )
        )
        cache_records = records[M3ArtifactInventoryKind.MODEL_CACHE_ENTRY]
        model_cache_entries = tuple(
            sorted(
                (
                    M3ValidatedModelCacheEntry(
                        request=cache_requests[
                            cast(ModelCacheEntry, record.document).cache_entry_id
                        ],
                        entry=cast(ModelCacheEntry, record.document),
                        record_identity_sha256=record.identity,
                    )
                    for record in cache_records
                ),
                key=lambda item: (
                    item.entry.cache_entry_id,
                    item.record_identity_sha256,
                ),
            )
        )
        usage_records = records[M3ArtifactInventoryKind.MODEL_CALL_USAGE]
        model_call_usages = tuple(
            sorted(
                (
                    M3ValidatedModelCallUsage(
                        usage=cast(UsageSummary, record.document),
                        request_id=_text(record.row, "request_id"),
                        response_id=_text(record.row, "response_id"),
                        case_id=_text(record.row, "case_id"),
                        case_revision=_integer(record.row, "case_revision"),
                        consumer_kind=_text(record.row, "consumer_kind"),
                        consumer_id=_text(record.row, "consumer_id"),
                        accounted_at=_text(record.row, "accounted_at"),
                        record_identity_sha256=record.identity,
                    )
                    for record in usage_records
                ),
                key=lambda item: (item.request_id, item.record_identity_sha256),
            )
        )
        traversed = tuple(
            M3TraversedInventory(kind, counts[kind]) for kind in M3ArtifactInventoryKind
        )
        ordered_failures = tuple(
            sorted(
                failures,
                key=lambda item: (
                    item.inventory_kind.value,
                    item.record_identity_sha256,
                    item.failure_type.value,
                    item.reason_code,
                ),
            )
        )
        return M3ArtifactAuthoritySnapshot(
            traversed=traversed,
            raw_responses=raw_responses,
            failures=ordered_failures,
            model_call_requests=model_call_requests,
            model_call_failure_authorities=model_call_failure_authorities,
            parsed_outputs=parsed_outputs,
            parse_receipts=parse_receipts,
            model_cache_entries=model_cache_entries,
            model_call_usages=model_call_usages,
        )

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> bool:
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        if len(integrity_rows) != 1 or integrity_rows[0][0] != "ok":
            raise ReadOnlySnapshotError("DATABASE_INTEGRITY_INVALID")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ReadOnlySnapshotError("DATABASE_FOREIGN_KEY_INVALID")
        expected = {
            "model_call_claims",
            "model_call_failure_authorities",
            "model_responses",
            "parsed_screening_outputs",
            "model_parse_receipts",
            "model_cache",
            "model_call_usage_accounting",
            "screening_results",
            "verdicts",
            "procedural_reviews",
            "procedural_defects",
            "backlog_items",
            "backlog_item_versions",
            "backlog_heads",
            "backlog_completion_receipts",
        }
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
        all_tables = {str(row[0]) for row in table_rows if isinstance(row[0], str)}
        tables = all_tables & expected
        versions = {
            int(row[0])
            for row in connection.execute(
                "SELECT version FROM schema_migrations WHERE version IN (4, 5, 6, 7)"
            ).fetchall()
            if isinstance(row[0], int) and not isinstance(row[0], bool)
        }
        if not tables and not versions:
            return False
        if (
            tables != expected
            or versions != M3_REQUIRED_MIGRATION_VERSIONS
            or not m3_authority_hardening_installed(connection)
        ):
            raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
        return True

    @staticmethod
    def _failure(
        failures: list[M3ArtifactAuthorityFailure],
        *,
        failure_type: M3AuthorityFailureType,
        kind: M3ArtifactInventoryKind,
        identity: str,
        artifact_id: str | None,
        reason_code: str,
    ) -> None:
        failure = M3ArtifactAuthorityFailure(
            failure_type=failure_type,
            inventory_kind=kind,
            record_identity_sha256=identity,
            artifact_id=artifact_id,
            reason_code=reason_code,
        )
        if failure not in failures:
            failures.append(failure)

    def _scan_document_rows(
        self,
        *,
        rows: tuple[sqlite3.Row, ...],
        kind: M3ArtifactInventoryKind,
        identity_keys: tuple[str, ...],
        artifact_id_key: str,
        loader: object,
        index_validator: object,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        load = cast(_DocumentLoader, loader)
        validate_index = cast(_IndexValidator, index_validator)
        for row in rows:
            counts[kind] += 1
            identity = _record_identity(kind, row, identity_keys)
            artifact_id = _safe_artifact_id(row, artifact_id_key)
            try:
                document = load(row)
            except _DocumentFailure as error:
                self._failure(
                    failures,
                    failure_type=M3AuthorityFailureType.DOCUMENT_INVALID,
                    kind=kind,
                    identity=identity,
                    artifact_id=artifact_id,
                    reason_code=error.reason_code,
                )
                continue
            try:
                validate_index(row, document)
            except _IndexFailure as error:
                self._failure(
                    failures,
                    failure_type=M3AuthorityFailureType.INDEX_MISMATCH,
                    kind=kind,
                    identity=identity,
                    artifact_id=artifact_id,
                    reason_code=error.reason_code,
                )
                continue
            records[kind].append(_Record(kind, identity, artifact_id, row, document))

    @staticmethod
    def _rows(
        connection: sqlite3.Connection,
        table: str,
        run_id: str,
        order_by: str,
    ) -> tuple[sqlite3.Row, ...]:
        allowed = {
            "model_call_claims",
            "model_call_failure_authorities",
            "model_responses",
            "parsed_screening_outputs",
            "model_parse_receipts",
            "model_cache",
            "model_call_usage_accounting",
            "screening_results",
            "verdicts",
            "procedural_reviews",
            "procedural_defects",
            "backlog_items",
            "backlog_item_versions",
            "backlog_heads",
            "backlog_completion_receipts",
        }
        if table not in allowed:
            raise ValueError("unsupported M3 artifact table")
        return tuple(
            connection.execute(
                f"SELECT * FROM {table} WHERE run_id = ? ORDER BY {order_by}",
                (run_id,),
            ).fetchall()
        )

    def _scan_claims(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(connection, "model_call_claims", run_id, "request_id"),
            kind=M3ArtifactInventoryKind.MODEL_CALL_CLAIM,
            identity_keys=("request_id",),
            artifact_id_key="request_id",
            loader=lambda row: cast(
                BaseModel,
                _load_request_document(
                    row,
                    json_key="request_json",
                    sha256_key="request_document_sha256",
                ),
            ),
            index_validator=_validate_claim_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_failure_authorities(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(
                connection,
                "model_call_failure_authorities",
                run_id,
                "authority_id",
            ),
            kind=M3ArtifactInventoryKind.MODEL_CALL_FAILURE_AUTHORITY,
            identity_keys=("authority_id",),
            artifact_id_key="authority_id",
            loader=lambda row: _load_document(
                row,
                json_key="authority_json",
                sha256_key="document_sha256",
                model_type=ModelCallFailureAuthority,
            ),
            index_validator=_validate_failure_authority_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_responses(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(connection, "model_responses", run_id, "response_id"),
            kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
            identity_keys=("response_id",),
            artifact_id_key="response_id",
            loader=lambda row: _load_document(
                row,
                json_key="response_json",
                sha256_key="document_sha256",
                model_type=VLMResponse,
            ),
            index_validator=_validate_response_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_parsed_outputs(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(
                connection,
                "parsed_screening_outputs",
                run_id,
                "parsed_output_id",
            ),
            kind=M3ArtifactInventoryKind.PARSED_SCREENING_OUTPUT,
            identity_keys=("parsed_output_id",),
            artifact_id_key="parsed_output_id",
            loader=lambda row: _load_document(
                row,
                json_key="output_json",
                sha256_key="document_sha256",
                model_type=ParsedScreeningOutput,
            ),
            index_validator=_validate_parsed_output_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_parse_receipts(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(
                connection,
                "model_parse_receipts",
                run_id,
                "parse_receipt_id",
            ),
            kind=M3ArtifactInventoryKind.MODEL_PARSE_RECEIPT,
            identity_keys=("parse_receipt_id",),
            artifact_id_key="parse_receipt_id",
            loader=lambda row: _load_document(
                row,
                json_key="receipt_json",
                sha256_key="document_sha256",
                model_type=ModelParseReceipt,
            ),
            index_validator=_validate_parse_receipt_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_cache(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
        cache_requests: dict[str, VLMCallRequest],
    ) -> None:
        kind = M3ArtifactInventoryKind.MODEL_CACHE_ENTRY
        for row in self._rows(connection, "model_cache", run_id, "cache_key"):
            counts[kind] += 1
            identity = _record_identity(kind, row, ("cache_key",))
            artifact_id = _safe_artifact_id(row, "cache_entry_id")
            try:
                request = _load_request_document(
                    row,
                    json_key="request_json",
                    sha256_key="request_document_sha256",
                )
                entry = cast(
                    ModelCacheEntry,
                    _load_document(
                        row,
                        json_key="entry_json",
                        sha256_key="document_sha256",
                        model_type=ModelCacheEntry,
                    ),
                )
            except _DocumentFailure as error:
                self._failure(
                    failures,
                    failure_type=M3AuthorityFailureType.DOCUMENT_INVALID,
                    kind=kind,
                    identity=identity,
                    artifact_id=artifact_id,
                    reason_code=error.reason_code,
                )
                continue
            try:
                _validate_cache_index(row, request, entry)
            except _IndexFailure as error:
                self._failure(
                    failures,
                    failure_type=M3AuthorityFailureType.INDEX_MISMATCH,
                    kind=kind,
                    identity=identity,
                    artifact_id=artifact_id,
                    reason_code=error.reason_code,
                )
                continue
            records[kind].append(_Record(kind, identity, artifact_id, row, entry))
            if entry.cache_entry_id in cache_requests:
                raise _IndexFailure("DUPLICATE_CACHE_ENTRY_ID")
            cache_requests[entry.cache_entry_id] = request

    def _scan_usage(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(
                connection,
                "model_call_usage_accounting",
                run_id,
                "request_id",
            ),
            kind=M3ArtifactInventoryKind.MODEL_CALL_USAGE,
            identity_keys=("request_id",),
            artifact_id_key="request_id",
            loader=lambda row: _load_document(
                row,
                json_key="usage_json",
                sha256_key="document_sha256",
                model_type=UsageSummary,
            ),
            index_validator=_validate_usage_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_screenings(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(connection, "screening_results", run_id, "screening_id"),
            kind=M3ArtifactInventoryKind.SCREENING_RESULT,
            identity_keys=("screening_id",),
            artifact_id_key="screening_id",
            loader=lambda row: _load_document(
                row,
                json_key="result_json",
                sha256_key="document_sha256",
                model_type=ScreeningResult,
            ),
            index_validator=_validate_screening_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_verdicts(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(connection, "verdicts", run_id, "verdict_id"),
            kind=M3ArtifactInventoryKind.VERDICT,
            identity_keys=("verdict_id",),
            artifact_id_key="verdict_id",
            loader=lambda row: _load_document(
                row,
                json_key="verdict_json",
                sha256_key="document_sha256",
                model_type=Verdict,
            ),
            index_validator=_validate_verdict_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_reviews(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(connection, "procedural_reviews", run_id, "review_id"),
            kind=M3ArtifactInventoryKind.PROCEDURAL_REVIEW,
            identity_keys=("review_id",),
            artifact_id_key="review_id",
            loader=lambda row: _load_document(
                row,
                json_key="review_json",
                sha256_key="document_sha256",
                model_type=ProceduralReview,
            ),
            index_validator=_validate_review_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_defects(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(
                connection,
                "procedural_defects",
                run_id,
                "owner_kind, owner_id, ordinal",
            ),
            kind=M3ArtifactInventoryKind.PROCEDURAL_DEFECT,
            identity_keys=("owner_kind", "owner_id", "ordinal"),
            artifact_id_key="defect_id",
            loader=lambda row: _load_document(
                row,
                json_key="defect_json",
                sha256_key="document_sha256",
                model_type=ProceduralDefect,
            ),
            index_validator=_validate_defect_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_backlog_items(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(connection, "backlog_items", run_id, "item_id"),
            kind=M3ArtifactInventoryKind.BACKLOG_ITEM,
            identity_keys=("item_id",),
            artifact_id_key="item_id",
            loader=lambda row: _load_document(
                row,
                json_key="initial_json",
                sha256_key="initial_document_sha256",
                model_type=BacklogItem,
            ),
            index_validator=_validate_backlog_identity_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_backlog_versions(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(
                connection,
                "backlog_item_versions",
                run_id,
                "item_id, version",
            ),
            kind=M3ArtifactInventoryKind.BACKLOG_ITEM_VERSION,
            identity_keys=("item_id", "version"),
            artifact_id_key="item_id",
            loader=lambda row: _load_document(
                row,
                json_key="item_json",
                sha256_key="document_sha256",
                model_type=BacklogItem,
            ),
            index_validator=_validate_backlog_version_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _scan_backlog_heads(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> tuple[_HeadRecord, ...]:
        kind = M3ArtifactInventoryKind.BACKLOG_HEAD
        heads: list[_HeadRecord] = []
        for row in self._rows(connection, "backlog_heads", run_id, "item_id"):
            counts[kind] += 1
            identity = _record_identity(kind, row, ("item_id",))
            artifact_id = _safe_artifact_id(row, "item_id")
            try:
                if (
                    _text(row, "run_id") != run_id
                    or _safe_artifact_id(row, "item_id") is None
                    or _integer(row, "current_version") <= 0
                ):
                    raise _IndexFailure()
            except _IndexFailure as error:
                self._failure(
                    failures,
                    failure_type=M3AuthorityFailureType.INDEX_MISMATCH,
                    kind=kind,
                    identity=identity,
                    artifact_id=artifact_id,
                    reason_code=error.reason_code,
                )
                continue
            heads.append(_HeadRecord(identity, artifact_id, row))
        return tuple(heads)

    def _scan_backlog_completion_receipts(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        counts: Counter[M3ArtifactInventoryKind],
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        self._scan_document_rows(
            rows=self._rows(
                connection,
                "backlog_completion_receipts",
                run_id,
                "receipt_id",
            ),
            kind=M3ArtifactInventoryKind.BACKLOG_COMPLETION_RECEIPT,
            identity_keys=("receipt_id",),
            artifact_id_key="receipt_id",
            loader=lambda row: _load_document(
                row,
                json_key="receipt_json",
                sha256_key="document_sha256",
                model_type=BacklogCompletionReceipt,
            ),
            index_validator=_validate_completion_receipt_index,
            counts=counts,
            records=records,
            failures=failures,
        )

    def _reference_failure(
        self,
        failures: list[M3ArtifactAuthorityFailure],
        record: _Record | _HeadRecord,
        reason_code: str,
    ) -> None:
        kind = record.kind if isinstance(record, _Record) else M3ArtifactInventoryKind.BACKLOG_HEAD
        self._failure(
            failures,
            failure_type=M3AuthorityFailureType.REFERENCE_INVALID,
            kind=kind,
            identity=record.identity,
            artifact_id=record.artifact_id,
            reason_code=reason_code,
        )


__all__ = [
    "M3ArtifactAuthorityFailure",
    "M3ArtifactAuthoritySnapshot",
    "M3AuthorityFailureType",
    "M3TraversedInventory",
    "M3ValidatedModelCacheEntry",
    "M3ValidatedModelCallFailureAuthority",
    "M3ValidatedModelCallRequest",
    "M3ValidatedModelCallUsage",
    "M3ValidatedModelParseReceipt",
    "M3ValidatedParsedScreeningOutput",
    "M3ValidatedRawResponse",
    "ReadonlyM3ArtifactRepository",
]
