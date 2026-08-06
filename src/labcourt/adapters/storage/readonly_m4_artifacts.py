"""Read-only reconstruction of the complete M4 SQLite authority graph."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Generic, TypeVar, cast

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.hearing import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    EvidencePackDerivation,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingRoleOutput,
    HearingUsageReceipt,
    ToolExecutionManifest,
    ToolExecutionReceipt,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.references import require_reference_token

from ._readonly_m4_artifact_codec import (
    M4_TYPED_TABLES,
    M4_UNTYPED_TABLES,
    M4DocumentFailure,
    M4IndexFailure,
    M4Record,
    load_m4_record,
)
from .readonly_sqlite import ReadOnlySnapshotError
from .sqlite_schema import (
    M4_AUTHORITY_TABLES,
    M4_REQUIRED_MIGRATION_VERSIONS,
    m4_hearing_authority_installed,
)


class M4AuthorityFailureType(StrEnum):
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_MISMATCH = "INDEX_MISMATCH"
    REFERENCE_INVALID = "REFERENCE_INVALID"
    SCHEMA_UNSUPPORTED = "SCHEMA_UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class M4ArtifactAuthorityFailure:
    failure_type: M4AuthorityFailureType
    inventory_kind: M4ProjectionArtifactKind
    record_identity_sha256: str
    artifact_id: str | None
    reason_code: str


@dataclass(frozen=True, slots=True)
class M4ValidatedDocument:
    kind: M4ProjectionArtifactKind
    artifact_id: str
    canonical_document: str

    @property
    def document_sha256(self) -> str:
        return hashlib.sha256(self.canonical_document.encode("utf-8")).hexdigest()

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.kind.value, self.artifact_id)


M4ReplayDocument = (
    HearingModelRequest
    | HearingModelResponse
    | HearingModelCacheEntry
    | HearingUsageReceipt
    | HearingModelParseReceipt
    | HearingRoleOutput
    | HearingPrecedentRetrievalReceipt
    | HearingModelCallFailureAuthority
    | AcquisitionRequest
    | ToolExecutionManifest
    | AcquisitionExecutionPublication
    | ToolExecutionReceipt
    | EvidencePackDerivation
)
M4ReplayDocumentT = TypeVar("M4ReplayDocumentT", bound=BaseModel)

M4_REPLAY_AUTHORITY_KINDS = frozenset(
    {
        M4ProjectionArtifactKind.MODEL_REQUEST,
        M4ProjectionArtifactKind.MODEL_RESPONSE,
        M4ProjectionArtifactKind.MODEL_CACHE_ENTRY,
        M4ProjectionArtifactKind.USAGE_RECEIPT,
        M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
        M4ProjectionArtifactKind.ROLE_OUTPUT,
        M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL,
        M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY,
        M4ProjectionArtifactKind.ACQUISITION_REQUEST,
        M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST,
        M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION,
        M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
        M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION,
    }
)

_REPLAY_DOCUMENT_TYPE_BY_KIND: dict[
    M4ProjectionArtifactKind,
    type[BaseModel],
] = {
    M4ProjectionArtifactKind.MODEL_REQUEST: HearingModelRequest,
    M4ProjectionArtifactKind.MODEL_RESPONSE: HearingModelResponse,
    M4ProjectionArtifactKind.MODEL_CACHE_ENTRY: HearingModelCacheEntry,
    M4ProjectionArtifactKind.USAGE_RECEIPT: HearingUsageReceipt,
    M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT: HearingModelParseReceipt,
    M4ProjectionArtifactKind.ROLE_OUTPUT: HearingRoleOutput,
    M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL: HearingPrecedentRetrievalReceipt,
    M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY: (HearingModelCallFailureAuthority),
    M4ProjectionArtifactKind.ACQUISITION_REQUEST: AcquisitionRequest,
    M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST: ToolExecutionManifest,
    M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION: (AcquisitionExecutionPublication),
    M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT: ToolExecutionReceipt,
    M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION: EvidencePackDerivation,
}

_REPLAY_TABLE_BY_KIND: dict[M4ProjectionArtifactKind, str] = {
    M4ProjectionArtifactKind.MODEL_REQUEST: "m4_model_call_claims",
    M4ProjectionArtifactKind.MODEL_RESPONSE: "m4_model_responses",
    M4ProjectionArtifactKind.MODEL_CACHE_ENTRY: "m4_model_cache",
    M4ProjectionArtifactKind.USAGE_RECEIPT: "m4_hearing_usage_receipts",
    M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT: "m4_model_parse_receipts",
    M4ProjectionArtifactKind.ROLE_OUTPUT: "m4_parsed_hearing_outputs",
    M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL: ("m4_precedent_retrieval_receipts"),
    M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY: ("m4_model_call_failure_authorities"),
    M4ProjectionArtifactKind.ACQUISITION_REQUEST: "m4_acquisition_requests",
    M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST: ("m4_tool_execution_manifests"),
    M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION: (
        "m4_acquisition_execution_publications"
    ),
    M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT: "m4_tool_execution_receipts",
    M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION: ("m4_evidence_pack_derivations"),
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _replay_artifact_id(
    kind: M4ProjectionArtifactKind,
    document: BaseModel,
) -> str:
    attribute_by_kind = {
        M4ProjectionArtifactKind.MODEL_REQUEST: "request_id",
        M4ProjectionArtifactKind.MODEL_RESPONSE: "response_id",
        M4ProjectionArtifactKind.MODEL_CACHE_ENTRY: "cache_entry_id",
        M4ProjectionArtifactKind.USAGE_RECEIPT: "usage_receipt_id",
        M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT: "parse_receipt_id",
        M4ProjectionArtifactKind.ROLE_OUTPUT: "output_id",
        M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL: "receipt_id",
        M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY: "authority_id",
        M4ProjectionArtifactKind.ACQUISITION_REQUEST: "request_id",
        M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST: "execution_manifest_id",
        M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION: "publication_id",
        M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT: "receipt_id",
        M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION: "derivation_id",
    }
    value = getattr(document, attribute_by_kind[kind], None)
    if not isinstance(value, str):
        raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_IDENTITY_INVALID")
    return value


def _replay_record_identity(
    kind: M4ProjectionArtifactKind,
    artifact_id: str,
) -> str:
    return hashlib.sha256(
        canonical_json(
            [
                "m4-sqlite-record",
                1,
                _REPLAY_TABLE_BY_KIND[kind],
                kind.value,
                artifact_id,
            ]
        ).encode("utf-8")
    ).hexdigest()


def _replay_run_id(document: BaseModel) -> str | None:
    run_id = getattr(document, "run_id", None)
    if isinstance(run_id, str):
        return run_id
    if isinstance(document, (AcquisitionExecutionPublication, ToolExecutionReceipt)):
        return document.request.run_id
    return None


@dataclass(frozen=True, slots=True)
class M4ValidatedReplayDocument(Generic[M4ReplayDocumentT]):
    """One canonical typed M4 document safe for locked replay consumption."""

    kind: M4ProjectionArtifactKind
    artifact_id: str
    document: M4ReplayDocumentT
    record_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, M4ProjectionArtifactKind) or not isinstance(
            self.artifact_id, str
        ):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        expected_type = _REPLAY_DOCUMENT_TYPE_BY_KIND.get(self.kind)
        if expected_type is None or not isinstance(self.document, expected_type):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        try:
            canonical_document = canonical_json(self.document.model_dump(mode="json"))
            validated = expected_type.model_validate_json(canonical_document)
        except (AttributeError, ValidationError, TypeError, ValueError, UnicodeError):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_CONTRACT_INVALID") from None
        artifact_id = _replay_artifact_id(self.kind, validated)
        if self.artifact_id != artifact_id:
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_IDENTITY_INVALID")
        if (
            not isinstance(self.record_identity_sha256, str)
            or _SHA256.fullmatch(self.record_identity_sha256) is None
            or self.record_identity_sha256 != _replay_record_identity(self.kind, self.artifact_id)
        ):
            raise ReadOnlySnapshotError("VALIDATED_RECORD_IDENTITY_INVALID")
        object.__setattr__(self, "document", cast(M4ReplayDocumentT, validated))

    @property
    def canonical_document(self) -> str:
        return canonical_json(self.document.model_dump(mode="json"))

    @property
    def document_sha256(self) -> str:
        return hashlib.sha256(self.canonical_document.encode("utf-8")).hexdigest()

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (self.kind.value, self.artifact_id, self.record_identity_sha256)


def _revalidate_replay_documents(
    documents: object,
) -> tuple[M4ValidatedReplayDocument[M4ReplayDocument], ...]:
    if not isinstance(documents, tuple) or any(
        not isinstance(item, M4ValidatedReplayDocument) for item in documents
    ):
        raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
    return tuple(
        M4ValidatedReplayDocument(
            kind=item.kind,
            artifact_id=item.artifact_id,
            document=cast(M4ReplayDocument, item.document),
            record_identity_sha256=item.record_identity_sha256,
        )
        for item in documents
    )


@dataclass(frozen=True, slots=True)
class M4ReplayAuthoritySnapshot:
    """Closed M4 replay subset, bound to one fully validated authority graph."""

    run_id: str
    source_authority_root_sha256: str
    documents: tuple[M4ValidatedReplayDocument[M4ReplayDocument], ...]

    def __post_init__(self) -> None:
        documents = _revalidate_replay_documents(self.documents)
        object.__setattr__(self, "documents", documents)
        try:
            controlled_run_id = require_reference_token(
                self.run_id,
                "M4 replay authority run_id",
            )
        except (TypeError, ValueError):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_RUN_INVALID") from None
        if (
            controlled_run_id != self.run_id
            or not isinstance(self.source_authority_root_sha256, str)
            or _SHA256.fullmatch(self.source_authority_root_sha256) is None
        ):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_TYPE_INVALID")
        keys = tuple(item.sort_key for item in self.documents)
        identities = tuple((item.kind, item.artifact_id) for item in self.documents)
        record_identities = tuple(item.record_identity_sha256 for item in self.documents)
        if keys != tuple(sorted(keys)):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_ORDER_INVALID")
        if len(identities) != len(set(identities)) or len(record_identities) != len(
            set(record_identities)
        ):
            raise ReadOnlySnapshotError("DUPLICATE_VALIDATED_DOCUMENT")
        if any(_replay_run_id(item.document) != self.run_id for item in self.documents):
            raise ReadOnlySnapshotError("FOREIGN_VALIDATED_DOCUMENT")

    @property
    def authority_root_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json(
                [
                    "m4-replay-authority-snapshot",
                    1,
                    self.run_id,
                    self.source_authority_root_sha256,
                    [
                        [
                            item.kind.value,
                            item.artifact_id,
                            item.record_identity_sha256,
                            item.document_sha256,
                        ]
                        for item in self.documents
                    ],
                ]
            ).encode("utf-8")
        ).hexdigest()

    def documents_of_kind(
        self,
        kind: M4ProjectionArtifactKind,
    ) -> tuple[M4ValidatedReplayDocument[Any], ...]:
        if not isinstance(kind, M4ProjectionArtifactKind) or kind not in M4_REPLAY_AUTHORITY_KINDS:
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_KIND_INVALID")
        return tuple(item for item in self.documents if item.kind == kind)


@dataclass(frozen=True, slots=True)
class M4HearingAuthorityRoot:
    hearing_session_id: str
    case_id: str
    current_case_revision: int
    current_evidence_pack_id: str
    current_evidence_pack_version: int
    latest_checkpoint_id: str
    latest_checkpoint_version: int
    latest_round_id: str | None
    latest_record_id: str | None
    latest_record_version: int | None
    latest_record_sha256: str | None
    latest_verdict_id: str | None
    latest_review_id: str | None
    human_review_receipt_id: str | None
    root_sha256: str


@dataclass(frozen=True, slots=True)
class M4TraversedInventory:
    inventory_kind: M4ProjectionArtifactKind
    count: int


@dataclass(frozen=True, slots=True)
class M4ArtifactAuthoritySnapshot:
    run_id: str
    traversed: tuple[M4TraversedInventory, ...]
    documents: tuple[M4ValidatedDocument, ...]
    hearing_roots: tuple[M4HearingAuthorityRoot, ...]
    failures: tuple[M4ArtifactAuthorityFailure, ...]
    replay_documents: tuple[M4ValidatedReplayDocument[M4ReplayDocument], ...] = ()

    def __post_init__(self) -> None:
        replay_documents = _revalidate_replay_documents(self.replay_documents)
        object.__setattr__(self, "replay_documents", replay_documents)
        keys = tuple(item.sort_key for item in self.replay_documents)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ReadOnlySnapshotError("VALIDATED_DOCUMENT_ORDER_INVALID")
        if self.failures and self.replay_documents:
            raise ReadOnlySnapshotError("DATABASE_AUTHORITY_INVALID")
        if any(_replay_run_id(item.document) != self.run_id for item in self.replay_documents):
            raise ReadOnlySnapshotError("FOREIGN_VALIDATED_DOCUMENT")

    @property
    def authority_root_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json(
                [
                    "m4-authority-snapshot",
                    1,
                    self.run_id,
                    [
                        [item.kind.value, item.artifact_id, item.document_sha256]
                        for item in self.documents
                    ],
                    [[root.hearing_session_id, root.root_sha256] for root in self.hearing_roots],
                ]
            ).encode("utf-8")
        ).hexdigest()


class ReadonlyM4ArtifactRepository:
    """Validate M4 rows and both directions of their graph from one snapshot."""

    __slots__ = ("_immutable", "_snapshot")

    def __init__(self, snapshot: str | Path, *, immutable: bool = False) -> None:
        if not isinstance(immutable, bool):
            raise TypeError("immutable must be a bool")
        self._snapshot = Path(snapshot).absolute()
        self._immutable = immutable

    def scan(self, run_id: str) -> M4ArtifactAuthoritySnapshot:
        controlled_run_id = require_reference_token(run_id, "M4 artifact scan run_id")
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
            snapshot = self._scan_connection(connection, controlled_run_id)
            connection.commit()
            return snapshot
        except (sqlite3.Error, IndexError):
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID") from None
        finally:
            if connection is not None:
                connection.close()

    def scan_replay_authority(self, run_id: str) -> M4ReplayAuthoritySnapshot:
        """Return the locked-replay subset only when the complete M4 graph is valid."""

        authority = self.scan(run_id)
        if authority.failures:
            raise ReadOnlySnapshotError("DATABASE_AUTHORITY_INVALID")
        return M4ReplayAuthoritySnapshot(
            run_id=authority.run_id,
            source_authority_root_sha256=authority.authority_root_sha256,
            documents=authority.replay_documents,
        )

    def _scan_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> M4ArtifactAuthoritySnapshot:
        from ._readonly_m4_artifact_relations import M4ArtifactReferenceValidator

        self._require_schema(connection)
        failures: list[M4ArtifactAuthorityFailure] = []
        counts: Counter[M4ProjectionArtifactKind] = Counter()
        records: dict[M4ProjectionArtifactKind, list[M4Record]] = {
            kind: [] for kind in M4ProjectionArtifactKind
        }

        for spec in M4_TYPED_TABLES:
            order_by = spec.order_by or spec.id_column
            rows = tuple(
                connection.execute(
                    f'SELECT * FROM "{spec.table}" WHERE run_id = ? ORDER BY {order_by}',
                    (run_id,),
                ).fetchall()
            )
            for row in rows:
                counts[spec.kind] += 1
                artifact_id = row[spec.id_column]
                identity = _row_identity(spec.table, artifact_id)
                try:
                    record = load_m4_record(row, spec)
                except M4DocumentFailure as error:
                    _append_failure(
                        failures,
                        M4AuthorityFailureType.DOCUMENT_INVALID,
                        spec.kind,
                        identity,
                        artifact_id if isinstance(artifact_id, str) else None,
                        error.reason_code,
                    )
                    continue
                except M4IndexFailure as error:
                    _append_failure(
                        failures,
                        M4AuthorityFailureType.INDEX_MISMATCH,
                        spec.kind,
                        identity,
                        artifact_id if isinstance(artifact_id, str) else None,
                        error.reason_code,
                    )
                    continue
                records[spec.kind].append(record)

        for table, kind in M4_UNTYPED_TABLES:
            rows = tuple(
                connection.execute(
                    f'SELECT rowid, * FROM "{table}" WHERE run_id = ? ORDER BY rowid',
                    (run_id,),
                ).fetchall()
            )
            counts[kind] += len(rows)
            for row in rows:
                artifact_id = _first_text_identity(row)
                _append_failure(
                    failures,
                    M4AuthorityFailureType.SCHEMA_UNSUPPORTED,
                    kind,
                    _row_identity(table, artifact_id),
                    artifact_id,
                    "TYPED_CONTRACT_UNAVAILABLE",
                )

        relation = M4ArtifactReferenceValidator().validate(
            connection=connection,
            run_id=run_id,
            records=records,
        )
        failures.extend(relation.failures)
        documents = [
            M4ValidatedDocument(record.kind, record.artifact_id, record.canonical_document)
            for kind_records in records.values()
            for record in kind_records
        ]
        documents.extend(relation.documents)
        ordered_documents = tuple(sorted(set(documents), key=lambda item: item.sort_key))
        ordered_failures = tuple(
            sorted(
                set(failures),
                key=lambda item: (
                    item.inventory_kind.value,
                    item.record_identity_sha256,
                    item.failure_type.value,
                    item.reason_code,
                ),
            )
        )
        replay_documents = (
            ()
            if ordered_failures
            else tuple(
                sorted(
                    (
                        M4ValidatedReplayDocument(
                            kind=record.kind,
                            artifact_id=record.artifact_id,
                            document=cast(M4ReplayDocument, record.document),
                            record_identity_sha256=record.identity,
                        )
                        for kind in M4_REPLAY_AUTHORITY_KINDS
                        for record in records[kind]
                    ),
                    key=lambda item: item.sort_key,
                )
            )
        )
        traversed = tuple(
            M4TraversedInventory(kind, counts[kind]) for kind in M4ProjectionArtifactKind
        )
        return M4ArtifactAuthoritySnapshot(
            run_id=run_id,
            traversed=traversed,
            documents=ordered_documents,
            hearing_roots=relation.hearing_roots,
            failures=ordered_failures,
            replay_documents=replay_documents,
        )

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
                "SELECT version FROM schema_migrations WHERE version BETWEEN 4 AND 8"
            ).fetchall()
            if isinstance(row[0], int) and not isinstance(row[0], bool)
        }
        if (
            not M4_AUTHORITY_TABLES.issubset(tables)
            or versions != M4_REQUIRED_MIGRATION_VERSIONS
            or not m4_hearing_authority_installed(connection)
        ):
            raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")


def _row_identity(table: str, artifact_id: object) -> str:
    return hashlib.sha256(
        canonical_json(["m4-artifact-row", 1, table, artifact_id]).encode("utf-8")
    ).hexdigest()


def _first_text_identity(row: sqlite3.Row) -> str | None:
    for key in tuple(row.keys()):
        if key in {"run_id", "rowid"}:
            continue
        value = row[key]
        if isinstance(value, str):
            return value
    return None


def _append_failure(
    failures: list[M4ArtifactAuthorityFailure],
    failure_type: M4AuthorityFailureType,
    kind: M4ProjectionArtifactKind,
    identity: str,
    artifact_id: str | None,
    reason_code: str,
) -> None:
    failure = M4ArtifactAuthorityFailure(
        failure_type=failure_type,
        inventory_kind=kind,
        record_identity_sha256=identity,
        artifact_id=artifact_id,
        reason_code=reason_code,
    )
    if failure not in failures:
        failures.append(failure)


__all__ = [
    "M4_REPLAY_AUTHORITY_KINDS",
    "M4ArtifactAuthorityFailure",
    "M4ArtifactAuthoritySnapshot",
    "M4AuthorityFailureType",
    "M4HearingAuthorityRoot",
    "M4ReplayAuthoritySnapshot",
    "M4ReplayDocument",
    "M4TraversedInventory",
    "M4ValidatedDocument",
    "M4ValidatedReplayDocument",
    "ReadonlyM4ArtifactRepository",
]
