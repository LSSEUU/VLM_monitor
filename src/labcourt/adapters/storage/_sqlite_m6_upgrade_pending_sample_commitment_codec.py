"""Strict SQLite codec for durable M6 pending sample commitments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.m6_regression import MAX_M6_REGRESSION_CASES
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    MAX_M6_UPGRADE_PENDING_SAMPLE_COMMITMENT_DOCUMENT_BYTES,
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.references import require_reference_token
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
)

from ._sqlite_read_session import SQLiteReadSession
from .sqlite_repository import (
    RepositoryIntegrityError,
    _document,
    _row_int,
    _row_str,
    _verify_contract_document,
)

MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES = MAX_M6_UPGRADE_PENDING_SAMPLE_COMMITMENT_DOCUMENT_BYTES
MAX_M6_UPGRADE_PENDING_RECORD_BYTES = MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES
MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES
MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES

_ModelT = TypeVar("_ModelT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class M6UpgradePendingSampleCommitmentDocuments:
    """Canonical storage documents for one commitment and its exact V2 record."""

    commitment_json: str
    document_sha256: str
    size_bytes: int
    sample_execution_record_json: str
    sample_execution_record_document_sha256: str
    sample_execution_record_size_bytes: int


@dataclass(frozen=True, slots=True)
class StoredM6UpgradePendingSampleCommitment:
    """Validated authority plus the exact canonical bytes persisted for it."""

    authority: M6UpgradePendingSampleCommitmentAuthority
    documents: M6UpgradePendingSampleCommitmentDocuments


def _error(
    code: M6UpgradePendingSampleCommitmentFailureCode,
) -> M6UpgradePendingSampleCommitmentError:
    return M6UpgradePendingSampleCommitmentError(code)


def _require_complete_key(
    candidate_run_id: object,
    execution_scope_authority_id: object,
    ledger_sequence: object,
) -> tuple[str, str, int]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(
            candidate_run_id,
            "M6 pending sample commitment candidate run_id",
        )
    except (TypeError, ValueError) as exc:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT) from exc
    if (
        not isinstance(execution_scope_authority_id, str)
        or len(execution_scope_authority_id) != 64
        or any(character not in "0123456789abcdef" for character in execution_scope_authority_id)
        or not isinstance(ledger_sequence, int)
        or isinstance(ledger_sequence, bool)
        or not 0 <= ledger_sequence < MAX_M6_REGRESSION_CASES
    ):
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT)
    return run_id, execution_scope_authority_id, ledger_sequence


def canonical_pending_sample_commitment(
    value: object,
) -> M6UpgradePendingSampleCommitmentAuthority:
    """Reject untyped, constructed, or otherwise non-canonical input."""

    if not isinstance(value, M6UpgradePendingSampleCommitmentAuthority):
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT)
    try:
        controlled = M6UpgradePendingSampleCommitmentAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT) from exc
    if controlled != value:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT)
    return controlled


def pending_sample_commitment_documents(
    value: M6UpgradePendingSampleCommitmentAuthority,
) -> M6UpgradePendingSampleCommitmentDocuments:
    """Build and cross-check both canonical documents before persistence."""

    controlled = canonical_pending_sample_commitment(value)
    record_json, record_sha256 = _document(controlled.sample_execution_record)
    record_size = len(record_json.encode("utf-8"))
    if record_size > MAX_M6_UPGRADE_PENDING_RECORD_BYTES:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE)
    if (
        record_sha256 != controlled.sample_execution_record_document_sha256
        or record_size != controlled.sample_execution_record_size_bytes
    ):
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT)

    commitment_json, document_sha256 = _document(controlled)
    size_bytes = len(commitment_json.encode("utf-8"))
    if size_bytes > MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE)
    return M6UpgradePendingSampleCommitmentDocuments(
        commitment_json=commitment_json,
        document_sha256=document_sha256,
        size_bytes=size_bytes,
        sample_execution_record_json=record_json,
        sample_execution_record_document_sha256=record_sha256,
        sample_execution_record_size_bytes=record_size,
    )


def _preflight_pending_sample_commitment(
    connection: SQLiteReadSession,
    *,
    run_id: str,
    execution_scope_authority_id: str,
    ledger_sequence: int,
) -> int:
    """Check both raw documents and their claims before selecting either TEXT value."""

    row = connection.execute(
        """
        SELECT
            COUNT(*) AS item_count,
            COALESCE(SUM(
                CASE WHEN typeof(size_bytes) = 'integer'
                           AND size_bytes BETWEEN 1 AND ?
                     THEN size_bytes ELSE 0 END
            ), 0) AS commitment_claimed_bytes,
            COALESCE(SUM(
                CASE WHEN typeof(commitment_json) = 'text'
                     THEN length(CAST(commitment_json AS BLOB)) ELSE 0 END
            ), 0) AS commitment_actual_bytes,
            COALESCE(SUM(
                CASE WHEN typeof(sample_execution_record_size_bytes) = 'integer'
                           AND sample_execution_record_size_bytes BETWEEN 1 AND ?
                     THEN sample_execution_record_size_bytes ELSE 0 END
            ), 0) AS record_claimed_bytes,
            COALESCE(SUM(
                CASE WHEN typeof(sample_execution_record_json) = 'text'
                     THEN length(CAST(sample_execution_record_json AS BLOB)) ELSE 0 END
            ), 0) AS record_actual_bytes,
            COALESCE(SUM(
                CASE WHEN typeof(size_bytes) <> 'integer'
                           OR typeof(commitment_json) <> 'text'
                           OR size_bytes < 1
                           OR length(CAST(commitment_json AS BLOB)) < 1
                           OR size_bytes <> length(CAST(commitment_json AS BLOB))
                           OR typeof(sample_execution_record_size_bytes) <> 'integer'
                           OR typeof(sample_execution_record_json) <> 'text'
                           OR sample_execution_record_size_bytes < 1
                           OR length(CAST(sample_execution_record_json AS BLOB)) < 1
                           OR sample_execution_record_size_bytes
                              <> length(CAST(sample_execution_record_json AS BLOB))
                     THEN 1 ELSE 0 END
            ), 0) AS invalid_count,
            COALESCE(SUM(
                CASE WHEN (typeof(size_bytes) = 'integer' AND size_bytes > ?)
                           OR length(CAST(commitment_json AS BLOB)) > ?
                           OR (typeof(sample_execution_record_size_bytes) = 'integer'
                               AND sample_execution_record_size_bytes > ?)
                           OR length(CAST(sample_execution_record_json AS BLOB)) > ?
                     THEN 1 ELSE 0 END
            ), 0) AS oversized_count
        FROM m6_upgrade_pending_sample_commitments
        WHERE run_id = ?
          AND execution_scope_authority_id = ?
          AND ledger_sequence = ?
        """,
        (
            MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES,
            MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
            MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES,
            MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES,
            MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
            MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
            run_id,
            execution_scope_authority_id,
            ledger_sequence,
        ),
    ).fetchone()
    try:
        if row is None:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        item_count = _row_int(row, "item_count")
        commitment_claimed_bytes = _row_int(row, "commitment_claimed_bytes")
        commitment_actual_bytes = _row_int(row, "commitment_actual_bytes")
        record_claimed_bytes = _row_int(row, "record_claimed_bytes")
        record_actual_bytes = _row_int(row, "record_actual_bytes")
        invalid_count = _row_int(row, "invalid_count")
        oversized_count = _row_int(row, "oversized_count")
    except M6UpgradePendingSampleCommitmentError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID) from exc
    if item_count > 1:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
    if item_count == 0:
        return 0
    if oversized_count:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE)
    if (
        invalid_count
        or commitment_claimed_bytes != commitment_actual_bytes
        or record_claimed_bytes != record_actual_bytes
    ):
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
    return item_count


def _parse_canonical_document(
    *,
    raw: str,
    document_sha256: str,
    claimed_size_bytes: int,
    max_bytes: int,
    model_type: type[_ModelT],
) -> _ModelT:
    if claimed_size_bytes > max_bytes:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE)
    encoded_size = len(raw.encode("utf-8"))
    if encoded_size > max_bytes:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE)
    if encoded_size != claimed_size_bytes:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
    try:
        value = model_type.model_validate_json(raw)
        _verify_contract_document(raw, value)
        canonical, observed_sha256 = _document(value)
    except (TypeError, ValueError, ValidationError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID) from exc
    if canonical != raw or observed_sha256 != document_sha256:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
    return value


def pending_sample_commitment_from_connection(
    connection: SQLiteReadSession,
    candidate_run_id: object,
    execution_scope_authority_id: object,
    ledger_sequence: object,
) -> StoredM6UpgradePendingSampleCommitment | None:
    """Load one complete key without reading raw JSON until its preflight passes."""

    run_id, scope_id, sequence = _require_complete_key(
        candidate_run_id,
        execution_scope_authority_id,
        ledger_sequence,
    )
    if (
        _preflight_pending_sample_commitment(
            connection,
            run_id=run_id,
            execution_scope_authority_id=scope_id,
            ledger_sequence=sequence,
        )
        == 0
    ):
        return None
    row = connection.execute(
        """
        SELECT
            run_id, execution_scope_authority_id, ledger_sequence,
            pending_sample_commitment_authority_id, command_id,
            execution_dataset_snapshot_id, execution_entry_id, sample_id,
            observation_authority_id, sample_execution_record_id,
            sample_execution_record_json,
            sample_execution_record_document_sha256,
            sample_execution_record_size_bytes,
            commitment_json, document_sha256, size_bytes
        FROM m6_upgrade_pending_sample_commitments
        WHERE run_id = ?
          AND execution_scope_authority_id = ?
          AND ledger_sequence = ?
        """,
        (run_id, scope_id, sequence),
    ).fetchone()
    if row is None:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
    try:
        commitment_json = _row_str(row, "commitment_json")
        document_sha256 = _row_str(row, "document_sha256")
        size_bytes = _row_int(row, "size_bytes")
        record_json = _row_str(row, "sample_execution_record_json")
        record_sha256 = _row_str(row, "sample_execution_record_document_sha256")
        record_size = _row_int(row, "sample_execution_record_size_bytes")
        record = _parse_canonical_document(
            raw=record_json,
            document_sha256=record_sha256,
            claimed_size_bytes=record_size,
            max_bytes=MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
            model_type=M6UpgradeSampleExecutionRecordV2,
        )
        authority = _parse_canonical_document(
            raw=commitment_json,
            document_sha256=document_sha256,
            claimed_size_bytes=size_bytes,
            max_bytes=MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES,
            model_type=M6UpgradePendingSampleCommitmentAuthority,
        )
        nested_record_json, nested_record_sha256 = _document(authority.sample_execution_record)
        if (
            authority.sample_execution_record != record
            or nested_record_json != record_json
            or nested_record_sha256 != record_sha256
            or len(nested_record_json.encode("utf-8")) != record_size
            or authority.sample_execution_record_document_sha256 != record_sha256
            or authority.sample_execution_record_size_bytes != record_size
        ):
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)

        observed = (
            _row_str(row, "run_id"),
            _row_str(row, "execution_scope_authority_id"),
            _row_int(row, "ledger_sequence"),
            _row_str(row, "pending_sample_commitment_authority_id"),
            _row_str(row, "command_id"),
            _row_str(row, "execution_dataset_snapshot_id"),
            _row_str(row, "execution_entry_id"),
            _row_str(row, "sample_id"),
            _row_str(row, "observation_authority_id"),
            _row_str(row, "sample_execution_record_id"),
        )
        expected = (
            authority.candidate_run_id,
            authority.execution_scope_authority_id,
            authority.ledger_sequence,
            authority.pending_sample_commitment_authority_id,
            authority.command_id,
            authority.execution_dataset_snapshot_id,
            authority.execution_entry_id,
            authority.sample_id,
            authority.observation_authority_id,
            authority.sample_execution_record_id,
        )
        if observed != expected:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        documents = M6UpgradePendingSampleCommitmentDocuments(
            commitment_json=commitment_json,
            document_sha256=document_sha256,
            size_bytes=size_bytes,
            sample_execution_record_json=record_json,
            sample_execution_record_document_sha256=record_sha256,
            sample_execution_record_size_bytes=record_size,
        )
        return StoredM6UpgradePendingSampleCommitment(
            authority=authority,
            documents=documents,
        )
    except M6UpgradePendingSampleCommitmentError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID) from exc


__all__ = [
    "MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES",
    "MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES",
    "MAX_M6_UPGRADE_PENDING_RECORD_BYTES",
    "MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES",
    "M6UpgradePendingSampleCommitmentDocuments",
    "StoredM6UpgradePendingSampleCommitment",
    "canonical_pending_sample_commitment",
    "pending_sample_commitment_documents",
    "pending_sample_commitment_from_connection",
]
