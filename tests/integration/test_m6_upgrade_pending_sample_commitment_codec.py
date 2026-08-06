from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_pending_sample_commitment_codec as codec
from labcourt.adapters.storage._sqlite_m6_upgrade_pending_sample_commitment_codec import (
    M6UpgradePendingSampleCommitmentDocuments,
    StoredM6UpgradePendingSampleCommitment,
    canonical_pending_sample_commitment,
    pending_sample_commitment_documents,
    pending_sample_commitment_from_connection,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
)
from tests.contract.test_m6_upgrade_pending_sample_commitment_contracts import (
    _commitment,
)


def _sha(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@pytest.fixture
def connection() -> Iterator[sqlite3.Connection]:
    value = sqlite3.connect(":memory:")
    value.row_factory = sqlite3.Row
    value.execute(
        """
        CREATE TABLE m6_upgrade_pending_sample_commitments (
            run_id TEXT,
            execution_scope_authority_id TEXT,
            ledger_sequence INTEGER,
            pending_sample_commitment_authority_id TEXT,
            command_id TEXT,
            execution_dataset_snapshot_id TEXT,
            execution_entry_id TEXT,
            sample_id TEXT,
            observation_authority_id TEXT,
            sample_execution_record_id TEXT,
            sample_execution_record_json TEXT,
            sample_execution_record_document_sha256 TEXT,
            sample_execution_record_size_bytes INTEGER,
            commitment_json TEXT,
            document_sha256 TEXT,
            size_bytes INTEGER,
            PRIMARY KEY (run_id, execution_scope_authority_id, ledger_sequence)
        ) STRICT
        """
    )
    try:
        yield value
    finally:
        value.close()


def _insert(
    connection: sqlite3.Connection,
    commitment: M6UpgradePendingSampleCommitmentAuthority,
) -> M6UpgradePendingSampleCommitmentDocuments:
    documents = pending_sample_commitment_documents(commitment)
    connection.execute(
        """
        INSERT INTO m6_upgrade_pending_sample_commitments(
            run_id, execution_scope_authority_id, ledger_sequence,
            pending_sample_commitment_authority_id, command_id,
            execution_dataset_snapshot_id, execution_entry_id, sample_id,
            observation_authority_id, sample_execution_record_id,
            sample_execution_record_json,
            sample_execution_record_document_sha256,
            sample_execution_record_size_bytes, commitment_json,
            document_sha256, size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            commitment.candidate_run_id,
            commitment.execution_scope_authority_id,
            commitment.ledger_sequence,
            commitment.pending_sample_commitment_authority_id,
            commitment.command_id,
            commitment.execution_dataset_snapshot_id,
            commitment.execution_entry_id,
            commitment.sample_id,
            commitment.observation_authority_id,
            commitment.sample_execution_record_id,
            documents.sample_execution_record_json,
            documents.sample_execution_record_document_sha256,
            documents.sample_execution_record_size_bytes,
            documents.commitment_json,
            documents.document_sha256,
            documents.size_bytes,
        ),
    )
    return documents


def _load(
    connection: sqlite3.Connection,
    commitment: M6UpgradePendingSampleCommitmentAuthority,
    *,
    run_id: str | None = None,
    scope_id: str | None = None,
    sequence: int | None = None,
) -> StoredM6UpgradePendingSampleCommitment | None:
    return pending_sample_commitment_from_connection(
        connection,
        run_id or commitment.candidate_run_id,
        scope_id or commitment.execution_scope_authority_id,
        commitment.ledger_sequence if sequence is None else sequence,
    )


def _assert_stored_invalid(
    connection: sqlite3.Connection,
    commitment: M6UpgradePendingSampleCommitmentAuthority,
    *,
    run_id: str | None = None,
    scope_id: str | None = None,
    sequence: int | None = None,
) -> None:
    with pytest.raises(M6UpgradePendingSampleCommitmentError) as rejected:
        _load(
            connection,
            commitment,
            run_id=run_id,
            scope_id=scope_id,
            sequence=sequence,
        )
    assert (
        rejected.value.reason_code
        == M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
    )


def test_canonical_documents_load_exactly_and_missing_key_returns_none(
    connection: sqlite3.Connection,
) -> None:
    commitment = _commitment()
    controlled = canonical_pending_sample_commitment(commitment)
    documents = pending_sample_commitment_documents(controlled)

    assert controlled == commitment
    assert documents.document_sha256 == _sha(documents.commitment_json)
    assert documents.size_bytes == len(documents.commitment_json.encode("utf-8"))
    assert documents.sample_execution_record_document_sha256 == _sha(
        documents.sample_execution_record_json
    )
    assert documents.sample_execution_record_size_bytes == len(
        documents.sample_execution_record_json.encode("utf-8")
    )
    assert _load(connection, commitment) is None

    assert _insert(connection, commitment) == documents
    stored = _load(connection, commitment)
    assert stored is not None
    assert stored.authority == commitment
    assert stored.documents == documents


def test_canonical_input_rejects_untyped_and_constructed_values() -> None:
    with pytest.raises(M6UpgradePendingSampleCommitmentError) as untyped:
        canonical_pending_sample_commitment(object())
    assert untyped.value.reason_code == M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT

    commitment = _commitment()
    invalid = M6UpgradePendingSampleCommitmentAuthority.model_construct(
        schema_version=commitment.schema_version,
        execution_scope_authority_id="f" * 64,
        candidate_run_id=commitment.candidate_run_id,
        command_id=commitment.command_id,
        execution_dataset_snapshot_id=commitment.execution_dataset_snapshot_id,
        execution_entry=commitment.execution_entry,
        ledger_sequence=commitment.ledger_sequence,
        observation_authority_id=commitment.observation_authority_id,
        sample_execution_record=commitment.sample_execution_record,
        sample_execution_record_document_sha256=(
            commitment.sample_execution_record_document_sha256
        ),
        sample_execution_record_size_bytes=commitment.sample_execution_record_size_bytes,
    )
    with pytest.raises(M6UpgradePendingSampleCommitmentError) as constructed:
        canonical_pending_sample_commitment(invalid)
    assert (
        constructed.value.reason_code
        == M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT
    )


@pytest.mark.parametrize(
    ("column", "raw_column", "sha_column", "size_column"),
    (
        (
            "outer",
            "commitment_json",
            "document_sha256",
            "size_bytes",
        ),
        (
            "record",
            "sample_execution_record_json",
            "sample_execution_record_document_sha256",
            "sample_execution_record_size_bytes",
        ),
    ),
)
def test_outer_and_record_json_pollution_fail_closed(
    connection: sqlite3.Connection,
    column: str,
    raw_column: str,
    sha_column: str,
    size_column: str,
) -> None:
    del column
    commitment = _commitment()
    _insert(connection, commitment)
    raw = "{}"
    connection.execute(
        f"""
        UPDATE m6_upgrade_pending_sample_commitments
        SET {raw_column} = ?, {sha_column} = ?, {size_column} = ?
        """,
        (raw, _sha(raw), len(raw)),
    )
    _assert_stored_invalid(connection, commitment)


@pytest.mark.parametrize(
    ("column", "value"),
    (
        ("document_sha256", "f" * 64),
        ("sample_execution_record_document_sha256", "f" * 64),
    ),
)
def test_outer_and_record_sha_pollution_fail_closed(
    connection: sqlite3.Connection,
    column: str,
    value: str,
) -> None:
    commitment = _commitment()
    documents = _insert(connection, commitment)
    actual = getattr(documents, column)
    replacement = value if value != actual else "e" * 64
    connection.execute(
        f"UPDATE m6_upgrade_pending_sample_commitments SET {column} = ?",
        (replacement,),
    )
    _assert_stored_invalid(connection, commitment)


@pytest.mark.parametrize(
    "column",
    ("size_bytes", "sample_execution_record_size_bytes"),
)
def test_outer_and_record_size_pollution_fails_in_preflight(
    connection: sqlite3.Connection,
    column: str,
) -> None:
    commitment = _commitment()
    _insert(connection, commitment)
    connection.execute(f"UPDATE m6_upgrade_pending_sample_commitments SET {column} = {column} + 1")
    _assert_stored_invalid(connection, commitment)


def test_two_valid_documents_with_different_nested_records_fail_exact_byte_check(
    connection: sqlite3.Connection,
) -> None:
    commitment = _commitment()
    _insert(connection, commitment)
    foreign_documents = pending_sample_commitment_documents(_commitment(1))
    connection.execute(
        """
        UPDATE m6_upgrade_pending_sample_commitments
        SET sample_execution_record_json = ?,
            sample_execution_record_document_sha256 = ?,
            sample_execution_record_size_bytes = ?
        """,
        (
            foreign_documents.sample_execution_record_json,
            foreign_documents.sample_execution_record_document_sha256,
            foreign_documents.sample_execution_record_size_bytes,
        ),
    )
    _assert_stored_invalid(connection, commitment)


_NORMALIZED_COLUMNS = (
    "run_id",
    "execution_scope_authority_id",
    "ledger_sequence",
    "pending_sample_commitment_authority_id",
    "command_id",
    "execution_dataset_snapshot_id",
    "execution_entry_id",
    "sample_id",
    "observation_authority_id",
    "sample_execution_record_id",
)


@pytest.mark.parametrize("column", _NORMALIZED_COLUMNS)
def test_every_normalized_column_is_matched_to_the_canonical_authority(
    connection: sqlite3.Connection,
    column: str,
) -> None:
    commitment = _commitment()
    _insert(connection, commitment)
    run_id: str | None = None
    scope_id: str | None = None
    sequence: int | None = None
    if column == "run_id":
        replacement: object = "tampered-run"
        run_id = str(replacement)
    elif column == "execution_scope_authority_id":
        replacement = "f" * 64
        if replacement == commitment.execution_scope_authority_id:
            replacement = "e" * 64
        scope_id = str(replacement)
    elif column == "ledger_sequence":
        replacement = commitment.ledger_sequence + 1
        sequence = int(replacement)
    elif column == "sample_id":
        replacement = "tampered-sample"
    else:
        replacement = "f" * 64
        expected = {
            "pending_sample_commitment_authority_id": (
                commitment.pending_sample_commitment_authority_id
            ),
            "command_id": commitment.command_id,
            "execution_dataset_snapshot_id": commitment.execution_dataset_snapshot_id,
            "execution_entry_id": commitment.execution_entry_id,
            "observation_authority_id": commitment.observation_authority_id,
            "sample_execution_record_id": commitment.sample_execution_record_id,
        }[column]
        if replacement == expected:
            replacement = "e" * 64
    connection.execute(
        f"UPDATE m6_upgrade_pending_sample_commitments SET {column} = ?",
        (replacement,),
    )
    _assert_stored_invalid(
        connection,
        commitment,
        run_id=run_id,
        scope_id=scope_id,
        sequence=sequence,
    )


def test_null_normalized_column_fails_closed(connection: sqlite3.Connection) -> None:
    commitment = _commitment()
    _insert(connection, commitment)
    connection.execute("UPDATE m6_upgrade_pending_sample_commitments SET command_id = NULL")
    _assert_stored_invalid(connection, commitment)


@pytest.mark.parametrize("target", ("outer", "record"))
def test_oversize_is_rejected_before_any_contract_parse(
    connection: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    commitment = _commitment()
    _insert(connection, commitment)
    limit = 128
    raw = "x" * (limit + 1)
    if target == "outer":
        monkeypatch.setattr(codec, "MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES", limit)
        raw_column = "commitment_json"
        sha_column = "document_sha256"
        size_column = "size_bytes"
    else:
        monkeypatch.setattr(codec, "MAX_M6_UPGRADE_PENDING_RECORD_BYTES", limit)
        raw_column = "sample_execution_record_json"
        sha_column = "sample_execution_record_document_sha256"
        size_column = "sample_execution_record_size_bytes"
    connection.execute(
        f"""
        UPDATE m6_upgrade_pending_sample_commitments
        SET {raw_column} = ?, {sha_column} = ?, {size_column} = ?
        """,
        (raw, _sha(raw), len(raw)),
    )

    def unexpected_parse(**_kwargs: object) -> object:
        raise AssertionError("oversized stored JSON reached contract parsing")

    monkeypatch.setattr(codec, "_parse_canonical_document", unexpected_parse)
    with pytest.raises(M6UpgradePendingSampleCommitmentError) as rejected:
        _load(connection, commitment)
    assert (
        rejected.value.reason_code == M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE
    )


@pytest.mark.parametrize(
    ("run_id", "scope_id", "sequence"),
    (
        ("", "f" * 64, 0),
        ("valid-run", "not-a-sha", 0),
        ("valid-run", "f" * 64, True),
        ("valid-run", "f" * 64, -1),
    ),
)
def test_complete_lookup_key_is_strict(
    connection: sqlite3.Connection,
    run_id: object,
    scope_id: object,
    sequence: object,
) -> None:
    with pytest.raises(M6UpgradePendingSampleCommitmentError) as rejected:
        pending_sample_commitment_from_connection(connection, run_id, scope_id, sequence)
    assert (
        rejected.value.reason_code == M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT
    )
