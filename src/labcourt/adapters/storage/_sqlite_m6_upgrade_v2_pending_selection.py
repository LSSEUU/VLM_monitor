"""Small-field pending selection for the A side of an M6 live read cut.

The selector runs while connection A owns the writer slot.  It deliberately
does not read an authority JSON document: connection B validates those bytes
after the unique durable pending state has been selected.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, TypeGuard

from labcourt.contracts.m6_regression import MAX_M6_REGRESSION_CASES
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ContractViolation

from ._sqlite_m6_live_read_cut import (
    M6LivePendingSelector,
    M6LiveReadCutError,
)
from .sqlite_repository import (
    RepositoryIntegrityError,
    _row_int,
    _row_optional_int,
    _row_optional_str,
    _row_str,
)


class M6UpgradeV2PendingSelectionFailureCode(StrEnum):
    """Payload-free reasons emitted by the internal A-side selector."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    LEGACY_LEDGER_UNSUPPORTED = "LEGACY_LEDGER_UNSUPPORTED"
    NO_PENDING_SAMPLE = "NO_PENDING_SAMPLE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    CAPABILITY_REJECTED = "CAPABILITY_REJECTED"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradeV2PendingSelectionError(ContractViolation):
    """Typed failure that exposes neither SQLite text nor authority payloads."""

    def __init__(self, reason_code: M6UpgradeV2PendingSelectionFailureCode) -> None:
        if not isinstance(reason_code, M6UpgradeV2PendingSelectionFailureCode):
            raise TypeError("reason_code must be an M6UpgradeV2PendingSelectionFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 V2 pending selection failed: {reason_code.value}")


def _error(
    code: M6UpgradeV2PendingSelectionFailureCode,
) -> M6UpgradeV2PendingSelectionError:
    return M6UpgradeV2PendingSelectionError(code)


def _is_lower_sha256(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == 64
        and not any(character not in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True)
class M6UpgradeV2PendingSelection:
    """The only four scalars allowed to leave A's pending-selection phase."""

    sequence: int
    observation_authority_id: str
    pending_sample_commitment_authority_id: str | None
    previous_ledger_entry_hash: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or not 0 <= self.sequence < MAX_M6_REGRESSION_CASES
        ):
            raise ValueError("sequence must be a bounded non-negative integer")
        if not _is_lower_sha256(self.observation_authority_id):
            raise ValueError("observation_authority_id must be a lowercase SHA-256")
        if self.pending_sample_commitment_authority_id is not None and not _is_lower_sha256(
            self.pending_sample_commitment_authority_id
        ):
            raise ValueError("pending_sample_commitment_authority_id must be a lowercase SHA-256")
        if not _is_lower_sha256(self.previous_ledger_entry_hash):
            raise ValueError("previous_ledger_entry_hash must be a lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class _SequenceInventory:
    count: int
    first_sequence: int | None
    last_sequence: int | None


def _require_inputs(
    selector: object,
    candidate_run_id: object,
    execution_scope_authority_id: object,
) -> tuple[M6LivePendingSelector, str, str]:
    if type(selector) is not M6LivePendingSelector:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.INVALID_ARGUMENT)
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(candidate_run_id, "M6 V2 pending run_id")
    except (TypeError, ValueError) as exc:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.INVALID_ARGUMENT) from exc
    if not _is_lower_sha256(execution_scope_authority_id):
        raise _error(M6UpgradeV2PendingSelectionFailureCode.INVALID_ARGUMENT)
    return selector, run_id, execution_scope_authority_id


def _rows(
    selector: M6LivePendingSelector,
    statement: str,
    parameters: tuple[object, ...],
) -> list[sqlite3.Row]:
    cursor = selector.execute(statement, parameters)
    rows = cursor.fetchall()
    cursor.close()
    return rows


def _row(
    selector: M6LivePendingSelector,
    statement: str,
    parameters: tuple[object, ...],
) -> sqlite3.Row:
    rows = _rows(selector, statement, parameters)
    if len(rows) != 1:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    return rows[0]


def _scope_expected_count(
    selector: M6LivePendingSelector,
    run_id: str,
    requested_scope_id: str,
    *,
    expected_protocol_version: Literal["v2", "v3"],
) -> int:
    rows = _rows(
        selector,
        """
        SELECT
            scope.execution_scope_authority_id AS scope_id,
            scope.expected_sample_count AS expected_sample_count,
            protocol.execution_scope_authority_id AS protocol_scope_id,
            protocol.protocol_version AS protocol_version
        FROM m6_upgrade_execution_scopes AS scope
        LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
          ON protocol.run_id = scope.run_id
        WHERE scope.run_id = ?
        LIMIT 2
        """,
        (run_id,),
    )
    if not rows:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.SCOPE_NOT_FOUND)
    if len(rows) != 1:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)

    row = rows[0]
    scope_id = _row_str(row, "scope_id")
    if not _is_lower_sha256(scope_id):
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    if scope_id != requested_scope_id:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.SCOPE_MISMATCH)

    protocol_scope_id = _row_optional_str(row, "protocol_scope_id")
    protocol_version = _row_optional_str(row, "protocol_version")
    if protocol_scope_id != scope_id or protocol_version is None:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    if protocol_version == "v1" or (expected_protocol_version == "v3" and protocol_version == "v2"):
        raise _error(M6UpgradeV2PendingSelectionFailureCode.LEGACY_LEDGER_UNSUPPORTED)
    if protocol_version != expected_protocol_version:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)

    expected_count = _row_int(row, "expected_sample_count")
    if not 1 <= expected_count <= MAX_M6_REGRESSION_CASES:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    return expected_count


def _sequence_inventory(
    selector: M6LivePendingSelector,
    statement: str,
    parameters: tuple[object, ...],
    *,
    maximum_count: int,
) -> _SequenceInventory:
    row = _row(selector, statement, parameters)
    count = _row_int(row, "item_count")
    first_sequence = _row_optional_int(row, "first_sequence")
    last_sequence = _row_optional_int(row, "last_sequence")
    invalid_count = _row_int(row, "invalid_count")
    if count < 0 or count > maximum_count or invalid_count != 0:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    if count == 0:
        if first_sequence is not None or last_sequence is not None:
            raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    elif first_sequence != 0 or last_sequence != count - 1:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    return _SequenceInventory(
        count=count,
        first_sequence=first_sequence,
        last_sequence=last_sequence,
    )


def _sample_inventory(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
    expected_count: int,
) -> _SequenceInventory:
    return _sequence_inventory(
        selector,
        """
        SELECT
            COUNT(*) AS item_count,
            MIN(ledger_sequence) AS first_sequence,
            MAX(ledger_sequence) AS last_sequence,
            COALESCE(SUM(invalid_row), 0) AS invalid_count
        FROM (
            SELECT
                ledger_sequence,
                CASE WHEN execution_scope_authority_id = ?
                           AND record_schema_version = 'v2'
                           AND length(CAST(observation_authority_id AS BLOB)) = 64
                           AND observation_authority_id NOT GLOB '*[^0-9a-f]*'
                           AND length(CAST(sample_execution_record_id AS BLOB)) = 64
                           AND sample_execution_record_id NOT GLOB '*[^0-9a-f]*'
                           AND length(CAST(previous_ledger_entry_hash AS BLOB)) = 64
                           AND previous_ledger_entry_hash NOT GLOB '*[^0-9a-f]*'
                     THEN 0 ELSE 1 END AS invalid_row
            FROM m6_upgrade_sample_executions
            WHERE run_id = ?
            ORDER BY ledger_sequence
            LIMIT ?
        )
        """,
        (scope_id, run_id, expected_count + 1),
        maximum_count=expected_count,
    )


def _observation_inventory(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
    expected_count: int,
    *,
    expected_observation_schema_version: Literal["v1", "v2"],
) -> _SequenceInventory:
    return _sequence_inventory(
        selector,
        """
        SELECT
            COUNT(*) AS item_count,
            MIN(ledger_sequence) AS first_sequence,
            MAX(ledger_sequence) AS last_sequence,
            COALESCE(SUM(invalid_row), 0) AS invalid_count
        FROM (
            SELECT
                ledger_sequence,
                CASE WHEN execution_scope_authority_id = ?
                           AND observation_schema_version = ?
                           AND length(CAST(observation_authority_id AS BLOB)) = 64
                           AND observation_authority_id NOT GLOB '*[^0-9a-f]*'
                     THEN 0 ELSE 1 END AS invalid_row
            FROM m6_upgrade_sample_execution_observations
            WHERE run_id = ?
            ORDER BY ledger_sequence
            LIMIT ?
        )
        """,
        (
            scope_id,
            expected_observation_schema_version,
            run_id,
            expected_count + 1,
        ),
        maximum_count=expected_count,
    )


def _commitment_inventory(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
    expected_count: int,
) -> _SequenceInventory:
    return _sequence_inventory(
        selector,
        """
        SELECT
            COUNT(*) AS item_count,
            MIN(ledger_sequence) AS first_sequence,
            MAX(ledger_sequence) AS last_sequence,
            COALESCE(SUM(invalid_row), 0) AS invalid_count
        FROM (
            SELECT
                ledger_sequence,
                CASE WHEN execution_scope_authority_id = ?
                           AND length(
                               CAST(pending_sample_commitment_authority_id AS BLOB)
                           ) = 64
                           AND pending_sample_commitment_authority_id
                               NOT GLOB '*[^0-9a-f]*'
                           AND length(CAST(observation_authority_id AS BLOB)) = 64
                           AND observation_authority_id NOT GLOB '*[^0-9a-f]*'
                           AND length(CAST(sample_execution_record_id AS BLOB)) = 64
                           AND sample_execution_record_id NOT GLOB '*[^0-9a-f]*'
                     THEN 0 ELSE 1 END AS invalid_row
            FROM m6_upgrade_pending_sample_commitments
            WHERE run_id = ?
            ORDER BY ledger_sequence
            LIMIT ?
        )
        """,
        (scope_id, run_id, expected_count + 1),
        maximum_count=expected_count,
    )


def _seal_count(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
) -> int:
    row = _row(
        selector,
        """
        SELECT
            COUNT(*) AS item_count,
            COALESCE(SUM(invalid_row), 0) AS invalid_count
        FROM (
            SELECT
                CASE WHEN execution_scope_authority_id = ?
                           AND seal_schema_version = 'v2'
                     THEN 0 ELSE 1 END AS invalid_row
            FROM m6_upgrade_execution_ledger_seals
            WHERE run_id = ?
            LIMIT 2
        )
        """,
        (scope_id, run_id),
    )
    count = _row_int(row, "item_count")
    invalid_count = _row_int(row, "invalid_count")
    if count not in {0, 1} or invalid_count != 0:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    return count


def _validate_committed_prefix(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
) -> None:
    row = _row(
        selector,
        """
        SELECT EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_executions AS sample
            LEFT JOIN m6_upgrade_sample_execution_observations AS observation
              ON observation.run_id = sample.run_id
             AND observation.ledger_sequence = sample.ledger_sequence
            LEFT JOIN m6_upgrade_pending_sample_commitments AS commitment
              ON commitment.run_id = sample.run_id
             AND commitment.ledger_sequence = sample.ledger_sequence
            LEFT JOIN m6_upgrade_sample_executions AS predecessor
              ON predecessor.run_id = sample.run_id
             AND predecessor.ledger_sequence = sample.ledger_sequence - 1
            WHERE sample.run_id = ?
              AND (
                  sample.execution_scope_authority_id IS NOT ?
                  OR observation.execution_scope_authority_id IS NOT ?
                  OR commitment.execution_scope_authority_id IS NOT ?
                  OR sample.observation_authority_id
                     IS NOT observation.observation_authority_id
                  OR sample.observation_authority_id
                     IS NOT commitment.observation_authority_id
                  OR sample.sample_execution_record_id
                     IS NOT commitment.sample_execution_record_id
                  OR (
                      sample.ledger_sequence = 0
                      AND sample.previous_ledger_entry_hash IS NOT ?
                  )
                  OR (
                      sample.ledger_sequence > 0
                      AND sample.previous_ledger_entry_hash
                          IS NOT predecessor.sample_execution_record_id
                  )
              )
            LIMIT 1
        ) AS invalid_count
        """,
        (
            run_id,
            scope_id,
            scope_id,
            scope_id,
            M6_UPGRADE_LEDGER_GENESIS_HASH,
        ),
    )
    if _row_int(row, "invalid_count") != 0:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)


def _validate_topology(
    *,
    expected_count: int,
    sample_count: int,
    observation_count: int,
    commitment_count: int,
    seal_count: int,
) -> None:
    if seal_count == 1:
        if not (sample_count == observation_count == commitment_count == expected_count):
            raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
        return
    if not (
        sample_count <= expected_count
        and observation_count in {sample_count, sample_count + 1}
        and commitment_count in {sample_count, sample_count + 1}
        and commitment_count <= observation_count
        and (sample_count < expected_count or observation_count == commitment_count == sample_count)
    ):
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)


def _previous_head(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
    sequence: int,
) -> str:
    if sequence == 0:
        return M6_UPGRADE_LEDGER_GENESIS_HASH
    row = _row(
        selector,
        """
        SELECT sample_execution_record_id
        FROM m6_upgrade_sample_executions
        WHERE run_id = ?
          AND execution_scope_authority_id = ?
          AND ledger_sequence = ?
        LIMIT 2
        """,
        (run_id, scope_id, sequence - 1),
    )
    head = _row_str(row, "sample_execution_record_id")
    if not _is_lower_sha256(head):
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    return head


def _pending_observation_id(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
    sequence: int,
) -> str:
    row = _row(
        selector,
        """
        SELECT execution_scope_authority_id, ledger_sequence, observation_authority_id
        FROM m6_upgrade_sample_execution_observations
        WHERE run_id = ? AND ledger_sequence = ?
        LIMIT 2
        """,
        (run_id, sequence),
    )
    if (
        _row_str(row, "execution_scope_authority_id") != scope_id
        or _row_int(row, "ledger_sequence") != sequence
    ):
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    observation_id = _row_str(row, "observation_authority_id")
    if not _is_lower_sha256(observation_id):
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    return observation_id


def _pending_commitment_id(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
    sequence: int,
    observation_id: str,
    *,
    present: bool,
) -> str | None:
    rows = _rows(
        selector,
        """
        SELECT
            execution_scope_authority_id,
            ledger_sequence,
            observation_authority_id,
            pending_sample_commitment_authority_id
        FROM m6_upgrade_pending_sample_commitments
        WHERE run_id = ? AND ledger_sequence = ?
        LIMIT 2
        """,
        (run_id, sequence),
    )
    if not present:
        if rows:
            raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
        return None
    if len(rows) != 1:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    row = rows[0]
    if (
        _row_str(row, "execution_scope_authority_id") != scope_id
        or _row_int(row, "ledger_sequence") != sequence
        or _row_str(row, "observation_authority_id") != observation_id
    ):
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    commitment_id = _row_str(row, "pending_sample_commitment_authority_id")
    if not _is_lower_sha256(commitment_id):
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID)
    return commitment_id


def _select(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
    *,
    expected_protocol_version: Literal["v2", "v3"],
    expected_observation_schema_version: Literal["v1", "v2"],
) -> M6UpgradeV2PendingSelection:
    if not selector.in_transaction:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.CAPABILITY_REJECTED)

    expected_count = _scope_expected_count(
        selector,
        run_id,
        scope_id,
        expected_protocol_version=expected_protocol_version,
    )
    samples = _sample_inventory(selector, run_id, scope_id, expected_count)
    observations = _observation_inventory(
        selector,
        run_id,
        scope_id,
        expected_count,
        expected_observation_schema_version=expected_observation_schema_version,
    )
    commitments = _commitment_inventory(selector, run_id, scope_id, expected_count)
    seal_count = _seal_count(selector, run_id, scope_id)
    _validate_committed_prefix(selector, run_id, scope_id)
    _validate_topology(
        expected_count=expected_count,
        sample_count=samples.count,
        observation_count=observations.count,
        commitment_count=commitments.count,
        seal_count=seal_count,
    )
    if observations.count == samples.count:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.NO_PENDING_SAMPLE)

    sequence = samples.count
    observation_id = _pending_observation_id(selector, run_id, scope_id, sequence)
    commitment_id = _pending_commitment_id(
        selector,
        run_id,
        scope_id,
        sequence,
        observation_id,
        present=commitments.count == samples.count + 1,
    )
    return M6UpgradeV2PendingSelection(
        sequence=sequence,
        observation_authority_id=observation_id,
        pending_sample_commitment_authority_id=commitment_id,
        previous_ledger_entry_hash=_previous_head(
            selector,
            run_id,
            scope_id,
            sequence,
        ),
    )


def select_m6_upgrade_v2_pending(
    selector: object,
    candidate_run_id: object,
    execution_scope_authority_id: object,
) -> M6UpgradeV2PendingSelection:
    """Select one durable pending sample without exposing A or reading JSON."""

    controlled_selector, run_id, scope_id = _require_inputs(
        selector,
        candidate_run_id,
        execution_scope_authority_id,
    )
    try:
        return _select(
            controlled_selector,
            run_id,
            scope_id,
            expected_protocol_version="v2",
            expected_observation_schema_version="v1",
        )
    except M6UpgradeV2PendingSelectionError:
        raise
    except M6LiveReadCutError as exc:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.CAPABILITY_REJECTED) from exc
    except sqlite3.Error as exc:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORAGE_REJECTED) from exc
    except (IndexError, KeyError, TypeError, ValueError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID) from exc


def select_m6_upgrade_v3_pending(
    selector: object,
    candidate_run_id: object,
    execution_scope_authority_id: object,
) -> M6UpgradeV2PendingSelection:
    """Select one exact V3/V2-observation pending sample without reading JSON."""

    controlled_selector, run_id, scope_id = _require_inputs(
        selector,
        candidate_run_id,
        execution_scope_authority_id,
    )
    try:
        return _select(
            controlled_selector,
            run_id,
            scope_id,
            expected_protocol_version="v3",
            expected_observation_schema_version="v2",
        )
    except M6UpgradeV2PendingSelectionError:
        raise
    except M6LiveReadCutError as exc:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.CAPABILITY_REJECTED) from exc
    except sqlite3.Error as exc:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORAGE_REJECTED) from exc
    except (IndexError, KeyError, TypeError, ValueError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID) from exc


__all__ = [
    "M6UpgradeV2PendingSelection",
    "M6UpgradeV2PendingSelectionError",
    "M6UpgradeV2PendingSelectionFailureCode",
    "select_m6_upgrade_v2_pending",
    "select_m6_upgrade_v3_pending",
]
