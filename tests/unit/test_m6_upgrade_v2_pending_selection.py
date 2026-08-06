from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, fields

import pytest

from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LivePendingSelector,
    _CapabilityMode,
    _new_pending_selector,
    _revoke_capability,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_v2_pending_selection import (
    M6UpgradeV2PendingSelection,
    M6UpgradeV2PendingSelectionError,
    M6UpgradeV2PendingSelectionFailureCode,
    select_m6_upgrade_v2_pending,
    select_m6_upgrade_v3_pending,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
)

RUN_ID = "candidate-run"
SCOPE_ID = "a" * 64
OTHER_SCOPE_ID = "f" * 64
OBSERVATION_ZERO = "b" * 64
OBSERVATION_ONE = "c" * 64
COMMITMENT_ZERO = "d" * 64
COMMITMENT_ONE = "e" * 64
RECORD_ZERO = "1" * 64
RECORD_ONE = "2" * 64

_SCHEMA = """
CREATE TABLE m6_upgrade_execution_scopes (
    run_id TEXT,
    execution_scope_authority_id TEXT,
    expected_sample_count INTEGER
);
CREATE TABLE m6_upgrade_execution_ledger_protocols (
    run_id TEXT,
    execution_scope_authority_id TEXT,
    protocol_version TEXT
);
CREATE TABLE m6_upgrade_sample_executions (
    run_id TEXT,
    execution_scope_authority_id TEXT,
    ledger_sequence INTEGER,
    previous_ledger_entry_hash TEXT,
    sample_execution_record_id TEXT,
    record_schema_version TEXT,
    observation_authority_id TEXT
);
CREATE TABLE m6_upgrade_sample_execution_observations (
    run_id TEXT,
    execution_scope_authority_id TEXT,
    ledger_sequence INTEGER,
    observation_authority_id TEXT,
    observation_schema_version TEXT
);
CREATE TABLE m6_upgrade_pending_sample_commitments (
    run_id TEXT,
    execution_scope_authority_id TEXT,
    ledger_sequence INTEGER,
    pending_sample_commitment_authority_id TEXT,
    observation_authority_id TEXT,
    sample_execution_record_id TEXT
);
CREATE TABLE m6_upgrade_execution_ledger_seals (
    run_id TEXT,
    execution_scope_authority_id TEXT,
    seal_schema_version TEXT
);
"""


@pytest.fixture
def connection() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.executescript(_SCHEMA)
    connection.execute(
        "INSERT INTO m6_upgrade_execution_scopes VALUES (?, ?, ?)",
        (RUN_ID, SCOPE_ID, 2),
    )
    connection.execute(
        "INSERT INTO m6_upgrade_execution_ledger_protocols VALUES (?, ?, 'v2')",
        (RUN_ID, SCOPE_ID),
    )
    try:
        yield connection
    finally:
        connection.close()


@contextmanager
def _selector(connection: sqlite3.Connection) -> Iterator[M6LivePendingSelector]:
    connection.execute("BEGIN IMMEDIATE")
    selector = _new_pending_selector(connection)
    try:
        yield selector
    finally:
        assert _revoke_capability(selector, _CapabilityMode.SELECTOR) is None
        connection.rollback()


def _insert_observation(
    connection: sqlite3.Connection,
    sequence: int,
    observation_id: str,
    *,
    scope_id: str = SCOPE_ID,
    schema_version: str = "v1",
) -> None:
    connection.execute(
        "INSERT INTO m6_upgrade_sample_execution_observations VALUES (?, ?, ?, ?, ?)",
        (RUN_ID, scope_id, sequence, observation_id, schema_version),
    )


def _insert_commitment(
    connection: sqlite3.Connection,
    sequence: int,
    observation_id: str,
    commitment_id: str,
    record_id: str,
    *,
    scope_id: str = SCOPE_ID,
) -> None:
    connection.execute(
        "INSERT INTO m6_upgrade_pending_sample_commitments VALUES (?, ?, ?, ?, ?, ?)",
        (RUN_ID, scope_id, sequence, commitment_id, observation_id, record_id),
    )


def _insert_sample(
    connection: sqlite3.Connection,
    sequence: int,
    observation_id: str,
    record_id: str,
    previous_hash: str,
    *,
    scope_id: str = SCOPE_ID,
) -> None:
    connection.execute(
        "INSERT INTO m6_upgrade_sample_executions VALUES (?, ?, ?, ?, ?, 'v2', ?)",
        (RUN_ID, scope_id, sequence, previous_hash, record_id, observation_id),
    )


def _reason(
    selector: M6LivePendingSelector,
    *,
    scope_id: str = SCOPE_ID,
) -> M6UpgradeV2PendingSelectionFailureCode:
    with pytest.raises(M6UpgradeV2PendingSelectionError) as raised:
        select_m6_upgrade_v2_pending(selector, RUN_ID, scope_id)
    return raised.value.reason_code


def test_error_reason_code_is_closed() -> None:
    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeV2PendingSelectionError("SCOPE_NOT_FOUND")  # type: ignore[arg-type]


def test_selects_pending_observation_from_only_normalized_small_fields(
    connection: sqlite3.Connection,
) -> None:
    _insert_observation(connection, 0, OBSERVATION_ZERO)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)

    with _selector(connection) as selector:
        selection = select_m6_upgrade_v2_pending(selector, RUN_ID, SCOPE_ID)

    assert selection == M6UpgradeV2PendingSelection(
        sequence=0,
        observation_authority_id=OBSERVATION_ZERO,
        pending_sample_commitment_authority_id=None,
        previous_ledger_entry_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
    )
    assert [field.name for field in fields(selection)] == [
        "sequence",
        "observation_authority_id",
        "pending_sample_commitment_authority_id",
        "previous_ledger_entry_hash",
    ]
    assert not hasattr(selection, "__dict__")
    assert not hasattr(selection, "connection")
    assert not hasattr(selection, "selector")
    assert all("json" not in statement.lower() for statement in statements)
    with pytest.raises(FrozenInstanceError):
        selection.sequence = 1  # type: ignore[misc]


def test_v2_and_v3_selectors_are_exact_in_both_directions(
    connection: sqlite3.Connection,
) -> None:
    _insert_observation(connection, 0, OBSERVATION_ZERO)

    with (
        _selector(connection) as selector,
        pytest.raises(M6UpgradeV2PendingSelectionError) as old_protocol,
    ):
        select_m6_upgrade_v3_pending(selector, RUN_ID, SCOPE_ID)
    assert old_protocol.value.reason_code == (
        M6UpgradeV2PendingSelectionFailureCode.LEGACY_LEDGER_UNSUPPORTED
    )

    connection.execute("UPDATE m6_upgrade_execution_ledger_protocols SET protocol_version = 'v3'")
    with (
        _selector(connection) as selector,
        pytest.raises(M6UpgradeV2PendingSelectionError) as new_protocol,
    ):
        select_m6_upgrade_v2_pending(selector, RUN_ID, SCOPE_ID)
    assert new_protocol.value.reason_code == (
        M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID
    )

    with (
        _selector(connection) as selector,
        pytest.raises(M6UpgradeV2PendingSelectionError) as old_observation,
    ):
        select_m6_upgrade_v3_pending(selector, RUN_ID, SCOPE_ID)
    assert old_observation.value.reason_code == (
        M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID
    )

    connection.execute(
        """
        UPDATE m6_upgrade_sample_execution_observations
        SET observation_schema_version = 'v2'
        """
    )
    with _selector(connection) as selector:
        selection = select_m6_upgrade_v3_pending(selector, RUN_ID, SCOPE_ID)
    assert selection.sequence == 0
    assert selection.observation_authority_id == OBSERVATION_ZERO


def test_v2_selector_rejects_v2_observation_marker(
    connection: sqlite3.Connection,
) -> None:
    _insert_observation(
        connection,
        0,
        OBSERVATION_ZERO,
        schema_version="v2",
    )

    with _selector(connection) as selector:
        assert _reason(selector) == (
            M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID
        )


def test_selects_optional_commitment_and_exact_previous_head(
    connection: sqlite3.Connection,
) -> None:
    _insert_observation(connection, 0, OBSERVATION_ZERO)
    _insert_commitment(
        connection,
        0,
        OBSERVATION_ZERO,
        COMMITMENT_ZERO,
        RECORD_ZERO,
    )
    _insert_sample(
        connection,
        0,
        OBSERVATION_ZERO,
        RECORD_ZERO,
        M6_UPGRADE_LEDGER_GENESIS_HASH,
    )
    _insert_observation(connection, 1, OBSERVATION_ONE)
    _insert_commitment(
        connection,
        1,
        OBSERVATION_ONE,
        COMMITMENT_ONE,
        RECORD_ONE,
    )

    with _selector(connection) as selector:
        selection = select_m6_upgrade_v2_pending(selector, RUN_ID, SCOPE_ID)

    assert selection == M6UpgradeV2PendingSelection(
        sequence=1,
        observation_authority_id=OBSERVATION_ONE,
        pending_sample_commitment_authority_id=COMMITMENT_ONE,
        previous_ledger_entry_hash=RECORD_ZERO,
    )


def test_rejects_nul_suffixed_hashes_in_a_historical_committed_prefix(
    connection: sqlite3.Connection,
) -> None:
    connection.execute("UPDATE m6_upgrade_execution_scopes SET expected_sample_count = 3")
    nul_observation = f"{OBSERVATION_ZERO}\x00forged"
    nul_commitment = f"{COMMITMENT_ZERO}\x00forged"
    nul_record = f"{RECORD_ZERO}\x00forged"
    legacy_text_shape_check = connection.execute(
        """
        SELECT length(?) = 64 AND ? NOT GLOB '*[^0-9a-f]*' AS accepted
        """,
        (nul_record, nul_record),
    ).fetchone()
    assert legacy_text_shape_check is not None
    assert legacy_text_shape_check["accepted"] == 1

    _insert_observation(connection, 0, nul_observation)
    _insert_commitment(
        connection,
        0,
        nul_observation,
        nul_commitment,
        nul_record,
    )
    _insert_sample(
        connection,
        0,
        nul_observation,
        nul_record,
        M6_UPGRADE_LEDGER_GENESIS_HASH,
    )
    _insert_observation(connection, 1, OBSERVATION_ONE)
    _insert_commitment(
        connection,
        1,
        OBSERVATION_ONE,
        COMMITMENT_ONE,
        RECORD_ONE,
    )
    _insert_sample(
        connection,
        1,
        OBSERVATION_ONE,
        RECORD_ONE,
        nul_record,
    )
    _insert_observation(connection, 2, "3" * 64)

    with _selector(connection) as selector:
        assert _reason(selector) == (
            M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID
        )


def test_rejects_nul_suffixed_record_id_in_the_pending_commitment(
    connection: sqlite3.Connection,
) -> None:
    _insert_observation(connection, 0, OBSERVATION_ZERO)
    _insert_commitment(
        connection,
        0,
        OBSERVATION_ZERO,
        COMMITMENT_ZERO,
        f"{RECORD_ZERO}\x00forged",
    )

    with _selector(connection) as selector:
        assert _reason(selector) == (
            M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID
        )


def test_distinguishes_scope_missing_scope_mismatch_and_v1(
    connection: sqlite3.Connection,
) -> None:
    with _selector(connection) as selector:
        assert _reason(selector, scope_id=OTHER_SCOPE_ID) == (
            M6UpgradeV2PendingSelectionFailureCode.SCOPE_MISMATCH
        )

    connection.execute("UPDATE m6_upgrade_execution_ledger_protocols SET protocol_version = 'v1'")
    with _selector(connection) as selector:
        assert _reason(selector) == (
            M6UpgradeV2PendingSelectionFailureCode.LEGACY_LEDGER_UNSUPPORTED
        )

    connection.execute("DELETE FROM m6_upgrade_execution_ledger_protocols")
    connection.execute("DELETE FROM m6_upgrade_execution_scopes")
    with _selector(connection) as selector:
        assert _reason(selector) == M6UpgradeV2PendingSelectionFailureCode.SCOPE_NOT_FOUND


@pytest.mark.parametrize("complete", [False, True])
def test_no_pending_is_not_reported_as_corruption(
    connection: sqlite3.Connection,
    *,
    complete: bool,
) -> None:
    if complete:
        for sequence, observation_id, commitment_id, record_id, previous_hash in (
            (
                0,
                OBSERVATION_ZERO,
                COMMITMENT_ZERO,
                RECORD_ZERO,
                M6_UPGRADE_LEDGER_GENESIS_HASH,
            ),
            (1, OBSERVATION_ONE, COMMITMENT_ONE, RECORD_ONE, RECORD_ZERO),
        ):
            _insert_observation(connection, sequence, observation_id)
            _insert_commitment(
                connection,
                sequence,
                observation_id,
                commitment_id,
                record_id,
            )
            _insert_sample(
                connection,
                sequence,
                observation_id,
                record_id,
                previous_hash,
            )

    with _selector(connection) as selector:
        assert _reason(selector) == M6UpgradeV2PendingSelectionFailureCode.NO_PENDING_SAMPLE


@pytest.mark.parametrize(
    "damage",
    [
        "missing_protocol",
        "non_contiguous_observation",
        "orphan_commitment",
        "committed_identity_mismatch",
        "broken_previous_head",
        "seal_with_pending",
    ],
)
def test_normalized_damage_fails_closed(
    connection: sqlite3.Connection,
    damage: str,
) -> None:
    if damage == "missing_protocol":
        connection.execute("DELETE FROM m6_upgrade_execution_ledger_protocols")
    elif damage == "non_contiguous_observation":
        _insert_observation(connection, 1, OBSERVATION_ONE)
    elif damage == "orphan_commitment":
        _insert_commitment(
            connection,
            0,
            OBSERVATION_ZERO,
            COMMITMENT_ZERO,
            RECORD_ZERO,
        )
    elif damage == "committed_identity_mismatch":
        _insert_observation(connection, 0, OBSERVATION_ZERO)
        _insert_commitment(
            connection,
            0,
            OBSERVATION_ONE,
            COMMITMENT_ZERO,
            RECORD_ZERO,
        )
        _insert_sample(
            connection,
            0,
            OBSERVATION_ZERO,
            RECORD_ZERO,
            M6_UPGRADE_LEDGER_GENESIS_HASH,
        )
    elif damage == "broken_previous_head":
        _insert_observation(connection, 0, OBSERVATION_ZERO)
        _insert_commitment(
            connection,
            0,
            OBSERVATION_ZERO,
            COMMITMENT_ZERO,
            RECORD_ZERO,
        )
        _insert_sample(connection, 0, OBSERVATION_ZERO, RECORD_ZERO, OTHER_SCOPE_ID)
    else:
        _insert_observation(connection, 0, OBSERVATION_ZERO)
        connection.execute(
            "INSERT INTO m6_upgrade_execution_ledger_seals VALUES (?, ?, 'v2')",
            (RUN_ID, SCOPE_ID),
        )

    with _selector(connection) as selector:
        assert _reason(selector) == (
            M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID
        )


def test_rejects_non_capability_and_revoked_capability(
    connection: sqlite3.Connection,
) -> None:
    with pytest.raises(M6UpgradeV2PendingSelectionError) as invalid:
        select_m6_upgrade_v2_pending(object(), RUN_ID, SCOPE_ID)
    assert invalid.value.reason_code == M6UpgradeV2PendingSelectionFailureCode.INVALID_ARGUMENT

    connection.execute("BEGIN IMMEDIATE")
    selector = _new_pending_selector(connection)
    assert _revoke_capability(selector, _CapabilityMode.SELECTOR) is None
    with pytest.raises(M6UpgradeV2PendingSelectionError) as revoked:
        select_m6_upgrade_v2_pending(selector, RUN_ID, SCOPE_ID)
    connection.rollback()
    assert revoked.value.reason_code == (M6UpgradeV2PendingSelectionFailureCode.CAPABILITY_REJECTED)
