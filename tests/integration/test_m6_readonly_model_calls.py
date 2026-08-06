from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from labcourt.adapters.storage.readonly_m6_model_calls import (
    ReadonlyM6ModelCallAuthorityRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.application.m6_model_call_authority import (
    M6ModelCallAuthorityError,
    M6ModelCallAuthorityErrorCode,
    assemble_m6_locked_screening_model_calls,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.m6_replay_locked import M6LockedModelCallResultKind
from tests.integration.test_m3_sqlite_repository import (
    RUN_ID,
    _all_m3_artifacts_for_validation,
    _failed_model_call_for_validation,
    _repair_artifacts_for_validation,
)


def _source_case(database: Path) -> Case:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT case_json FROM case_versions
            WHERE run_id = ? ORDER BY revision DESC LIMIT 1
            """,
            (RUN_ID,),
        ).fetchone()
    assert row is not None
    return Case.model_validate_json(str(row[0]))


def _source_fingerprint(root: Path) -> dict[str, tuple[int, str]]:
    return {
        path.name: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.iterdir()
        if path.is_file()
    }


def test_readonly_repository_assembles_real_response_chain_without_writes(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    source_case = _source_case(database)
    before = _source_fingerprint(tmp_path)

    with readonly_sqlite_snapshot(database) as snapshot:
        private_before = {path.name for path in snapshot.parent.iterdir()}
        repository = ReadonlyM6ModelCallAuthorityRepository(snapshot)
        authority = repository.load_validated_snapshot(source_case)
        calls = repository.assemble(source_case)
        resolved = repository.resolve(source_case)
        private_after = {path.name for path in snapshot.parent.iterdir()}

    assert len(calls) == 1
    assert calls[0].result_kind == M6LockedModelCallResultKind.RESPONSE
    assert calls[0].parsed_output_ref is not None
    assert len(authority.usages) == 1
    assert authority.usages[0].request_id == authority.requests[0].request.request_id
    assert authority.usages[0].response_id == authority.responses[0].response.response_id
    assert authority.usages[0].case_id == source_case.case_id
    assert len(resolved) == 1
    assert private_after == private_before
    assert _source_fingerprint(tmp_path) == before


def test_readonly_repository_assembles_real_two_attempt_repair_history(
    tmp_path: Path,
) -> None:
    database, _first_receipt_id = _repair_artifacts_for_validation(tmp_path)
    source_case = _source_case(database)

    with readonly_sqlite_snapshot(database) as snapshot:
        repository = ReadonlyM6ModelCallAuthorityRepository(snapshot)
        authority = repository.load_validated_snapshot(source_case)
        calls = repository.assemble(source_case)

    assert len(calls) == 2
    assert len(authority.usages) == 2
    assert {usage.request_id for usage in authority.usages} == {
        document.request.request_id for document in authority.requests
    }
    assert {usage.response_id for usage in authority.usages} == {
        document.response.response_id for document in authority.responses
    }
    assert {call.attempt_index for call in calls} == {0, 1}
    by_attempt = {call.attempt_index: call for call in calls}
    assert by_attempt[0].parsed_output_ref is None
    assert by_attempt[1].parsed_output_ref is not None


def test_application_rejects_unstable_real_two_attempt_snapshot(tmp_path: Path) -> None:
    database, _first_receipt_id = _repair_artifacts_for_validation(tmp_path)
    source_case = _source_case(database)

    with readonly_sqlite_snapshot(database) as snapshot_path:
        snapshot = ReadonlyM6ModelCallAuthorityRepository(snapshot_path).load_validated_snapshot(
            source_case
        )

    with pytest.raises(M6ModelCallAuthorityError) as raised:
        assemble_m6_locked_screening_model_calls(
            source_case=source_case,
            snapshot=replace(snapshot, requests=tuple(reversed(snapshot.requests))),
        )

    assert raised.value.code == M6ModelCallAuthorityErrorCode.MODEL_REQUEST_UNSTABLE


def test_readonly_repository_assembles_real_failure_authority(
    tmp_path: Path,
) -> None:
    database, _request_id = _failed_model_call_for_validation(tmp_path)
    source_case = _source_case(database)

    with readonly_sqlite_snapshot(database) as snapshot:
        repository = ReadonlyM6ModelCallAuthorityRepository(snapshot)
        authority = repository.load_validated_snapshot(source_case)
        calls = repository.assemble(source_case)

    assert len(calls) == 1
    assert calls[0].result_kind == M6LockedModelCallResultKind.FAILURE
    assert calls[0].failure_ref is not None
    assert authority.usages == ()


def test_readonly_repository_hard_fails_when_m3_snapshot_has_any_failure(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    source_case = _source_case(database)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER model_responses_no_update")
        connection.execute("UPDATE model_responses SET response_json = ' ' || response_json")

    with readonly_sqlite_snapshot(database) as snapshot:
        repository = ReadonlyM6ModelCallAuthorityRepository(snapshot)
        with pytest.raises(M6ModelCallAuthorityError) as raised:
            repository.assemble(source_case)

    assert raised.value.code == M6ModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID
