from __future__ import annotations

import copy
import hashlib
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from labcourt.adapters.storage.readonly_m4_artifacts import ReadonlyM4ArtifactRepository
from labcourt.adapters.storage.readonly_m6_hearing_model_calls import (
    ReadonlyM6HearingModelCallAuthorityRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.application.m6_hearing_model_call_authority import (
    M6HearingModelCallAuthorityError,
    M6HearingModelCallAuthorityErrorCode,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.m3_models import VlmCallBudget
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from tests.integration import test_m4_sqlite_backlog as m4_sqlite_backlog
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m4_readonly_projection import _drop_restore_trigger
from tests.integration.test_m4_replay_authority_snapshot import _one_role_call
from tests.integration.test_m4_sqlite_hearing_retry import _provider_outage_seed


def _source_fingerprint(root: Path) -> dict[str, tuple[int, str]]:
    return {
        path.name: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.iterdir()
        if path.is_file()
    }


def _stored_case_id(database: Path) -> str:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT case_id FROM cases WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
    assert row is not None and isinstance(row[0], str)
    return row[0]


def _stored_current_case(database: Path) -> Case:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT version.case_json
            FROM cases AS current
            JOIN case_versions AS version
              ON version.run_id = current.run_id
             AND version.case_id = current.case_id
             AND version.revision = current.current_revision
            WHERE current.run_id = ?
            """,
            (RUN_ID,),
        ).fetchone()
    assert row is not None and isinstance(row[0], str)
    return Case.model_validate_json(row[0])


def test_repository_assembles_real_response_chain_without_raw_reads_or_writes(
    tmp_path: Path,
) -> None:
    started = _one_role_call(tmp_path)
    source_case = started.repository.load_case(
        RUN_ID,
        started.session.case_id,
    ).case
    source_before = _source_fingerprint(tmp_path)

    with readonly_sqlite_snapshot(started.database) as private_snapshot:
        repository = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot)
        authority = repository.load_authority(source_case)
        calls = repository.assemble(source_case)
        normalized = repository.resolve(source_case)

    assert len(authority.requests) == 1
    assert len(authority.usages) == 1
    assert len(calls) == 1
    assert calls[0].result_kind == M6LockedModelCallResultKind.RESPONSE
    assert calls[0].response_ref is not None
    assert calls[0].cache_ref is not None
    assert calls[0].parse_receipt_ref is not None
    assert calls[0].parsed_output_ref is not None
    assert len(normalized) == 1
    raw_locator = authority.responses[0].response.raw_response_ref
    assert not (started.database.parent / raw_locator).exists()
    assert _source_fingerprint(tmp_path) == source_before


def test_repository_is_stable_across_independent_readonly_snapshots(
    tmp_path: Path,
) -> None:
    started = _one_role_call(tmp_path)
    source_case = started.repository.load_case(
        RUN_ID,
        started.session.case_id,
    ).case

    with readonly_sqlite_snapshot(started.database) as first_snapshot:
        first = ReadonlyM6HearingModelCallAuthorityRepository(first_snapshot).assemble(source_case)
    with readonly_sqlite_snapshot(started.database) as second_snapshot:
        second = ReadonlyM6HearingModelCallAuthorityRepository(second_snapshot).assemble(
            source_case
        )

    assert first == second


def test_repository_assembles_real_failure_only_call(tmp_path: Path) -> None:
    seed = _provider_outage_seed(tmp_path)
    source_case = seed.repository.load_case(
        RUN_ID,
        _stored_case_id(seed.database),
    ).case

    with readonly_sqlite_snapshot(seed.database) as private_snapshot:
        repository = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot)
        authority = repository.load_authority(source_case)
        calls = repository.assemble(source_case)
        normalized = repository.resolve(source_case)

    assert len(authority.failures) == 1
    assert len(calls) == 1
    assert calls[0].result_kind == M6LockedModelCallResultKind.FAILURE
    assert calls[0].failure_ref is not None
    assert normalized == ()


def test_repository_proves_real_primary_and_repair_attempt_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    m4_sqlite_backlog.test_hearing_record_reload_includes_malformed_primary_and_valid_repair(
        tmp_path,
        monkeypatch,
    )
    database = next(tmp_path.glob("*.sqlite3"))
    source_case = _stored_current_case(database)

    with readonly_sqlite_snapshot(database) as private_snapshot:
        calls = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot).assemble(
            source_case
        )

    prosecutor_calls = tuple(item for item in calls if item.role == M6LockedModelRole.PROSECUTOR)
    assert len(calls) == 4
    assert {item.attempt_index for item in prosecutor_calls} == {0, 1}
    by_attempt = {item.attempt_index: item for item in prosecutor_calls}
    assert by_attempt[0].parsed_output_ref is None
    assert by_attempt[1].parsed_output_ref is not None


def test_repository_converts_invalid_m4_snapshot_to_typed_failure(
    tmp_path: Path,
) -> None:
    started = _one_role_call(tmp_path)
    source_case = started.repository.load_case(
        RUN_ID,
        started.session.case_id,
    ).case
    with sqlite3.connect(started.database) as connection:

        def tamper() -> None:
            row = connection.execute(
                "SELECT response_json FROM m4_model_responses WHERE run_id = ?",
                (RUN_ID,),
            ).fetchone()
            assert row is not None and isinstance(row[0], str)
            connection.execute(
                "UPDATE m4_model_responses SET response_json = ? WHERE run_id = ?",
                (row[0] + " ", RUN_ID),
            )

        _drop_restore_trigger(connection, "m4_model_responses_no_update", tamper)

    with readonly_sqlite_snapshot(started.database) as private_snapshot:
        repository = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot)
        with pytest.raises(M6HearingModelCallAuthorityError) as raised:
            repository.assemble(source_case)

    assert raised.value.code == M6HearingModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID


def test_repository_rejects_usage_retry_drift_from_durable_claim_takeover(
    tmp_path: Path,
) -> None:
    started = _one_role_call(tmp_path)
    source_case = started.repository.load_case(
        RUN_ID,
        started.session.case_id,
    ).case
    with sqlite3.connect(started.database) as connection:

        def tamper() -> None:
            connection.execute(
                """
                UPDATE m4_model_call_claims
                SET takeover_count = takeover_count + 1
                WHERE run_id = ?
                """,
                (RUN_ID,),
            )

        _drop_restore_trigger(
            connection,
            "m4_model_call_claims_controlled_update",
            tamper,
        )

    with readonly_sqlite_snapshot(started.database) as private_snapshot:
        full = ReadonlyM4ArtifactRepository(private_snapshot).scan(RUN_ID)
        assert any(
            item.reason_code == "COMPLETED_CALL_USAGE_CLAIM_MISMATCH" for item in full.failures
        )
        repository = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot)
        with pytest.raises(M6HearingModelCallAuthorityError) as raised:
            repository.assemble(source_case)

    assert raised.value.code == M6HearingModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID


def test_readonly_m4_scan_recomputes_usage_cost_from_request_budget(
    tmp_path: Path,
) -> None:
    started = _one_role_call(tmp_path)

    with readonly_sqlite_snapshot(started.database) as private_snapshot:
        baseline = ReadonlyM4ArtifactRepository(private_snapshot).scan(RUN_ID)
        assert baseline.failures == ()
        with patch.object(
            VlmCallBudget,
            "estimate_cost",
            return_value=999_999.0,
        ):
            recomputed = ReadonlyM4ArtifactRepository(private_snapshot).scan(RUN_ID)

    assert any(
        item.reason_code == "COMPLETED_CALL_CLOSURE_MISMATCH" for item in recomputed.failures
    )


def test_repository_revalidates_source_case_before_any_sqlite_scan(
    tmp_path: Path,
) -> None:
    started = _one_role_call(tmp_path)
    source_case = started.repository.load_case(
        RUN_ID,
        started.session.case_id,
    ).case
    forged = copy.deepcopy(source_case)
    object.__setattr__(forged, "run_id", "invalid run id")

    with readonly_sqlite_snapshot(started.database) as private_snapshot:
        repository = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot)
        with (
            patch.object(
                ReadonlyM4ArtifactRepository,
                "scan_replay_authority",
            ) as scan,
            pytest.raises(M6HearingModelCallAuthorityError) as raised,
        ):
            repository.load_authority(forged)

    assert raised.value.code == M6HearingModelCallAuthorityErrorCode.SOURCE_CASE_INVALID
    scan.assert_not_called()
