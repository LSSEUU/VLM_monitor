from __future__ import annotations

import hashlib
import sqlite3
import traceback
from collections.abc import Callable
from pathlib import Path

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_execution_ledger_v3_codec as v3_codec
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation import (
    SQLiteM6UpgradeExecutionObservationRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation_v3 import (
    SQLiteM6UpgradeExecutionObservationV3Repository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind, AuditAction
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.ports.m6_upgrade_execution_observation import (
    M6UpgradeExecutionObservationError,
    M6UpgradeExecutionObservationFailureCode,
)
from tests.contract.test_m6_regression_execution_contracts import _inventory
from tests.integration import test_m2_sqlite_repository as m2_fixture

BUSY_TIMEOUT_MS = 2_000
ORPHAN_OBSERVATION_AUTHORITY_ID = "e" * 64


def _assert_payload_free_observation_error(
    error: M6UpgradeExecutionObservationError,
    expected: M6UpgradeExecutionObservationFailureCode,
    *,
    forbidden: str,
) -> None:
    assert error.reason_code == expected
    assert error.__cause__ is None
    assert error.__context__ is None
    assert forbidden not in "".join(traceback.format_exception(error))
    repository_frames = []
    current = error.__traceback__
    while current is not None:
        if current.tb_frame.f_code.co_filename.endswith(
            "sqlite_m6_upgrade_execution_observation_v3.py"
        ):
            repository_frames.append(current.tb_frame)
        current = current.tb_next
    assert repository_frames
    assert all("self" not in frame.f_locals for frame in repository_frames)


def _observation_v1(
    scope: M6UpgradeExecutionScopeAuthority,
    *,
    ledger_sequence: int = 0,
) -> M6UpgradeSampleExecutionObservationAuthority:
    return M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[ledger_sequence],
        ledger_sequence=ledger_sequence,
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifacts=(
            M6UpgradeObservedArtifactIdentity(
                source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                kind=M6UpgradePhysicalArtifactKind.FRAME,
                artifact_id=f"camera-v3:stream-v3:{ledger_sequence}",
                usage=M6UpgradeArtifactUsage.CONSUMED,
            ),
        ),
        model_calls=(),
    )


def _observation_v2(
    scope: M6UpgradeExecutionScopeAuthority,
    *,
    ledger_sequence: int = 0,
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    base = _observation_v1(scope, ledger_sequence=ledger_sequence)
    return M6UpgradeSampleExecutionObservationAuthorityV2(
        **base.model_dump(
            mode="python",
            exclude={"schema_version"},
            exclude_computed_fields=True,
        ),
        selected_case_audit_anchor=None,
    )


def _prepare_v3(
    database: Path,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> tuple[
    SQLiteM6UpgradeExecutionObservationV3Repository,
    M6UpgradeExecutionScopeAuthority,
]:
    scope = _inventory().execution_ledger.execution_scope
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    repository = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        fault_injector=fault_injector,
    )
    repository.begin_execution(scope)
    return repository, scope


def _counts(database: Path) -> tuple[int, int, int, int, int]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "m6_upgrade_observed_non_model_artifacts",
                "m6_upgrade_observed_model_calls",
                "m6_upgrade_sample_execution_observations",
                "m6_upgrade_pending_sample_commitments",
                "m6_upgrade_sample_executions",
            )
        )  # type: ignore[return-value]


def _insert_orphan_child(database: Path, *, run_id: str, child_kind: str) -> None:
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        if child_kind == "artifact":
            connection.execute(
                """
                INSERT INTO m6_upgrade_observed_non_model_artifacts(
                    run_id, observation_authority_id, ordinal,
                    source, kind, artifact_id, usage
                ) VALUES (?, ?, 0, 'M2_PERCEPTION', 'FRAME', ?, 'CONSUMED')
                """,
                (run_id, ORPHAN_OBSERVATION_AUTHORITY_ID, "orphan:frame"),
            )
        elif child_kind == "model_call":
            connection.execute(
                """
                INSERT INTO m6_upgrade_observed_model_calls(
                    run_id, observation_authority_id, ordinal,
                    request_id, layer, role, attempt_index,
                    result_kind, provider_invoked
                ) VALUES (?, ?, 0, ?, 'SCREENING', 'SCREENING', 0, 'FAILURE', 0)
                """,
                (run_id, ORPHAN_OBSERVATION_AUTHORITY_ID, "d" * 64),
            )
        else:
            raise AssertionError(f"unsupported orphan child kind: {child_kind}")
        connection.commit()
    finally:
        connection.close()


def test_v3_append_load_and_exact_pending_retry_are_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare_v3(database)
    observation = _observation_v2(scope)

    assert repository.append(observation) == observation
    assert (
        repository.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        )
        == observation
    )
    assert repository.append(observation) == observation
    assert _counts(database) == (1, 0, 1, 0, 0)

    with sqlite3.connect(database) as connection:
        protocol = connection.execute(
            "SELECT protocol_version FROM m6_upgrade_execution_ledger_protocols WHERE run_id = ?",
            (scope.candidate_run_id,),
        ).fetchone()
        normalized = connection.execute(
            """
            SELECT observation_schema_version, selected_case_audit_anchor_id,
                   case_audit_action, case_audit_object_kind, case_audit_object_id
            FROM m6_upgrade_sample_execution_observations WHERE run_id = ?
            """,
            (scope.candidate_run_id,),
        ).fetchone()
    assert protocol == ("v3",)
    assert normalized == ("v2", None, None, None, None)


@pytest.mark.parametrize("child_kind", ("artifact", "model_call"))
@pytest.mark.parametrize("operation", ("fresh_append", "load", "exact_retry"))
def test_v3_fails_closed_on_orphan_observation_children(
    tmp_path: Path,
    child_kind: str,
    operation: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare_v3(database)
    observation = _observation_v2(scope)
    assert observation.observation_authority_id != ORPHAN_OBSERVATION_AUTHORITY_ID

    if operation != "fresh_append":
        assert repository.append(observation) == observation
    _insert_orphan_child(
        database,
        run_id=scope.candidate_run_id,
        child_kind=child_kind,
    )

    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        if operation == "load":
            repository.load(
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
                observation.ledger_sequence,
            )
        else:
            repository.append(observation)

    assert (
        rejected.value.reason_code
        == M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID
    )
    assert _counts(database)[2] == (0 if operation == "fresh_append" else 1)


def test_v3_begin_execution_writer_lock_is_a_payload_free_storage_rejection(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope = _inventory().execution_ledger.execution_scope
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    repository = SQLiteM6UpgradeExecutionObservationV3Repository(database, 1)
    blocker = sqlite3.connect(database)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
            repository.begin_execution(scope)
    finally:
        blocker.rollback()
        blocker.close()

    error = rejected.value
    _assert_payload_free_observation_error(
        error,
        M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED,
        forbidden="database is locked",
    )
    assert error.args == ("M6 execution observation failed: STORAGE_REJECTED",)
    assert vars(error) == {"reason_code": M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED}
    assert str(database) not in str(error)
    assert "database is locked" not in str(error).lower()
    assert repository.begin_execution(scope) == scope


def test_v3_observation_begin_retry_preflights_scope_before_raw_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare_v3(database)
    with sqlite3.connect(database) as connection:
        stored_size = connection.execute(
            """
            SELECT size_bytes FROM m6_upgrade_execution_scopes
            WHERE run_id = ?
            """,
            (scope.candidate_run_id,),
        ).fetchone()[0]
    assert isinstance(stored_size, int) and stored_size > 1
    monkeypatch.setattr(v3_codec, "MAX_M6_UPGRADE_SCOPE_BYTES", stored_size - 1)

    def raw_parser_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scope raw parser ran before byte-budget preflight")

    monkeypatch.setattr(v3_codec, "scope_from_row", raw_parser_must_not_run)
    statements: list[str] = []
    original_connection = repository._connection

    def traced_connection() -> sqlite3.Connection:
        connection = original_connection()
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(repository, "_connection", traced_connection)
    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.begin_execution(scope)
    _assert_payload_free_observation_error(
        rejected.value,
        M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE,
        forbidden=scope.candidate_run_id,
    )
    normalized = tuple(" ".join(statement.upper().split()) for statement in statements)
    assert not any(
        "SELECT * FROM M6_UPGRADE_EXECUTION_SCOPES" in statement for statement in normalized
    )


def test_v3_case_observation_exact_joins_the_selected_creation_audit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare_v3(database)
    evidence = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    event_payload = m2_fixture._event().model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    event_payload["rule_version"] = scope.candidate_manifest.rule_version
    event_payload["manifest_id"] = scope.candidate_manifest.manifest_id
    for fact in event_payload["objective_facts"]:
        fact["source_manifest_id"] = scope.candidate_manifest.manifest_id
    case_snapshot = evidence.create_or_get_case(
        scope.candidate_run_id,
        CandidateEvent.model_validate(event_payload),
    )
    case_raw = canonical_json(case_snapshot.case.model_dump(mode="json"))
    case_document_sha256 = hashlib.sha256(case_raw.encode("utf-8")).hexdigest()
    audit_head = evidence.get_audit_head(scope.candidate_run_id)
    binding = M6UpgradeCandidateCaseBinding(
        case_id=case_snapshot.case.case_id,
        case_revision=case_snapshot.revision,
        case_document_sha256=case_document_sha256,
        case_audit_sequence=audit_head.sequence,
        case_audit_entry_hash=audit_head.entry_hash,
    )
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=binding.case_binding_id,
        action=AuditAction.CASE_CREATED,
        object_ref=ArtifactRef(
            kind=ArtifactKind.CASE,
            artifact_id=case_snapshot.case.case_id,
        ),
    )
    no_case = _observation_v1(scope)
    observation = M6UpgradeSampleExecutionObservationAuthorityV2(
        execution_scope_authority_id=no_case.execution_scope_authority_id,
        candidate_run_id=no_case.candidate_run_id,
        command_id=no_case.command_id,
        execution_dataset_snapshot_id=no_case.execution_dataset_snapshot_id,
        execution_entry=no_case.execution_entry,
        ledger_sequence=no_case.ledger_sequence,
        outcome=M6ReplayExecutionOutcome.CASE_REPLAYED,
        candidate_case=binding,
        selected_case_audit_anchor=anchor,
        artifacts=no_case.artifacts,
        model_calls=(),
    )

    assert repository.append(observation) == observation
    with sqlite3.connect(database) as connection:
        normalized = connection.execute(
            """
            SELECT selected_case_audit_anchor_id, case_audit_action,
                   case_audit_object_kind, case_audit_object_id
            FROM m6_upgrade_sample_execution_observations WHERE run_id = ?
            """,
            (scope.candidate_run_id,),
        ).fetchone()
    assert normalized == (
        anchor.selected_case_audit_anchor_id,
        AuditAction.CASE_CREATED.value,
        ArtifactKind.CASE.value,
        case_snapshot.case.case_id,
    )


def test_v3_second_pending_observation_is_rejected_without_child_leak(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare_v3(database)
    assert repository.append(_observation_v2(scope)) == _observation_v2(scope)

    with pytest.raises(M6UpgradeExecutionObservationError) as raised:
        repository.append(_observation_v2(scope, ledger_sequence=1))
    assert (
        raised.value.reason_code
        == M6UpgradeExecutionObservationFailureCode.PENDING_OBSERVATION_EXISTS
    )
    assert _counts(database) == (1, 0, 1, 0, 0)


def test_v2_and_v3_repository_types_and_protocols_cannot_cross(
    tmp_path: Path,
) -> None:
    v3_workspace = tmp_path / "v3"
    v3_workspace.mkdir()
    v3_database = v3_workspace / "labcourt.sqlite3"
    v3_repository, scope = _prepare_v3(v3_database)
    with pytest.raises(M6UpgradeExecutionObservationError) as raised:
        v3_repository.append(_observation_v1(scope))  # type: ignore[arg-type]
    assert raised.value.reason_code == M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT

    legacy_repository = SQLiteM6UpgradeExecutionObservationRepository(
        v3_database,
        BUSY_TIMEOUT_MS,
    )
    with pytest.raises(M6UpgradeExecutionObservationError) as raised:
        legacy_repository.begin_execution(scope)
    assert (
        raised.value.reason_code
        == M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED
    )

    v2_workspace = tmp_path / "v2"
    v2_workspace.mkdir()
    v2_database = v2_workspace / "labcourt.sqlite3"
    MigrationRunner(v2_database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(v2_database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    v2_repository = SQLiteM6UpgradeExecutionObservationRepository(
        v2_database,
        BUSY_TIMEOUT_MS,
    )
    v2_repository.begin_execution(scope)
    with pytest.raises(M6UpgradeExecutionObservationError) as raised:
        v2_repository.append(_observation_v2(scope))
    assert raised.value.reason_code == M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT
    with pytest.raises(M6UpgradeExecutionObservationError) as raised:
        SQLiteM6UpgradeExecutionObservationV3Repository(
            v2_database,
            BUSY_TIMEOUT_MS,
        ).begin_execution(scope)
    assert (
        raised.value.reason_code
        == M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED
    )


def test_v3_codec_rejects_normalized_schema_drift(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare_v3(database)
    repository.append(_observation_v2(scope))
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER m6_upgrade_sample_execution_observations_no_update")
        connection.execute(
            """
            UPDATE m6_upgrade_sample_execution_observations
            SET observation_schema_version = 'v1'
            WHERE run_id = ?
            """,
            (scope.candidate_run_id,),
        )
        connection.execute(
            """
            CREATE TRIGGER m6_upgrade_sample_execution_observations_no_update
            BEFORE UPDATE ON m6_upgrade_sample_execution_observations
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'M6 upgrade execution observations are append-only'
                );
            END
            """
        )

    with pytest.raises(M6UpgradeExecutionObservationError) as raised:
        repository.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        )
    assert (
        raised.value.reason_code
        == M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID
    )


@pytest.mark.parametrize(
    "fault_phase",
    (
        "append.after_artifacts",
        "append.after_model_calls",
        "append.after_observation",
        "append.before_commit",
    ),
)
def test_v3_all_fault_phases_roll_back_the_pending_observation(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    def fail_at(phase: str) -> None:
        if phase == f"m6_upgrade_execution_observation_v3.{fault_phase}":
            raise RuntimeError("simulated V3 observation crash")

    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare_v3(database, fault_injector=fail_at)
    observation = _observation_v2(scope)
    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.append(observation)
    _assert_payload_free_observation_error(
        rejected.value,
        M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED,
        forbidden="simulated V3 observation crash",
    )
    assert _counts(database) == (0, 0, 0, 0, 0)

    recovered = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    assert recovered.append(observation) == observation
