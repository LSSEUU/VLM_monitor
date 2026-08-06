from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v2 import (
    SQLiteM6UpgradeExecutionLedgerV2Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
    load_m6_upgrade_v3_state_from_connection,
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
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Status,
)
from tests.contract.test_m6_regression_execution_contracts import _inventory
from tests.integration import test_m2_sqlite_repository as m2_fixture
from tests.integration.test_m6_upgrade_execution_observation_v3_repository import (
    BUSY_TIMEOUT_MS,
    _observation_v2,
    _prepare_v3,
)


def _load_state(
    database: Path,
    repository: SQLiteM6UpgradeExecutionLedgerV3Repository,
    run_id: str,
    scope_id: str,
):
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN")
        state = load_m6_upgrade_v3_state_from_connection(
            repository,
            connection,
            run_id,
            scope_id,
        )
        assert connection.in_transaction
        return state
    finally:
        connection.rollback()
        connection.close()


def test_v3_state_codec_reads_fresh_and_observation_pending_states(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    observation_repository, scope = _prepare_v3(database)
    ledger_repository = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )

    fresh = _load_state(
        database,
        ledger_repository,
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert fresh.records == fresh.observations == fresh.commitments == ()
    assert fresh.seal is None
    assert (
        ledger_repository.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        ).status
        == M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION
    )

    observation = _observation_v2(scope)
    assert observation_repository.append(observation) == observation
    pending = _load_state(
        database,
        ledger_repository,
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert pending.records == pending.commitments == ()
    assert tuple(item.authority for item in pending.observations) == (observation,)
    resumed = ledger_repository.resume(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert resumed.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT
    assert resumed.pending_observation == observation


def test_v3_state_codec_rejects_cross_protocol_before_authority_dispatch(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope = _inventory().execution_ledger.execution_scope
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    SQLiteM6UpgradeExecutionLedgerV2Repository(
        database,
        BUSY_TIMEOUT_MS,
    ).begin_execution(scope)
    repository = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN")
        with pytest.raises(M6UpgradeExecutionLedgerV3Error) as raised:
            load_m6_upgrade_v3_state_from_connection(
                repository,
                connection,
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
            )
        assert connection.in_transaction
    finally:
        connection.rollback()
        connection.close()
    assert (
        raised.value.reason_code == M6UpgradeExecutionLedgerV3FailureCode.LEGACY_LEDGER_UNSUPPORTED
    )


def _case_observation(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    evidence = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    event_payload = m2_fixture._event().model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    event_payload["rule_version"] = scope.candidate_manifest.rule_version
    event_payload["manifest_id"] = scope.candidate_manifest.manifest_id
    for fact in event_payload["objective_facts"]:
        fact["source_manifest_id"] = scope.candidate_manifest.manifest_id
    snapshot = evidence.create_or_get_case(
        scope.candidate_run_id,
        CandidateEvent.model_validate(event_payload),
    )
    case_raw = canonical_json(snapshot.case.model_dump(mode="json"))
    audit_head = evidence.get_audit_head(scope.candidate_run_id)
    binding = M6UpgradeCandidateCaseBinding(
        case_id=snapshot.case.case_id,
        case_revision=snapshot.revision,
        case_document_sha256=hashlib.sha256(case_raw.encode("utf-8")).hexdigest(),
        case_audit_sequence=audit_head.sequence,
        case_audit_entry_hash=audit_head.entry_hash,
    )
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=binding.case_binding_id,
        action=AuditAction.CASE_CREATED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=snapshot.case.case_id),
    )
    no_case = _observation_v2(scope)
    return M6UpgradeSampleExecutionObservationAuthorityV2(
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


def test_v3_state_codec_exact_joins_case_version_and_selected_audit_anchor(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    observation_repository, scope = _prepare_v3(database)
    ledger_repository = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    observation = _case_observation(database, scope)
    assert observation_repository.append(observation) == observation
    assert (
        ledger_repository.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        ).status
        == M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT
    )

    assert observation.candidate_case is not None
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER case_versions_no_update")
        connection.execute(
            """
            UPDATE case_versions SET document_sha256 = ?
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (
                "0" * 64,
                scope.candidate_run_id,
                observation.candidate_case.case_id,
                observation.candidate_case.case_revision,
            ),
        )

    with pytest.raises(M6UpgradeExecutionLedgerV3Error) as raised:
        ledger_repository.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert (
        raised.value.reason_code == M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID
    )
