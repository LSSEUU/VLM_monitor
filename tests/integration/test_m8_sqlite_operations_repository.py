from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    M8_MIGRATIONS,
    SQLiteM8OperationsRepository,
)
from labcourt.adapters.storage.sqlite_repository import MigrationRunner, RepositoryIntegrityError
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseAction,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseReasonCode,
    M8OperationalCaseStatus,
    M8OperationalCaseTransitionCommandV1,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_case_persistence import M8OperationalCaseCommitReceiptV1
from labcourt.exceptions import ConcurrentModification

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BUSY_TIMEOUT_MS = 5_000


def _actor(*, revision: int = 1, active: bool = True) -> M8ActorAuthorityV1:
    return M8ActorAuthorityV1(
        actor_id="safety-officer-01",
        role=M8ActorRole.SAFETY_OFFICER,
        scope_kind=M8ActorScopeKind.LOCATIONS,
        scope_location_ids=("room-chem-301",),
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=revision,
        active=active,
        manifest_id=SHA_B,
    )


def _create_command() -> M8OperationalCaseCreateCommandV1:
    return M8OperationalCaseCreateCommandV1(
        source_catalog_id=SHA_A,
        location_id="room-chem-301",
        risk_level=M8OperationalRiskLevel.EMERGENCY,
        policy_rule_id="simulated-smoke-active-emergency-v1",
        policy_manifest_id=SHA_B,
        source_ids=("sensor-simulated-smoke-01",),
        simulated_source_ids=("sensor-simulated-smoke-01",),
        trigger_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.SENSOR_SIGNAL,
                authority_id="smoke-sample-01",
                document_sha256=SHA_C,
            ),
        ),
        automation_component_id="m8-offline-sensor-simulator",
        automation_manifest_id=SHA_D,
    )


def _transition(
    case: M8OperationalCaseCommitReceiptV1,
    actor: M8ActorAuthorityV1,
    *,
    action: M8OperationalCaseAction = M8OperationalCaseAction.CONFIRM,
) -> M8OperationalCaseTransitionCommandV1:
    reason = {
        M8OperationalCaseAction.CONFIRM: M8OperationalCaseReasonCode.VERIFIED_VIOLATION,
        M8OperationalCaseAction.REJECT: M8OperationalCaseReasonCode.FALSE_POSITIVE,
        M8OperationalCaseAction.RESOLVE: M8OperationalCaseReasonCode.HAZARD_CLEARED,
    }[action]
    return M8OperationalCaseTransitionCommandV1(
        case_id=case.case_id,
        source_case_version=case.case_version,
        source_case_authority_sha256=case.case_document_sha256,
        source_status=case.status,
        case_location_id=case.audit_event.case_authority.location_id,
        subject_actor_id=case.audit_event.case_authority.subject_actor_id,
        action=action,
        reason_code=reason,
        reason_summary="安全负责人已明确核实该动作及支持材料。",
        supporting_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.USER_STATEMENT,
                authority_id="statement-01",
                document_sha256=SHA_D,
            ),
        ),
        actor_authority=actor,
        explicit_human_confirmation=True,
        command_manifest_id=SHA_E,
    )


def _repository(tmp_path: Path) -> SQLiteM8OperationsRepository:
    operations_root = tmp_path / "operations"
    operations_root.mkdir()
    return SQLiteM8OperationsRepository.initialize(
        operations_root / "labcourt.sqlite3",
        BUSY_TIMEOUT_MS,
        SHA_C,
    )


def test_isolated_m8_migrations_install_only_additive_operations_layout(
    tmp_path: Path,
) -> None:
    operations_root = tmp_path / "isolated-operations"
    operations_root.mkdir()
    database = operations_root / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, M8_MIGRATIONS).apply_all() == (
        1,
        2,
        3,
        4,
        5,
        6,
        7,
    )
    with sqlite3.connect(database) as connection:
        versions = connection.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version"
        ).fetchall()
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert versions == [
        (1, "m8_actor_case_authority"),
        (2, "m8_campus_inventory"),
        (3, "m8_sensor_cache"),
        (4, "m8_notification_outbox"),
        (5, "m8_knowledge"),
        (6, "m8_adapter_commissioning"),
        (7, "m8_feishu_sandbox_activation"),
    ]
    assert tables == {
        "schema_migrations",
        "m8_actor_authorities",
        "m8_operational_case_versions",
        "m8_campus_topology_versions",
        "m8_source_catalog_versions",
        "m8_sensor_raw_signals",
        "m8_sensor_samples",
        "m8_sensor_poll_cache",
        "m8_sensor_poll_cache_samples",
        "m8_notification_targets",
        "m8_notification_raw_artifacts",
        "m8_notification_versions",
        "m8_notification_version_raw_artifacts",
        "m8_knowledge_raw_contents",
        "m8_knowledge_catalog_versions",
        "m8_knowledge_catalog_documents",
        "m8_knowledge_answer_receipts",
        "m8_production_adapter_candidates",
        "m8_commissioning_evidence",
        "m8_feishu_sandbox_activations",
        "m8_feishu_sandbox_activation_revocations",
    }


def test_repository_persists_idempotent_actor_create_transition_and_audit_chain(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    actor = _actor()
    actor_receipt = repository.publish_actor_authority(actor, None)
    assert repository.publish_actor_authority(actor, None) == actor_receipt

    create_command = _create_command()
    created = repository.create_operational_case(
        create_command,
        "student-01",
        SHA_D,
        SHA_E,
    )
    assert (
        repository.create_operational_case(
            create_command,
            "student-01",
            SHA_D,
            SHA_E,
        )
        == created
    )
    assert created.status == M8OperationalCaseStatus.PENDING_VERIFICATION

    transition = _transition(created, actor)
    confirmed = repository.transition_operational_case(transition, SHA_D, SHA_E)
    assert repository.transition_operational_case(transition, SHA_D, SHA_E) == confirmed
    with pytest.raises(ConcurrentModification, match="different authority"):
        repository.transition_operational_case(transition, SHA_A, SHA_E)
    assert confirmed.case_version == 2
    assert confirmed.status == M8OperationalCaseStatus.CONFIRMED

    resolved = repository.transition_operational_case(
        _transition(confirmed, actor, action=M8OperationalCaseAction.RESOLVE),
        SHA_D,
        SHA_E,
    )
    assert resolved.case_version == 3
    assert repository.transition_operational_case(transition, SHA_D, SHA_E) == confirmed

    reopened = SQLiteM8OperationsRepository(
        tmp_path / "operations" / "labcourt.sqlite3",
        BUSY_TIMEOUT_MS,
        SHA_C,
    )
    assert reopened.get_current_actor_authority(actor.actor_id) == actor_receipt
    assert reopened.get_current_operational_case(created.case_id) == resolved
    assert reopened.list_current_operational_cases(10) == (resolved,)
    audit = reopened.list_operational_case_audit(created.case_id)
    assert tuple(event.event_sequence for event in audit) == (1, 2, 3)
    assert audit[1].prior_audit_event_sha256 == audit[0].audit_event_sha256
    assert audit[2].prior_audit_event_sha256 == audit[1].audit_event_sha256


def test_repository_converts_missing_m8_migration_ledger_to_typed_integrity_failure(
    tmp_path: Path,
) -> None:
    operations_root = tmp_path / "uninitialized-operations"
    operations_root.mkdir()
    database = operations_root / "labcourt.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")

    with pytest.raises(RepositoryIntegrityError, match="migration ledger"):
        SQLiteM8OperationsRepository(database, BUSY_TIMEOUT_MS, SHA_C)


def test_repository_rejects_client_actor_authority_after_persisted_revision_advances(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    actor_v1 = _actor()
    repository.publish_actor_authority(actor_v1, None)
    created = repository.create_operational_case(
        _create_command(),
        "student-01",
        SHA_D,
        SHA_E,
    )
    command_with_stale_actor = _transition(created, actor_v1)

    repository.publish_actor_authority(_actor(revision=2, active=False), 1)
    with pytest.raises(ConcurrentModification, match="current persisted authority"):
        repository.transition_operational_case(command_with_stale_actor, SHA_D, SHA_E)
    assert repository.get_current_operational_case(created.case_id).case_version == 1


def test_repository_optimistic_case_fence_rejects_second_command_from_same_source(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    actor = _actor()
    repository.publish_actor_authority(actor, None)
    created = repository.create_operational_case(
        _create_command(),
        "student-01",
        SHA_D,
        SHA_E,
    )
    confirm = _transition(created, actor)
    reject = _transition(created, actor, action=M8OperationalCaseAction.REJECT)

    repository.transition_operational_case(confirm, SHA_D, SHA_E)
    with pytest.raises(ConcurrentModification, match="source version is stale"):
        repository.transition_operational_case(reject, SHA_D, SHA_E)
    assert repository.get_current_operational_case(created.case_id).case_version == 2


def test_m8_authority_rows_are_append_only_at_sql_boundary(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    actor = _actor()
    repository.publish_actor_authority(actor, None)
    created = repository.create_operational_case(
        _create_command(),
        "student-01",
        SHA_D,
        SHA_E,
    )
    database = tmp_path / "operations" / "labcourt.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA recursive_triggers = ON")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m8_actor_authorities SET active = 0 WHERE actor_id = ?",
                (actor.actor_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM m8_operational_case_versions WHERE case_id = ?",
                (created.case_id,),
            )
