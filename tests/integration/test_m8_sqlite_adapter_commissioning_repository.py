from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m8_adapter_commissioning_repository import (
    SQLiteM8AdapterCommissioningRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
)
from labcourt.contracts.m8_adapter_commissioning import (
    M8CommissioningEvidenceAuthorityV1,
    M8CommissioningEvidenceKind,
    M8CommissioningEvidenceOutcome,
    M8CommissioningReadiness,
    M8ExternalIdempotencyKey,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterKind,
)
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService
from labcourt.services.m8_commissioning_api import M8CommissioningApiService
from labcourt.services.m8_operations_api import M8ApiServiceError, M8ApiServiceFailureCode

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
BUSY_TIMEOUT_MS = 5_000
REVIEWED_AT = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)
ARTIFACT = b"commissioning-evidence" * 8


def _actor(
    role: M8ActorRole,
    *,
    revision: int = 1,
    active: bool = True,
) -> M8ActorAuthorityV1:
    actor_id = {
        M8ActorRole.OPERATIONS: "operations-commissioning-01",
        M8ActorRole.SAFETY_OFFICER: "safety-commissioning-01",
    }[role]
    return M8ActorAuthorityV1(
        actor_id=actor_id,
        role=role,
        scope_kind=M8ActorScopeKind.LOCATIONS,
        scope_location_ids=("room-chem-301",),
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=revision,
        active=active,
        manifest_id=SHA_B,
    )


def _candidate(
    *,
    timeout_ms: int = 5_000,
    adapter_revision: str = "revision-01",
) -> M8ProductionAdapterCandidateAuthorityV1:
    return M8ProductionAdapterCandidateAuthorityV1(
        adapter_id="rtsp-camera-adapter-01",
        adapter_revision=adapter_revision,
        adapter_kind=M8ProductionAdapterKind.RTSP_CAMERA,
        provider_id="camera-provider-reviewed-01",
        product_revision="firmware-revision-01",
        campus_id="campus-main",
        scope_kind=M8ActorScopeKind.LOCATIONS,
        scope_location_ids=("room-chem-301",),
        declared_license_id="license-review-required",
        request_timeout_ms=timeout_ms,
        idempotency_key=M8ExternalIdempotencyKey.SOURCE_SEQUENCE,
        network_required=True,
        offline_fallback_adapter_id="recorded-video-fake",
        offline_fallback_revision="offline-revision-01",
        adapter_manifest_id=SHA_C,
        offline_fallback_manifest_id=SHA_D,
    )


def _evidence(
    candidate: M8ProductionAdapterCandidateAuthorityV1,
    reviewer: M8ActorAuthorityCommitReceiptV1,
    *,
    kind: M8CommissioningEvidenceKind = M8CommissioningEvidenceKind.SAFETY_REVIEW,
    artifact: bytes = ARTIFACT,
    outcome: M8CommissioningEvidenceOutcome = M8CommissioningEvidenceOutcome.PASSED,
    reviewed_at: datetime = REVIEWED_AT,
    ref_suffix: str = "",
) -> M8CommissioningEvidenceAuthorityV1:
    return M8CommissioningEvidenceAuthorityV1(
        candidate=candidate,
        evidence_kind=kind,
        outcome=outcome,
        artifact_ref=f"artifact-{kind.value.lower().replace('_', '-')}{ref_suffix}",
        artifact_sha256=hashlib.sha256(artifact).hexdigest(),
        artifact_size_bytes=len(artifact),
        reviewer_actor_receipt=reviewer,
        reviewed_at=reviewed_at,
        valid_through=reviewed_at + timedelta(days=30),
        simulated=kind == M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
        evidence_manifest_id=SHA_C,
    )


def _principal(actor_id: str) -> M8ApiPrincipalV1:
    return M8ApiPrincipalV1(
        actor_id=actor_id,
        credential_id=f"credential-{actor_id}",
        credential_authority_id=SHA_A,
        credential_catalog_id=SHA_B,
        authentication_manifest_id=SHA_C,
    )


@pytest.fixture
def repositories(
    tmp_path: Path,
) -> tuple[
    Path,
    SQLiteM8OperationsRepository,
    SQLiteM8AdapterCommissioningRepository,
    M8ActorAuthorityCommitReceiptV1,
    M8ActorAuthorityCommitReceiptV1,
]:
    root = tmp_path / "commissioning"
    root.mkdir()
    database = root / "labcourt.sqlite3"
    operations = SQLiteM8OperationsRepository.initialize(database, BUSY_TIMEOUT_MS, SHA_A)
    operations_receipt = operations.publish_actor_authority(_actor(M8ActorRole.OPERATIONS), None)
    safety_receipt = operations.publish_actor_authority(_actor(M8ActorRole.SAFETY_OFFICER), None)
    commissioning = SQLiteM8AdapterCommissioningRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    return database, operations, commissioning, operations_receipt, safety_receipt


def test_candidate_and_raw_evidence_are_restart_safe_append_only_and_idempotent(
    repositories: tuple[
        Path,
        SQLiteM8OperationsRepository,
        SQLiteM8AdapterCommissioningRepository,
        M8ActorAuthorityCommitReceiptV1,
        M8ActorAuthorityCommitReceiptV1,
    ],
) -> None:
    database, _operations, repository, operations_receipt, safety_receipt = repositories
    candidate = _candidate()
    candidate_receipt = repository.register_candidate(
        candidate,
        operations_receipt.authority.actor_id,
    )
    assert repository.register_candidate(candidate, operations_receipt.authority.actor_id) == (
        candidate_receipt
    )
    evidence = _evidence(candidate, safety_receipt)
    evidence_receipt = repository.commit_evidence(evidence, ARTIFACT, SHA_B)
    assert repository.commit_evidence(evidence, ARTIFACT, SHA_B) == evidence_receipt
    assert repository.read_artifact(evidence.artifact_ref) == ARTIFACT

    reopened = SQLiteM8AdapterCommissioningRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    assert reopened.get_candidate(candidate.candidate_authority_id) == candidate_receipt
    assert reopened.get_evidence(evidence.evidence_authority_id) == evidence_receipt
    assert reopened.list_candidate_evidence(candidate.candidate_authority_id, 5) == (
        evidence_receipt,
    )

    connection = sqlite3.connect(database)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m8_production_adapter_candidates SET campus_id = 'other-campus'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m8_commissioning_evidence")
    finally:
        connection.close()


def test_registration_and_evidence_recheck_current_actor_authority(
    repositories: tuple[
        Path,
        SQLiteM8OperationsRepository,
        SQLiteM8AdapterCommissioningRepository,
        M8ActorAuthorityCommitReceiptV1,
        M8ActorAuthorityCommitReceiptV1,
    ],
) -> None:
    _database, operations, repository, operations_receipt, safety_receipt = repositories
    candidate = _candidate()
    repository.register_candidate(candidate, operations_receipt.authority.actor_id)
    evidence = _evidence(candidate, safety_receipt)
    operations.publish_actor_authority(
        _actor(M8ActorRole.SAFETY_OFFICER, revision=2, active=False),
        1,
    )
    with pytest.raises(ConcurrentModification, match="reviewer is not current"):
        repository.commit_evidence(evidence, ARTIFACT, SHA_B)

    operations.publish_actor_authority(
        _actor(M8ActorRole.OPERATIONS, revision=2, active=False),
        1,
    )
    with pytest.raises(ConcurrentModification, match="in-scope operations actor"):
        repository.register_candidate(
            _candidate(adapter_revision="revision-02"),
            operations_receipt.authority.actor_id,
        )


def test_evidence_requires_registered_candidate_and_exact_raw_bytes_atomically(
    repositories: tuple[
        Path,
        SQLiteM8OperationsRepository,
        SQLiteM8AdapterCommissioningRepository,
        M8ActorAuthorityCommitReceiptV1,
        M8ActorAuthorityCommitReceiptV1,
    ],
) -> None:
    _database, _operations, repository, operations_receipt, safety_receipt = repositories
    candidate = _candidate()
    evidence = _evidence(candidate, safety_receipt)
    with pytest.raises(EvidenceMissing, match="not registered"):
        repository.commit_evidence(evidence, ARTIFACT, SHA_B)

    repository.register_candidate(candidate, operations_receipt.authority.actor_id)
    with pytest.raises(ConcurrentModification, match="hash or size"):
        repository.commit_evidence(evidence, b"x" * len(ARTIFACT), SHA_B)
    with pytest.raises(EvidenceMissing):
        repository.get_evidence(evidence.evidence_authority_id)


def test_candidate_revision_collision_and_evidence_query_budget_fail_closed(
    repositories: tuple[
        Path,
        SQLiteM8OperationsRepository,
        SQLiteM8AdapterCommissioningRepository,
        M8ActorAuthorityCommitReceiptV1,
        M8ActorAuthorityCommitReceiptV1,
    ],
) -> None:
    _database, _operations, repository, operations_receipt, safety_receipt = repositories
    candidate = _candidate()
    repository.register_candidate(candidate, operations_receipt.authority.actor_id)
    with pytest.raises(ConcurrentModification, match="revision"):
        repository.register_candidate(
            _candidate(timeout_ms=6_000),
            operations_receipt.authority.actor_id,
        )

    safety = _evidence(candidate, safety_receipt)
    site = _evidence(
        candidate,
        safety_receipt,
        kind=M8CommissioningEvidenceKind.SITE_ACCEPTANCE,
    )
    repository.commit_evidence(safety, ARTIFACT, SHA_B)
    repository.commit_evidence(site, ARTIFACT, SHA_B)
    with pytest.raises(BudgetExceeded):
        repository.list_candidate_evidence(candidate.candidate_authority_id, 1)


def test_corrupt_raw_artifact_and_repository_manifest_fail_closed(
    repositories: tuple[
        Path,
        SQLiteM8OperationsRepository,
        SQLiteM8AdapterCommissioningRepository,
        M8ActorAuthorityCommitReceiptV1,
        M8ActorAuthorityCommitReceiptV1,
    ],
) -> None:
    database, _operations, repository, operations_receipt, safety_receipt = repositories
    candidate = _candidate()
    repository.register_candidate(candidate, operations_receipt.authority.actor_id)
    evidence = _evidence(candidate, safety_receipt)
    repository.commit_evidence(evidence, ARTIFACT, SHA_B)

    with pytest.raises(RepositoryIntegrityError, match="index conflicts"):
        SQLiteM8AdapterCommissioningRepository(database, BUSY_TIMEOUT_MS, SHA_B).get_candidate(
            candidate.candidate_authority_id
        )

    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TRIGGER m8_commissioning_evidence_no_update")
        connection.execute(
            "UPDATE m8_commissioning_evidence SET artifact_bytes = ?",
            (b"x" * len(ARTIFACT),),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RepositoryIntegrityError, match="index conflicts"):
        repository.read_artifact(evidence.artifact_ref)


def test_readiness_service_selects_latest_persisted_evidence_and_current_assessor(
    repositories: tuple[
        Path,
        SQLiteM8OperationsRepository,
        SQLiteM8AdapterCommissioningRepository,
        M8ActorAuthorityCommitReceiptV1,
        M8ActorAuthorityCommitReceiptV1,
    ],
) -> None:
    _database, operations, repository, operations_receipt, safety_receipt = repositories
    candidate = _candidate()
    repository.register_candidate(candidate, operations_receipt.authority.actor_id)
    service = M8AdapterReadinessService(repository, operations, SHA_D)

    empty = service.assess(
        candidate.candidate_authority_id,
        operations_receipt.authority.actor_id,
        REVIEWED_AT + timedelta(minutes=1),
    )
    assert empty.readiness == M8CommissioningReadiness.BLOCKED
    assert empty.production_activation_permitted is False

    for kind in M8CommissioningEvidenceKind:
        reviewer = (
            operations_receipt
            if kind
            in {
                M8CommissioningEvidenceKind.LICENSE_REVIEW,
                M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
                M8CommissioningEvidenceKind.SECURITY_REVIEW,
            }
            else safety_receipt
        )
        repository.commit_evidence(_evidence(candidate, reviewer, kind=kind), ARTIFACT, SHA_B)
    ready = service.assess(
        candidate.candidate_authority_id,
        operations_receipt.authority.actor_id,
        REVIEWED_AT + timedelta(hours=1),
    )
    assert ready.readiness == M8CommissioningReadiness.READY_FOR_HUMAN_ACTIVATION
    assert ready.production_activation_permitted is False

    later_failed = _evidence(
        candidate,
        operations_receipt,
        kind=M8CommissioningEvidenceKind.LICENSE_REVIEW,
        outcome=M8CommissioningEvidenceOutcome.FAILED,
        reviewed_at=REVIEWED_AT + timedelta(hours=2),
        ref_suffix="-later",
    )
    repository.commit_evidence(later_failed, ARTIFACT, SHA_B)
    blocked = service.assess(
        candidate.candidate_authority_id,
        operations_receipt.authority.actor_id,
        REVIEWED_AT + timedelta(hours=3),
    )
    assert blocked.readiness == M8CommissioningReadiness.BLOCKED
    assert blocked.failed_evidence_kinds == (M8CommissioningEvidenceKind.LICENSE_REVIEW,)

    operations.publish_actor_authority(
        _actor(M8ActorRole.OPERATIONS, revision=2, active=False),
        1,
    )
    with pytest.raises(ConcurrentModification, match="not authorized"):
        service.assess(
            candidate.candidate_authority_id,
            operations_receipt.authority.actor_id,
            REVIEWED_AT + timedelta(hours=4),
        )


def test_readiness_api_uses_server_clock_current_operations_and_has_no_side_effect(
    repositories: tuple[
        Path,
        SQLiteM8OperationsRepository,
        SQLiteM8AdapterCommissioningRepository,
        M8ActorAuthorityCommitReceiptV1,
        M8ActorAuthorityCommitReceiptV1,
    ],
) -> None:
    _database, operations, repository, operations_receipt, safety_receipt = repositories
    candidate = _candidate()
    candidate_receipt = repository.register_candidate(
        candidate,
        operations_receipt.authority.actor_id,
    )
    assessed_at = REVIEWED_AT + timedelta(hours=1)
    api = M8CommissioningApiService(
        M8AdapterReadinessService(repository, operations, SHA_D),
        operations,
        clock=lambda: assessed_at,
    )

    assessment = api.readiness(
        _principal(operations_receipt.authority.actor_id),
        candidate.candidate_authority_id,
    )
    assert assessment.assessed_at == assessed_at
    assert assessment.readiness == M8CommissioningReadiness.BLOCKED
    assert assessment.production_activation_permitted is False
    assert assessment.life_safety_action_permitted is False
    assert repository.get_candidate(candidate.candidate_authority_id) == candidate_receipt
    assert repository.list_candidate_evidence(candidate.candidate_authority_id, 1) == ()

    with pytest.raises(M8ApiServiceError) as denied:
        api.readiness(
            _principal(safety_receipt.authority.actor_id),
            candidate.candidate_authority_id,
        )
    assert denied.value.reason_code == M8ApiServiceFailureCode.FORBIDDEN


def test_readiness_api_fails_closed_on_actor_race_and_invalid_server_clock(
    repositories: tuple[
        Path,
        SQLiteM8OperationsRepository,
        SQLiteM8AdapterCommissioningRepository,
        M8ActorAuthorityCommitReceiptV1,
        M8ActorAuthorityCommitReceiptV1,
    ],
) -> None:
    _database, operations, repository, operations_receipt, _safety_receipt = repositories
    candidate = _candidate()
    repository.register_candidate(candidate, operations_receipt.authority.actor_id)

    def racing_clock() -> datetime:
        operations.publish_actor_authority(_actor(M8ActorRole.OPERATIONS, revision=2), 1)
        return REVIEWED_AT + timedelta(hours=1)

    racing_api = M8CommissioningApiService(
        M8AdapterReadinessService(repository, operations, SHA_D),
        operations,
        clock=racing_clock,
    )
    with pytest.raises(M8ApiServiceError) as conflict:
        racing_api.readiness(
            _principal(operations_receipt.authority.actor_id),
            candidate.candidate_authority_id,
        )
    assert conflict.value.reason_code == M8ApiServiceFailureCode.CONCURRENT_MODIFICATION

    invalid_clock_api = M8CommissioningApiService(
        M8AdapterReadinessService(repository, operations, SHA_D),
        operations,
        clock=lambda: REVIEWED_AT.replace(tzinfo=None),
    )
    with pytest.raises(M8ApiServiceError) as invalid_clock:
        invalid_clock_api.readiness(
            _principal(operations_receipt.authority.actor_id),
            candidate.candidate_authority_id,
        )
    assert invalid_clock.value.reason_code == M8ApiServiceFailureCode.INTERNAL_FAILURE
