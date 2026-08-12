from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m8_feishu_activation_repository import (
    SQLiteM8FeishuActivationRepository,
)
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
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
    M8AdapterActivationIntentV1,
    M8CommissioningEvidenceAuthorityV1,
    M8CommissioningEvidenceKind,
    M8CommissioningEvidenceOutcome,
    M8ExternalIdempotencyKey,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterKind,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_activation import (
    M8FeishuSandboxRevocationReason,
    M8FeishuSandboxRuntimeConfigV1,
    m8_feishu_runtime_config_bytes,
)
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationChannelKind,
    M8NotificationTargetAuthorityV1,
)
from labcourt.exceptions import ConcurrentModification
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BASE_TIME = datetime(2026, 8, 11, 8, 0, tzinfo=UTC)
BUSY_TIMEOUT_MS = 5_000


def _actor(
    role: M8ActorRole,
    *,
    revision: int = 1,
    active: bool = True,
) -> M8ActorAuthorityV1:
    scope_kind = (
        M8ActorScopeKind.SELF_ONLY if role == M8ActorRole.STUDENT else M8ActorScopeKind.CAMPUS_WIDE
    )
    return M8ActorAuthorityV1(
        actor_id=f"{role.value.lower().replace('_', '-')}-feishu-activation-01",
        role=role,
        scope_kind=scope_kind,
        scope_location_ids=(),
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=revision,
        active=active,
        manifest_id=SHA_B,
    )


def _candidate() -> M8ProductionAdapterCandidateAuthorityV1:
    return M8ProductionAdapterCandidateAuthorityV1(
        adapter_id="m8-feishu-tenant-app",
        adapter_revision="im-v1-2026-04-10",
        adapter_kind=M8ProductionAdapterKind.EXTERNAL_NOTIFICATION,
        provider_id="feishu-open-platform",
        product_revision="tenant-custom-app-im-v1",
        campus_id="campus-main",
        scope_kind=M8ActorScopeKind.CAMPUS_WIDE,
        scope_location_ids=(),
        declared_license_id="feishu-open-platform-terms-review",
        request_timeout_ms=5_000,
        idempotency_key=M8ExternalIdempotencyKey.NOTIFICATION_ID,
        network_required=True,
        offline_fallback_adapter_id="m8-local-message-fake",
        offline_fallback_revision="v1",
        adapter_manifest_id=SHA_C,
        offline_fallback_manifest_id=SHA_D,
    )


def _target(*, revision: int = 1, active: bool = True) -> M8NotificationTargetAuthorityV1:
    return M8NotificationTargetAuthorityV1(
        actor_id="student-feishu-activation-01",
        identity_provider_id="campus-idp",
        external_subject_binding_sha256=SHA_E,
        channel=M8NotificationChannelKind.FEISHU,
        authority_revision=revision,
        active=active,
        inbound_response_supported=True,
        manifest_id=SHA_C,
    )


def _profile() -> M8FeishuAdapterProfileV1:
    return M8FeishuAdapterProfileV1(
        candidate=_candidate(),
        credential_bundle_reference_id="secret-feishu-sandbox-campus-main",
        app_id_sha256=SHA_B,
        profile_manifest_id=SHA_C,
    )


def _config(*, revision: int = 1) -> M8FeishuSandboxRuntimeConfigV1:
    profile = _profile()
    binding = M8FeishuRecipientBindingAuthorityV1(
        target=_target(),
        profile_id=profile.profile_id,
        receive_id_reference="feishu-open-id-student-sandbox-01",
        receive_id_sha256=SHA_E,
        mapping_revision=1,
        active=True,
        mapping_manifest_id=SHA_D,
    )
    return M8FeishuSandboxRuntimeConfigV1(
        profile=profile,
        recipient_allowlist=(binding,),
        runtime_config_ref=f"m8-feishu-sandbox-runtime-config-{revision:02d}",
        runtime_config_manifest_id=SHA_E if revision == 1 else SHA_D,
    )


def _evidence(
    kind: M8CommissioningEvidenceKind,
    reviewer: M8ActorAuthorityCommitReceiptV1,
    *,
    outcome: M8CommissioningEvidenceOutcome = M8CommissioningEvidenceOutcome.PASSED,
    reviewed_at: datetime = BASE_TIME,
    suffix: str = "",
) -> tuple[M8CommissioningEvidenceAuthorityV1, bytes]:
    raw = f"feishu-{kind.value}-{outcome.value}-{suffix}".encode()
    return (
        M8CommissioningEvidenceAuthorityV1(
            candidate=_candidate(),
            evidence_kind=kind,
            outcome=outcome,
            artifact_ref=(
                f"feishu-{kind.value.lower().replace('_', '-')}-{outcome.value.lower()}{suffix}"
            ),
            artifact_sha256=hashlib.sha256(raw).hexdigest(),
            artifact_size_bytes=len(raw),
            reviewer_actor_receipt=reviewer,
            reviewed_at=reviewed_at,
            valid_through=reviewed_at + timedelta(days=30),
            simulated=kind == M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
            evidence_manifest_id=SHA_C,
        ),
        raw,
    )


@dataclass(frozen=True)
class _Harness:
    database: Path
    operations: SQLiteM8OperationsRepository
    notifications: SQLiteM8NotificationRepository
    activations: SQLiteM8FeishuActivationRepository
    operations_receipt: M8ActorAuthorityCommitReceiptV1
    safety_receipt: M8ActorAuthorityCommitReceiptV1

    def readiness(self, assessed_at: datetime):
        return M8AdapterReadinessService(
            self.activations,
            self.operations,
            SHA_E,
        ).assess(
            _candidate().candidate_authority_id,
            self.operations_receipt.authority.actor_id,
            assessed_at,
        )

    def intent(
        self,
        config: M8FeishuSandboxRuntimeConfigV1,
        *,
        assessed_at: datetime,
        requested_at: datetime,
    ) -> M8AdapterActivationIntentV1:
        raw = m8_feishu_runtime_config_bytes(config)
        return M8AdapterActivationIntentV1(
            readiness_assessment=self.readiness(assessed_at),
            operations_actor_receipt=self.operations.get_current_actor_authority(
                self.operations_receipt.authority.actor_id
            ),
            safety_actor_receipt=self.operations.get_current_actor_authority(
                self.safety_receipt.authority.actor_id
            ),
            runtime_config_ref=config.runtime_config_ref,
            runtime_config_sha256=hashlib.sha256(raw).hexdigest(),
            runtime_config_size_bytes=len(raw),
            credential_reference_id=config.profile.credential_bundle_reference_id,
            requested_at=requested_at,
            activation_manifest_id=SHA_D,
        )


@pytest.fixture
def harness(tmp_path: Path) -> _Harness:
    database = tmp_path / "labcourt.sqlite3"
    operations = SQLiteM8OperationsRepository.initialize(database, BUSY_TIMEOUT_MS, SHA_A)
    operations_receipt = operations.publish_actor_authority(
        _actor(M8ActorRole.OPERATIONS),
        None,
    )
    safety_receipt = operations.publish_actor_authority(
        _actor(M8ActorRole.SAFETY_OFFICER),
        None,
    )
    operations.publish_actor_authority(_actor(M8ActorRole.STUDENT), None)
    notifications = SQLiteM8NotificationRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    notifications.publish_target_authority(_target(), None)
    activations = SQLiteM8FeishuActivationRepository(database, BUSY_TIMEOUT_MS, SHA_A, SHA_E)
    activations.register_candidate(_candidate(), operations_receipt.authority.actor_id)
    operations_review = {
        M8CommissioningEvidenceKind.LICENSE_REVIEW,
        M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
        M8CommissioningEvidenceKind.SECURITY_REVIEW,
    }
    for kind in M8CommissioningEvidenceKind:
        reviewer = operations_receipt if kind in operations_review else safety_receipt
        evidence, raw = _evidence(kind, reviewer)
        activations.commit_evidence(evidence, raw, SHA_B)
    return _Harness(
        database,
        operations,
        notifications,
        activations,
        operations_receipt,
        safety_receipt,
    )


def _activate(
    harness: _Harness,
    *,
    config_revision: int = 1,
    hour: int = 1,
):
    config = _config(revision=config_revision)
    intent = harness.intent(
        config,
        assessed_at=BASE_TIME + timedelta(hours=hour),
        requested_at=BASE_TIME + timedelta(hours=hour + 1),
    )
    raw = m8_feishu_runtime_config_bytes(config)
    receipt = harness.activations.commit_activation(
        intent,
        config,
        raw,
        SHA_B,
        BASE_TIME + timedelta(hours=hour + 2),
        BASE_TIME + timedelta(hours=hour + 3),
    )
    return config, intent, raw, receipt


def test_activation_is_restart_safe_idempotent_revocable_and_reactivatable(
    harness: _Harness,
) -> None:
    config, intent, raw, first = _activate(harness)
    assert first.activation_revision == 1
    assert first.prior_activation_commit_id is None
    assert (
        harness.activations.commit_activation(
            intent,
            config,
            raw,
            SHA_B,
            BASE_TIME + timedelta(hours=3),
            BASE_TIME + timedelta(hours=4),
        )
        == first
    )
    assert harness.activations.get_activation(first.activation_commit_id) == first
    assert harness.activations.read_runtime_config(config.runtime_config_ref) == raw
    assert (
        harness.activations.get_current_status(
            _candidate().candidate_authority_id,
            BASE_TIME + timedelta(hours=5),
        ).sandbox_external_call_permitted
        is True
    )

    reopened = SQLiteM8FeishuActivationRepository(
        harness.database,
        BUSY_TIMEOUT_MS,
        SHA_A,
        SHA_E,
    )
    assert reopened.get_activation(first.activation_commit_id) == first

    revocation = reopened.revoke_activation(
        first.activation_commit_id,
        harness.safety_receipt.authority.actor_id,
        M8FeishuSandboxRevocationReason.MANUAL_SAFETY_STOP,
        "sandbox-safety-stop-01",
        BASE_TIME + timedelta(hours=6),
        SHA_D,
    )
    assert (
        reopened.revoke_activation(
            first.activation_commit_id,
            harness.safety_receipt.authority.actor_id,
            M8FeishuSandboxRevocationReason.MANUAL_SAFETY_STOP,
            "sandbox-safety-stop-01",
            BASE_TIME + timedelta(hours=6),
            SHA_D,
        )
        == revocation
    )
    assert (
        reopened.get_current_status(
            _candidate().candidate_authority_id,
            BASE_TIME + timedelta(hours=7),
        ).activation_state
        == "REVOKED"
    )

    _config_two, _intent_two, _raw_two, second = _activate(
        harness,
        config_revision=2,
        hour=8,
    )
    assert second.activation_revision == 2
    assert second.prior_activation_commit_id == first.activation_commit_id
    assert (
        reopened.get_current_status(
            _candidate().candidate_authority_id,
            BASE_TIME + timedelta(hours=12),
        ).sandbox_external_call_permitted
        is True
    )

    with sqlite3.connect(harness.database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE m8_feishu_sandbox_activations SET activation_revision = 9")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m8_feishu_sandbox_activation_revocations")


def test_current_actor_or_recipient_change_invalidates_external_call(
    harness: _Harness,
) -> None:
    _config_one, _intent_one, _raw_one, activation = _activate(harness)
    harness.operations.publish_actor_authority(
        _actor(M8ActorRole.SAFETY_OFFICER, revision=2, active=False),
        1,
    )
    actor_invalidated = harness.activations.get_current_status(
        _candidate().candidate_authority_id,
        BASE_TIME + timedelta(hours=5),
    )
    assert actor_invalidated.activation_state == "INVALIDATED"
    assert actor_invalidated.human_authority_current is False
    assert actor_invalidated.sandbox_external_call_permitted is False

    harness.operations.publish_actor_authority(
        _actor(M8ActorRole.SAFETY_OFFICER, revision=3, active=True),
        2,
    )
    harness.notifications.publish_target_authority(
        _target(revision=2, active=False),
        1,
    )
    target_invalidated = harness.activations.get_current_status(
        _candidate().candidate_authority_id,
        BASE_TIME + timedelta(hours=6),
    )
    assert target_invalidated.activation_receipt == activation
    assert target_invalidated.recipient_authority_current is False
    assert target_invalidated.sandbox_external_call_permitted is False


def test_later_failed_commissioning_evidence_invalidates_without_manual_revocation(
    harness: _Harness,
) -> None:
    _config_one, _intent_one, _raw_one, _activation = _activate(harness)
    failed, raw = _evidence(
        M8CommissioningEvidenceKind.SECURITY_REVIEW,
        harness.operations_receipt,
        outcome=M8CommissioningEvidenceOutcome.FAILED,
        reviewed_at=BASE_TIME + timedelta(hours=5),
        suffix="-later",
    )
    harness.activations.commit_evidence(failed, raw, SHA_B)
    status = harness.activations.get_current_status(
        _candidate().candidate_authority_id,
        BASE_TIME + timedelta(hours=6),
    )
    assert status.activation_state == "INVALIDATED"
    assert status.commissioning_current is False
    assert status.sandbox_external_call_permitted is False


def test_commit_rechecks_human_authority_and_canonical_runtime_bytes(
    harness: _Harness,
) -> None:
    config = _config()
    intent = harness.intent(
        config,
        assessed_at=BASE_TIME + timedelta(hours=1),
        requested_at=BASE_TIME + timedelta(hours=2),
    )
    with pytest.raises(ConcurrentModification, match="gate is not current"):
        harness.activations.commit_activation(
            intent,
            config,
            b"{}",
            SHA_B,
            BASE_TIME + timedelta(hours=3),
            BASE_TIME + timedelta(hours=4),
        )

    harness.operations.publish_actor_authority(
        _actor(M8ActorRole.SAFETY_OFFICER, revision=2, active=False),
        1,
    )
    with pytest.raises(ConcurrentModification, match="gate is not current"):
        harness.activations.commit_activation(
            intent,
            config,
            m8_feishu_runtime_config_bytes(config),
            SHA_B,
            BASE_TIME + timedelta(hours=3),
            BASE_TIME + timedelta(hours=4),
        )


def test_repository_rejects_incomplete_activation_layout(harness: _Harness) -> None:
    with sqlite3.connect(harness.database) as connection:
        connection.execute("DROP TRIGGER m8_feishu_sandbox_activations_no_update")
    with pytest.raises(RepositoryIntegrityError, match="layout is incomplete"):
        SQLiteM8FeishuActivationRepository(
            harness.database,
            BUSY_TIMEOUT_MS,
            SHA_A,
            SHA_E,
        )
