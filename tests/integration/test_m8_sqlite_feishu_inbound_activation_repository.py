from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m8_feishu_inbound_activation_repository import (
    SQLiteM8FeishuInboundActivationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_adapter_commissioning import (
    M8AdapterActivationIntentV1,
    M8CommissioningEvidenceKind,
    M8CommissioningEvidenceOutcome,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundWebhookProfileV1
from labcourt.contracts.m8_feishu_inbound_activation import (
    M8FeishuInboundRevocationReason,
    M8FeishuInboundSandboxRuntimeConfigV1,
    m8_feishu_inbound_runtime_config_bytes,
)
from labcourt.exceptions import ConcurrentModification
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService
from tests.integration.test_m8_sqlite_feishu_activation_repository import (
    BASE_TIME,
    BUSY_TIMEOUT_MS,
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    SHA_E,
    _actor,
    _candidate,
    _evidence,
    _profile,
)


def _inbound_profile() -> M8FeishuInboundWebhookProfileV1:
    return M8FeishuInboundWebhookProfileV1(
        outbound_profile=_profile(),
        request_url_reference_id="feishu-public-callback-sandbox-01",
        encrypt_key_reference_id="secret-feishu-encrypt-key-01",
        encrypt_key_sha256=SHA_A,
        verification_token_reference_id="secret-feishu-verification-token-01",
        verification_token_sha256=SHA_B,
        profile_manifest_id=SHA_C,
    )


def _config(*, revision: int = 1) -> M8FeishuInboundSandboxRuntimeConfigV1:
    return M8FeishuInboundSandboxRuntimeConfigV1(
        profile=_inbound_profile(),
        runtime_config_ref=f"m8-feishu-inbound-runtime-config-{revision:02d}",
        public_callback_url_reference_id="feishu-public-callback-sandbox-01",
        public_callback_url_sha256=SHA_D if revision == 1 else SHA_E,
        tls_configuration_reference_id=f"feishu-public-tls-sandbox-{revision:02d}",
        tls_configuration_sha256=SHA_E if revision == 1 else SHA_D,
        application_bind_port=9443,
        runtime_config_manifest_id=SHA_A if revision == 1 else SHA_B,
    )


@dataclass(frozen=True)
class _Harness:
    database: Path
    operations: SQLiteM8OperationsRepository
    activations: SQLiteM8FeishuInboundActivationRepository
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
        config: M8FeishuInboundSandboxRuntimeConfigV1,
        *,
        assessed_at: datetime,
        requested_at: datetime,
    ) -> M8AdapterActivationIntentV1:
        raw = m8_feishu_inbound_runtime_config_bytes(config)
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
            credential_reference_id=(
                config.profile.outbound_profile.credential_bundle_reference_id
            ),
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
    activations = SQLiteM8FeishuInboundActivationRepository(
        database,
        BUSY_TIMEOUT_MS,
        SHA_A,
        SHA_E,
    )
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
    raw = m8_feishu_inbound_runtime_config_bytes(config)
    receipt = harness.activations.commit_inbound_activation(
        intent,
        config,
        raw,
        SHA_B,
        BASE_TIME + timedelta(hours=hour + 2),
        BASE_TIME + timedelta(hours=hour + 3),
    )
    return config, intent, raw, receipt


def test_inbound_activation_is_restart_safe_revocable_and_reactivatable(
    harness: _Harness,
) -> None:
    config, intent, raw, first = _activate(harness)
    assert first.activation_revision == 1
    assert (
        harness.activations.commit_inbound_activation(
            intent,
            config,
            raw,
            SHA_B,
            BASE_TIME + timedelta(hours=3),
            BASE_TIME + timedelta(hours=4),
        )
        == first
    )
    assert harness.activations.get_inbound_activation(first.activation_commit_id) == first
    assert harness.activations.read_inbound_runtime_config(config.runtime_config_ref) == raw
    assert harness.activations.get_current_inbound_status(
        _candidate().candidate_authority_id,
        BASE_TIME + timedelta(hours=5),
    ).sandbox_external_ingress_permitted

    reopened = SQLiteM8FeishuInboundActivationRepository(
        harness.database,
        BUSY_TIMEOUT_MS,
        SHA_A,
        SHA_E,
    )
    assert reopened.get_inbound_activation(first.activation_commit_id) == first
    revocation = reopened.revoke_inbound_activation(
        first.activation_commit_id,
        harness.safety_receipt.authority.actor_id,
        M8FeishuInboundRevocationReason.MANUAL_SAFETY_STOP,
        "sandbox-inbound-safety-stop-01",
        BASE_TIME + timedelta(hours=6),
        SHA_D,
    )
    assert (
        reopened.revoke_inbound_activation(
            first.activation_commit_id,
            harness.safety_receipt.authority.actor_id,
            M8FeishuInboundRevocationReason.MANUAL_SAFETY_STOP,
            "sandbox-inbound-safety-stop-01",
            BASE_TIME + timedelta(hours=6),
            SHA_D,
        )
        == revocation
    )
    assert (
        reopened.get_current_inbound_status(
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

    with sqlite3.connect(harness.database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m8_feishu_inbound_sandbox_activations SET activation_revision = 9"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m8_feishu_inbound_sandbox_activation_revocations")


def test_current_actor_or_commissioning_change_invalidates_ingress(
    harness: _Harness,
) -> None:
    _config_one, _intent_one, _raw_one, activation = _activate(harness)
    harness.operations.publish_actor_authority(
        _actor(M8ActorRole.SAFETY_OFFICER, revision=2, active=False),
        1,
    )
    actor_invalidated = harness.activations.get_current_inbound_status(
        _candidate().candidate_authority_id,
        BASE_TIME + timedelta(hours=5),
    )
    assert actor_invalidated.activation_receipt == activation
    assert actor_invalidated.activation_state == "INVALIDATED"
    assert actor_invalidated.human_authority_current is False
    assert actor_invalidated.sandbox_external_ingress_permitted is False

    harness.operations.publish_actor_authority(
        _actor(M8ActorRole.SAFETY_OFFICER, revision=3, active=True),
        2,
    )
    failed, failed_raw = _evidence(
        M8CommissioningEvidenceKind.SECURITY_REVIEW,
        harness.operations_receipt,
        outcome=M8CommissioningEvidenceOutcome.FAILED,
        reviewed_at=BASE_TIME + timedelta(hours=6),
        suffix="-later",
    )
    harness.activations.commit_evidence(failed, failed_raw, SHA_B)
    commissioning_invalidated = harness.activations.get_current_inbound_status(
        _candidate().candidate_authority_id,
        BASE_TIME + timedelta(hours=7),
    )
    assert commissioning_invalidated.activation_state == "INVALIDATED"
    assert commissioning_invalidated.commissioning_current is False


def test_commit_rechecks_canonical_runtime_bytes_and_current_humans(
    harness: _Harness,
) -> None:
    config = _config()
    intent = harness.intent(
        config,
        assessed_at=BASE_TIME + timedelta(hours=1),
        requested_at=BASE_TIME + timedelta(hours=2),
    )
    with pytest.raises(ConcurrentModification, match="gate is not current"):
        harness.activations.commit_inbound_activation(
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
        harness.activations.commit_inbound_activation(
            intent,
            config,
            m8_feishu_inbound_runtime_config_bytes(config),
            SHA_B,
            BASE_TIME + timedelta(hours=3),
            BASE_TIME + timedelta(hours=4),
        )


def test_repository_rejects_incomplete_inbound_activation_layout(
    harness: _Harness,
) -> None:
    with sqlite3.connect(harness.database) as connection:
        connection.execute("DROP TRIGGER m8_feishu_inbound_sandbox_activations_no_update")
    with pytest.raises(RepositoryIntegrityError, match="layout is incomplete"):
        SQLiteM8FeishuInboundActivationRepository(
            harness.database,
            BUSY_TIMEOUT_MS,
            SHA_A,
            SHA_E,
        )
