from __future__ import annotations

from datetime import timedelta

import pytest

from labcourt.application.m8_feishu_webhook_authority import (
    commit_m8_feishu_webhook_activation,
    get_m8_feishu_webhook_activation_status,
    revoke_m8_feishu_webhook_activation,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_inbound_activation import (
    M8FeishuInboundRevocationReason,
    m8_feishu_inbound_runtime_config_bytes,
)
from labcourt.exceptions import ContractViolation, EvidenceMissing
from tests.integration.test_m8_sqlite_feishu_activation_repository import (
    BASE_TIME,
    BUSY_TIMEOUT_MS,
    SHA_A,
    SHA_B,
    SHA_D,
    SHA_E,
)
from tests.integration.test_m8_sqlite_feishu_inbound_activation_repository import (
    _config,
    _Harness,
)
from tests.integration.test_m8_sqlite_feishu_inbound_activation_repository import (
    harness as inbound_harness,  # noqa: F401
)


def _documents(authority: _Harness) -> tuple[bytes, bytes]:
    config = _config()
    intent = authority.intent(
        config,
        assessed_at=BASE_TIME + timedelta(hours=1),
        requested_at=BASE_TIME + timedelta(hours=2),
    )
    intent_document = canonical_json(intent.model_dump(mode="json")).encode("utf-8")
    return intent_document, m8_feishu_inbound_runtime_config_bytes(config)


def test_authority_boundary_commits_recomputes_and_revokes_current_activation(
    inbound_harness: _Harness,  # noqa: F811
) -> None:
    intent_document, config_document = _documents(inbound_harness)
    activation = commit_m8_feishu_webhook_activation(
        database_path=inbound_harness.database,
        activation_intent_document=intent_document,
        runtime_config_document=config_document,
        runtime_config_storage_manifest_id=SHA_B,
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=lambda: BASE_TIME + timedelta(hours=3),
    )
    assert activation.activation_state == "SANDBOX_INBOUND_ACTIVE"
    assert activation.listener_autostart_permitted is False

    active = get_m8_feishu_webhook_activation_status(
        database_path=inbound_harness.database,
        candidate_authority_id=(
            activation.runtime_config.profile.outbound_profile.candidate.candidate_authority_id
        ),
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=lambda: BASE_TIME + timedelta(hours=4),
    )
    assert active.sandbox_external_ingress_permitted is True

    revocation = revoke_m8_feishu_webhook_activation(
        database_path=inbound_harness.database,
        activation_commit_id=activation.activation_commit_id,
        revoker_actor_id=inbound_harness.safety_receipt.authority.actor_id,
        reason=M8FeishuInboundRevocationReason.MANUAL_SAFETY_STOP,
        reason_ref="sandbox-inbound-safety-stop-authority-test",
        revoked_at=BASE_TIME + timedelta(hours=5),
        revocation_manifest_id=SHA_D,
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
    )
    assert revocation.activation_state == "REVOKED"
    assert revocation.automatic_reactivation_permitted is False
    assert (
        revoke_m8_feishu_webhook_activation(
            database_path=inbound_harness.database,
            activation_commit_id=activation.activation_commit_id,
            revoker_actor_id=inbound_harness.safety_receipt.authority.actor_id,
            reason=M8FeishuInboundRevocationReason.MANUAL_SAFETY_STOP,
            reason_ref="sandbox-inbound-safety-stop-authority-test",
            revoked_at=BASE_TIME + timedelta(hours=5),
            revocation_manifest_id=SHA_D,
            repository_manifest_id=SHA_A,
            assessment_manifest_id=SHA_E,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
        )
        == revocation
    )

    revoked = get_m8_feishu_webhook_activation_status(
        database_path=inbound_harness.database,
        candidate_authority_id=(
            activation.runtime_config.profile.outbound_profile.candidate.candidate_authority_id
        ),
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=lambda: BASE_TIME + timedelta(hours=6),
    )
    assert revoked.activation_state == "REVOKED"
    assert revoked.business_event_ingress_permitted is False


def test_authority_boundary_rejects_noncanonical_runtime_config_before_commit(
    inbound_harness: _Harness,  # noqa: F811
) -> None:
    intent_document, config_document = _documents(inbound_harness)
    noncanonical = b"\n" + config_document

    with pytest.raises(ContractViolation, match="exact canonical bytes"):
        commit_m8_feishu_webhook_activation(
            database_path=inbound_harness.database,
            activation_intent_document=intent_document,
            runtime_config_document=noncanonical,
            runtime_config_storage_manifest_id=SHA_B,
            repository_manifest_id=SHA_A,
            assessment_manifest_id=SHA_E,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            clock=lambda: BASE_TIME + timedelta(hours=3),
        )

    with pytest.raises(EvidenceMissing, match="status was not found"):
        get_m8_feishu_webhook_activation_status(
            database_path=inbound_harness.database,
            candidate_authority_id=(
                _config().profile.outbound_profile.candidate.candidate_authority_id
            ),
            repository_manifest_id=SHA_A,
            assessment_manifest_id=SHA_E,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            clock=lambda: BASE_TIME + timedelta(hours=4),
        )
