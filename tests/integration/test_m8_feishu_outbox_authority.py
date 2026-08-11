from __future__ import annotations

from datetime import timedelta

import pytest

from labcourt.application.m8_feishu_outbox_authority import (
    commit_m8_feishu_outbox_activation,
    get_m8_feishu_outbox_activation_status,
    revoke_m8_feishu_outbox_activation,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_activation import (
    M8FeishuSandboxRevocationReason,
    m8_feishu_runtime_config_bytes,
)
from labcourt.exceptions import ContractViolation, EvidenceMissing
from tests.integration.test_m8_sqlite_feishu_activation_repository import (
    BASE_TIME,
    BUSY_TIMEOUT_MS,
    SHA_A,
    SHA_B,
    SHA_D,
    SHA_E,
    _config,
    _Harness,
)
from tests.integration.test_m8_sqlite_feishu_activation_repository import (
    harness as outbox_harness,  # noqa: F401
)


def _documents(authority: _Harness) -> tuple[bytes, bytes]:
    config = _config()
    intent = authority.intent(
        config,
        assessed_at=BASE_TIME + timedelta(hours=1),
        requested_at=BASE_TIME + timedelta(hours=2),
    )
    intent_document = canonical_json(intent.model_dump(mode="json")).encode("utf-8")
    return intent_document, m8_feishu_runtime_config_bytes(config)


def test_outbox_authority_commits_recomputes_and_exactly_revokes(
    outbox_harness: _Harness,  # noqa: F811
) -> None:
    intent_document, config_document = _documents(outbox_harness)
    activation = commit_m8_feishu_outbox_activation(
        database_path=outbox_harness.database,
        activation_intent_document=intent_document,
        runtime_config_document=config_document,
        runtime_config_storage_manifest_id=SHA_B,
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=lambda: BASE_TIME + timedelta(hours=3),
    )
    assert activation.activation_state == "SANDBOX_ACTIVE"
    assert activation.automatic_activation_permitted is False

    candidate_id = activation.runtime_config.profile.candidate.candidate_authority_id
    active = get_m8_feishu_outbox_activation_status(
        database_path=outbox_harness.database,
        candidate_authority_id=candidate_id,
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=lambda: BASE_TIME + timedelta(hours=4),
    )
    assert active.sandbox_external_call_permitted is True
    assert active.recipient_authority_current is True

    arguments = {
        "database_path": outbox_harness.database,
        "activation_commit_id": activation.activation_commit_id,
        "revoker_actor_id": outbox_harness.safety_receipt.authority.actor_id,
        "reason": M8FeishuSandboxRevocationReason.MANUAL_SAFETY_STOP,
        "reason_ref": "sandbox-outbox-safety-stop-authority-test",
        "revoked_at": BASE_TIME + timedelta(hours=5),
        "revocation_manifest_id": SHA_D,
        "repository_manifest_id": SHA_A,
        "assessment_manifest_id": SHA_E,
        "busy_timeout_ms": BUSY_TIMEOUT_MS,
    }
    revocation = revoke_m8_feishu_outbox_activation(**arguments)
    assert revoke_m8_feishu_outbox_activation(**arguments) == revocation
    assert revocation.activation_state == "REVOKED"

    revoked = get_m8_feishu_outbox_activation_status(
        database_path=outbox_harness.database,
        candidate_authority_id=candidate_id,
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=lambda: BASE_TIME + timedelta(hours=6),
    )
    assert revoked.sandbox_external_call_permitted is False


def test_outbox_authority_rejects_noncanonical_config_before_commit(
    outbox_harness: _Harness,  # noqa: F811
) -> None:
    intent_document, config_document = _documents(outbox_harness)

    with pytest.raises(ContractViolation, match="exact canonical bytes"):
        commit_m8_feishu_outbox_activation(
            database_path=outbox_harness.database,
            activation_intent_document=intent_document,
            runtime_config_document=b"\n" + config_document,
            runtime_config_storage_manifest_id=SHA_B,
            repository_manifest_id=SHA_A,
            assessment_manifest_id=SHA_E,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            clock=lambda: BASE_TIME + timedelta(hours=3),
        )

    with pytest.raises(EvidenceMissing, match="status was not found"):
        get_m8_feishu_outbox_activation_status(
            database_path=outbox_harness.database,
            candidate_authority_id=_config().profile.candidate.candidate_authority_id,
            repository_manifest_id=SHA_A,
            assessment_manifest_id=SHA_E,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            clock=lambda: BASE_TIME + timedelta(hours=4),
        )
