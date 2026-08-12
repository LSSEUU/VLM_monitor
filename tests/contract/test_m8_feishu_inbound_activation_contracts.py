from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_adapter_commissioning import M8AdapterActivationIntentV1
from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundWebhookProfileV1
from labcourt.contracts.m8_feishu_inbound_activation import (
    M8FeishuInboundRevocationReason,
    M8FeishuInboundSandboxActivationCommitReceiptV1,
    M8FeishuInboundSandboxActivationRevocationCommitReceiptV1,
    M8FeishuInboundSandboxActivationStatusV1,
    M8FeishuInboundSandboxRuntimeConfigV1,
    m8_feishu_inbound_runtime_config_bytes,
)
from tests.contract.test_m8_feishu_activation_contracts import (
    BASE_TIME,
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    SHA_E,
    _actor_receipt,
    _assessment,
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


def _config() -> M8FeishuInboundSandboxRuntimeConfigV1:
    return M8FeishuInboundSandboxRuntimeConfigV1(
        profile=_inbound_profile(),
        runtime_config_ref="m8-feishu-inbound-runtime-config-01",
        public_callback_url_reference_id="feishu-public-callback-sandbox-01",
        public_callback_url_sha256=SHA_D,
        tls_configuration_reference_id="feishu-public-tls-sandbox-01",
        tls_configuration_sha256=SHA_E,
        application_bind_port=9443,
        runtime_config_manifest_id=SHA_A,
    )


def _intent(config: M8FeishuInboundSandboxRuntimeConfigV1) -> M8AdapterActivationIntentV1:
    raw = m8_feishu_inbound_runtime_config_bytes(config)
    return M8AdapterActivationIntentV1(
        readiness_assessment=_assessment(assessed_at=BASE_TIME + timedelta(hours=1)),
        operations_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        safety_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        runtime_config_ref=config.runtime_config_ref,
        runtime_config_sha256=hashlib.sha256(raw).hexdigest(),
        runtime_config_size_bytes=len(raw),
        credential_reference_id=(
            config.profile.outbound_profile.credential_bundle_reference_id
        ),
        requested_at=BASE_TIME + timedelta(hours=2),
        activation_manifest_id=SHA_D,
    )


def _receipt() -> M8FeishuInboundSandboxActivationCommitReceiptV1:
    config = _config()
    return M8FeishuInboundSandboxActivationCommitReceiptV1(
        activation_intent=_intent(config),
        runtime_config=config,
        current_readiness_assessment=_assessment(
            assessed_at=BASE_TIME + timedelta(hours=3)
        ),
        current_operations_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        current_safety_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        activation_revision=1,
        committed_at=BASE_TIME + timedelta(hours=4),
        runtime_config_storage_manifest_id=SHA_B,
        repository_manifest_id=SHA_C,
    )


def _revocation() -> M8FeishuInboundSandboxActivationRevocationCommitReceiptV1:
    return M8FeishuInboundSandboxActivationRevocationCommitReceiptV1(
        activation_receipt=_receipt(),
        revoked_by_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        reason=M8FeishuInboundRevocationReason.MANUAL_SAFETY_STOP,
        reason_ref="feishu-inbound-stop-drill-01",
        revoked_at=BASE_TIME + timedelta(hours=5),
        revocation_manifest_id=SHA_E,
        repository_manifest_id=SHA_C,
    )


def _status(
    *,
    revocation: M8FeishuInboundSandboxActivationRevocationCommitReceiptV1 | None = None,
) -> M8FeishuInboundSandboxActivationStatusV1:
    assessed_at = BASE_TIME + timedelta(hours=6 if revocation is not None else 5)
    return M8FeishuInboundSandboxActivationStatusV1(
        activation_receipt=_receipt(),
        revocation_receipt=revocation,
        current_operations_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        current_safety_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        current_readiness_assessment=_assessment(assessed_at=assessed_at),
        assessed_at=assessed_at,
        repository_manifest_id=SHA_C,
    )


def test_runtime_config_is_secret_free_and_not_ingress_authority() -> None:
    config = _config()
    raw = m8_feishu_inbound_runtime_config_bytes(config)

    assert config.environment == "SANDBOX"
    assert config.public_transport_kind == "HTTPS_JSON"
    assert config.application_bind_host == "127.0.0.1"
    assert config.tls_termination_kind == "EXTERNAL_REVERSE_PROXY"
    assert config.public_ca_certificate_required is True
    assert config.encrypted_envelope_required is True
    assert config.business_event_signature_required is True
    assert config.external_ingress_permitted is False
    assert config.listener_autostart_permitted is False
    assert config.secret_material_embedded is False
    assert config.clear_public_url_embedded is False
    assert b'"encrypt_key":' not in raw
    assert b'"verification_token":' not in raw
    assert b'"public_callback_url":' not in raw


def test_runtime_config_rejects_callback_reference_graft() -> None:
    with pytest.raises(ValidationError, match="URL reference conflicts"):
        _config().model_copy(
            update={"public_callback_url_reference_id": "feishu-public-callback-other"}
        )


def test_activation_only_authorizes_sandbox_ingress_without_business_actions() -> None:
    receipt = _receipt()

    assert receipt.activation_state == "SANDBOX_INBOUND_ACTIVE"
    assert receipt.sandbox_external_ingress_permitted is True
    assert receipt.production_external_ingress_permitted is False
    assert receipt.url_challenge_permitted is True
    assert receipt.business_event_ingress_permitted is True
    assert receipt.listener_autostart_permitted is False
    assert receipt.notification_reply_commit_permitted is False
    assert receipt.case_transition_permitted is False
    assert receipt.direct_disciplinary_action_permitted is False
    assert receipt.face_recognition_permitted is False
    assert receipt.cross_camera_reidentification_permitted is False


def test_activation_rejects_changed_config_credential_or_revision_chain() -> None:
    receipt = _receipt()

    with pytest.raises(ValidationError, match="runtime config bytes conflict"):
        receipt.model_copy(
            update={
                "runtime_config": receipt.runtime_config.model_copy(
                    update={"tls_configuration_sha256": SHA_A}
                )
            }
        )
    with pytest.raises(ValidationError, match="credential reference conflicts"):
        receipt.model_copy(
            update={
                "activation_intent": receipt.activation_intent.model_copy(
                    update={"credential_reference_id": "secret-feishu-other"}
                )
            }
        )
    with pytest.raises(ValidationError, match="exact prior commit"):
        receipt.model_copy(update={"activation_revision": 2})


def test_activation_rejects_changed_humans_or_commissioning_evidence() -> None:
    receipt = _receipt()

    with pytest.raises(ValidationError, match="assessed by current operations"):
        receipt.model_copy(
            update={
                "current_operations_actor_receipt": _actor_receipt(
                    M8ActorRole.OPERATIONS,
                    actor_suffix="02",
                )
            }
        )
    changed = receipt.current_readiness_assessment.model_copy(
        update={"evidence": receipt.current_readiness_assessment.evidence[:-1]}
    )
    with pytest.raises(ValidationError, match="complete current readiness"):
        receipt.model_copy(update={"current_readiness_assessment": changed})


def test_serialized_activation_claim_cannot_open_production_ingress() -> None:
    payload = _receipt().model_dump(mode="json")
    payload["production_external_ingress_permitted"] = True
    with pytest.raises(ValidationError, match="production_external_ingress_permitted"):
        M8FeishuInboundSandboxActivationCommitReceiptV1.model_validate(payload)


def test_revocation_is_immediate_single_human_kill_switch() -> None:
    revocation = _revocation()

    assert revocation.activation_state == "REVOKED"
    assert revocation.sandbox_external_ingress_permitted is False
    assert revocation.production_external_ingress_permitted is False
    assert revocation.automatic_reactivation_permitted is False

    with pytest.raises(ValidationError, match="operations or safety"):
        revocation.model_copy(
            update={"revoked_by_actor_receipt": _actor_receipt(M8ActorRole.LEADER)}
        )
    with pytest.raises(ValidationError, match="cannot predate activation"):
        revocation.model_copy(update={"revoked_at": BASE_TIME})


def test_status_recomputes_current_humans_commissioning_and_revocation() -> None:
    active = _status()
    assert active.activation_state == "SANDBOX_INBOUND_ACTIVE"
    assert active.human_authority_current is True
    assert active.commissioning_current is True
    assert active.sandbox_external_ingress_permitted is True
    assert active.url_challenge_permitted is True
    assert active.business_event_ingress_permitted is True

    revoked = _status(revocation=_revocation())
    assert revoked.activation_state == "REVOKED"
    assert revoked.sandbox_external_ingress_permitted is False

    invalidated = active.model_copy(
        update={
            "current_safety_actor_receipt": _actor_receipt(
                M8ActorRole.SAFETY_OFFICER,
                actor_suffix="02",
            )
        }
    )
    assert invalidated.activation_state == "INVALIDATED"
    assert invalidated.human_authority_current is False
    assert invalidated.sandbox_external_ingress_permitted is False

    stale_commissioning = active.model_copy(update={"current_readiness_assessment": None})
    assert stale_commissioning.activation_state == "INVALIDATED"
    assert stale_commissioning.commissioning_current is False


@pytest.mark.parametrize("model", (_config(), _receipt(), _revocation(), _status()))
def test_inbound_activation_contracts_validate_as_serialization_schemas(
    model: BaseModel,
) -> None:
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )
    assert type(model).model_validate_json(model.model_dump_json()) == model


def test_inbound_activation_schemas_are_registered() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-feishu-inbound-sandbox-activation-commit-receipt-v1": (
            M8FeishuInboundSandboxActivationCommitReceiptV1
        ),
        "m8-feishu-inbound-sandbox-activation-revocation-commit-receipt-v1": (
            M8FeishuInboundSandboxActivationRevocationCommitReceiptV1
        ),
        "m8-feishu-inbound-sandbox-activation-status-v1": (
            M8FeishuInboundSandboxActivationStatusV1
        ),
        "m8-feishu-inbound-sandbox-runtime-config-v1": (
            M8FeishuInboundSandboxRuntimeConfigV1
        ),
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
