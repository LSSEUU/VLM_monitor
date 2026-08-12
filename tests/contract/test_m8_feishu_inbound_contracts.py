from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.contracts.m8_feishu_inbound import (
    M8FeishuInboundMessageCommitReceiptV1,
    M8FeishuInboundMessageVerificationReceiptV1,
    M8FeishuInboundWebhookProfileV1,
    M8FeishuWebhookIngressRequestV1,
)
from tests.contract.test_m8_feishu_notification_contracts import _profile

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
RECEIVED_AT = datetime(2026, 8, 11, 15, 0, tzinfo=UTC)


def _webhook_profile() -> M8FeishuInboundWebhookProfileV1:
    return M8FeishuInboundWebhookProfileV1(
        outbound_profile=_profile(),
        request_url_reference_id="feishu-inbound-url-sandbox-01",
        encrypt_key_reference_id="secret-feishu-encrypt-key-01",
        encrypt_key_sha256=SHA_A,
        verification_token_reference_id="secret-feishu-verification-token-01",
        verification_token_sha256=SHA_B,
        profile_manifest_id=SHA_C,
    )


def _ingress() -> M8FeishuWebhookIngressRequestV1:
    return M8FeishuWebhookIngressRequestV1(
        inbound_profile_id=_webhook_profile().inbound_profile_id,
        request_timestamp_seconds=int(RECEIVED_AT.timestamp()),
        request_nonce="nonce-sandbox-01",
        request_signature=SHA_C,
        encrypted_body_ref="feishu-encrypted-event-01",
        encrypted_body_sha256=SHA_D,
        encrypted_body_size_bytes=512,
        received_at=RECEIVED_AT,
        ingress_manifest_id=SHA_E,
    )


def _verified() -> M8FeishuInboundMessageVerificationReceiptV1:
    return M8FeishuInboundMessageVerificationReceiptV1(
        profile=_webhook_profile(),
        ingress_request=_ingress(),
        decrypted_event_ref="feishu-decrypted-event-01",
        decrypted_event_sha256=SHA_A,
        decrypted_event_size_bytes=480,
        provider_event_id="event-sandbox-01",
        provider_message_id="om_student_reply_01",
        provider_parent_message_id="om_outbound_case_card_01",
        provider_root_message_id="om_outbound_case_card_01",
        app_id_sha256=_profile().app_id_sha256,
        tenant_key_sha256=SHA_B,
        verification_token_sha256=SHA_B,
        sender_open_id_sha256=SHA_C,
        event_created_at=RECEIVED_AT - timedelta(seconds=2),
        message_created_at=RECEIVED_AT - timedelta(seconds=3),
        content_document_ref="feishu-text-content-01",
        content_document_sha256=SHA_D,
        content_size_bytes=96,
        verification_manifest_id=SHA_E,
    )


def _commit() -> M8FeishuInboundMessageCommitReceiptV1:
    return M8FeishuInboundMessageCommitReceiptV1(
        verification_receipt=_verified(),
        committed_at=RECEIVED_AT + timedelta(seconds=1),
        raw_storage_manifest_id=SHA_A,
        commit_manifest_id=SHA_B,
        repository_manifest_id=SHA_C,
    )


def test_profile_pins_encrypted_p2p_text_webhook_without_activation_or_secrets() -> None:
    profile = _webhook_profile()
    payload = profile.model_dump(mode="json")

    assert profile.delivery_kind == "HTTPS_WEBHOOK"
    assert profile.event_type == "im.message.receive_v1"
    assert profile.required_scope == "im:message.p2p_msg:readonly"
    assert profile.allowed_chat_type == "p2p"
    assert profile.allowed_sender_type == "user"
    assert profile.allowed_message_type == "text"
    assert profile.request_signature_required is True
    assert profile.message_id_deduplication_required is True
    assert profile.secret_material_embedded is False
    assert profile.external_ingress_permitted is False
    assert "encrypt_key" not in payload
    assert "verification_token" not in payload


def test_ingress_is_only_encrypted_evidence_and_claims_no_verification() -> None:
    ingress = _ingress()

    assert ingress.signature_verified is False
    assert ingress.payload_decrypted is False
    assert ingress.business_event_accepted is False
    assert ingress.credential_material_persisted is False
    assert len(ingress.ingress_request_id) == 64


def test_verified_reply_uses_message_id_for_dedup_and_parent_for_correlation() -> None:
    receipt = _verified()

    assert receipt.signature_verified is True
    assert receipt.payload_decrypted is True
    assert receipt.verification_token_verified is True
    assert receipt.event_type == "im.message.receive_v1"
    assert receipt.chat_type == "p2p"
    assert receipt.sender_type == "user"
    assert receipt.message_type == "text"
    assert receipt.provider_message_deduplication_key == receipt.provider_message_id
    assert receipt.provider_message_deduplication_key != receipt.provider_event_id
    assert receipt.reply_correlation_message_id == receipt.provider_parent_message_id
    assert receipt.clear_message_content_embedded is False
    assert receipt.clear_sender_identifier_persisted is False
    assert receipt.notification_reply_commit_permitted is False
    assert receipt.case_transition_permitted is False
    assert receipt.direct_disciplinary_action_permitted is False


def test_verified_reply_rejects_stale_request_wrong_app_and_self_parent() -> None:
    receipt = _verified()

    stale_ingress = receipt.ingress_request.model_copy(
        update={
            "request_timestamp_seconds": int(
                (receipt.ingress_request.received_at - timedelta(minutes=6)).timestamp()
            )
        }
    )
    with pytest.raises(ValidationError, match="freshness window"):
        receipt.model_copy(update={"ingress_request": stale_ingress})

    with pytest.raises(ValidationError, match="another app or token"):
        receipt.model_copy(update={"app_id_sha256": SHA_E})

    with pytest.raises(ValidationError, match="parent itself"):
        receipt.model_copy(update={"provider_parent_message_id": receipt.provider_message_id})


def test_verified_reply_rejects_future_provider_time_and_raw_reference_graft() -> None:
    receipt = _verified()

    with pytest.raises(ValidationError, match="implausibly in the future"):
        receipt.model_copy(
            update={"event_created_at": RECEIVED_AT + timedelta(minutes=6)}
        )
    with pytest.raises(ValidationError, match="distinct references"):
        receipt.model_copy(
            update={"content_document_ref": receipt.decrypted_event_ref}
        )


def test_commit_receipt_binds_ordered_raw_inventory_and_no_business_transition() -> None:
    receipt = _commit()

    assert receipt.provider_message_id == _verified().provider_message_id
    assert receipt.provider_message_deduplication_key == receipt.provider_message_id
    assert receipt.raw_artifact_refs == (
        "feishu-encrypted-event-01",
        "feishu-decrypted-event-01",
        "feishu-text-content-01",
    )
    assert receipt.raw_artifact_sizes_bytes == (512, 480, 96)
    assert receipt.total_raw_artifact_size_bytes == 1_088
    assert receipt.verified_evidence_persisted is True
    assert receipt.automatic_replay_permitted is False
    assert receipt.notification_reply_commit_permitted is False
    assert receipt.case_transition_permitted is False

    with pytest.raises(ValidationError, match="cannot predate ingress"):
        receipt.model_copy(update={"committed_at": RECEIVED_AT - timedelta(seconds=1)})


@pytest.mark.parametrize("model", (_webhook_profile(), _ingress(), _verified(), _commit()))
def test_inbound_contracts_round_trip_validate_and_hide_clear_content(model: BaseModel) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )
    serialized = json.dumps(model.model_dump(mode="json"))
    assert "student explanation text" not in serialized
    assert "ou_clear_open_id" not in serialized


def test_inbound_contracts_reject_serialized_computed_claim_grafts() -> None:
    payload = _verified().model_dump(mode="json")
    payload["notification_reply_commit_permitted"] = True
    with pytest.raises(ValidationError, match="notification_reply_commit_permitted"):
        M8FeishuInboundMessageVerificationReceiptV1.model_validate(payload)


def test_inbound_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-feishu-inbound-message-commit-receipt-v1": (
            M8FeishuInboundMessageCommitReceiptV1
        ),
        "m8-feishu-inbound-message-verification-receipt-v1": (
            M8FeishuInboundMessageVerificationReceiptV1
        ),
        "m8-feishu-inbound-webhook-profile-v1": M8FeishuInboundWebhookProfileV1,
        "m8-feishu-webhook-ingress-request-v1": M8FeishuWebhookIngressRequestV1,
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
