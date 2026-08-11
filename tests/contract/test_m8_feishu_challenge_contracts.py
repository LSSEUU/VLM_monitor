from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.contracts.m8_feishu_challenge import (
    M8FeishuUrlChallengeIngressRequestV1,
    M8FeishuUrlChallengeVerificationReceiptV1,
)
from tests.contract.test_m8_feishu_inbound_contracts import _webhook_profile

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
RECEIVED_AT = datetime(2026, 8, 11, 16, 30, tzinfo=UTC)


def _ingress() -> M8FeishuUrlChallengeIngressRequestV1:
    return M8FeishuUrlChallengeIngressRequestV1(
        inbound_profile_id=_webhook_profile().inbound_profile_id,
        encrypted_body_ref="feishu-encrypted-url-challenge-01",
        encrypted_body_sha256=SHA_A,
        encrypted_body_size_bytes=512,
        received_at=RECEIVED_AT,
        ingress_manifest_id=SHA_B,
    )


def _receipt() -> M8FeishuUrlChallengeVerificationReceiptV1:
    return M8FeishuUrlChallengeVerificationReceiptV1(
        profile=_webhook_profile(),
        ingress_request=_ingress(),
        decrypted_challenge_ref="feishu-decrypted-url-challenge-01",
        decrypted_challenge_sha256=SHA_B,
        decrypted_challenge_size_bytes=128,
        response_document_ref="feishu-url-challenge-response-01",
        response_document_sha256=SHA_C,
        response_document_size_bytes=64,
        verification_token_sha256=_webhook_profile().verification_token_sha256,
        verified_at=RECEIVED_AT + timedelta(milliseconds=10),
        verification_manifest_id=SHA_D,
    )


def test_ingress_separates_url_verification_from_business_event_signature() -> None:
    ingress = _ingress()

    assert ingress.request_signature_applicable is False
    assert ingress.signature_verified is False
    assert ingress.payload_decrypted is False
    assert ingress.business_event_accepted is False
    assert ingress.credential_material_embedded is False
    assert len(ingress.ingress_request_id) == 64


def test_verified_challenge_only_authorizes_exact_json_response() -> None:
    receipt = _receipt()

    assert receipt.challenge_type == "url_verification"
    assert receipt.payload_decrypted is True
    assert receipt.verification_token_verified is True
    assert receipt.response_status_code == 200
    assert receipt.response_content_type == "application/json"
    assert receipt.response_deadline_milliseconds == 1_000
    assert receipt.clear_challenge_value_embedded is False
    assert receipt.challenge_response_permitted is True
    assert receipt.external_ingress_activation_permitted is False
    assert receipt.notification_reply_commit_permitted is False
    assert receipt.case_transition_permitted is False
    assert receipt.direct_disciplinary_action_permitted is False


def test_verified_challenge_rejects_profile_token_time_and_reference_grafts() -> None:
    receipt = _receipt()

    with pytest.raises(ValidationError, match="another profile"):
        receipt.model_copy(
            update={
                "ingress_request": receipt.ingress_request.model_copy(
                    update={"inbound_profile_id": SHA_D}
                )
            }
        )
    with pytest.raises(ValidationError, match="another token"):
        receipt.model_copy(update={"verification_token_sha256": SHA_D})
    with pytest.raises(ValidationError, match="cannot predate ingress"):
        receipt.model_copy(update={"verified_at": RECEIVED_AT - timedelta(seconds=1)})
    with pytest.raises(ValidationError, match="missed its deadline"):
        receipt.model_copy(update={"verified_at": RECEIVED_AT + timedelta(seconds=2)})
    with pytest.raises(ValidationError, match="distinct references"):
        receipt.model_copy(
            update={"response_document_ref": receipt.decrypted_challenge_ref}
        )


@pytest.mark.parametrize("model", (_ingress(), _receipt()))
def test_challenge_contracts_round_trip_and_hide_clear_values(model: BaseModel) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )
    serialized = json.dumps(model.model_dump(mode="json"))
    assert "challenge-clear-fixture" not in serialized
    assert "verification-token-clear-fixture" not in serialized


def test_challenge_contracts_reject_computed_authority_grafts() -> None:
    payload = _receipt().model_dump(mode="json")
    payload["external_ingress_activation_permitted"] = True
    with pytest.raises(ValidationError, match="external_ingress_activation_permitted"):
        M8FeishuUrlChallengeVerificationReceiptV1.model_validate(payload)


def test_challenge_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-feishu-url-challenge-ingress-request-v1": (
            M8FeishuUrlChallengeIngressRequestV1
        ),
        "m8-feishu-url-challenge-verification-receipt-v1": (
            M8FeishuUrlChallengeVerificationReceiptV1
        ),
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
