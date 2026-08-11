from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_adapter_commissioning import M8AdapterActivationIntentV1
from labcourt.contracts.m8_feishu_activation import (
    M8FeishuSandboxActivationCommitReceiptV1,
    M8FeishuSandboxActivationStatusV1,
    M8FeishuSandboxRuntimeConfigV1,
    m8_feishu_runtime_config_bytes,
)
from labcourt.contracts.m8_feishu_transport import (
    M8FeishuSandboxSendOutcome,
    M8FeishuSandboxSendReceiptV1,
    M8FeishuTokenAcquisitionReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelFailureCode,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchResultV1,
)
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationTargetCommitReceiptV1,
)
from labcourt.ports.m8_feishu_secrets import M8FeishuResolvedSecrets
from tests.contract.test_m8_feishu_activation_contracts import (
    BASE_TIME,
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    SHA_E,
    _actor_receipt,
    _assessment,
)
from tests.contract.test_m8_feishu_notification_contracts import _preflight


def _activation_status() -> M8FeishuSandboxActivationStatusV1:
    preflight = _preflight()
    config = M8FeishuSandboxRuntimeConfigV1(
        profile=preflight.profile,
        recipient_allowlist=(preflight.recipient_binding,),
        runtime_config_ref="m8-feishu-sandbox-send-runtime-01",
        runtime_config_manifest_id=SHA_A,
    )
    raw = m8_feishu_runtime_config_bytes(config)
    intent = M8AdapterActivationIntentV1(
        readiness_assessment=_assessment(assessed_at=BASE_TIME + timedelta(hours=1)),
        operations_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        safety_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        runtime_config_ref=config.runtime_config_ref,
        runtime_config_sha256=hashlib.sha256(raw).hexdigest(),
        runtime_config_size_bytes=len(raw),
        credential_reference_id=config.profile.credential_bundle_reference_id,
        requested_at=BASE_TIME + timedelta(hours=2),
        activation_manifest_id=SHA_B,
    )
    activation = M8FeishuSandboxActivationCommitReceiptV1(
        activation_intent=intent,
        runtime_config=config,
        current_readiness_assessment=_assessment(assessed_at=BASE_TIME + timedelta(hours=3)),
        current_operations_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        current_safety_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        activation_revision=1,
        committed_at=BASE_TIME + timedelta(hours=4),
        runtime_config_storage_manifest_id=SHA_B,
        repository_manifest_id=SHA_C,
    )
    return M8FeishuSandboxActivationStatusV1(
        activation_receipt=activation,
        current_operations_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        current_safety_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        current_recipient_target_receipts=(
            M8NotificationTargetCommitReceiptV1(
                target=preflight.recipient_binding.target,
                repository_manifest_id=SHA_C,
            ),
        ),
        current_readiness_assessment=_assessment(assessed_at=BASE_TIME + timedelta(hours=5)),
        assessed_at=BASE_TIME + timedelta(hours=5),
        repository_manifest_id=SHA_C,
    )


def _token_receipt() -> M8FeishuTokenAcquisitionReceiptV1:
    redacted = b'{"code":0,"expire":7200,"tenant_access_token_sha256":"redacted"}\n'
    return M8FeishuTokenAcquisitionReceiptV1(
        profile_id=_preflight().profile.profile_id,
        credential_bundle_reference_id=_preflight().profile.credential_bundle_reference_id,
        app_id_sha256=_preflight().profile.app_id_sha256,
        tenant_access_token_sha256=SHA_E,
        acquired_at=BASE_TIME + timedelta(hours=5),
        expires_at=BASE_TIME + timedelta(hours=7),
        provider_log_id="feishu-token-log-01",
        redacted_raw_response_ref="feishu-token-response-redacted-01",
        redacted_raw_response_sha256=hashlib.sha256(redacted).hexdigest(),
        redacted_raw_response_size_bytes=len(redacted),
        token_manifest_id=SHA_D,
    )


def _send_receipt(
    outcome: M8FeishuSandboxSendOutcome = M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED,
) -> M8FeishuSandboxSendReceiptV1:
    preflight = _preflight()
    accepted = outcome == M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED
    permission = outcome == M8FeishuSandboxSendOutcome.MESSAGE_PERMISSION_DENIED
    token_failure = outcome in {
        M8FeishuSandboxSendOutcome.TOKEN_REJECTED,
        M8FeishuSandboxSendOutcome.TOKEN_TIMEOUT,
    }
    timeout = outcome in {
        M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN,
        M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID,
    }
    raw = b'{"code":0,"data":{"message_id":"om-sandbox-01"}}\n'
    disposition = (
        M8NotificationDispatchDisposition.ACCEPTED
        if accepted
        else (
            M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
            if timeout
            else M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
        )
    )
    failure = None
    if not accepted:
        failure = {
            M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID: (
                M8NotificationChannelFailureCode.RECEIPT_INVALID
            ),
            M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN: (
                M8NotificationChannelFailureCode.UNKNOWN_DELIVERY
            ),
            M8FeishuSandboxSendOutcome.TOKEN_TIMEOUT: (
                M8NotificationChannelFailureCode.CHANNEL_TIMEOUT
            ),
        }.get(outcome, M8NotificationChannelFailureCode.CHANNEL_REJECTED)
    result = M8NotificationDispatchResultV1(
        request=preflight.notification_request,
        disposition=disposition,
        provider_receipt_id="om-sandbox-01" if accepted else None,
        raw_response_ref="feishu-sandbox-response-01",
        raw_response_sha256=hashlib.sha256(raw).hexdigest(),
        failure_code=failure,
        completed_at=BASE_TIME + timedelta(hours=5),
        result_manifest_id=SHA_A,
    )
    return M8FeishuSandboxSendReceiptV1(
        preflight=preflight,
        activation_status=_activation_status(),
        outcome=outcome,
        token_acquisition_receipt=None if token_failure else _token_receipt(),
        token_cache_hit=False,
        message_request_attempted=not token_failure,
        provider_http_status=(200 if accepted else (400 if permission else None)),
        provider_code=(0 if accepted else (230035 if permission else None)),
        provider_log_id=("feishu-message-log-01" if accepted or permission else None),
        dispatch_result=result,
        raw_response_size_bytes=len(raw),
        send_manifest_id=SHA_B,
    )


def test_token_receipt_is_redacted_hash_only_and_expiring() -> None:
    receipt = _token_receipt()
    payload = receipt.model_dump(mode="json")
    serialized = json.dumps(payload)
    assert receipt.raw_response_redacted is True
    assert receipt.token_secret_persisted is False
    assert 'tenant_access_token"' not in serialized
    assert receipt.expires_at > receipt.acquired_at

    with pytest.raises(ValidationError, match="expiry"):
        receipt.model_copy(update={"expires_at": receipt.acquired_at})


def test_accepted_send_requires_current_allowlist_and_never_claims_delivery() -> None:
    receipt = _send_receipt()
    assert receipt.outcome == M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED
    assert receipt.provider_acceptance_confirmed is True
    assert receipt.notification_transition_permitted is True
    assert receipt.real_delivery_confirmed is False
    assert receipt.case_transition_permitted is False
    assert receipt.direct_disciplinary_action_permitted is False
    assert receipt.simulated is False

    invalid_status = receipt.activation_status.model_copy(
        update={"current_readiness_assessment": None}
    )
    with pytest.raises(ValidationError, match="current sandbox activation"):
        receipt.model_copy(update={"activation_status": invalid_status})


def test_send_outcome_cannot_hide_timeout_or_provider_rejection() -> None:
    timeout = _send_receipt(M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN)
    assert timeout.dispatch_result.disposition == M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
    assert timeout.provider_acceptance_confirmed is False
    with pytest.raises(ValidationError, match="outcome shape"):
        timeout.model_copy(update={"provider_http_status": 200, "provider_code": 0})

    denied = _send_receipt(M8FeishuSandboxSendOutcome.MESSAGE_PERMISSION_DENIED)
    assert denied.dispatch_result.failure_code == M8NotificationChannelFailureCode.CHANNEL_REJECTED
    with pytest.raises(ValidationError, match="outcome shape"):
        denied.model_copy(update={"provider_code": 0})


def test_resolved_secret_lease_is_non_serializable_redacted_and_zeroized() -> None:
    lease = M8FeishuResolvedSecrets(
        profile_id=SHA_A,
        binding_authority_id=SHA_B,
        credential_bundle_reference_id="secret-feishu-test",
        app_id=b"cli_fake_app_id",
        app_secret=b"fake_app_secret",
        open_id=b"ou_fake_open_id",
    )
    assert "fake" not in repr(lease)
    assert lease.app_id_bytes() == b"cli_fake_app_id"
    lease.close()
    assert "closed=True" in repr(lease)
    with pytest.raises(RuntimeError, match="closed"):
        lease.open_id_bytes()


@pytest.mark.parametrize("model", (_token_receipt(), _send_receipt()))
def test_feishu_transport_contracts_validate_as_serialization_schemas(
    model: BaseModel,
) -> None:
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )


def test_feishu_transport_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-feishu-sandbox-send-receipt-v1": M8FeishuSandboxSendReceiptV1,
        "m8-feishu-token-acquisition-receipt-v1": M8FeishuTokenAcquisitionReceiptV1,
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
