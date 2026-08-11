from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
)
from labcourt.contracts.m8_adapter_commissioning import (
    M8AdapterActivationIntentV1,
    M8AdapterReadinessAssessmentV1,
    M8CommissioningEvidenceAuthorityV1,
    M8CommissioningEvidenceCommitReceiptV1,
    M8CommissioningEvidenceKind,
    M8CommissioningEvidenceOutcome,
    M8ExternalIdempotencyKey,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterKind,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_activation import (
    M8FeishuSandboxActivationCommitReceiptV1,
    M8FeishuSandboxRuntimeConfigV1,
    m8_feishu_runtime_config_bytes,
)
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_notification_lifecycle import M8NotificationChannelKind
from labcourt.contracts.m8_notifications import M8NotificationTargetAuthorityV1

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BASE_TIME = datetime(2026, 8, 11, 8, 0, tzinfo=UTC)


def _actor_receipt(
    role: M8ActorRole,
    *,
    actor_suffix: str = "01",
) -> M8ActorAuthorityCommitReceiptV1:
    return M8ActorAuthorityCommitReceiptV1(
        authority=M8ActorAuthorityV1(
            actor_id=(f"{role.value.lower().replace('_', '-')}-feishu-sandbox-{actor_suffix}"),
            role=role,
            scope_kind=M8ActorScopeKind.CAMPUS_WIDE,
            scope_location_ids=(),
            identity_provider_id="campus-idp",
            subject_binding_sha256=SHA_A,
            authority_revision=1,
            active=True,
            manifest_id=SHA_B,
        ),
        repository_manifest_id=SHA_C,
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
        adapter_manifest_id=SHA_A,
        offline_fallback_manifest_id=SHA_B,
    )


def _evidence(
    kind: M8CommissioningEvidenceKind,
    *,
    artifact_sha256: str = SHA_D,
) -> M8CommissioningEvidenceCommitReceiptV1:
    role = (
        M8ActorRole.OPERATIONS
        if kind
        in {
            M8CommissioningEvidenceKind.LICENSE_REVIEW,
            M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
            M8CommissioningEvidenceKind.SECURITY_REVIEW,
        }
        else M8ActorRole.SAFETY_OFFICER
    )
    return M8CommissioningEvidenceCommitReceiptV1(
        evidence=M8CommissioningEvidenceAuthorityV1(
            candidate=_candidate(),
            evidence_kind=kind,
            outcome=M8CommissioningEvidenceOutcome.PASSED,
            artifact_ref=f"feishu-{kind.value.lower().replace('_', '-')}",
            artifact_sha256=artifact_sha256,
            artifact_size_bytes=128,
            reviewer_actor_receipt=_actor_receipt(role),
            reviewed_at=BASE_TIME,
            valid_through=BASE_TIME + timedelta(days=30),
            simulated=kind == M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
            evidence_manifest_id=SHA_E,
        ),
        artifact_storage_manifest_id=SHA_A,
        repository_manifest_id=SHA_C,
    )


def _assessment(
    *,
    assessed_at: datetime,
    evidence: tuple[M8CommissioningEvidenceCommitReceiptV1, ...] | None = None,
) -> M8AdapterReadinessAssessmentV1:
    resolved = evidence or tuple(_evidence(kind) for kind in M8CommissioningEvidenceKind)
    return M8AdapterReadinessAssessmentV1(
        candidate=_candidate(),
        evidence=tuple(sorted(resolved, key=lambda item: item.evidence.evidence_kind.value)),
        assessor_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        assessed_at=assessed_at,
        assessment_manifest_id=SHA_A,
    )


def _profile() -> M8FeishuAdapterProfileV1:
    return M8FeishuAdapterProfileV1(
        candidate=_candidate(),
        credential_bundle_reference_id="secret-feishu-sandbox-campus-main",
        app_id_sha256=SHA_B,
        profile_manifest_id=SHA_C,
    )


def _binding(
    *,
    actor_id: str = "student-test-01",
    receive_id_sha256: str = SHA_D,
) -> M8FeishuRecipientBindingAuthorityV1:
    target = M8NotificationTargetAuthorityV1(
        actor_id=actor_id,
        identity_provider_id="campus-idp",
        external_subject_binding_sha256=receive_id_sha256,
        channel=M8NotificationChannelKind.FEISHU,
        authority_revision=1,
        active=True,
        inbound_response_supported=True,
        manifest_id=SHA_A,
    )
    return M8FeishuRecipientBindingAuthorityV1(
        target=target,
        profile_id=_profile().profile_id,
        receive_id_reference=f"feishu-open-id-{actor_id}",
        receive_id_sha256=receive_id_sha256,
        mapping_revision=1,
        active=True,
        mapping_manifest_id=SHA_B,
    )


def _config() -> M8FeishuSandboxRuntimeConfigV1:
    bindings = tuple(sorted((_binding(),), key=lambda item: item.binding_authority_id))
    return M8FeishuSandboxRuntimeConfigV1(
        profile=_profile(),
        recipient_allowlist=bindings,
        runtime_config_ref="m8-feishu-sandbox-runtime-config-01",
        runtime_config_manifest_id=SHA_E,
    )


def _intent(config: M8FeishuSandboxRuntimeConfigV1) -> M8AdapterActivationIntentV1:
    raw = m8_feishu_runtime_config_bytes(config)
    return M8AdapterActivationIntentV1(
        readiness_assessment=_assessment(assessed_at=BASE_TIME + timedelta(hours=1)),
        operations_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        safety_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        runtime_config_ref=config.runtime_config_ref,
        runtime_config_sha256=hashlib.sha256(raw).hexdigest(),
        runtime_config_size_bytes=len(raw),
        credential_reference_id=config.profile.credential_bundle_reference_id,
        requested_at=BASE_TIME + timedelta(hours=2),
        activation_manifest_id=SHA_D,
    )


def _receipt() -> M8FeishuSandboxActivationCommitReceiptV1:
    config = _config()
    return M8FeishuSandboxActivationCommitReceiptV1(
        activation_intent=_intent(config),
        runtime_config=config,
        current_readiness_assessment=_assessment(assessed_at=BASE_TIME + timedelta(hours=3)),
        current_operations_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        current_safety_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        committed_at=BASE_TIME + timedelta(hours=4),
        runtime_config_storage_manifest_id=SHA_B,
        repository_manifest_id=SHA_C,
    )


def test_runtime_config_is_secret_free_sandbox_allowlist_not_call_authority() -> None:
    config = _config()
    assert config.environment == "SANDBOX"
    assert config.recipient_allowlist_enforced is True
    assert config.external_call_permitted is False
    assert config.secret_material_embedded is False
    assert config.clear_receive_id_persisted is False
    assert config.recipient_binding_ids == (config.recipient_allowlist[0].binding_authority_id,)
    assert b'"app_secret":' not in m8_feishu_runtime_config_bytes(config)
    assert b'"tenant_access_token":' not in m8_feishu_runtime_config_bytes(config)


def test_runtime_config_rejects_foreign_inactive_duplicate_or_unstable_allowlist() -> None:
    config = _config()
    binding = config.recipient_allowlist[0]
    with pytest.raises(ValidationError, match="another adapter profile"):
        config.model_copy(
            update={"recipient_allowlist": (binding.model_copy(update={"profile_id": SHA_A}),)}
        )
    with pytest.raises(ValidationError, match="active bindings"):
        config.model_copy(
            update={"recipient_allowlist": (binding.model_copy(update={"active": False}),)}
        )
    with pytest.raises(ValidationError, match="duplicates"):
        config.model_copy(update={"recipient_allowlist": (binding, binding)})

    second = _binding(actor_id="student-test-02", receive_id_sha256=SHA_E)
    unstable = tuple(
        sorted((binding, second), key=lambda item: item.binding_authority_id, reverse=True)
    )
    with pytest.raises(ValidationError, match="stable order"):
        config.model_copy(update={"recipient_allowlist": unstable})


def test_activation_receipt_only_authorizes_allowlisted_sandbox_calls() -> None:
    receipt = _receipt()
    raw = m8_feishu_runtime_config_bytes(receipt.runtime_config)
    assert receipt.runtime_config_document_sha256 == hashlib.sha256(raw).hexdigest()
    assert receipt.runtime_config_size_bytes == len(raw)
    assert receipt.activation_state == "SANDBOX_ACTIVE"
    assert receipt.sandbox_external_call_permitted is True
    assert receipt.production_external_call_permitted is False
    assert receipt.test_recipient_allowlist_only is True
    assert receipt.automatic_activation_permitted is False
    assert receipt.credential_material_persisted is False
    assert receipt.life_safety_action_permitted is False
    assert receipt.direct_disciplinary_action_permitted is False
    assert receipt.face_recognition_permitted is False
    assert receipt.cross_camera_reidentification_permitted is False


def test_activation_receipt_rejects_changed_config_or_credential_reference() -> None:
    receipt = _receipt()
    with pytest.raises(ValidationError, match="runtime config bytes conflict"):
        receipt.model_copy(
            update={
                "runtime_config": receipt.runtime_config.model_copy(
                    update={"runtime_config_manifest_id": SHA_A}
                )
            }
        )
    changed_intent = receipt.activation_intent.model_copy(
        update={"credential_reference_id": "secret-feishu-sandbox-another"}
    )
    with pytest.raises(ValidationError, match="credential reference conflicts"):
        receipt.model_copy(update={"activation_intent": changed_intent})


def test_activation_receipt_rejects_stale_humans_or_changed_evidence() -> None:
    receipt = _receipt()
    stale_operations = _actor_receipt(M8ActorRole.OPERATIONS, actor_suffix="02")
    with pytest.raises(ValidationError, match="assessed by current operations"):
        receipt.model_copy(update={"current_operations_actor_receipt": stale_operations})

    changed_evidence = tuple(
        _evidence(
            kind,
            artifact_sha256=(
                SHA_A if kind == M8CommissioningEvidenceKind.SECURITY_REVIEW else SHA_D
            ),
        )
        for kind in M8CommissioningEvidenceKind
    )
    with pytest.raises(ValidationError, match="evidence changed"):
        receipt.model_copy(
            update={
                "current_readiness_assessment": _assessment(
                    assessed_at=BASE_TIME + timedelta(hours=3),
                    evidence=changed_evidence,
                )
            }
        )


def test_serialized_activation_claims_cannot_escalate_authority() -> None:
    payload = _receipt().model_dump(mode="json")
    payload["production_external_call_permitted"] = True
    with pytest.raises(ValidationError, match="production_external_call_permitted"):
        M8FeishuSandboxActivationCommitReceiptV1.model_validate(payload)


@pytest.mark.parametrize("model", (_config(), _receipt()))
def test_feishu_activation_contracts_validate_as_serialization_schemas(
    model: BaseModel,
) -> None:
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )


def test_feishu_activation_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-feishu-sandbox-activation-commit-receipt-v1": (
            M8FeishuSandboxActivationCommitReceiptV1
        ),
        "m8-feishu-sandbox-runtime-config-v1": M8FeishuSandboxRuntimeConfigV1,
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
