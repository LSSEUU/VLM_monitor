"""Dual-human activation contracts for Feishu sandbox webhook ingress."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_adapter_commissioning import (
    MAX_M8_RUNTIME_CONFIG_BYTES,
    M8AdapterActivationIntentV1,
    M8AdapterReadinessAssessmentV1,
    M8CommissioningReadiness,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundWebhookProfileV1
from labcourt.contracts.references import ReferenceToken, require_reference_token


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu inbound activation {name} must be timezone-aware UTC")
    return value


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    if not any(present for present, _claimed in claims.values()):
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(
                f"serialized {name} conflicts with derived M8 Feishu inbound activation"
            )


class M8FeishuInboundSandboxRuntimeConfigV1(FrozenContractModel):
    """Secret-free public callback configuration; never ingress authority alone."""

    schema_version: Literal["m8-feishu-inbound-sandbox-runtime-config-v1"] = (
        "m8-feishu-inbound-sandbox-runtime-config-v1"
    )
    profile: M8FeishuInboundWebhookProfileV1
    runtime_config_ref: ReferenceToken
    public_callback_url_reference_id: ReferenceToken
    public_callback_url_sha256: Sha256Hex
    tls_configuration_reference_id: ReferenceToken
    tls_configuration_sha256: Sha256Hex
    environment: Literal["SANDBOX"] = "SANDBOX"
    public_transport_kind: Literal["HTTPS_JSON"] = "HTTPS_JSON"
    callback_path: Literal["/callbacks/feishu/v1"] = "/callbacks/feishu/v1"
    application_bind_host: Literal["127.0.0.1"] = "127.0.0.1"
    application_bind_port: int = Field(ge=1, le=65_535, strict=True)
    tls_termination_kind: Literal["EXTERNAL_REVERSE_PROXY"] = "EXTERNAL_REVERSE_PROXY"
    public_ca_certificate_required: Literal[True] = True
    hostname_validation_required: Literal[True] = True
    encrypted_envelope_required: Literal[True] = True
    business_event_signature_required: Literal[True] = True
    url_challenge_response_deadline_milliseconds: Literal[1000] = 1_000
    business_event_ack_deadline_milliseconds: Literal[3000] = 3_000
    raw_body_max_bytes: Literal[262144] = 262_144
    business_event_persistence_before_ack_required: Literal[True] = True
    secret_material_embedded: Literal[False] = False
    clear_public_url_embedded: Literal[False] = False
    external_ingress_permitted: Literal[False] = False
    listener_autostart_permitted: Literal[False] = False
    runtime_config_manifest_id: Sha256Hex

    @field_validator(
        "runtime_config_ref",
        "public_callback_url_reference_id",
        "tls_configuration_reference_id",
    )
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu inbound sandbox runtime reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("credential_reference_inventory_sha256", "runtime_config_id"),
        )
        config = handler(payload)
        _verify_computed_claims(config, claims)
        return config

    @model_validator(mode="after")
    def validate_profile_binding(self) -> Self:
        if self.public_callback_url_reference_id != self.profile.request_url_reference_id:
            raise ValueError("M8 Feishu inbound callback URL reference conflicts with profile")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def credential_reference_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                self.profile.outbound_profile.credential_bundle_reference_id,
                self.profile.encrypt_key_reference_id,
                self.profile.verification_token_reference_id,
                self.tls_configuration_reference_id,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def runtime_config_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-inbound-sandbox-runtime-config",
                1,
                self.profile.inbound_profile_id,
                self.runtime_config_ref,
                self.public_callback_url_reference_id,
                self.public_callback_url_sha256,
                self.tls_configuration_reference_id,
                self.tls_configuration_sha256,
                self.credential_reference_inventory_sha256,
                self.environment,
                self.public_transport_kind,
                self.callback_path,
                self.application_bind_host,
                self.application_bind_port,
                self.tls_termination_kind,
                self.public_ca_certificate_required,
                self.hostname_validation_required,
                self.encrypted_envelope_required,
                self.business_event_signature_required,
                self.url_challenge_response_deadline_milliseconds,
                self.business_event_ack_deadline_milliseconds,
                self.raw_body_max_bytes,
                self.business_event_persistence_before_ack_required,
                self.secret_material_embedded,
                self.clear_public_url_embedded,
                self.external_ingress_permitted,
                self.listener_autostart_permitted,
                self.runtime_config_manifest_id,
            ]
        )


def m8_feishu_inbound_runtime_config_bytes(
    config: M8FeishuInboundSandboxRuntimeConfigV1,
) -> bytes:
    """Return exact canonical bytes bound by human intent and persistence."""

    return canonical_json(config.model_dump(mode="json")).encode("utf-8")


class M8FeishuInboundSandboxActivationCommitReceiptV1(FrozenContractModel):
    """Persisted dual-human authority for sandbox webhook ingress only."""

    schema_version: Literal[
        "m8-feishu-inbound-sandbox-activation-commit-receipt-v1"
    ] = "m8-feishu-inbound-sandbox-activation-commit-receipt-v1"
    activation_intent: M8AdapterActivationIntentV1
    runtime_config: M8FeishuInboundSandboxRuntimeConfigV1
    current_readiness_assessment: M8AdapterReadinessAssessmentV1
    current_operations_actor_receipt: M8ActorAuthorityCommitReceiptV1
    current_safety_actor_receipt: M8ActorAuthorityCommitReceiptV1
    activation_revision: int = Field(gt=0, strict=True)
    prior_activation_commit_id: Sha256Hex | None = None
    committed_at: datetime
    runtime_config_storage_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @field_validator("committed_at")
    @classmethod
    def validate_committed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "committed_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "runtime_config_document_sha256",
                "runtime_config_size_bytes",
                "activation_state",
                "sandbox_external_ingress_permitted",
                "production_external_ingress_permitted",
                "url_challenge_permitted",
                "business_event_ingress_permitted",
                "listener_autostart_permitted",
                "notification_reply_commit_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "face_recognition_permitted",
                "cross_camera_reidentification_permitted",
                "activation_commit_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_current_activation_gate(self) -> Self:
        intent = self.activation_intent
        config = self.runtime_config
        current = self.current_readiness_assessment
        operations = self.current_operations_actor_receipt
        safety = self.current_safety_actor_receipt
        candidate = config.profile.outbound_profile.candidate
        if candidate != intent.readiness_assessment.candidate:
            raise ValueError("M8 Feishu inbound config belongs to another candidate")
        if current.candidate != candidate:
            raise ValueError("M8 Feishu inbound current readiness belongs to another candidate")
        if current.readiness != M8CommissioningReadiness.READY_FOR_HUMAN_ACTIVATION:
            raise ValueError("M8 Feishu inbound activation requires complete current readiness")
        if (
            current.evidence_inventory_sha256
            != intent.readiness_assessment.evidence_inventory_sha256
        ):
            raise ValueError("M8 Feishu inbound evidence changed after human confirmation")
        if current.assessor_actor_receipt != operations:
            raise ValueError("M8 Feishu inbound readiness was not assessed by current operations")
        if operations != intent.operations_actor_receipt:
            raise ValueError("M8 Feishu inbound operations confirmation is no longer current")
        if safety != intent.safety_actor_receipt:
            raise ValueError("M8 Feishu inbound safety confirmation is no longer current")
        if (
            operations.authority.role != M8ActorRole.OPERATIONS
            or safety.authority.role != M8ActorRole.SAFETY_OFFICER
        ):
            raise ValueError("M8 Feishu inbound activation requires operations and safety roles")
        if current.assessed_at < intent.requested_at:
            raise ValueError("M8 Feishu inbound current readiness predates activation intent")
        if self.committed_at < current.assessed_at:
            raise ValueError("M8 Feishu inbound activation cannot predate current readiness")
        if (self.activation_revision == 1) != (self.prior_activation_commit_id is None):
            raise ValueError("M8 Feishu inbound activation revision requires an exact prior commit")
        if config.runtime_config_ref != intent.runtime_config_ref:
            raise ValueError("M8 Feishu inbound runtime config reference conflicts with intent")
        if (
            config.profile.outbound_profile.credential_bundle_reference_id
            != intent.credential_reference_id
        ):
            raise ValueError("M8 Feishu inbound credential reference conflicts with intent")
        if (
            self.runtime_config_document_sha256 != intent.runtime_config_sha256
            or self.runtime_config_size_bytes != intent.runtime_config_size_bytes
        ):
            raise ValueError("M8 Feishu inbound runtime config bytes conflict with intent")
        repository_manifests = {
            self.repository_manifest_id,
            operations.repository_manifest_id,
            safety.repository_manifest_id,
            *(item.repository_manifest_id for item in current.evidence),
        }
        if len(repository_manifests) != 1:
            raise ValueError("M8 Feishu inbound activation authorities cross repositories")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def runtime_config_document_sha256(self) -> Sha256Hex:
        return hashlib.sha256(
            m8_feishu_inbound_runtime_config_bytes(self.runtime_config)
        ).hexdigest()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def runtime_config_size_bytes(self) -> int:
        return len(m8_feishu_inbound_runtime_config_bytes(self.runtime_config))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def activation_state(self) -> str:
        return "SANDBOX_INBOUND_ACTIVE"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sandbox_external_ingress_permitted(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def production_external_ingress_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def url_challenge_permitted(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def business_event_ingress_permitted(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def listener_autostart_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_reply_commit_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def face_recognition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cross_camera_reidentification_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def activation_commit_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-inbound-sandbox-activation-commit-receipt",
                1,
                self.activation_intent.activation_intent_id,
                self.runtime_config.runtime_config_id,
                self.current_readiness_assessment.assessment_id,
                self.current_operations_actor_receipt.commit_receipt_id,
                self.current_safety_actor_receipt.commit_receipt_id,
                self.activation_revision,
                self.prior_activation_commit_id,
                _canonical_utc(self.committed_at),
                self.runtime_config_document_sha256,
                self.runtime_config_size_bytes,
                self.runtime_config_storage_manifest_id,
                self.repository_manifest_id,
                self.activation_state,
                self.sandbox_external_ingress_permitted,
                self.production_external_ingress_permitted,
                self.url_challenge_permitted,
                self.business_event_ingress_permitted,
                self.listener_autostart_permitted,
                self.notification_reply_commit_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
                self.face_recognition_permitted,
                self.cross_camera_reidentification_permitted,
            ]
        )

    @model_validator(mode="after")
    def validate_runtime_config_bound(self) -> Self:
        if not 0 < self.runtime_config_size_bytes <= MAX_M8_RUNTIME_CONFIG_BYTES:
            raise ValueError("M8 Feishu inbound runtime config exceeds the allowed bound")
        return self


__all__ = [
    "M8FeishuInboundSandboxActivationCommitReceiptV1",
    "M8FeishuInboundSandboxRuntimeConfigV1",
    "m8_feishu_inbound_runtime_config_bytes",
]
