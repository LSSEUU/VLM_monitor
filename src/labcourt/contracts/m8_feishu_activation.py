"""Fail-closed Feishu sandbox activation authorities for M8.7."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from enum import StrEnum
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
from labcourt.contracts.m8_access_cases import M8ActorRole, M8ActorScopeKind
from labcourt.contracts.m8_adapter_commissioning import (
    MAX_M8_RUNTIME_CONFIG_BYTES,
    M8AdapterActivationIntentV1,
    M8AdapterReadinessAssessmentV1,
    M8CommissioningReadiness,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationTargetCommitReceiptV1,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_FEISHU_SANDBOX_RECIPIENTS = 32


class M8FeishuSandboxRevocationReason(StrEnum):
    COMMISSIONING_INVALIDATED = "COMMISSIONING_INVALIDATED"
    CONFIGURATION_REPLACED = "CONFIGURATION_REPLACED"
    CREDENTIAL_ROTATION = "CREDENTIAL_ROTATION"
    MANUAL_OPERATIONS_STOP = "MANUAL_OPERATIONS_STOP"
    MANUAL_SAFETY_STOP = "MANUAL_SAFETY_STOP"


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu sandbox {name} must be timezone-aware UTC")
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
                f"serialized {name} conflicts with derived M8 Feishu sandbox authority"
            )


class M8FeishuSandboxRuntimeConfigV1(FrozenContractModel):
    """Secret-free, allowlist-only runtime configuration; never call authority alone."""

    schema_version: Literal["m8-feishu-sandbox-runtime-config-v1"] = (
        "m8-feishu-sandbox-runtime-config-v1"
    )
    profile: M8FeishuAdapterProfileV1
    recipient_allowlist: tuple[M8FeishuRecipientBindingAuthorityV1, ...] = Field(
        min_length=1,
        max_length=MAX_M8_FEISHU_SANDBOX_RECIPIENTS,
    )
    runtime_config_ref: ReferenceToken
    environment: Literal["SANDBOX"] = "SANDBOX"
    transport_kind: Literal["HTTPS_JSON"] = "HTTPS_JSON"
    tls_certificate_validation_required: Literal[True] = True
    recipient_allowlist_enforced: Literal[True] = True
    provider_response_max_bytes: Literal[262144] = 262_144
    secret_material_embedded: Literal[False] = False
    clear_receive_id_persisted: Literal[False] = False
    external_call_permitted: Literal[False] = False
    runtime_config_manifest_id: Sha256Hex

    @field_validator("runtime_config_ref")
    @classmethod
    def validate_runtime_config_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu sandbox runtime config")

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
                "recipient_binding_ids",
                "recipient_target_ids",
                "recipient_allowlist_sha256",
                "runtime_config_id",
            ),
        )
        config = handler(payload)
        _verify_computed_claims(config, claims)
        return config

    @model_validator(mode="after")
    def validate_closed_allowlist(self) -> Self:
        bindings = self.recipient_allowlist
        binding_ids = tuple(item.binding_authority_id for item in bindings)
        target_ids = tuple(item.target.target_authority_id for item in bindings)
        if binding_ids != tuple(sorted(binding_ids)):
            raise ValueError("M8 Feishu sandbox recipient allowlist must use stable order")
        if len(binding_ids) != len(set(binding_ids)) or len(target_ids) != len(set(target_ids)):
            raise ValueError("M8 Feishu sandbox recipient allowlist cannot contain duplicates")
        if any(item.profile_id != self.profile.profile_id for item in bindings):
            raise ValueError("M8 Feishu sandbox recipient belongs to another adapter profile")
        if any(not item.active or not item.target.active for item in bindings):
            raise ValueError("M8 Feishu sandbox recipient allowlist requires active bindings")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def recipient_binding_ids(self) -> tuple[Sha256Hex, ...]:
        return tuple(item.binding_authority_id for item in self.recipient_allowlist)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def recipient_target_ids(self) -> tuple[Sha256Hex, ...]:
        return tuple(item.target.target_authority_id for item in self.recipient_allowlist)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def recipient_allowlist_sha256(self) -> Sha256Hex:
        return sha256_hex(self.recipient_binding_ids)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def runtime_config_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-sandbox-runtime-config",
                1,
                self.profile.profile_id,
                self.recipient_binding_ids,
                self.recipient_target_ids,
                self.recipient_allowlist_sha256,
                self.runtime_config_ref,
                self.environment,
                self.transport_kind,
                self.tls_certificate_validation_required,
                self.recipient_allowlist_enforced,
                self.provider_response_max_bytes,
                self.secret_material_embedded,
                self.clear_receive_id_persisted,
                self.external_call_permitted,
                self.runtime_config_manifest_id,
            ]
        )


def m8_feishu_runtime_config_bytes(config: M8FeishuSandboxRuntimeConfigV1) -> bytes:
    """Return the exact canonical bytes bound by activation intent and persistence."""

    return canonical_json(config.model_dump(mode="json")).encode("utf-8")


class M8FeishuSandboxActivationCommitReceiptV1(FrozenContractModel):
    """Persisted dual-human authority for allowlisted sandbox calls only."""

    schema_version: Literal["m8-feishu-sandbox-activation-commit-receipt-v1"] = (
        "m8-feishu-sandbox-activation-commit-receipt-v1"
    )
    activation_intent: M8AdapterActivationIntentV1
    runtime_config: M8FeishuSandboxRuntimeConfigV1
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
        return _require_utc(value, "activation committed_at")

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
                "sandbox_external_call_permitted",
                "production_external_call_permitted",
                "test_recipient_allowlist_only",
                "automatic_activation_permitted",
                "credential_material_persisted",
                "life_safety_action_permitted",
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
        current_operations = self.current_operations_actor_receipt
        current_safety = self.current_safety_actor_receipt
        if config.profile.candidate != intent.readiness_assessment.candidate:
            raise ValueError("M8 Feishu sandbox config belongs to another activation candidate")
        if current.candidate != intent.readiness_assessment.candidate:
            raise ValueError("M8 Feishu sandbox current readiness belongs to another candidate")
        if current.readiness != M8CommissioningReadiness.READY_FOR_HUMAN_ACTIVATION:
            raise ValueError("M8 Feishu sandbox activation requires complete current readiness")
        if (
            current.evidence_inventory_sha256
            != intent.readiness_assessment.evidence_inventory_sha256
        ):
            raise ValueError("M8 Feishu sandbox evidence changed after human confirmation")
        if current.assessor_actor_receipt != current_operations:
            raise ValueError("M8 Feishu sandbox readiness was not assessed by current operations")
        if current_operations != intent.operations_actor_receipt:
            raise ValueError("M8 Feishu sandbox operations confirmation is no longer current")
        if current_safety != intent.safety_actor_receipt:
            raise ValueError("M8 Feishu sandbox safety confirmation is no longer current")
        if (
            current_operations.authority.role != M8ActorRole.OPERATIONS
            or current_safety.authority.role != M8ActorRole.SAFETY_OFFICER
        ):
            raise ValueError("M8 Feishu sandbox activation requires operations and safety roles")
        if current.assessed_at < intent.requested_at:
            raise ValueError("M8 Feishu sandbox current readiness predates activation intent")
        if self.committed_at < current.assessed_at:
            raise ValueError("M8 Feishu sandbox activation cannot predate current readiness")
        if (self.activation_revision == 1) != (self.prior_activation_commit_id is None):
            raise ValueError("M8 Feishu sandbox activation revision requires an exact prior commit")
        if config.runtime_config_ref != intent.runtime_config_ref:
            raise ValueError("M8 Feishu sandbox runtime config reference conflicts with intent")
        if config.profile.credential_bundle_reference_id != intent.credential_reference_id:
            raise ValueError("M8 Feishu sandbox credential reference conflicts with intent")
        if (
            self.runtime_config_document_sha256 != intent.runtime_config_sha256
            or self.runtime_config_size_bytes != intent.runtime_config_size_bytes
        ):
            raise ValueError("M8 Feishu sandbox runtime config bytes conflict with intent")
        repository_manifests = {
            self.repository_manifest_id,
            current_operations.repository_manifest_id,
            current_safety.repository_manifest_id,
            *(item.repository_manifest_id for item in current.evidence),
        }
        if len(repository_manifests) != 1:
            raise ValueError("M8 Feishu sandbox activation authorities cross repositories")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def runtime_config_document_sha256(self) -> Sha256Hex:
        return hashlib.sha256(m8_feishu_runtime_config_bytes(self.runtime_config)).hexdigest()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def runtime_config_size_bytes(self) -> int:
        return len(m8_feishu_runtime_config_bytes(self.runtime_config))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def activation_state(self) -> str:
        return "SANDBOX_ACTIVE"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sandbox_external_call_permitted(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def production_external_call_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def test_recipient_allowlist_only(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_activation_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def credential_material_persisted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def life_safety_action_permitted(self) -> bool:
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
                "m8-feishu-sandbox-activation-commit-receipt",
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
                self.sandbox_external_call_permitted,
                self.production_external_call_permitted,
                self.test_recipient_allowlist_only,
                self.automatic_activation_permitted,
                self.credential_material_persisted,
                self.life_safety_action_permitted,
                self.direct_disciplinary_action_permitted,
                self.face_recognition_permitted,
                self.cross_camera_reidentification_permitted,
            ]
        )

    @model_validator(mode="after")
    def validate_runtime_config_bound(self) -> Self:
        if not 0 < self.runtime_config_size_bytes <= MAX_M8_RUNTIME_CONFIG_BYTES:
            raise ValueError("M8 Feishu sandbox runtime config exceeds the allowed bound")
        return self


class M8FeishuSandboxActivationRevocationCommitReceiptV1(FrozenContractModel):
    """Append-only one-person kill switch for a persisted sandbox activation."""

    schema_version: Literal["m8-feishu-sandbox-activation-revocation-commit-receipt-v1"] = (
        "m8-feishu-sandbox-activation-revocation-commit-receipt-v1"
    )
    activation_receipt: M8FeishuSandboxActivationCommitReceiptV1
    revoked_by_actor_receipt: M8ActorAuthorityCommitReceiptV1
    reason: M8FeishuSandboxRevocationReason
    reason_ref: ReferenceToken
    revoked_at: datetime
    explicit_confirmation: Literal[True] = True
    revocation_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @field_validator("reason_ref")
    @classmethod
    def validate_reason_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu sandbox revocation reason")

    @field_validator("revoked_at")
    @classmethod
    def validate_revoked_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "revoked_at")

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
                "activation_state",
                "sandbox_external_call_permitted",
                "production_external_call_permitted",
                "automatic_reactivation_permitted",
                "revocation_commit_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_revocation_authority(self) -> Self:
        actor = self.revoked_by_actor_receipt.authority
        candidate = self.activation_receipt.runtime_config.profile.candidate
        if actor.role not in {M8ActorRole.OPERATIONS, M8ActorRole.SAFETY_OFFICER}:
            raise ValueError("M8 Feishu sandbox revocation requires operations or safety")
        if not actor.active or actor.scope_kind != M8ActorScopeKind.CAMPUS_WIDE:
            raise ValueError("M8 Feishu sandbox revocation actor is inactive or out of scope")
        if actor.scope_location_ids or candidate.scope_kind != M8ActorScopeKind.CAMPUS_WIDE:
            raise ValueError("M8 Feishu sandbox revocation requires campus-wide authority")
        if self.revoked_at < self.activation_receipt.committed_at:
            raise ValueError("M8 Feishu sandbox revocation cannot predate activation")
        if (
            self.repository_manifest_id != self.activation_receipt.repository_manifest_id
            or self.repository_manifest_id != self.revoked_by_actor_receipt.repository_manifest_id
        ):
            raise ValueError("M8 Feishu sandbox revocation authorities cross repositories")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def activation_state(self) -> str:
        return "REVOKED"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sandbox_external_call_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def production_external_call_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_reactivation_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def revocation_commit_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-sandbox-activation-revocation-commit-receipt",
                1,
                self.activation_receipt.activation_commit_id,
                self.revoked_by_actor_receipt.commit_receipt_id,
                self.reason,
                self.reason_ref,
                _canonical_utc(self.revoked_at),
                self.explicit_confirmation,
                self.revocation_manifest_id,
                self.repository_manifest_id,
                self.activation_state,
                self.sandbox_external_call_permitted,
                self.production_external_call_permitted,
                self.automatic_reactivation_permitted,
            ]
        )


class M8FeishuSandboxActivationStatusV1(FrozenContractModel):
    """Repository-derived current status consumed by a future sandbox transport."""

    schema_version: Literal["m8-feishu-sandbox-activation-status-v1"] = (
        "m8-feishu-sandbox-activation-status-v1"
    )
    activation_receipt: M8FeishuSandboxActivationCommitReceiptV1
    revocation_receipt: M8FeishuSandboxActivationRevocationCommitReceiptV1 | None = None
    current_operations_actor_receipt: M8ActorAuthorityCommitReceiptV1
    current_safety_actor_receipt: M8ActorAuthorityCommitReceiptV1
    current_recipient_target_receipts: tuple[M8NotificationTargetCommitReceiptV1, ...]
    current_readiness_assessment: M8AdapterReadinessAssessmentV1 | None = None
    assessed_at: datetime
    repository_manifest_id: Sha256Hex

    @field_validator("assessed_at")
    @classmethod
    def validate_assessed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "status assessed_at")

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
                "activation_state",
                "human_authority_current",
                "commissioning_current",
                "recipient_authority_current",
                "sandbox_external_call_permitted",
                "production_external_call_permitted",
                "test_recipient_allowlist_only",
                "status_id",
            ),
        )
        status = handler(payload)
        _verify_computed_claims(status, claims)
        return status

    @model_validator(mode="after")
    def validate_current_status(self) -> Self:
        if self.repository_manifest_id != self.activation_receipt.repository_manifest_id:
            raise ValueError("M8 Feishu sandbox status crosses repositories")
        if self.assessed_at < self.activation_receipt.committed_at:
            raise ValueError("M8 Feishu sandbox status cannot predate activation")
        if (
            self.current_operations_actor_receipt.repository_manifest_id
            != self.repository_manifest_id
            or self.current_safety_actor_receipt.repository_manifest_id
            != self.repository_manifest_id
        ):
            raise ValueError("M8 Feishu sandbox current actor status crosses repositories")
        bindings = self.activation_receipt.runtime_config.recipient_allowlist
        if len(self.current_recipient_target_receipts) != len(bindings):
            raise ValueError("M8 Feishu sandbox status requires every current recipient target")
        for binding, target_receipt in zip(
            bindings,
            self.current_recipient_target_receipts,
            strict=True,
        ):
            if (
                target_receipt.target.actor_id != binding.target.actor_id
                or target_receipt.target.channel != binding.target.channel
                or target_receipt.repository_manifest_id != self.repository_manifest_id
            ):
                raise ValueError("M8 Feishu sandbox status grafts current recipient authority")
        if self.current_readiness_assessment is not None and (
            self.current_readiness_assessment.candidate
            != self.activation_receipt.runtime_config.profile.candidate
            or self.current_readiness_assessment.assessor_actor_receipt
            != self.current_operations_actor_receipt
            or self.current_readiness_assessment.assessed_at != self.assessed_at
        ):
            raise ValueError("M8 Feishu sandbox status grafts current readiness")
        if self.revocation_receipt is not None:
            if self.revocation_receipt.activation_receipt != self.activation_receipt:
                raise ValueError("M8 Feishu sandbox status grafts another revocation")
            if self.revocation_receipt.repository_manifest_id != self.repository_manifest_id:
                raise ValueError("M8 Feishu sandbox revocation status crosses repositories")
            if self.assessed_at < self.revocation_receipt.revoked_at:
                raise ValueError("M8 Feishu sandbox status cannot predate revocation")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def activation_state(self) -> str:
        if self.revocation_receipt is not None:
            return "REVOKED"
        if (
            not self.human_authority_current
            or not self.commissioning_current
            or not self.recipient_authority_current
        ):
            return "INVALIDATED"
        return "SANDBOX_ACTIVE"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def human_authority_current(self) -> bool:
        activation = self.activation_receipt
        return (
            self.current_operations_actor_receipt == activation.current_operations_actor_receipt
            and self.current_safety_actor_receipt == activation.current_safety_actor_receipt
            and self.current_operations_actor_receipt.authority.active
            and self.current_safety_actor_receipt.authority.active
            and self.current_operations_actor_receipt.authority.role == M8ActorRole.OPERATIONS
            and self.current_safety_actor_receipt.authority.role == M8ActorRole.SAFETY_OFFICER
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commissioning_current(self) -> bool:
        assessment = self.current_readiness_assessment
        return (
            assessment is not None
            and assessment.readiness == M8CommissioningReadiness.READY_FOR_HUMAN_ACTIVATION
            and assessment.evidence_inventory_sha256
            == self.activation_receipt.current_readiness_assessment.evidence_inventory_sha256
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def recipient_authority_current(self) -> bool:
        bindings = self.activation_receipt.runtime_config.recipient_allowlist
        return all(
            receipt.target == binding.target and receipt.target.active
            for binding, receipt in zip(
                bindings,
                self.current_recipient_target_receipts,
                strict=True,
            )
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sandbox_external_call_permitted(self) -> bool:
        return self.activation_state == "SANDBOX_ACTIVE"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def production_external_call_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def test_recipient_allowlist_only(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-sandbox-activation-status",
                1,
                self.activation_receipt.activation_commit_id,
                (
                    self.revocation_receipt.revocation_commit_id
                    if self.revocation_receipt is not None
                    else None
                ),
                self.current_operations_actor_receipt.commit_receipt_id,
                self.current_safety_actor_receipt.commit_receipt_id,
                tuple(item.commit_receipt_id for item in self.current_recipient_target_receipts),
                (
                    self.current_readiness_assessment.assessment_id
                    if self.current_readiness_assessment is not None
                    else None
                ),
                _canonical_utc(self.assessed_at),
                self.repository_manifest_id,
                self.activation_state,
                self.human_authority_current,
                self.commissioning_current,
                self.recipient_authority_current,
                self.sandbox_external_call_permitted,
                self.production_external_call_permitted,
                self.test_recipient_allowlist_only,
            ]
        )


__all__ = [
    "MAX_M8_FEISHU_SANDBOX_RECIPIENTS",
    "M8FeishuSandboxActivationCommitReceiptV1",
    "M8FeishuSandboxActivationRevocationCommitReceiptV1",
    "M8FeishuSandboxActivationStatusV1",
    "M8FeishuSandboxRevocationReason",
    "M8FeishuSandboxRuntimeConfigV1",
    "m8_feishu_runtime_config_bytes",
]
