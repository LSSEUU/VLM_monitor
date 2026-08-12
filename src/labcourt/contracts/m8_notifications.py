"""M8 notification planning, routing, and escalation authorities."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_NOTIFICATION_RESPONSE_TIMEOUT_SECONDS = 7 * 24 * 60 * 60
MAX_M8_NOTIFICATION_DELIVERY_ATTEMPTS = 10


class M8NotificationStatus(StrEnum):
    PLANNED = "PLANNED"
    QUEUED = "QUEUED"
    SENT = "SENT"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESPONDED = "RESPONDED"


class M8NotificationChannelKind(StrEnum):
    DINGTALK = "DINGTALK"
    FEISHU = "FEISHU"
    LOCAL_OFFLINE_FAKE = "LOCAL_OFFLINE_FAKE"
    WECHAT_WORK = "WECHAT_WORK"


class M8NotificationPurpose(StrEnum):
    APPEAL_OUTCOME = "APPEAL_OUTCOME"
    APPEAL_UPDATED = "APPEAL_UPDATED"
    CASE_ACTION_REQUIRED = "CASE_ACTION_REQUIRED"
    CASE_CREATED = "CASE_CREATED"
    CASE_UPDATED = "CASE_UPDATED"
    DEVICE_ATTENTION_REQUIRED = "DEVICE_ATTENTION_REQUIRED"
    ESCALATION = "ESCALATION"
    EVIDENCE_REQUESTED = "EVIDENCE_REQUESTED"


class M8NotificationAudienceKind(StrEnum):
    CASE_SUBJECT = "CASE_SUBJECT"
    LEADER_MAJOR_EVENT = "LEADER_MAJOR_EVENT"
    OPERATIONS_DEVICE_RESPONSE = "OPERATIONS_DEVICE_RESPONSE"
    SAFETY_RESPONDER = "SAFETY_RESPONDER"


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 {name} must be timezone-aware UTC")
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
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and isinstance(claimed, datetime):
            expected = datetime.fromisoformat(str(serialized[name]).replace("Z", "+00:00"))
            if _require_utc(claimed, f"serialized {name}") != expected:
                raise ValueError(
                    f"serialized {name} conflicts with derived M8 notification authority"
                )
            continue
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 notification authority")


def _require_stable_enum_inventory(values: tuple[StrEnum, ...], name: str) -> None:
    keys = tuple(value.value for value in values)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ValueError(f"M8 {name} must be unique and use stable order")


class M8NotificationTargetAuthorityV1(FrozenContractModel):
    """Versioned privacy-safe mapping from one actor to one delivery channel."""

    schema_version: Literal["m8-notification-target-authority-v1"] = (
        "m8-notification-target-authority-v1"
    )
    actor_id: ReferenceToken
    identity_provider_id: ReferenceToken
    external_subject_binding_sha256: Sha256Hex
    channel: M8NotificationChannelKind
    authority_revision: int = Field(gt=0, strict=True)
    active: StrictBool
    inbound_response_supported: StrictBool
    manifest_id: Sha256Hex

    @field_validator("actor_id", "identity_provider_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 notification target reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("simulated", "display_badge", "target_authority_id"),
        )
        target = handler(payload)
        _verify_computed_claims(target, claims)
        return target

    @model_validator(mode="after")
    def validate_local_identity_provider(self) -> Self:
        if self.channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE:
            if self.identity_provider_id != "labcourt-local-fake":
                raise ValueError(
                    "M8 local fake target requires labcourt-local-fake identity provider"
                )
        elif self.identity_provider_id == "labcourt-local-fake":
            raise ValueError("M8 external channel cannot use the local fake identity provider")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulated(self) -> bool:
        return self.channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_badge(self) -> str:
        if self.simulated:
            return "SIMULATED · LOCAL MESSAGE"
        return f"EXTERNAL · {self.channel.value}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-target-authority",
                1,
                self.actor_id,
                self.identity_provider_id,
                self.external_subject_binding_sha256,
                self.channel,
                self.authority_revision,
                self.active,
                self.inbound_response_supported,
                self.manifest_id,
            ]
        )


class M8NotificationTemplateAuthorityV1(FrozenContractModel):
    """Versioned message-card template reference, never a Case decision rule."""

    schema_version: Literal["m8-notification-template-authority-v1"] = (
        "m8-notification-template-authority-v1"
    )
    template_id: ReferenceToken
    template_version: int = Field(gt=0, strict=True)
    locale: ReferenceToken
    effective_at: datetime
    content_document_sha256: Sha256Hex
    allowed_purposes: tuple[M8NotificationPurpose, ...] = Field(min_length=1, max_length=32)
    allowed_channels: tuple[M8NotificationChannelKind, ...] = Field(min_length=1, max_length=16)
    manifest_id: Sha256Hex

    @field_validator("template_id", "locale")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 notification template reference")

    @field_validator("effective_at")
    @classmethod
    def validate_effective_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "notification template effective_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("ordinary_document_can_define_case_rule", "template_authority_id"),
        )
        template = handler(payload)
        _verify_computed_claims(template, claims)
        return template

    @model_validator(mode="after")
    def validate_inventories(self) -> Self:
        _require_stable_enum_inventory(self.allowed_purposes, "notification template purposes")
        _require_stable_enum_inventory(self.allowed_channels, "notification template channels")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ordinary_document_can_define_case_rule(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def template_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-template-authority",
                1,
                self.template_id,
                self.template_version,
                self.locale,
                _canonical_utc(self.effective_at),
                self.content_document_sha256,
                [purpose.value for purpose in self.allowed_purposes],
                [channel.value for channel in self.allowed_channels],
                self.manifest_id,
                self.ordinary_document_can_define_case_rule,
            ]
        )


class M8NotificationEscalationPolicyAuthorityV1(FrozenContractModel):
    """Bounded response deadline and escalation routing policy."""

    schema_version: Literal["m8-notification-escalation-policy-authority-v1"] = (
        "m8-notification-escalation-policy-authority-v1"
    )
    policy_rule_id: ReferenceToken
    risk_level: M8OperationalRiskLevel
    response_timeout_seconds: int = Field(
        gt=0,
        le=MAX_M8_NOTIFICATION_RESPONSE_TIMEOUT_SECONDS,
        strict=True,
    )
    max_delivery_attempts: int = Field(
        gt=0,
        le=MAX_M8_NOTIFICATION_DELIVERY_ATTEMPTS,
        strict=True,
    )
    escalation_roles: tuple[M8ActorRole, ...] = Field(min_length=1, max_length=4)
    requires_human_send_confirmation: StrictBool
    policy_manifest_id: Sha256Hex

    @field_validator("policy_rule_id")
    @classmethod
    def validate_policy_rule_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 notification escalation policy")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("case_transition_permitted", "policy_authority_id"),
        )
        policy = handler(payload)
        _verify_computed_claims(policy, claims)
        return policy

    @model_validator(mode="after")
    def validate_escalation_roles(self) -> Self:
        _require_stable_enum_inventory(self.escalation_roles, "notification escalation roles")
        if M8ActorRole.STUDENT in self.escalation_roles:
            raise ValueError("M8 notification escalation cannot route responsibility to STUDENT")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def policy_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-escalation-policy-authority",
                1,
                self.policy_rule_id,
                self.risk_level,
                self.response_timeout_seconds,
                self.max_delivery_attempts,
                [role.value for role in self.escalation_roles],
                self.requires_human_send_confirmation,
                self.policy_manifest_id,
                self.case_transition_permitted,
            ]
        )


class M8NotificationPlanAuthorityV1(FrozenContractModel):
    """Immutable PLANNED outbox intent for one exact operational Case version."""

    schema_version: Literal["m8-notification-plan-authority-v1"] = (
        "m8-notification-plan-authority-v1"
    )
    case_id: ReferenceToken
    case_version: int = Field(gt=0, strict=True)
    case_authority_sha256: Sha256Hex
    case_status: M8OperationalCaseStatus
    case_subject_actor_id: ReferenceToken | None = None
    risk_level: M8OperationalRiskLevel
    location_id: ReferenceToken
    purpose: M8NotificationPurpose
    audience: M8NotificationAudienceKind
    target: M8NotificationTargetAuthorityV1
    template: M8NotificationTemplateAuthorityV1
    escalation_policy: M8NotificationEscalationPolicyAuthorityV1
    planned_at: datetime
    status: Literal[M8NotificationStatus.PLANNED] = M8NotificationStatus.PLANNED
    notification_manifest_id: Sha256Hex

    @field_validator("case_id", "location_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 notification plan reference")

    @field_validator("case_subject_actor_id")
    @classmethod
    def validate_subject_actor_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 notification Case subject")

    @field_validator("planned_at")
    @classmethod
    def validate_planned_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "notification planned_at")

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
                "simulated",
                "display_badge",
                "response_due_at",
                "direct_disciplinary_action_permitted",
                "case_transition_permitted",
                "external_delivery_claim_permitted",
                "notification_id",
                "idempotency_key",
            ),
        )
        plan = handler(payload)
        _verify_computed_claims(plan, claims)
        return plan

    @model_validator(mode="after")
    def validate_plan_bindings(self) -> Self:
        if not self.target.active:
            raise ValueError("M8 notification plan requires an active target authority")
        if self.target.channel not in self.template.allowed_channels:
            raise ValueError("M8 notification target channel is not allowed by the template")
        if self.purpose not in self.template.allowed_purposes:
            raise ValueError("M8 notification purpose is not allowed by the template")
        if self.planned_at < self.template.effective_at:
            raise ValueError("M8 notification cannot use a template before its effective time")
        if self.escalation_policy.risk_level != self.risk_level:
            raise ValueError("M8 notification escalation policy risk does not match the Case")
        if self.audience == M8NotificationAudienceKind.CASE_SUBJECT and (
            self.case_subject_actor_id is None or self.target.actor_id != self.case_subject_actor_id
        ):
            raise ValueError("M8 Case subject notification target must be the Case subject")
        if (
            self.audience == M8NotificationAudienceKind.LEADER_MAJOR_EVENT
            and self.risk_level
            not in {
                M8OperationalRiskLevel.SEVERE,
                M8OperationalRiskLevel.EMERGENCY,
            }
        ):
            raise ValueError("M8 leader notification is limited to major events")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulated(self) -> bool:
        return self.target.simulated

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_badge(self) -> str:
        return self.target.display_badge

    @computed_field  # type: ignore[prop-decorator]
    @property
    def response_due_at(self) -> datetime:
        return self.planned_at + timedelta(seconds=self.escalation_policy.response_timeout_seconds)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_delivery_claim_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-plan-authority",
                1,
                self.case_id,
                self.case_version,
                self.case_authority_sha256,
                self.case_status,
                self.case_subject_actor_id,
                self.risk_level,
                self.location_id,
                self.purpose,
                self.audience,
                self.target.target_authority_id,
                self.template.template_authority_id,
                self.escalation_policy.policy_authority_id,
                _canonical_utc(self.planned_at),
                self.status,
                self.notification_manifest_id,
                self.direct_disciplinary_action_permitted,
                self.case_transition_permitted,
                self.external_delivery_claim_permitted,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def idempotency_key(self) -> Sha256Hex:
        return self.notification_id


__all__ = [
    "MAX_M8_NOTIFICATION_DELIVERY_ATTEMPTS",
    "MAX_M8_NOTIFICATION_RESPONSE_TIMEOUT_SECONDS",
    "M8NotificationAudienceKind",
    "M8NotificationChannelKind",
    "M8NotificationEscalationPolicyAuthorityV1",
    "M8NotificationPlanAuthorityV1",
    "M8NotificationPurpose",
    "M8NotificationStatus",
    "M8NotificationTargetAuthorityV1",
    "M8NotificationTemplateAuthorityV1",
]
