"""Provider-specific Feishu notification preflight authorities for M8.7."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictInt,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import (
    M8ExternalIdempotencyKey,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterKind,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationChannelKind,
    M8NotificationPlanAuthorityV1,
    M8NotificationPurpose,
    M8NotificationTargetAuthorityV1,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_FEISHU_CARD_CONTENT_BYTES = 30 * 1024
MAX_M8_FEISHU_PROVIDER_UUID_CHARACTERS = 50
MAX_M8_FEISHU_RAW_RESPONSE_BYTES = 256 * 1024


class M8FeishuConformanceOutcome(StrEnum):
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RATE_LIMITED = "RATE_LIMITED"
    SUCCESS = "SUCCESS"
    TIMEOUT_UNKNOWN_DELIVERY = "TIMEOUT_UNKNOWN_DELIVERY"


class M8FeishuConformanceFailureCode(StrEnum):
    CHANNEL_TIMEOUT = "CHANNEL_TIMEOUT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RATE_LIMITED = "RATE_LIMITED"


_TITLE_BY_PURPOSE: dict[M8NotificationPurpose, str] = {
    M8NotificationPurpose.APPEAL_UPDATED: "LabCourt 申诉进展通知",
    M8NotificationPurpose.CASE_ACTION_REQUIRED: "LabCourt 安全事件操作提醒",
    M8NotificationPurpose.CASE_CREATED: "LabCourt 安全事件待核实通知",
    M8NotificationPurpose.CASE_UPDATED: "LabCourt 安全事件处理进展",
    M8NotificationPurpose.DEVICE_ATTENTION_REQUIRED: "LabCourt 设备关注提醒",
    M8NotificationPurpose.EVIDENCE_REQUESTED: "LabCourt 补充说明请求",
    M8NotificationPurpose.ESCALATION: "LabCourt 安全事件升级提醒",
}


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu {name} must be timezone-aware UTC")
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
            raise ValueError(f"serialized {name} conflicts with derived M8 Feishu authority")


class M8FeishuAdapterProfileV1(FrozenContractModel):
    """Pinned custom-app API profile that contains references, never Feishu secrets."""

    schema_version: Literal["m8-feishu-adapter-profile-v1"] = "m8-feishu-adapter-profile-v1"
    candidate: M8ProductionAdapterCandidateAuthorityV1
    credential_bundle_reference_id: ReferenceToken
    app_id_sha256: Sha256Hex
    api_origin: Literal["https://open.feishu.cn"] = "https://open.feishu.cn"
    token_path: Literal["/open-apis/auth/v3/tenant_access_token/internal"] = (
        "/open-apis/auth/v3/tenant_access_token/internal"
    )
    message_path: Literal["/open-apis/im/v1/messages"] = "/open-apis/im/v1/messages"
    authentication_kind: Literal["TENANT_ACCESS_TOKEN_INTERNAL"] = "TENANT_ACCESS_TOKEN_INTERNAL"
    required_scope: Literal["im:message:send_as_bot"] = "im:message:send_as_bot"
    receive_id_type: Literal["open_id"] = "open_id"
    provider_uuid_max_characters: Literal[50] = 50
    provider_uuid_dedup_window_seconds: Literal[3600] = 3_600
    max_card_content_bytes: Literal[30720] = 30_720
    token_cache_required: Literal[True] = True
    raw_response_required: Literal[True] = True
    bot_capability_required: Literal[True] = True
    published_app_version_required: Literal[True] = True
    secret_material_embedded: Literal[False] = False
    external_call_permitted: Literal[False] = False
    profile_manifest_id: Sha256Hex

    @field_validator("credential_bundle_reference_id")
    @classmethod
    def validate_credential_reference(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu credential bundle")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("profile_id",))
        profile = handler(payload)
        _verify_computed_claims(profile, claims)
        return profile

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        candidate = self.candidate
        if (
            candidate.adapter_kind != M8ProductionAdapterKind.EXTERNAL_NOTIFICATION
            or candidate.provider_id != "feishu-open-platform"
            or candidate.idempotency_key != M8ExternalIdempotencyKey.NOTIFICATION_ID
            or not candidate.network_required
        ):
            raise ValueError("M8 Feishu profile requires a Feishu external notification candidate")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def profile_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-adapter-profile",
                1,
                self.candidate.candidate_authority_id,
                self.credential_bundle_reference_id,
                self.app_id_sha256,
                self.api_origin,
                self.token_path,
                self.message_path,
                self.authentication_kind,
                self.required_scope,
                self.receive_id_type,
                self.provider_uuid_max_characters,
                self.provider_uuid_dedup_window_seconds,
                self.max_card_content_bytes,
                self.token_cache_required,
                self.raw_response_required,
                self.bot_capability_required,
                self.published_app_version_required,
                self.secret_material_embedded,
                self.external_call_permitted,
                self.profile_manifest_id,
            ]
        )


class M8FeishuRecipientBindingAuthorityV1(FrozenContractModel):
    """Authorized target-to-open-ID hash binding without persisting the clear identifier."""

    schema_version: Literal["m8-feishu-recipient-binding-authority-v1"] = (
        "m8-feishu-recipient-binding-authority-v1"
    )
    target: M8NotificationTargetAuthorityV1
    profile_id: Sha256Hex
    receive_id_type: Literal["open_id"] = "open_id"
    receive_id_reference: ReferenceToken
    receive_id_sha256: Sha256Hex
    mapping_revision: int = Field(gt=0, strict=True)
    active: StrictBool
    mapping_manifest_id: Sha256Hex

    @field_validator("receive_id_reference")
    @classmethod
    def validate_receive_id_reference(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu open ID mapping")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("clear_receive_id_persisted", "binding_authority_id"),
        )
        binding = handler(payload)
        _verify_computed_claims(binding, claims)
        return binding

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.target.channel != M8NotificationChannelKind.FEISHU:
            raise ValueError("M8 Feishu recipient binding requires a FEISHU target")
        if self.receive_id_sha256 != self.target.external_subject_binding_sha256:
            raise ValueError("M8 Feishu receive ID hash conflicts with target subject binding")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def clear_receive_id_persisted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def binding_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-recipient-binding-authority",
                1,
                self.target.target_authority_id,
                self.profile_id,
                self.receive_id_type,
                self.receive_id_reference,
                self.receive_id_sha256,
                self.mapping_revision,
                self.active,
                self.mapping_manifest_id,
                self.clear_receive_id_persisted,
            ]
        )


class M8FeishuNotificationCardV1(FrozenContractModel):
    """Deterministic Feishu interactive-card content derived from an exact M8 plan."""

    schema_version: Literal["m8-feishu-notification-card-v1"] = "m8-feishu-notification-card-v1"
    plan: M8NotificationPlanAuthorityV1
    card_renderer_manifest_id: Sha256Hex

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
                "msg_type",
                "provider_content_json",
                "provider_content_sha256",
                "provider_content_size_bytes",
                "reply_event_type",
                "reply_event_contract_activated",
                "real_send_confirmed",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "card_id",
                "raw_card_ref",
            ),
        )
        card = handler(payload)
        _verify_computed_claims(card, claims)
        return card

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if self.plan.target.channel != M8NotificationChannelKind.FEISHU or self.plan.simulated:
            raise ValueError("M8 Feishu card requires a non-simulated FEISHU plan")
        if self.provider_content_size_bytes > MAX_M8_FEISHU_CARD_CONTENT_BYTES:
            raise ValueError("M8 Feishu interactive card exceeds the official content bound")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def msg_type(self) -> str:
        return "interactive"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_content_json(self) -> str:
        title = _TITLE_BY_PURPOSE[self.plan.purpose]
        markdown = "\n".join(
            (
                f"**风险等级**: {self.plan.risk_level.value}",
                f"**案件状态**: {self.plan.case_status.value}",
                f"**地点引用**: {self.plan.location_id}",
                f"**案件引用**: {self.plan.case_id[:16]}",
                "本事件仍待有权限人员核实; AI 输出不作为定责或处分依据。",
                "如需说明或申诉, 请直接回复本消息; 回复只作为补充材料。",
            )
        )
        return canonical_json(
            {
                "elements": ({"content": markdown, "tag": "markdown"},),
                "header": {
                    "title": {
                        "content": title,
                        "tag": "plain_text",
                    }
                },
            }
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_content_sha256(self) -> Sha256Hex:
        return hashlib.sha256(self.provider_content_json.encode("utf-8")).hexdigest()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_content_size_bytes(self) -> int:
        return len(self.provider_content_json.encode("utf-8"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reply_event_type(self) -> str:
        return "im.message.receive_v1"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reply_event_contract_activated(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def real_send_confirmed(self) -> bool:
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
    def card_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-notification-card",
                1,
                self.plan.notification_id,
                self.plan.case_id,
                self.plan.case_version,
                self.plan.case_authority_sha256,
                self.plan.target.target_authority_id,
                self.plan.template.template_authority_id,
                self.msg_type,
                self.provider_content_sha256,
                self.provider_content_size_bytes,
                self.reply_event_type,
                self.reply_event_contract_activated,
                self.card_renderer_manifest_id,
                self.real_send_confirmed,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_card_ref(self) -> ReferenceToken:
        return f"m8-feishu-card-{self.card_id[:48]}"


class M8FeishuCardDispatchPreflightV1(FrozenContractModel):
    """Exact outbox/card/recipient envelope that still cannot perform an external call."""

    schema_version: Literal["m8-feishu-card-dispatch-preflight-v1"] = (
        "m8-feishu-card-dispatch-preflight-v1"
    )
    notification_request: M8NotificationDispatchRequestV1
    profile: M8FeishuAdapterProfileV1
    recipient_binding: M8FeishuRecipientBindingAuthorityV1
    card: M8FeishuNotificationCardV1
    preflight_manifest_id: Sha256Hex

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
                "provider_endpoint",
                "provider_uuid",
                "msg_type",
                "content_is_json_encoded_string",
                "external_call_permitted",
                "notification_transition_permitted",
                "preflight_id",
            ),
        )
        preflight = handler(payload)
        _verify_computed_claims(preflight, claims)
        return preflight

    @model_validator(mode="after")
    def validate_exact_bindings(self) -> Self:
        request = self.notification_request
        candidate = self.profile.candidate
        capability = request.channel_capability
        if (
            request.plan.target.channel != M8NotificationChannelKind.FEISHU
            or request.plan.simulated
        ):
            raise ValueError("M8 Feishu preflight requires a non-simulated FEISHU request")
        if (
            capability.adapter_id != candidate.adapter_id
            or capability.adapter_revision != candidate.adapter_revision
            or capability.adapter_manifest_id != candidate.adapter_manifest_id
            or capability.request_timeout_ms != candidate.request_timeout_ms
        ):
            raise ValueError("M8 Feishu request capability conflicts with adapter candidate")
        if self.recipient_binding.profile_id != self.profile.profile_id:
            raise ValueError("M8 Feishu recipient binding belongs to another profile")
        if (
            not self.recipient_binding.active
            or not self.recipient_binding.target.active
            or self.recipient_binding.target != request.plan.target
        ):
            raise ValueError("M8 Feishu recipient binding is not current for the plan target")
        if self.card.plan != request.plan:
            raise ValueError("M8 Feishu card belongs to another notification plan")
        if (
            request.rendered_card_ref != self.card.raw_card_ref
            or request.rendered_card_sha256 != self.card.provider_content_sha256
        ):
            raise ValueError("M8 Feishu rendered card does not bind exact provider content")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_endpoint(self) -> str:
        return (
            f"{self.profile.api_origin}{self.profile.message_path}"
            f"?receive_id_type={self.profile.receive_id_type}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_uuid(self) -> str:
        return f"lc-{self.notification_request.plan.notification_id[:47]}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def msg_type(self) -> str:
        return self.card.msg_type

    @computed_field  # type: ignore[prop-decorator]
    @property
    def content_is_json_encoded_string(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_call_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def preflight_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-card-dispatch-preflight",
                1,
                self.notification_request.dispatch_request_id,
                self.profile.profile_id,
                self.recipient_binding.binding_authority_id,
                self.card.card_id,
                self.provider_endpoint,
                self.provider_uuid,
                self.msg_type,
                self.content_is_json_encoded_string,
                self.preflight_manifest_id,
                self.external_call_permitted,
                self.notification_transition_permitted,
            ]
        )


class M8FeishuConformanceResultV1(FrozenContractModel):
    """Synthetic provider-shaped response that can never claim or commit a real send."""

    schema_version: Literal["m8-feishu-conformance-result-v1"] = "m8-feishu-conformance-result-v1"
    preflight: M8FeishuCardDispatchPreflightV1
    outcome: M8FeishuConformanceOutcome
    disposition: M8NotificationDispatchDisposition
    provider_http_status: StrictInt | None = None
    provider_code: StrictInt | None = None
    provider_message_id: ReferenceToken | None = None
    provider_log_id: ReferenceToken | None = None
    failure_code: M8FeishuConformanceFailureCode | None = None
    completed_at: datetime
    raw_response_ref: ReferenceToken
    raw_response_sha256: Sha256Hex
    raw_response_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_FEISHU_RAW_RESPONSE_BYTES,
        strict=True,
    )
    simulated: Literal[True] = True
    conformance_manifest_id: Sha256Hex

    @field_validator("provider_message_id", "provider_log_id", "raw_response_ref")
    @classmethod
    def validate_references(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 Feishu conformance reference")

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "conformance completed_at")

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
                "provider_acceptance_simulated",
                "real_send_confirmed",
                "delivery_confirmed",
                "notification_transition_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "conformance_result_id",
            ),
        )
        result = handler(payload)
        _verify_computed_claims(result, claims)
        return result

    @model_validator(mode="after")
    def validate_result_shape(self) -> Self:
        if self.completed_at < self.preflight.notification_request.dispatched_at:
            raise ValueError("M8 Feishu conformance cannot complete before dispatch")
        expected = {
            M8FeishuConformanceOutcome.SUCCESS: (
                M8NotificationDispatchDisposition.ACCEPTED,
                200,
                0,
                True,
                None,
            ),
            M8FeishuConformanceOutcome.PERMISSION_DENIED: (
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                400,
                230035,
                False,
                M8FeishuConformanceFailureCode.PERMISSION_DENIED,
            ),
            M8FeishuConformanceOutcome.RATE_LIMITED: (
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                400,
                230020,
                False,
                M8FeishuConformanceFailureCode.RATE_LIMITED,
            ),
            M8FeishuConformanceOutcome.TIMEOUT_UNKNOWN_DELIVERY: (
                M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
                None,
                None,
                False,
                M8FeishuConformanceFailureCode.CHANNEL_TIMEOUT,
            ),
        }[self.outcome]
        disposition, http_status, code, needs_message_id, failure = expected
        if (
            self.disposition != disposition
            or self.provider_http_status != http_status
            or self.provider_code != code
            or (self.provider_message_id is not None) != needs_message_id
            or self.failure_code != failure
        ):
            raise ValueError("M8 Feishu conformance result conflicts with its outcome shape")
        if self.outcome == M8FeishuConformanceOutcome.TIMEOUT_UNKNOWN_DELIVERY:
            if self.provider_log_id is not None:
                raise ValueError("M8 Feishu timeout cannot claim a provider log ID")
        elif self.provider_log_id is None:
            raise ValueError("M8 Feishu provider response requires x-tt-logid reference")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_acceptance_simulated(self) -> bool:
        return self.outcome == M8FeishuConformanceOutcome.SUCCESS

    @computed_field  # type: ignore[prop-decorator]
    @property
    def real_send_confirmed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def delivery_confirmed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_transition_permitted(self) -> bool:
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
    def conformance_result_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-conformance-result",
                1,
                self.preflight.preflight_id,
                self.outcome,
                self.disposition,
                self.provider_http_status,
                self.provider_code,
                self.provider_message_id,
                self.provider_log_id,
                self.failure_code,
                _canonical_utc(self.completed_at),
                self.raw_response_ref,
                self.raw_response_sha256,
                self.raw_response_size_bytes,
                self.simulated,
                self.conformance_manifest_id,
                self.provider_acceptance_simulated,
                self.real_send_confirmed,
                self.delivery_confirmed,
                self.notification_transition_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = [
    "MAX_M8_FEISHU_CARD_CONTENT_BYTES",
    "MAX_M8_FEISHU_PROVIDER_UUID_CHARACTERS",
    "MAX_M8_FEISHU_RAW_RESPONSE_BYTES",
    "M8FeishuAdapterProfileV1",
    "M8FeishuCardDispatchPreflightV1",
    "M8FeishuConformanceFailureCode",
    "M8FeishuConformanceOutcome",
    "M8FeishuConformanceResultV1",
    "M8FeishuNotificationCardV1",
    "M8FeishuRecipientBindingAuthorityV1",
]
