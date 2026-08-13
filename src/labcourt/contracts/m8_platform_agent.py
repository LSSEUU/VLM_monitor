"""Closed, additive V2 contracts for the modular offline platform Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8OperationalCaseStatus
from labcourt.contracts.m8_feishu_platform import M8FeishuTestCardCheckRequestV1
from labcourt.contracts.m8_knowledge_projection import M8KnowledgeQueryProjectionV1
from labcourt.contracts.m8_platform_demo import M8PlatformScenarioKind
from labcourt.contracts.references import ReferenceToken, require_reference_token


class M8PlatformAgentIntentV2(StrEnum):
    CASE_QUERY = "CASE_QUERY"
    CASE_TRANSITION_ACTION = "CASE_TRANSITION_ACTION"
    DELIVERY_STATUS_QUERY = "DELIVERY_STATUS_QUERY"
    DEVICE_QUERY = "DEVICE_QUERY"
    FEISHU_STATUS_QUERY = "FEISHU_STATUS_QUERY"
    FEISHU_TEST_CARD_ACTION = "FEISHU_TEST_CARD_ACTION"
    KNOWLEDGE_QUERY = "KNOWLEDGE_QUERY"
    MAP_QUERY = "MAP_QUERY"
    NOTIFICATION_QUERY = "NOTIFICATION_QUERY"
    NOTIFICATION_SEND_ACTION = "NOTIFICATION_SEND_ACTION"
    RESET_ACTION = "RESET_ACTION"
    SCENARIO_ACTION = "SCENARIO_ACTION"
    SENSOR_QUERY = "SENSOR_QUERY"
    UNKNOWN = "UNKNOWN"


class M8PlatformAgentActionKindV2(StrEnum):
    CASE_TRANSITION = "CASE_TRANSITION"
    FEISHU_TEST_CARD_CHECK = "FEISHU_TEST_CARD_CHECK"
    NOTIFICATION_SEND = "NOTIFICATION_SEND"
    RESET_DEMO = "RESET_DEMO"
    RUN_SCENARIO = "RUN_SCENARIO"


class M8AgentCaseTransitionPayloadV2(FrozenContractModel):
    action: Literal["CONFIRM"]
    source_case_version: int = Field(gt=0, strict=True)
    source_case_authority_sha256: Sha256Hex
    source_status: Literal[M8OperationalCaseStatus.PENDING_VERIFICATION]
    explicit_human_confirmation: Literal[True]


class M8AgentRunScenarioPayloadV2(FrozenContractModel):
    scenario_kind: Literal[M8PlatformScenarioKind.SMOKE_TEMPERATURE_EMERGENCY]
    explicit_human_confirmation: Literal[True]


class M8AgentResetPayloadV2(FrozenContractModel):
    explicit_human_confirmation: Literal[True]


class M8AgentNotificationSendPayloadV2(FrozenContractModel):
    kind: Literal["CASE_UPDATED"]
    source_case_version: int = Field(gt=0, strict=True)
    source_case_authority_sha256: Sha256Hex
    explicit_human_confirmation: Literal[True]


class M8AgentFeishuTestCardPayloadV2(M8FeishuTestCardCheckRequestV1):
    pass


M8AgentActionPayloadV2 = (
    M8AgentCaseTransitionPayloadV2
    | M8AgentRunScenarioPayloadV2
    | M8AgentResetPayloadV2
    | M8AgentNotificationSendPayloadV2
    | M8AgentFeishuTestCardPayloadV2
)


class M8PlatformProposedActionV2(FrozenContractModel):
    schema_version: Literal["m8-platform-proposed-action-v2"] = "m8-platform-proposed-action-v2"
    action_kind: M8PlatformAgentActionKindV2
    target_ref: ReferenceToken
    endpoint_path: str = Field(min_length=1, max_length=512)
    current_version: int = Field(ge=0, strict=True)
    current_fence: Sha256Hex
    impact_summary: str = Field(min_length=1, max_length=240)
    requires_confirmation: Literal[True] = True
    request_payload: M8AgentActionPayloadV2

    @field_validator("target_ref")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return require_reference_token(value, "M8 Agent V2 target")

    @field_validator("endpoint_path")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        if not value.startswith("/api/m8/") or ".." in value or "\\" in value:
            raise ValueError("M8 Agent V2 action endpoint must remain same-origin")
        return value

    @model_validator(mode="after")
    def validate_payload_kind(self) -> Self:
        expected_type = {
            M8PlatformAgentActionKindV2.CASE_TRANSITION: M8AgentCaseTransitionPayloadV2,
            M8PlatformAgentActionKindV2.RUN_SCENARIO: M8AgentRunScenarioPayloadV2,
            M8PlatformAgentActionKindV2.RESET_DEMO: M8AgentResetPayloadV2,
            M8PlatformAgentActionKindV2.NOTIFICATION_SEND: M8AgentNotificationSendPayloadV2,
            M8PlatformAgentActionKindV2.FEISHU_TEST_CARD_CHECK: M8AgentFeishuTestCardPayloadV2,
        }[self.action_kind]
        if not isinstance(self.request_payload, expected_type):
            raise ValueError("M8 Agent V2 action kind conflicts with its closed payload")
        return self


class M8PlatformAgentQueryResponseV2(FrozenContractModel):
    schema_version: Literal["m8-platform-agent-query-response-v2"] = (
        "m8-platform-agent-query-response-v2"
    )
    outcome: Literal["ANSWERED", "NO_MATCH"]
    normalized_intent: M8PlatformAgentIntentV2
    answer: str = Field(min_length=1, max_length=2_048)
    source_refs: tuple[ReferenceToken, ...] = Field(default=(), max_length=32)
    knowledge_projection: M8KnowledgeQueryProjectionV1 | None = None
    proposed_action: M8PlatformProposedActionV2 | None = None
    model_used: Literal[False] = False
    network_used: Literal[False] = False
    direct_execution_permitted: Literal[False] = False


class M8PlatformNotificationDispatchRequestV2(FrozenContractModel):
    schema_version: Literal["m8-platform-notification-dispatch-request-v2"] = (
        "m8-platform-notification-dispatch-request-v2"
    )
    kind: Literal["CASE_UPDATED"]
    source_case_version: int = Field(gt=0, strict=True)
    source_case_authority_sha256: Sha256Hex
    explicit_human_confirmation: Literal[True]


__all__ = [
    "M8AgentActionPayloadV2",
    "M8AgentCaseTransitionPayloadV2",
    "M8AgentFeishuTestCardPayloadV2",
    "M8AgentNotificationSendPayloadV2",
    "M8AgentResetPayloadV2",
    "M8AgentRunScenarioPayloadV2",
    "M8PlatformAgentActionKindV2",
    "M8PlatformAgentIntentV2",
    "M8PlatformAgentQueryResponseV2",
    "M8PlatformNotificationDispatchRequestV2",
    "M8PlatformProposedActionV2",
]
