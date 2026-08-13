from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_agent_chat import (
    M8AgentConversationCreateRequestV1,
    M8AgentConversationRemovalReceiptV1,
    M8AgentExecutionMode,
    M8AgentFailureCode,
    M8AgentModelCallReceiptV1,
    M8AgentModelProfileV1,
    M8AgentStreamEventKind,
    M8AgentStreamEventV1,
    M8AgentTurnRequestV1,
)


def _sha(value: str) -> str:
    return value * 64


def test_conversation_removal_receipt_is_closed_and_audit_retained() -> None:
    receipt = M8AgentConversationRemovalReceiptV1(
        removal_receipt_id=_sha("a"),
        conversation_id=_sha("b"),
        actor_id="actor-safety",
        actor_authority_commit_receipt_id=_sha("c"),
        removed_at=datetime(2026, 8, 13, tzinfo=UTC),
    )
    assert receipt.retained_for_audit is True
    with pytest.raises(ValidationError):
        M8AgentConversationRemovalReceiptV1.model_validate(
            {**receipt.model_dump(mode="python"), "retained_for_audit": False}
        )


def test_agent_turn_request_is_closed_and_rejects_blank_text() -> None:
    assert M8AgentConversationCreateRequestV1().schema_version.endswith("-v1")
    assert M8AgentTurnRequestV1(query="查看设备状态").query == "查看设备状态"
    with pytest.raises(ValidationError):
        M8AgentTurnRequestV1(query="   ")
    with pytest.raises(ValidationError):
        M8AgentTurnRequestV1.model_validate({"query": "案件", "extra": True})


def test_agent_model_profile_requires_live_qwen_and_disables_cache_replay() -> None:
    profile = M8AgentModelProfileV1(
        profile_id=_sha("a"),
        prompt_manifest_id=_sha("b"),
        tool_schema_manifest_id=_sha("c"),
        model_manifest_id=_sha("d"),
    )
    assert profile.reply_policy == "LIVE_ONLY"
    assert profile.cache_enabled is False
    with pytest.raises(ValidationError):
        M8AgentModelProfileV1.model_validate(
            {**profile.model_dump(mode="python"), "cache_enabled": True}
        )


def test_model_receipt_and_stream_event_enforce_terminal_shapes() -> None:
    receipt = M8AgentModelCallReceiptV1(
        model_call_id=_sha("a"),
        round_index=1,
        cache_key=_sha("b"),
        provider_profile_id=_sha("c"),
        model_manifest_id=_sha("d"),
        prompt_manifest_id=_sha("e"),
        tool_schema_manifest_id=_sha("f"),
        raw_response_ref=_sha("1"),
        raw_response_sha256=_sha("2"),
        input_tokens=12,
        output_tokens=4,
        cache_hit=False,
        completed=False,
        failure_code=M8AgentFailureCode.STREAM_INTERRUPTED,
    )
    assert receipt.failure_code == M8AgentFailureCode.STREAM_INTERRUPTED
    assert M8AgentExecutionMode.LIVE_QWEN.value == "LIVE_QWEN"
    with pytest.raises(ValidationError):
        M8AgentModelCallReceiptV1.model_validate(
            {**receipt.model_dump(mode="python"), "completed": True}
        )
    with pytest.raises(ValidationError):
        M8AgentStreamEventV1(
            event_kind=M8AgentStreamEventKind.MESSAGE_DELTA,
            conversation_id=_sha("3"),
            turn_id=_sha("4"),
            event_index=1,
        )
    failed = M8AgentStreamEventV1(
        event_kind=M8AgentStreamEventKind.TURN_FAILED,
        conversation_id=_sha("3"),
        turn_id=_sha("4"),
        event_index=2,
        failure_code=M8AgentFailureCode.PROVIDER_TIMEOUT,
    )
    assert failed.model_dump(mode="json")["failure_code"] == "PROVIDER_TIMEOUT"
    assert datetime.now(UTC).tzinfo is UTC
