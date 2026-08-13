from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.contracts.m8_access_cases import M8ActorRole, M8OperationalCaseAction
from labcourt.contracts.m8_feishu_live import (
    M8FeishuCardActionIntentV1,
    M8FeishuConversationChannelProjectionV1,
    M8FeishuDutyRouteRevisionRequestV1,
    M8FeishuDutyRouteV1,
    M8FeishuInboundEventKind,
    M8FeishuInboundEventV1,
    M8FeishuInboundJobState,
    M8FeishuInboundJobV1,
    M8FeishuLiveConnectionState,
    M8FeishuRuntimeHeartbeatV1,
    M8FeishuRuntimeStatusV2,
    M8FeishuTurnOrigin,
    M8FeishuWorkerState,
)
from labcourt.contracts.m8_feishu_platform import (
    M8FeishuPlatformDisplayStatus,
    M8FeishuPlatformStatusV1,
)

NOW = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _route() -> M8FeishuDutyRouteV1:
    return M8FeishuDutyRouteV1(
        actor_id="safety-officer-demo",
        actor_role=M8ActorRole.SAFETY_OFFICER,
        actor_authority_commit_receipt_id=SHA_A,
        recipient_binding_authority_id=SHA_B,
        activation_revision=1,
        activation_status_id=SHA_C,
        route_revision=1,
        committed_at=NOW,
        repository_manifest_id=SHA_D,
    )


def _heartbeat(component: str) -> M8FeishuRuntimeHeartbeatV1:
    payload: dict[str, object] = {
        "component": component,
        "observed_at": NOW,
        "runtime_manifest_id": SHA_A,
    }
    if component == "LONG_CONNECTION":
        payload["connection_state"] = M8FeishuLiveConnectionState.READY
    else:
        payload["worker_state"] = M8FeishuWorkerState.READY
    return M8FeishuRuntimeHeartbeatV1.model_validate(payload)


def _direct_event() -> M8FeishuInboundEventV1:
    return M8FeishuInboundEventV1(
        event_kind=M8FeishuInboundEventKind.DIRECT_MESSAGE,
        provider_event_id="event-live-01",
        provider_message_id="om-live-01",
        sender_open_id_sha256=SHA_A,
        chat_id_sha256=SHA_B,
        received_at=NOW,
        raw_event_ref="feishu-live-raw-event-01",
        raw_event_sha256=SHA_C,
        content_ref="feishu-live-content-01",
        content_sha256=SHA_D,
        ingress_manifest_id=SHA_E,
    )


def test_duty_route_requires_safety_actor_current_activation_and_confirmation() -> None:
    request = M8FeishuDutyRouteRevisionRequestV1(
        actor_id="safety-officer-demo",
        recipient_binding_authority_id=SHA_B,
        activation_revision=1,
        activation_status_id=SHA_C,
        explicit_human_confirmation=True,
    )
    route = _route()
    assert request.expected_prior_revision is None
    assert route.actor_role == M8ActorRole.SAFETY_OFFICER
    assert len(route.route_id) == 64
    assert route.prior_route_id is None

    with pytest.raises(ValidationError, match="prior reference"):
        route.model_copy(update={"route_revision": 2})


def test_runtime_status_requires_every_live_gate() -> None:
    platform = M8FeishuPlatformStatusV1(
        display_status=M8FeishuPlatformDisplayStatus.NOT_CONFIGURED,
        assessed_at=NOW,
        test_card_check_available=False,
        external_call_permitted=False,
    )
    status = M8FeishuRuntimeStatusV2(
        platform=platform,
        connection=_heartbeat("LONG_CONNECTION"),
        authority_worker=_heartbeat("AUTHORITY_WORKER"),
        delivery_worker=_heartbeat("DELIVERY_WORKER"),
        duty_route=_route(),
        assessed_at=NOW,
        live_dispatch_available=False,
    )
    assert status.live_dispatch_available is False
    with pytest.raises(ValidationError, match="availability"):
        status.model_copy(update={"live_dispatch_available": True})


def test_inbound_event_is_closed_and_job_completion_binds_agent_turn() -> None:
    event = _direct_event()
    queued = M8FeishuInboundJobV1(
        inbound_event=event,
        state=M8FeishuInboundJobState.QUEUED,
        state_revision=1,
        occurred_at=NOW,
        repository_manifest_id=SHA_A,
    )
    completed = queued.model_copy(
        update={
            "state": M8FeishuInboundJobState.COMPLETED,
            "state_revision": 3,
            "actor_id": "safety-officer-demo",
            "conversation_id": SHA_B,
            "turn_id": SHA_C,
            "occurred_at": NOW + timedelta(seconds=2),
        }
    )
    assert completed.inbound_event.inbound_event_id == event.inbound_event_id
    assert completed.failure_code is None
    assert event.clear_sender_identifier_persisted is False

    with pytest.raises(ValidationError, match="requires Agent authorities"):
        queued.model_copy(
            update={"state": M8FeishuInboundJobState.COMPLETED, "state_revision": 3}
        )


def test_card_intent_is_closed_single_use_boundary_with_ten_minute_expiry() -> None:
    intent = M8FeishuCardActionIntentV1(
        notification_id=SHA_A,
        notification_version=2,
        case_id=SHA_B,
        case_version=1,
        case_authority_sha256=SHA_C,
        actor_id="safety-officer-demo",
        action=M8OperationalCaseAction.CONFIRM,
        confirmation_token_sha256=SHA_D,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        intent_manifest_id=SHA_E,
    )
    assert len(intent.intent_id) == 64
    with pytest.raises(ValidationError, match="closed first-release set"):
        intent.model_copy(update={"action": M8OperationalCaseAction.RESOLVE})
    with pytest.raises(ValidationError, match="ten minutes"):
        intent.model_copy(update={"expires_at": NOW + timedelta(minutes=11)})


def test_channel_projection_marks_only_turn_origin_without_provider_ids() -> None:
    projection = M8FeishuConversationChannelProjectionV1(
        conversation_id=SHA_A,
        actor_id="safety-officer-demo",
        binding_revision=1,
        chat_id_sha256=SHA_B,
        turn_origins={SHA_C: M8FeishuTurnOrigin.FEISHU},
        bound_at=NOW,
    )
    assert projection.channel == "FEISHU_P2P"
    assert projection.turn_origins[SHA_C] == M8FeishuTurnOrigin.FEISHU


@pytest.mark.parametrize(
    "model",
    (
        _route(),
        _heartbeat("LONG_CONNECTION"),
        _direct_event(),
        M8FeishuConversationChannelProjectionV1(
            conversation_id=SHA_A,
            actor_id="safety-officer-demo",
            binding_revision=1,
            chat_id_sha256=SHA_B,
            bound_at=NOW,
        ),
    ),
)
def test_live_contracts_are_registered_serialization_roots(model: BaseModel) -> None:
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )
