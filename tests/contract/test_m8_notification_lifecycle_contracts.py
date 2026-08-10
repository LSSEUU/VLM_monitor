from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationChannelFailureCode,
    M8NotificationDeliveryDisposition,
    M8NotificationDeliveryReceiptV1,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
    M8NotificationInitiatorKind,
    M8NotificationReplyAuthorityV1,
    M8NotificationReplyKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationAudienceKind,
    M8NotificationChannelKind,
    M8NotificationEscalationPolicyAuthorityV1,
    M8NotificationPlanAuthorityV1,
    M8NotificationPurpose,
    M8NotificationStatus,
    M8NotificationTargetAuthorityV1,
    M8NotificationTemplateAuthorityV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)


def _target(
    channel: M8NotificationChannelKind = M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
) -> M8NotificationTargetAuthorityV1:
    return M8NotificationTargetAuthorityV1(
        actor_id="student-01",
        identity_provider_id=(
            "labcourt-local-fake"
            if channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
            else "campus-idp"
        ),
        external_subject_binding_sha256=SHA_A,
        channel=channel,
        authority_revision=1,
        active=True,
        inbound_response_supported=True,
        manifest_id=SHA_B,
    )


def _plan(
    channel: M8NotificationChannelKind = M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
) -> M8NotificationPlanAuthorityV1:
    target = _target(channel)
    return M8NotificationPlanAuthorityV1(
        case_id=SHA_A,
        case_version=2,
        case_authority_sha256=SHA_B,
        case_status=M8OperationalCaseStatus.EVIDENCE_REQUESTED,
        case_subject_actor_id="student-01",
        risk_level=M8OperationalRiskLevel.GENERAL,
        location_id="room-chem-301",
        purpose=M8NotificationPurpose.EVIDENCE_REQUESTED,
        audience=M8NotificationAudienceKind.CASE_SUBJECT,
        target=target,
        template=M8NotificationTemplateAuthorityV1(
            template_id="case-student-card",
            template_version=1,
            locale="zh-CN",
            effective_at=BASE_TIME - timedelta(days=1),
            content_document_sha256=SHA_B,
            allowed_purposes=(M8NotificationPurpose.EVIDENCE_REQUESTED,),
            allowed_channels=(channel,),
            manifest_id=SHA_C,
        ),
        escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
            policy_rule_id="general-student-response-v1",
            risk_level=M8OperationalRiskLevel.GENERAL,
            response_timeout_seconds=3600,
            max_delivery_attempts=3,
            escalation_roles=(M8ActorRole.SAFETY_OFFICER,),
            requires_human_send_confirmation=True,
            policy_manifest_id=SHA_C,
        ),
        planned_at=BASE_TIME,
        notification_manifest_id=SHA_D,
    )


def _capability(
    channel: M8NotificationChannelKind = M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
) -> M8NotificationChannelCapabilityAuthorityV1:
    simulated = channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
    return M8NotificationChannelCapabilityAuthorityV1(
        adapter_id=("m8-local-message-fake" if simulated else "m8-feishu-adapter"),
        adapter_revision="v1",
        channel=channel,
        request_timeout_ms=1000,
        network_required=not simulated,
        offline_capable=simulated,
        simulated=simulated,
        inbound_response_supported=True,
        adapter_manifest_id=SHA_D,
    )


def _dispatch_request(
    channel: M8NotificationChannelKind = M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
) -> M8NotificationDispatchRequestV1:
    plan = _plan(channel)
    return M8NotificationDispatchRequestV1(
        plan=plan,
        source_notification_version=2,
        source_notification_authority_sha256=SHA_C,
        attempt_number=1,
        channel_capability=_capability(channel),
        rendered_card_ref="notification-card-01",
        rendered_card_sha256=SHA_D,
        dispatched_at=BASE_TIME + timedelta(minutes=1),
        timeout_ms=1000,
        idempotency_key=plan.notification_id,
        request_manifest_id=SHA_E,
    )


def _dispatch_result(
    *,
    disposition: M8NotificationDispatchDisposition = M8NotificationDispatchDisposition.ACCEPTED,
) -> M8NotificationDispatchResultV1:
    return M8NotificationDispatchResultV1(
        request=_dispatch_request(),
        disposition=disposition,
        provider_receipt_id=(
            "local-message-receipt-01"
            if disposition == M8NotificationDispatchDisposition.ACCEPTED
            else None
        ),
        raw_response_ref="raw-notification-response-01",
        raw_response_sha256=SHA_E,
        failure_code=(
            None
            if disposition == M8NotificationDispatchDisposition.ACCEPTED
            else M8NotificationChannelFailureCode.CHANNEL_REJECTED
        ),
        completed_at=BASE_TIME + timedelta(minutes=1, seconds=1),
        result_manifest_id=SHA_E,
    )


def _delivery(
    *,
    disposition: M8NotificationDeliveryDisposition = M8NotificationDeliveryDisposition.DELIVERED,
    channel: M8NotificationChannelKind = M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
) -> M8NotificationDeliveryReceiptV1:
    dispatch = _dispatch_result()
    return M8NotificationDeliveryReceiptV1(
        notification_id=dispatch.request.plan.notification_id,
        dispatch_result_id=dispatch.dispatch_result_id,
        target_authority_id=dispatch.request.plan.target.target_authority_id,
        channel=channel,
        disposition=disposition,
        provider_delivery_id=(
            "local-delivery-01"
            if disposition == M8NotificationDeliveryDisposition.DELIVERED
            else None
        ),
        failure_code=(
            None
            if disposition == M8NotificationDeliveryDisposition.DELIVERED
            else M8NotificationChannelFailureCode.DELIVERY_REJECTED
        ),
        occurred_at=BASE_TIME + timedelta(minutes=2),
        raw_response_ref="raw-delivery-response-01",
        raw_response_sha256=SHA_A,
        simulated=channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
        receipt_manifest_id=SHA_E,
    )


def _reply() -> M8NotificationReplyAuthorityV1:
    plan = _plan()
    return M8NotificationReplyAuthorityV1(
        notification_id=plan.notification_id,
        target_authority_id=plan.target.target_authority_id,
        actor_id="student-01",
        channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
        reply_kind=M8NotificationReplyKind.EXPLANATION,
        reply_document_sha256=SHA_B,
        raw_reply_ref="raw-notification-reply-01",
        raw_reply_sha256=SHA_C,
        received_at=BASE_TIME + timedelta(minutes=3),
        simulated=True,
        reply_manifest_id=SHA_D,
    )


def _actor(role: M8ActorRole) -> M8ActorAuthorityV1:
    actor_id = "student-01" if role == M8ActorRole.STUDENT else "safety-officer-01"
    return M8ActorAuthorityV1(
        actor_id=actor_id,
        role=role,
        scope_kind=(
            M8ActorScopeKind.SELF_ONLY
            if role == M8ActorRole.STUDENT
            else M8ActorScopeKind.LOCATIONS
        ),
        scope_location_ids=(() if role == M8ActorRole.STUDENT else ("room-chem-301",)),
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=1,
        active=True,
        manifest_id=SHA_B,
    )


def _support() -> tuple[M8AuthorityReference, ...]:
    return (
        M8AuthorityReference(
            kind=M8AuthorityReferenceKind.NOTIFICATION_REPLY,
            authority_id="notification-support-01",
            document_sha256=SHA_E,
        ),
    )


def _command(
    *,
    action: M8NotificationAction,
    source_status: M8NotificationStatus,
    source_version: int,
    initiator_kind: M8NotificationInitiatorKind,
    actor: M8ActorAuthorityV1 | None = None,
    system_authority_id: str | None = None,
    dispatch: M8NotificationDispatchResultV1 | None = None,
    delivery: M8NotificationDeliveryReceiptV1 | None = None,
    reply: M8NotificationReplyAuthorityV1 | None = None,
) -> M8NotificationTransitionCommandV1:
    return M8NotificationTransitionCommandV1(
        notification_id=_plan().notification_id,
        source_notification_version=source_version,
        source_notification_authority_sha256=(
            dispatch.request.source_notification_authority_sha256 if dispatch is not None else SHA_D
        ),
        source_status=source_status,
        action=action,
        initiator_kind=initiator_kind,
        actor_authority=actor,
        system_authority_id=system_authority_id,
        dispatch_result=dispatch,
        delivery_receipt=delivery,
        reply=reply,
        supporting_authorities=_support(),
        explicit_human_confirmation=initiator_kind == M8NotificationInitiatorKind.ACTOR,
        occurred_at=BASE_TIME + timedelta(minutes=4),
        command_manifest_id=SHA_E,
    )


def test_local_capability_is_offline_bounded_and_unforgeable() -> None:
    capability = _capability()

    assert capability.network_required is False
    assert capability.offline_capable is True
    assert capability.simulated is True
    assert len(capability.capability_authority_id) == 64

    payload = capability.model_dump(mode="json", exclude={"capability_authority_id"})
    payload["network_required"] = True
    with pytest.raises(ValidationError, match="offline"):
        M8NotificationChannelCapabilityAuthorityV1.model_validate(payload)
    payload = capability.model_dump(mode="json")
    payload["capability_authority_id"] = SHA_A
    with pytest.raises(ValidationError, match="capability_authority_id"):
        M8NotificationChannelCapabilityAuthorityV1.model_validate(payload)


def test_dispatch_binds_card_channel_timeout_idempotency_and_raw_result() -> None:
    request = _dispatch_request()
    result = _dispatch_result()

    assert request.idempotency_key == request.plan.notification_id
    assert request.external_delivery_claim_permitted is False
    assert result.accepted is True
    assert result.simulated is True
    assert result.real_delivery_confirmed is False
    assert len(result.dispatch_result_id) == 64

    payload = request.model_dump(
        mode="json", exclude={"external_delivery_claim_permitted", "dispatch_request_id"}
    )
    payload["timeout_ms"] = 999
    with pytest.raises(ValidationError, match="timeout"):
        M8NotificationDispatchRequestV1.model_validate(payload)
    with pytest.raises(ValidationError, match="typed failure"):
        M8NotificationDispatchResultV1(
            **{
                **result.model_dump(
                    mode="python",
                    exclude={
                        "accepted",
                        "simulated",
                        "real_delivery_confirmed",
                        "dispatch_result_id",
                    },
                ),
                "disposition": M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                "provider_receipt_id": None,
            }
        )


def test_delivery_and_reply_preserve_simulation_and_never_change_case() -> None:
    delivery = _delivery()
    reply = _reply()

    assert delivery.real_delivery_confirmed is False
    assert delivery.case_transition_permitted is False
    assert reply.direct_disciplinary_action_permitted is False
    assert reply.case_transition_permitted is False

    external = _delivery(channel=M8NotificationChannelKind.FEISHU)
    assert external.real_delivery_confirmed is True
    payload = reply.model_dump(mode="json")
    payload["case_transition_permitted"] = True
    with pytest.raises(ValidationError, match="case_transition_permitted"):
        M8NotificationReplyAuthorityV1.model_validate(payload)


def test_lifecycle_commands_cover_closed_state_graph_without_case_authority() -> None:
    queue = _command(
        action=M8NotificationAction.QUEUE,
        source_status=M8NotificationStatus.PLANNED,
        source_version=1,
        initiator_kind=M8NotificationInitiatorKind.SYSTEM,
        system_authority_id=SHA_A,
    )
    sent = _command(
        action=M8NotificationAction.RECORD_SENT,
        source_status=M8NotificationStatus.QUEUED,
        source_version=2,
        initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
        dispatch=_dispatch_result(),
    )
    delivered = _command(
        action=M8NotificationAction.RECORD_DELIVERED,
        source_status=M8NotificationStatus.SENT,
        source_version=3,
        initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
        delivery=_delivery(),
    )
    acknowledged = _command(
        action=M8NotificationAction.ACKNOWLEDGE,
        source_status=M8NotificationStatus.DELIVERED,
        source_version=4,
        initiator_kind=M8NotificationInitiatorKind.ACTOR,
        actor=_actor(M8ActorRole.STUDENT),
    )
    responded = _command(
        action=M8NotificationAction.RESPOND,
        source_status=M8NotificationStatus.ACKNOWLEDGED,
        source_version=5,
        initiator_kind=M8NotificationInitiatorKind.ACTOR,
        actor=_actor(M8ActorRole.STUDENT),
        reply=_reply(),
    )

    assert tuple(
        command.target_status for command in (queue, sent, delivered, acknowledged, responded)
    ) == (
        M8NotificationStatus.QUEUED,
        M8NotificationStatus.SENT,
        M8NotificationStatus.DELIVERED,
        M8NotificationStatus.ACKNOWLEDGED,
        M8NotificationStatus.RESPONDED,
    )
    assert all(command.case_transition_permitted is False for command in (queue, sent, delivered))
    assert responded.target_notification_version == 6
    assert len(responded.command_id) == 64


def test_failure_retry_and_initiator_boundaries_fail_closed() -> None:
    failed = _command(
        action=M8NotificationAction.RECORD_FAILED,
        source_status=M8NotificationStatus.QUEUED,
        source_version=2,
        initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
        dispatch=_dispatch_result(
            disposition=M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
        ),
    )
    retry = _command(
        action=M8NotificationAction.RETRY,
        source_status=M8NotificationStatus.FAILED,
        source_version=3,
        initiator_kind=M8NotificationInitiatorKind.ACTOR,
        actor=_actor(M8ActorRole.SAFETY_OFFICER),
    )
    assert failed.target_status == M8NotificationStatus.FAILED
    assert retry.target_status == M8NotificationStatus.QUEUED

    with pytest.raises(ValidationError, match="SAFETY_OFFICER"):
        _command(
            action=M8NotificationAction.RETRY,
            source_status=M8NotificationStatus.FAILED,
            source_version=3,
            initiator_kind=M8NotificationInitiatorKind.ACTOR,
            actor=_actor(M8ActorRole.STUDENT),
        )
    with pytest.raises(ValidationError, match="source status"):
        _command(
            action=M8NotificationAction.RECORD_SENT,
            source_status=M8NotificationStatus.PLANNED,
            source_version=1,
            initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
            dispatch=_dispatch_result(),
        )


@pytest.mark.parametrize(
    "model",
    (
        _capability(),
        _dispatch_request(),
        _dispatch_result(),
        _delivery(),
        _reply(),
        _command(
            action=M8NotificationAction.QUEUE,
            source_status=M8NotificationStatus.PLANNED,
            source_version=1,
            initiator_kind=M8NotificationInitiatorKind.SYSTEM,
            system_authority_id=SHA_A,
        ),
    ),
)
def test_lifecycle_authorities_round_trip_and_validate_serialization_schema(
    model: M8NotificationChannelCapabilityAuthorityV1
    | M8NotificationDispatchRequestV1
    | M8NotificationDispatchResultV1
    | M8NotificationDeliveryReceiptV1
    | M8NotificationReplyAuthorityV1
    | M8NotificationTransitionCommandV1,
) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )
