from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.m8_offline_notification_channel import (
    DeterministicOfflineNotificationChannel,
)
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseCreateCommandV1,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_case_persistence import M8OperationalCaseCommitReceiptV1
from labcourt.contracts.m8_notification_cards import (
    M8NotificationWorkflowManifestAuthorityV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationChannelCapabilityAuthorityV1,
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
from labcourt.contracts.m8_notification_persistence import M8NotificationCommitReceiptV1
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
from labcourt.exceptions import ConcurrentModification
from labcourt.services.m8_notifications import M8NotificationService

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)
BUSY_TIMEOUT_MS = 5_000


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _student(*, revision: int = 1, active: bool = True) -> M8ActorAuthorityV1:
    return M8ActorAuthorityV1(
        actor_id="student-01",
        role=M8ActorRole.STUDENT,
        scope_kind=M8ActorScopeKind.SELF_ONLY,
        scope_location_ids=(),
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=revision,
        active=active,
        manifest_id=SHA_B,
    )


def _create_command() -> M8OperationalCaseCreateCommandV1:
    return M8OperationalCaseCreateCommandV1(
        source_catalog_id=SHA_A,
        location_id="room-chem-301",
        risk_level=M8OperationalRiskLevel.GENERAL,
        policy_rule_id="missing-goggles-general-v1",
        policy_manifest_id=SHA_B,
        source_ids=("camera-simulated-01",),
        simulated_source_ids=("camera-simulated-01",),
        trigger_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.SENSOR_SIGNAL,
                authority_id="simulated-goggles-sample-01",
                document_sha256=SHA_C,
            ),
        ),
        automation_component_id="m8-offline-case-builder",
        automation_manifest_id=SHA_D,
    )


def _target(*, revision: int = 1, active: bool = True) -> M8NotificationTargetAuthorityV1:
    return M8NotificationTargetAuthorityV1(
        actor_id="student-01",
        identity_provider_id="labcourt-local-fake",
        external_subject_binding_sha256=SHA_A,
        channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
        authority_revision=revision,
        active=active,
        inbound_response_supported=True,
        manifest_id=SHA_B,
    )


def _plan(
    case: M8OperationalCaseCommitReceiptV1,
    target: M8NotificationTargetAuthorityV1,
    *,
    planned_at: datetime = BASE_TIME,
    requires_human_send_confirmation: bool = False,
) -> M8NotificationPlanAuthorityV1:
    authority = case.audit_event.case_authority
    return M8NotificationPlanAuthorityV1(
        case_id=case.case_id,
        case_version=case.case_version,
        case_authority_sha256=case.case_document_sha256,
        case_status=case.status,
        case_subject_actor_id=authority.subject_actor_id,
        risk_level=authority.risk_level,
        location_id=authority.location_id,
        purpose=M8NotificationPurpose.CASE_CREATED,
        audience=M8NotificationAudienceKind.CASE_SUBJECT,
        target=target,
        template=M8NotificationTemplateAuthorityV1(
            template_id="case-created-student-card",
            template_version=1,
            locale="zh-CN",
            effective_at=BASE_TIME - timedelta(days=1),
            content_document_sha256=SHA_B,
            allowed_purposes=(M8NotificationPurpose.CASE_CREATED,),
            allowed_channels=(M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,),
            manifest_id=SHA_C,
        ),
        escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
            policy_rule_id="general-student-response-v1",
            risk_level=authority.risk_level,
            response_timeout_seconds=3_600,
            max_delivery_attempts=3,
            escalation_roles=(M8ActorRole.SAFETY_OFFICER,),
            requires_human_send_confirmation=requires_human_send_confirmation,
            policy_manifest_id=SHA_C,
        ),
        planned_at=planned_at,
        notification_manifest_id=SHA_D,
    )


def _support(name: str) -> tuple[M8AuthorityReference, ...]:
    return (
        M8AuthorityReference(
            kind=M8AuthorityReferenceKind.NOTIFICATION_REPLY,
            authority_id=name,
            document_sha256=SHA_E,
        ),
    )


def _channel_capability() -> M8NotificationChannelCapabilityAuthorityV1:
    return M8NotificationChannelCapabilityAuthorityV1(
        adapter_id="m8-local-message-fake",
        adapter_revision="v1",
        channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
        request_timeout_ms=1_000,
        network_required=False,
        offline_capable=True,
        simulated=True,
        inbound_response_supported=True,
        adapter_manifest_id=SHA_D,
    )


def _workflow() -> M8NotificationWorkflowManifestAuthorityV1:
    return M8NotificationWorkflowManifestAuthorityV1(
        card_renderer_manifest_id=SHA_A,
        dispatch_request_manifest_id=SHA_B,
        transition_command_manifest_id=SHA_C,
        raw_storage_manifest_id=SHA_D,
        audit_manifest_id=SHA_E,
        workflow_manifest_id="f" * 64,
    )


def _queue(
    before: M8NotificationCommitReceiptV1,
    *,
    occurred_at: datetime = BASE_TIME + timedelta(minutes=1),
) -> M8NotificationTransitionCommandV1:
    return M8NotificationTransitionCommandV1(
        notification_id=before.notification_id,
        source_notification_version=before.notification_version,
        source_notification_authority_sha256=before.notification_document_sha256,
        source_status=before.status,
        action=M8NotificationAction.QUEUE,
        initiator_kind=M8NotificationInitiatorKind.SYSTEM,
        system_authority_id=SHA_A,
        supporting_authorities=_support("notification-queue-policy-01"),
        explicit_human_confirmation=False,
        occurred_at=occurred_at,
        command_manifest_id=SHA_E,
    )


def _dispatch(
    before: M8NotificationCommitReceiptV1,
    card: bytes,
    response: bytes,
) -> M8NotificationTransitionCommandV1:
    plan = before.audit_event.notification_authority.plan
    capability = M8NotificationChannelCapabilityAuthorityV1(
        adapter_id="m8-local-message-fake",
        adapter_revision="v1",
        channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
        request_timeout_ms=1_000,
        network_required=False,
        offline_capable=True,
        simulated=True,
        inbound_response_supported=True,
        adapter_manifest_id=SHA_D,
    )
    request = M8NotificationDispatchRequestV1(
        plan=plan,
        source_notification_version=before.notification_version,
        source_notification_authority_sha256=before.notification_document_sha256,
        attempt_number=1,
        channel_capability=capability,
        rendered_card_ref="notification-card-01",
        rendered_card_sha256=_sha(card),
        dispatched_at=BASE_TIME + timedelta(minutes=2),
        timeout_ms=1_000,
        idempotency_key=plan.notification_id,
        request_manifest_id=SHA_E,
    )
    result = M8NotificationDispatchResultV1(
        request=request,
        disposition=M8NotificationDispatchDisposition.ACCEPTED,
        provider_receipt_id="local-message-receipt-01",
        raw_response_ref="raw-notification-response-01",
        raw_response_sha256=_sha(response),
        completed_at=BASE_TIME + timedelta(minutes=2, seconds=1),
        result_manifest_id=SHA_E,
    )
    return M8NotificationTransitionCommandV1(
        notification_id=before.notification_id,
        source_notification_version=before.notification_version,
        source_notification_authority_sha256=before.notification_document_sha256,
        source_status=before.status,
        action=M8NotificationAction.RECORD_SENT,
        initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
        dispatch_result=result,
        supporting_authorities=_support("local-channel-capability-01"),
        explicit_human_confirmation=False,
        occurred_at=result.completed_at,
        command_manifest_id=SHA_E,
    )


def _delivery(
    before: M8NotificationCommitReceiptV1,
    response: bytes,
) -> M8NotificationTransitionCommandV1:
    authority = before.audit_event.notification_authority
    plan = authority.plan
    assert authority.last_dispatch_result_id is not None
    receipt = M8NotificationDeliveryReceiptV1(
        notification_id=before.notification_id,
        dispatch_result_id=authority.last_dispatch_result_id,
        target_authority_id=plan.target.target_authority_id,
        channel=plan.target.channel,
        disposition=M8NotificationDeliveryDisposition.DELIVERED,
        provider_delivery_id="local-delivery-01",
        occurred_at=BASE_TIME + timedelta(minutes=3),
        raw_response_ref="raw-delivery-response-01",
        raw_response_sha256=_sha(response),
        simulated=True,
        receipt_manifest_id=SHA_E,
    )
    return M8NotificationTransitionCommandV1(
        notification_id=before.notification_id,
        source_notification_version=before.notification_version,
        source_notification_authority_sha256=before.notification_document_sha256,
        source_status=before.status,
        action=M8NotificationAction.RECORD_DELIVERED,
        initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
        delivery_receipt=receipt,
        supporting_authorities=_support("local-delivery-simulator-01"),
        explicit_human_confirmation=False,
        occurred_at=receipt.occurred_at,
        command_manifest_id=SHA_E,
    )


def _response(
    before: M8NotificationCommitReceiptV1,
    actor: M8ActorAuthorityV1,
    raw_reply: bytes,
) -> M8NotificationTransitionCommandV1:
    plan = before.audit_event.notification_authority.plan
    reply = M8NotificationReplyAuthorityV1(
        notification_id=before.notification_id,
        target_authority_id=plan.target.target_authority_id,
        actor_id=actor.actor_id,
        channel=plan.target.channel,
        reply_kind=M8NotificationReplyKind.EXPLANATION,
        reply_document_sha256=SHA_B,
        raw_reply_ref="raw-notification-reply-01",
        raw_reply_sha256=_sha(raw_reply),
        received_at=BASE_TIME + timedelta(minutes=4),
        simulated=True,
        reply_manifest_id=SHA_D,
    )
    return M8NotificationTransitionCommandV1(
        notification_id=before.notification_id,
        source_notification_version=before.notification_version,
        source_notification_authority_sha256=before.notification_document_sha256,
        source_status=before.status,
        action=M8NotificationAction.RESPOND,
        initiator_kind=M8NotificationInitiatorKind.ACTOR,
        actor_authority=actor,
        reply=reply,
        supporting_authorities=_support("student-explanation-01"),
        explicit_human_confirmation=True,
        occurred_at=reply.received_at,
        command_manifest_id=SHA_E,
    )


def _repositories(
    tmp_path: Path,
) -> tuple[SQLiteM8OperationsRepository, SQLiteM8NotificationRepository, Path]:
    root = tmp_path / "operations"
    root.mkdir()
    database = root / "labcourt.sqlite3"
    operations = SQLiteM8OperationsRepository.initialize(database, BUSY_TIMEOUT_MS, SHA_C)
    notifications = SQLiteM8NotificationRepository.initialize(database, BUSY_TIMEOUT_MS, SHA_C)
    return operations, notifications, database


def _planned_fixture(
    tmp_path: Path,
) -> tuple[
    SQLiteM8OperationsRepository,
    SQLiteM8NotificationRepository,
    Path,
    M8ActorAuthorityV1,
    M8OperationalCaseCommitReceiptV1,
    M8NotificationCommitReceiptV1,
]:
    operations, notifications, database = _repositories(tmp_path)
    student = _student()
    operations.publish_actor_authority(student, None)
    case = operations.create_operational_case(
        _create_command(),
        student.actor_id,
        SHA_D,
        SHA_E,
    )
    target = _target()
    notifications.publish_target_authority(target, None)
    planned = notifications.create_notification(_plan(case, target), SHA_E)
    return operations, notifications, database, student, case, planned


def test_notification_lifecycle_is_atomic_idempotent_and_restart_safe(tmp_path: Path) -> None:
    _, notifications, database, student, _, planned = _planned_fixture(tmp_path)
    assert (
        notifications.create_notification(planned.audit_event.notification_authority.plan, SHA_E)
        == planned
    )

    queued = notifications.transition_notification(_queue(planned), (), SHA_D, SHA_E)
    card = b'{"badge":"SIMULATED - LOCAL MESSAGE","case":"pending-verification"}'
    dispatch_response = b'{"accepted":true,"simulated":true}'
    send_command = _dispatch(queued, card, dispatch_response)
    sent = notifications.transition_notification(
        send_command,
        (card, dispatch_response),
        SHA_D,
        SHA_E,
    )
    assert (
        notifications.transition_notification(
            send_command,
            (card, dispatch_response),
            SHA_D,
            SHA_E,
        )
        == sent
    )
    delivery_response = b'{"delivered":true,"simulated":true}'
    delivered = notifications.transition_notification(
        _delivery(sent, delivery_response),
        (delivery_response,),
        SHA_D,
        SHA_E,
    )
    raw_reply = b"Offline simulated explanation; never a direct Case transition."
    responded = notifications.transition_notification(
        _response(delivered, student, raw_reply),
        (raw_reply,),
        SHA_D,
        SHA_E,
    )

    reopened = SQLiteM8NotificationRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    assert reopened.get_current_notification(planned.notification_id) == responded
    assert reopened.read_raw_artifact("notification-card-01") == card
    assert reopened.read_raw_artifact("raw-notification-response-01") == dispatch_response
    assert reopened.read_raw_artifact("raw-delivery-response-01") == delivery_response
    assert reopened.read_raw_artifact("raw-notification-reply-01") == raw_reply
    assert tuple(
        event.event_sequence for event in reopened.list_notification_audit(planned.notification_id)
    ) == (
        1,
        2,
        3,
        4,
        5,
    )
    assert reopened.list_notifications_by_status(M8NotificationStatus.RESPONDED, 10) == (responded,)
    assert reopened.list_notifications_by_status(M8NotificationStatus.SENT, 10) == ()


def test_notification_rejects_stale_target_actor_and_source_fences(tmp_path: Path) -> None:
    operations, notifications, _, student, case, planned = _planned_fixture(tmp_path)
    queued = notifications.transition_notification(_queue(planned), (), SHA_D, SHA_E)
    stale_queue = _queue(planned, occurred_at=BASE_TIME + timedelta(minutes=1, seconds=1))
    with pytest.raises(ConcurrentModification, match="source version is stale"):
        notifications.transition_notification(stale_queue, (), SHA_D, SHA_E)

    notifications.publish_target_authority(_target(revision=2), 1)
    with pytest.raises(ConcurrentModification, match="current persisted target"):
        notifications.create_notification(
            _plan(case, _target(), planned_at=BASE_TIME + timedelta(seconds=1)),
            SHA_E,
        )

    card = b'{"badge":"SIMULATED"}'
    dispatch_response = b'{"accepted":true}'
    sent = notifications.transition_notification(
        _dispatch(queued, card, dispatch_response),
        (card, dispatch_response),
        SHA_D,
        SHA_E,
    )
    operations.publish_actor_authority(_student(revision=2, active=False), 1)
    reply_bytes = b"inactive actor reply"
    with pytest.raises(ConcurrentModification, match="current persisted authority"):
        notifications.transition_notification(
            _response(sent, student, reply_bytes),
            (reply_bytes,),
            SHA_D,
            SHA_E,
        )
    assert notifications.get_current_notification(planned.notification_id) == sent


def test_notification_raw_failure_rolls_back_and_storage_is_append_only(tmp_path: Path) -> None:
    _, notifications, database, _, _, planned = _planned_fixture(tmp_path)
    queued = notifications.transition_notification(_queue(planned), (), SHA_D, SHA_E)
    card = b'{"badge":"SIMULATED"}'
    response = b'{"accepted":true}'
    command = _dispatch(queued, card, response)
    with pytest.raises(ConcurrentModification, match="hash does not match"):
        notifications.transition_notification(command, (card, b"wrong"), SHA_D, SHA_E)

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM m8_notification_raw_artifacts"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT max(notification_version) FROM m8_notification_versions"
        ).fetchone() == (2,)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m8_notification_versions SET status = 'FAILED' WHERE notification_id = ?",
                (planned.notification_id,),
            )

    sent = notifications.transition_notification(command, (card, response), SHA_D, SHA_E)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER m8_notification_raw_artifacts_no_update")
        connection.execute(
            """
            UPDATE m8_notification_raw_artifacts SET raw_artifact_bytes = ?
            WHERE raw_artifact_ref = ?
            """,
            (b"x" * len(card), "notification-card-01"),
        )
    with pytest.raises(RepositoryIntegrityError, match="raw byte hash"):
        notifications.get_current_notification(sent.notification_id)


def test_notification_service_runs_offline_card_to_reply_without_changing_case(
    tmp_path: Path,
) -> None:
    operations, notifications, database = _repositories(tmp_path)
    student = _student()
    operations.publish_actor_authority(student, None)
    case = operations.create_operational_case(
        _create_command(),
        student.actor_id,
        SHA_D,
        SHA_E,
    )
    channel = DeterministicOfflineNotificationChannel(_channel_capability())
    service = M8NotificationService(notifications, operations, channel, _workflow())
    target = _target()
    service.publish_target(target, None)
    planned = service.create_notification(_plan(case, target))

    queued = service.queue_as_system(
        planned.notification_id,
        BASE_TIME + timedelta(minutes=1),
        _support("notification-queue-policy-01"),
    )
    card, card_bytes = service.render_card(planned.notification_id)
    assert card.simulated is True
    assert b"SIMULATED" in card_bytes

    sent = service.dispatch(
        planned.notification_id,
        _support("local-channel-capability-01"),
    )
    assert sent.status == M8NotificationStatus.SENT
    assert (
        service.dispatch(
            planned.notification_id,
            _support("local-channel-capability-01"),
        )
        == sent
    )
    assert sent.raw_artifact_receipts[0].raw_artifact_ref == card.raw_card_ref
    assert notifications.read_raw_artifact(card.raw_card_ref) == card_bytes

    delivered = service.confirm_simulated_delivery(
        planned.notification_id,
        BASE_TIME + timedelta(minutes=2),
        _support("local-delivery-simulator-01"),
    )
    assert delivered.status == M8NotificationStatus.DELIVERED
    assert (
        service.confirm_simulated_delivery(
            planned.notification_id,
            BASE_TIME + timedelta(minutes=2),
            _support("local-delivery-simulator-01"),
        )
        == delivered
    )

    raw_reply = b"I was replacing damaged goggles; please review the attached evidence."
    responded = service.respond(
        planned.notification_id,
        student.actor_id,
        M8NotificationReplyKind.EXPLANATION,
        hashlib.sha256(raw_reply).hexdigest(),
        raw_reply,
        BASE_TIME + timedelta(minutes=3),
        _support("student-explanation-01"),
    )
    assert responded.status == M8NotificationStatus.RESPONDED
    assert responded.audit_event.transition_command is not None
    reply = responded.audit_event.transition_command.reply
    assert reply is not None
    assert reply.case_transition_permitted is False
    assert notifications.read_raw_artifact(reply.raw_reply_ref) == raw_reply
    assert operations.get_current_operational_case(case.case_id) == case

    reopened = SQLiteM8NotificationRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    assert reopened.get_current_notification(planned.notification_id) == responded
    assert tuple(
        event.event_sequence for event in reopened.list_notification_audit(planned.notification_id)
    ) == (
        1,
        2,
        3,
        4,
        5,
    )
    assert queued.status == M8NotificationStatus.QUEUED


def test_notification_service_requires_safety_actor_when_send_policy_requires_human(
    tmp_path: Path,
) -> None:
    operations, notifications, _ = _repositories(tmp_path)
    student = _student()
    safety = M8ActorAuthorityV1(
        actor_id="safety-officer-01",
        role=M8ActorRole.SAFETY_OFFICER,
        scope_kind=M8ActorScopeKind.LOCATIONS,
        scope_location_ids=("room-chem-301",),
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=1,
        active=True,
        manifest_id=SHA_B,
    )
    operations.publish_actor_authority(student, None)
    operations.publish_actor_authority(safety, None)
    case = operations.create_operational_case(
        _create_command(),
        student.actor_id,
        SHA_D,
        SHA_E,
    )
    service = M8NotificationService(
        notifications,
        operations,
        DeterministicOfflineNotificationChannel(_channel_capability()),
        _workflow(),
    )
    target = _target()
    service.publish_target(target, None)
    planned = service.create_notification(
        _plan(case, target, requires_human_send_confirmation=True)
    )

    with pytest.raises(ConcurrentModification, match="human send confirmation"):
        service.queue_as_system(
            planned.notification_id,
            BASE_TIME + timedelta(minutes=1),
            _support("notification-queue-policy-01"),
        )
    queued = service.queue_as_actor(
        planned.notification_id,
        safety.actor_id,
        BASE_TIME + timedelta(minutes=1),
        _support("notification-human-confirmation-01"),
    )
    command = queued.audit_event.transition_command
    assert command is not None
    assert command.actor_authority == safety
    assert command.explicit_human_confirmation is True
