from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.application.m8_notification_workflow import build_notification_transition_commit
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxActivationStatusV1
from labcourt.contracts.m8_feishu_inbound import (
    M8FeishuInboundMessageCommitReceiptV1,
    M8FeishuInboundMessageVerificationReceiptV1,
    M8FeishuInboundWebhookProfileV1,
    M8FeishuWebhookIngressRequestV1,
)
from labcourt.contracts.m8_feishu_inbound_reply import (
    M8FeishuInboundReplyCommitReceiptV1,
    M8FeishuInboundReplyCorrelationAuthorityV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
    M8NotificationInitiatorKind,
    M8NotificationReplyAuthorityV1,
    M8NotificationReplyKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notification_persistence import (
    M8_NOTIFICATION_AUDIT_GENESIS_SHA256,
    M8NotificationAuditEventV1,
    M8NotificationAuthorityV1,
    M8NotificationCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationAudienceKind,
    M8NotificationChannelKind,
    M8NotificationEscalationPolicyAuthorityV1,
    M8NotificationPlanAuthorityV1,
    M8NotificationPurpose,
    M8NotificationStatus,
    M8NotificationTemplateAuthorityV1,
)
from tests.contract.test_m8_feishu_activation_contracts import (
    BASE_TIME,
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    SHA_E,
    _actor_receipt,
    _assessment,
    _current_target_receipts,
    _receipt,
)

RECEIVED_AT = datetime(2026, 8, 11, 15, 0, tzinfo=UTC)
CARD_BYTES = b'{"type":"template","data":{"template_id":"sandbox-card"}}'
RESPONSE_BYTES = b'{"code":0,"data":{"message_id":"om_outbound_case_card_01"}}'
CONTENT_BYTES = '{"text":"我已佩戴护目镜,请复核。"}'.encode()


def _support(
    authority_id: str = "notification-sandbox-send-01",
) -> tuple[M8AuthorityReference, ...]:
    return (
        M8AuthorityReference(
            kind=M8AuthorityReferenceKind.NOTIFICATION_REPLY,
            authority_id=authority_id,
            document_sha256=SHA_A,
        ),
    )


def _plan() -> M8NotificationPlanAuthorityV1:
    target = _receipt().runtime_config.recipient_allowlist[0].target
    return M8NotificationPlanAuthorityV1(
        case_id=SHA_A,
        case_version=2,
        case_authority_sha256=SHA_B,
        case_status=M8OperationalCaseStatus.EVIDENCE_REQUESTED,
        case_subject_actor_id=target.actor_id,
        risk_level=M8OperationalRiskLevel.GENERAL,
        location_id="room-chem-301",
        purpose=M8NotificationPurpose.EVIDENCE_REQUESTED,
        audience=M8NotificationAudienceKind.CASE_SUBJECT,
        target=target,
        template=M8NotificationTemplateAuthorityV1(
            template_id="case-student-card",
            template_version=1,
            locale="zh-CN",
            effective_at=BASE_TIME,
            content_document_sha256=SHA_B,
            allowed_purposes=(M8NotificationPurpose.EVIDENCE_REQUESTED,),
            allowed_channels=(M8NotificationChannelKind.FEISHU,),
            manifest_id=SHA_C,
        ),
        escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
            policy_rule_id="general-student-response-v1",
            risk_level=M8OperationalRiskLevel.GENERAL,
            response_timeout_seconds=3600,
            max_delivery_attempts=3,
            escalation_roles=(M8ActorRole.SAFETY_OFFICER,),
            requires_human_send_confirmation=False,
            policy_manifest_id=SHA_C,
        ),
        planned_at=BASE_TIME + timedelta(hours=5),
        notification_manifest_id=SHA_D,
    )


def _planned() -> M8NotificationCommitReceiptV1:
    authority = M8NotificationAuthorityV1(
        plan=_plan(),
        notification_version=1,
        status=M8NotificationStatus.PLANNED,
        notification_manifest_id=SHA_D,
    )
    return M8NotificationCommitReceiptV1(
        audit_event=M8NotificationAuditEventV1(
            notification_authority=authority,
            event_sequence=1,
            plan_authority_id=authority.plan.notification_id,
            prior_audit_event_sha256=M8_NOTIFICATION_AUDIT_GENESIS_SHA256,
            audit_manifest_id=SHA_E,
        ),
        raw_artifact_receipts=(),
        repository_manifest_id=SHA_C,
    )


def _queued() -> M8NotificationCommitReceiptV1:
    before = _planned()
    command = M8NotificationTransitionCommandV1(
        notification_id=before.notification_id,
        source_notification_version=before.notification_version,
        source_notification_authority_sha256=before.notification_document_sha256,
        source_status=before.status,
        action=M8NotificationAction.QUEUE,
        initiator_kind=M8NotificationInitiatorKind.SYSTEM,
        system_authority_id=SHA_A,
        supporting_authorities=_support(),
        explicit_human_confirmation=False,
        occurred_at=BASE_TIME + timedelta(hours=5, minutes=1),
        command_manifest_id=SHA_E,
    )
    return build_notification_transition_commit(
        before,
        command,
        (),
        SHA_A,
        None,
        SHA_E,
        SHA_C,
    )


def _sent() -> M8NotificationCommitReceiptV1:
    before = _queued()
    capability = M8NotificationChannelCapabilityAuthorityV1(
        adapter_id="m8-feishu-adapter",
        adapter_revision="im-v1-2026-04-10",
        channel=M8NotificationChannelKind.FEISHU,
        request_timeout_ms=5_000,
        network_required=True,
        offline_capable=False,
        simulated=False,
        inbound_response_supported=True,
        adapter_manifest_id=SHA_D,
    )
    request = M8NotificationDispatchRequestV1(
        plan=before.audit_event.notification_authority.plan,
        source_notification_version=before.notification_version,
        source_notification_authority_sha256=before.notification_document_sha256,
        attempt_number=1,
        channel_capability=capability,
        rendered_card_ref="feishu-card-sandbox-01",
        rendered_card_sha256=hashlib.sha256(CARD_BYTES).hexdigest(),
        dispatched_at=BASE_TIME + timedelta(hours=5, minutes=2),
        timeout_ms=5_000,
        idempotency_key=before.notification_id,
        request_manifest_id=SHA_D,
    )
    result = M8NotificationDispatchResultV1(
        request=request,
        disposition=M8NotificationDispatchDisposition.ACCEPTED,
        provider_receipt_id="om_outbound_case_card_01",
        raw_response_ref="feishu-send-response-sandbox-01",
        raw_response_sha256=hashlib.sha256(RESPONSE_BYTES).hexdigest(),
        completed_at=request.dispatched_at + timedelta(seconds=1),
        result_manifest_id=SHA_E,
    )
    command = M8NotificationTransitionCommandV1(
        notification_id=before.notification_id,
        source_notification_version=before.notification_version,
        source_notification_authority_sha256=before.notification_document_sha256,
        source_status=before.status,
        action=M8NotificationAction.RECORD_SENT,
        initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
        dispatch_result=result,
        supporting_authorities=_support(),
        explicit_human_confirmation=False,
        occurred_at=result.completed_at,
        command_manifest_id=SHA_E,
    )
    return build_notification_transition_commit(
        before,
        command,
        (CARD_BYTES, RESPONSE_BYTES),
        SHA_A,
        None,
        SHA_E,
        SHA_C,
    )


def _activation_status() -> M8FeishuSandboxActivationStatusV1:
    assessed_at = BASE_TIME + timedelta(hours=5)
    return M8FeishuSandboxActivationStatusV1(
        activation_receipt=_receipt(),
        current_operations_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        current_safety_actor_receipt=_actor_receipt(M8ActorRole.SAFETY_OFFICER),
        current_recipient_target_receipts=_current_target_receipts(),
        current_readiness_assessment=_assessment(assessed_at=assessed_at),
        assessed_at=assessed_at,
        repository_manifest_id=SHA_C,
    )


def _student_actor_receipt() -> M8ActorAuthorityCommitReceiptV1:
    target = _plan().target
    return M8ActorAuthorityCommitReceiptV1(
        authority=M8ActorAuthorityV1(
            actor_id=target.actor_id,
            role=M8ActorRole.STUDENT,
            scope_kind=M8ActorScopeKind.SELF_ONLY,
            scope_location_ids=(),
            identity_provider_id=target.identity_provider_id,
            subject_binding_sha256=SHA_A,
            authority_revision=1,
            active=True,
            manifest_id=SHA_B,
        ),
        repository_manifest_id=SHA_C,
    )


def _inbound_commit() -> M8FeishuInboundMessageCommitReceiptV1:
    activation = _receipt()
    profile = M8FeishuInboundWebhookProfileV1(
        outbound_profile=activation.runtime_config.profile,
        request_url_reference_id="feishu-inbound-url-sandbox-01",
        encrypt_key_reference_id="secret-feishu-encrypt-key-01",
        encrypt_key_sha256=SHA_A,
        verification_token_reference_id="secret-feishu-verification-token-01",
        verification_token_sha256=SHA_B,
        profile_manifest_id=SHA_C,
    )
    ingress = M8FeishuWebhookIngressRequestV1(
        inbound_profile_id=profile.inbound_profile_id,
        request_timestamp_seconds=int(RECEIVED_AT.timestamp()),
        request_nonce="nonce-sandbox-reply-01",
        request_signature=SHA_C,
        encrypted_body_ref="feishu-encrypted-reply-01",
        encrypted_body_sha256=SHA_D,
        encrypted_body_size_bytes=512,
        received_at=RECEIVED_AT,
        ingress_manifest_id=SHA_E,
    )
    verified = M8FeishuInboundMessageVerificationReceiptV1(
        profile=profile,
        ingress_request=ingress,
        decrypted_event_ref="feishu-decrypted-reply-01",
        decrypted_event_sha256=SHA_A,
        decrypted_event_size_bytes=480,
        provider_event_id="event-sandbox-reply-01",
        provider_message_id="om_student_reply_01",
        provider_parent_message_id="om_outbound_case_card_01",
        provider_root_message_id="om_outbound_case_card_01",
        app_id_sha256=profile.outbound_profile.app_id_sha256,
        tenant_key_sha256=SHA_B,
        verification_token_sha256=profile.verification_token_sha256,
        sender_open_id_sha256=activation.runtime_config.recipient_allowlist[0].receive_id_sha256,
        event_created_at=RECEIVED_AT - timedelta(seconds=1),
        message_created_at=RECEIVED_AT - timedelta(seconds=2),
        content_document_ref="feishu-text-content-reply-01",
        content_document_sha256=hashlib.sha256(CONTENT_BYTES).hexdigest(),
        content_size_bytes=len(CONTENT_BYTES),
        verification_manifest_id=SHA_E,
    )
    return M8FeishuInboundMessageCommitReceiptV1(
        verification_receipt=verified,
        committed_at=RECEIVED_AT + timedelta(seconds=1),
        raw_storage_manifest_id=SHA_A,
        commit_manifest_id=SHA_B,
        repository_manifest_id=SHA_C,
    )


def _correlation() -> M8FeishuInboundReplyCorrelationAuthorityV1:
    inbound = _inbound_commit()
    activation = _activation_status()
    binding = activation.activation_receipt.runtime_config.recipient_allowlist[0]
    reply = M8NotificationReplyAuthorityV1(
        notification_id=_sent().notification_id,
        target_authority_id=binding.target.target_authority_id,
        actor_id=binding.target.actor_id,
        channel=M8NotificationChannelKind.FEISHU,
        reply_kind=M8NotificationReplyKind.EXPLANATION,
        reply_document_sha256=inbound.verification_receipt.content_document_sha256,
        raw_reply_ref=inbound.verification_receipt.content_document_ref,
        raw_reply_sha256=inbound.verification_receipt.content_document_sha256,
        received_at=inbound.verification_receipt.ingress_request.received_at,
        simulated=False,
        reply_manifest_id=SHA_E,
    )
    return M8FeishuInboundReplyCorrelationAuthorityV1(
        inbound_commit=inbound,
        notification_commit_chain=(_sent(),),
        activation_status=activation,
        recipient_binding=binding,
        current_target_receipt=activation.current_recipient_target_receipts[0],
        current_actor_receipt=_student_actor_receipt(),
        reply=reply,
        correlated_at=RECEIVED_AT + timedelta(seconds=2),
        correlation_manifest_id=SHA_E,
    )


def _reply_commit() -> M8FeishuInboundReplyCommitReceiptV1:
    correlation = _correlation()
    before = correlation.notification_commit_chain[-1]
    command = M8NotificationTransitionCommandV1(
        notification_id=before.notification_id,
        source_notification_version=before.notification_version,
        source_notification_authority_sha256=before.notification_document_sha256,
        source_status=before.status,
        action=M8NotificationAction.RESPOND,
        initiator_kind=M8NotificationInitiatorKind.ACTOR,
        actor_authority=correlation.current_actor_receipt.authority,
        reply=correlation.reply,
        supporting_authorities=(correlation.supporting_authority(),),
        explicit_human_confirmation=True,
        occurred_at=correlation.reply.received_at,
        command_manifest_id=SHA_E,
    )
    notification_commit = build_notification_transition_commit(
        before,
        command,
        (CONTENT_BYTES,),
        SHA_A,
        correlation.current_actor_receipt,
        SHA_E,
        SHA_C,
    )
    return M8FeishuInboundReplyCommitReceiptV1(
        correlation_authority=correlation,
        notification_commit=notification_commit,
        reply_commit_manifest_id=SHA_D,
    )


def test_correlation_exactly_binds_parent_sender_student_target_and_content() -> None:
    authority = _correlation()

    assert authority.provider_message_id == "om_student_reply_01"
    assert authority.reply_correlation_message_id == "om_outbound_case_card_01"
    assert authority.reply.reply_kind == M8NotificationReplyKind.EXPLANATION
    assert authority.reply_kind_inferred is False
    assert authority.human_reply_explicit is True
    assert authority.notification_reply_commit_permitted is True
    assert authority.automatic_appeal_permitted is False
    assert authority.case_transition_permitted is False
    assert authority.direct_disciplinary_action_permitted is False
    assert authority.supporting_authority().authority_id == authority.correlation_authority_id


def test_correlation_rejects_wrong_parent_sender_target_or_actor() -> None:
    authority = _correlation()
    verified = authority.inbound_commit.verification_receipt

    wrong_parent = verified.model_copy(update={"provider_parent_message_id": "om_foreign_card"})
    with pytest.raises(ValidationError, match="parent does not match"):
        authority.model_copy(
            update={
                "inbound_commit": authority.inbound_commit.model_copy(
                    update={"verification_receipt": wrong_parent}
                )
            }
        )
    wrong_sender = verified.model_copy(update={"sender_open_id_sha256": SHA_E})
    with pytest.raises(ValidationError, match="sender does not match"):
        authority.model_copy(
            update={
                "inbound_commit": authority.inbound_commit.model_copy(
                    update={"verification_receipt": wrong_sender}
                )
            }
        )
    with pytest.raises(ValidationError, match="current activation status"):
        authority.model_copy(
            update={
                "current_target_receipt": authority.current_target_receipt.model_copy(
                    update={"target": authority.current_target_receipt.target.model_copy(
                        update={"inbound_response_supported": False}
                    )}
                )
            }
        )
    inactive_actor = authority.current_actor_receipt.authority.model_copy(update={"active": False})
    with pytest.raises(ValidationError, match="current active target student"):
        authority.model_copy(
            update={
                "current_actor_receipt": authority.current_actor_receipt.model_copy(
                    update={"authority": inactive_actor}
                )
            }
        )


def test_correlation_rejects_reply_kind_guess_or_cross_repository_graft() -> None:
    authority = _correlation()
    with pytest.raises(ValidationError, match="exactly bind inbound content"):
        authority.model_copy(
            update={
                "reply": authority.reply.model_copy(
                    update={"reply_kind": M8NotificationReplyKind.APPEAL_REQUEST}
                )
            }
        )
    with pytest.raises(ValidationError, match="cross repositories"):
        authority.model_copy(
            update={
                "current_actor_receipt": authority.current_actor_receipt.model_copy(
                    update={"repository_manifest_id": SHA_E}
                )
            }
        )


def test_commit_receipt_binds_one_generic_reply_and_no_case_action() -> None:
    receipt = _reply_commit()

    assert receipt.notification_commit.status == M8NotificationStatus.RESPONDED
    assert receipt.provider_message_deduplication_key == "om_student_reply_01"
    assert receipt.notification_reply_committed is True
    assert receipt.automatic_replay_permitted is False
    assert receipt.case_transition_permitted is False
    assert receipt.direct_disciplinary_action_permitted is False

    command = receipt.notification_commit.audit_event.transition_command
    assert command is not None
    with pytest.raises(ValidationError, match="exactly bind"):
        receipt.model_copy(
            update={
                "notification_commit": receipt.notification_commit.model_copy(
                    update={
                        "audit_event": receipt.notification_commit.audit_event.model_copy(
                            update={
                                "transition_command": command.model_copy(
                                    update={"supporting_authorities": _support("foreign-authority")}
                                )
                            }
                        )
                    }
                )
            }
        )


@pytest.mark.parametrize("model", (_correlation(), _reply_commit()))
def test_reply_contracts_round_trip_and_validate_as_serialization_schemas(
    model: BaseModel,
) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )


def test_reply_contracts_reject_serialized_authority_escalation() -> None:
    payload = _correlation().model_dump(mode="json")
    payload["case_transition_permitted"] = True
    with pytest.raises(ValidationError, match="case_transition_permitted"):
        M8FeishuInboundReplyCorrelationAuthorityV1.model_validate(payload)


def test_reply_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-feishu-inbound-reply-commit-receipt-v1": M8FeishuInboundReplyCommitReceiptV1,
        "m8-feishu-inbound-reply-correlation-authority-v1": (
            M8FeishuInboundReplyCorrelationAuthorityV1
        ),
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
