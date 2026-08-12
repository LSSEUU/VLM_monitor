"""Pure construction of M8 notification target, plan, and transition commits."""

from __future__ import annotations

import hashlib

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_case_persistence import (
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationInitiatorKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notification_persistence import (
    M8_NOTIFICATION_AUDIT_GENESIS_SHA256,
    M8NotificationAuditEventV1,
    M8NotificationAuthorityV1,
    M8NotificationCommitReceiptV1,
    M8NotificationRawArtifactCommitReceiptV1,
    M8NotificationTargetCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationPlanAuthorityV1,
    M8NotificationTargetAuthorityV1,
)


def build_notification_target_commit(
    target: M8NotificationTargetAuthorityV1,
    prior: M8NotificationTargetCommitReceiptV1 | None,
    repository_manifest_id: Sha256Hex,
) -> M8NotificationTargetCommitReceiptV1:
    if prior is None:
        if target.authority_revision != 1:
            raise ValueError("first persisted M8 notification target must use revision 1")
        return M8NotificationTargetCommitReceiptV1(
            target=target,
            repository_manifest_id=repository_manifest_id,
        )
    if prior.target.actor_id != target.actor_id or prior.target.channel != target.channel:
        raise ValueError("M8 notification target successor belongs to another actor/channel")
    if target.authority_revision != prior.target.authority_revision + 1:
        raise ValueError("M8 notification target successor revision must be contiguous")
    return M8NotificationTargetCommitReceiptV1(
        target=target,
        prior_target_authority_id=prior.target.target_authority_id,
        prior_document_sha256=prior.target_document_sha256,
        repository_manifest_id=repository_manifest_id,
    )


def build_notification_plan_commit(
    plan: M8NotificationPlanAuthorityV1,
    resolved_case: M8OperationalCaseCommitReceiptV1,
    resolved_target: M8NotificationTargetCommitReceiptV1,
    resolved_target_actor: M8ActorAuthorityCommitReceiptV1,
    audit_manifest_id: Sha256Hex,
    repository_manifest_id: Sha256Hex,
) -> M8NotificationCommitReceiptV1:
    case_authority = resolved_case.audit_event.case_authority
    expected_case = (
        resolved_case.case_id,
        resolved_case.case_version,
        resolved_case.case_document_sha256,
        resolved_case.status,
        case_authority.subject_actor_id,
        case_authority.risk_level,
        case_authority.location_id,
    )
    actual_case = (
        plan.case_id,
        plan.case_version,
        plan.case_authority_sha256,
        plan.case_status,
        plan.case_subject_actor_id,
        plan.risk_level,
        plan.location_id,
    )
    if actual_case != expected_case:
        raise ValueError("M8 notification plan does not bind the current persisted Case")
    if resolved_target.target != plan.target:
        raise ValueError("M8 notification plan target is not the current persisted target")
    actor = resolved_target_actor.authority
    if not actor.active or actor.actor_id != plan.target.actor_id:
        raise ValueError("M8 notification plan target actor is not current and active")

    authority = M8NotificationAuthorityV1(
        plan=plan,
        notification_version=1,
        status=plan.status,
        notification_manifest_id=plan.notification_manifest_id,
    )
    event = M8NotificationAuditEventV1(
        notification_authority=authority,
        event_sequence=1,
        plan_authority_id=plan.notification_id,
        prior_audit_event_sha256=M8_NOTIFICATION_AUDIT_GENESIS_SHA256,
        audit_manifest_id=audit_manifest_id,
    )
    return M8NotificationCommitReceiptV1(
        audit_event=event,
        raw_artifact_receipts=(),
        repository_manifest_id=repository_manifest_id,
    )


def build_notification_transition_commit(
    before: M8NotificationCommitReceiptV1,
    command: M8NotificationTransitionCommandV1,
    raw_artifacts: tuple[bytes, ...],
    raw_storage_manifest_id: Sha256Hex,
    resolved_actor: M8ActorAuthorityCommitReceiptV1 | None,
    audit_manifest_id: Sha256Hex,
    repository_manifest_id: Sha256Hex,
) -> M8NotificationCommitReceiptV1:
    if command.notification_id != before.notification_id:
        raise ValueError("M8 notification command belongs to another notification")
    if command.source_notification_version != before.notification_version:
        raise ValueError("M8 notification command source version is stale")
    if command.source_notification_authority_sha256 != before.notification_document_sha256:
        raise ValueError("M8 notification command source document is stale")
    if command.source_status != before.status:
        raise ValueError("M8 notification command source status is stale")
    plan = before.audit_event.notification_authority.plan
    if command.occurred_at < plan.planned_at:
        raise ValueError("M8 notification transition cannot predate its plan")

    actor_document_sha256: Sha256Hex | None = None
    if command.initiator_kind == M8NotificationInitiatorKind.ACTOR:
        if resolved_actor is None or command.actor_authority != resolved_actor.authority:
            raise ValueError("M8 notification actor is not the current persisted authority")
        actor_document_sha256 = resolved_actor.authority_document_sha256
        initiator_authority_id = resolved_actor.authority.actor_authority_id
    elif command.initiator_kind == M8NotificationInitiatorKind.SYSTEM:
        if resolved_actor is not None or command.system_authority_id is None:
            raise ValueError("M8 notification system transition actor resolution is invalid")
        initiator_authority_id = command.system_authority_id
    else:
        if resolved_actor is not None:
            raise ValueError("M8 notification channel transition cannot resolve an actor")
        if command.dispatch_result is not None:
            initiator_authority_id = (
                command.dispatch_result.request.channel_capability.capability_authority_id
            )
        elif command.delivery_receipt is not None:
            initiator_authority_id = command.delivery_receipt.delivery_receipt_id
        else:
            raise ValueError("M8 notification channel transition lacks channel authority")

    if command.delivery_receipt is not None and (
        before.audit_event.notification_authority.last_dispatch_result_id
        != command.delivery_receipt.dispatch_result_id
    ):
        raise ValueError("M8 notification delivery does not bind the current sent attempt")

    raw_scope: tuple[tuple[str, str], ...]
    if command.dispatch_result is not None:
        request = command.dispatch_result.request
        raw_scope = (
            (request.rendered_card_ref, request.rendered_card_sha256),
            (
                command.dispatch_result.raw_response_ref,
                command.dispatch_result.raw_response_sha256,
            ),
        )
    elif command.delivery_receipt is not None:
        raw_scope = (
            (
                command.delivery_receipt.raw_response_ref,
                command.delivery_receipt.raw_response_sha256,
            ),
        )
    elif command.reply is not None:
        raw_scope = ((command.reply.raw_reply_ref, command.reply.raw_reply_sha256),)
    else:
        raw_scope = ()
    if len(raw_artifacts) != len(raw_scope):
        raise ValueError("M8 notification raw artifact inventory does not match the command")
    raw_receipts = tuple(
        M8NotificationRawArtifactCommitReceiptV1(
            raw_artifact_ref=raw_ref,
            raw_artifact_sha256=raw_sha256,
            raw_artifact_size_bytes=len(raw_bytes),
            raw_storage_manifest_id=raw_storage_manifest_id,
            repository_manifest_id=repository_manifest_id,
        )
        for (raw_ref, raw_sha256), raw_bytes in zip(raw_scope, raw_artifacts, strict=True)
        if hashlib.sha256(raw_bytes).hexdigest() == raw_sha256
    )
    if len(raw_receipts) != len(raw_scope):
        raise ValueError("M8 notification raw artifact hash does not match the command")

    authority = M8NotificationAuthorityV1(
        plan=plan,
        notification_version=command.target_notification_version,
        status=command.target_status,
        prior_notification_document_sha256=before.notification_document_sha256,
        last_transition_command_id=command.command_id,
        last_initiator_authority_id=initiator_authority_id,
        last_dispatch_result_id=(
            command.dispatch_result.dispatch_result_id
            if command.dispatch_result is not None
            else None
        ),
        last_delivery_receipt_id=(
            command.delivery_receipt.delivery_receipt_id
            if command.delivery_receipt is not None
            else None
        ),
        last_reply_authority_id=(
            command.reply.reply_authority_id if command.reply is not None else None
        ),
        notification_manifest_id=before.audit_event.notification_authority.notification_manifest_id,
    )
    event = M8NotificationAuditEventV1(
        notification_authority=authority,
        event_sequence=command.target_notification_version,
        transition_command=command,
        resolved_actor_document_sha256=actor_document_sha256,
        prior_audit_event_sha256=before.audit_event.audit_event_sha256,
        audit_manifest_id=audit_manifest_id,
    )
    return M8NotificationCommitReceiptV1(
        audit_event=event,
        raw_artifact_receipts=raw_receipts,
        repository_manifest_id=repository_manifest_id,
    )


__all__ = [
    "build_notification_plan_commit",
    "build_notification_target_commit",
    "build_notification_transition_commit",
]
