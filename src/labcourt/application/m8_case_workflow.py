"""Pure construction of M8 actor and operational-Case commit authorities."""

from __future__ import annotations

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8OperationalCaseAuditIntentV1,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseTransitionCommandV1,
)
from labcourt.contracts.m8_case_persistence import (
    M8_AUDIT_GENESIS_SHA256,
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseAuditEventV1,
    M8OperationalCaseAuthorityV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.references import ReferenceToken


def build_actor_authority_commit(
    authority: M8ActorAuthorityV1,
    prior: M8ActorAuthorityCommitReceiptV1 | None,
    repository_manifest_id: Sha256Hex,
) -> M8ActorAuthorityCommitReceiptV1:
    if prior is None:
        if authority.authority_revision != 1:
            raise ValueError("first persisted M8 actor authority must use revision 1")
        return M8ActorAuthorityCommitReceiptV1(
            authority=authority,
            repository_manifest_id=repository_manifest_id,
        )
    if prior.authority.actor_id != authority.actor_id:
        raise ValueError("M8 actor authority successor belongs to another actor")
    if authority.authority_revision != prior.authority.authority_revision + 1:
        raise ValueError("M8 actor authority successor revision must be contiguous")
    return M8ActorAuthorityCommitReceiptV1(
        authority=authority,
        prior_authority_id=prior.authority.actor_authority_id,
        prior_document_sha256=prior.authority_document_sha256,
        repository_manifest_id=repository_manifest_id,
    )


def build_operational_case_create_commit(
    command: M8OperationalCaseCreateCommandV1,
    subject_actor_id: ReferenceToken | None,
    case_manifest_id: Sha256Hex,
    audit_manifest_id: Sha256Hex,
    repository_manifest_id: Sha256Hex,
) -> M8OperationalCaseCommitReceiptV1:
    authority = M8OperationalCaseAuthorityV1(
        create_command=command,
        case_version=1,
        status=command.initial_status,
        subject_actor_id=subject_actor_id,
        case_manifest_id=case_manifest_id,
    )
    event = M8OperationalCaseAuditEventV1(
        case_authority=authority,
        event_sequence=1,
        create_command_id=command.create_command_id,
        prior_audit_event_sha256=M8_AUDIT_GENESIS_SHA256,
        audit_manifest_id=audit_manifest_id,
    )
    return M8OperationalCaseCommitReceiptV1(
        audit_event=event,
        repository_manifest_id=repository_manifest_id,
    )


def build_operational_case_transition_commit(
    before: M8OperationalCaseCommitReceiptV1,
    command: M8OperationalCaseTransitionCommandV1,
    resolved_actor: M8ActorAuthorityCommitReceiptV1,
    case_manifest_id: Sha256Hex,
    audit_manifest_id: Sha256Hex,
    repository_manifest_id: Sha256Hex,
) -> M8OperationalCaseCommitReceiptV1:
    before_authority = before.audit_event.case_authority
    if command.case_id != before.case_id:
        raise ValueError("M8 transition command belongs to another Case")
    if command.source_case_version != before.case_version:
        raise ValueError("M8 transition command source version is stale")
    if command.source_case_authority_sha256 != before.case_document_sha256:
        raise ValueError("M8 transition command source document is stale")
    if command.source_status != before.status:
        raise ValueError("M8 transition command source status is stale")
    if command.case_location_id != before_authority.location_id:
        raise ValueError("M8 transition command Case location conflicts with authority")
    if command.subject_actor_id != before_authority.subject_actor_id:
        raise ValueError("M8 transition command subject conflicts with authority")
    if command.actor_authority != resolved_actor.authority:
        raise ValueError("M8 transition actor is not the current persisted authority")

    authority = M8OperationalCaseAuthorityV1(
        create_command=before_authority.create_command,
        case_version=command.target_case_version,
        status=command.target_status,
        subject_actor_id=before_authority.subject_actor_id,
        prior_case_document_sha256=before.case_document_sha256,
        last_transition_command_id=command.command_id,
        last_actor_authority_id=resolved_actor.authority.actor_authority_id,
        case_manifest_id=case_manifest_id,
    )
    event = M8OperationalCaseAuditEventV1(
        case_authority=authority,
        event_sequence=command.target_case_version,
        transition_intent=M8OperationalCaseAuditIntentV1(
            command=command,
            audit_manifest_id=audit_manifest_id,
        ),
        resolved_actor_document_sha256=resolved_actor.authority_document_sha256,
        prior_audit_event_sha256=before.audit_event.audit_event_sha256,
        audit_manifest_id=audit_manifest_id,
    )
    return M8OperationalCaseCommitReceiptV1(
        audit_event=event,
        repository_manifest_id=repository_manifest_id,
    )


__all__ = [
    "build_actor_authority_commit",
    "build_operational_case_create_commit",
    "build_operational_case_transition_commit",
]
