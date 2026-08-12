from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseAction,
    M8OperationalCaseAuditIntentV1,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseReasonCode,
    M8OperationalCaseStatus,
    M8OperationalCaseTransitionCommandV1,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_case_persistence import (
    M8_AUDIT_GENESIS_SHA256,
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseAuditEventKind,
    M8OperationalCaseAuditEventV1,
    M8OperationalCaseAuthorityV1,
    M8OperationalCaseCommitReceiptV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _actor(*, revision: int = 1, active: bool = True) -> M8ActorAuthorityV1:
    return M8ActorAuthorityV1(
        actor_id="safety-officer-01",
        role=M8ActorRole.SAFETY_OFFICER,
        scope_kind=M8ActorScopeKind.LOCATIONS,
        scope_location_ids=("room-chem-301",),
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=revision,
        active=active,
        manifest_id=SHA_B,
    )


def _actor_receipt(*, revision: int = 1) -> M8ActorAuthorityCommitReceiptV1:
    actor = _actor(revision=revision)
    if revision == 1:
        return M8ActorAuthorityCommitReceiptV1(
            authority=actor,
            repository_manifest_id=SHA_C,
        )
    prior = _actor_receipt(revision=revision - 1)
    return M8ActorAuthorityCommitReceiptV1(
        authority=actor,
        prior_authority_id=prior.authority.actor_authority_id,
        prior_document_sha256=prior.authority_document_sha256,
        repository_manifest_id=SHA_C,
    )


def _create_command() -> M8OperationalCaseCreateCommandV1:
    return M8OperationalCaseCreateCommandV1(
        source_catalog_id=SHA_A,
        location_id="room-chem-301",
        risk_level=M8OperationalRiskLevel.EMERGENCY,
        policy_rule_id="simulated-smoke-active-emergency-v1",
        policy_manifest_id=SHA_B,
        source_ids=("sensor-simulated-smoke-01",),
        simulated_source_ids=("sensor-simulated-smoke-01",),
        trigger_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.SENSOR_SIGNAL,
                authority_id="smoke-sample-01",
                document_sha256=SHA_C,
            ),
        ),
        automation_component_id="m8-offline-sensor-simulator",
        automation_manifest_id=SHA_D,
    )


def _created_receipt() -> M8OperationalCaseCommitReceiptV1:
    command = _create_command()
    authority = M8OperationalCaseAuthorityV1(
        create_command=command,
        case_version=1,
        status=M8OperationalCaseStatus.PENDING_VERIFICATION,
        subject_actor_id="student-01",
        case_manifest_id=SHA_D,
    )
    event = M8OperationalCaseAuditEventV1(
        case_authority=authority,
        event_sequence=1,
        create_command_id=command.create_command_id,
        prior_audit_event_sha256=M8_AUDIT_GENESIS_SHA256,
        audit_manifest_id=SHA_E,
    )
    return M8OperationalCaseCommitReceiptV1(
        audit_event=event,
        repository_manifest_id=SHA_C,
    )


def _transitioned_receipt() -> M8OperationalCaseCommitReceiptV1:
    created = _created_receipt()
    actor_receipt = _actor_receipt()
    command = M8OperationalCaseTransitionCommandV1(
        case_id=created.case_id,
        source_case_version=created.case_version,
        source_case_authority_sha256=created.case_document_sha256,
        source_status=created.status,
        case_location_id=created.audit_event.case_authority.location_id,
        subject_actor_id="student-01",
        action=M8OperationalCaseAction.CONFIRM,
        reason_code=M8OperationalCaseReasonCode.VERIFIED_VIOLATION,
        reason_summary="安全负责人已核实模拟信号与现场说明。",
        supporting_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.USER_STATEMENT,
                authority_id="statement-01",
                document_sha256=SHA_D,
            ),
        ),
        actor_authority=actor_receipt.authority,
        explicit_human_confirmation=True,
        command_manifest_id=SHA_E,
    )
    authority = M8OperationalCaseAuthorityV1(
        create_command=created.audit_event.case_authority.create_command,
        case_version=command.target_case_version,
        status=command.target_status,
        subject_actor_id=command.subject_actor_id,
        prior_case_document_sha256=created.case_document_sha256,
        last_transition_command_id=command.command_id,
        last_actor_authority_id=command.actor_authority.actor_authority_id,
        case_manifest_id=SHA_D,
    )
    event = M8OperationalCaseAuditEventV1(
        case_authority=authority,
        event_sequence=2,
        transition_intent=M8OperationalCaseAuditIntentV1(
            command=command,
            audit_manifest_id=SHA_E,
        ),
        resolved_actor_document_sha256=actor_receipt.authority_document_sha256,
        prior_audit_event_sha256=created.audit_event.audit_event_sha256,
        audit_manifest_id=SHA_E,
    )
    return M8OperationalCaseCommitReceiptV1(
        audit_event=event,
        repository_manifest_id=SHA_C,
    )


def test_actor_commit_receipt_requires_contiguous_prior_shape_and_content_hash() -> None:
    first = _actor_receipt()
    second = _actor_receipt(revision=2)

    assert first.prior_authority_id is None
    assert second.prior_authority_id == first.authority.actor_authority_id
    assert second.prior_document_sha256 == first.authority_document_sha256
    assert len(second.authority_document_sha256) == 64
    assert len(second.commit_receipt_id) == 64

    with pytest.raises(ValidationError, match="prior"):
        M8ActorAuthorityCommitReceiptV1(
            authority=_actor(revision=2),
            repository_manifest_id=SHA_C,
        )


def test_created_case_authority_and_audit_are_pending_only_and_genesis_bound() -> None:
    receipt = _created_receipt()

    assert receipt.case_version == 1
    assert receipt.status == M8OperationalCaseStatus.PENDING_VERIFICATION
    assert receipt.audit_event.event_kind == M8OperationalCaseAuditEventKind.CASE_CREATED
    assert receipt.audit_event.prior_audit_event_sha256 == M8_AUDIT_GENESIS_SHA256
    assert receipt.audit_event.create_command_id == (
        receipt.audit_event.case_authority.create_command.create_command_id
    )
    assert len(receipt.case_document_sha256) == 64
    assert len(receipt.audit_event.audit_event_sha256) == 64
    assert len(receipt.commit_receipt_id) == 64

    with pytest.raises(ValidationError, match="PENDING_VERIFICATION"):
        receipt.audit_event.case_authority.model_copy(
            update={"status": M8OperationalCaseStatus.CONFIRMED}
        )


def test_transition_receipt_binds_exact_before_after_actor_intent_and_audit_chain() -> None:
    created = _created_receipt()
    transitioned = _transitioned_receipt()
    command = transitioned.audit_event.transition_intent.command  # type: ignore[union-attr]

    assert transitioned.case_id == created.case_id
    assert transitioned.case_version == 2
    assert transitioned.status == M8OperationalCaseStatus.CONFIRMED
    assert transitioned.audit_event.event_kind == (
        M8OperationalCaseAuditEventKind.CASE_TRANSITIONED
    )
    assert command.source_case_authority_sha256 == created.case_document_sha256
    assert transitioned.audit_event.prior_audit_event_sha256 == (
        created.audit_event.audit_event_sha256
    )
    assert transitioned.audit_event.case_authority.last_transition_command_id == (
        command.command_id
    )
    assert transitioned.audit_event.case_authority.last_actor_authority_id == (
        command.actor_authority.actor_authority_id
    )

    with pytest.raises(ValidationError, match="manifest conflicts"):
        transitioned.audit_event.model_copy(update={"audit_manifest_id": SHA_A})


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        ("event_sequence", 3, "sequence"),
        ("prior_audit_event_sha256", SHA_A, None),
        ("resolved_actor_document_sha256", None, "resolved actor"),
    ),
)
def test_transition_audit_rejects_grafted_sequence_actor_and_chain(
    field: str,
    value: object,
    match: str | None,
) -> None:
    receipt = _transitioned_receipt()
    if field == "prior_audit_event_sha256":
        changed = receipt.audit_event.model_copy(update={field: value})
        assert changed.audit_event_sha256 != receipt.audit_event.audit_event_sha256
        return
    with pytest.raises(ValidationError, match=match):
        receipt.audit_event.model_copy(update={field: value})


def test_persistence_computed_claims_reject_serialized_forgery() -> None:
    receipt = _transitioned_receipt()
    forged = receipt.model_dump(mode="json")
    forged["case_version"] = 99
    with pytest.raises(ValidationError, match="case_version"):
        M8OperationalCaseCommitReceiptV1.model_validate(forged)

    Draft202012Validator(
        M8OperationalCaseCommitReceiptV1.model_json_schema(mode="serialization")
    ).validate(receipt.model_dump(mode="json"))


def test_m8_case_persistence_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-actor-authority-commit-receipt-v1": M8ActorAuthorityCommitReceiptV1,
        "m8-operational-case-audit-event-v1": M8OperationalCaseAuditEventV1,
        "m8-operational-case-authority-v1": M8OperationalCaseAuthorityV1,
        "m8-operational-case-commit-receipt-v1": M8OperationalCaseCommitReceiptV1,
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
