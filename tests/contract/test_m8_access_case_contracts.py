from __future__ import annotations

from collections.abc import Callable

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8AppealResolution,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8Capability,
    M8OperationalCaseAction,
    M8OperationalCaseAuditIntentV1,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseReasonCode,
    M8OperationalCaseStatus,
    M8OperationalCaseTransitionCommandV1,
    M8OperationalRiskLevel,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _actor(
    role: M8ActorRole,
    *,
    actor_id: str | None = None,
    active: bool = True,
    scope_kind: M8ActorScopeKind | None = None,
    scope_location_ids: tuple[str, ...] | None = None,
) -> M8ActorAuthorityV1:
    if scope_kind is None:
        scope_kind = {
            M8ActorRole.LEADER: M8ActorScopeKind.CAMPUS_WIDE,
            M8ActorRole.SAFETY_OFFICER: M8ActorScopeKind.LOCATIONS,
            M8ActorRole.STUDENT: M8ActorScopeKind.SELF_ONLY,
            M8ActorRole.OPERATIONS: M8ActorScopeKind.LOCATIONS,
        }[role]
    if scope_location_ids is None:
        scope_location_ids = ("room-chem-301",) if scope_kind == M8ActorScopeKind.LOCATIONS else ()
    return M8ActorAuthorityV1(
        actor_id=actor_id or f"actor-{role.value.lower().replace('_', '-')}",
        role=role,
        scope_kind=scope_kind,
        scope_location_ids=scope_location_ids,
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=1,
        active=active,
        manifest_id=SHA_B,
    )


def _authority_ref(
    *,
    kind: M8AuthorityReferenceKind = M8AuthorityReferenceKind.SENSOR_SIGNAL,
    authority_id: str = "signal-01",
    document_sha256: str = SHA_C,
) -> M8AuthorityReference:
    return M8AuthorityReference(
        kind=kind,
        authority_id=authority_id,
        document_sha256=document_sha256,
    )


def _create_command() -> M8OperationalCaseCreateCommandV1:
    return M8OperationalCaseCreateCommandV1(
        source_catalog_id=SHA_A,
        location_id="room-chem-301",
        risk_level=M8OperationalRiskLevel.EMERGENCY,
        policy_rule_id="simulated-smoke-emergency-v1",
        policy_manifest_id=SHA_B,
        source_ids=("camera-recorded-01", "sensor-simulated-01"),
        simulated_source_ids=("camera-recorded-01", "sensor-simulated-01"),
        trigger_authorities=(_authority_ref(),),
        automation_component_id="m8-offline-sensor-simulator",
        automation_manifest_id=SHA_D,
    )


_ACTION_CASES = (
    (
        M8OperationalCaseAction.CONFIRM,
        M8OperationalCaseStatus.PENDING_VERIFICATION,
        M8OperationalCaseStatus.CONFIRMED,
        M8Capability.CONFIRM_CASE,
        M8ActorRole.SAFETY_OFFICER,
        M8OperationalCaseReasonCode.VERIFIED_VIOLATION,
        None,
    ),
    (
        M8OperationalCaseAction.REJECT,
        M8OperationalCaseStatus.PENDING_VERIFICATION,
        M8OperationalCaseStatus.REJECTED,
        M8Capability.REJECT_CASE,
        M8ActorRole.SAFETY_OFFICER,
        M8OperationalCaseReasonCode.FALSE_POSITIVE,
        None,
    ),
    (
        M8OperationalCaseAction.REQUEST_EVIDENCE,
        M8OperationalCaseStatus.PENDING_VERIFICATION,
        M8OperationalCaseStatus.EVIDENCE_REQUESTED,
        M8Capability.REQUEST_CASE_EVIDENCE,
        M8ActorRole.SAFETY_OFFICER,
        M8OperationalCaseReasonCode.MORE_EVIDENCE_REQUIRED,
        None,
    ),
    (
        M8OperationalCaseAction.RETURN_TO_VERIFICATION,
        M8OperationalCaseStatus.EVIDENCE_REQUESTED,
        M8OperationalCaseStatus.PENDING_VERIFICATION,
        M8Capability.RETURN_CASE_TO_VERIFICATION,
        M8ActorRole.SAFETY_OFFICER,
        M8OperationalCaseReasonCode.EVIDENCE_RECEIVED,
        None,
    ),
    (
        M8OperationalCaseAction.RESOLVE,
        M8OperationalCaseStatus.CONFIRMED,
        M8OperationalCaseStatus.RESOLVED,
        M8Capability.RESOLVE_CASE,
        M8ActorRole.SAFETY_OFFICER,
        M8OperationalCaseReasonCode.HAZARD_CLEARED,
        None,
    ),
    (
        M8OperationalCaseAction.SUBMIT_APPEAL,
        M8OperationalCaseStatus.CONFIRMED,
        M8OperationalCaseStatus.APPEALED,
        M8Capability.SUBMIT_APPEAL,
        M8ActorRole.STUDENT,
        M8OperationalCaseReasonCode.SUBJECT_DISPUTE,
        None,
    ),
    (
        M8OperationalCaseAction.SUBMIT_APPEAL,
        M8OperationalCaseStatus.RESOLVED,
        M8OperationalCaseStatus.APPEALED,
        M8Capability.SUBMIT_APPEAL,
        M8ActorRole.STUDENT,
        M8OperationalCaseReasonCode.SUBJECT_DISPUTE,
        None,
    ),
    (
        M8OperationalCaseAction.RESOLVE_APPEAL,
        M8OperationalCaseStatus.APPEALED,
        M8OperationalCaseStatus.APPEAL_RESOLVED,
        M8Capability.RESOLVE_APPEAL,
        M8ActorRole.SAFETY_OFFICER,
        M8OperationalCaseReasonCode.APPEAL_OVERTURNED,
        M8AppealResolution.OVERTURNED,
    ),
)


def _transition(
    *,
    action: M8OperationalCaseAction = M8OperationalCaseAction.CONFIRM,
    source_status: M8OperationalCaseStatus = M8OperationalCaseStatus.PENDING_VERIFICATION,
    role: M8ActorRole = M8ActorRole.SAFETY_OFFICER,
    reason_code: M8OperationalCaseReasonCode = (M8OperationalCaseReasonCode.VERIFIED_VIOLATION),
    appeal_resolution: M8AppealResolution | None = None,
    actor: M8ActorAuthorityV1 | None = None,
    subject_actor_id: str | None = "actor-student",
    explicit_human_confirmation: bool = True,
) -> M8OperationalCaseTransitionCommandV1:
    selected_actor = actor or _actor(
        role,
        actor_id="actor-student" if role == M8ActorRole.STUDENT else None,
    )
    return M8OperationalCaseTransitionCommandV1(
        case_id="operational-case-01",
        source_case_version=1,
        source_case_authority_sha256=SHA_A,
        source_status=source_status,
        case_location_id="room-chem-301",
        subject_actor_id=subject_actor_id,
        action=action,
        reason_code=reason_code,
        reason_summary="操作者已明确核对该动作及其依据。",
        supporting_authorities=(_authority_ref(),),
        actor_authority=selected_actor,
        appeal_resolution=appeal_resolution,
        explicit_human_confirmation=explicit_human_confirmation,
        command_manifest_id=SHA_D,
    )


@pytest.mark.parametrize(
    ("role", "expected_scope", "present", "absent"),
    (
        (
            M8ActorRole.LEADER,
            M8ActorScopeKind.CAMPUS_WIDE,
            {M8Capability.VIEW_GLOBAL_OVERVIEW, M8Capability.VIEW_MAJOR_EVENTS},
            {M8Capability.CONFIRM_CASE, M8Capability.RESOLVE_CASE},
        ),
        (
            M8ActorRole.SAFETY_OFFICER,
            M8ActorScopeKind.LOCATIONS,
            {M8Capability.CONFIRM_CASE, M8Capability.RESOLVE_APPEAL},
            {M8Capability.MANAGE_DEVICES, M8Capability.SUBMIT_APPEAL},
        ),
        (
            M8ActorRole.STUDENT,
            M8ActorScopeKind.SELF_ONLY,
            {M8Capability.VIEW_OWN_CASE, M8Capability.SUBMIT_APPEAL},
            {M8Capability.VIEW_GLOBAL_OVERVIEW, M8Capability.CONFIRM_CASE},
        ),
        (
            M8ActorRole.OPERATIONS,
            M8ActorScopeKind.LOCATIONS,
            {M8Capability.MANAGE_DEVICES, M8Capability.VIEW_DEVICE_HEALTH},
            {M8Capability.CONFIRM_CASE, M8Capability.RESOLVE_APPEAL},
        ),
    ),
)
def test_actor_role_derives_closed_capabilities_without_approval_leakage(
    role: M8ActorRole,
    expected_scope: M8ActorScopeKind,
    present: set[M8Capability],
    absent: set[M8Capability],
) -> None:
    actor = _actor(role)

    assert actor.scope_kind == expected_scope
    assert present <= set(actor.capabilities)
    assert set(actor.capabilities).isdisjoint(absent)
    assert len(actor.actor_authority_id) == 64
    Draft202012Validator(M8ActorAuthorityV1.model_json_schema(mode="serialization")).validate(
        actor.model_dump(mode="json")
    )

    forged = actor.model_dump(mode="json")
    forged["capabilities"] = [M8Capability.CONFIRM_CASE.value]
    with pytest.raises(ValidationError, match="capabilities"):
        M8ActorAuthorityV1.model_validate(forged)


@pytest.mark.parametrize(
    "build",
    (
        lambda: _actor(
            M8ActorRole.LEADER,
            scope_kind=M8ActorScopeKind.LOCATIONS,
            scope_location_ids=("room-chem-301",),
        ),
        lambda: _actor(
            M8ActorRole.STUDENT,
            scope_kind=M8ActorScopeKind.CAMPUS_WIDE,
        ),
        lambda: _actor(
            M8ActorRole.SAFETY_OFFICER,
            scope_kind=M8ActorScopeKind.LOCATIONS,
            scope_location_ids=(),
        ),
        lambda: _actor(
            M8ActorRole.OPERATIONS,
            scope_kind=M8ActorScopeKind.LOCATIONS,
            scope_location_ids=("room-b", "room-a"),
        ),
    ),
)
def test_actor_authority_rejects_role_scope_grafts(
    build: Callable[[], M8ActorAuthorityV1],
) -> None:
    with pytest.raises(ValidationError):
        build()


def test_automated_create_is_pending_human_review_only_and_propagates_simulation() -> None:
    command = _create_command()

    assert command.initial_status == M8OperationalCaseStatus.PENDING_VERIFICATION
    assert command.human_verification_required is True
    assert command.direct_disciplinary_action_permitted is False
    assert command.simulation_disclosure_required is True
    assert command.display_badge == "SIMULATED INPUT · PENDING VERIFICATION"
    assert len(command.case_id) == 64
    assert len(command.create_command_id) == 64
    Draft202012Validator(
        M8OperationalCaseCreateCommandV1.model_json_schema(mode="serialization")
    ).validate(command.model_dump(mode="json"))

    for field, value in (
        ("initial_status", M8OperationalCaseStatus.CONFIRMED.value),
        ("human_verification_required", False),
        ("direct_disciplinary_action_permitted", True),
        ("simulation_disclosure_required", False),
    ):
        forged = command.model_dump(mode="json")
        forged[field] = value
        with pytest.raises(ValidationError, match=field):
            M8OperationalCaseCreateCommandV1.model_validate(forged)


def test_automated_create_rejects_source_and_trigger_inventory_grafts() -> None:
    command = _create_command()

    with pytest.raises(ValidationError, match="stable"):
        command.model_copy(update={"source_ids": tuple(reversed(command.source_ids))})
    with pytest.raises(ValidationError, match="subset"):
        command.model_copy(update={"simulated_source_ids": ("unknown-source",)})
    with pytest.raises(ValidationError, match="unique"):
        command.model_copy(update={"trigger_authorities": (command.trigger_authorities[0],) * 2})


@pytest.mark.parametrize(
    (
        "action",
        "source_status",
        "target_status",
        "required_capability",
        "role",
        "reason_code",
        "appeal_resolution",
    ),
    _ACTION_CASES,
)
def test_transition_matrix_requires_exact_human_role_capability_and_state(
    action: M8OperationalCaseAction,
    source_status: M8OperationalCaseStatus,
    target_status: M8OperationalCaseStatus,
    required_capability: M8Capability,
    role: M8ActorRole,
    reason_code: M8OperationalCaseReasonCode,
    appeal_resolution: M8AppealResolution | None,
) -> None:
    command = _transition(
        action=action,
        source_status=source_status,
        role=role,
        reason_code=reason_code,
        appeal_resolution=appeal_resolution,
    )

    assert command.target_status == target_status
    assert command.required_capability == required_capability
    assert command.target_case_version == command.source_case_version + 1
    assert command.direct_disciplinary_action_permitted is False
    assert len(command.command_id) == 64
    Draft202012Validator(
        M8OperationalCaseTransitionCommandV1.model_json_schema(mode="serialization")
    ).validate(command.model_dump(mode="json"))


@pytest.mark.parametrize("role", (M8ActorRole.LEADER, M8ActorRole.OPERATIONS))
def test_leader_and_operations_cannot_execute_case_transitions(role: M8ActorRole) -> None:
    with pytest.raises(ValidationError, match="capability"):
        _transition(actor=_actor(role))


def test_transition_rejects_inactive_out_of_scope_and_non_subject_actors() -> None:
    with pytest.raises(ValidationError, match="active"):
        _transition(actor=_actor(M8ActorRole.SAFETY_OFFICER, active=False))
    with pytest.raises(ValidationError, match="scope"):
        _transition(
            actor=_actor(
                M8ActorRole.SAFETY_OFFICER,
                scope_location_ids=("room-other",),
            )
        )
    with pytest.raises(ValidationError, match="subject"):
        _transition(
            action=M8OperationalCaseAction.SUBMIT_APPEAL,
            source_status=M8OperationalCaseStatus.CONFIRMED,
            role=M8ActorRole.STUDENT,
            reason_code=M8OperationalCaseReasonCode.SUBJECT_DISPUTE,
            actor=_actor(M8ActorRole.STUDENT, actor_id="actor-another-student"),
        )


def test_transition_rejects_wrong_state_reason_resolution_and_confirmation() -> None:
    with pytest.raises(ValidationError, match="source status"):
        _transition(source_status=M8OperationalCaseStatus.RESOLVED)
    with pytest.raises(ValidationError, match="reason"):
        _transition(reason_code=M8OperationalCaseReasonCode.FALSE_POSITIVE)
    with pytest.raises(ValidationError, match="appeal_resolution"):
        _transition(appeal_resolution=M8AppealResolution.UPHELD)
    with pytest.raises(ValidationError, match="explicit human confirmation"):
        _transition(explicit_human_confirmation=False)
    with pytest.raises(ValidationError, match="supporting_authorities"):
        _transition().model_copy(update={"supporting_authorities": ()})


def test_transition_computed_claims_and_schema_reject_forged_authority() -> None:
    command = _transition()
    for field, value in (
        ("target_status", M8OperationalCaseStatus.REJECTED.value),
        ("required_capability", M8Capability.REJECT_CASE.value),
        ("target_case_version", 9),
        ("direct_disciplinary_action_permitted", True),
        ("command_id", "0" * 64),
    ):
        forged = command.model_dump(mode="json")
        forged[field] = value
        with pytest.raises(ValidationError, match=field):
            M8OperationalCaseTransitionCommandV1.model_validate(forged)

    # JSON Schema can freeze closed action matrices and literal safety boundaries,
    # while relative version increments and content hashes remain Pydantic authority.
    for field, value in (
        ("target_status", M8OperationalCaseStatus.REJECTED.value),
        ("required_capability", M8Capability.REJECT_CASE.value),
        ("direct_disciplinary_action_permitted", True),
    ):
        forged = command.model_dump(mode="json")
        forged[field] = value
        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(
                M8OperationalCaseTransitionCommandV1.model_json_schema(mode="serialization")
            ).validate(forged)


def test_audit_intent_binds_exact_transition_without_executing_it() -> None:
    command = _transition()
    intent = M8OperationalCaseAuditIntentV1(
        command=command,
        audit_manifest_id=SHA_C,
    )

    assert intent.case_id == command.case_id
    assert intent.before_case_version == command.source_case_version
    assert intent.after_case_version == command.target_case_version
    assert intent.before_status == command.source_status
    assert intent.after_status == command.target_status
    assert intent.actor_authority_id == command.actor_authority.actor_authority_id
    assert intent.transition_command_id == command.command_id
    assert len(intent.supporting_authority_inventory_sha256) == 64
    assert len(intent.audit_intent_id) == 64

    forged = intent.model_dump(mode="json")
    forged["after_status"] = M8OperationalCaseStatus.REJECTED.value
    with pytest.raises(ValidationError, match="after_status"):
        M8OperationalCaseAuditIntentV1.model_validate(forged)


def test_m8_access_and_case_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-actor-authority-v1": M8ActorAuthorityV1,
        "m8-authority-reference": M8AuthorityReference,
        "m8-operational-case-audit-intent-v1": M8OperationalCaseAuditIntentV1,
        "m8-operational-case-create-command-v1": M8OperationalCaseCreateCommandV1,
        "m8-operational-case-transition-command-v1": (M8OperationalCaseTransitionCommandV1),
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
    for model in expected.values():
        schema = model.model_json_schema(mode="serialization")
        assert schema["additionalProperties"] is False
