from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
)
from labcourt.contracts.m8_adapter_commissioning import (
    M8AdapterReadinessAssessmentV1,
    M8CommissioningEvidenceAuthorityV1,
    M8CommissioningEvidenceCommitReceiptV1,
    M8CommissioningEvidenceKind,
    M8CommissioningEvidenceOutcome,
    M8CommissioningReadiness,
    M8ExternalIdempotencyKey,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterKind,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.schema_registry import SCHEMA_MODELS

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
REVIEWED_AT = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)
ASSESSED_AT = REVIEWED_AT + timedelta(hours=1)


def _actor_receipt(
    role: M8ActorRole,
    *,
    scope_kind: M8ActorScopeKind = M8ActorScopeKind.LOCATIONS,
    scope_location_ids: tuple[str, ...] = ("room-chem-301",),
    active: bool = True,
) -> M8ActorAuthorityCommitReceiptV1:
    actor = M8ActorAuthorityV1(
        actor_id=f"{role.value.lower().replace('_', '-')}-commissioning-01",
        role=role,
        scope_kind=scope_kind,
        scope_location_ids=scope_location_ids,
        identity_provider_id="campus-idp",
        subject_binding_sha256=SHA_A,
        authority_revision=1,
        active=active,
        manifest_id=SHA_B,
    )
    return M8ActorAuthorityCommitReceiptV1(
        authority=actor,
        repository_manifest_id=SHA_C,
    )


def _candidate(
    *,
    kind: M8ProductionAdapterKind = M8ProductionAdapterKind.RTSP_CAMERA,
) -> M8ProductionAdapterCandidateAuthorityV1:
    location_scoped = kind in {
        M8ProductionAdapterKind.RTSP_CAMERA,
        M8ProductionAdapterKind.PHYSICAL_SENSOR,
    }
    idempotency = {
        M8ProductionAdapterKind.DISASTER_RECOVERY: (M8ExternalIdempotencyKey.BACKUP_GENERATION_ID),
        M8ProductionAdapterKind.EXTERNAL_NOTIFICATION: M8ExternalIdempotencyKey.NOTIFICATION_ID,
        M8ProductionAdapterKind.OBSERVABILITY: M8ExternalIdempotencyKey.EXPORT_BATCH_ID,
        M8ProductionAdapterKind.OIDC_IDENTITY: M8ExternalIdempotencyKey.SUBJECT_ASSERTION_ID,
        M8ProductionAdapterKind.PHYSICAL_SENSOR: M8ExternalIdempotencyKey.SOURCE_SEQUENCE,
        M8ProductionAdapterKind.RTSP_CAMERA: M8ExternalIdempotencyKey.SOURCE_SEQUENCE,
    }[kind]
    return M8ProductionAdapterCandidateAuthorityV1(
        adapter_id=f"candidate-{kind.value.lower().replace('_', '-')}",
        adapter_revision="revision-01",
        adapter_kind=kind,
        provider_id="provider-reviewed-01",
        product_revision="product-revision-01",
        campus_id="campus-main",
        scope_kind=(
            M8ActorScopeKind.LOCATIONS if location_scoped else M8ActorScopeKind.CAMPUS_WIDE
        ),
        scope_location_ids=("room-chem-301",) if location_scoped else (),
        declared_license_id="license-review-required",
        request_timeout_ms=5_000,
        idempotency_key=idempotency,
        network_required=kind != M8ProductionAdapterKind.PHYSICAL_SENSOR,
        offline_fallback_adapter_id="m8-offline-fake-adapter",
        offline_fallback_revision="offline-revision-01",
        adapter_manifest_id=SHA_A,
        offline_fallback_manifest_id=SHA_B,
    )


def _evidence(
    kind: M8CommissioningEvidenceKind,
    *,
    candidate: M8ProductionAdapterCandidateAuthorityV1 | None = None,
    outcome: M8CommissioningEvidenceOutcome = M8CommissioningEvidenceOutcome.PASSED,
    valid_through: datetime | None = REVIEWED_AT + timedelta(days=30),
) -> M8CommissioningEvidenceCommitReceiptV1:
    reviewer_role = (
        M8ActorRole.OPERATIONS
        if kind
        in {
            M8CommissioningEvidenceKind.LICENSE_REVIEW,
            M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
            M8CommissioningEvidenceKind.SECURITY_REVIEW,
        }
        else M8ActorRole.SAFETY_OFFICER
    )
    return M8CommissioningEvidenceCommitReceiptV1(
        evidence=M8CommissioningEvidenceAuthorityV1(
            candidate=candidate or _candidate(),
            evidence_kind=kind,
            outcome=outcome,
            artifact_ref=f"evidence-{kind.value.lower().replace('_', '-')}",
            artifact_sha256=SHA_C,
            artifact_size_bytes=128,
            reviewer_actor_receipt=_actor_receipt(reviewer_role),
            reviewed_at=REVIEWED_AT,
            valid_through=valid_through,
            simulated=kind == M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
            evidence_manifest_id=SHA_D,
        ),
        artifact_storage_manifest_id=SHA_A,
        repository_manifest_id=SHA_B,
    )


def _assessment(
    evidence: tuple[M8CommissioningEvidenceCommitReceiptV1, ...],
    *,
    candidate: M8ProductionAdapterCandidateAuthorityV1 | None = None,
) -> M8AdapterReadinessAssessmentV1:
    resolved_candidate = candidate or _candidate()
    return M8AdapterReadinessAssessmentV1(
        candidate=resolved_candidate,
        evidence=tuple(sorted(evidence, key=lambda item: item.evidence.evidence_kind.value)),
        assessor_actor_receipt=_actor_receipt(M8ActorRole.OPERATIONS),
        assessed_at=ASSESSED_AT,
        assessment_manifest_id=SHA_D,
    )


def test_candidate_closes_adapter_scope_idempotency_and_safety_boundaries() -> None:
    for kind in M8ProductionAdapterKind:
        candidate = _candidate(kind=kind)
        assert candidate.production_activation_permitted is False
        assert candidate.life_safety_action_permitted is False
        assert candidate.direct_disciplinary_action_permitted is False
        assert candidate.face_recognition_permitted is False
        assert candidate.cross_camera_reidentification_permitted is False
        assert candidate.raw_receipt_required is True
        assert candidate.secret_material_embedded is False

    with pytest.raises(ValidationError, match="idempotency key"):
        _candidate().model_copy(update={"idempotency_key": M8ExternalIdempotencyKey.REQUEST_ID})
    with pytest.raises(ValidationError, match="require location scope"):
        _candidate().model_copy(
            update={"scope_kind": M8ActorScopeKind.CAMPUS_WIDE, "scope_location_ids": ()}
        )
    with pytest.raises(ValidationError, match="campus-wide scope"):
        _candidate(kind=M8ProductionAdapterKind.OIDC_IDENTITY).model_copy(
            update={
                "scope_kind": M8ActorScopeKind.LOCATIONS,
                "scope_location_ids": ("room-chem-301",),
            }
        )


def test_evidence_requires_human_role_scope_and_real_site_review() -> None:
    site = _evidence(M8CommissioningEvidenceKind.SITE_ACCEPTANCE).evidence
    assert site.human_attested is True
    assert site.model_generated is False
    assert site.simulated is False

    with pytest.raises(ValidationError, match="unauthorized reviewer role"):
        site.model_copy(update={"reviewer_actor_receipt": _actor_receipt(M8ActorRole.OPERATIONS)})
    with pytest.raises(ValidationError, match="cannot be simulated"):
        site.model_copy(update={"simulated": True})
    with pytest.raises(ValidationError, match="does not cover"):
        site.model_copy(
            update={
                "reviewer_actor_receipt": _actor_receipt(
                    M8ActorRole.SAFETY_OFFICER,
                    scope_location_ids=("room-physics-201",),
                )
            }
        )


def test_readiness_reports_missing_failed_and_expired_evidence_without_activation() -> None:
    candidate = _candidate()
    blocked = _assessment(
        (
            _evidence(M8CommissioningEvidenceKind.LICENSE_REVIEW, candidate=candidate),
            _evidence(
                M8CommissioningEvidenceKind.SECURITY_REVIEW,
                candidate=candidate,
                outcome=M8CommissioningEvidenceOutcome.FAILED,
            ),
            _evidence(
                M8CommissioningEvidenceKind.SAFETY_REVIEW,
                candidate=candidate,
                valid_through=REVIEWED_AT,
            ),
        ),
        candidate=candidate,
    )
    assert blocked.readiness == M8CommissioningReadiness.BLOCKED
    assert blocked.missing_evidence_kinds == (
        M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
        M8CommissioningEvidenceKind.SITE_ACCEPTANCE,
    )
    assert blocked.failed_evidence_kinds == (M8CommissioningEvidenceKind.SECURITY_REVIEW,)
    assert blocked.expired_evidence_kinds == (M8CommissioningEvidenceKind.SAFETY_REVIEW,)
    assert blocked.production_activation_permitted is False
    assert blocked.human_activation_required is True


def test_complete_readiness_still_requires_separate_human_activation() -> None:
    candidate = _candidate()
    evidence = tuple(_evidence(kind, candidate=candidate) for kind in M8CommissioningEvidenceKind)
    assessment = _assessment(evidence, candidate=candidate)
    assert assessment.readiness == M8CommissioningReadiness.READY_FOR_HUMAN_ACTIVATION
    assert assessment.missing_evidence_kinds == ()
    assert assessment.failed_evidence_kinds == ()
    assert assessment.expired_evidence_kinds == ()
    assert assessment.production_activation_permitted is False
    assert assessment.life_safety_action_permitted is False
    assert assessment.direct_disciplinary_action_permitted is False


def test_assessment_rejects_candidate_graft_duplicate_and_future_evidence() -> None:
    candidate = _candidate()
    license_evidence = _evidence(
        M8CommissioningEvidenceKind.LICENSE_REVIEW,
        candidate=candidate,
    )
    with pytest.raises(ValidationError, match="duplicate evidence"):
        _assessment((license_evidence, license_evidence), candidate=candidate)
    foreign = _evidence(
        M8CommissioningEvidenceKind.SECURITY_REVIEW,
        candidate=_candidate(kind=M8ProductionAdapterKind.PHYSICAL_SENSOR),
    )
    with pytest.raises(ValidationError, match="another candidate"):
        _assessment((foreign,), candidate=candidate)
    with pytest.raises(ValidationError, match="postdate"):
        _assessment(
            (
                license_evidence.model_copy(
                    update={
                        "evidence": license_evidence.evidence.model_copy(
                            update={
                                "reviewed_at": ASSESSED_AT + timedelta(seconds=1),
                                "valid_through": ASSESSED_AT + timedelta(days=1),
                            }
                        )
                    }
                ),
            ),
            candidate=candidate,
        )


@pytest.mark.parametrize(
    "model",
    (
        _candidate(),
        _evidence(M8CommissioningEvidenceKind.LICENSE_REVIEW),
        _evidence(M8CommissioningEvidenceKind.LICENSE_REVIEW).evidence,
        _assessment((), candidate=_candidate()),
    ),
)
def test_commissioning_contracts_validate_as_serialization_schemas(model: BaseModel) -> None:
    schema = type(model).model_json_schema(mode="serialization")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(model.model_dump(mode="json"))


@pytest.mark.parametrize(
    ("model", "field"),
    (
        (_candidate(), "production_activation_permitted"),
        (_candidate(), "candidate_authority_id"),
        (
            _evidence(M8CommissioningEvidenceKind.LICENSE_REVIEW),
            "commit_receipt_id",
        ),
        (
            _evidence(M8CommissioningEvidenceKind.LICENSE_REVIEW).evidence,
            "evidence_authority_id",
        ),
        (_assessment((), candidate=_candidate()), "readiness"),
        (_assessment((), candidate=_candidate()), "assessment_id"),
    ),
)
def test_commissioning_contracts_reject_computed_claim_forgery(
    model: BaseModel,
    field: str,
) -> None:
    payload = model.model_dump(mode="json")
    payload[field] = "0" * 64 if field.endswith("id") else True
    with pytest.raises(ValidationError, match=field):
        type(model).model_validate(payload)


def test_commissioning_schemas_are_registered_serialization_roots() -> None:
    expected = {
        "m8-adapter-readiness-assessment-v1": M8AdapterReadinessAssessmentV1,
        "m8-commissioning-evidence-authority-v1": M8CommissioningEvidenceAuthorityV1,
        "m8-commissioning-evidence-commit-receipt-v1": (M8CommissioningEvidenceCommitReceiptV1),
        "m8-production-adapter-candidate-authority-v1": (M8ProductionAdapterCandidateAuthorityV1),
    }
    for schema_name, model in expected.items():
        assert SCHEMA_MODELS[schema_name] is model
