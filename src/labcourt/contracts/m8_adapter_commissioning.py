"""M8.7 production-adapter candidates and fail-closed commissioning evidence."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8ActorRole, M8ActorScopeKind
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_COMMISSIONING_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_M8_PRODUCTION_ADAPTER_TIMEOUT_MS = 120_000
MAX_M8_RUNTIME_CONFIG_BYTES = 1024 * 1024


class M8ProductionAdapterKind(StrEnum):
    DISASTER_RECOVERY = "DISASTER_RECOVERY"
    EXTERNAL_NOTIFICATION = "EXTERNAL_NOTIFICATION"
    OBSERVABILITY = "OBSERVABILITY"
    OIDC_IDENTITY = "OIDC_IDENTITY"
    PHYSICAL_SENSOR = "PHYSICAL_SENSOR"
    RTSP_CAMERA = "RTSP_CAMERA"


class M8ExternalIdempotencyKey(StrEnum):
    BACKUP_GENERATION_ID = "BACKUP_GENERATION_ID"
    EXPORT_BATCH_ID = "EXPORT_BATCH_ID"
    NOTIFICATION_ID = "NOTIFICATION_ID"
    REQUEST_ID = "REQUEST_ID"
    SOURCE_SEQUENCE = "SOURCE_SEQUENCE"
    SUBJECT_ASSERTION_ID = "SUBJECT_ASSERTION_ID"


class M8CommissioningEvidenceKind(StrEnum):
    LICENSE_REVIEW = "LICENSE_REVIEW"
    OFFLINE_FALLBACK_DRILL = "OFFLINE_FALLBACK_DRILL"
    SAFETY_REVIEW = "SAFETY_REVIEW"
    SECURITY_REVIEW = "SECURITY_REVIEW"
    SITE_ACCEPTANCE = "SITE_ACCEPTANCE"


class M8CommissioningEvidenceOutcome(StrEnum):
    FAILED = "FAILED"
    PASSED = "PASSED"


class M8CommissioningReadiness(StrEnum):
    BLOCKED = "BLOCKED"
    READY_FOR_HUMAN_ACTIVATION = "READY_FOR_HUMAN_ACTIVATION"


_IDEMPOTENCY_BY_ADAPTER_KIND = {
    M8ProductionAdapterKind.DISASTER_RECOVERY: M8ExternalIdempotencyKey.BACKUP_GENERATION_ID,
    M8ProductionAdapterKind.EXTERNAL_NOTIFICATION: M8ExternalIdempotencyKey.NOTIFICATION_ID,
    M8ProductionAdapterKind.OBSERVABILITY: M8ExternalIdempotencyKey.EXPORT_BATCH_ID,
    M8ProductionAdapterKind.OIDC_IDENTITY: M8ExternalIdempotencyKey.SUBJECT_ASSERTION_ID,
    M8ProductionAdapterKind.PHYSICAL_SENSOR: M8ExternalIdempotencyKey.SOURCE_SEQUENCE,
    M8ProductionAdapterKind.RTSP_CAMERA: M8ExternalIdempotencyKey.SOURCE_SEQUENCE,
}
_LOCATION_SCOPED_KINDS = frozenset(
    {M8ProductionAdapterKind.PHYSICAL_SENSOR, M8ProductionAdapterKind.RTSP_CAMERA}
)
_REQUIRED_EVIDENCE = tuple(sorted(M8CommissioningEvidenceKind, key=lambda item: item.value))
_OPERATIONS_REVIEW_KINDS = frozenset(
    {
        M8CommissioningEvidenceKind.LICENSE_REVIEW,
        M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
        M8CommissioningEvidenceKind.SECURITY_REVIEW,
    }
)


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 {name} must be timezone-aware UTC")
    return value


def _canonical_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    if not any(present for present, _claimed in claims.values()):
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 commissioning authority")


def _actor_covers_candidate(
    receipt: M8ActorAuthorityCommitReceiptV1,
    candidate: M8ProductionAdapterCandidateAuthorityV1,
) -> bool:
    actor = receipt.authority
    if not actor.active:
        return False
    if actor.scope_kind == M8ActorScopeKind.CAMPUS_WIDE:
        return True
    if candidate.scope_kind == M8ActorScopeKind.CAMPUS_WIDE:
        return False
    return set(candidate.scope_location_ids).issubset(actor.scope_location_ids)


class M8ProductionAdapterCandidateAuthorityV1(FrozenContractModel):
    """A pinned external adapter candidate; it is never activation authority by itself."""

    schema_version: Literal["m8-production-adapter-candidate-authority-v1"] = (
        "m8-production-adapter-candidate-authority-v1"
    )
    adapter_id: ReferenceToken
    adapter_revision: ReferenceToken
    adapter_kind: M8ProductionAdapterKind
    provider_id: ReferenceToken
    product_revision: ReferenceToken
    campus_id: ReferenceToken
    scope_kind: M8ActorScopeKind
    scope_location_ids: tuple[ReferenceToken, ...] = Field(default=(), max_length=256)
    declared_license_id: ReferenceToken
    request_timeout_ms: int = Field(
        gt=0,
        le=MAX_M8_PRODUCTION_ADAPTER_TIMEOUT_MS,
        strict=True,
    )
    idempotency_key: M8ExternalIdempotencyKey
    network_required: StrictBool
    external_io_required: Literal[True] = True
    raw_receipt_required: Literal[True] = True
    secret_material_embedded: Literal[False] = False
    offline_fallback_adapter_id: ReferenceToken
    offline_fallback_revision: ReferenceToken
    adapter_manifest_id: Sha256Hex
    offline_fallback_manifest_id: Sha256Hex

    @field_validator(
        "adapter_id",
        "adapter_revision",
        "provider_id",
        "product_revision",
        "campus_id",
        "declared_license_id",
        "offline_fallback_adapter_id",
        "offline_fallback_revision",
    )
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 production adapter candidate reference")

    @field_validator("scope_location_ids")
    @classmethod
    def validate_scope_locations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for location_id in value:
            require_reference_token(location_id, "M8 production adapter candidate location")
        if value != tuple(sorted(value)) or len(value) != len(set(value)):
            raise ValueError("M8 adapter candidate locations must be unique and stable")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "production_activation_permitted",
                "life_safety_action_permitted",
                "direct_disciplinary_action_permitted",
                "face_recognition_permitted",
                "cross_camera_reidentification_permitted",
                "candidate_authority_id",
            ),
        )
        candidate = handler(payload)
        _verify_computed_claims(candidate, claims)
        return candidate

    @model_validator(mode="after")
    def validate_closed_kind_matrix(self) -> Self:
        if self.idempotency_key != _IDEMPOTENCY_BY_ADAPTER_KIND[self.adapter_kind]:
            raise ValueError("M8 adapter candidate idempotency key conflicts with adapter kind")
        if self.adapter_kind in _LOCATION_SCOPED_KINDS:
            if self.scope_kind != M8ActorScopeKind.LOCATIONS or not self.scope_location_ids:
                raise ValueError("M8 camera and physical sensor candidates require location scope")
        elif self.scope_kind != M8ActorScopeKind.CAMPUS_WIDE or self.scope_location_ids:
            raise ValueError("M8 campus service candidates require campus-wide scope")
        if self.offline_fallback_adapter_id == self.adapter_id:
            raise ValueError("M8 production adapter and offline fallback must be distinct")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def production_activation_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def life_safety_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def face_recognition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cross_camera_reidentification_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-production-adapter-candidate-authority",
                1,
                self.adapter_id,
                self.adapter_revision,
                self.adapter_kind,
                self.provider_id,
                self.product_revision,
                self.campus_id,
                self.scope_kind,
                self.scope_location_ids,
                self.declared_license_id,
                self.request_timeout_ms,
                self.idempotency_key,
                self.network_required,
                self.external_io_required,
                self.raw_receipt_required,
                self.secret_material_embedded,
                self.offline_fallback_adapter_id,
                self.offline_fallback_revision,
                self.adapter_manifest_id,
                self.offline_fallback_manifest_id,
                self.production_activation_permitted,
                self.life_safety_action_permitted,
                self.direct_disciplinary_action_permitted,
                self.face_recognition_permitted,
                self.cross_camera_reidentification_permitted,
            ]
        )


class M8ProductionAdapterCandidateCommitReceiptV1(FrozenContractModel):
    """Commit proof for a candidate registered by current in-scope operations authority."""

    schema_version: Literal["m8-production-adapter-candidate-commit-receipt-v1"] = (
        "m8-production-adapter-candidate-commit-receipt-v1"
    )
    candidate: M8ProductionAdapterCandidateAuthorityV1
    registered_by_actor_receipt: M8ActorAuthorityCommitReceiptV1
    repository_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("candidate_document_sha256", "commit_receipt_id"),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_registrar(self) -> Self:
        actor = self.registered_by_actor_receipt.authority
        if actor.role != M8ActorRole.OPERATIONS or not _actor_covers_candidate(
            self.registered_by_actor_receipt,
            self.candidate,
        ):
            raise ValueError("M8 adapter candidate registration requires in-scope operations actor")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.candidate.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-production-adapter-candidate-commit-receipt",
                1,
                self.candidate.candidate_authority_id,
                self.candidate_document_sha256,
                self.registered_by_actor_receipt.commit_receipt_id,
                self.repository_manifest_id,
            ]
        )


class M8CommissioningEvidenceAuthorityV1(FrozenContractModel):
    """One human-attested evidence reference for an exact adapter candidate."""

    schema_version: Literal["m8-commissioning-evidence-authority-v1"] = (
        "m8-commissioning-evidence-authority-v1"
    )
    candidate: M8ProductionAdapterCandidateAuthorityV1
    evidence_kind: M8CommissioningEvidenceKind
    outcome: M8CommissioningEvidenceOutcome
    artifact_ref: ReferenceToken
    artifact_sha256: Sha256Hex
    artifact_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_COMMISSIONING_EVIDENCE_BYTES,
        strict=True,
    )
    reviewer_actor_receipt: M8ActorAuthorityCommitReceiptV1
    reviewed_at: datetime
    valid_through: datetime | None = None
    human_attested: Literal[True] = True
    model_generated: Literal[False] = False
    simulated: StrictBool
    evidence_manifest_id: Sha256Hex

    @field_validator("artifact_ref")
    @classmethod
    def validate_artifact_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 commissioning evidence artifact")

    @field_validator("reviewed_at")
    @classmethod
    def validate_reviewed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "commissioning reviewed_at")

    @field_validator("valid_through")
    @classmethod
    def validate_valid_through(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _require_utc(value, "commissioning valid_through")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("evidence_authority_id",))
        evidence = handler(payload)
        _verify_computed_claims(evidence, claims)
        return evidence

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        if self.valid_through is not None and self.valid_through < self.reviewed_at:
            raise ValueError("M8 commissioning evidence validity precedes its review")
        expected_role = (
            M8ActorRole.OPERATIONS
            if self.evidence_kind in _OPERATIONS_REVIEW_KINDS
            else M8ActorRole.SAFETY_OFFICER
        )
        if self.reviewer_actor_receipt.authority.role != expected_role:
            raise ValueError("M8 commissioning evidence uses an unauthorized reviewer role")
        if not _actor_covers_candidate(self.reviewer_actor_receipt, self.candidate):
            raise ValueError("M8 commissioning reviewer does not cover the candidate scope")
        if (
            self.evidence_kind != M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL
            and self.simulated
        ):
            raise ValueError("M8 review and site evidence cannot be simulated")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-commissioning-evidence-authority",
                1,
                self.candidate.candidate_authority_id,
                self.evidence_kind,
                self.outcome,
                self.artifact_ref,
                self.artifact_sha256,
                self.artifact_size_bytes,
                self.reviewer_actor_receipt.commit_receipt_id,
                _canonical_utc(self.reviewed_at),
                _canonical_utc(self.valid_through),
                self.human_attested,
                self.model_generated,
                self.simulated,
                self.evidence_manifest_id,
            ]
        )


class M8CommissioningEvidenceCommitReceiptV1(FrozenContractModel):
    """Commit proof binding one evidence authority to persisted raw artifact bytes."""

    schema_version: Literal["m8-commissioning-evidence-commit-receipt-v1"] = (
        "m8-commissioning-evidence-commit-receipt-v1"
    )
    evidence: M8CommissioningEvidenceAuthorityV1
    artifact_storage_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("evidence_document_sha256", "commit_receipt_id"),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.evidence.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-commissioning-evidence-commit-receipt",
                1,
                self.evidence.evidence_authority_id,
                self.evidence_document_sha256,
                self.evidence.artifact_ref,
                self.evidence.artifact_sha256,
                self.evidence.artifact_size_bytes,
                self.artifact_storage_manifest_id,
                self.repository_manifest_id,
            ]
        )


class M8AdapterReadinessAssessmentV1(FrozenContractModel):
    """A read-only readiness result that still cannot activate an external adapter."""

    schema_version: Literal["m8-adapter-readiness-assessment-v1"] = (
        "m8-adapter-readiness-assessment-v1"
    )
    candidate: M8ProductionAdapterCandidateAuthorityV1
    evidence: tuple[M8CommissioningEvidenceCommitReceiptV1, ...] = Field(
        max_length=len(M8CommissioningEvidenceKind)
    )
    assessor_actor_receipt: M8ActorAuthorityCommitReceiptV1
    assessed_at: datetime
    assessment_manifest_id: Sha256Hex

    @field_validator("assessed_at")
    @classmethod
    def validate_assessed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "adapter readiness assessed_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "required_evidence_kinds",
                "missing_evidence_kinds",
                "failed_evidence_kinds",
                "expired_evidence_kinds",
                "evidence_inventory_sha256",
                "readiness",
                "human_activation_required",
                "production_activation_permitted",
                "life_safety_action_permitted",
                "direct_disciplinary_action_permitted",
                "assessment_id",
            ),
        )
        assessment = handler(payload)
        _verify_computed_claims(assessment, claims)
        return assessment

    @model_validator(mode="after")
    def validate_closed_assessment(self) -> Self:
        kinds = tuple(item.evidence.evidence_kind for item in self.evidence)
        if kinds != tuple(sorted(kinds, key=lambda item: item.value)):
            raise ValueError("M8 commissioning evidence must use stable kind order")
        if len(kinds) != len(set(kinds)):
            raise ValueError("M8 commissioning assessment cannot duplicate evidence kinds")
        if any(item.evidence.candidate != self.candidate for item in self.evidence):
            raise ValueError("M8 commissioning assessment grafts evidence from another candidate")
        if any(item.evidence.reviewed_at > self.assessed_at for item in self.evidence):
            raise ValueError("M8 commissioning evidence cannot postdate its assessment")
        assessor = self.assessor_actor_receipt.authority
        if assessor.role != M8ActorRole.OPERATIONS or not _actor_covers_candidate(
            self.assessor_actor_receipt,
            self.candidate,
        ):
            raise ValueError("M8 readiness assessment requires an in-scope operations actor")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def required_evidence_kinds(self) -> tuple[M8CommissioningEvidenceKind, ...]:
        return _REQUIRED_EVIDENCE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def missing_evidence_kinds(self) -> tuple[M8CommissioningEvidenceKind, ...]:
        present = {item.evidence.evidence_kind for item in self.evidence}
        return tuple(item for item in _REQUIRED_EVIDENCE if item not in present)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def failed_evidence_kinds(self) -> tuple[M8CommissioningEvidenceKind, ...]:
        return tuple(
            item.evidence.evidence_kind
            for item in self.evidence
            if item.evidence.outcome == M8CommissioningEvidenceOutcome.FAILED
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def expired_evidence_kinds(self) -> tuple[M8CommissioningEvidenceKind, ...]:
        return tuple(
            item.evidence.evidence_kind
            for item in self.evidence
            if item.evidence.valid_through is not None
            and item.evidence.valid_through < self.assessed_at
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex([item.commit_receipt_id for item in self.evidence])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def readiness(self) -> M8CommissioningReadiness:
        if self.missing_evidence_kinds or self.failed_evidence_kinds or self.expired_evidence_kinds:
            return M8CommissioningReadiness.BLOCKED
        return M8CommissioningReadiness.READY_FOR_HUMAN_ACTIVATION

    @computed_field  # type: ignore[prop-decorator]
    @property
    def human_activation_required(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def production_activation_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def life_safety_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def assessment_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-adapter-readiness-assessment",
                1,
                self.candidate.candidate_authority_id,
                self.evidence_inventory_sha256,
                self.assessor_actor_receipt.commit_receipt_id,
                _canonical_utc(self.assessed_at),
                self.assessment_manifest_id,
                self.required_evidence_kinds,
                self.missing_evidence_kinds,
                self.failed_evidence_kinds,
                self.expired_evidence_kinds,
                self.readiness,
                self.human_activation_required,
                self.production_activation_permitted,
                self.life_safety_action_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


class M8AdapterActivationIntentV1(FrozenContractModel):
    """Dual-human intent to persist activation; it cannot call the adapter itself."""

    schema_version: Literal["m8-adapter-activation-intent-v1"] = "m8-adapter-activation-intent-v1"
    readiness_assessment: M8AdapterReadinessAssessmentV1
    operations_actor_receipt: M8ActorAuthorityCommitReceiptV1
    safety_actor_receipt: M8ActorAuthorityCommitReceiptV1
    runtime_config_ref: ReferenceToken
    runtime_config_sha256: Sha256Hex
    runtime_config_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_RUNTIME_CONFIG_BYTES,
        strict=True,
    )
    credential_reference_id: ReferenceToken | None = None
    requested_at: datetime
    operations_explicit_confirmation: Literal[True] = True
    safety_explicit_confirmation: Literal[True] = True
    secret_material_embedded: Literal[False] = False
    activation_manifest_id: Sha256Hex

    @field_validator("runtime_config_ref")
    @classmethod
    def validate_runtime_config_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 adapter runtime config")

    @field_validator("credential_reference_id")
    @classmethod
    def validate_credential_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 adapter credential reference")

    @field_validator("requested_at")
    @classmethod
    def validate_requested_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "adapter activation requested_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "activation_commit_permitted",
                "external_call_permitted",
                "automatic_activation_permitted",
                "life_safety_action_permitted",
                "direct_disciplinary_action_permitted",
                "face_recognition_permitted",
                "cross_camera_reidentification_permitted",
                "activation_intent_id",
            ),
        )
        intent = handler(payload)
        _verify_computed_claims(intent, claims)
        return intent

    @model_validator(mode="after")
    def validate_dual_human_gate(self) -> Self:
        assessment = self.readiness_assessment
        candidate = assessment.candidate
        if assessment.readiness != M8CommissioningReadiness.READY_FOR_HUMAN_ACTIVATION:
            raise ValueError("M8 adapter activation requires complete current readiness")
        operations_actor = self.operations_actor_receipt.authority
        safety_actor = self.safety_actor_receipt.authority
        if operations_actor.role != M8ActorRole.OPERATIONS or not _actor_covers_candidate(
            self.operations_actor_receipt,
            candidate,
        ):
            raise ValueError("M8 adapter activation requires in-scope operations confirmation")
        if safety_actor.role != M8ActorRole.SAFETY_OFFICER or not _actor_covers_candidate(
            self.safety_actor_receipt,
            candidate,
        ):
            raise ValueError("M8 adapter activation requires in-scope safety confirmation")
        if operations_actor.actor_id == safety_actor.actor_id:
            raise ValueError("M8 adapter activation requires two distinct human actors")
        evidence_repository_manifests = {
            item.repository_manifest_id for item in assessment.evidence
        }
        if evidence_repository_manifests != {
            self.operations_actor_receipt.repository_manifest_id
        } or evidence_repository_manifests != {self.safety_actor_receipt.repository_manifest_id}:
            raise ValueError("M8 adapter activation authorities cross repository manifests")
        if candidate.network_required and self.credential_reference_id is None:
            raise ValueError("M8 network adapter activation requires a secret-store reference")
        if self.requested_at < assessment.assessed_at:
            raise ValueError("M8 adapter activation cannot predate readiness assessment")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def activation_commit_permitted(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_call_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_activation_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def life_safety_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def face_recognition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cross_camera_reidentification_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def activation_intent_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-adapter-activation-intent",
                1,
                self.readiness_assessment.assessment_id,
                self.operations_actor_receipt.commit_receipt_id,
                self.safety_actor_receipt.commit_receipt_id,
                self.runtime_config_ref,
                self.runtime_config_sha256,
                self.runtime_config_size_bytes,
                self.credential_reference_id,
                _canonical_utc(self.requested_at),
                self.operations_explicit_confirmation,
                self.safety_explicit_confirmation,
                self.secret_material_embedded,
                self.activation_manifest_id,
                self.activation_commit_permitted,
                self.external_call_permitted,
                self.automatic_activation_permitted,
                self.life_safety_action_permitted,
                self.direct_disciplinary_action_permitted,
                self.face_recognition_permitted,
                self.cross_camera_reidentification_permitted,
            ]
        )


__all__ = [
    "MAX_M8_COMMISSIONING_EVIDENCE_BYTES",
    "MAX_M8_PRODUCTION_ADAPTER_TIMEOUT_MS",
    "MAX_M8_RUNTIME_CONFIG_BYTES",
    "M8AdapterActivationIntentV1",
    "M8AdapterReadinessAssessmentV1",
    "M8CommissioningEvidenceAuthorityV1",
    "M8CommissioningEvidenceCommitReceiptV1",
    "M8CommissioningEvidenceKind",
    "M8CommissioningEvidenceOutcome",
    "M8CommissioningReadiness",
    "M8ExternalIdempotencyKey",
    "M8ProductionAdapterCandidateAuthorityV1",
    "M8ProductionAdapterCandidateCommitReceiptV1",
    "M8ProductionAdapterKind",
]
