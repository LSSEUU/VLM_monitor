"""Pre-ledger runtime observations for one M6 upgrade sample execution.

These authorities capture stable logical identities while the candidate is
executing.  Artifact observations deliberately contain no physical reference,
byte digest, byte size, or Detection container claim.  The enclosing authority
commits its intended ledger sequence, but no previous hash or committed record
identity.  A later trusted verifier resolves the identities against one
database snapshot and constructs the physical ledger closure.
"""

from __future__ import annotations

from typing import Literal, Self, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import ArtifactKind, AuditAction
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionEntry,
    M6ReplayExecutionOutcome,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_PHYSICAL_IDENTIFIER_LENGTH,
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
    m6_upgrade_physical_byte_authority_for,
    require_m6_upgrade_artifact_usage,
)
from labcourt.contracts.references import ReferenceToken, parse_frame_id, require_reference_token
from labcourt.contracts.storage import ArtifactRef

MAX_M6_UPGRADE_MODEL_CALL_OBSERVATIONS_PER_SAMPLE = 1_000

_CanonicalT = TypeVar("_CanonicalT", bound=BaseModel)
_ARTIFACT_SOURCE_RANK = {
    source: index for index, source in enumerate(M6UpgradePhysicalArtifactSource)
}
_ARTIFACT_KIND_RANK = {kind: index for index, kind in enumerate(M6UpgradePhysicalArtifactKind)}
_MODEL_LAYER_RANK = {layer: index for index, layer in enumerate(M6LockedModelCallLayer)}
_MODEL_ROLE_RANK = {role: index for index, role in enumerate(M6LockedModelRole)}
_MODEL_ARTIFACT_KINDS = frozenset(
    kind for kind in M6UpgradePhysicalArtifactKind if kind.value.startswith("MODEL_")
)
_NO_CASE_ARTIFACT_KINDS = frozenset(
    {
        M6UpgradePhysicalArtifactKind.FRAME,
        M6UpgradePhysicalArtifactKind.DETECTION,
    }
)
_SELECTED_CASE_AUDIT_OBJECT_KINDS = {
    AuditAction.CASE_CREATED: frozenset({ArtifactKind.CASE}),
    AuditAction.EVIDENCE_PACK_PUBLISHED: frozenset({ArtifactKind.CASE}),
    AuditAction.CASE_STATE_CHANGED: frozenset(
        {
            ArtifactKind.CASE,
            ArtifactKind.SCREENING_RESULT,
            ArtifactKind.PROCEDURAL_REVIEW,
            ArtifactKind.BACKLOG_ITEM,
            ArtifactKind.APPEAL,
        }
    ),
    AuditAction.CASE_CLOSED: frozenset({ArtifactKind.CASE, ArtifactKind.ALERT}),
}


def _pop_claim(value: object, name: str) -> tuple[object, bool, object]:
    if not isinstance(value, dict):
        return value, False, None
    payload = dict(value)
    present = name in payload
    claim = payload.pop(name, None)
    return payload, present, claim


def _canonical_nested(expected: type[_CanonicalT], value: object, label: str) -> _CanonicalT:
    if not isinstance(value, expected):
        raise ValueError(f"{label} must be a canonical typed authority")
    controlled = expected.model_validate(
        value.model_dump(mode="json", exclude_computed_fields=True)
    )
    if controlled != value:
        raise ValueError(f"{label} must be a canonical typed authority")
    return controlled


class M6UpgradeObservedArtifactIdentity(FrozenContractModel):
    """One non-model artifact identity observed during candidate execution."""

    source: M6UpgradePhysicalArtifactSource
    kind: M6UpgradePhysicalArtifactKind
    artifact_id: str = Field(
        min_length=1,
        max_length=MAX_M6_UPGRADE_PHYSICAL_IDENTIFIER_LENGTH,
    )
    usage: M6UpgradeArtifactUsage

    @model_validator(mode="after")
    def validate_logical_identity(self) -> Self:
        if self.kind in _MODEL_ARTIFACT_KINDS:
            raise ValueError("model artifacts require a typed model-call observation")
        m6_upgrade_physical_byte_authority_for(self.source, self.kind)
        if self.kind == M6UpgradePhysicalArtifactKind.FRAME:
            parse_frame_id(self.artifact_id)
        else:
            require_reference_token(self.artifact_id, "M6 observed artifact_id")
        require_m6_upgrade_artifact_usage(self.kind, self.usage)
        return self

    @property
    def identity_key(
        self,
    ) -> tuple[M6UpgradePhysicalArtifactSource, M6UpgradePhysicalArtifactKind, str]:
        return self.source, self.kind, self.artifact_id

    @property
    def sort_key(self) -> tuple[int, int, str]:
        return (
            _ARTIFACT_SOURCE_RANK[self.source],
            _ARTIFACT_KIND_RANK[self.kind],
            self.artifact_id,
        )


class M6UpgradeObservedModelCall(FrozenContractModel):
    """Runtime facts needed to resolve one model call from trusted stores."""

    request_id: Sha256Hex
    layer: M6LockedModelCallLayer
    role: M6LockedModelRole
    attempt_index: int = Field(ge=0, le=1, strict=True)
    result_kind: M6LockedModelCallResultKind
    provider_invoked: StrictBool

    @model_validator(mode="after")
    def validate_layer_role(self) -> Self:
        if self.layer == M6LockedModelCallLayer.SCREENING:
            if self.role != M6LockedModelRole.SCREENING:
                raise ValueError("screening model observation requires the SCREENING role")
        elif self.role == M6LockedModelRole.SCREENING:
            raise ValueError("hearing model observation cannot use the SCREENING role")
        return self

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        return (
            _MODEL_LAYER_RANK[self.layer],
            _MODEL_ROLE_RANK[self.role],
            self.attempt_index,
            self.request_id,
        )


class M6UpgradeSelectedCaseAuditAnchor(FrozenContractModel):
    """Explicit selected-Case audit action and object bound to a legacy Case binding."""

    schema_version: Literal["m6-upgrade-selected-case-audit-anchor-v1"] = (
        "m6-upgrade-selected-case-audit-anchor-v1"
    )
    candidate_case_binding_id: Sha256Hex
    action: AuditAction
    object_ref: ArtifactRef

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_anchor_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, present, claim = _pop_claim(value, "selected_case_audit_anchor_id")
        anchor = handler(payload)
        if present and canonical_json(claim) != canonical_json(
            anchor.selected_case_audit_anchor_id
        ):
            raise ValueError(
                "serialized selected_case_audit_anchor_id conflicts with derived M6 anchor"
            )
        return anchor

    @model_validator(mode="after")
    def validate_case_transition_shape(self) -> Self:
        object_ref = _canonical_nested(
            ArtifactRef,
            self.object_ref,
            "M6 selected Case audit object",
        )
        allowed_kinds = _SELECTED_CASE_AUDIT_OBJECT_KINDS.get(self.action)
        if allowed_kinds is None or object_ref.kind not in allowed_kinds:
            raise ValueError(
                "M6 selected Case audit anchor must describe a recognized Case transition"
            )
        object.__setattr__(self, "object_ref", object_ref)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def selected_case_audit_anchor_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-selected-case-audit-anchor",
                1,
                self.candidate_case_binding_id,
                self.action,
                self.object_ref.kind,
                self.object_ref.artifact_id,
            ]
        )


class M6UpgradeSampleExecutionObservationAuthority(FrozenContractModel):
    """Complete logical observation captured before one ledger entry exists."""

    model_config = ConfigDict(revalidate_instances="always")

    schema_version: Literal["m6-upgrade-sample-execution-observation-authority-v1"] = (
        "m6-upgrade-sample-execution-observation-authority-v1"
    )
    execution_scope_authority_id: Sha256Hex
    candidate_run_id: ReferenceToken
    command_id: Sha256Hex
    execution_dataset_snapshot_id: Sha256Hex
    execution_entry: M6RegressionExecutionEntry
    ledger_sequence: int = Field(ge=0, strict=True)
    outcome: M6ReplayExecutionOutcome
    candidate_case: M6UpgradeCandidateCaseBinding | None = None
    artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...] = Field(
        min_length=1,
        max_length=MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    )
    model_calls: tuple[M6UpgradeObservedModelCall, ...] = Field(
        default=(),
        max_length=MAX_M6_UPGRADE_MODEL_CALL_OBSERVATIONS_PER_SAMPLE,
    )

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 observation candidate run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_observation_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, present, claim = _pop_claim(value, "observation_authority_id")
        observation = handler(payload)
        if present and canonical_json(claim) != canonical_json(
            observation.observation_authority_id
        ):
            raise ValueError(
                "serialized observation_authority_id conflicts with derived M6 execution "
                "observation"
            )
        return observation

    @model_validator(mode="after")
    def validate_complete_observation(self) -> Self:
        entry = _canonical_nested(
            M6RegressionExecutionEntry,
            self.execution_entry,
            "M6 observation execution entry",
        )
        candidate_case = self.candidate_case
        if candidate_case is not None:
            candidate_case = _canonical_nested(
                M6UpgradeCandidateCaseBinding,
                candidate_case,
                "M6 observation candidate Case binding",
            )
        if (candidate_case is not None) != (self.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED):
            raise ValueError("M6 observation outcome and candidate Case binding differ")

        artifacts = tuple(
            _canonical_nested(
                M6UpgradeObservedArtifactIdentity,
                item,
                "M6 observed non-model artifact identity",
            )
            for item in self.artifacts
        )
        artifact_keys = tuple(item.sort_key for item in artifacts)
        if artifact_keys != tuple(sorted(artifact_keys)):
            raise ValueError("M6 observed artifacts must use stable order")
        identity_keys = tuple(item.identity_key for item in artifacts)
        if len(identity_keys) != len(set(identity_keys)):
            raise ValueError("M6 observed artifact identities must be unique")
        if not any(item.kind == M6UpgradePhysicalArtifactKind.FRAME for item in artifacts):
            raise ValueError("M6 execution observation requires at least one Frame")

        model_calls = tuple(
            _canonical_nested(
                M6UpgradeObservedModelCall,
                item,
                "M6 observed model call",
            )
            for item in self.model_calls
        )
        model_keys = tuple(item.sort_key for item in model_calls)
        if model_keys != tuple(sorted(model_keys)) or len(model_keys) != len(set(model_keys)):
            raise ValueError("M6 observed model calls must be unique and ordered")
        request_ids = tuple(item.request_id for item in model_calls)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("M6 observed model request_ids must be unique")

        if candidate_case is None:
            if model_calls:
                raise ValueError("M6 observed model calls require a candidate Case")
            if any(item.kind not in _NO_CASE_ARTIFACT_KINDS for item in artifacts):
                raise ValueError("M6 NO_CASE observation permits only Frame and Detection")

        object.__setattr__(self, "execution_entry", entry)
        object.__setattr__(self, "candidate_case", candidate_case)
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "model_calls", model_calls)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def observation_authority_id(self) -> Sha256Hex:
        candidate_case = self.candidate_case
        return sha256_hex(
            [
                "m6-upgrade-sample-execution-observation-authority",
                1,
                self.execution_scope_authority_id,
                self.candidate_run_id,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.execution_entry.execution_entry_id,
                self.ledger_sequence,
                self.outcome,
                candidate_case.case_binding_id if candidate_case is not None else None,
                [[item.source, item.kind, item.artifact_id, item.usage] for item in self.artifacts],
                [
                    [
                        item.request_id,
                        item.layer,
                        item.role,
                        item.attempt_index,
                        item.result_kind,
                        item.provider_invoked,
                    ]
                    for item in self.model_calls
                ],
            ]
        )


class M6UpgradeSampleExecutionObservationAuthorityV2(M6UpgradeSampleExecutionObservationAuthority):
    """Observation that makes the selected Case audit action and object explicit."""

    schema_version: Literal["m6-upgrade-sample-execution-observation-authority-v2"] = (
        "m6-upgrade-sample-execution-observation-authority-v2"  # type: ignore[assignment]
    )
    selected_case_audit_anchor: M6UpgradeSelectedCaseAuditAnchor | None

    @model_validator(mode="after")
    def validate_selected_case_audit_anchor(self) -> Self:
        candidate_case = self.candidate_case
        anchor = self.selected_case_audit_anchor
        if candidate_case is None:
            if anchor is not None:
                raise ValueError("M6 NO_CASE forbids a selected Case audit anchor")
            return self
        if anchor is None:
            raise ValueError("M6 CASE_REPLAYED requires one selected Case audit anchor")
        anchor = _canonical_nested(
            M6UpgradeSelectedCaseAuditAnchor,
            anchor,
            "M6 selected Case audit anchor",
        )
        if anchor.candidate_case_binding_id != candidate_case.case_binding_id:
            raise ValueError("M6 selected Case audit anchor differs from candidate Case binding")
        if (candidate_case.case_revision == 1) != (anchor.action == AuditAction.CASE_CREATED):
            raise ValueError("M6 selected Case revision and audit action differ")
        if (
            anchor.object_ref.kind == ArtifactKind.CASE
            and anchor.object_ref.artifact_id != candidate_case.case_id
        ):
            raise ValueError("M6 CASE audit object must name the selected Case")
        object.__setattr__(self, "selected_case_audit_anchor", anchor)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def observation_authority_id(self) -> Sha256Hex:
        candidate_case = self.candidate_case
        anchor = self.selected_case_audit_anchor
        return sha256_hex(
            [
                "m6-upgrade-sample-execution-observation-authority",
                2,
                self.execution_scope_authority_id,
                self.candidate_run_id,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.execution_entry.execution_entry_id,
                self.ledger_sequence,
                self.outcome,
                candidate_case.case_binding_id if candidate_case is not None else None,
                anchor.selected_case_audit_anchor_id if anchor is not None else None,
                [[item.source, item.kind, item.artifact_id, item.usage] for item in self.artifacts],
                [
                    [
                        item.request_id,
                        item.layer,
                        item.role,
                        item.attempt_index,
                        item.result_kind,
                        item.provider_invoked,
                    ]
                    for item in self.model_calls
                ],
            ]
        )


__all__ = [
    "MAX_M6_UPGRADE_MODEL_CALL_OBSERVATIONS_PER_SAMPLE",
    "M6UpgradeObservedArtifactIdentity",
    "M6UpgradeObservedModelCall",
    "M6UpgradeSampleExecutionObservationAuthority",
    "M6UpgradeSampleExecutionObservationAuthorityV2",
    "M6UpgradeSelectedCaseAuditAnchor",
]
