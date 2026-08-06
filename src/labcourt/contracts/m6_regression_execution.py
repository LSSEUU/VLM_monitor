"""Additive physical authorities for M6 upgrade candidate outputs.

The frozen report v1 remains unchanged.  These evaluator-blind authorities
close the physical candidate-run boundary before results and receipts are
derived by the report assembler.
"""

from __future__ import annotations

import hashlib
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
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ExecutionLocation,
    ProviderTransport,
    ReproducibilityMode,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression import (
    MAX_M6_REGRESSION_CASES,
    M6CaseReplaySnapshot,
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionRunCommand,
    M6ReplayExecutionOutcome,
    M6ReplayExecutionReceipt,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionLedgerSealV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
    m6_upgrade_physical_artifact_requires_case,
)
from labcourt.contracts.manifests import REQUIRED_MODEL_COMPONENTS, RunManifest
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE = 20_000
MAX_M6_UPGRADE_MODEL_CALLS_PER_SAMPLE = 1_000

_CanonicalT = TypeVar("_CanonicalT", bound=BaseModel)

M6UpgradeCandidateArtifactKind = M6UpgradePhysicalArtifactKind
M6UpgradeCandidateArtifactRef = M6UpgradePhysicalArtifactRef

_MODEL_LAYER_RANK = {kind: index for index, kind in enumerate(M6LockedModelCallLayer)}
_MODEL_ROLE_RANK = {kind: index for index, kind in enumerate(M6LockedModelRole)}


def _pop_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M6 upgrade content")


def _canonical_nested(expected: type[_CanonicalT], value: object, label: str) -> _CanonicalT:
    if not isinstance(value, expected):
        raise ValueError(f"{label} must be a canonical typed authority")
    controlled = expected.model_validate(
        value.model_dump(mode="json", exclude_computed_fields=True)
    )
    if controlled != value:
        raise ValueError(f"{label} must be a canonical typed authority")
    return controlled


def _physical_content_sha256(value: BaseModel) -> Sha256Hex:
    document = canonical_json(value.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _physical_size_bytes(value: BaseModel) -> int:
    return len(canonical_json(value.model_dump(mode="json")).encode("utf-8"))


class M6UpgradeCandidateModelCallAuthority(FrozenContractModel):
    """One offline-fake model call with timeout, cache, manifest, and raw proof."""

    sample_id: ReferenceToken
    layer: M6LockedModelCallLayer
    role: M6LockedModelRole
    attempt_index: int = Field(ge=0, le=1, strict=True)
    provider_mode: Literal["FAKE_OFFLINE"] = "FAKE_OFFLINE"
    timeout_ms: int = Field(gt=0, le=3_600_000, strict=True)
    execution_model_manifest_id: Sha256Hex
    provider_invoked: StrictBool
    request_ref: M6UpgradeCandidateArtifactRef
    cache_ref: M6UpgradeCandidateArtifactRef | None = None
    result_kind: M6LockedModelCallResultKind
    response_ref: M6UpgradeCandidateArtifactRef | None = None
    parse_receipt_ref: M6UpgradeCandidateArtifactRef | None = None
    parsed_output_ref: M6UpgradeCandidateArtifactRef | None = None
    failure_ref: M6UpgradeCandidateArtifactRef | None = None
    usage_receipt_ref: M6UpgradeCandidateArtifactRef | None = None

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 upgrade model-call sample_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_call_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("model_call_authority_id",))
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_call_matrix(self) -> Self:
        refs = tuple(
            _canonical_nested(
                M6UpgradeCandidateArtifactRef,
                ref,
                "M6 upgrade model-call artifact",
            )
            for ref in (
                self.request_ref,
                self.cache_ref,
                self.response_ref,
                self.parse_receipt_ref,
                self.parsed_output_ref,
                self.failure_ref,
                self.usage_receipt_ref,
            )
            if ref is not None
        )
        if len({item.physical_key for item in refs}) != len(refs):
            raise ValueError("M6 upgrade model-call physical artifacts must be unique")
        if self.request_ref.kind != M6UpgradeCandidateArtifactKind.MODEL_REQUEST:
            raise ValueError("M6 upgrade model call requires a request authority")
        expected_source = (
            M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
            if self.layer == M6LockedModelCallLayer.SCREENING
            else M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
        )
        if any(item.source != expected_source for item in refs):
            raise ValueError("M6 upgrade model call uses another physical model layer")
        if (
            self.cache_ref is not None
            and self.cache_ref.kind != M6UpgradeCandidateArtifactKind.MODEL_CACHE
        ):
            raise ValueError("M6 upgrade model-call cache uses another artifact kind")
        if self.layer == M6LockedModelCallLayer.SCREENING:
            if self.role != M6LockedModelRole.SCREENING:
                raise ValueError("M6 upgrade model role conflicts with its layer")
        elif self.role == M6LockedModelRole.SCREENING:
            raise ValueError("M6 upgrade model role conflicts with its layer")

        if self.result_kind == M6LockedModelCallResultKind.RESPONSE:
            if (
                self.response_ref is None
                or self.cache_ref is None
                or self.parse_receipt_ref is None
                or self.usage_receipt_ref is None
                or self.failure_ref is not None
                or self.response_ref.kind != M6UpgradeCandidateArtifactKind.MODEL_RESPONSE
                or self.parse_receipt_ref.kind != M6UpgradeCandidateArtifactKind.MODEL_PARSE_RECEIPT
                or self.usage_receipt_ref.kind != M6UpgradeCandidateArtifactKind.MODEL_USAGE_RECEIPT
                or (
                    self.parsed_output_ref is not None
                    and self.parsed_output_ref.kind
                    != M6UpgradeCandidateArtifactKind.MODEL_PARSED_OUTPUT
                )
            ):
                raise ValueError("M6 upgrade response model-call closure is incomplete")
        elif (
            self.failure_ref is None
            or self.cache_ref is not None
            or self.response_ref is not None
            or self.parse_receipt_ref is not None
            or self.parsed_output_ref is not None
            or self.usage_receipt_ref is not None
            or self.failure_ref.kind != M6UpgradeCandidateArtifactKind.MODEL_CALL_FAILURE
        ):
            raise ValueError("M6 upgrade failed model-call closure is incomplete")
        return self

    @property
    def artifact_refs(self) -> tuple[M6UpgradeCandidateArtifactRef, ...]:
        return tuple(
            ref
            for ref in (
                self.request_ref,
                self.response_ref,
                self.cache_ref,
                self.parse_receipt_ref,
                self.parsed_output_ref,
                self.failure_ref,
                self.usage_receipt_ref,
            )
            if ref is not None
        )

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        return (
            _MODEL_LAYER_RANK[self.layer],
            _MODEL_ROLE_RANK[self.role],
            self.attempt_index,
            self.request_ref.artifact_id,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_call_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-model-call-authority",
                1,
                self.sample_id,
                self.layer,
                self.role,
                self.attempt_index,
                self.provider_mode,
                self.timeout_ms,
                self.execution_model_manifest_id,
                self.provider_invoked,
                [item.artifact_ref_id for item in self.artifact_refs],
                self.result_kind,
            ]
        )


class M6UpgradeCandidateRunCutAuthority(FrozenContractModel):
    """One immutable physical cut of the complete candidate run."""

    schema_version: Literal["m6-upgrade-candidate-run-cut-authority-v1"] = (
        "m6-upgrade-candidate-run-cut-authority-v1"
    )
    candidate_run_id: ReferenceToken
    candidate_manifest: RunManifest
    candidate_manifest_content_sha256: Sha256Hex
    candidate_config: AppConfig
    candidate_config_content_sha256: Sha256Hex
    execution_component_manifest_id: Sha256Hex
    audit_head_sequence: int = Field(ge=-1, strict=True)
    audit_head_hash: Sha256Hex
    validation_report: M5ArtifactValidationReport
    validation_report_content_sha256: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 upgrade candidate run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("candidate_run_cut_authority_id",))
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_physical_run_cut(self) -> Self:
        manifest = _canonical_nested(
            RunManifest,
            self.candidate_manifest,
            "M6 candidate manifest",
        )
        report = _canonical_nested(
            M5ArtifactValidationReport,
            self.validation_report,
            "M6 candidate validation report",
        )
        config = _canonical_nested(
            AppConfig,
            self.candidate_config,
            "M6 candidate config",
        )
        predecessor = report.predecessor_report
        if not isinstance(predecessor, M4ArtifactValidationReport):
            raise ValueError("M6 upgrade candidate requires a complete M4 predecessor report")
        m4_report = _canonical_nested(
            M4ArtifactValidationReport,
            predecessor,
            "M6 candidate M4 validation report",
        )
        m3_report = m4_report.m3_report
        m2_report = m3_report.m2_report
        role_profiles = {
            "screening": config.screening.provider_profile,
            "prosecutor": config.hearing.prosecutor_profile,
            "defender": config.hearing.defender_profile,
            "judge": config.hearing.judge_profile,
        }
        offline_profiles_match = all(
            (
                (profile := config.providers[profile_name]).provider == "fake"
                and profile.execution_location == ExecutionLocation.LOCAL
                and profile.transport == ProviderTransport.IN_PROCESS
                and (model := manifest.models[role]).provider == profile.provider
                and model.model == profile.model
                and model.revision == profile.revision
                and model.quantization == profile.quantization
            )
            for role, profile_name in role_profiles.items()
        )
        offline_component_providers_match = config.perception.provider == "precomputed" and all(
            manifest.models[component_name].provider == expected_provider
            for component_name, expected_provider in {
                "detector": "precomputed",
                "tracker": "precomputed",
                "pose": "precomputed",
                "text_embedding": "fake",
                "visual_embedding": "fake",
            }.items()
        )
        if (
            manifest.reproducibility_mode != ReproducibilityMode.UPGRADE_REGRESSION
            or config.run.reproducibility_mode != ReproducibilityMode.UPGRADE_REGRESSION
            or config.config_sha256 != manifest.config_sha256
            or set(manifest.models) != REQUIRED_MODEL_COMPONENTS
            or _physical_content_sha256(manifest) != self.candidate_manifest_content_sha256
            or _physical_content_sha256(config) != self.candidate_config_content_sha256
            or not offline_profiles_match
            or not offline_component_providers_match
            or not report.passed
            or not m4_report.passed
            or not m3_report.passed
            or not m2_report.passed
            or report.run_id != self.candidate_run_id
            or report.manifest_id != manifest.manifest_id
            or report.config_sha256 != manifest.config_sha256
            or _physical_content_sha256(report) != self.validation_report_content_sha256
            or m2_report.manifest_id != manifest.manifest_id
            or m2_report.audit_head_sequence != self.audit_head_sequence
            or m2_report.audit_head_hash != self.audit_head_hash
        ):
            raise ValueError("M6 upgrade candidate run cut is not one exact passing run")
        object.__setattr__(self, "candidate_manifest", manifest)
        object.__setattr__(self, "candidate_config", config)
        object.__setattr__(self, "validation_report", report)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_run_cut_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-run-cut-authority",
                1,
                self.candidate_run_id,
                self.candidate_manifest.manifest_id,
                self.candidate_manifest_content_sha256,
                self.candidate_config.config_sha256,
                self.candidate_config_content_sha256,
                self.execution_component_manifest_id,
                self.audit_head_sequence,
                self.audit_head_hash,
                self.validation_report.report_id,
                self.validation_report_content_sha256,
                self.validation_report.authority_root_sha256,
            ]
        )


class M6UpgradeCandidateCaseDocumentRef(FrozenContractModel):
    case_id: ReferenceToken
    case_revision: int = Field(gt=0, strict=True)
    case_document_sha256: Sha256Hex

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 upgrade candidate case_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_ref_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("case_document_ref_id",))
        reference = handler(payload)
        _verify_claims(reference, claims)
        return reference

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_document_ref_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-case-document-ref",
                1,
                self.case_id,
                self.case_revision,
                self.case_document_sha256,
            ]
        )

    @property
    def sort_key(self) -> tuple[str, int]:
        return self.case_id, self.case_revision


class M6UpgradeCandidateSampleOutputAuthority(FrozenContractModel):
    """Complete evaluator-blind output authority for one execution entry."""

    schema_version: Literal["m6-upgrade-candidate-sample-output-authority-v1"] = (
        "m6-upgrade-candidate-sample-output-authority-v1"
    )
    mode: Literal[ReproducibilityMode.UPGRADE_REGRESSION] = ReproducibilityMode.UPGRADE_REGRESSION
    command_id: Sha256Hex
    execution_dataset_snapshot_id: Sha256Hex
    execution_entry: M6RegressionExecutionEntry
    sample_execution_record_id: Sha256Hex
    candidate_run_cut_authority_id: Sha256Hex
    candidate_run_id: ReferenceToken
    candidate_manifest_id: Sha256Hex
    execution_component_manifest_id: Sha256Hex
    outcome: M6ReplayExecutionOutcome
    candidate_snapshot: M6CaseReplaySnapshot | None = None
    frames: tuple[M6UpgradeCandidateArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE,
    )
    detections: tuple[M6UpgradeCandidateArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE,
    )
    model_calls: tuple[M6UpgradeCandidateModelCallAuthority, ...] = Field(
        default=(),
        max_length=MAX_M6_UPGRADE_MODEL_CALLS_PER_SAMPLE,
    )
    embeddings: tuple[M6UpgradeCandidateArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE,
    )
    precedent_exposures: tuple[M6UpgradeCandidateArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE,
    )
    tool_execution_manifests: tuple[M6UpgradeCandidateArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE,
    )
    tool_results: tuple[M6UpgradeCandidateArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE,
    )
    evidence_packs: tuple[M6UpgradeCandidateArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE,
    )

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 upgrade sample candidate run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "sample_id",
                "execution_entry_id",
                "candidate_snapshot_content_sha256",
                "detection_count",
                "detection_inventory_root_sha256",
                "model_response_count",
                "model_response_inventory_root_sha256",
                "embedding_count",
                "embedding_inventory_root_sha256",
                "tool_result_count",
                "tool_result_inventory_root_sha256",
                "model_call_count",
                "model_call_inventory_root_sha256",
                "provider_call_count",
                "artifact_count",
                "artifact_inventory_root_sha256",
                "execution_receipt",
                "candidate_output_authority_id",
            ),
        )
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_complete_output(self) -> Self:
        entry = _canonical_nested(
            M6RegressionExecutionEntry,
            self.execution_entry,
            "M6 upgrade execution entry",
        )
        snapshot = self.candidate_snapshot
        if snapshot is not None:
            snapshot = _canonical_nested(
                M6CaseReplaySnapshot,
                snapshot,
                "M6 upgrade candidate snapshot",
            )
        has_case = snapshot is not None
        if has_case != (self.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED):
            raise ValueError("M6 upgrade outcome and candidate snapshot binding differ")
        if snapshot is not None and (
            snapshot.sample_id != entry.sample_id
            or snapshot.source_run_id != self.candidate_run_id
            or snapshot.manifest_id != self.candidate_manifest_id
        ):
            raise ValueError("M6 upgrade candidate snapshot differs from its execution scope")

        typed_groups = (
            (
                self.frames,
                M6UpgradeCandidateArtifactKind.FRAME,
                "frames",
            ),
            (
                self.detections,
                M6UpgradeCandidateArtifactKind.DETECTION,
                "detections",
            ),
            (
                self.embeddings,
                M6UpgradeCandidateArtifactKind.EMBEDDING,
                "embeddings",
            ),
            (
                self.precedent_exposures,
                M6UpgradeCandidateArtifactKind.PRECEDENT_EXPOSURE,
                "precedent_exposures",
            ),
            (
                self.tool_execution_manifests,
                M6UpgradeCandidateArtifactKind.TOOL_EXECUTION_MANIFEST,
                "tool_execution_manifests",
            ),
            (
                self.tool_results,
                M6UpgradeCandidateArtifactKind.TOOL_RESULT,
                "tool_results",
            ),
            (
                self.evidence_packs,
                M6UpgradeCandidateArtifactKind.EVIDENCE_PACK,
                "evidence_packs",
            ),
        )
        direct_refs: list[M6UpgradeCandidateArtifactRef] = []
        for values, expected_kind, label in typed_groups:
            canonical = tuple(
                _canonical_nested(
                    M6UpgradeCandidateArtifactRef,
                    item,
                    f"M6 upgrade candidate {label}",
                )
                for item in values
            )
            if canonical != values or any(item.kind != expected_kind for item in canonical):
                raise ValueError(f"M6 upgrade candidate {label} use another artifact kind")
            keys = tuple(item.sort_key for item in canonical)
            if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
                raise ValueError(f"M6 upgrade candidate {label} must be unique and ordered")
            direct_refs.extend(canonical)

        calls = tuple(
            _canonical_nested(
                M6UpgradeCandidateModelCallAuthority,
                item,
                "M6 upgrade candidate model call",
            )
            for item in self.model_calls
        )
        call_keys = tuple(item.sort_key for item in calls)
        if call_keys != tuple(sorted(call_keys)) or len(call_keys) != len(set(call_keys)):
            raise ValueError("M6 upgrade candidate model calls must be unique and ordered")
        if any(item.sample_id != entry.sample_id for item in calls):
            raise ValueError("M6 upgrade candidate model call uses another sample scope")
        all_refs = tuple(direct_refs) + tuple(ref for call in calls for ref in call.artifact_refs)
        if len(all_refs) > MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE:
            raise ValueError("M6 upgrade candidate artifact inventory exceeds its bound")
        if not has_case and any(
            m6_upgrade_physical_artifact_requires_case(ref.kind) for ref in all_refs
        ):
            raise ValueError("M6 upgrade no-Case sample cannot claim case-scoped artifacts")
        by_physical_key: dict[tuple[int, int, str, str], M6UpgradeCandidateArtifactRef] = {}
        for ref in all_refs:
            prior = by_physical_key.setdefault(ref.physical_key, ref)
            if prior != ref:
                raise ValueError(
                    "M6 upgrade physical artifact identity conflicts within the sample"
                )
        frame_ids = {frame.artifact_id for frame in self.frames}
        if any(detection.container_id not in frame_ids for detection in self.detections):
            raise ValueError(
                "M6 upgrade candidate Detection must belong to a Frame in the same sample"
            )
        object.__setattr__(self, "execution_entry", entry)
        object.__setattr__(self, "candidate_snapshot", snapshot)
        object.__setattr__(self, "model_calls", calls)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_id(self) -> ReferenceToken:
        return self.execution_entry.sample_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_entry_id(self) -> Sha256Hex:
        return self.execution_entry.execution_entry_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_snapshot_content_sha256(self) -> Sha256Hex | None:
        snapshot = self.candidate_snapshot
        return _physical_content_sha256(snapshot) if snapshot is not None else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def detection_count(self) -> int:
        return len(self.detections)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def detection_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-detection-inventory",
                1,
                [item.artifact_ref_id for item in self.detections],
            ]
        )

    def _response_refs(self) -> tuple[M6UpgradeCandidateArtifactRef, ...]:
        refs = tuple(
            call.response_ref for call in self.model_calls if call.response_ref is not None
        )
        return tuple({item.artifact_id: item for item in refs}.values())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_response_count(self) -> int:
        return len(self._response_refs())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_response_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-model-response-inventory",
                1,
                [item.artifact_ref_id for item in self._response_refs()],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def embedding_count(self) -> int:
        return len(self.embeddings)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def embedding_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-embedding-inventory",
                1,
                [item.artifact_ref_id for item in self.embeddings],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def tool_result_count(self) -> int:
        return len(self.tool_results)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def tool_result_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-tool-result-inventory",
                1,
                [item.artifact_ref_id for item in self.tool_results],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_call_count(self) -> int:
        return len(self.model_calls)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_call_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-model-call-inventory",
                1,
                [item.model_call_authority_id for item in self.model_calls],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_call_count(self) -> int:
        return sum(item.provider_invoked for item in self.model_calls)

    def _all_artifact_refs(self) -> tuple[M6UpgradeCandidateArtifactRef, ...]:
        return (
            self.frames
            + self.detections
            + tuple(ref for call in self.model_calls for ref in call.artifact_refs)
            + self.embeddings
            + self.precedent_exposures
            + self.tool_execution_manifests
            + self.tool_results
            + self.evidence_packs
        )

    def _unique_artifact_refs(self) -> tuple[M6UpgradeCandidateArtifactRef, ...]:
        by_physical_key = {item.physical_key: item for item in self._all_artifact_refs()}
        return tuple(sorted(by_physical_key.values(), key=lambda item: item.sort_key))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_count(self) -> int:
        return len(self._unique_artifact_refs())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-sample-artifact-inventory",
                1,
                [item.artifact_ref_id for item in self._unique_artifact_refs()],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_receipt(self) -> M6ReplayExecutionReceipt:
        snapshot = self.candidate_snapshot
        return M6ReplayExecutionReceipt(
            command_id=self.command_id,
            mode=self.mode,
            sample_id=self.sample_id,
            execution_entry_id=self.execution_entry_id,
            candidate_run_id=self.candidate_run_id,
            candidate_manifest_id=self.candidate_manifest_id,
            execution_component_manifest_id=self.execution_component_manifest_id,
            outcome=self.outcome,
            candidate_snapshot_id=(snapshot.snapshot_id if snapshot is not None else None),
            detection_count=self.detection_count,
            detection_inventory_root_sha256=self.detection_inventory_root_sha256,
            model_response_count=self.model_response_count,
            model_response_inventory_root_sha256=(self.model_response_inventory_root_sha256),
            embedding_count=self.embedding_count,
            embedding_inventory_root_sha256=self.embedding_inventory_root_sha256,
            tool_result_count=self.tool_result_count,
            tool_result_inventory_root_sha256=self.tool_result_inventory_root_sha256,
            provider_call_count=self.provider_call_count,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_output_authority_id(self) -> Sha256Hex:
        snapshot = self.candidate_snapshot
        return sha256_hex(
            [
                "m6-upgrade-candidate-sample-output-authority",
                1,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.execution_entry_id,
                self.sample_execution_record_id,
                self.candidate_run_cut_authority_id,
                self.candidate_run_id,
                self.candidate_manifest_id,
                self.execution_component_manifest_id,
                self.outcome,
                snapshot.snapshot_id if snapshot is not None else None,
                self.candidate_snapshot_content_sha256,
                self.model_call_count,
                self.model_call_inventory_root_sha256,
                self.artifact_count,
                self.artifact_inventory_root_sha256,
                self.execution_receipt.execution_receipt_id,
            ]
        )


class M6UpgradeCandidateOutputInventoryAuthority(FrozenContractModel):
    """Complete, ordered candidate output inventory for one upgrade command."""

    model_config = ConfigDict(revalidate_instances="always")

    schema_version: Literal["m6-upgrade-candidate-output-inventory-authority-v1"] = (
        "m6-upgrade-candidate-output-inventory-authority-v1"
    )
    command: M6RegressionRunCommand
    execution_dataset: M6RegressionExecutionDatasetSnapshot
    candidate_run_cut: M6UpgradeCandidateRunCutAuthority
    execution_ledger: M6UpgradeExecutionLedgerSeal
    execution_ledger_content_sha256: Sha256Hex
    execution_ledger_size_bytes: int = Field(
        gt=0, le=MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES, strict=True
    )
    candidate_cases: tuple[M6UpgradeCandidateCaseDocumentRef, ...] = Field(
        default=(),
        max_length=MAX_M6_REGRESSION_CASES,
    )
    outputs: tuple[M6UpgradeCandidateSampleOutputAuthority, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )

    @classmethod
    def _execution_ledger_model(cls) -> type[M6UpgradeExecutionLedgerSeal]:
        return M6UpgradeExecutionLedgerSeal

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "output_count",
                "candidate_case_count",
                "candidate_case_inventory_root_sha256",
                "model_call_count",
                "model_call_inventory_root_sha256",
                "artifact_link_count",
                "artifact_count",
                "artifact_inventory_root_sha256",
                "candidate_output_inventory_root_sha256",
                "candidate_output_inventory_authority_id",
            ),
        )
        inventory = handler(payload)
        _verify_claims(inventory, claims)
        return inventory

    @model_validator(mode="after")
    def validate_complete_candidate_inventory(self) -> Self:
        command = _canonical_nested(
            M6RegressionRunCommand,
            self.command,
            "M6 upgrade command",
        )
        dataset = _canonical_nested(
            M6RegressionExecutionDatasetSnapshot,
            self.execution_dataset,
            "M6 upgrade execution dataset",
        )
        run_cut = _canonical_nested(
            M6UpgradeCandidateRunCutAuthority,
            self.candidate_run_cut,
            "M6 upgrade candidate run cut",
        )
        ledger = _canonical_nested(
            type(self)._execution_ledger_model(),
            self.execution_ledger,
            "M6 upgrade execution ledger",
        )
        cases = tuple(
            _canonical_nested(
                M6UpgradeCandidateCaseDocumentRef,
                item,
                "M6 upgrade candidate Case reference",
            )
            for item in self.candidate_cases
        )
        outputs = tuple(
            _canonical_nested(
                M6UpgradeCandidateSampleOutputAuthority,
                item,
                "M6 upgrade candidate sample output",
            )
            for item in self.outputs
        )
        if (
            command.mode != ReproducibilityMode.UPGRADE_REGRESSION
            or command.execution_dataset_snapshot_id != dataset.execution_dataset_snapshot_id
            or command.baseline_manifest_id != dataset.baseline_manifest_id
            or command.candidate_manifest_id != run_cut.candidate_manifest.manifest_id
            or ledger.command != command
            or ledger.execution_dataset != dataset
            or ledger.candidate_run_id != run_cut.candidate_run_id
            or ledger.candidate_manifest_id != run_cut.candidate_manifest.manifest_id
            or ledger.candidate_manifest_content_sha256 != run_cut.candidate_manifest_content_sha256
            or ledger.candidate_config_sha256 != run_cut.candidate_config.config_sha256
            or ledger.candidate_config_content_sha256 != run_cut.candidate_config_content_sha256
            or ledger.execution_component.component_authority_id
            != run_cut.execution_component_manifest_id
            or ledger.source_audit_head_sequence != run_cut.audit_head_sequence
            or ledger.source_audit_head_hash != run_cut.audit_head_hash
            or run_cut.validation_report.counts.case_roots != ledger.candidate_case_count
            or _physical_content_sha256(ledger) != self.execution_ledger_content_sha256
            or _physical_size_bytes(ledger) != self.execution_ledger_size_bytes
        ):
            raise ValueError("M6 upgrade inventory command, ledger, and run cut differ")

        case_keys = tuple(item.sort_key for item in cases)
        case_ids = tuple(item.case_id for item in cases)
        if case_keys != tuple(sorted(case_keys)) or len(case_ids) != len(set(case_ids)):
            raise ValueError("M6 upgrade candidate Cases must be unique and ordered")
        if len(outputs) != len(dataset.entries):
            raise ValueError("M6 upgrade output inventory must cover every execution entry")
        model_component_by_role = {
            M6LockedModelRole.SCREENING: "screening",
            M6LockedModelRole.PROSECUTOR: "prosecutor",
            M6LockedModelRole.DEFENDER: "defender",
            M6LockedModelRole.JUDGE: "judge",
        }
        provider_profile_by_role = {
            M6LockedModelRole.SCREENING: (run_cut.candidate_config.screening.provider_profile),
            M6LockedModelRole.PROSECUTOR: (run_cut.candidate_config.hearing.prosecutor_profile),
            M6LockedModelRole.DEFENDER: (run_cut.candidate_config.hearing.defender_profile),
            M6LockedModelRole.JUDGE: run_cut.candidate_config.hearing.judge_profile,
        }
        for execution_entry, record, output in zip(
            dataset.entries,
            ledger.sample_executions,
            outputs,
            strict=True,
        ):
            if (
                output.command_id != command.command_id
                or output.execution_dataset_snapshot_id != dataset.execution_dataset_snapshot_id
                or output.execution_entry != execution_entry
                or output.sample_execution_record_id != record.sample_execution_record_id
                or output.candidate_run_cut_authority_id != run_cut.candidate_run_cut_authority_id
                or output.candidate_run_id != run_cut.candidate_run_id
                or output.candidate_manifest_id != run_cut.candidate_manifest.manifest_id
                or output.execution_component_manifest_id != run_cut.execution_component_manifest_id
            ):
                raise ValueError("M6 upgrade sample output differs from its exact run scope")
            snapshot = output.candidate_snapshot
            case_binding = record.candidate_case
            if (
                output.outcome != record.outcome
                or (snapshot is None) != (case_binding is None)
                or (
                    snapshot is not None
                    and case_binding is not None
                    and (
                        snapshot.source_case_id != case_binding.case_id
                        or snapshot.source_case_revision != case_binding.case_revision
                        or snapshot.source_case_document_sha256 != case_binding.case_document_sha256
                    )
                )
            ):
                raise ValueError("M6 upgrade sample output differs from its ledger Case binding")
            output_artifact_ids = tuple(
                item.artifact_ref_id for item in output._unique_artifact_refs()
            )
            ledger_artifact_ids = tuple(
                item.artifact.artifact_ref_id for item in record.artifact_links
            )
            if output_artifact_ids != ledger_artifact_ids:
                raise ValueError("M6 upgrade sample output and ledger artifacts differ")
            ledger_usage_by_artifact = {
                item.artifact.artifact_ref_id: item.usage for item in record.artifact_links
            }
            if any(
                call.cache_ref is not None
                and ledger_usage_by_artifact[call.cache_ref.artifact_ref_id]
                != (
                    M6UpgradeArtifactUsage.PRODUCED
                    if call.provider_invoked
                    else M6UpgradeArtifactUsage.CONSUMED
                )
                for call in output.model_calls
            ):
                raise ValueError("M6 upgrade model cache usage conflicts with provider delivery")
            if any(
                (
                    call.execution_model_manifest_id
                    != run_cut.candidate_manifest.models[
                        model_component_by_role[call.role]
                    ].model_manifest_id
                    or call.timeout_ms
                    > int(
                        run_cut.candidate_config.providers[
                            provider_profile_by_role[call.role]
                        ].timeout_seconds
                        * 1_000
                    )
                )
                for call in output.model_calls
            ):
                raise ValueError("M6 upgrade model call differs from its offline candidate profile")
        output_ids = tuple(item.candidate_output_authority_id for item in outputs)
        if len(output_ids) != len(set(output_ids)):
            raise ValueError("M6 upgrade candidate outputs must be unique")
        physical_artifacts: dict[tuple[int, int, str, str], M6UpgradeCandidateArtifactRef] = {}
        for output in outputs:
            for ref in output._unique_artifact_refs():
                prior = physical_artifacts.setdefault(ref.physical_key, ref)
                if prior != ref:
                    raise ValueError(
                        "M6 upgrade physical artifact identity conflicts across samples"
                    )
        model_call_ids = tuple(
            call.model_call_authority_id for output in outputs for call in output.model_calls
        )
        if len(model_call_ids) != len(set(model_call_ids)):
            raise ValueError("M6 upgrade model calls must be unique across all samples")

        derived_cases = tuple(
            sorted(
                (
                    M6UpgradeCandidateCaseDocumentRef(
                        case_id=snapshot.source_case_id,
                        case_revision=snapshot.source_case_revision,
                        case_document_sha256=snapshot.source_case_document_sha256,
                    )
                    for output in outputs
                    if (snapshot := output.candidate_snapshot) is not None
                ),
                key=lambda item: item.sort_key,
            )
        )
        if derived_cases != cases:
            raise ValueError(
                "M6 upgrade candidate output Cases differ from the physical Case inventory"
            )
        object.__setattr__(self, "command", command)
        object.__setattr__(self, "execution_dataset", dataset)
        object.__setattr__(self, "candidate_run_cut", run_cut)
        object.__setattr__(self, "execution_ledger", ledger)
        object.__setattr__(self, "candidate_cases", cases)
        object.__setattr__(self, "outputs", outputs)
        if _physical_size_bytes(self) > MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES:
            raise ValueError("M6 upgrade output inventory exceeds its document byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def output_count(self) -> int:
        return len(self.outputs)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_case_count(self) -> int:
        return len(self.candidate_cases)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_case_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-case-inventory",
                1,
                [item.case_document_ref_id for item in self.candidate_cases],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_call_count(self) -> int:
        return sum(item.model_call_count for item in self.outputs)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_call_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-global-model-call-inventory",
                1,
                [
                    [
                        item.candidate_output_authority_id,
                        item.model_call_count,
                        item.model_call_inventory_root_sha256,
                    ]
                    for item in self.outputs
                ],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_link_count(self) -> int:
        return sum(item.artifact_count for item in self.outputs)

    def _unique_artifact_refs(self) -> tuple[M6UpgradeCandidateArtifactRef, ...]:
        by_physical_key = {
            ref.physical_key: ref
            for output in self.outputs
            for ref in output._unique_artifact_refs()
        }
        return tuple(sorted(by_physical_key.values(), key=lambda item: item.sort_key))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_count(self) -> int:
        return len(self._unique_artifact_refs())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-artifact-inventory",
                1,
                [item.artifact_ref_id for item in self._unique_artifact_refs()],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_output_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-output-inventory",
                1,
                [item.candidate_output_authority_id for item in self.outputs],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_output_inventory_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-output-inventory-authority",
                1,
                self.command.command_id,
                self.execution_dataset.execution_dataset_snapshot_id,
                self.candidate_run_cut.candidate_run_cut_authority_id,
                self.execution_ledger.ledger_seal_authority_id,
                self.execution_ledger_content_sha256,
                self.execution_ledger_size_bytes,
                self.output_count,
                self.candidate_case_count,
                self.candidate_case_inventory_root_sha256,
                self.model_call_count,
                self.model_call_inventory_root_sha256,
                self.artifact_link_count,
                self.artifact_count,
                self.artifact_inventory_root_sha256,
                self.candidate_output_inventory_root_sha256,
            ]
        )


class M6UpgradeCandidateOutputInventoryAuthorityV2(M6UpgradeCandidateOutputInventoryAuthority):
    """Observation-backed candidate inventory with exact, bidirectional joins."""

    schema_version: Literal["m6-upgrade-candidate-output-inventory-authority-v2"] = (
        "m6-upgrade-candidate-output-inventory-authority-v2"  # type: ignore[assignment]
    )
    execution_ledger: M6UpgradeExecutionLedgerSealV2
    execution_observations: tuple[M6UpgradeSampleExecutionObservationAuthority, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )

    @classmethod
    def _execution_ledger_model(cls) -> type[M6UpgradeExecutionLedgerSeal]:
        return M6UpgradeExecutionLedgerSealV2

    @classmethod
    def _execution_observation_model(
        cls,
    ) -> type[M6UpgradeSampleExecutionObservationAuthority]:
        return M6UpgradeSampleExecutionObservationAuthority

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_observation_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "execution_observation_count",
                "execution_observation_inventory_root_sha256",
            ),
        )
        inventory = handler(payload)
        _verify_claims(inventory, claims)
        return inventory

    @model_validator(mode="after")
    def validate_observation_backed_inventory(self) -> Self:
        observation_model = type(self)._execution_observation_model()
        observations = tuple(
            _canonical_nested(
                observation_model,
                item,
                "M6 upgrade execution observation",
            )
            for item in self.execution_observations
        )
        records = self.execution_ledger.sample_executions
        entries = self.execution_dataset.entries
        if len(observations) != len(entries):
            raise ValueError(
                "M6 upgrade v2 inventory must cover every execution entry with an observation"
            )
        observation_ids = tuple(item.observation_authority_id for item in observations)
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("M6 upgrade v2 execution observations must be unique")

        for index, (entry, record, output, observation) in enumerate(
            zip(entries, records, self.outputs, observations, strict=True)
        ):
            if (
                observation.execution_entry != entry
                or observation.ledger_sequence != index
                or observation.ledger_sequence != record.ledger_sequence
                or observation.execution_scope_authority_id
                != self.execution_ledger.execution_scope.execution_scope_authority_id
                or observation.candidate_run_id != self.candidate_run_cut.candidate_run_id
                or observation.command_id != self.command.command_id
                or observation.execution_dataset_snapshot_id
                != self.execution_dataset.execution_dataset_snapshot_id
                or observation.outcome != record.outcome
                or observation.outcome != output.outcome
                or observation.candidate_case != record.candidate_case
                or record.observation_authority_id != observation.observation_authority_id
            ):
                raise ValueError(
                    "M6 upgrade v2 observation differs from its exact sample execution scope"
                )

            observed_artifacts = {
                (item.source, item.kind, item.artifact_id): item.usage
                for item in observation.artifacts
            }
            ledger_non_model_links = tuple(
                item
                for item in record.artifact_links
                if not item.artifact.kind.value.startswith("MODEL_")
            )
            ledger_artifacts = {
                (item.artifact.source, item.artifact.kind, item.artifact.artifact_id): item.usage
                for item in ledger_non_model_links
            }
            output_non_model_refs = tuple(
                item
                for item in output._unique_artifact_refs()
                if not item.kind.value.startswith("MODEL_")
            )
            output_artifact_identities = {
                (item.source, item.kind, item.artifact_id) for item in output_non_model_refs
            }
            if (
                len(ledger_artifacts) != len(ledger_non_model_links)
                or len(output_artifact_identities) != len(output_non_model_refs)
                or observed_artifacts != ledger_artifacts
                or set(observed_artifacts) != output_artifact_identities
            ):
                raise ValueError(
                    "M6 upgrade v2 ordinary observations, outputs, and ledger links differ"
                )

            observed_model_calls = {
                item.request_id: (
                    item.layer,
                    item.role,
                    item.attempt_index,
                    item.result_kind,
                    item.provider_invoked,
                )
                for item in observation.model_calls
            }
            output_model_calls = {
                item.request_ref.artifact_id: (
                    item.layer,
                    item.role,
                    item.attempt_index,
                    item.result_kind,
                    item.provider_invoked,
                )
                for item in output.model_calls
            }
            if (
                len(observed_model_calls) != len(observation.model_calls)
                or len(output_model_calls) != len(output.model_calls)
                or observed_model_calls != output_model_calls
            ):
                raise ValueError(
                    "M6 upgrade v2 model observations and candidate model calls differ"
                )

        object.__setattr__(self, "execution_observations", observations)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_observation_count(self) -> int:
        return len(self.execution_observations)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_observation_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-execution-observation-inventory",
                2,
                [item.observation_authority_id for item in self.execution_observations],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_output_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-output-inventory",
                2,
                [
                    [
                        output.candidate_output_authority_id,
                        observation.observation_authority_id,
                    ]
                    for output, observation in zip(
                        self.outputs,
                        self.execution_observations,
                        strict=True,
                    )
                ],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_output_inventory_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-output-inventory-authority",
                2,
                self.command.command_id,
                self.execution_dataset.execution_dataset_snapshot_id,
                self.candidate_run_cut.candidate_run_cut_authority_id,
                self.execution_ledger.ledger_seal_authority_id,
                self.execution_ledger_content_sha256,
                self.execution_ledger_size_bytes,
                self.output_count,
                self.candidate_case_count,
                self.candidate_case_inventory_root_sha256,
                self.model_call_count,
                self.model_call_inventory_root_sha256,
                self.artifact_link_count,
                self.artifact_count,
                self.artifact_inventory_root_sha256,
                self.execution_observation_count,
                self.execution_observation_inventory_root_sha256,
                self.candidate_output_inventory_root_sha256,
            ]
        )


class M6UpgradeCandidateOutputInventoryAuthorityV3(M6UpgradeCandidateOutputInventoryAuthorityV2):
    """Terminal inventory backed by explicit selected-Case audit anchors."""

    schema_version: Literal["m6-upgrade-candidate-output-inventory-authority-v3"] = (
        "m6-upgrade-candidate-output-inventory-authority-v3"  # type: ignore[assignment]
    )
    execution_observations: tuple[M6UpgradeSampleExecutionObservationAuthorityV2, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )

    @classmethod
    def _execution_observation_model(
        cls,
    ) -> type[M6UpgradeSampleExecutionObservationAuthority]:
        return M6UpgradeSampleExecutionObservationAuthorityV2

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_observation_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-execution-observation-inventory",
                3,
                [item.observation_authority_id for item in self.execution_observations],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_output_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-output-inventory",
                3,
                [
                    [
                        output.candidate_output_authority_id,
                        observation.observation_authority_id,
                    ]
                    for output, observation in zip(
                        self.outputs,
                        self.execution_observations,
                        strict=True,
                    )
                ],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_output_inventory_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-output-inventory-authority",
                3,
                self.command.command_id,
                self.execution_dataset.execution_dataset_snapshot_id,
                self.candidate_run_cut.candidate_run_cut_authority_id,
                self.execution_ledger.ledger_seal_authority_id,
                self.execution_ledger_content_sha256,
                self.execution_ledger_size_bytes,
                self.output_count,
                self.candidate_case_count,
                self.candidate_case_inventory_root_sha256,
                self.model_call_count,
                self.model_call_inventory_root_sha256,
                self.artifact_link_count,
                self.artifact_count,
                self.artifact_inventory_root_sha256,
                self.execution_observation_count,
                self.execution_observation_inventory_root_sha256,
                self.candidate_output_inventory_root_sha256,
            ]
        )


__all__ = [
    "MAX_M6_UPGRADE_ARTIFACTS_PER_SAMPLE",
    "MAX_M6_UPGRADE_MODEL_CALLS_PER_SAMPLE",
    "M6UpgradeCandidateArtifactKind",
    "M6UpgradeCandidateArtifactRef",
    "M6UpgradeCandidateCaseDocumentRef",
    "M6UpgradeCandidateModelCallAuthority",
    "M6UpgradeCandidateOutputInventoryAuthority",
    "M6UpgradeCandidateOutputInventoryAuthorityV2",
    "M6UpgradeCandidateOutputInventoryAuthorityV3",
    "M6UpgradeCandidateRunCutAuthority",
    "M6UpgradeCandidateSampleOutputAuthority",
]
