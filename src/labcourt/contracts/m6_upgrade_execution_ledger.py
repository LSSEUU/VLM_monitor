"""Append-only, evaluator-blind physical execution ledger for M6 upgrades."""

from __future__ import annotations

import hashlib
from typing import Literal, Self, TypeVar

from pydantic import (
    BaseModel,
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ExecutionLocation,
    ProviderTransport,
    ReproducibilityMode,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m6_regression import (
    MAX_M6_REGRESSION_CASES,
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionRunCommand,
    M6ReplayExecutionOutcome,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
    m6_upgrade_physical_artifact_requires_case,
    require_m6_upgrade_artifact_usage,
)
from labcourt.contracts.manifests import REQUIRED_MODEL_COMPONENTS, RunManifest
from labcourt.contracts.references import ReferenceToken, require_reference_token

M6_UPGRADE_LEDGER_GENESIS_HASH = "0" * 64
MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE = 20_000
MAX_M6_UPGRADE_LEDGER_LINKS = 250_000
MAX_M6_UPGRADE_COMPONENT_VERSION_LENGTH = 128
MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES = 256 * 1024 * 1024
MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES = 64 * 1024 * 1024

_CanonicalT = TypeVar("_CanonicalT", bound=BaseModel)


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
            raise ValueError(f"serialized {name} conflicts with derived M6 upgrade ledger")


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


class M6UpgradeExecutionComponentAuthority(FrozenContractModel):
    schema_version: Literal["m6-upgrade-execution-component-authority-v1"] = (
        "m6-upgrade-execution-component-authority-v1"
    )
    component: Literal["labcourt-m6-upgrade-executor"] = "labcourt-m6-upgrade-executor"
    package: Literal["labcourt"] = "labcourt"
    version: str = Field(min_length=1, max_length=MAX_M6_UPGRADE_COMPONENT_VERSION_LENGTH)
    code_commit: str = Field(min_length=1, max_length=128)
    execution_mode: Literal["OFFLINE_FAKE"] = "OFFLINE_FAKE"
    input_contract: Literal["BLINDED_EXECUTION_DATASET"] = "BLINDED_EXECUTION_DATASET"
    output_contract: Literal["APPEND_ONLY_SAMPLE_LEDGER"] = "APPEND_ONLY_SAMPLE_LEDGER"
    network_allowed: Literal[False] = False
    gpu_required: Literal[False] = False
    evaluator_fields_accessible: Literal[False] = False

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("component_authority_id",))
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @computed_field  # type: ignore[prop-decorator]
    @property
    def component_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-execution-component-authority",
                1,
                self.component,
                self.package,
                self.version,
                self.code_commit,
                self.execution_mode,
                self.input_contract,
                self.output_contract,
                self.network_allowed,
                self.gpu_required,
                self.evaluator_fields_accessible,
            ]
        )


class M6UpgradeExecutionScopeAuthority(FrozenContractModel):
    """Execution-start cut persisted before any candidate sample can commit."""

    schema_version: Literal["m6-upgrade-execution-scope-authority-v1"] = (
        "m6-upgrade-execution-scope-authority-v1"
    )
    candidate_run_id: ReferenceToken
    command: M6RegressionRunCommand
    command_content_sha256: Sha256Hex
    command_size_bytes: int = Field(gt=0, le=MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES, strict=True)
    execution_dataset: M6RegressionExecutionDatasetSnapshot
    execution_dataset_content_sha256: Sha256Hex
    execution_dataset_size_bytes: int = Field(
        gt=0, le=MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES, strict=True
    )
    candidate_manifest: RunManifest
    candidate_manifest_content_sha256: Sha256Hex
    candidate_manifest_size_bytes: int = Field(
        gt=0, le=MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES, strict=True
    )
    candidate_config: AppConfig
    candidate_config_content_sha256: Sha256Hex
    candidate_config_size_bytes: int = Field(
        gt=0, le=MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES, strict=True
    )
    execution_component: M6UpgradeExecutionComponentAuthority
    execution_component_content_sha256: Sha256Hex
    execution_component_size_bytes: int = Field(
        gt=0, le=MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES, strict=True
    )
    execution_start_audit_head_sequence: int = Field(ge=-1, strict=True)
    execution_start_audit_head_hash: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 upgrade execution scope candidate run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_scope_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("execution_scope_authority_id",))
        scope = handler(payload)
        _verify_claims(scope, claims)
        return scope

    @model_validator(mode="after")
    def validate_execution_start_cut(self) -> Self:
        command = _canonical_nested(
            M6RegressionRunCommand,
            self.command,
            "M6 upgrade execution scope command",
        )
        dataset = _canonical_nested(
            M6RegressionExecutionDatasetSnapshot,
            self.execution_dataset,
            "M6 upgrade execution scope dataset",
        )
        manifest = _canonical_nested(
            RunManifest,
            self.candidate_manifest,
            "M6 upgrade execution scope manifest",
        )
        config = _canonical_nested(
            AppConfig,
            self.candidate_config,
            "M6 upgrade execution scope config",
        )
        component = _canonical_nested(
            M6UpgradeExecutionComponentAuthority,
            self.execution_component,
            "M6 upgrade execution scope component",
        )
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
            command.mode != ReproducibilityMode.UPGRADE_REGRESSION
            or command.execution_dataset_snapshot_id != dataset.execution_dataset_snapshot_id
            or command.baseline_manifest_id != dataset.baseline_manifest_id
            or command.candidate_manifest_id != manifest.manifest_id
            or command.policy_authority.config_sha256 != config.config_sha256
            or manifest.reproducibility_mode != ReproducibilityMode.UPGRADE_REGRESSION
            or config.run.reproducibility_mode != ReproducibilityMode.UPGRADE_REGRESSION
            or manifest.config_sha256 != config.config_sha256
            or set(manifest.models) != REQUIRED_MODEL_COMPONENTS
            or component.code_commit != manifest.code_commit
            or not offline_profiles_match
            or not offline_component_providers_match
            or _physical_content_sha256(command) != self.command_content_sha256
            or _physical_size_bytes(command) != self.command_size_bytes
            or _physical_content_sha256(dataset) != self.execution_dataset_content_sha256
            or _physical_size_bytes(dataset) != self.execution_dataset_size_bytes
            or _physical_content_sha256(manifest) != self.candidate_manifest_content_sha256
            or _physical_size_bytes(manifest) != self.candidate_manifest_size_bytes
            or _physical_content_sha256(config) != self.candidate_config_content_sha256
            or _physical_size_bytes(config) != self.candidate_config_size_bytes
            or _physical_content_sha256(component) != self.execution_component_content_sha256
            or _physical_size_bytes(component) != self.execution_component_size_bytes
        ):
            raise ValueError("M6 upgrade execution scope is not one exact offline start cut")
        if (
            self.execution_start_audit_head_sequence != -1
            or self.execution_start_audit_head_hash != AUDIT_GENESIS_HASH
        ):
            raise ValueError("M6 upgrade execution must start from a fresh audit genesis")
        object.__setattr__(self, "command", command)
        object.__setattr__(self, "execution_dataset", dataset)
        object.__setattr__(self, "candidate_manifest", manifest)
        object.__setattr__(self, "candidate_config", config)
        object.__setattr__(self, "execution_component", component)
        if _physical_size_bytes(self) > MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES:
            raise ValueError("M6 upgrade execution scope exceeds its document byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_scope_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-execution-scope-authority",
                1,
                self.candidate_run_id,
                self.command.command_id,
                self.command_content_sha256,
                self.command_size_bytes,
                self.execution_dataset.execution_dataset_snapshot_id,
                self.execution_dataset_content_sha256,
                self.execution_dataset_size_bytes,
                self.candidate_manifest.manifest_id,
                self.candidate_manifest_content_sha256,
                self.candidate_manifest_size_bytes,
                self.candidate_config.config_sha256,
                self.candidate_config_content_sha256,
                self.candidate_config_size_bytes,
                self.execution_component.component_authority_id,
                self.execution_component_content_sha256,
                self.execution_component_size_bytes,
                self.execution_start_audit_head_sequence,
                self.execution_start_audit_head_hash,
            ]
        )


class M6UpgradeSampleArtifactLink(FrozenContractModel):
    ordinal: int = Field(ge=0, strict=True)
    usage: M6UpgradeArtifactUsage
    artifact: M6UpgradePhysicalArtifactRef

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_link_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("artifact_link_id",))
        link = handler(payload)
        _verify_claims(link, claims)
        return link

    @model_validator(mode="after")
    def validate_physical_link(self) -> Self:
        artifact = _canonical_nested(
            M6UpgradePhysicalArtifactRef,
            self.artifact,
            "M6 upgrade ledger physical artifact",
        )
        require_m6_upgrade_artifact_usage(artifact.kind, self.usage)
        object.__setattr__(self, "artifact", artifact)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_link_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-sample-artifact-link",
                1,
                self.ordinal,
                self.usage,
                self.artifact.artifact_ref_id,
            ]
        )

    @property
    def physical_key(self) -> tuple[int, int, str, str]:
        return self.artifact.physical_key


class M6UpgradeCandidateCaseBinding(FrozenContractModel):
    case_id: ReferenceToken
    case_revision: int = Field(gt=0, strict=True)
    case_document_sha256: Sha256Hex
    case_audit_sequence: int = Field(ge=0, strict=True)
    case_audit_entry_hash: Sha256Hex

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 upgrade ledger case_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_case_binding_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("case_binding_id",))
        binding = handler(payload)
        _verify_claims(binding, claims)
        return binding

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_binding_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-candidate-case-binding",
                1,
                self.case_id,
                self.case_revision,
                self.case_document_sha256,
                self.case_audit_sequence,
                self.case_audit_entry_hash,
            ]
        )


class M6UpgradeSampleExecutionRecord(FrozenContractModel):
    schema_version: Literal["m6-upgrade-sample-execution-record-v1"] = (
        "m6-upgrade-sample-execution-record-v1"
    )
    execution_scope_authority_id: Sha256Hex
    candidate_run_id: ReferenceToken
    command_id: Sha256Hex
    execution_dataset_snapshot_id: Sha256Hex
    execution_entry: M6RegressionExecutionEntry
    outcome: M6ReplayExecutionOutcome
    candidate_case: M6UpgradeCandidateCaseBinding | None = None
    artifact_links: tuple[M6UpgradeSampleArtifactLink, ...] = Field(
        min_length=1,
        max_length=MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    )
    ledger_sequence: int = Field(ge=0, strict=True)
    previous_ledger_entry_hash: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 upgrade ledger candidate run_id")

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
                "artifact_link_count",
                "artifact_link_inventory_root_sha256",
                "sample_execution_record_id",
            ),
        )
        record = handler(payload)
        _verify_claims(record, claims)
        return record

    @model_validator(mode="after")
    def validate_complete_record(self) -> Self:
        entry = _canonical_nested(
            M6RegressionExecutionEntry,
            self.execution_entry,
            "M6 upgrade ledger execution entry",
        )
        case = self.candidate_case
        if case is not None:
            case = _canonical_nested(
                M6UpgradeCandidateCaseBinding,
                case,
                "M6 upgrade ledger candidate Case binding",
            )
        if (case is not None) != (self.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED):
            raise ValueError("M6 upgrade ledger outcome and Case binding differ")
        links = tuple(
            _canonical_nested(
                M6UpgradeSampleArtifactLink,
                item,
                "M6 upgrade ledger artifact link",
            )
            for item in self.artifact_links
        )
        if tuple(item.ordinal for item in links) != tuple(range(len(links))):
            raise ValueError("M6 upgrade ledger artifact ordinals must be contiguous")
        physical_keys = tuple(item.physical_key for item in links)
        if len(physical_keys) != len(set(physical_keys)):
            raise ValueError("M6 upgrade ledger physical artifact links must be unique")
        if physical_keys != tuple(sorted(physical_keys)):
            raise ValueError("M6 upgrade ledger physical artifact links must use stable order")
        if case is None and any(
            m6_upgrade_physical_artifact_requires_case(item.artifact.kind) for item in links
        ):
            raise ValueError("M6 upgrade ledger no-Case sample cannot claim case-scoped artifacts")
        if not any(item.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME for item in links):
            raise ValueError("M6 upgrade ledger sample execution requires a physical Frame")
        frame_ids = {
            item.artifact.artifact_id
            for item in links
            if item.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
        }
        if any(
            item.artifact.container_id not in frame_ids
            for item in links
            if item.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
        ):
            raise ValueError(
                "M6 upgrade ledger Detection must belong to a Frame in the same sample"
            )
        if (self.ledger_sequence == 0) != (
            self.previous_ledger_entry_hash == M6_UPGRADE_LEDGER_GENESIS_HASH
        ):
            raise ValueError("M6 upgrade ledger genesis binding is invalid")
        object.__setattr__(self, "execution_entry", entry)
        object.__setattr__(self, "candidate_case", case)
        object.__setattr__(self, "artifact_links", links)
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
    def artifact_link_count(self) -> int:
        return len(self.artifact_links)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_link_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-sample-artifact-link-inventory",
                1,
                [item.artifact_link_id for item in self.artifact_links],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_record_id(self) -> Sha256Hex:
        case = self.candidate_case
        return sha256_hex(
            [
                "m6-upgrade-sample-execution-ledger-entry",
                1,
                self.previous_ledger_entry_hash,
                self.ledger_sequence,
                self.execution_scope_authority_id,
                self.candidate_run_id,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.execution_entry_id,
                self.outcome,
                case.case_binding_id if case is not None else None,
                self.artifact_link_count,
                self.artifact_link_inventory_root_sha256,
            ]
        )


class M6UpgradeSampleExecutionRecordV2(M6UpgradeSampleExecutionRecord):
    """Observation-backed sample record without changing the public v1 wire contract."""

    schema_version: Literal["m6-upgrade-sample-execution-record-v2"] = (
        "m6-upgrade-sample-execution-record-v2"  # type: ignore[assignment]
    )
    observation_authority_id: Sha256Hex

    @model_validator(mode="after")
    def validate_observation_backed_physical_budget(self) -> Self:
        if (
            sum(item.artifact.size_bytes for item in self.artifact_links)
            > MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES
        ):
            raise ValueError("M6 upgrade v2 ledger sample physical byte budget exceeded")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_record_id(self) -> Sha256Hex:
        case = self.candidate_case
        return sha256_hex(
            [
                "m6-upgrade-sample-execution-ledger-entry",
                2,
                self.previous_ledger_entry_hash,
                self.ledger_sequence,
                self.execution_scope_authority_id,
                self.candidate_run_id,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.execution_entry_id,
                self.outcome,
                case.case_binding_id if case is not None else None,
                self.observation_authority_id,
                self.artifact_link_count,
                self.artifact_link_inventory_root_sha256,
            ]
        )


class M6UpgradeExecutionLedgerSeal(FrozenContractModel):
    schema_version: Literal["m6-upgrade-execution-ledger-seal-v1"] = (
        "m6-upgrade-execution-ledger-seal-v1"
    )
    execution_scope: M6UpgradeExecutionScopeAuthority
    execution_scope_content_sha256: Sha256Hex
    execution_scope_size_bytes: int = Field(
        gt=0, le=MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES, strict=True
    )
    source_audit_head_sequence: int = Field(ge=-1, strict=True)
    source_audit_head_hash: Sha256Hex
    sample_executions: tuple[M6UpgradeSampleExecutionRecord, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )

    @classmethod
    def _sample_execution_model(cls) -> type[M6UpgradeSampleExecutionRecord]:
        return M6UpgradeSampleExecutionRecord

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
                "sample_execution_count",
                "sample_execution_inventory_root_sha256",
                "artifact_link_count",
                "artifact_link_inventory_root_sha256",
                "candidate_case_count",
                "candidate_case_inventory_root_sha256",
                "ledger_preseal_sequence",
                "ledger_preseal_hash",
                "ledger_head_sequence",
                "ledger_seal_authority_id",
            ),
        )
        seal = handler(payload)
        _verify_claims(seal, claims)
        return seal

    @model_validator(mode="after")
    def validate_complete_sealed_ledger(self) -> Self:
        scope = _canonical_nested(
            M6UpgradeExecutionScopeAuthority,
            self.execution_scope,
            "M6 upgrade ledger execution scope",
        )
        command = scope.command
        dataset = scope.execution_dataset
        record_model = type(self)._sample_execution_model()
        records = tuple(
            _canonical_nested(
                record_model,
                item,
                "M6 upgrade ledger sample execution",
            )
            for item in self.sample_executions
        )
        if (
            _physical_content_sha256(scope) != self.execution_scope_content_sha256
            or _physical_size_bytes(scope) != self.execution_scope_size_bytes
        ):
            raise ValueError("M6 upgrade ledger execution scope physical content differs")
        if (self.source_audit_head_sequence == -1) != (
            self.source_audit_head_hash == AUDIT_GENESIS_HASH
        ):
            raise ValueError("M6 upgrade ledger source audit head is invalid")
        if self.source_audit_head_sequence < scope.execution_start_audit_head_sequence:
            raise ValueError("M6 upgrade ledger audit head precedes its execution start cut")
        if len(records) != len(dataset.entries):
            raise ValueError("M6 upgrade ledger must cover every blinded execution entry")
        if sum(record.artifact_link_count for record in records) > MAX_M6_UPGRADE_LEDGER_LINKS:
            raise ValueError("M6 upgrade ledger artifact link inventory exceeds its bound")
        previous = M6_UPGRADE_LEDGER_GENESIS_HASH
        for index, (entry, record) in enumerate(zip(dataset.entries, records, strict=True)):
            if (
                record.ledger_sequence != index
                or record.previous_ledger_entry_hash != previous
                or record.execution_scope_authority_id != scope.execution_scope_authority_id
                or record.candidate_run_id != scope.candidate_run_id
                or record.command_id != command.command_id
                or record.execution_dataset_snapshot_id != dataset.execution_dataset_snapshot_id
                or record.execution_entry != entry
            ):
                raise ValueError("M6 upgrade ledger sample chain or execution scope differs")
            previous = record.sample_execution_record_id
        physical_artifacts: dict[tuple[int, int, str, str], M6UpgradePhysicalArtifactRef] = {}
        for record in records:
            for link in record.artifact_links:
                artifact = link.artifact
                prior = physical_artifacts.setdefault(artifact.physical_key, artifact)
                if prior != artifact:
                    raise ValueError(
                        "M6 upgrade ledger physical artifact identity conflicts across samples"
                    )
        case_ids = tuple(
            record.candidate_case.case_id for record in records if record.candidate_case is not None
        )
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("M6 upgrade ledger current Case bindings must be unique")
        if any(
            record.candidate_case is not None
            and (
                record.candidate_case.case_audit_sequence
                <= scope.execution_start_audit_head_sequence
                or record.candidate_case.case_audit_sequence > self.source_audit_head_sequence
            )
            for record in records
        ):
            raise ValueError("M6 upgrade ledger Case lies beyond its candidate audit head")
        object.__setattr__(self, "execution_scope", scope)
        object.__setattr__(self, "sample_executions", records)
        if _physical_size_bytes(self) > MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES:
            raise ValueError("M6 upgrade execution ledger exceeds its document byte budget")
        return self

    @property
    def candidate_run_id(self) -> ReferenceToken:
        return self.execution_scope.candidate_run_id

    @property
    def command(self) -> M6RegressionRunCommand:
        return self.execution_scope.command

    @property
    def command_content_sha256(self) -> Sha256Hex:
        return self.execution_scope.command_content_sha256

    @property
    def execution_dataset(self) -> M6RegressionExecutionDatasetSnapshot:
        return self.execution_scope.execution_dataset

    @property
    def execution_dataset_content_sha256(self) -> Sha256Hex:
        return self.execution_scope.execution_dataset_content_sha256

    @property
    def candidate_manifest_id(self) -> Sha256Hex:
        return self.execution_scope.candidate_manifest.manifest_id

    @property
    def candidate_manifest_content_sha256(self) -> Sha256Hex:
        return self.execution_scope.candidate_manifest_content_sha256

    @property
    def candidate_config_sha256(self) -> Sha256Hex:
        return self.execution_scope.candidate_config.config_sha256

    @property
    def candidate_config_content_sha256(self) -> Sha256Hex:
        return self.execution_scope.candidate_config_content_sha256

    @property
    def execution_component(self) -> M6UpgradeExecutionComponentAuthority:
        return self.execution_scope.execution_component

    @property
    def execution_component_content_sha256(self) -> Sha256Hex:
        return self.execution_scope.execution_component_content_sha256

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_count(self) -> int:
        return len(self.sample_executions)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-sample-execution-inventory",
                1,
                [item.sample_execution_record_id for item in self.sample_executions],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_link_count(self) -> int:
        return sum(item.artifact_link_count for item in self.sample_executions)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_link_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-global-artifact-link-inventory",
                1,
                [
                    [
                        item.sample_execution_record_id,
                        item.artifact_link_inventory_root_sha256,
                    ]
                    for item in self.sample_executions
                ],
            ]
        )

    def _candidate_case_binding_ids(self) -> tuple[Sha256Hex, ...]:
        return tuple(
            sorted(
                item.candidate_case.case_binding_id
                for item in self.sample_executions
                if item.candidate_case is not None
            )
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_case_count(self) -> int:
        return len(self._candidate_case_binding_ids())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_case_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-ledger-candidate-case-inventory",
                1,
                self._candidate_case_binding_ids(),
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ledger_preseal_sequence(self) -> int:
        return len(self.sample_executions) - 1

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ledger_preseal_hash(self) -> Sha256Hex:
        return self.sample_executions[-1].sample_execution_record_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ledger_head_sequence(self) -> int:
        return len(self.sample_executions)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ledger_seal_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-execution-ledger-seal",
                1,
                self.ledger_preseal_hash,
                self.ledger_head_sequence,
                self.execution_scope.execution_scope_authority_id,
                self.execution_scope_content_sha256,
                self.execution_scope_size_bytes,
                self.source_audit_head_sequence,
                self.source_audit_head_hash,
                self.sample_execution_count,
                self.sample_execution_inventory_root_sha256,
                self.artifact_link_count,
                self.artifact_link_inventory_root_sha256,
                self.candidate_case_count,
                self.candidate_case_inventory_root_sha256,
            ]
        )


class M6UpgradeExecutionLedgerSealV2(M6UpgradeExecutionLedgerSeal):
    """Sealed ledger whose complete chain is backed by execution observations."""

    schema_version: Literal["m6-upgrade-execution-ledger-seal-v2"] = (
        "m6-upgrade-execution-ledger-seal-v2"  # type: ignore[assignment]
    )
    sample_executions: tuple[M6UpgradeSampleExecutionRecordV2, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )

    @classmethod
    def _sample_execution_model(cls) -> type[M6UpgradeSampleExecutionRecord]:
        return M6UpgradeSampleExecutionRecordV2

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ledger_seal_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-execution-ledger-seal",
                2,
                self.ledger_preseal_hash,
                self.ledger_head_sequence,
                self.execution_scope.execution_scope_authority_id,
                self.execution_scope_content_sha256,
                self.execution_scope_size_bytes,
                self.source_audit_head_sequence,
                self.source_audit_head_hash,
                self.sample_execution_count,
                self.sample_execution_inventory_root_sha256,
                self.artifact_link_count,
                self.artifact_link_inventory_root_sha256,
                self.candidate_case_count,
                self.candidate_case_inventory_root_sha256,
            ]
        )


__all__ = [
    "M6_UPGRADE_LEDGER_GENESIS_HASH",
    "MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES",
    "MAX_M6_UPGRADE_LEDGER_LINKS",
    "MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE",
    "MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES",
    "M6UpgradeArtifactUsage",
    "M6UpgradeCandidateCaseBinding",
    "M6UpgradeExecutionComponentAuthority",
    "M6UpgradeExecutionLedgerSeal",
    "M6UpgradeExecutionLedgerSealV2",
    "M6UpgradeExecutionScopeAuthority",
    "M6UpgradePhysicalArtifactKind",
    "M6UpgradePhysicalArtifactRef",
    "M6UpgradePhysicalArtifactSource",
    "M6UpgradeSampleArtifactLink",
    "M6UpgradeSampleExecutionRecord",
    "M6UpgradeSampleExecutionRecordV2",
]
