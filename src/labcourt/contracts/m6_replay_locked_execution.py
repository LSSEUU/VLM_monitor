"""Exact offline execution-start contracts for M6 ``REPLAY_LOCKED``."""

from __future__ import annotations

import hashlib
from enum import StrEnum
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
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.frames import Sha256Hex
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
    M6ProviderCapabilityCounters,
    M6ProviderTrapAuthority,
    M6ReplayInputClosureAuthority,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import (
    ReferenceToken,
    require_portable_run_id,
    require_reference_token,
)

MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES = 256 * 1024 * 1024
MAX_M6_REPLAY_LOCKED_COMPONENT_VERSION_LENGTH = 128

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
            raise ValueError(f"serialized {name} conflicts with derived M6 locked execution")


def _canonical_nested(expected: type[_CanonicalT], value: object, label: str) -> _CanonicalT:
    if type(value) is not expected:
        raise ValueError(f"{label} must be an exact canonical authority")
    controlled = expected.model_validate(
        value.model_dump(mode="json", exclude_computed_fields=True)
    )
    if controlled != value:
        raise ValueError(f"{label} must be an exact canonical authority")
    return controlled


def _physical_content_sha256(value: BaseModel) -> Sha256Hex:
    return hashlib.sha256(canonical_json(value.model_dump(mode="json")).encode("utf-8")).hexdigest()


def _physical_size_bytes(value: BaseModel) -> int:
    return len(canonical_json(value.model_dump(mode="json")).encode("utf-8"))


class M6ReplayLockedExecutionRoute(StrEnum):
    M3_FAST_TERMINAL_POST_PARSE = "M3_FAST_TERMINAL_POST_PARSE"
    M4_HEARING_GATE_TERMINAL_POST_PARSE = "M4_HEARING_GATE_TERMINAL_POST_PARSE"


class M6ReplayLockedExecutionComponentAuthority(FrozenContractModel):
    schema_version: Literal["m6-replay-locked-execution-component-authority-v1"] = (
        "m6-replay-locked-execution-component-authority-v1"
    )
    component: Literal["labcourt-m6-replay-locked-executor"] = "labcourt-m6-replay-locked-executor"
    package: Literal["labcourt"] = "labcourt"
    version: str = Field(
        min_length=1,
        max_length=MAX_M6_REPLAY_LOCKED_COMPONENT_VERSION_LENGTH,
    )
    code_commit: str = Field(min_length=1, max_length=128)
    execution_mode: Literal["OFFLINE_LOCKED"] = "OFFLINE_LOCKED"
    input_contract: Literal["SEALED_SAVED_AUTHORITIES"] = "SEALED_SAVED_AUTHORITIES"
    output_contract: Literal["APPEND_ONLY_LOCKED_INVENTORY"] = "APPEND_ONLY_LOCKED_INVENTORY"
    supported_routes: tuple[M6ReplayLockedExecutionRoute, ...] = (
        M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
    )
    network_allowed: Literal[False] = False
    gpu_required: Literal[False] = False
    evaluator_fields_accessible: Literal[False] = False
    provider_ports_exposed: Literal[False] = False
    recovery_ports_exposed: Literal[False] = False
    cache_write_ports_exposed: Literal[False] = False
    live_tail_ports_exposed: Literal[False] = False
    raw_model_response_accessible: Literal[False] = False
    safety_signal_accessible: Literal[False] = False

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

    @model_validator(mode="after")
    def validate_supported_routes(self) -> Self:
        if not self.supported_routes:
            raise ValueError("M6 locked execution component requires a supported route")
        if self.supported_routes != tuple(sorted(set(self.supported_routes), key=str)):
            raise ValueError("M6 locked execution routes must be unique and ordered")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def component_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-execution-component-authority",
                1,
                self.component,
                self.package,
                self.version,
                self.code_commit,
                self.execution_mode,
                self.input_contract,
                self.output_contract,
                self.supported_routes,
                self.network_allowed,
                self.gpu_required,
                self.evaluator_fields_accessible,
                self.provider_ports_exposed,
                self.recovery_ports_exposed,
                self.cache_write_ports_exposed,
                self.live_tail_ports_exposed,
                self.raw_model_response_accessible,
                self.safety_signal_accessible,
            ]
        )


class M6ReplayLockedExecutionScopeAuthority(FrozenContractModel):
    """Candidate-blind locked execution cut persisted before any sample runs."""

    schema_version: Literal["m6-replay-locked-execution-scope-authority-v1"] = (
        "m6-replay-locked-execution-scope-authority-v1"
    )
    candidate_run_id: ReferenceToken
    command: M6RegressionRunCommand
    command_content_sha256: Sha256Hex
    command_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    execution_dataset: M6RegressionExecutionDatasetSnapshot
    execution_dataset_content_sha256: Sha256Hex
    execution_dataset_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    source_catalog_content_sha256: Sha256Hex
    source_catalog_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    source_catalog_entry_count: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_CASES,
        strict=True,
    )
    source_catalog_entry_ids: tuple[Sha256Hex, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )
    source_run_ids: tuple[ReferenceToken, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )
    locked_manifest: RunManifest
    locked_manifest_content_sha256: Sha256Hex
    locked_manifest_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    locked_config: AppConfig
    locked_config_content_sha256: Sha256Hex
    locked_config_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    execution_component: M6ReplayLockedExecutionComponentAuthority
    execution_component_content_sha256: Sha256Hex
    execution_component_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    execution_start_audit_head_sequence: int = Field(ge=-1, strict=True)
    execution_start_audit_head_hash: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M6 locked execution candidate run_id")

    @field_validator("source_run_ids")
    @classmethod
    def validate_source_run_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(require_reference_token(item, "M6 locked source run_id") for item in value)

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
                "source_catalog_entry_inventory_root_sha256",
                "source_run_inventory_root_sha256",
                "execution_scope_authority_id",
            ),
        )
        scope = handler(payload)
        _verify_claims(scope, claims)
        return scope

    @model_validator(mode="after")
    def validate_exact_locked_start_cut(self) -> Self:
        command = _canonical_nested(
            M6RegressionRunCommand,
            self.command,
            "M6 locked execution command",
        )
        dataset = _canonical_nested(
            M6RegressionExecutionDatasetSnapshot,
            self.execution_dataset,
            "M6 locked execution dataset",
        )
        manifest = _canonical_nested(
            RunManifest,
            self.locked_manifest,
            "M6 locked manifest",
        )
        config = _canonical_nested(
            AppConfig,
            self.locked_config,
            "M6 locked config",
        )
        component = _canonical_nested(
            M6ReplayLockedExecutionComponentAuthority,
            self.execution_component,
            "M6 locked execution component",
        )
        source_run_ids = tuple(self.source_run_ids)
        source_catalog_entry_ids = tuple(self.source_catalog_entry_ids)
        if source_run_ids != tuple(sorted(source_run_ids)) or len(source_run_ids) != len(
            set(source_run_ids)
        ):
            raise ValueError("M6 locked source run IDs must be unique and ordered")
        if len(source_catalog_entry_ids) != self.source_catalog_entry_count or len(
            source_catalog_entry_ids
        ) != len(set(source_catalog_entry_ids)):
            raise ValueError("M6 locked source catalog entry IDs must be complete and unique")
        if self.candidate_run_id in source_run_ids:
            raise ValueError("M6 locked candidate run must differ from every source run")
        if (
            command.mode != ReproducibilityMode.REPLAY_LOCKED
            or command.baseline_manifest_id != command.candidate_manifest_id
            or command.execution_dataset_snapshot_id != dataset.execution_dataset_snapshot_id
            or command.baseline_manifest_id != dataset.baseline_manifest_id
            or command.candidate_manifest_id != manifest.manifest_id
            or command.policy_authority.config_sha256 != config.config_sha256
            or manifest.config_sha256 != config.config_sha256
            or component.code_commit != manifest.code_commit
            or dataset.source_catalog_document_sha256 != self.source_catalog_content_sha256
            or len(dataset.entries) != self.source_catalog_entry_count
            or _physical_content_sha256(command) != self.command_content_sha256
            or _physical_size_bytes(command) != self.command_size_bytes
            or _physical_content_sha256(dataset) != self.execution_dataset_content_sha256
            or _physical_size_bytes(dataset) != self.execution_dataset_size_bytes
            or _physical_content_sha256(manifest) != self.locked_manifest_content_sha256
            or _physical_size_bytes(manifest) != self.locked_manifest_size_bytes
            or _physical_content_sha256(config) != self.locked_config_content_sha256
            or _physical_size_bytes(config) != self.locked_config_size_bytes
            or _physical_content_sha256(component) != self.execution_component_content_sha256
            or _physical_size_bytes(component) != self.execution_component_size_bytes
        ):
            raise ValueError("M6 locked execution scope is not one exact offline start cut")
        if (
            self.execution_start_audit_head_sequence != -1
            or self.execution_start_audit_head_hash != AUDIT_GENESIS_HASH
        ):
            raise ValueError("M6 locked execution must start from a fresh audit genesis")
        object.__setattr__(self, "command", command)
        object.__setattr__(self, "execution_dataset", dataset)
        object.__setattr__(self, "locked_manifest", manifest)
        object.__setattr__(self, "locked_config", config)
        object.__setattr__(self, "execution_component", component)
        if _physical_size_bytes(self) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            raise ValueError("M6 locked execution scope exceeds its document byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_catalog_entry_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-source-catalog-entry-inventory",
                1,
                self.source_catalog_entry_ids,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_run_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(["m6-replay-locked-source-run-inventory", 1, self.source_run_ids])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_scope_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-execution-scope-authority",
                1,
                self.candidate_run_id,
                self.command.command_id,
                self.command_content_sha256,
                self.command_size_bytes,
                self.execution_dataset.execution_dataset_snapshot_id,
                self.execution_dataset_content_sha256,
                self.execution_dataset_size_bytes,
                self.execution_dataset.source_catalog_authority_id,
                self.source_catalog_content_sha256,
                self.source_catalog_size_bytes,
                self.source_catalog_entry_count,
                self.source_catalog_entry_inventory_root_sha256,
                self.source_run_inventory_root_sha256,
                self.locked_manifest.manifest_id,
                self.locked_manifest_content_sha256,
                self.locked_manifest_size_bytes,
                self.locked_config.config_sha256,
                self.locked_config_content_sha256,
                self.locked_config_size_bytes,
                self.execution_component.component_authority_id,
                self.execution_component_content_sha256,
                self.execution_component_size_bytes,
                self.execution_start_audit_head_sequence,
                self.execution_start_audit_head_hash,
            ]
        )


class M6ReplayLockedCandidateCaseBinding(FrozenContractModel):
    """Physical identity and audit anchor of one independently persisted Case."""

    schema_version: Literal["m6-replay-locked-candidate-case-binding-v1"] = (
        "m6-replay-locked-candidate-case-binding-v1"
    )
    candidate_run_id: ReferenceToken
    sample_id: ReferenceToken
    case_id: ReferenceToken
    case_revision: int = Field(gt=0, strict=True)
    case_document_sha256: Sha256Hex
    case_document_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    case_audit_sequence: int = Field(ge=0, strict=True)
    case_audit_entry_hash: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M6 locked candidate Case run_id")

    @field_validator("sample_id", "case_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 locked candidate Case reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_binding_id(
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
                "m6-replay-locked-candidate-case-binding",
                1,
                self.candidate_run_id,
                self.sample_id,
                self.case_id,
                self.case_revision,
                self.case_document_sha256,
                self.case_document_size_bytes,
                self.case_audit_sequence,
                self.case_audit_entry_hash,
            ]
        )


class M6ReplayLockedPendingSampleCommitmentAuthority(FrozenContractModel):
    """Durable intent fixed before one locked candidate sample is materialized."""

    schema_version: Literal["m6-replay-locked-pending-sample-commitment-v1"] = (
        "m6-replay-locked-pending-sample-commitment-v1"
    )
    execution_scope_authority_id: Sha256Hex
    candidate_run_id: ReferenceToken
    command_id: Sha256Hex
    execution_dataset_snapshot_id: Sha256Hex
    execution_component_authority_id: Sha256Hex
    source_catalog_entry_id: Sha256Hex
    route: M6ReplayLockedExecutionRoute
    execution_entry: M6RegressionExecutionEntry
    ledger_sequence: int = Field(ge=0, strict=True)
    previous_ledger_entry_hash: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M6 locked pending candidate run_id")

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
                "pending_commitment_authority_id",
            ),
        )
        pending = handler(payload)
        _verify_claims(pending, claims)
        return pending

    @model_validator(mode="after")
    def validate_pending_chain(self) -> Self:
        entry = _canonical_nested(
            M6RegressionExecutionEntry,
            self.execution_entry,
            "M6 locked pending execution entry",
        )
        if (self.ledger_sequence == 0) != (self.previous_ledger_entry_hash == AUDIT_GENESIS_HASH):
            raise ValueError("M6 locked pending ledger genesis binding is invalid")
        object.__setattr__(self, "execution_entry", entry)
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
    def pending_commitment_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-pending-sample-commitment",
                1,
                self.previous_ledger_entry_hash,
                self.ledger_sequence,
                self.execution_scope_authority_id,
                self.candidate_run_id,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.execution_component_authority_id,
                self.source_catalog_entry_id,
                self.route,
                self.execution_entry_id,
            ]
        )


class M6ReplayLockedSampleExecutionRecord(FrozenContractModel):
    """One chained locked execution output, before the run-wide trap is sealed."""

    schema_version: Literal["m6-replay-locked-sample-execution-record-v1"] = (
        "m6-replay-locked-sample-execution-record-v1"
    )
    execution_scope_authority_id: Sha256Hex
    candidate_run_id: ReferenceToken
    command_id: Sha256Hex
    execution_dataset_snapshot_id: Sha256Hex
    candidate_manifest_id: Sha256Hex
    route: M6ReplayLockedExecutionRoute
    outcome: Literal[M6ReplayExecutionOutcome.CASE_REPLAYED] = (
        M6ReplayExecutionOutcome.CASE_REPLAYED
    )
    execution_entry: M6RegressionExecutionEntry
    pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority
    replay_input_closure: M6ReplayInputClosureAuthority
    source_determinism: M6ReplayLockedSourceDeterminismAuthority
    candidate_case: M6ReplayLockedCandidateCaseBinding
    candidate_snapshot: M6CaseReplaySnapshot
    ledger_sequence: int = Field(ge=0, strict=True)
    previous_ledger_entry_hash: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M6 locked sample candidate run_id")

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
                "pending_commitment_authority_id",
                "source_snapshot_id",
                "source_semantic_case_hash",
                "candidate_snapshot_id",
                "candidate_semantic_case_hash",
                "candidate_snapshot_content_sha256",
                "candidate_snapshot_size_bytes",
                "sample_execution_record_id",
            ),
        )
        record = handler(payload)
        _verify_claims(record, claims)
        return record

    @model_validator(mode="after")
    def validate_complete_locked_record(self) -> Self:
        entry = _canonical_nested(
            M6RegressionExecutionEntry,
            self.execution_entry,
            "M6 locked execution entry",
        )
        pending = _canonical_nested(
            M6ReplayLockedPendingSampleCommitmentAuthority,
            self.pending_commitment,
            "M6 locked pending sample commitment",
        )
        closure = _canonical_nested(
            M6ReplayInputClosureAuthority,
            self.replay_input_closure,
            "M6 locked replay input closure",
        )
        proof = _canonical_nested(
            M6ReplayLockedSourceDeterminismAuthority,
            self.source_determinism,
            "M6 locked source determinism",
        )
        candidate_case = _canonical_nested(
            M6ReplayLockedCandidateCaseBinding,
            self.candidate_case,
            "M6 locked candidate Case binding",
        )
        snapshot = _canonical_nested(
            M6CaseReplaySnapshot,
            self.candidate_snapshot,
            "M6 locked candidate snapshot",
        )
        entry_closure = (
            entry.sample_id,
            entry.input_authority_id,
            entry.input_authority_document_sha256,
            entry.replay_input_closure_authority_id,
            entry.replay_input_closure_document_sha256,
        )
        closure_identity = (
            closure.sample_id,
            closure.input_authority_id,
            closure.input_authority_document_sha256,
            closure.replay_input_closure_authority_id,
            closure.replay_input_closure_document_sha256,
        )
        proof_identity = (
            proof.sample_id,
            proof.replay_input_closure_authority_id,
            proof.replay_input_closure_document_sha256,
        )
        if entry_closure != closure_identity or proof_identity != (
            closure.sample_id,
            closure.replay_input_closure_authority_id,
            closure.replay_input_closure_document_sha256,
        ):
            raise ValueError("M6 locked sample input closure differs from its execution entry")
        if (
            pending.execution_scope_authority_id != self.execution_scope_authority_id
            or pending.candidate_run_id != self.candidate_run_id
            or pending.command_id != self.command_id
            or pending.execution_dataset_snapshot_id != self.execution_dataset_snapshot_id
            or pending.route != self.route
            or pending.execution_entry != entry
            or pending.ledger_sequence != self.ledger_sequence
            or pending.previous_ledger_entry_hash != self.previous_ledger_entry_hash
        ):
            raise ValueError("M6 locked pending commitment differs from its sample record")
        if (
            proof.command_id != self.command_id
            or proof.execution_entry_id != entry.execution_entry_id
            or proof.source_run_id != closure.source_run_id
            or proof.candidate_run_id != self.candidate_run_id
            or proof.source_manifest_id != closure.source_manifest_id
        ):
            raise ValueError("M6 locked source proof differs from its sample execution scope")
        if (
            closure.source_case_id is None
            or closure.source_case_revision is None
            or closure.source_case_document_sha256 is None
            or candidate_case.candidate_run_id != self.candidate_run_id
            or candidate_case.sample_id != entry.sample_id
            or candidate_case.case_document_sha256 == closure.source_case_document_sha256
            or snapshot.sample_id != entry.sample_id
            or snapshot.source_run_id != self.candidate_run_id
            or snapshot.source_case_id != candidate_case.case_id
            or snapshot.source_case_revision != candidate_case.case_revision
            or snapshot.source_case_document_sha256 != candidate_case.case_document_sha256
            or snapshot.manifest_id != self.candidate_manifest_id
        ):
            raise ValueError("M6 locked candidate Case is not an independent persisted output")
        if (
            snapshot.snapshot_id == proof.first_source_snapshot_id
            or snapshot.semantic_case_hash != proof.first_semantic_case_hash
        ):
            raise ValueError("M6 locked candidate snapshot is not source-semantically identical")
        if (self.ledger_sequence == 0) != (self.previous_ledger_entry_hash == AUDIT_GENESIS_HASH):
            raise ValueError("M6 locked sample ledger genesis binding is invalid")
        object.__setattr__(self, "execution_entry", entry)
        object.__setattr__(self, "pending_commitment", pending)
        object.__setattr__(self, "replay_input_closure", closure)
        object.__setattr__(self, "source_determinism", proof)
        object.__setattr__(self, "candidate_case", candidate_case)
        object.__setattr__(self, "candidate_snapshot", snapshot)
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
    def pending_commitment_authority_id(self) -> Sha256Hex:
        return self.pending_commitment.pending_commitment_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_snapshot_id(self) -> Sha256Hex:
        return self.source_determinism.first_source_snapshot_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_semantic_case_hash(self) -> Sha256Hex:
        return self.source_determinism.first_semantic_case_hash

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_snapshot_id(self) -> Sha256Hex:
        return self.candidate_snapshot.snapshot_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_semantic_case_hash(self) -> Sha256Hex:
        return self.candidate_snapshot.semantic_case_hash

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_snapshot_content_sha256(self) -> Sha256Hex:
        return _physical_content_sha256(self.candidate_snapshot)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_snapshot_size_bytes(self) -> int:
        return _physical_size_bytes(self.candidate_snapshot)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_record_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-sample-execution-record",
                1,
                self.previous_ledger_entry_hash,
                self.ledger_sequence,
                self.execution_scope_authority_id,
                self.candidate_run_id,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.candidate_manifest_id,
                self.route,
                self.execution_entry_id,
                self.pending_commitment_authority_id,
                self.replay_input_closure.replay_input_closure_authority_id,
                self.source_determinism.source_determinism_authority_id,
                self.candidate_case.case_binding_id,
                self.candidate_snapshot_id,
                self.candidate_snapshot_content_sha256,
                self.candidate_snapshot_size_bytes,
            ]
        )


class M6ReplayLockedRunTrapSealAuthority(FrozenContractModel):
    """One executor-owned capability trap sealed only after every sample record."""

    schema_version: Literal["m6-replay-locked-run-trap-seal-authority-v1"] = (
        "m6-replay-locked-run-trap-seal-authority-v1"
    )
    execution_scope_authority_id: Sha256Hex
    command_id: Sha256Hex
    candidate_run_id: ReferenceToken
    execution_component_authority_id: Sha256Hex
    counters: M6ProviderCapabilityCounters
    sealed_sample_execution_count: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_CASES,
        strict=True,
    )
    sealed_sample_execution_inventory_root_sha256: Sha256Hex
    terminal_ledger_sequence: int = Field(ge=0, strict=True)
    terminal_sample_execution_record_id: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M6 locked run trap candidate run_id")

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
                "external_capability_call_count",
                "clean",
                "provider_trap",
                "run_trap_seal_authority_id",
            ),
        )
        seal = handler(payload)
        _verify_claims(seal, claims)
        return seal

    @model_validator(mode="after")
    def validate_terminal_clean_trap(self) -> Self:
        counters = _canonical_nested(
            M6ProviderCapabilityCounters,
            self.counters,
            "M6 locked run trap counters",
        )
        if self.terminal_ledger_sequence != self.sealed_sample_execution_count - 1:
            raise ValueError("M6 locked run trap was not sealed after its terminal record")
        if counters.total != 0:
            raise ValueError("M6 locked run trap observed an external capability call")
        object.__setattr__(self, "counters", counters)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_capability_call_count(self) -> int:
        return self.counters.total

    @computed_field  # type: ignore[prop-decorator]
    @property
    def clean(self) -> bool:
        return self.external_capability_call_count == 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_trap(self) -> M6ProviderTrapAuthority:
        return M6ProviderTrapAuthority(
            command_id=self.command_id,
            candidate_run_id=self.candidate_run_id,
            execution_component_manifest_id=self.execution_component_authority_id,
            counters=self.counters,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def run_trap_seal_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-run-trap-seal-authority",
                1,
                self.execution_scope_authority_id,
                self.command_id,
                self.candidate_run_id,
                self.execution_component_authority_id,
                self.provider_trap.provider_trap_authority_id,
                self.provider_trap.provider_trap_document_sha256,
                self.sealed_sample_execution_count,
                self.sealed_sample_execution_inventory_root_sha256,
                self.terminal_ledger_sequence,
                self.terminal_sample_execution_record_id,
            ]
        )


class M6ReplayLockedExecutionSealAuthority(FrozenContractModel):
    """Complete terminal inventory and run-wide zero-capability seal."""

    schema_version: Literal["m6-replay-locked-execution-seal-authority-v1"] = (
        "m6-replay-locked-execution-seal-authority-v1"
    )
    execution_scope: M6ReplayLockedExecutionScopeAuthority
    execution_scope_content_sha256: Sha256Hex
    execution_scope_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    candidate_audit_head_sequence: int = Field(ge=0, strict=True)
    candidate_audit_head_hash: Sha256Hex
    sample_executions: tuple[M6ReplayLockedSampleExecutionRecord, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )
    run_trap_seal: M6ReplayLockedRunTrapSealAuthority

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
                "candidate_case_count",
                "candidate_case_inventory_root_sha256",
                "execution_receipts",
                "execution_receipt_count",
                "execution_receipt_inventory_root_sha256",
                "execution_seal_authority_id",
            ),
        )
        seal = handler(payload)
        _verify_claims(seal, claims)
        return seal

    @model_validator(mode="after")
    def validate_complete_terminal_inventory(self) -> Self:
        scope = _canonical_nested(
            M6ReplayLockedExecutionScopeAuthority,
            self.execution_scope,
            "M6 locked execution scope",
        )
        records = tuple(
            _canonical_nested(
                M6ReplayLockedSampleExecutionRecord,
                item,
                "M6 locked sample execution record",
            )
            for item in self.sample_executions
        )
        trap = _canonical_nested(
            M6ReplayLockedRunTrapSealAuthority,
            self.run_trap_seal,
            "M6 locked run trap seal",
        )
        if (
            _physical_content_sha256(scope) != self.execution_scope_content_sha256
            or _physical_size_bytes(scope) != self.execution_scope_size_bytes
        ):
            raise ValueError("M6 locked terminal scope physical content differs")
        if len(records) != len(scope.execution_dataset.entries):
            raise ValueError("M6 locked terminal inventory must cover every execution entry")
        previous = AUDIT_GENESIS_HASH
        supported_routes = set(scope.execution_component.supported_routes)
        for index, (entry, source_catalog_entry_id, record) in enumerate(
            zip(
                scope.execution_dataset.entries,
                scope.source_catalog_entry_ids,
                records,
                strict=True,
            )
        ):
            if (
                record.ledger_sequence != index
                or record.previous_ledger_entry_hash != previous
                or record.execution_scope_authority_id != scope.execution_scope_authority_id
                or record.candidate_run_id != scope.candidate_run_id
                or record.command_id != scope.command.command_id
                or record.execution_dataset_snapshot_id
                != scope.execution_dataset.execution_dataset_snapshot_id
                or record.candidate_manifest_id != scope.locked_manifest.manifest_id
                or record.execution_entry != entry
                or record.route not in supported_routes
                or record.pending_commitment.execution_component_authority_id
                != scope.execution_component.component_authority_id
                or record.pending_commitment.source_catalog_entry_id != source_catalog_entry_id
                or record.source_determinism.execution_component_manifest_id
                != scope.execution_component.component_authority_id
                or record.candidate_case.case_audit_sequence != index
            ):
                raise ValueError("M6 locked sample chain or execution scope differs")
            previous = record.sample_execution_record_id
        case_ids = tuple(item.candidate_case.case_id for item in records)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("M6 locked candidate Case bindings must be unique")
        source_catalog_entry_ids = tuple(
            item.pending_commitment.source_catalog_entry_id for item in records
        )
        if len(source_catalog_entry_ids) != len(set(source_catalog_entry_ids)):
            raise ValueError("M6 locked source catalog entry bindings must be unique")
        if (
            self.candidate_audit_head_sequence != len(records) - 1
            or self.candidate_audit_head_hash != records[-1].candidate_case.case_audit_entry_hash
        ):
            raise ValueError("M6 locked candidate audit head is not the terminal Case anchor")
        if (
            trap.execution_scope_authority_id != scope.execution_scope_authority_id
            or trap.command_id != scope.command.command_id
            or trap.candidate_run_id != scope.candidate_run_id
            or trap.execution_component_authority_id
            != scope.execution_component.component_authority_id
            or trap.sealed_sample_execution_count != len(records)
            or trap.sealed_sample_execution_inventory_root_sha256
            != self.sample_execution_inventory_root_sha256
            or trap.terminal_ledger_sequence != len(records) - 1
            or trap.terminal_sample_execution_record_id != records[-1].sample_execution_record_id
            or not trap.clean
        ):
            raise ValueError("M6 locked run trap seal differs from terminal inventory")
        object.__setattr__(self, "execution_scope", scope)
        object.__setattr__(self, "sample_executions", records)
        object.__setattr__(self, "run_trap_seal", trap)
        if _physical_size_bytes(self) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            raise ValueError("M6 locked execution seal exceeds its document byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_count(self) -> int:
        return len(self.sample_executions)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-sample-execution-inventory",
                1,
                [item.sample_execution_record_id for item in self.sample_executions],
            ]
        )

    def _candidate_case_binding_ids(self) -> tuple[Sha256Hex, ...]:
        return tuple(item.candidate_case.case_binding_id for item in self.sample_executions)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_case_count(self) -> int:
        return len(self.sample_executions)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_case_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-candidate-case-inventory",
                1,
                self._candidate_case_binding_ids(),
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_receipts(self) -> tuple[M6ReplayExecutionReceipt, ...]:
        provider_trap = self.run_trap_seal.provider_trap
        return tuple(
            M6ReplayExecutionReceipt(
                command_id=self.execution_scope.command.command_id,
                mode=ReproducibilityMode.REPLAY_LOCKED,
                sample_id=record.sample_id,
                execution_entry_id=record.execution_entry_id,
                candidate_run_id=self.execution_scope.candidate_run_id,
                candidate_manifest_id=self.execution_scope.locked_manifest.manifest_id,
                execution_component_manifest_id=(
                    self.execution_scope.execution_component.component_authority_id
                ),
                outcome=record.outcome,
                candidate_snapshot_id=record.candidate_snapshot_id,
                detection_count=record.replay_input_closure.detection_count,
                detection_inventory_root_sha256=(
                    record.replay_input_closure.detection_inventory_root_sha256
                ),
                model_response_count=record.replay_input_closure.model_response_count,
                model_response_inventory_root_sha256=(
                    record.replay_input_closure.model_response_inventory_root_sha256
                ),
                embedding_count=record.replay_input_closure.embedding_count,
                embedding_inventory_root_sha256=(
                    record.replay_input_closure.embedding_inventory_root_sha256
                ),
                tool_result_count=record.replay_input_closure.tool_result_count,
                tool_result_inventory_root_sha256=(
                    record.replay_input_closure.tool_result_inventory_root_sha256
                ),
                provider_call_count=provider_trap.external_capability_call_count,
                provider_trap_authority_id=provider_trap.provider_trap_authority_id,
                provider_trap_document_sha256=(provider_trap.provider_trap_document_sha256),
            )
            for record in self.sample_executions
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_receipt_count(self) -> int:
        return len(self.execution_receipts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_receipt_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-execution-receipt-inventory",
                1,
                [item.execution_receipt_id for item in self.execution_receipts],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_seal_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-execution-seal-authority",
                1,
                self.execution_scope.execution_scope_authority_id,
                self.execution_scope_content_sha256,
                self.execution_scope_size_bytes,
                self.candidate_audit_head_sequence,
                self.candidate_audit_head_hash,
                self.sample_execution_count,
                self.sample_execution_inventory_root_sha256,
                self.candidate_case_count,
                self.candidate_case_inventory_root_sha256,
                self.run_trap_seal.run_trap_seal_authority_id,
                self.execution_receipt_count,
                self.execution_receipt_inventory_root_sha256,
            ]
        )


__all__ = [
    "MAX_M6_REPLAY_LOCKED_COMPONENT_VERSION_LENGTH",
    "MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES",
    "M6ReplayLockedCandidateCaseBinding",
    "M6ReplayLockedExecutionComponentAuthority",
    "M6ReplayLockedExecutionRoute",
    "M6ReplayLockedExecutionScopeAuthority",
    "M6ReplayLockedExecutionSealAuthority",
    "M6ReplayLockedPendingSampleCommitmentAuthority",
    "M6ReplayLockedRunTrapSealAuthority",
    "M6ReplayLockedSampleExecutionRecord",
]
