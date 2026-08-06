"""Typed report for read-only M5 SQLite and current-projection validation."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.artifact_validation import M3ArtifactValidationReport
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_projection import M5AuthorityKind, M5ProjectionFileKind
from labcourt.contracts.references import ReferenceToken, require_reference_token

M5_ARTIFACT_VALIDATOR_VERSION: Literal["m5-artifacts-v1"] = "m5-artifacts-v1"


class M5ArtifactValidationArea(StrEnum):
    AUTHORITY = "AUTHORITY"
    DATASET = "DATASET"
    PROJECTION = "PROJECTION"
    RETENTION = "RETENTION"
    BUDGET = "BUDGET"


class M5ArtifactValidationIssueCode(StrEnum):
    AUTHORITY_DOCUMENT_INVALID = "AUTHORITY_DOCUMENT_INVALID"
    AUTHORITY_INDEX_MISMATCH = "AUTHORITY_INDEX_MISMATCH"
    AUTHORITY_REFERENCE_INVALID = "AUTHORITY_REFERENCE_INVALID"
    AUTHORITY_HEAD_INVALID = "AUTHORITY_HEAD_INVALID"
    AUTHORITY_SCHEMA_INVALID = "AUTHORITY_SCHEMA_INVALID"
    ALERT_POLICY_REPLAY_INVALID = "ALERT_POLICY_REPLAY_INVALID"
    ALERT_AUTOMATIC_PRECEDENT_INVALID = "ALERT_AUTOMATIC_PRECEDENT_INVALID"
    PRECEDENT_ACTIVATION_INVALID = "PRECEDENT_ACTIVATION_INVALID"
    PRECEDENT_CAUSAL_LEDGER_INVALID = "PRECEDENT_CAUSAL_LEDGER_INVALID"
    TRAINING_CAUSAL_LEDGER_INVALID = "TRAINING_CAUSAL_LEDGER_INVALID"
    DATASET_SNAPSHOT_CLOSURE_INVALID = "DATASET_SNAPSHOT_CLOSURE_INVALID"
    PROJECTION_MISSING = "PROJECTION_MISSING"
    PROJECTION_UNSAFE = "PROJECTION_UNSAFE"
    PROJECTION_CONTENT_MISMATCH = "PROJECTION_CONTENT_MISMATCH"
    PROJECTION_ROOT_MISMATCH = "PROJECTION_ROOT_MISMATCH"
    PROJECTION_INVENTORY_MISMATCH = "PROJECTION_INVENTORY_MISMATCH"
    DATASET_PATH_UNSAFE = "DATASET_PATH_UNSAFE"
    DATASET_CONTENT_MISSING = "DATASET_CONTENT_MISSING"
    DATASET_CONTENT_HASH_MISMATCH = "DATASET_CONTENT_HASH_MISMATCH"
    DATASET_CONTENT_SIZE_MISMATCH = "DATASET_CONTENT_SIZE_MISMATCH"
    DATASET_CROP_AUTHORITY_INVALID = "DATASET_CROP_AUTHORITY_INVALID"
    DATASET_REPORT_REBUILD_MISMATCH = "DATASET_REPORT_REBUILD_MISMATCH"
    DATASET_CONTENT_REBUILD_MISMATCH = "DATASET_CONTENT_REBUILD_MISMATCH"
    DATASET_UNREGISTERED_FILE = "DATASET_UNREGISTERED_FILE"
    DATASET_DIRECTORY_UNSAFE = "DATASET_DIRECTORY_UNSAFE"
    DATASET_RETENTION_HOLD_MISSING = "DATASET_RETENTION_HOLD_MISSING"
    DATASET_RETENTION_HOLD_EXTRA = "DATASET_RETENTION_HOLD_EXTRA"
    DATASET_RETENTION_HOLD_RELEASED = "DATASET_RETENTION_HOLD_RELEASED"
    DATASET_RETENTION_HOLD_OWNER_MISMATCH = "DATASET_RETENTION_HOLD_OWNER_MISMATCH"
    DATASET_RETENTION_HOLD_DOCUMENT_MISMATCH = "DATASET_RETENTION_HOLD_DOCUMENT_MISMATCH"
    DATASET_RETENTION_AUDIT_LINK_INVALID = "DATASET_RETENTION_AUDIT_LINK_INVALID"
    ORPHAN_APPEAL_RETENTION_HOLD = "ORPHAN_APPEAL_RETENTION_HOLD"
    ORPHAN_DATASET_RETENTION_HOLD = "ORPHAN_DATASET_RETENTION_HOLD"
    AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED = "AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED"
    AUTHORITY_RECORD_BYTES_BUDGET_EXCEEDED = "AUTHORITY_RECORD_BYTES_BUDGET_EXCEEDED"
    AUTHORITY_TOTAL_BYTES_BUDGET_EXCEEDED = "AUTHORITY_TOTAL_BYTES_BUDGET_EXCEEDED"
    PROJECTION_FILE_BYTES_BUDGET_EXCEEDED = "PROJECTION_FILE_BYTES_BUDGET_EXCEEDED"
    PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED = "PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED"
    DATASET_FILE_COUNT_BUDGET_EXCEEDED = "DATASET_FILE_COUNT_BUDGET_EXCEEDED"
    DATASET_FILE_BYTES_BUDGET_EXCEEDED = "DATASET_FILE_BYTES_BUDGET_EXCEEDED"
    DATASET_TOTAL_BYTES_BUDGET_EXCEEDED = "DATASET_TOTAL_BYTES_BUDGET_EXCEEDED"
    RETENTION_RECORD_COUNT_BUDGET_EXCEEDED = "RETENTION_RECORD_COUNT_BUDGET_EXCEEDED"
    RETENTION_RECORD_BYTES_BUDGET_EXCEEDED = "RETENTION_RECORD_BYTES_BUDGET_EXCEEDED"
    RETENTION_TOTAL_BYTES_BUDGET_EXCEEDED = "RETENTION_TOTAL_BYTES_BUDGET_EXCEEDED"


class M5AlertAuthorityReasonCode(StrEnum):
    """Stable fail-closed reasons for alert/automatic-precedent replay."""

    ALERT_POLICY_INPUT_ROOT_INVALID = "ALERT_POLICY_INPUT_ROOT_INVALID"
    ALERT_PRIOR_COOLDOWN_CAUSAL_HEAD_MISMATCH = "ALERT_PRIOR_COOLDOWN_CAUSAL_HEAD_MISMATCH"
    ALERT_COOLDOWN_WRITE_CAUSAL_CLOSURE_INVALID = "ALERT_COOLDOWN_WRITE_CAUSAL_CLOSURE_INVALID"
    ALERT_POLICY_REPLAY_MISMATCH = "ALERT_POLICY_REPLAY_MISMATCH"
    ALERT_AUTOMATIC_PRECEDENT_MISSING = "ALERT_AUTOMATIC_PRECEDENT_MISSING"
    ALERT_AUTOMATIC_PRECEDENT_DUPLICATE = "ALERT_AUTOMATIC_PRECEDENT_DUPLICATE"
    ALERT_AUTOMATIC_PRECEDENT_ORPHAN = "ALERT_AUTOMATIC_PRECEDENT_ORPHAN"
    ALERT_AUTOMATIC_PRECEDENT_REPLAY_MISMATCH = "ALERT_AUTOMATIC_PRECEDENT_REPLAY_MISMATCH"
    ALERT_AUTOMATIC_PRECEDENT_EMBEDDING_CLOSURE_INVALID = (
        "ALERT_AUTOMATIC_PRECEDENT_EMBEDDING_CLOSURE_INVALID"
    )
    ALERT_AUTOMATIC_PRECEDENT_TIME_INVALID = "ALERT_AUTOMATIC_PRECEDENT_TIME_INVALID"


class M5ActivationAuthorityReasonCode(StrEnum):
    """Stable fail-closed reasons for automatic-activation Case-cut replay."""

    ACTIVATION_SOURCE_CASE_CUT_INVALID = "ACTIVATION_SOURCE_CASE_CUT_INVALID"
    ACTIVATION_APPEAL_INVENTORY_MISMATCH = "ACTIVATION_APPEAL_INVENTORY_MISMATCH"
    ACTIVATION_CASE_CAUSAL_STATE_INVALID = "ACTIVATION_CASE_CAUSAL_STATE_INVALID"
    ACTIVATION_REPLAY_MISMATCH = "ACTIVATION_REPLAY_MISMATCH"


class M5PrecedentCausalLedgerReasonCode(StrEnum):
    """Stable fail-closed reasons for the source/event bijection and chain."""

    PRECEDENT_CAUSAL_SOURCE_DUPLICATE = "PRECEDENT_CAUSAL_SOURCE_DUPLICATE"
    PRECEDENT_CAUSAL_EVENT_MISSING = "PRECEDENT_CAUSAL_EVENT_MISSING"
    PRECEDENT_CAUSAL_EVENT_DUPLICATE = "PRECEDENT_CAUSAL_EVENT_DUPLICATE"
    PRECEDENT_CAUSAL_EVENT_ORPHAN = "PRECEDENT_CAUSAL_EVENT_ORPHAN"
    PRECEDENT_CAUSAL_EVENT_SOURCE_MISMATCH = "PRECEDENT_CAUSAL_EVENT_SOURCE_MISMATCH"
    PRECEDENT_CAUSAL_EVENT_CHAIN_INVALID = "PRECEDENT_CAUSAL_EVENT_CHAIN_INVALID"


class M5PrecedentConflictHistoryReasonCode(StrEnum):
    """Stable fail-closed reasons for causal conflict-batch replay."""

    CONFLICT_BATCH_TRUSTED_POLICY_MISMATCH = "CONFLICT_BATCH_TRUSTED_POLICY_MISMATCH"
    CONFLICT_BATCH_CAUSAL_CUT_INVALID = "CONFLICT_BATCH_CAUSAL_CUT_INVALID"
    CONFLICT_BATCH_ACTIVE_ROOT_MISMATCH = "CONFLICT_BATCH_ACTIVE_ROOT_MISMATCH"
    CONFLICT_BATCH_CAUSAL_INTERVAL_INVALID = "CONFLICT_BATCH_CAUSAL_INTERVAL_INVALID"
    CONFLICT_BATCH_MARKER_MISSING_OR_INVALID = "CONFLICT_BATCH_MARKER_MISSING_OR_INVALID"
    CONFLICT_BATCH_RECEIPT_CLOSURE_INVALID = "CONFLICT_BATCH_RECEIPT_CLOSURE_INVALID"
    CONFLICT_BATCH_AUTHORITY_REFERENCE_INVALID = "CONFLICT_BATCH_AUTHORITY_REFERENCE_INVALID"
    CONFLICT_BATCH_POLICY_REPLAY_INVALID = "CONFLICT_BATCH_POLICY_REPLAY_INVALID"


class M5PrecedentRevocationHistoryReasonCode(StrEnum):
    """Stable fail-closed reasons for causal revocation replay."""

    REVOCATION_CAUSAL_INTERVAL_INVALID = "REVOCATION_CAUSAL_INTERVAL_INVALID"
    REVOCATION_CITATION_SNAPSHOT_MISMATCH = "REVOCATION_CITATION_SNAPSHOT_MISMATCH"
    REVOCATION_MARKER_MISSING_OR_INVALID = "REVOCATION_MARKER_MISSING_OR_INVALID"
    REVOCATION_RECEIPT_CLOSURE_INVALID = "REVOCATION_RECEIPT_CLOSURE_INVALID"


class M5AppealResolutionHistoryReasonCode(StrEnum):
    """Stable fail-closed reasons for historical appeal side-effect replay."""

    APPEAL_RESOLUTION_EFFECT_ROOT_MISMATCH = "APPEAL_RESOLUTION_EFFECT_ROOT_MISMATCH"
    APPEAL_RESOLUTION_CAUSAL_INTERVAL_INVALID = "APPEAL_RESOLUTION_CAUSAL_INTERVAL_INVALID"
    APPEAL_RESOLUTION_MARKER_MISSING_OR_INVALID = "APPEAL_RESOLUTION_MARKER_MISSING_OR_INVALID"
    APPEAL_RESOLUTION_RECEIPT_CLOSURE_INVALID = "APPEAL_RESOLUTION_RECEIPT_CLOSURE_INVALID"


class M5TrainingLabelProvenanceReasonCode(StrEnum):
    """Stable fail-closed reasons for strong training-label provenance closure."""

    TRAINING_LABEL_PROVENANCE_MISSING = "TRAINING_LABEL_PROVENANCE_MISSING"
    TRAINING_LABEL_PROVENANCE_DUPLICATE = "TRAINING_LABEL_PROVENANCE_DUPLICATE"
    TRAINING_LABEL_PROVENANCE_ORPHAN = "TRAINING_LABEL_PROVENANCE_ORPHAN"
    TRAINING_LABEL_WEAK_PROVENANCE_FORBIDDEN = "TRAINING_LABEL_WEAK_PROVENANCE_FORBIDDEN"
    TRAINING_LABEL_AUTHORITY_INVALID = "TRAINING_LABEL_AUTHORITY_INVALID"
    TRAINING_LABEL_REVIEW_AUTHORITY_INVALID = "TRAINING_LABEL_REVIEW_AUTHORITY_INVALID"
    TRAINING_LABEL_TERMINAL_AUTHORITY_INVALID = "TRAINING_LABEL_TERMINAL_AUTHORITY_INVALID"
    TRAINING_LABEL_RESOLUTION_INTENT_INVALID = "TRAINING_LABEL_RESOLUTION_INTENT_INVALID"
    TRAINING_LABEL_RESOLUTION_COMMIT_INVALID = "TRAINING_LABEL_RESOLUTION_COMMIT_INVALID"
    TRAINING_LABEL_RESOLUTION_MARKER_INVALID = "TRAINING_LABEL_RESOLUTION_MARKER_INVALID"
    DATASET_LABEL_PROVENANCE_INVALID = "DATASET_LABEL_PROVENANCE_INVALID"


class M5TrainingHistoryReasonCode(StrEnum):
    """Stable fail-closed reasons for historical training and dataset closure."""

    TRAINING_CAUSAL_EVENT_MISSING = "TRAINING_CAUSAL_EVENT_MISSING"
    TRAINING_CAUSAL_EVENT_DUPLICATE = "TRAINING_CAUSAL_EVENT_DUPLICATE"
    TRAINING_CAUSAL_EVENT_ORPHAN = "TRAINING_CAUSAL_EVENT_ORPHAN"
    TRAINING_CAUSAL_EVENT_SOURCE_MISMATCH = "TRAINING_CAUSAL_EVENT_SOURCE_MISMATCH"
    TRAINING_CAUSAL_EVENT_CHAIN_INVALID = "TRAINING_CAUSAL_EVENT_CHAIN_INVALID"
    DATASET_REGISTRATION_SNAPSHOT_MISSING = "DATASET_REGISTRATION_SNAPSHOT_MISSING"
    DATASET_REGISTRATION_SNAPSHOT_DUPLICATE = "DATASET_REGISTRATION_SNAPSHOT_DUPLICATE"
    DATASET_REGISTRATION_MARKER_MISSING_OR_INVALID = (
        "DATASET_REGISTRATION_MARKER_MISSING_OR_INVALID"
    )
    DATASET_CAUSAL_CUT_INVALID = "DATASET_CAUSAL_CUT_INVALID"
    DATASET_LABEL_CUT_ACCOUNTING_INVALID = "DATASET_LABEL_CUT_ACCOUNTING_INVALID"
    DATASET_LABEL_AUTHORITY_MISMATCH = "DATASET_LABEL_AUTHORITY_MISMATCH"
    DATASET_LABEL_INVENTORY_ROOT_MISMATCH = "DATASET_LABEL_INVENTORY_ROOT_MISMATCH"
    DATASET_CROP_SNAPSHOT_MISSING = "DATASET_CROP_SNAPSHOT_MISSING"
    DATASET_CROP_SNAPSHOT_EXTRA = "DATASET_CROP_SNAPSHOT_EXTRA"
    DATASET_CROP_SNAPSHOT_DUPLICATE = "DATASET_CROP_SNAPSHOT_DUPLICATE"
    DATASET_CROP_SNAPSHOT_ROOT_MISMATCH = "DATASET_CROP_SNAPSHOT_ROOT_MISMATCH"
    DATASET_HISTORICAL_CASE_MISSING = "DATASET_HISTORICAL_CASE_MISSING"
    DATASET_HISTORICAL_CASE_DOCUMENT_MISMATCH = "DATASET_HISTORICAL_CASE_DOCUMENT_MISMATCH"
    DATASET_HISTORICAL_PACK_INVALID = "DATASET_HISTORICAL_PACK_INVALID"
    DATASET_HISTORICAL_CROP_INVALID = "DATASET_HISTORICAL_CROP_INVALID"


class M5ArtifactValidationBudget(FrozenContractModel):
    max_authority_records: int = Field(default=1_000_000, gt=0, le=10_000_000, strict=True)
    max_authority_record_bytes: int = Field(
        default=16 * 1024 * 1024, gt=0, le=1024 * 1024 * 1024, strict=True
    )
    max_authority_total_bytes: int = Field(
        default=1024 * 1024 * 1024,
        gt=0,
        le=64 * 1024 * 1024 * 1024,
        strict=True,
    )
    max_projection_file_bytes: int = Field(
        default=64 * 1024 * 1024, gt=0, le=1024 * 1024 * 1024, strict=True
    )
    max_projection_total_bytes: int = Field(
        default=256 * 1024 * 1024, gt=0, le=4 * 1024 * 1024 * 1024, strict=True
    )
    max_dataset_files: int = Field(default=10_000, gt=0, le=1_000_000, strict=True)
    max_dataset_file_bytes: int = Field(
        default=64 * 1024 * 1024, gt=0, le=1024 * 1024 * 1024, strict=True
    )
    max_dataset_total_bytes: int = Field(
        default=1024 * 1024 * 1024,
        gt=0,
        le=64 * 1024 * 1024 * 1024,
        strict=True,
    )
    max_retention_records: int = Field(default=1_000_000, gt=0, le=10_000_000, strict=True)
    max_retention_record_bytes: int = Field(
        default=16 * 1024 * 1024, gt=0, le=1024 * 1024 * 1024, strict=True
    )
    max_retention_total_bytes: int = Field(
        default=1024 * 1024 * 1024,
        gt=0,
        le=64 * 1024 * 1024 * 1024,
        strict=True,
    )


class M5ArtifactValidationScope(FrozenContractModel):
    sqlite_snapshot: Literal[True] = True
    canonical_run_manifest: Literal[True] = True
    config_manifest_binding: Literal[True] = True
    sql_authority_budget_preflight: Literal[True] = True
    streaming_limit_plus_one: Literal[True] = True
    canonical_documents: Literal[True] = True
    duplicated_index_columns: Literal[True] = True
    foreign_key_closure: Literal[True] = True
    application_reference_closure: Literal[True] = True
    current_case_heads: Literal[True] = True
    current_precedent_heads: Literal[True] = True
    automatic_activation_case_cut_replay: Literal[True] = True
    precedent_causal_ledger_bijection: Literal[True] = True
    current_cooldown_heads: Literal[True] = True
    current_appeal_heads: Literal[True] = True
    deterministic_dataset_rebuild: Literal[True] = True
    current_training_crop_verification: Literal[True] = True
    dataset_physical_bytes: Literal[True] = True
    dataset_directory_exact_inventory: Literal[True] = True
    dataset_retention_closure: Literal[True] = True
    appeal_dataset_orphan_hold_classification: Literal[True] = True
    current_projection_exact_inventory: Literal[True] = True
    authority_mutation: Literal[False] = False
    dataset_mutation: Literal[False] = False
    projection_mutation: Literal[False] = False


class M5ArtifactValidationInventoryCount(FrozenContractModel):
    authority_kind: M5AuthorityKind
    authoritative_count: int = Field(ge=0, strict=True)

    @property
    def sort_key(self) -> str:
        return self.authority_kind.value


class M5ArtifactValidationProjectionCount(FrozenContractModel):
    file_kind: M5ProjectionFileKind
    record_count: int = Field(ge=0, strict=True)

    @property
    def sort_key(self) -> str:
        return self.file_kind.value


class M5ArtifactValidationCounts(FrozenContractModel):
    authority_rows: int = Field(default=0, ge=0, strict=True)
    authority_bytes: int = Field(default=0, ge=0, strict=True)
    validated_authority_documents: int = Field(default=0, ge=0, strict=True)
    authority_failures: int = Field(default=0, ge=0, strict=True)
    case_roots: int = Field(default=0, ge=0, strict=True)
    max_authority_record_bytes: int = Field(default=0, ge=0, strict=True)
    projection_files: int = Field(default=0, ge=0, strict=True)
    projection_records: int = Field(default=0, ge=0, strict=True)
    projection_bytes: int = Field(default=0, ge=0, strict=True)
    max_projection_file_bytes: int = Field(default=0, ge=0, strict=True)
    dataset_registrations: int = Field(default=0, ge=0, strict=True)
    verified_dataset_files: int = Field(default=0, ge=0, strict=True)
    dataset_bytes: int = Field(default=0, ge=0, strict=True)
    max_dataset_file_bytes: int = Field(default=0, ge=0, strict=True)
    unregistered_dataset_files: int = Field(default=0, ge=0, strict=True)
    dataset_retention_holds: int = Field(default=0, ge=0, strict=True)
    orphan_retention_holds: int = Field(default=0, ge=0, strict=True)
    retention_rows: int = Field(default=0, ge=0, strict=True)
    retention_bytes: int = Field(default=0, ge=0, strict=True)
    max_retention_record_bytes: int = Field(default=0, ge=0, strict=True)
    inventories: tuple[M5ArtifactValidationInventoryCount, ...] = ()
    projections: tuple[M5ArtifactValidationProjectionCount, ...] = ()

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        inventory_keys = tuple(item.sort_key for item in self.inventories)
        projection_keys = tuple(item.sort_key for item in self.projections)
        if inventory_keys != tuple(sorted(inventory_keys)) or len(inventory_keys) != len(
            set(inventory_keys)
        ):
            raise ValueError("M5 authority inventories must be unique and ordered")
        if projection_keys != tuple(sorted(projection_keys)) or len(projection_keys) != len(
            set(projection_keys)
        ):
            raise ValueError("M5 projection inventories must be unique and ordered")
        if self.authority_rows != sum(item.authoritative_count for item in self.inventories):
            raise ValueError("M5 authority row count conflicts with inventories")
        if self.projection_records != sum(item.record_count for item in self.projections):
            raise ValueError("M5 projection record count conflicts with inventories")
        if self.validated_authority_documents > self.authority_rows:
            raise ValueError("M5 validated documents exceed traversed authority rows")
        if self.projection_files == 0:
            if self.projection_bytes or self.max_projection_file_bytes or self.projections:
                raise ValueError("empty M5 projection cannot carry observations")
        elif self.max_projection_file_bytes > self.projection_bytes:
            raise ValueError("M5 maximum projection file exceeds total bytes")
        if self.verified_dataset_files > self.dataset_registrations:
            raise ValueError("verified M5 dataset files exceed registrations")
        if self.verified_dataset_files == 0:
            if self.dataset_bytes or self.max_dataset_file_bytes:
                raise ValueError("empty M5 dataset verification cannot carry byte observations")
        elif self.max_dataset_file_bytes > self.dataset_bytes:
            raise ValueError("M5 maximum dataset file exceeds total bytes")
        if self.retention_rows == 0:
            if self.retention_bytes or self.max_retention_record_bytes:
                raise ValueError("empty M5 retention scan cannot carry byte observations")
        elif self.max_retention_record_bytes > self.retention_bytes:
            raise ValueError("M5 maximum retention record exceeds total bytes")
        return self


class M5ArtifactValidationIssue(FrozenContractModel):
    code: M5ArtifactValidationIssueCode
    area: M5ArtifactValidationArea
    authority_kind: M5AuthorityKind | None = None
    file_kind: M5ProjectionFileKind | None = None
    record_identity_sha256: Sha256Hex | None = None
    source_token: Sha256Hex | None = None
    dataset_id: Sha256Hex | None = None
    hold_identity_sha256: Sha256Hex | None = None
    reason_code: ReferenceToken
    limit: int | None = Field(default=None, gt=0, strict=True)
    observed: int | None = Field(default=None, ge=0, strict=True)
    expected_sha256: Sha256Hex | None = None
    actual_sha256: Sha256Hex | None = None

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        if self.area == M5ArtifactValidationArea.AUTHORITY:
            if self.authority_kind is None or self.record_identity_sha256 is None:
                raise ValueError("M5 authority issue requires a typed record identity")
            if any(
                item is not None
                for item in (
                    self.file_kind,
                    self.source_token,
                    self.dataset_id,
                    self.hold_identity_sha256,
                )
            ):
                raise ValueError("M5 authority issue cannot carry projection identity")
        elif self.area == M5ArtifactValidationArea.PROJECTION:
            if (
                self.source_token is None
                or self.authority_kind is not None
                or self.record_identity_sha256 is not None
                or self.dataset_id is not None
                or self.hold_identity_sha256 is not None
            ):
                raise ValueError("M5 projection issue requires an opaque source token")
        elif self.area == M5ArtifactValidationArea.DATASET:
            if (
                (self.dataset_id is None and self.source_token is None)
                or self.authority_kind is not None
                or self.file_kind is not None
                or self.record_identity_sha256 is not None
                or self.hold_identity_sha256 is not None
            ):
                raise ValueError("M5 dataset issue requires a dataset or opaque source identity")
        elif self.area == M5ArtifactValidationArea.RETENTION:
            if (
                self.hold_identity_sha256 is None
                or self.authority_kind is not None
                or self.file_kind is not None
                or self.record_identity_sha256 is not None
                or self.source_token is not None
                or self.expected_sha256 is not None
                or self.actual_sha256 is not None
            ):
                raise ValueError("M5 retention issue requires a typed hold identity")
        else:
            if (
                self.limit is None
                or self.observed is None
                or self.observed <= self.limit
                or any(
                    item is not None
                    for item in (
                        self.authority_kind,
                        self.file_kind,
                        self.record_identity_sha256,
                        self.source_token,
                        self.dataset_id,
                        self.hold_identity_sha256,
                        self.expected_sha256,
                        self.actual_sha256,
                    )
                )
            ):
                raise ValueError("M5 budget issue requires only an exceeded limit")
        if self.code == M5ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH and (
            self.expected_sha256 is None
            or self.actual_sha256 is None
            or self.expected_sha256 == self.actual_sha256
        ):
            raise ValueError("M5 projection content issue must describe a real mismatch")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.area.value,
            self.authority_kind.value if self.authority_kind else "",
            (
                self.record_identity_sha256
                or self.dataset_id
                or self.hold_identity_sha256
                or self.source_token
                or ""
            ),
            self.code.value,
            self.reason_code,
        )


class M5ArtifactValidationReport(FrozenContractModel):
    validator_version: Literal["m5-artifacts-v1"] = M5_ARTIFACT_VALIDATOR_VERSION
    run_id: ReferenceToken
    manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    predecessor_report: M3ArtifactValidationReport | M4ArtifactValidationReport | None = None
    scope: M5ArtifactValidationScope = Field(default_factory=M5ArtifactValidationScope)
    authority_root_sha256: Sha256Hex | None = None
    counts: M5ArtifactValidationCounts = Field(default_factory=M5ArtifactValidationCounts)
    issues: tuple[M5ArtifactValidationIssue, ...] = ()

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M5 artifact validation run reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_passed = payload.pop("passed", None)
        claimed_report_id = payload.pop("report_id", None)
        passed_present = "passed" in value
        report_present = "report_id" in value
        report = handler(payload)
        if passed_present and claimed_passed != report.passed:
            raise ValueError("serialized M5 passed conflicts with findings")
        if report_present and claimed_report_id != report.report_id:
            raise ValueError("serialized M5 report ID conflicts with content")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return (
            not self.issues
            and self.authority_root_sha256 is not None
            and (self.predecessor_report is None or self.predecessor_report.passed)
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def report_id(self) -> Sha256Hex:
        return hashlib.sha256(
            canonical_json(self.model_dump(mode="json", exclude={"passed", "report_id"})).encode(
                "utf-8"
            )
        ).hexdigest()

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.predecessor_report is not None and self.predecessor_report.run_id != self.run_id:
            raise ValueError("M5 and predecessor artifact report run IDs differ")
        keys = tuple(issue.sort_key for issue in self.issues)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M5 validation issues must be unique and ordered")
        if not self.issues and self.authority_root_sha256 is None:
            raise ValueError("a passing M5 report requires an authority root")
        return self


__all__ = [
    "M5_ARTIFACT_VALIDATOR_VERSION",
    "M5ActivationAuthorityReasonCode",
    "M5AlertAuthorityReasonCode",
    "M5AppealResolutionHistoryReasonCode",
    "M5ArtifactValidationArea",
    "M5ArtifactValidationBudget",
    "M5ArtifactValidationCounts",
    "M5ArtifactValidationInventoryCount",
    "M5ArtifactValidationIssue",
    "M5ArtifactValidationIssueCode",
    "M5ArtifactValidationProjectionCount",
    "M5ArtifactValidationReport",
    "M5ArtifactValidationScope",
    "M5PrecedentCausalLedgerReasonCode",
    "M5PrecedentConflictHistoryReasonCode",
    "M5PrecedentRevocationHistoryReasonCode",
    "M5TrainingHistoryReasonCode",
    "M5TrainingLabelProvenanceReasonCode",
]
