"""Typed, deterministic reports for read-only M2 and M3 artifact validation.

The M2 report is a frozen public contract.  M3 therefore adds a separate root
report which embeds, rather than widens, the M2 result.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditChainFailureReason,
    ClosureDefectCode,
    MediaAvailability,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.projection_generation import ProjectionArtifactKind
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef

ARTIFACT_VALIDATOR_VERSION: Literal["m2-artifacts-v1"] = "m2-artifacts-v1"
M3_ARTIFACT_VALIDATOR_VERSION: Literal["m3-artifacts-v1"] = "m3-artifacts-v1"


class ArtifactValidationArea(StrEnum):
    AUTHORITY = "AUTHORITY"
    AUDIT = "AUDIT"
    EVENT = "EVENT"
    CASE = "CASE"
    PACK = "PACK"
    MEDIA = "MEDIA"
    PROJECTION = "PROJECTION"
    BUDGET = "BUDGET"


class ArtifactInventoryKind(StrEnum):
    AUDIT_ENTRY = "AUDIT_ENTRY"
    EVENT = "EVENT"
    CASE = "CASE"
    PACK = "PACK"
    MEDIA = "MEDIA"


class ArtifactValidationIssueCode(StrEnum):
    AUTHORITY_DOCUMENT_INVALID = "AUTHORITY_DOCUMENT_INVALID"
    AUTHORITY_INVENTORY_MISMATCH = "AUTHORITY_INVENTORY_MISMATCH"
    AUDIT_DOCUMENT_INVALID = "AUDIT_DOCUMENT_INVALID"
    AUDIT_CHAIN_INVALID = "AUDIT_CHAIN_INVALID"
    EVENT_DOCUMENT_INVALID = "EVENT_DOCUMENT_INVALID"
    CASE_DOCUMENT_INVALID = "CASE_DOCUMENT_INVALID"
    CASE_SCOPE_MISMATCH = "CASE_SCOPE_MISMATCH"
    PACK_DOCUMENT_INVALID = "PACK_DOCUMENT_INVALID"
    PACK_SCOPE_MISMATCH = "PACK_SCOPE_MISMATCH"
    CURRENT_CLOSURE_INVALID = "CURRENT_CLOSURE_INVALID"
    CURRENT_CLOSURE_DEFECT = "CURRENT_CLOSURE_DEFECT"
    MEDIA_UNAVAILABLE = "MEDIA_UNAVAILABLE"
    PROJECTION_MISSING = "PROJECTION_MISSING"
    PROJECTION_UNSAFE = "PROJECTION_UNSAFE"
    PROJECTION_CONTENT_MISMATCH = "PROJECTION_CONTENT_MISMATCH"
    DOCUMENT_BYTES_BUDGET_EXCEEDED = "DOCUMENT_BYTES_BUDGET_EXCEEDED"
    AUDIT_BUDGET_EXCEEDED = "AUDIT_BUDGET_EXCEEDED"
    EVENT_BUDGET_EXCEEDED = "EVENT_BUDGET_EXCEEDED"
    CASE_BUDGET_EXCEEDED = "CASE_BUDGET_EXCEEDED"
    PACK_BUDGET_EXCEEDED = "PACK_BUDGET_EXCEEDED"
    MEDIA_BUDGET_EXCEEDED = "MEDIA_BUDGET_EXCEEDED"
    PROJECTION_BYTES_BUDGET_EXCEEDED = "PROJECTION_BYTES_BUDGET_EXCEEDED"


_INVENTORY_AREAS = {
    ArtifactInventoryKind.AUDIT_ENTRY: ArtifactValidationArea.AUDIT,
    ArtifactInventoryKind.EVENT: ArtifactValidationArea.EVENT,
    ArtifactInventoryKind.CASE: ArtifactValidationArea.CASE,
    ArtifactInventoryKind.PACK: ArtifactValidationArea.PACK,
    ArtifactInventoryKind.MEDIA: ArtifactValidationArea.MEDIA,
}
_BUDGET_CODES = frozenset(
    {
        ArtifactValidationIssueCode.DOCUMENT_BYTES_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.AUDIT_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.EVENT_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.CASE_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.PACK_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.MEDIA_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.PROJECTION_BYTES_BUDGET_EXCEEDED,
    }
)
_PROJECTION_CODES = frozenset(
    {
        ArtifactValidationIssueCode.PROJECTION_MISSING,
        ArtifactValidationIssueCode.PROJECTION_UNSAFE,
        ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
    }
)


class ArtifactValidationBudget(FrozenContractModel):
    max_database_bytes: int = Field(
        default=4 * 1024 * 1024 * 1024,
        gt=0,
        le=64 * 1024 * 1024 * 1024,
        strict=True,
    )
    max_audit_entries: int = Field(default=100_000, gt=0, le=1_000_000, strict=True)
    max_document_bytes: int = Field(
        default=16 * 1024 * 1024,
        gt=0,
        le=1024 * 1024 * 1024,
        strict=True,
    )
    max_events: int = Field(default=10_000, gt=0, le=1_000_000, strict=True)
    max_cases: int = Field(default=10_000, gt=0, le=1_000_000, strict=True)
    max_packs: int = Field(default=50_000, gt=0, le=1_000_000, strict=True)
    max_media: int = Field(default=200_000, gt=0, le=2_000_000, strict=True)
    max_projection_bytes: int = Field(
        default=256 * 1024 * 1024,
        gt=0,
        le=4 * 1024 * 1024 * 1024,
        strict=True,
    )


class ArtifactValidationScope(FrozenContractModel):
    authority: Literal["SQLITE"] = "SQLITE"
    database_documents: Literal[True] = True
    audit_chain_and_head: Literal[True] = True
    current_closure: Literal[True] = True
    canonical_projections: Literal[True] = True
    stored_media: Literal[True] = True
    source_pixel_replay: Literal[False] = False
    privacy_transform_replay: Literal[False] = False
    creation_privacy_basis: Literal["IMMUTABLE_DB_AND_CREATION_CLOSURE"] = (
        "IMMUTABLE_DB_AND_CREATION_CLOSURE"
    )


class ArtifactValidationCounts(FrozenContractModel):
    max_document_bytes: int = Field(default=0, ge=0, strict=True)
    audit_entries: int = Field(default=0, ge=0, strict=True)
    events: int = Field(default=0, ge=0, strict=True)
    cases: int = Field(default=0, ge=0, strict=True)
    packs: int = Field(default=0, ge=0, strict=True)
    media: int = Field(default=0, ge=0, strict=True)
    projections: int = Field(default=0, ge=0, strict=True)
    projection_bytes: int = Field(default=0, ge=0, strict=True)


class ArtifactValidationIssue(FrozenContractModel):
    code: ArtifactValidationIssueCode
    area: ArtifactValidationArea
    root_ref: ArtifactRef | None = None
    artifact_ref: ArtifactRef | None = None
    closure_defect_code: ClosureDefectCode | None = None
    audit_failure_reason: AuditChainFailureReason | None = None
    media_availability: MediaAvailability | None = None
    projection_kind: ProjectionArtifactKind | None = None
    projection_id: ReferenceToken | None = None
    sequence: int | None = Field(default=None, ge=0, strict=True)
    limit: int | None = Field(default=None, gt=0, strict=True)
    observed: int | None = Field(default=None, ge=0, strict=True)
    expected_sha256: Sha256Hex | None = None
    actual_sha256: Sha256Hex | None = None
    expected_size_bytes: int | None = Field(default=None, ge=0, strict=True)
    actual_size_bytes: int | None = Field(default=None, ge=0, strict=True)
    inventory_kind: ArtifactInventoryKind | None = None
    authoritative_count: int | None = Field(default=None, ge=0, strict=True)
    traversed_count: int | None = Field(default=None, ge=0, strict=True)
    reason_code: ReferenceToken | None = None

    @field_validator("projection_id")
    @classmethod
    def validate_projection_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "artifact validation projection_id")

    @model_validator(mode="after")
    def validate_typed_context(self) -> Self:
        inventory_counts = (self.authoritative_count, self.traversed_count)
        if self.code == ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH:
            if (
                self.inventory_kind is None
                or any(value is None for value in inventory_counts)
                or self.authoritative_count == self.traversed_count
            ):
                raise ValueError(
                    "authority-inventory mismatch requires distinct authoritative and "
                    "traversed counts"
                )
            if self.area != _INVENTORY_AREAS[self.inventory_kind]:
                raise ValueError("authority-inventory mismatch area conflicts with its kind")
            if self.root_ref is not None or self.artifact_ref is not None:
                raise ValueError("authority-inventory mismatch cannot carry artifact references")
        elif self.inventory_kind is not None or any(
            value is not None for value in inventory_counts
        ):
            raise ValueError("only authority-inventory mismatches may carry inventory counts")

        if self.code in _BUDGET_CODES:
            if self.limit is None or self.observed is None or self.observed <= self.limit:
                raise ValueError("budget issues require an observed count above the limit")
        elif self.limit is not None or self.observed is not None:
            raise ValueError("only budget issues may carry limit and observed counts")

        if self.code in _PROJECTION_CODES:
            if self.projection_kind is None or self.projection_id is None:
                raise ValueError("projection issues require a typed projection scope")
        elif self.projection_kind is not None or self.projection_id is not None:
            raise ValueError("only projection issues may carry projection scope")

        if self.code == ArtifactValidationIssueCode.CURRENT_CLOSURE_DEFECT:
            if (
                self.root_ref is None
                or self.closure_defect_code is None
                or self.root_ref.kind != ArtifactKind.EVIDENCE_PACK
            ):
                raise ValueError("current-closure issues require a pack root and defect code")
        elif self.closure_defect_code is not None:
            raise ValueError("only current-closure issues may carry a closure defect code")

        if self.code == ArtifactValidationIssueCode.AUDIT_CHAIN_INVALID:
            if self.audit_failure_reason is None:
                raise ValueError("audit-chain issues require a typed failure reason")
        elif self.audit_failure_reason is not None:
            raise ValueError("only audit-chain issues may carry an audit failure reason")

        if self.code == ArtifactValidationIssueCode.MEDIA_UNAVAILABLE:
            if self.media_availability not in {
                MediaAvailability.PURGING,
                MediaAvailability.PURGED_BY_RETENTION,
            }:
                raise ValueError("media-unavailable issues require a non-available state")
        elif self.media_availability is not None:
            raise ValueError("only media-unavailable issues may carry availability")

        if self.code == ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH and (
            self.expected_sha256 is None
            or self.actual_sha256 is None
            or self.expected_sha256 == self.actual_sha256
        ):
            raise ValueError("projection mismatch requires distinct expected and actual hashes")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str, str, str, str, str]:
        root = self.root_ref.sort_key if self.root_ref is not None else ("", "")
        artifact = self.artifact_ref.sort_key if self.artifact_ref is not None else ("", "")
        context = self.model_dump(
            mode="json",
            exclude={"code", "area", "root_ref", "artifact_ref"},
            exclude_none=True,
        )
        return (
            self.area.value,
            self.code.value,
            root[0],
            root[1],
            artifact[0],
            artifact[1],
            canonical_json(context),
        )


class ArtifactValidationReport(FrozenContractModel):
    validator_version: Literal["m2-artifacts-v1"] = ARTIFACT_VALIDATOR_VERSION
    run_id: ReferenceToken
    manifest_id: Sha256Hex | None = None
    audit_head_sequence: int | None = Field(default=None, ge=-1, strict=True)
    audit_head_hash: Sha256Hex | None = None
    scope: ArtifactValidationScope = Field(default_factory=ArtifactValidationScope)
    budget: ArtifactValidationBudget = Field(default_factory=ArtifactValidationBudget)
    counts: ArtifactValidationCounts = Field(default_factory=ArtifactValidationCounts)
    issues: tuple[ArtifactValidationIssue, ...] = ()

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "artifact validation run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_passed(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "passed" in payload
        claimed = payload.pop("passed", None)
        report = handler(payload)
        if claimed_present and not isinstance(claimed, bool):
            raise ValueError("serialized artifact validation passed must be a boolean")
        if claimed_present and claimed != report.passed:
            raise ValueError("serialized artifact validation passed conflicts with its issues")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return not self.issues

    @model_validator(mode="after")
    def validate_scope_and_order(self) -> Self:
        head_values = (
            self.manifest_id,
            self.audit_head_sequence,
            self.audit_head_hash,
        )
        if any(value is None for value in head_values) and any(
            value is not None for value in head_values
        ):
            raise ValueError("artifact validation authority head must be complete or absent")
        keys = tuple(issue.sort_key for issue in self.issues)
        if len(keys) != len(set(keys)):
            raise ValueError("artifact validation issues must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("artifact validation issues must use stable order")
        inventory_kinds: set[ArtifactInventoryKind] = set()
        for issue in self.issues:
            if issue.code != ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH:
                continue
            assert issue.inventory_kind is not None
            assert issue.authoritative_count is not None
            if issue.inventory_kind in inventory_kinds:
                raise ValueError("artifact validation inventory kinds must be unique")
            inventory_kinds.add(issue.inventory_kind)
            if issue.authoritative_count != _authoritative_inventory_count(
                self.counts,
                issue.inventory_kind,
            ):
                raise ValueError(
                    "authority-inventory mismatch conflicts with report authority counts"
                )
        return self


class M3ArtifactValidationArea(StrEnum):
    CLAIM = "CLAIM"
    RESPONSE = "RESPONSE"
    CACHE = "CACHE"
    PARSE = "PARSE"
    SCREENING = "SCREENING"
    VERDICT = "VERDICT"
    REVIEW = "REVIEW"
    BACKLOG = "BACKLOG"
    USAGE = "USAGE"
    RAW_RESPONSE = "RAW_RESPONSE"
    BUDGET = "BUDGET"


class M3ArtifactInventoryKind(StrEnum):
    MODEL_CALL_CLAIM = "MODEL_CALL_CLAIM"
    MODEL_CALL_FAILURE_AUTHORITY = "MODEL_CALL_FAILURE_AUTHORITY"
    MODEL_RESPONSE = "MODEL_RESPONSE"
    PARSED_SCREENING_OUTPUT = "PARSED_SCREENING_OUTPUT"
    MODEL_PARSE_RECEIPT = "MODEL_PARSE_RECEIPT"
    MODEL_CACHE_ENTRY = "MODEL_CACHE_ENTRY"
    MODEL_CALL_USAGE = "MODEL_CALL_USAGE"
    SCREENING_RESULT = "SCREENING_RESULT"
    VERDICT = "VERDICT"
    PROCEDURAL_REVIEW = "PROCEDURAL_REVIEW"
    PROCEDURAL_DEFECT = "PROCEDURAL_DEFECT"
    BACKLOG_ITEM = "BACKLOG_ITEM"
    BACKLOG_ITEM_VERSION = "BACKLOG_ITEM_VERSION"
    BACKLOG_HEAD = "BACKLOG_HEAD"
    BACKLOG_COMPLETION_RECEIPT = "BACKLOG_COMPLETION_RECEIPT"


_M3_INVENTORY_AREAS = {
    M3ArtifactInventoryKind.MODEL_CALL_CLAIM: M3ArtifactValidationArea.CLAIM,
    M3ArtifactInventoryKind.MODEL_CALL_FAILURE_AUTHORITY: M3ArtifactValidationArea.CLAIM,
    M3ArtifactInventoryKind.MODEL_RESPONSE: M3ArtifactValidationArea.RESPONSE,
    M3ArtifactInventoryKind.PARSED_SCREENING_OUTPUT: M3ArtifactValidationArea.PARSE,
    M3ArtifactInventoryKind.MODEL_PARSE_RECEIPT: M3ArtifactValidationArea.PARSE,
    M3ArtifactInventoryKind.MODEL_CACHE_ENTRY: M3ArtifactValidationArea.CACHE,
    M3ArtifactInventoryKind.MODEL_CALL_USAGE: M3ArtifactValidationArea.USAGE,
    M3ArtifactInventoryKind.SCREENING_RESULT: M3ArtifactValidationArea.SCREENING,
    M3ArtifactInventoryKind.VERDICT: M3ArtifactValidationArea.VERDICT,
    M3ArtifactInventoryKind.PROCEDURAL_REVIEW: M3ArtifactValidationArea.REVIEW,
    M3ArtifactInventoryKind.PROCEDURAL_DEFECT: M3ArtifactValidationArea.REVIEW,
    M3ArtifactInventoryKind.BACKLOG_ITEM: M3ArtifactValidationArea.BACKLOG,
    M3ArtifactInventoryKind.BACKLOG_ITEM_VERSION: M3ArtifactValidationArea.BACKLOG,
    M3ArtifactInventoryKind.BACKLOG_HEAD: M3ArtifactValidationArea.BACKLOG,
    M3ArtifactInventoryKind.BACKLOG_COMPLETION_RECEIPT: M3ArtifactValidationArea.BACKLOG,
}


class M3ArtifactValidationIssueCode(StrEnum):
    AUTHORITY_DOCUMENT_INVALID = "AUTHORITY_DOCUMENT_INVALID"
    AUTHORITY_INDEX_MISMATCH = "AUTHORITY_INDEX_MISMATCH"
    AUTHORITY_REFERENCE_INVALID = "AUTHORITY_REFERENCE_INVALID"
    AUTHORITY_INVENTORY_MISMATCH = "AUTHORITY_INVENTORY_MISMATCH"
    RAW_RESPONSE_MISSING = "RAW_RESPONSE_MISSING"
    RAW_RESPONSE_UNSAFE = "RAW_RESPONSE_UNSAFE"
    RAW_RESPONSE_CONTENT_MISMATCH = "RAW_RESPONSE_CONTENT_MISMATCH"
    RAW_RESPONSE_UNREFERENCED = "RAW_RESPONSE_UNREFERENCED"
    RAW_RESPONSE_INVENTORY_UNSAFE = "RAW_RESPONSE_INVENTORY_UNSAFE"
    DOCUMENT_BYTES_BUDGET_EXCEEDED = "DOCUMENT_BYTES_BUDGET_EXCEEDED"
    DOCUMENT_COUNT_BUDGET_EXCEEDED = "DOCUMENT_COUNT_BUDGET_EXCEEDED"
    RAW_RESPONSE_BYTES_BUDGET_EXCEEDED = "RAW_RESPONSE_BYTES_BUDGET_EXCEEDED"
    RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED = "RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED"
    RAW_RESPONSE_FILE_COUNT_BUDGET_EXCEEDED = "RAW_RESPONSE_FILE_COUNT_BUDGET_EXCEEDED"


_M3_AUTHORITY_CODES = frozenset(
    {
        M3ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
        M3ArtifactValidationIssueCode.AUTHORITY_INDEX_MISMATCH,
        M3ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID,
    }
)
_M3_RAW_RESPONSE_CODES = frozenset(
    {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING,
        M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE,
        M3ArtifactValidationIssueCode.RAW_RESPONSE_CONTENT_MISMATCH,
    }
)
_M3_BUDGET_CODES = frozenset(
    {
        M3ArtifactValidationIssueCode.DOCUMENT_BYTES_BUDGET_EXCEEDED,
        M3ArtifactValidationIssueCode.DOCUMENT_COUNT_BUDGET_EXCEEDED,
        M3ArtifactValidationIssueCode.RAW_RESPONSE_BYTES_BUDGET_EXCEEDED,
        M3ArtifactValidationIssueCode.RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED,
        M3ArtifactValidationIssueCode.RAW_RESPONSE_FILE_COUNT_BUDGET_EXCEEDED,
    }
)


class M3ArtifactValidationBudget(FrozenContractModel):
    max_documents: int = Field(default=1_000_000, gt=0, le=10_000_000, strict=True)
    max_document_bytes: int = Field(
        default=16 * 1024 * 1024,
        gt=0,
        le=1024 * 1024 * 1024,
        strict=True,
    )
    max_raw_response_bytes: int = Field(
        default=64 * 1024 * 1024,
        gt=0,
        le=1024 * 1024 * 1024,
        strict=True,
    )
    max_raw_response_total_bytes: int = Field(
        default=4 * 1024 * 1024 * 1024,
        gt=0,
        le=64 * 1024 * 1024 * 1024,
        strict=True,
    )
    max_raw_response_files: int = Field(
        default=1_000_000,
        gt=0,
        le=10_000_000,
        strict=True,
    )
    max_raw_response_name_bytes: int = Field(
        default=255,
        gt=0,
        le=4096,
        strict=True,
    )


class M3ArtifactValidationScope(FrozenContractModel):
    authority: Literal["SQLITE_SNAPSHOT"] = "SQLITE_SNAPSHOT"
    canonical_model_call_claims: Literal[True] = True
    canonical_model_call_failure_authorities: Literal[True] = True
    canonical_model_responses: Literal[True] = True
    canonical_model_cache: Literal[True] = True
    canonical_parse_artifacts: Literal[True] = True
    canonical_screening_results: Literal[True] = True
    canonical_verdicts_and_reviews: Literal[True] = True
    canonical_backlog_history: Literal[True] = True
    canonical_usage_accounting: Literal[True] = True
    relational_bindings: Literal[True] = True
    raw_response_locator_binding: Literal[True] = True
    raw_response_content_and_size: Literal[True] = True
    raw_response_physical_inventory: Literal[True] = True
    raw_response_bidirectional_closure: Literal[True] = True
    raw_response_inventory_consistency: Literal["FAIL_CLOSED_RESCAN"] = "FAIL_CLOSED_RESCAN"
    provider_replay: Literal[False] = False
    model_semantic_replay: Literal[False] = False


class M3ArtifactValidationCounts(FrozenContractModel):
    max_document_bytes: int = Field(default=0, ge=0, strict=True)
    raw_response_bytes: int = Field(default=0, ge=0, strict=True)
    max_raw_response_bytes: int = Field(default=0, ge=0, strict=True)
    physical_raw_response_entries: int = Field(default=0, ge=0, strict=True)
    physical_raw_response_files: int = Field(default=0, ge=0, strict=True)
    physical_raw_response_bytes: int = Field(default=0, ge=0, strict=True)
    max_physical_raw_response_bytes: int = Field(default=0, ge=0, strict=True)
    model_call_claims: int = Field(default=0, ge=0, strict=True)
    model_call_failure_authorities: int = Field(default=0, ge=0, strict=True)
    model_responses: int = Field(default=0, ge=0, strict=True)
    parsed_screening_outputs: int = Field(default=0, ge=0, strict=True)
    model_parse_receipts: int = Field(default=0, ge=0, strict=True)
    model_cache_entries: int = Field(default=0, ge=0, strict=True)
    model_call_usage: int = Field(default=0, ge=0, strict=True)
    screening_results: int = Field(default=0, ge=0, strict=True)
    verdicts: int = Field(default=0, ge=0, strict=True)
    procedural_reviews: int = Field(default=0, ge=0, strict=True)
    procedural_defects: int = Field(default=0, ge=0, strict=True)
    backlog_items: int = Field(default=0, ge=0, strict=True)
    backlog_item_versions: int = Field(default=0, ge=0, strict=True)
    backlog_heads: int = Field(default=0, ge=0, strict=True)
    backlog_completion_receipts: int = Field(default=0, ge=0, strict=True)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_documents(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "documents" in payload
        claimed = payload.pop("documents", None)
        counts = handler(payload)
        if claimed_present and (
            not isinstance(claimed, int) or isinstance(claimed, bool) or claimed != counts.documents
        ):
            raise ValueError("serialized M3 document count conflicts with inventory counts")
        return counts

    @computed_field  # type: ignore[prop-decorator]
    @property
    def documents(self) -> int:
        return sum(_m3_inventory_count(self, kind) for kind in M3ArtifactInventoryKind)

    @model_validator(mode="after")
    def validate_physical_inventory_counts(self) -> Self:
        if self.physical_raw_response_files > self.physical_raw_response_entries:
            raise ValueError("physical raw-response files cannot exceed directory entries")
        if self.physical_raw_response_files == 0:
            if self.physical_raw_response_bytes or self.max_physical_raw_response_bytes:
                raise ValueError("empty physical raw-response inventory cannot carry bytes")
        elif self.max_physical_raw_response_bytes > self.physical_raw_response_bytes:
            raise ValueError("maximum physical raw-response bytes exceed total bytes")
        return self


class M3ArtifactValidationIssue(FrozenContractModel):
    code: M3ArtifactValidationIssueCode
    area: M3ArtifactValidationArea
    inventory_kind: M3ArtifactInventoryKind | None = None
    record_identity_sha256: Sha256Hex | None = None
    artifact_id: ReferenceToken | None = None
    source_token: Sha256Hex | None = None
    reason_code: ReferenceToken | None = None
    authoritative_count: int | None = Field(default=None, ge=0, strict=True)
    traversed_count: int | None = Field(default=None, ge=0, strict=True)
    limit: int | None = Field(default=None, gt=0, strict=True)
    observed: int | None = Field(default=None, ge=0, strict=True)
    expected_sha256: Sha256Hex | None = None
    actual_sha256: Sha256Hex | None = None
    expected_size_bytes: int | None = Field(default=None, ge=0, strict=True)
    actual_size_bytes: int | None = Field(default=None, ge=0, strict=True)

    @field_validator("artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M3 artifact validation artifact_id")

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        inventory_counts = (self.authoritative_count, self.traversed_count)
        if self.code == M3ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH:
            if (
                self.inventory_kind is None
                or any(value is None for value in inventory_counts)
                or self.authoritative_count == self.traversed_count
            ):
                raise ValueError(
                    "M3 inventory mismatch requires distinct authoritative and traversed counts"
                )
            if self.area != _M3_INVENTORY_AREAS[self.inventory_kind]:
                raise ValueError("M3 inventory mismatch area conflicts with its kind")
            if any(
                value is not None
                for value in (
                    self.record_identity_sha256,
                    self.artifact_id,
                    self.reason_code,
                    self.source_token,
                )
            ):
                raise ValueError("M3 inventory mismatch cannot carry record-level context")
        elif any(value is not None for value in inventory_counts):
            raise ValueError("only M3 inventory mismatches may carry inventory counts")

        if self.code in _M3_AUTHORITY_CODES:
            if (
                self.inventory_kind is None
                or self.record_identity_sha256 is None
                or self.reason_code is None
                or self.source_token is not None
            ):
                raise ValueError("M3 authority issues require a typed record identity")
            if self.area != _M3_INVENTORY_AREAS[self.inventory_kind]:
                raise ValueError("M3 authority issue area conflicts with its kind")
        elif self.code in _M3_RAW_RESPONSE_CODES:
            if (
                self.inventory_kind != M3ArtifactInventoryKind.MODEL_RESPONSE
                or self.record_identity_sha256 is None
                or self.artifact_id is None
                or self.area != M3ArtifactValidationArea.RAW_RESPONSE
                or self.source_token is not None
            ):
                raise ValueError("raw-response issues require one typed model-response record")
        elif self.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_UNREFERENCED:
            if (
                self.area != M3ArtifactValidationArea.RAW_RESPONSE
                or self.artifact_id is None
                or self.source_token is None
                or self.record_identity_sha256 is not None
                or self.inventory_kind is not None
                or self.reason_code is not None
            ):
                raise ValueError(
                    "unreferenced raw responses require an artifact ID and opaque source token"
                )
        elif self.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE:
            if (
                self.area != M3ArtifactValidationArea.RAW_RESPONSE
                or self.source_token is None
                or self.reason_code is None
                or self.record_identity_sha256 is not None
                or self.inventory_kind is not None
            ):
                raise ValueError(
                    "unsafe raw-response inventory requires an opaque source token and reason"
                )
        elif self.code not in {
            M3ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
            *_M3_BUDGET_CODES,
        }:
            raise ValueError("unsupported M3 artifact validation issue context")

        if self.code in _M3_BUDGET_CODES:
            if self.limit is None or self.observed is None or self.observed <= self.limit:
                raise ValueError("M3 budget issues require an observed value above the limit")
            if self.area != M3ArtifactValidationArea.BUDGET:
                raise ValueError("M3 budget issues require the BUDGET area")
            if any(
                value is not None
                for value in (
                    self.inventory_kind,
                    self.record_identity_sha256,
                    self.artifact_id,
                    self.reason_code,
                    self.source_token,
                )
            ):
                raise ValueError("M3 budget issues cannot carry artifact context")
        elif self.limit is not None or self.observed is not None:
            raise ValueError("only M3 budget issues may carry limit and observed values")

        if self.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_CONTENT_MISMATCH:
            if self.reason_code is not None or any(
                value is None
                for value in (
                    self.expected_sha256,
                    self.actual_sha256,
                    self.expected_size_bytes,
                    self.actual_size_bytes,
                )
            ):
                raise ValueError(
                    "raw-response mismatch requires complete expected and actual receipts"
                )
            hashes_differ = self.expected_sha256 != self.actual_sha256
            sizes_differ = self.expected_size_bytes != self.actual_size_bytes
            if not hashes_differ and not sizes_differ:
                raise ValueError("raw-response mismatch requires a distinct hash or size")
        elif self.code in {
            M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING,
            M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE,
        }:
            if self.reason_code is None:
                raise ValueError("raw-response access issues require a reason code")
        elif any(
            value is not None
            for value in (
                self.expected_sha256,
                self.actual_sha256,
                self.expected_size_bytes,
                self.actual_size_bytes,
            )
        ):
            raise ValueError("only raw-response content mismatch may carry byte receipts")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str, str, str, str]:
        context = self.model_dump(
            mode="json",
            exclude={"code", "area", "inventory_kind", "record_identity_sha256"},
            exclude_none=True,
        )
        return (
            self.area.value,
            self.code.value,
            self.inventory_kind.value if self.inventory_kind is not None else "",
            self.record_identity_sha256 or "",
            self.artifact_id or "",
            canonical_json(context),
        )


class M3ArtifactValidationReport(FrozenContractModel):
    validator_version: Literal["m3-artifacts-v1"] = M3_ARTIFACT_VALIDATOR_VERSION
    run_id: ReferenceToken
    m2_report: ArtifactValidationReport
    scope: M3ArtifactValidationScope = Field(default_factory=M3ArtifactValidationScope)
    budget: M3ArtifactValidationBudget = Field(default_factory=M3ArtifactValidationBudget)
    counts: M3ArtifactValidationCounts = Field(default_factory=M3ArtifactValidationCounts)
    issues: tuple[M3ArtifactValidationIssue, ...] = ()

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M3 artifact validation run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_passed_present = "passed" in payload
        claimed_passed = payload.pop("passed", None)
        claimed_inventory_present = "physical_raw_response_inventory_complete" in payload
        claimed_inventory = payload.pop("physical_raw_response_inventory_complete", None)
        report = handler(payload)
        if claimed_passed_present and not isinstance(claimed_passed, bool):
            raise ValueError("serialized M3 artifact validation passed must be a boolean")
        if claimed_passed_present and claimed_passed != report.passed:
            raise ValueError("serialized M3 artifact validation passed conflicts with its issues")
        if claimed_inventory_present and (
            not isinstance(claimed_inventory, bool)
            or claimed_inventory != report.physical_raw_response_inventory_complete
        ):
            raise ValueError(
                "serialized physical raw-response inventory completeness conflicts with issues"
            )
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return self.m2_report.passed and not self.issues

    @computed_field  # type: ignore[prop-decorator]
    @property
    def physical_raw_response_inventory_complete(self) -> bool:
        incomplete_codes = {
            M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING,
            M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE,
            *_M3_BUDGET_CODES,
        }
        return not any(issue.code in incomplete_codes for issue in self.issues)

    @model_validator(mode="after")
    def validate_scope_and_order(self) -> Self:
        if self.m2_report.run_id != self.run_id:
            raise ValueError("M3 artifact report and embedded M2 report run IDs differ")
        keys = tuple(issue.sort_key for issue in self.issues)
        if len(keys) != len(set(keys)):
            raise ValueError("M3 artifact validation issues must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("M3 artifact validation issues must use stable order")
        inventory_kinds: set[M3ArtifactInventoryKind] = set()
        for issue in self.issues:
            if issue.code != M3ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH:
                continue
            assert issue.inventory_kind is not None
            assert issue.authoritative_count is not None
            if issue.inventory_kind in inventory_kinds:
                raise ValueError("M3 artifact inventory mismatch kinds must be unique")
            inventory_kinds.add(issue.inventory_kind)
            if issue.authoritative_count != _m3_inventory_count(
                self.counts,
                issue.inventory_kind,
            ):
                raise ValueError("M3 inventory mismatch conflicts with report authority counts")
        return self


def _m3_inventory_count(
    counts: M3ArtifactValidationCounts,
    kind: M3ArtifactInventoryKind,
) -> int:
    field_name = {
        M3ArtifactInventoryKind.MODEL_CALL_CLAIM: "model_call_claims",
        M3ArtifactInventoryKind.MODEL_CALL_FAILURE_AUTHORITY: ("model_call_failure_authorities"),
        M3ArtifactInventoryKind.MODEL_RESPONSE: "model_responses",
        M3ArtifactInventoryKind.PARSED_SCREENING_OUTPUT: "parsed_screening_outputs",
        M3ArtifactInventoryKind.MODEL_PARSE_RECEIPT: "model_parse_receipts",
        M3ArtifactInventoryKind.MODEL_CACHE_ENTRY: "model_cache_entries",
        M3ArtifactInventoryKind.MODEL_CALL_USAGE: "model_call_usage",
        M3ArtifactInventoryKind.SCREENING_RESULT: "screening_results",
        M3ArtifactInventoryKind.VERDICT: "verdicts",
        M3ArtifactInventoryKind.PROCEDURAL_REVIEW: "procedural_reviews",
        M3ArtifactInventoryKind.PROCEDURAL_DEFECT: "procedural_defects",
        M3ArtifactInventoryKind.BACKLOG_ITEM: "backlog_items",
        M3ArtifactInventoryKind.BACKLOG_ITEM_VERSION: "backlog_item_versions",
        M3ArtifactInventoryKind.BACKLOG_HEAD: "backlog_heads",
        M3ArtifactInventoryKind.BACKLOG_COMPLETION_RECEIPT: ("backlog_completion_receipts"),
    }[kind]
    return int(getattr(counts, field_name))


def _authoritative_inventory_count(
    counts: ArtifactValidationCounts,
    kind: ArtifactInventoryKind,
) -> int:
    if kind == ArtifactInventoryKind.AUDIT_ENTRY:
        return counts.audit_entries
    if kind == ArtifactInventoryKind.EVENT:
        return counts.events
    if kind == ArtifactInventoryKind.CASE:
        return counts.cases
    if kind == ArtifactInventoryKind.PACK:
        return counts.packs
    return counts.media


__all__ = [
    "ARTIFACT_VALIDATOR_VERSION",
    "M3_ARTIFACT_VALIDATOR_VERSION",
    "ArtifactInventoryKind",
    "ArtifactValidationArea",
    "ArtifactValidationBudget",
    "ArtifactValidationCounts",
    "ArtifactValidationIssue",
    "ArtifactValidationIssueCode",
    "ArtifactValidationReport",
    "ArtifactValidationScope",
    "M3ArtifactInventoryKind",
    "M3ArtifactValidationArea",
    "M3ArtifactValidationBudget",
    "M3ArtifactValidationCounts",
    "M3ArtifactValidationIssue",
    "M3ArtifactValidationIssueCode",
    "M3ArtifactValidationReport",
    "M3ArtifactValidationScope",
    "ProjectionArtifactKind",
]
