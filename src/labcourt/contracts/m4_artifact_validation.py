"""Independent, frozen reports for read-only M4 artifact validation.

M2 and M3 validation contracts are already public and frozen.  M4 therefore
embeds the complete M3 report and adds only M4 hearing-authority and current
projection observations.  The embedded report is not used as a direct Boolean
gate because the frozen validators cannot recognize successor M4 response,
verdict, and projection authority.  M4 instead revalidates the shared roots and
translates every non-successor M2/M3 finding into an explicit M4 issue.
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

from labcourt.contracts.artifact_validation import M3ArtifactValidationReport
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.references import ReferenceToken, require_reference_token

M4_ARTIFACT_VALIDATOR_VERSION: Literal["m4-artifacts-v1"] = "m4-artifacts-v1"


class M4ArtifactValidationArea(StrEnum):
    AUTHORITY = "AUTHORITY"
    EMBEDDED_M3 = "EMBEDDED_M3"
    PROJECTION = "PROJECTION"
    BUDGET = "BUDGET"


class M4ArtifactValidationIssueCode(StrEnum):
    AUTHORITY_DOCUMENT_INVALID = "AUTHORITY_DOCUMENT_INVALID"
    AUTHORITY_INDEX_MISMATCH = "AUTHORITY_INDEX_MISMATCH"
    AUTHORITY_REFERENCE_INVALID = "AUTHORITY_REFERENCE_INVALID"
    AUTHORITY_MEDIA_INVALID = "AUTHORITY_MEDIA_INVALID"
    AUTHORITY_SCHEMA_INVALID = "AUTHORITY_SCHEMA_INVALID"
    AUTHORITY_SCHEMA_UNSUPPORTED = "AUTHORITY_SCHEMA_UNSUPPORTED"
    PROJECTION_MISSING = "PROJECTION_MISSING"
    PROJECTION_UNSAFE = "PROJECTION_UNSAFE"
    PROJECTION_CONTENT_MISMATCH = "PROJECTION_CONTENT_MISMATCH"
    PROJECTION_ROOT_MISMATCH = "PROJECTION_ROOT_MISMATCH"
    PROJECTION_INVENTORY_MISMATCH = "PROJECTION_INVENTORY_MISMATCH"
    EMBEDDED_M3_DEFECT = "EMBEDDED_M3_DEFECT"
    AUTHORITY_DOCUMENT_COUNT_BUDGET_EXCEEDED = "AUTHORITY_DOCUMENT_COUNT_BUDGET_EXCEEDED"
    AUTHORITY_DOCUMENT_BYTES_BUDGET_EXCEEDED = "AUTHORITY_DOCUMENT_BYTES_BUDGET_EXCEEDED"
    PROJECTION_FILE_COUNT_BUDGET_EXCEEDED = "PROJECTION_FILE_COUNT_BUDGET_EXCEEDED"
    PROJECTION_FILE_BYTES_BUDGET_EXCEEDED = "PROJECTION_FILE_BYTES_BUDGET_EXCEEDED"
    PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED = "PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED"


_AUTHORITY_RECORD_CODES = frozenset(
    {
        M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
        M4ArtifactValidationIssueCode.AUTHORITY_INDEX_MISMATCH,
        M4ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID,
        M4ArtifactValidationIssueCode.AUTHORITY_MEDIA_INVALID,
        M4ArtifactValidationIssueCode.AUTHORITY_SCHEMA_UNSUPPORTED,
    }
)
_PROJECTION_CODES = frozenset(
    {
        M4ArtifactValidationIssueCode.PROJECTION_MISSING,
        M4ArtifactValidationIssueCode.PROJECTION_UNSAFE,
        M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
        M4ArtifactValidationIssueCode.PROJECTION_ROOT_MISMATCH,
        M4ArtifactValidationIssueCode.PROJECTION_INVENTORY_MISMATCH,
    }
)
_BUDGET_CODES = frozenset(
    {
        M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_COUNT_BUDGET_EXCEEDED,
        M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_BYTES_BUDGET_EXCEEDED,
        M4ArtifactValidationIssueCode.PROJECTION_FILE_COUNT_BUDGET_EXCEEDED,
        M4ArtifactValidationIssueCode.PROJECTION_FILE_BYTES_BUDGET_EXCEEDED,
        M4ArtifactValidationIssueCode.PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED,
    }
)


class M4ArtifactValidationBudget(FrozenContractModel):
    max_authority_documents: int = Field(
        default=1_000_000,
        gt=0,
        le=10_000_000,
        strict=True,
    )
    max_authority_document_bytes: int = Field(
        default=16 * 1024 * 1024,
        gt=0,
        le=1024 * 1024 * 1024,
        strict=True,
    )
    max_projection_files: int = Field(
        default=1_000_000,
        gt=0,
        le=10_000_000,
        strict=True,
    )
    max_projection_file_bytes: int = Field(
        default=64 * 1024 * 1024,
        gt=0,
        le=1024 * 1024 * 1024,
        strict=True,
    )
    max_projection_total_bytes: int = Field(
        default=256 * 1024 * 1024,
        gt=0,
        le=4 * 1024 * 1024 * 1024,
        strict=True,
    )
    max_projection_name_bytes: int = Field(default=512, gt=0, le=4096, strict=True)


class M4ArtifactValidationScope(FrozenContractModel):
    authority: Literal["SQLITE_SNAPSHOT"] = "SQLITE_SNAPSHOT"
    embedded_m3_report: Literal[True] = True
    embedded_m3_gating: Literal[False] = False
    embedded_m3_defect_translation: Literal["SUCCESSOR_AWARE"] = "SUCCESSOR_AWARE"
    base_audit_chain: Literal[True] = True
    base_case_history_and_current_head: Literal[True] = True
    base_current_pack_closure: Literal[True] = True
    base_physical_media: Literal[True] = True
    canonical_hearing_documents: Literal[True] = True
    duplicated_index_columns: Literal[True] = True
    bidirectional_relational_bindings: Literal[True] = True
    current_projection_pointer: Literal[True] = True
    current_projection_manifest: Literal[True] = True
    current_projection_documents: Literal[True] = True
    current_projection_exact_inventory: Literal[True] = True
    projection_rebuild: Literal[False] = False
    authority_mutation: Literal[False] = False
    projection_mutation: Literal[False] = False


class M4ArtifactValidationInventoryCount(FrozenContractModel):
    inventory_kind: M4ProjectionArtifactKind
    authoritative_count: int = Field(ge=0, strict=True)
    projected_count: int = Field(ge=0, strict=True)

    @property
    def sort_key(self) -> str:
        return self.inventory_kind.value


class M4ArtifactValidationCounts(FrozenContractModel):
    embedded_m3_issues: int = Field(default=0, ge=0, strict=True)
    embedded_m3_superseded_issues: int = Field(default=0, ge=0, strict=True)
    embedded_m3_gating_issues: int = Field(default=0, ge=0, strict=True)
    authority_rows: int = Field(default=0, ge=0, strict=True)
    validated_authority_documents: int = Field(default=0, ge=0, strict=True)
    authority_failures: int = Field(default=0, ge=0, strict=True)
    hearing_roots: int = Field(default=0, ge=0, strict=True)
    max_authority_document_bytes: int = Field(default=0, ge=0, strict=True)
    validated_media: int = Field(default=0, ge=0, strict=True)
    media_failures: int = Field(default=0, ge=0, strict=True)
    projection_files: int = Field(default=0, ge=0, strict=True)
    projection_documents: int = Field(default=0, ge=0, strict=True)
    projection_bytes: int = Field(default=0, ge=0, strict=True)
    max_projection_file_bytes: int = Field(default=0, ge=0, strict=True)
    inventories: tuple[M4ArtifactValidationInventoryCount, ...] = ()

    @model_validator(mode="after")
    def validate_derived_counts_and_inventory(self) -> Self:
        if self.embedded_m3_issues != (
            self.embedded_m3_superseded_issues + self.embedded_m3_gating_issues
        ):
            raise ValueError("M4 embedded M3 issue accounting is incomplete")
        if self.media_failures > self.validated_media:
            raise ValueError("M4 media failures exceed validated media")
        keys = tuple(item.sort_key for item in self.inventories)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M4 artifact inventory counts must be unique and stably ordered")
        if self.validated_authority_documents != sum(
            item.authoritative_count for item in self.inventories
        ):
            raise ValueError("M4 validated document count conflicts with inventory counts")
        if self.projection_documents != sum(item.projected_count for item in self.inventories):
            raise ValueError("M4 projected document count conflicts with inventory counts")
        if self.projection_files == 0:
            if self.projection_bytes or self.max_projection_file_bytes:
                raise ValueError("empty M4 projection inventory cannot carry byte counts")
        elif self.max_projection_file_bytes > self.projection_bytes:
            raise ValueError("maximum M4 projection file size exceeds total projection bytes")
        return self


class M4ArtifactValidationIssue(FrozenContractModel):
    code: M4ArtifactValidationIssueCode
    area: M4ArtifactValidationArea
    inventory_kind: M4ProjectionArtifactKind | None = None
    record_identity_sha256: Sha256Hex | None = None
    artifact_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=214,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,213}$",
    )
    source_token: Sha256Hex | None = None
    reason_code: ReferenceToken | None = None
    authoritative_count: int | None = Field(default=None, ge=0, strict=True)
    projected_count: int | None = Field(default=None, ge=0, strict=True)
    limit: int | None = Field(default=None, gt=0, strict=True)
    observed: int | None = Field(default=None, ge=0, strict=True)
    expected_sha256: Sha256Hex | None = None
    actual_sha256: Sha256Hex | None = None
    expected_size_bytes: int | None = Field(default=None, ge=0, strict=True)
    actual_size_bytes: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="after")
    def validate_typed_context(self) -> Self:
        if self.code in _AUTHORITY_RECORD_CODES:
            if (
                self.area != M4ArtifactValidationArea.AUTHORITY
                or self.inventory_kind is None
                or self.record_identity_sha256 is None
                or self.reason_code is None
                or self.source_token is not None
            ):
                raise ValueError("M4 authority issues require one typed record identity")
        elif self.code == M4ArtifactValidationIssueCode.AUTHORITY_SCHEMA_INVALID:
            if (
                self.area != M4ArtifactValidationArea.AUTHORITY
                or self.reason_code is None
                or any(
                    value is not None
                    for value in (
                        self.inventory_kind,
                        self.record_identity_sha256,
                        self.artifact_id,
                        self.source_token,
                    )
                )
            ):
                raise ValueError("M4 schema issues require only a typed reason")
        elif self.code == M4ArtifactValidationIssueCode.EMBEDDED_M3_DEFECT:
            if (
                self.area != M4ArtifactValidationArea.EMBEDDED_M3
                or self.source_token is None
                or self.reason_code is None
                or any(
                    value is not None
                    for value in (
                        self.inventory_kind,
                        self.record_identity_sha256,
                        self.artifact_id,
                    )
                )
            ):
                raise ValueError("embedded M3 defects require an opaque source and reason")
        elif self.code in _PROJECTION_CODES:
            if (
                self.area != M4ArtifactValidationArea.PROJECTION
                or self.source_token is None
                or self.reason_code is None
                or self.record_identity_sha256 is not None
            ):
                raise ValueError("M4 projection issues require an opaque source and reason")
        elif self.code not in _BUDGET_CODES:
            raise ValueError("unsupported M4 artifact validation issue context")

        inventory_counts = (self.authoritative_count, self.projected_count)
        if any(value is not None for value in inventory_counts) and (
            self.code != M4ArtifactValidationIssueCode.PROJECTION_INVENTORY_MISMATCH
            or any(value is None for value in inventory_counts)
        ):
            raise ValueError("only projection inventory issues carry paired counts")

        if self.code in _BUDGET_CODES:
            if (
                self.area != M4ArtifactValidationArea.BUDGET
                or self.limit is None
                or self.observed is None
                or self.observed <= self.limit
            ):
                raise ValueError("M4 budget issues require an observed value above the limit")
            if any(
                value is not None
                for value in (
                    self.inventory_kind,
                    self.record_identity_sha256,
                    self.artifact_id,
                    self.source_token,
                    self.reason_code,
                )
            ):
                raise ValueError("M4 budget issues cannot carry artifact context")
        elif self.limit is not None or self.observed is not None:
            raise ValueError("only M4 budget issues may carry limits")

        byte_receipt = (
            self.expected_sha256,
            self.actual_sha256,
            self.expected_size_bytes,
            self.actual_size_bytes,
        )
        if any(value is not None for value in byte_receipt):
            if self.code not in {
                M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                M4ArtifactValidationIssueCode.PROJECTION_ROOT_MISMATCH,
            } or any(value is None for value in byte_receipt[:2]):
                raise ValueError("M4 byte receipts require a projection content/root mismatch")
            if self.expected_sha256 == self.actual_sha256 and (
                self.expected_size_bytes is None
                or self.actual_size_bytes is None
                or self.expected_size_bytes == self.actual_size_bytes
            ):
                raise ValueError("M4 byte receipts must describe a real mismatch")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str, str, str, str]:
        context = self.model_dump(
            mode="json",
            exclude={"area", "code", "inventory_kind", "record_identity_sha256"},
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


class M4ArtifactValidationReport(FrozenContractModel):
    validator_version: Literal["m4-artifacts-v1"] = M4_ARTIFACT_VALIDATOR_VERSION
    run_id: ReferenceToken
    m3_report: M3ArtifactValidationReport
    authority_root_sha256: Sha256Hex | None = None
    scope: M4ArtifactValidationScope = Field(default_factory=M4ArtifactValidationScope)
    budget: M4ArtifactValidationBudget = Field(default_factory=M4ArtifactValidationBudget)
    counts: M4ArtifactValidationCounts = Field(default_factory=M4ArtifactValidationCounts)
    issues: tuple[M4ArtifactValidationIssue, ...] = ()

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M4 artifact validation run_id")

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
        present = "passed" in payload
        claimed = payload.pop("passed", None)
        report = handler(payload)
        if present and (not isinstance(claimed, bool) or claimed != report.passed):
            raise ValueError("serialized M4 artifact validation passed conflicts with issues")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return not self.issues

    @model_validator(mode="after")
    def validate_scope_and_order(self) -> Self:
        if self.m3_report.run_id != self.run_id:
            raise ValueError("M4 and embedded M3 artifact report run IDs differ")
        embedded_count = len(self.m3_report.m2_report.issues) + len(self.m3_report.issues)
        if self.counts.embedded_m3_issues != embedded_count:
            raise ValueError("M4 report did not account for every embedded M3 issue")
        translated_count = sum(
            issue.code == M4ArtifactValidationIssueCode.EMBEDDED_M3_DEFECT for issue in self.issues
        )
        if self.counts.embedded_m3_gating_issues != translated_count:
            raise ValueError("M4 report embedded M3 gating count conflicts with issues")
        keys = tuple(issue.sort_key for issue in self.issues)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M4 artifact validation issues must be unique and stably ordered")
        if self.passed and self.authority_root_sha256 is None:
            raise ValueError("passing M4 artifact validation requires an authority root")
        return self


__all__ = [
    "M4_ARTIFACT_VALIDATOR_VERSION",
    "M4ArtifactValidationArea",
    "M4ArtifactValidationBudget",
    "M4ArtifactValidationCounts",
    "M4ArtifactValidationInventoryCount",
    "M4ArtifactValidationIssue",
    "M4ArtifactValidationIssueCode",
    "M4ArtifactValidationReport",
    "M4ArtifactValidationScope",
]
