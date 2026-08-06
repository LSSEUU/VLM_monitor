"""Privacy-safe presentation authority for the offline M6 static report."""

from __future__ import annotations

import unicodedata
from enum import StrEnum
from itertools import pairwise
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m6_regression import MAX_M6_REGRESSION_CASES
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import ReferenceToken, require_reference_token


class M6StaticReportEvidenceDisposition(StrEnum):
    PRIVACY_PROCESSED_AVAILABLE = "PRIVACY_PROCESSED_AVAILABLE"
    RETENTION_PURGED = "RETENTION_PURGED"
    NOT_PUBLISHED = "NOT_PUBLISHED"


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
            raise ValueError("serialized claim conflicts with derived M6 static report")


class M6StaticReportEvidenceItem(FrozenContractModel):
    sample_id: ReferenceToken
    disposition: M6StaticReportEvidenceDisposition
    artifact_relative_path: str | None = Field(default=None, min_length=1, max_length=1024)
    artifact_content_sha256: Sha256Hex | None = None
    deletion_audit_id: ReferenceToken | None = None
    retention_reason_code: ReferenceToken | None = None

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 static report sample_id")

    @field_validator("deletion_audit_id")
    @classmethod
    def validate_deletion_audit_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M6 static report deletion audit_id")

    @field_validator("retention_reason_code")
    @classmethod
    def validate_retention_reason_code(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M6 static report retention reason_code")

    @field_validator("artifact_relative_path")
    @classmethod
    def validate_artifact_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            controlled = require_safe_relative_posix_path(value)
        except (TypeError, ValueError):
            raise ValueError("M6 static evidence path must be a controlled relative path") from None
        if any(
            ord(character) == 0x7F
            or 0x80 <= ord(character) <= 0x9F
            or 0xD800 <= ord(character) <= 0xDFFF
            for character in controlled
        ):
            raise ValueError("M6 static evidence path must be portable")
        path = PurePosixPath(controlled)
        if (
            path.as_posix() != controlled
            or len(path.parts) < 2
            or path.parts[0] != "privacy-media"
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.suffix not in {".png", ".webp", ".avif"}
        ):
            raise ValueError("M6 static evidence must use a privacy-media raster path")
        if len(controlled.encode("utf-8")) > 1024 or any(
            len(part.encode("utf-8")) > 255 for part in path.parts
        ):
            raise ValueError("M6 static evidence path exceeds the portable byte budget")
        return controlled

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("evidence_item_id",))
        item = handler(payload)
        _verify_claims(item, claims)
        return item

    @model_validator(mode="after")
    def validate_disjoint_privacy_state(self) -> Self:
        artifact = (
            self.artifact_relative_path is not None and self.artifact_content_sha256 is not None
        )
        deletion = self.deletion_audit_id is not None and self.retention_reason_code is not None
        if self.disposition == M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE:
            if (
                not artifact
                or self.deletion_audit_id is not None
                or self.retention_reason_code is not None
            ):
                raise ValueError("available M6 static evidence requires only artifact fields")
        elif self.disposition == M6StaticReportEvidenceDisposition.RETENTION_PURGED:
            if (
                not deletion
                or self.artifact_relative_path is not None
                or self.artifact_content_sha256 is not None
            ):
                raise ValueError("purged M6 static evidence requires only deletion fields")
        elif any(
            value is not None
            for value in (
                self.artifact_relative_path,
                self.artifact_content_sha256,
                self.deletion_audit_id,
                self.retention_reason_code,
            )
        ):
            raise ValueError("unpublished M6 static evidence cannot carry artifact fields")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_item_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-static-report-evidence-item",
                1,
                self.sample_id,
                self.disposition,
                self.artifact_relative_path,
                self.artifact_content_sha256,
                self.deletion_audit_id,
                self.retention_reason_code,
            ]
        )


class M6PrivacySafeStaticReportManifestAuthorityV1(FrozenContractModel):
    schema_version: Literal["m6-privacy-safe-static-report-manifest-authority-v1"] = (
        "m6-privacy-safe-static-report-manifest-authority-v1"
    )
    report_id: Sha256Hex
    publication_seal_id: Sha256Hex
    candidate_run_id: ReferenceToken
    classification: Literal["SYNTHETIC_PRECOMPUTED_FAKE"] = "SYNTHETIC_PRECOMPUTED_FAKE"
    raw_media_included: Literal[False] = False
    hidden_reasoning_included: Literal[False] = False
    external_resources_included: Literal[False] = False
    evidence_items: tuple[M6StaticReportEvidenceItem, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 static report candidate run_id")

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
                "evidence_item_count",
                "evidence_inventory_root_sha256",
                "manifest_id",
            ),
        )
        manifest = handler(payload)
        _verify_claims(manifest, claims)
        return manifest

    @model_validator(mode="after")
    def validate_canonical_evidence_inventory(self) -> Self:
        canonical = tuple(
            M6StaticReportEvidenceItem.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.evidence_items
        )
        sample_ids = tuple(item.sample_id for item in canonical)
        if len(set(sample_ids)) != len(sample_ids):
            raise ValueError("M6 static evidence inventory requires exact unique samples")
        if canonical != self.evidence_items or sample_ids != tuple(sorted(sample_ids)):
            raise ValueError("M6 static evidence inventory must be canonical and ordered")
        normalized_paths = tuple(
            tuple(
                unicodedata.normalize("NFKC", part).casefold()
                for part in item.artifact_relative_path.split("/")
            )
            for item in canonical
            if item.artifact_relative_path is not None
        )
        ordered_paths = tuple(sorted(normalized_paths))
        for left, right in pairwise(ordered_paths):
            if left == right:
                raise ValueError("M6 static evidence paths must be portable and unique")
            if len(left) <= len(right) and right[: len(left)] == left:
                raise ValueError("M6 static evidence paths must be prefix-free")
        object.__setattr__(self, "evidence_items", canonical)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_item_count(self) -> int:
        return len(self.evidence_items)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-static-report-evidence-inventory",
                1,
                [item.evidence_item_id for item in self.evidence_items],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def manifest_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-privacy-safe-static-report-manifest",
                1,
                self.report_id,
                self.publication_seal_id,
                self.candidate_run_id,
                self.classification,
                self.raw_media_included,
                self.hidden_reasoning_included,
                self.external_resources_included,
                self.evidence_inventory_root_sha256,
            ]
        )


__all__ = [
    "M6PrivacySafeStaticReportManifestAuthorityV1",
    "M6StaticReportEvidenceDisposition",
    "M6StaticReportEvidenceItem",
]
