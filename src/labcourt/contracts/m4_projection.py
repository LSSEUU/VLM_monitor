"""Independent content-addressed projection contracts for M4 authority.

M2's projection wire format is frozen.  M4 therefore owns a separate
generation and current-pointer contract instead of widening the earlier
artifact-kind enum.  A generation is only a rebuildable view of one validated
SQLite snapshot; it never becomes business authority.
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
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token


class M4ProjectionArtifactKind(StrEnum):
    """Every canonical document needed to reconstruct an M4 hearing graph."""

    HEARING_SESSION = "HEARING_SESSION"
    HEARING_CYCLE = "HEARING_CYCLE"
    HEARING_CHECKPOINT = "HEARING_CHECKPOINT"
    PRECEDENT_RETRIEVAL = "PRECEDENT_RETRIEVAL"
    MODEL_REQUEST = "MODEL_REQUEST"
    MODEL_RESPONSE = "MODEL_RESPONSE"
    MODEL_PARSE_RECEIPT = "MODEL_PARSE_RECEIPT"
    ROLE_OUTPUT = "ROLE_OUTPUT"
    MODEL_CACHE_ENTRY = "MODEL_CACHE_ENTRY"
    USAGE_RECEIPT = "USAGE_RECEIPT"
    ACQUISITION_REQUEST = "ACQUISITION_REQUEST"
    ACQUISITION_EXECUTION_CLAIM = "ACQUISITION_EXECUTION_CLAIM"
    ACQUISITION_EXECUTION_PUBLICATION = "ACQUISITION_EXECUTION_PUBLICATION"
    HEARING_ROUND = "HEARING_ROUND"
    HEARING_RECORD = "HEARING_RECORD"
    TOOL_EXECUTION_MANIFEST = "TOOL_EXECUTION_MANIFEST"
    ACQUIRED_CROP = "ACQUIRED_CROP"
    TOOL_EXECUTION_RECEIPT = "TOOL_EXECUTION_RECEIPT"
    EVIDENCE_PACK_DERIVATION = "EVIDENCE_PACK_DERIVATION"
    VERDICT_BINDING = "VERDICT_BINDING"
    REWORK_RECEIPT = "REWORK_RECEIPT"
    HEARING_BACKLOG_COMPLETION = "HEARING_BACKLOG_COMPLETION"
    MODEL_CALL_FAILURE_AUTHORITY = "MODEL_CALL_FAILURE_AUTHORITY"
    STRICT_PARSE_FAILURE_ATTEMPT = "STRICT_PARSE_FAILURE_ATTEMPT"
    STRICT_PARSE_FAILURE_PROOF = "STRICT_PARSE_FAILURE_PROOF"
    BACKLOG_RETRY_OUTCOME = "BACKLOG_RETRY_OUTCOME"
    HUMAN_REVIEW_RECEIPT = "HUMAN_REVIEW_RECEIPT"
    CASE_VERSION = "CASE_VERSION"
    EVIDENCE_PACK = "EVIDENCE_PACK"
    SCREENING_RESULT = "SCREENING_RESULT"
    VERDICT = "VERDICT"
    PROCEDURAL_REVIEW = "PROCEDURAL_REVIEW"
    BACKLOG_ITEM = "BACKLOG_ITEM"
    BACKLOG_ITEM_VERSION = "BACKLOG_ITEM_VERSION"
    FRAME = "FRAME"
    DETECTION = "DETECTION"
    AUDIT_ENTRY = "AUDIT_ENTRY"


_DIRECTORY_BY_KIND: dict[M4ProjectionArtifactKind, str] = {
    kind: kind.value.lower().replace("_", "-") for kind in M4ProjectionArtifactKind
}


def m4_projection_relative_path(
    kind: M4ProjectionArtifactKind,
    artifact_id: str,
) -> str:
    """Map a logical ID (including colon-shaped Frame IDs) to a portable path."""

    component = sha256_hex(["m4-projection-path", 1, kind.value, artifact_id])
    return f"documents/{_DIRECTORY_BY_KIND[kind]}/{component}.json"


class M4ProjectionGenerationEntry(FrozenContractModel):
    """One exact canonical document in an immutable M4 generation."""

    kind: M4ProjectionArtifactKind
    artifact_id: str = Field(
        min_length=1,
        max_length=214,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,213}$",
    )
    relative_path: str
    sha256: Sha256Hex
    size_bytes: int = Field(ge=0, strict=True)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if (
            not value
            or "\\" in value
            or value.startswith("/")
            or value.endswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise ValueError("M4 projection path must be canonical relative POSIX")
        return value

    @model_validator(mode="after")
    def validate_kind_path(self) -> Self:
        expected = m4_projection_relative_path(self.kind, self.artifact_id)
        if self.relative_path != expected:
            raise ValueError("M4 projection path conflicts with artifact identity")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (self.relative_path, self.kind.value, self.artifact_id)


class M4ProjectionGenerationManifest(FrozenContractModel):
    """Complete file inventory for one validated M4 SQLite authority root."""

    schema_version: Literal["m4-projection-generation-v1"] = "m4-projection-generation-v1"
    run_id: ReferenceToken
    authority_root_sha256: Sha256Hex
    entries: tuple[M4ProjectionGenerationEntry, ...]

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M4 projection run reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_generation_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "generation_id" in payload
        claimed = payload.pop("generation_id", None)
        manifest = handler(payload)
        if present and claimed != manifest.generation_id:
            raise ValueError("serialized M4 generation ID conflicts with manifest")
        return manifest

    @computed_field  # type: ignore[prop-decorator]
    @property
    def generation_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m4-projection-generation",
                1,
                self.run_id,
                self.authority_root_sha256,
                [entry.model_dump(mode="json") for entry in self.entries],
            ]
        )

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        keys = tuple(entry.sort_key for entry in self.entries)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M4 projection entries must be unique and stably ordered")
        identities = tuple((entry.kind, entry.artifact_id) for entry in self.entries)
        if len(identities) != len(set(identities)):
            raise ValueError("M4 projection artifact identities must be unique")
        return self


class M4ProjectionCurrentPointer(FrozenContractModel):
    """Atomically selected complete M4 projection generation."""

    schema_version: Literal["m4-projection-current-v1"] = "m4-projection-current-v1"
    run_id: ReferenceToken
    authority_root_sha256: Sha256Hex
    generation_id: Sha256Hex
    manifest_relative_path: str
    manifest_sha256: Sha256Hex
    manifest_size_bytes: int = Field(gt=0, strict=True)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M4 projection current run reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_pointer_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "pointer_id" in payload
        claimed = payload.pop("pointer_id", None)
        pointer = handler(payload)
        if present and claimed != pointer.pointer_id:
            raise ValueError("serialized M4 projection pointer ID conflicts with content")
        return pointer

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pointer_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m4-projection-current",
                1,
                self.run_id,
                self.authority_root_sha256,
                self.generation_id,
                self.manifest_relative_path,
                self.manifest_sha256,
                self.manifest_size_bytes,
            ]
        )

    @model_validator(mode="after")
    def validate_manifest_path(self) -> Self:
        expected = (
            f"{self.run_id}/m4-projections/generations/{self.generation_id}/"
            f"manifest-{self.manifest_sha256}.json"
        )
        if self.manifest_relative_path != expected:
            raise ValueError("M4 current pointer manifest path conflicts with identities")
        return self


__all__ = [
    "M4ProjectionArtifactKind",
    "M4ProjectionCurrentPointer",
    "M4ProjectionGenerationEntry",
    "M4ProjectionGenerationManifest",
    "m4_projection_relative_path",
]
