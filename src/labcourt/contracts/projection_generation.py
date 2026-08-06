"""Content-addressed, whole-generation JSON projection release contracts."""

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

PROJECTION_GENERATION_SCHEMA: Literal["projection-generation-v1"] = "projection-generation-v1"
PROJECTION_CURRENT_SCHEMA: Literal["projection-current-v1"] = "projection-current-v1"


class ProjectionArtifactKind(StrEnum):
    EVENTS_JSONL = "EVENTS_JSONL"
    AUDIT_JSONL = "AUDIT_JSONL"
    CASE_JSON = "CASE_JSON"
    PACK_JSON = "PACK_JSON"


class ProjectionGenerationEntry(FrozenContractModel):
    """One exact canonical document in a generation closure."""

    kind: ProjectionArtifactKind
    projection_id: ReferenceToken
    relative_path: str
    sha256: Sha256Hex
    size_bytes: int = Field(ge=0, strict=True)

    @field_validator("projection_id")
    @classmethod
    def validate_projection_id(cls, value: str) -> str:
        return require_reference_token(value, "projection generation artifact reference")

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or "\\" in value
            or value.startswith("/")
            or value.endswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise ValueError("projection generation path must be canonical relative POSIX")
        return value

    @model_validator(mode="after")
    def validate_kind_path(self) -> Self:
        expected = {
            ProjectionArtifactKind.EVENTS_JSONL: "events.jsonl",
            ProjectionArtifactKind.AUDIT_JSONL: "audit.jsonl",
            ProjectionArtifactKind.CASE_JSON: f"cases/{self.projection_id}.json",
            ProjectionArtifactKind.PACK_JSON: f"packs/{self.projection_id}.json",
        }[self.kind]
        if self.relative_path != expected:
            raise ValueError("projection generation path conflicts with artifact identity")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (self.relative_path, self.kind.value, self.projection_id)


class ProjectionGenerationManifest(FrozenContractModel):
    """The complete immutable file inventory for one authority snapshot."""

    schema_version: Literal["projection-generation-v1"] = PROJECTION_GENERATION_SCHEMA
    run_id: ReferenceToken
    audit_head_sequence: int = Field(ge=-1, strict=True)
    audit_head_hash: Sha256Hex
    entries: tuple[ProjectionGenerationEntry, ...]

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "projection generation run reference")

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
        if present and (not isinstance(claimed, str) or claimed != manifest.generation_id):
            raise ValueError("serialized generation_id conflicts with manifest content")
        return manifest

    @computed_field  # type: ignore[prop-decorator]
    @property
    def generation_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "projection-generation",
                1,
                self.run_id,
                self.audit_head_sequence,
                self.audit_head_hash,
                [entry.model_dump(mode="json") for entry in self.entries],
            ]
        )

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        keys = tuple(entry.sort_key for entry in self.entries)
        if keys != tuple(sorted(keys)):
            raise ValueError("projection generation entries must use stable order")
        if len(keys) != len(set(keys)):
            raise ValueError("projection generation entries must be unique")
        by_kind = {kind: 0 for kind in ProjectionArtifactKind}
        ids: set[tuple[ProjectionArtifactKind, str]] = set()
        for entry in self.entries:
            by_kind[entry.kind] += 1
            identity = (entry.kind, entry.projection_id)
            if identity in ids:
                raise ValueError("projection generation artifact identities must be unique")
            ids.add(identity)
        if (
            by_kind[ProjectionArtifactKind.EVENTS_JSONL] != 1
            or by_kind[ProjectionArtifactKind.AUDIT_JSONL] != 1
        ):
            raise ValueError("projection generation requires one events and one audit root")
        for entry in self.entries:
            if (
                entry.kind
                in {
                    ProjectionArtifactKind.EVENTS_JSONL,
                    ProjectionArtifactKind.AUDIT_JSONL,
                }
                and entry.projection_id != self.run_id
            ):
                raise ValueError("projection root identity must match the generation run")
        return self


class ProjectionCurrentPointer(FrozenContractModel):
    """Atomically replaced pointer that makes one complete generation current."""

    schema_version: Literal["projection-current-v1"] = PROJECTION_CURRENT_SCHEMA
    run_id: ReferenceToken
    audit_head_sequence: int = Field(ge=-1, strict=True)
    audit_head_hash: Sha256Hex
    generation_id: Sha256Hex
    manifest_relative_path: str
    manifest_sha256: Sha256Hex
    manifest_size_bytes: int = Field(gt=0, strict=True)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "projection current run reference")

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
        if present and (not isinstance(claimed, str) or claimed != pointer.pointer_id):
            raise ValueError("serialized pointer_id conflicts with current pointer content")
        return pointer

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pointer_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "projection-current-pointer",
                1,
                self.run_id,
                self.audit_head_sequence,
                self.audit_head_hash,
                self.generation_id,
                self.manifest_relative_path,
                self.manifest_sha256,
                self.manifest_size_bytes,
            ]
        )

    @model_validator(mode="after")
    def validate_manifest_path(self) -> Self:
        expected = (
            f"{self.run_id}/projections/generations/{self.generation_id}/"
            f"manifest-{self.manifest_sha256}.json"
        )
        if self.manifest_relative_path != expected:
            raise ValueError("current pointer manifest path conflicts with its identities")
        return self


__all__ = [
    "PROJECTION_CURRENT_SCHEMA",
    "PROJECTION_GENERATION_SCHEMA",
    "ProjectionArtifactKind",
    "ProjectionCurrentPointer",
    "ProjectionGenerationEntry",
    "ProjectionGenerationManifest",
]
