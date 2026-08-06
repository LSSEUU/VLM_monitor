"""Content-addressed, rebuildable M5 JSONL projection contracts.

SQLite remains the only M5 business authority.  These contracts describe a
complete immutable generation selected by one atomically replaced pointer.
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


class M5AuthorityKind(StrEnum):
    PRECEDENT_EMBEDDING = "PRECEDENT_EMBEDDING"
    PRECEDENT = "PRECEDENT"
    PRECEDENT_EXPOSURE = "PRECEDENT_EXPOSURE"
    PRECEDENT_APPLICATION_BATCH = "PRECEDENT_APPLICATION_BATCH"
    PRECEDENT_CAUSAL_EVENT = "PRECEDENT_CAUSAL_EVENT"
    PRECEDENT_CITATION = "PRECEDENT_CITATION"
    PRECEDENT_CONFLICT_BATCH = "PRECEDENT_CONFLICT_BATCH"
    PRECEDENT_CONFLICT_BATCH_RECEIPT = "PRECEDENT_CONFLICT_BATCH_RECEIPT"
    PRECEDENT_LIFECYCLE = "PRECEDENT_LIFECYCLE"
    ALERT = "ALERT"
    ALERT_COOLDOWN = "ALERT_COOLDOWN"
    ALERT_OUTBOX = "ALERT_OUTBOX"
    ALERT_CHANNEL_CAPABILITY = "ALERT_CHANNEL_CAPABILITY"
    ALERT_DISPATCH_ATTEMPT = "ALERT_DISPATCH_ATTEMPT"
    ALERT_DISPATCH_RECEIPT = "ALERT_DISPATCH_RECEIPT"
    IMMEDIATE_SAFETY_DELIVERY = "IMMEDIATE_SAFETY_DELIVERY"
    APPEAL = "APPEAL"
    APPEAL_RESOLUTION = "APPEAL_RESOLUTION"
    APPEAL_RESOLUTION_COMMIT = "APPEAL_RESOLUTION_COMMIT"
    VERDICT_RESCISSION = "VERDICT_RESCISSION"
    ALERT_RESCISSION = "ALERT_RESCISSION"
    TRAINING_LABEL = "TRAINING_LABEL"
    STRONG_TRAINING_LABEL_PROVENANCE = "STRONG_TRAINING_LABEL_PROVENANCE"
    TRAINING_CAUSAL_EVENT = "TRAINING_CAUSAL_EVENT"
    DATASET_ARTIFACT = "DATASET_ARTIFACT"
    DATASET_REGISTRATION_SNAPSHOT = "DATASET_REGISTRATION_SNAPSHOT"
    DATASET_CROP_SNAPSHOT = "DATASET_CROP_SNAPSHOT"


class M5ProjectionFileKind(StrEnum):
    ALERTS = "ALERTS"
    PRECEDENTS = "PRECEDENTS"
    APPEALS = "APPEALS"
    TRAIN_BUFFER = "TRAIN_BUFFER"


_FILE_NAME = {
    M5ProjectionFileKind.ALERTS: "alerts.jsonl",
    M5ProjectionFileKind.PRECEDENTS: "precedents.jsonl",
    M5ProjectionFileKind.APPEALS: "appeals.jsonl",
    M5ProjectionFileKind.TRAIN_BUFFER: "train_buffer.jsonl",
}

_KINDS_BY_FILE: dict[M5ProjectionFileKind, tuple[M5AuthorityKind, ...]] = {
    M5ProjectionFileKind.ALERTS: tuple(
        sorted(
            (
                M5AuthorityKind.ALERT,
                M5AuthorityKind.ALERT_CHANNEL_CAPABILITY,
                M5AuthorityKind.ALERT_COOLDOWN,
                M5AuthorityKind.ALERT_DISPATCH_ATTEMPT,
                M5AuthorityKind.ALERT_DISPATCH_RECEIPT,
                M5AuthorityKind.ALERT_OUTBOX,
                M5AuthorityKind.IMMEDIATE_SAFETY_DELIVERY,
            ),
            key=lambda item: item.value,
        )
    ),
    M5ProjectionFileKind.PRECEDENTS: tuple(
        sorted(
            (
                M5AuthorityKind.PRECEDENT,
                M5AuthorityKind.PRECEDENT_APPLICATION_BATCH,
                M5AuthorityKind.PRECEDENT_CAUSAL_EVENT,
                M5AuthorityKind.PRECEDENT_CITATION,
                M5AuthorityKind.PRECEDENT_CONFLICT_BATCH,
                M5AuthorityKind.PRECEDENT_CONFLICT_BATCH_RECEIPT,
                M5AuthorityKind.PRECEDENT_EMBEDDING,
                M5AuthorityKind.PRECEDENT_EXPOSURE,
                M5AuthorityKind.PRECEDENT_LIFECYCLE,
            ),
            key=lambda item: item.value,
        )
    ),
    M5ProjectionFileKind.APPEALS: tuple(
        sorted(
            (
                M5AuthorityKind.ALERT_RESCISSION,
                M5AuthorityKind.APPEAL,
                M5AuthorityKind.APPEAL_RESOLUTION,
                M5AuthorityKind.APPEAL_RESOLUTION_COMMIT,
                M5AuthorityKind.VERDICT_RESCISSION,
            ),
            key=lambda item: item.value,
        )
    ),
    M5ProjectionFileKind.TRAIN_BUFFER: tuple(
        sorted(
            (
                M5AuthorityKind.DATASET_ARTIFACT,
                M5AuthorityKind.DATASET_CROP_SNAPSHOT,
                M5AuthorityKind.DATASET_REGISTRATION_SNAPSHOT,
                M5AuthorityKind.STRONG_TRAINING_LABEL_PROVENANCE,
                M5AuthorityKind.TRAINING_CAUSAL_EVENT,
                M5AuthorityKind.TRAINING_LABEL,
            ),
            key=lambda item: item.value,
        )
    ),
}


def m5_projection_relative_path(kind: M5ProjectionFileKind) -> str:
    return _FILE_NAME[kind]


def m5_projection_authority_kinds(
    kind: M5ProjectionFileKind,
) -> tuple[M5AuthorityKind, ...]:
    return _KINDS_BY_FILE[kind]


class M5ProjectionRecordReceipt(FrozenContractModel):
    authority_kind: M5AuthorityKind
    artifact_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$",
    )
    sha256: Sha256Hex

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.authority_kind.value, self.artifact_id)


class M5ProjectionGenerationEntry(FrozenContractModel):
    file_kind: M5ProjectionFileKind
    relative_path: str
    sha256: Sha256Hex
    size_bytes: int = Field(ge=0, strict=True)
    record_count: int = Field(ge=0, strict=True)
    authority_kinds: tuple[M5AuthorityKind, ...]
    records: tuple[M5ProjectionRecordReceipt, ...] = ()

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if (
            not value
            or "\\" in value
            or value.startswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise ValueError("M5 projection path must be canonical relative POSIX")
        return value

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        if self.relative_path != m5_projection_relative_path(self.file_kind):
            raise ValueError("M5 projection path conflicts with file kind")
        if self.authority_kinds != m5_projection_authority_kinds(self.file_kind):
            raise ValueError("M5 projection authority kinds conflict with file kind")
        keys = tuple(item.sort_key for item in self.records)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M5 projection records must be unique and ordered")
        if self.record_count != len(self.records):
            raise ValueError("M5 projection record count conflicts with receipts")
        if any(item.authority_kind not in self.authority_kinds for item in self.records):
            raise ValueError("M5 projection record is assigned to the wrong file")
        return self

    @property
    def sort_key(self) -> str:
        return self.relative_path


class M5ProjectionGenerationManifest(FrozenContractModel):
    schema_version: Literal["m5-projection-generation-v1"] = "m5-projection-generation-v1"
    run_id: ReferenceToken
    authority_root_sha256: Sha256Hex
    authority_record_count: int = Field(ge=0, strict=True)
    case_root_count: int = Field(ge=0, strict=True)
    entries: tuple[M5ProjectionGenerationEntry, ...]

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M5 projection run reference")

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
            raise ValueError("serialized M5 generation ID conflicts with manifest")
        return manifest

    @computed_field  # type: ignore[prop-decorator]
    @property
    def generation_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-projection-generation",
                1,
                self.run_id,
                self.authority_root_sha256,
                self.authority_record_count,
                self.case_root_count,
                [entry.model_dump(mode="json") for entry in self.entries],
            ]
        )

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        expected = tuple(sorted(M5ProjectionFileKind, key=lambda item: _FILE_NAME[item]))
        observed = tuple(entry.file_kind for entry in self.entries)
        if observed != expected:
            raise ValueError("M5 projection generation must contain the complete ordered inventory")
        flattened = tuple(kind for entry in self.entries for kind in entry.authority_kinds)
        if set(flattened) != set(M5AuthorityKind) or len(flattened) != len(set(flattened)):
            raise ValueError("M5 projection files must partition every authority kind exactly once")
        if self.authority_record_count != sum(entry.record_count for entry in self.entries):
            raise ValueError("M5 projection record count conflicts with entries")
        return self


class M5ProjectionCurrentPointer(FrozenContractModel):
    schema_version: Literal["m5-projection-current-v1"] = "m5-projection-current-v1"
    run_id: ReferenceToken
    authority_root_sha256: Sha256Hex
    generation_id: Sha256Hex
    manifest_relative_path: str
    manifest_sha256: Sha256Hex
    manifest_size_bytes: int = Field(gt=0, strict=True)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M5 current projection run reference")

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
            raise ValueError("serialized M5 pointer ID conflicts with content")
        return pointer

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pointer_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-projection-current",
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
            f"{self.run_id}/m5-projections/generations/{self.generation_id}/"
            f"manifest-{self.manifest_sha256}.json"
        )
        if self.manifest_relative_path != expected:
            raise ValueError("M5 current pointer manifest path conflicts with identities")
        return self


__all__ = [
    "M5AuthorityKind",
    "M5ProjectionCurrentPointer",
    "M5ProjectionFileKind",
    "M5ProjectionGenerationEntry",
    "M5ProjectionGenerationManifest",
    "M5ProjectionRecordReceipt",
    "m5_projection_authority_kinds",
    "m5_projection_relative_path",
]
