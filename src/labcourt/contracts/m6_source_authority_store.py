"""Immutable commit manifest for one sealed M6 replay source bundle."""

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
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M6_SOURCE_AUTHORITY_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_SOURCE_AUTHORITY_BUNDLE_BYTES = 256 * 1024 * 1024


class M6SourceAuthorityDocumentKind(StrEnum):
    REPLAY_INPUT_CLOSURE = "REPLAY_INPUT_CLOSURE"
    REPLAY_INPUT_AUTHORITY = "REPLAY_INPUT_AUTHORITY"
    SOURCE_VALIDATION_REPORT = "SOURCE_VALIDATION_REPORT"
    SOURCE_CASE = "SOURCE_CASE"
    SOURCE_MANIFEST = "SOURCE_MANIFEST"


_KIND_RANK = {kind: index for index, kind in enumerate(M6SourceAuthorityDocumentKind)}
_KIND_DIRECTORY = {
    M6SourceAuthorityDocumentKind.REPLAY_INPUT_CLOSURE: "replay-input-closures",
    M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY: "replay-input-authorities",
    M6SourceAuthorityDocumentKind.SOURCE_VALIDATION_REPORT: "source-validation-reports",
    M6SourceAuthorityDocumentKind.SOURCE_CASE: "source-cases",
    M6SourceAuthorityDocumentKind.SOURCE_MANIFEST: "source-manifests",
}


def m6_source_authority_document_relative_path(
    kind: M6SourceAuthorityDocumentKind,
    content_sha256: str,
) -> str:
    if not isinstance(kind, M6SourceAuthorityDocumentKind):
        raise TypeError("kind must be an M6SourceAuthorityDocumentKind")
    if (
        not isinstance(content_sha256, str)
        or len(content_sha256) != 64
        or any(character not in "0123456789abcdef" for character in content_sha256)
    ):
        raise ValueError("content_sha256 must be a lowercase SHA-256")
    return f"documents/{_KIND_DIRECTORY[kind]}/{content_sha256}.json"


def m6_source_authority_seal_relative_path(closure_authority_id: str) -> str:
    if (
        not isinstance(closure_authority_id, str)
        or len(closure_authority_id) != 64
        or any(character not in "0123456789abcdef" for character in closure_authority_id)
    ):
        raise ValueError("closure_authority_id must be a lowercase SHA-256")
    return f"seals/{closure_authority_id}/seal.json"


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
            raise ValueError(f"serialized {name} conflicts with derived M6 source seal")


class M6SourceAuthorityDocumentEntry(FrozenContractModel):
    kind: M6SourceAuthorityDocumentKind
    artifact_id: ReferenceToken
    declared_document_sha256: Sha256Hex
    content_sha256: Sha256Hex
    size_bytes: int = Field(
        gt=0,
        le=MAX_M6_SOURCE_AUTHORITY_DOCUMENT_BYTES,
        strict=True,
    )

    @field_validator("artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 source authority document artifact_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("relative_path", "entry_id"))
        entry = handler(payload)
        _verify_claims(entry, claims)
        return entry

    @computed_field  # type: ignore[prop-decorator]
    @property
    def relative_path(self) -> str:
        return m6_source_authority_document_relative_path(self.kind, self.content_sha256)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def entry_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-source-authority-document-entry",
                1,
                self.kind,
                self.artifact_id,
                self.declared_document_sha256,
                self.content_sha256,
                self.size_bytes,
                self.relative_path,
            ]
        )

    @property
    def sort_key(self) -> tuple[int, str]:
        return _KIND_RANK[self.kind], self.artifact_id


class M6SourceAuthoritySeal(FrozenContractModel):
    """The final immutable commit root for five exact source documents."""

    schema_version: Literal["m6-source-authority-seal-v1"] = "m6-source-authority-seal-v1"
    sample_id: ReferenceToken
    source_run_id: ReferenceToken
    source_case_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    source_case_document_sha256: Sha256Hex
    source_manifest_id: Sha256Hex
    source_manifest_document_sha256: Sha256Hex
    source_config_sha256: Sha256Hex
    source_m4_authority_root_sha256: Sha256Hex
    source_m5_authority_root_sha256: Sha256Hex
    audit_head_sequence: int = Field(ge=-1, strict=True)
    audit_head_hash: Sha256Hex
    replay_input_authority_id: Sha256Hex
    replay_input_authority_document_sha256: Sha256Hex
    replay_input_closure_authority_id: Sha256Hex
    replay_input_closure_document_sha256: Sha256Hex
    source_validation_report_id: Sha256Hex
    source_validation_report_document_sha256: Sha256Hex
    entries: tuple[M6SourceAuthorityDocumentEntry, ...] = Field(
        min_length=len(M6SourceAuthorityDocumentKind),
        max_length=len(M6SourceAuthorityDocumentKind),
    )

    @field_validator("sample_id", "source_run_id", "source_case_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 source authority seal reference")

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
                "document_inventory_root_sha256",
                "seal_id",
                "seal_relative_path",
            ),
        )
        seal = handler(payload)
        _verify_claims(seal, claims)
        return seal

    @model_validator(mode="after")
    def validate_exact_document_inventory(self) -> Self:
        canonical_entries = tuple(
            M6SourceAuthorityDocumentEntry.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.entries
        )
        keys = tuple(item.sort_key for item in canonical_entries)
        if canonical_entries != self.entries or keys != tuple(sorted(keys)):
            raise ValueError("M6 source authority seal entries must be canonical and ordered")
        if {item.kind for item in canonical_entries} != set(M6SourceAuthorityDocumentKind):
            raise ValueError("M6 source authority seal must contain exactly five document kinds")
        if (
            sum(item.size_bytes for item in canonical_entries)
            > MAX_M6_SOURCE_AUTHORITY_BUNDLE_BYTES
        ):
            raise ValueError("M6 source authority seal exceeds the bundle byte budget")
        entries = {item.kind: item for item in canonical_entries}
        expected = {
            M6SourceAuthorityDocumentKind.REPLAY_INPUT_CLOSURE: (
                self.replay_input_closure_authority_id,
                self.replay_input_closure_document_sha256,
            ),
            M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY: (
                self.replay_input_authority_id,
                self.replay_input_authority_document_sha256,
            ),
            M6SourceAuthorityDocumentKind.SOURCE_VALIDATION_REPORT: (
                self.source_validation_report_id,
                self.source_validation_report_document_sha256,
            ),
            M6SourceAuthorityDocumentKind.SOURCE_CASE: (
                self.source_case_id,
                self.source_case_document_sha256,
            ),
            M6SourceAuthorityDocumentKind.SOURCE_MANIFEST: (
                self.source_manifest_id,
                self.source_manifest_document_sha256,
            ),
        }
        if any(
            (entries[kind].artifact_id, entries[kind].declared_document_sha256) != binding
            for kind, binding in expected.items()
        ):
            raise ValueError("M6 source authority document entry conflicts with seal scope")
        object.__setattr__(self, "entries", canonical_entries)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def document_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-source-authority-document-inventory",
                1,
                [item.entry_id for item in self.entries],
            ]
        )

    def seal_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sample_id": self.sample_id,
            "source_run_id": self.source_run_id,
            "source_case_id": self.source_case_id,
            "source_case_revision": self.source_case_revision,
            "source_case_document_sha256": self.source_case_document_sha256,
            "source_manifest_id": self.source_manifest_id,
            "source_manifest_document_sha256": self.source_manifest_document_sha256,
            "source_config_sha256": self.source_config_sha256,
            "source_m4_authority_root_sha256": self.source_m4_authority_root_sha256,
            "source_m5_authority_root_sha256": self.source_m5_authority_root_sha256,
            "audit_head_sequence": self.audit_head_sequence,
            "audit_head_hash": self.audit_head_hash,
            "replay_input_authority_id": self.replay_input_authority_id,
            "replay_input_authority_document_sha256": (self.replay_input_authority_document_sha256),
            "replay_input_closure_authority_id": self.replay_input_closure_authority_id,
            "replay_input_closure_document_sha256": (self.replay_input_closure_document_sha256),
            "source_validation_report_id": self.source_validation_report_id,
            "source_validation_report_document_sha256": (
                self.source_validation_report_document_sha256
            ),
            "document_inventory_root_sha256": self.document_inventory_root_sha256,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seal_id(self) -> Sha256Hex:
        return sha256_hex(["m6-source-authority-seal", 1, self.seal_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seal_relative_path(self) -> str:
        return m6_source_authority_seal_relative_path(self.replay_input_closure_authority_id)


__all__ = [
    "MAX_M6_SOURCE_AUTHORITY_BUNDLE_BYTES",
    "MAX_M6_SOURCE_AUTHORITY_DOCUMENT_BYTES",
    "M6SourceAuthorityDocumentEntry",
    "M6SourceAuthorityDocumentKind",
    "M6SourceAuthoritySeal",
    "m6_source_authority_document_relative_path",
    "m6_source_authority_seal_relative_path",
]
