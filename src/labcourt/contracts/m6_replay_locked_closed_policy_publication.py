"""Additive publication V2 for one replay-locked CLOSED-policy report."""

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

MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_DOCUMENT_BYTES = 256 * 1024 * 1024
MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_BUNDLE_BYTES = 768 * 1024 * 1024


class M6ReplayLockedClosedPolicyPublicationDocumentKind(StrEnum):
    COMMAND = "COMMAND"
    EVALUATOR_DATASET = "EVALUATOR_DATASET"
    CLOSED_POLICY_EXECUTION_SEAL = "CLOSED_POLICY_EXECUTION_SEAL"
    REGRESSION_REPORT = "REGRESSION_REPORT"


_KIND_RANK = {
    kind: index for index, kind in enumerate(M6ReplayLockedClosedPolicyPublicationDocumentKind)
}
_KIND_DIRECTORY = {
    M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND: "commands",
    M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET: ("evaluator-datasets"),
    M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL: (
        "closed-policy-execution-seals"
    ),
}


def m6_replay_locked_closed_policy_publication_document_relative_path(
    kind: M6ReplayLockedClosedPolicyPublicationDocumentKind,
    content_sha256: str,
) -> str:
    if not isinstance(kind, M6ReplayLockedClosedPolicyPublicationDocumentKind):
        raise TypeError("kind must be an M6ReplayLockedClosedPolicyPublicationDocumentKind")
    if (
        not isinstance(content_sha256, str)
        or len(content_sha256) != 64
        or any(character not in "0123456789abcdef" for character in content_sha256)
    ):
        raise ValueError("content_sha256 must be a lowercase SHA-256")
    if kind == M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT:
        return "regression.json"
    return f"m6-regression/documents/{_KIND_DIRECTORY[kind]}/{content_sha256}.json"


def m6_replay_locked_closed_policy_publication_seal_relative_path(
    report_id: str,
) -> str:
    if (
        not isinstance(report_id, str)
        or len(report_id) != 64
        or any(character not in "0123456789abcdef" for character in report_id)
    ):
        raise ValueError("report_id must be a lowercase SHA-256")
    return f"m6-regression/closed-policy-seals/{report_id}/seal.json"


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
            raise ValueError(
                "serialized claim conflicts with the derived CLOSED-policy publication"
            )


class M6ReplayLockedClosedPolicyPublicationDocumentEntry(FrozenContractModel):
    kind: M6ReplayLockedClosedPolicyPublicationDocumentKind
    artifact_id: Sha256Hex
    content_sha256: Sha256Hex
    size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_DOCUMENT_BYTES,
        strict=True,
    )

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
        return m6_replay_locked_closed_policy_publication_document_relative_path(
            self.kind,
            self.content_sha256,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def entry_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-publication-document-entry",
                2,
                self.kind,
                self.artifact_id,
                self.content_sha256,
                self.size_bytes,
                self.relative_path,
            ]
        )

    @property
    def sort_key(self) -> tuple[int, str]:
        return _KIND_RANK[self.kind], self.artifact_id


class M6ReplayLockedClosedPolicyPublicationSealAuthorityV2(FrozenContractModel):
    """Four immutable documents with ``regression.json`` as the commit point."""

    schema_version: Literal["m6-replay-locked-closed-policy-publication-seal-authority-v2"] = (
        "m6-replay-locked-closed-policy-publication-seal-authority-v2"
    )
    candidate_run_id: ReferenceToken
    candidate_manifest_id: Sha256Hex
    source_catalog_authority_id: Sha256Hex
    source_catalog_document_sha256: Sha256Hex
    command_id: Sha256Hex
    execution_dataset_snapshot_id: Sha256Hex
    evaluator_dataset_snapshot_id: Sha256Hex
    closed_policy_execution_seal_authority_id: Sha256Hex
    report_id: Sha256Hex
    entries: tuple[M6ReplayLockedClosedPolicyPublicationDocumentEntry, ...] = Field(
        min_length=len(M6ReplayLockedClosedPolicyPublicationDocumentKind),
        max_length=len(M6ReplayLockedClosedPolicyPublicationDocumentKind),
    )

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(
            value,
            "M6 CLOSED-policy publication candidate run_id",
        )

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
            M6ReplayLockedClosedPolicyPublicationDocumentEntry.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.entries
        )
        keys = tuple(item.sort_key for item in canonical_entries)
        if canonical_entries != self.entries or keys != tuple(sorted(keys)):
            raise ValueError("M6 CLOSED-policy publication entries must be canonical and ordered")
        if {item.kind for item in canonical_entries} != set(
            M6ReplayLockedClosedPolicyPublicationDocumentKind
        ):
            raise ValueError("M6 CLOSED-policy publication requires exactly four document kinds")
        if (
            sum(item.size_bytes for item in canonical_entries)
            > MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_BUNDLE_BYTES
        ):
            raise ValueError("M6 CLOSED-policy publication exceeds its bundle byte budget")
        entries = {item.kind: item for item in canonical_entries}
        expected = {
            M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND: self.command_id,
            M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET: (
                self.evaluator_dataset_snapshot_id
            ),
            M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL: (
                self.closed_policy_execution_seal_authority_id
            ),
            M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT: (self.report_id),
        }
        if any(entries[kind].artifact_id != artifact_id for kind, artifact_id in expected.items()):
            raise ValueError("M6 CLOSED-policy publication entry conflicts with seal scope")
        if (
            entries[
                M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT
            ].relative_path
            != "regression.json"
        ):
            raise ValueError("M6 regression report must be the fixed publication commit point")
        object.__setattr__(self, "entries", canonical_entries)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def document_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-publication-document-inventory",
                2,
                [item.entry_id for item in self.entries],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seal_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-publication-seal",
                2,
                self.candidate_run_id,
                self.candidate_manifest_id,
                self.source_catalog_authority_id,
                self.source_catalog_document_sha256,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.evaluator_dataset_snapshot_id,
                self.closed_policy_execution_seal_authority_id,
                self.report_id,
                self.document_inventory_root_sha256,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seal_relative_path(self) -> str:
        return m6_replay_locked_closed_policy_publication_seal_relative_path(self.report_id)


__all__ = [
    "MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_BUNDLE_BYTES",
    "MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_DOCUMENT_BYTES",
    "M6ReplayLockedClosedPolicyPublicationDocumentEntry",
    "M6ReplayLockedClosedPolicyPublicationDocumentKind",
    "M6ReplayLockedClosedPolicyPublicationSealAuthorityV2",
    "m6_replay_locked_closed_policy_publication_document_relative_path",
    "m6_replay_locked_closed_policy_publication_seal_relative_path",
]
