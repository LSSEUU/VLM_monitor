"""Durable pre-ledger commitment to one exact M6 V2 sample record.

The authority closes the crash window only after its first successful append.
It cannot reconstruct or prove a record if the process crashes before this
commitment itself becomes durable.
"""

from __future__ import annotations

import hashlib
from typing import Literal, Self, TypeVar

from pydantic import (
    BaseModel,
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m6_regression import (
    MAX_M6_REGRESSION_CASES,
    M6RegressionExecutionEntry,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M6_UPGRADE_PENDING_SAMPLE_COMMITMENT_DOCUMENT_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES

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
            raise ValueError(
                f"serialized {name} conflicts with derived M6 pending sample commitment"
            )


def _canonical_nested(expected: type[_CanonicalT], value: object, label: str) -> _CanonicalT:
    if not isinstance(value, expected):
        raise ValueError(f"{label} must be a canonical typed authority")
    controlled = expected.model_validate(
        value.model_dump(mode="json", exclude_computed_fields=True)
    )
    if controlled != value:
        raise ValueError(f"{label} must be a canonical typed authority")
    return controlled


def _canonical_document_bytes(value: BaseModel) -> bytes:
    return canonical_json(value.model_dump(mode="json")).encode("utf-8")


class M6UpgradePendingSampleCommitmentAuthority(FrozenContractModel):
    """Append-only commitment to canonical V2 record bytes after observation append."""

    schema_version: Literal["m6-upgrade-pending-sample-commitment-authority-v1"] = (
        "m6-upgrade-pending-sample-commitment-authority-v1"
    )
    execution_scope_authority_id: Sha256Hex
    candidate_run_id: ReferenceToken
    command_id: Sha256Hex
    execution_dataset_snapshot_id: Sha256Hex
    execution_entry: M6RegressionExecutionEntry
    ledger_sequence: int = Field(
        ge=0,
        le=MAX_M6_REGRESSION_CASES - 1,
        strict=True,
    )
    observation_authority_id: Sha256Hex
    sample_execution_record: M6UpgradeSampleExecutionRecordV2
    sample_execution_record_document_sha256: Sha256Hex
    sample_execution_record_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES,
        strict=True,
    )

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 pending sample commitment candidate run_id")

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
                "sample_execution_record_id",
                "pending_sample_commitment_authority_id",
            ),
        )
        commitment = handler(payload)
        _verify_claims(commitment, claims)
        return commitment

    @model_validator(mode="after")
    def validate_exact_record_commitment(self) -> Self:
        entry = _canonical_nested(
            M6RegressionExecutionEntry,
            self.execution_entry,
            "M6 pending commitment execution entry",
        )
        record = _canonical_nested(
            M6UpgradeSampleExecutionRecordV2,
            self.sample_execution_record,
            "M6 pending commitment V2 sample record",
        )
        record_document = _canonical_document_bytes(record)
        if (
            record.execution_scope_authority_id != self.execution_scope_authority_id
            or record.candidate_run_id != self.candidate_run_id
            or record.command_id != self.command_id
            or record.execution_dataset_snapshot_id != self.execution_dataset_snapshot_id
            or record.execution_entry != entry
            or record.ledger_sequence != self.ledger_sequence
            or record.observation_authority_id != self.observation_authority_id
        ):
            raise ValueError("M6 pending commitment differs from its exact V2 sample record scope")
        if (
            hashlib.sha256(record_document).hexdigest()
            != self.sample_execution_record_document_sha256
            or len(record_document) != self.sample_execution_record_size_bytes
        ):
            raise ValueError("M6 pending commitment V2 record document identity differs")
        object.__setattr__(self, "execution_entry", entry)
        object.__setattr__(self, "sample_execution_record", record)
        if (
            len(_canonical_document_bytes(self))
            > MAX_M6_UPGRADE_PENDING_SAMPLE_COMMITMENT_DOCUMENT_BYTES
        ):
            raise ValueError("M6 pending sample commitment exceeds its document byte budget")
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
    def sample_execution_record_id(self) -> Sha256Hex:
        return self.sample_execution_record.sample_execution_record_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pending_sample_commitment_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-upgrade-pending-sample-commitment-authority",
                1,
                self.execution_scope_authority_id,
                self.candidate_run_id,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.execution_entry_id,
                self.ledger_sequence,
                self.observation_authority_id,
                self.sample_execution_record_id,
                self.sample_execution_record_document_sha256,
                self.sample_execution_record_size_bytes,
            ]
        )

    @property
    def persistence_key(self) -> tuple[str, str, int]:
        return (
            self.candidate_run_id,
            self.execution_scope_authority_id,
            self.ledger_sequence,
        )


__all__ = [
    "MAX_M6_UPGRADE_PENDING_SAMPLE_COMMITMENT_DOCUMENT_BYTES",
    "M6UpgradePendingSampleCommitmentAuthority",
]
