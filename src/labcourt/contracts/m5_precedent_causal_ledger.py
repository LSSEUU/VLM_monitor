"""Strict append events for the M5 precedent causal ledger.

The ledger records every precedent authority revision, every citation, and one
commit marker for every complete conflict-batch receipt. Event identity is
stable for a source while the event hash binds that source to one exact position
in the per-run chain.
"""

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

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_bytes, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token

M5_PRECEDENT_CAUSAL_GENESIS_SHA256 = "0" * 64


class M5PrecedentCausalEventKind(StrEnum):
    PRECEDENT_AUTHORITY_APPENDED = "PRECEDENT_AUTHORITY_APPENDED"
    PRECEDENT_CITATION_APPENDED = "PRECEDENT_CITATION_APPENDED"
    PRECEDENT_CONFLICT_BATCH_COMMITTED = "PRECEDENT_CONFLICT_BATCH_COMMITTED"
    PRECEDENT_REVOCATION_COMMITTED = "PRECEDENT_REVOCATION_COMMITTED"
    APPEAL_RESOLUTION_COMMITTED = "APPEAL_RESOLUTION_COMMITTED"


class M5PrecedentCausalEventSourceKind(StrEnum):
    """The frozen discriminator already persisted by citation roots."""

    DIRECT = "DIRECT"
    APPLIED = "APPLIED"


class M5PrecedentCausalEvent(FrozenContractModel):
    """One immutable source-to-ledger binding in a per-run hash chain."""

    schema_version: Literal["m5-precedent-causal-event-v1"] = "m5-precedent-causal-event-v1"
    run_id: ReferenceToken
    sequence: int = Field(gt=0, strict=True)
    event_kind: M5PrecedentCausalEventKind
    source_id: Sha256Hex
    precedent_id: ReferenceToken | None
    precedent_authority_id: Sha256Hex | None
    precedent_revision: int | None = Field(gt=0, strict=True)
    citation_kind: M5PrecedentCausalEventSourceKind | None
    manifest_id: Sha256Hex
    source_document_sha256: Sha256Hex
    previous_event_sha256: Sha256Hex

    @field_validator("run_id")
    @classmethod
    def validate_run_reference_token(cls, value: str) -> str:
        return require_reference_token(value, "M5 precedent causal event reference")

    @field_validator("precedent_id")
    @classmethod
    def validate_optional_precedent_reference_token(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M5 precedent causal event reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claims = {
            name: (name in payload, payload.pop(name, None))
            for name in ("source_identity_sha256", "event_id", "event_sha256")
        }
        event = handler(payload)
        for name, (present, claimed) in claims.items():
            if present and (not isinstance(claimed, str) or claimed != getattr(event, name)):
                raise ValueError(f"serialized {name} does not match event content")
        return event

    @model_validator(mode="after")
    def validate_chain_position_and_source_discriminator(self) -> Self:
        if self.sequence == 1:
            if self.previous_event_sha256 != M5_PRECEDENT_CAUSAL_GENESIS_SHA256:
                raise ValueError("first causal event must use the zero predecessor")
        elif self.previous_event_sha256 == M5_PRECEDENT_CAUSAL_GENESIS_SHA256:
            raise ValueError("later causal event must not use the zero predecessor")

        if self.event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED:
            if (
                self.precedent_id is None
                or self.precedent_authority_id is None
                or self.precedent_revision is None
                or self.citation_kind is not None
                or self.source_id != self.precedent_authority_id
            ):
                raise ValueError(
                    "authority event source must be its precedent authority without citation kind"
                )
        elif self.event_kind == M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED:
            if (
                self.precedent_id is None
                or self.precedent_authority_id is None
                or self.precedent_revision is None
                or self.citation_kind is None
            ):
                raise ValueError(
                    "citation event requires a precedent source and DIRECT or APPLIED kind"
                )
        elif self.event_kind == M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED:
            if (
                self.precedent_id is None
                or self.precedent_authority_id is None
                or self.precedent_revision is None
                or self.citation_kind is not None
            ):
                raise ValueError(
                    "revocation marker requires its resulting precedent authority without "
                    "citation kind"
                )
        elif (
            self.precedent_id is not None
            or self.precedent_authority_id is not None
            or self.precedent_revision is not None
            or self.citation_kind is not None
        ):
            raise ValueError("aggregate commit marker must not claim precedent or citation fields")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_identity_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-causal-source",
                1,
                self.run_id,
                self.event_kind,
                self.source_id,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def event_id(self) -> Sha256Hex:
        return sha256_hex(["m5-precedent-causal-event", 1, self.source_identity_sha256])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def event_sha256(self) -> Sha256Hex:
        body = [
            "m5-precedent-causal-event-chain",
            1,
            self.event_id,
            self.run_id,
            self.sequence,
            self.event_kind,
            self.source_id,
            self.precedent_id,
            self.precedent_authority_id,
            self.precedent_revision,
            self.citation_kind,
            self.manifest_id,
            self.source_document_sha256,
        ]
        return hashlib.sha256(
            self.previous_event_sha256.encode("ascii") + canonical_bytes(body)
        ).hexdigest()


__all__ = [
    "M5_PRECEDENT_CAUSAL_GENESIS_SHA256",
    "M5PrecedentCausalEvent",
    "M5PrecedentCausalEventKind",
    "M5PrecedentCausalEventSourceKind",
]
