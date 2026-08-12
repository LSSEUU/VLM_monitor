"""M8 operational-case persistence and commit receipt authorities."""

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
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8OperationalCaseAuditIntentV1,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

M8_AUDIT_GENESIS_SHA256 = "0" * 64


class M8OperationalCaseAuditEventKind(StrEnum):
    CASE_CREATED = "CASE_CREATED"
    CASE_TRANSITIONED = "CASE_TRANSITIONED"


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    if not claims:
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 persistence authority")


class M8ActorAuthorityCommitReceiptV1(FrozenContractModel):
    """Append receipt for one persisted actor authority revision."""

    schema_version: Literal["m8-actor-authority-commit-receipt-v1"] = (
        "m8-actor-authority-commit-receipt-v1"
    )
    authority: M8ActorAuthorityV1
    prior_authority_id: Sha256Hex | None = None
    prior_document_sha256: Sha256Hex | None = None
    repository_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("authority_document_sha256", "commit_receipt_id"),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_prior_shape(self) -> Self:
        if self.authority.authority_revision == 1:
            if self.prior_authority_id is not None or self.prior_document_sha256 is not None:
                raise ValueError("M8 first actor revision cannot declare prior authority")
        elif self.prior_authority_id is None or self.prior_document_sha256 is None:
            raise ValueError("M8 later actor revision requires prior authority and document hash")
        if (self.prior_authority_id is None) != (self.prior_document_sha256 is None):
            raise ValueError("M8 actor prior authority fields must be present together")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.authority.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-actor-authority-commit-receipt",
                1,
                self.authority.actor_authority_id,
                self.authority_document_sha256,
                self.prior_authority_id,
                self.prior_document_sha256,
                self.repository_manifest_id,
            ]
        )


class M8OperationalCaseAuthorityV1(FrozenContractModel):
    """One immutable version of an additive M8 operational Case."""

    schema_version: Literal["m8-operational-case-authority-v1"] = "m8-operational-case-authority-v1"
    create_command: M8OperationalCaseCreateCommandV1
    case_version: int = Field(gt=0, strict=True)
    status: M8OperationalCaseStatus
    subject_actor_id: ReferenceToken | None = None
    prior_case_document_sha256: Sha256Hex | None = None
    last_transition_command_id: Sha256Hex | None = None
    last_actor_authority_id: Sha256Hex | None = None
    case_manifest_id: Sha256Hex

    @field_validator("subject_actor_id")
    @classmethod
    def validate_subject_actor_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 persisted Case subject_actor_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("case_id", "location_id", "risk_level", "source_ids", "case_authority_id"),
        )
        authority = handler(payload)
        _verify_computed_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_version_shape(self) -> Self:
        transition_fields = (
            self.prior_case_document_sha256,
            self.last_transition_command_id,
            self.last_actor_authority_id,
        )
        if self.case_version == 1:
            if self.status != M8OperationalCaseStatus.PENDING_VERIFICATION:
                raise ValueError("M8 created Case must start PENDING_VERIFICATION")
            if any(value is not None for value in transition_fields):
                raise ValueError("M8 first Case version cannot declare transition fields")
        elif any(value is None for value in transition_fields):
            raise ValueError("M8 later Case version requires complete transition fields")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_id(self) -> Sha256Hex:
        return self.create_command.case_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def location_id(self) -> ReferenceToken:
        return self.create_command.location_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_level(self) -> M8OperationalRiskLevel:
        return self.create_command.risk_level

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_ids(self) -> tuple[ReferenceToken, ...]:
        return self.create_command.source_ids

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-case-authority",
                1,
                self.create_command.create_command_id,
                self.case_version,
                self.status,
                self.subject_actor_id,
                self.prior_case_document_sha256,
                self.last_transition_command_id,
                self.last_actor_authority_id,
                self.case_manifest_id,
            ]
        )


class M8OperationalCaseAuditEventV1(FrozenContractModel):
    """Per-Case append-only audit event binding one exact authority version."""

    schema_version: Literal["m8-operational-case-audit-event-v1"] = (
        "m8-operational-case-audit-event-v1"
    )
    case_authority: M8OperationalCaseAuthorityV1
    event_sequence: int = Field(gt=0, strict=True)
    create_command_id: Sha256Hex | None = None
    transition_intent: M8OperationalCaseAuditIntentV1 | None = None
    resolved_actor_document_sha256: Sha256Hex | None = None
    prior_audit_event_sha256: Sha256Hex
    audit_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "event_kind",
                "case_document_sha256",
                "audit_event_sha256",
                "audit_event_id",
            ),
        )
        event = handler(payload)
        _verify_computed_claims(event, claims)
        return event

    @model_validator(mode="after")
    def validate_event_binding(self) -> Self:
        authority = self.case_authority
        if self.event_sequence != authority.case_version:
            raise ValueError("M8 audit sequence must equal Case version")
        if authority.case_version == 1:
            if self.create_command_id != authority.create_command.create_command_id:
                raise ValueError("M8 create audit must bind the exact create command")
            if (
                self.transition_intent is not None
                or self.resolved_actor_document_sha256 is not None
            ):
                raise ValueError("M8 create audit cannot contain transition authority")
            if self.prior_audit_event_sha256 != M8_AUDIT_GENESIS_SHA256:
                raise ValueError("M8 first audit event must bind the genesis hash")
            return self

        if self.create_command_id is not None:
            raise ValueError("M8 transition audit cannot contain create_command_id")
        if self.transition_intent is None or self.resolved_actor_document_sha256 is None:
            raise ValueError("M8 transition audit requires intent and resolved actor document")
        if self.transition_intent.audit_manifest_id != self.audit_manifest_id:
            raise ValueError("M8 transition audit manifest conflicts with intent")
        command = self.transition_intent.command
        if command.case_id != authority.case_id:
            raise ValueError("M8 transition audit belongs to another Case")
        if command.target_case_version != authority.case_version:
            raise ValueError("M8 transition audit target version conflicts with Case")
        if command.target_status != authority.status:
            raise ValueError("M8 transition audit target status conflicts with Case")
        if command.source_case_authority_sha256 != authority.prior_case_document_sha256:
            raise ValueError("M8 transition audit source document conflicts with Case")
        if command.command_id != authority.last_transition_command_id:
            raise ValueError("M8 transition audit command conflicts with Case")
        if command.actor_authority.actor_authority_id != authority.last_actor_authority_id:
            raise ValueError("M8 transition audit actor conflicts with Case")
        if command.subject_actor_id != authority.subject_actor_id:
            raise ValueError("M8 transition audit subject conflicts with Case")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def event_kind(self) -> M8OperationalCaseAuditEventKind:
        if self.case_authority.case_version == 1:
            return M8OperationalCaseAuditEventKind.CASE_CREATED
        return M8OperationalCaseAuditEventKind.CASE_TRANSITIONED

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.case_authority.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def audit_event_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-case-audit-event",
                1,
                self.event_kind,
                self.case_authority.case_authority_id,
                self.case_document_sha256,
                self.event_sequence,
                self.create_command_id,
                self.transition_intent.model_dump(mode="json") if self.transition_intent else None,
                self.resolved_actor_document_sha256,
                self.prior_audit_event_sha256,
                self.audit_manifest_id,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def audit_event_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-case-audit-event-id",
                1,
                self.case_authority.case_id,
                self.event_sequence,
                self.audit_event_sha256,
            ]
        )


class M8OperationalCaseCommitReceiptV1(FrozenContractModel):
    """Atomic repository receipt for one Case version and its audit event."""

    schema_version: Literal["m8-operational-case-commit-receipt-v1"] = (
        "m8-operational-case-commit-receipt-v1"
    )
    audit_event: M8OperationalCaseAuditEventV1
    repository_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "case_id",
                "case_version",
                "status",
                "case_authority_id",
                "case_document_sha256",
                "audit_event_id",
                "commit_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_id(self) -> Sha256Hex:
        return self.audit_event.case_authority.case_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_version(self) -> int:
        return self.audit_event.case_authority.case_version

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status(self) -> M8OperationalCaseStatus:
        return self.audit_event.case_authority.status

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_authority_id(self) -> Sha256Hex:
        return self.audit_event.case_authority.case_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_document_sha256(self) -> Sha256Hex:
        return self.audit_event.case_document_sha256

    @computed_field  # type: ignore[prop-decorator]
    @property
    def audit_event_id(self) -> Sha256Hex:
        return self.audit_event.audit_event_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-case-commit-receipt",
                1,
                self.audit_event.audit_event_id,
                self.case_authority_id,
                self.case_document_sha256,
                self.repository_manifest_id,
            ]
        )


__all__ = [
    "M8_AUDIT_GENESIS_SHA256",
    "M8ActorAuthorityCommitReceiptV1",
    "M8OperationalCaseAuditEventKind",
    "M8OperationalCaseAuditEventV1",
    "M8OperationalCaseAuthorityV1",
    "M8OperationalCaseCommitReceiptV1",
]
