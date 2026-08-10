"""M8 loopback API authentication and human-command boundary contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    MAX_M8_CASE_AUTHORITIES,
    M8AppealResolution,
    M8AuthorityReference,
    M8OperationalCaseAction,
    M8OperationalCaseReasonCode,
    M8OperationalCaseStatus,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_API_CREDENTIALS = 10_000


class M8ApiErrorReason(StrEnum):
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    INVALID_CREDENTIAL = "INVALID_CREDENTIAL"
    FORBIDDEN = "FORBIDDEN"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    CONCURRENT_MODIFICATION = "CONCURRENT_MODIFICATION"
    INVALID_REQUEST = "INVALID_REQUEST"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    LOCAL_HOST_REQUIRED = "LOCAL_HOST_REQUIRED"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"


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
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 API authority")


class M8ApiCredentialAuthorityV1(FrozenContractModel):
    """One bearer-token hash mapping to an actor ID, never to role/capability."""

    schema_version: Literal["m8-api-credential-authority-v1"] = "m8-api-credential-authority-v1"
    credential_id: ReferenceToken
    actor_id: ReferenceToken
    bearer_token_sha256: Sha256Hex
    active: StrictBool
    manifest_id: Sha256Hex

    @field_validator("credential_id", "actor_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 API credential reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("credential_authority_id",))
        credential = handler(payload)
        _verify_computed_claims(credential, claims)
        return credential

    @computed_field  # type: ignore[prop-decorator]
    @property
    def credential_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-api-credential-authority",
                1,
                self.credential_id,
                self.actor_id,
                self.bearer_token_sha256,
                self.active,
                self.manifest_id,
            ]
        )


class M8ApiCredentialCatalogAuthorityV1(FrozenContractModel):
    """Complete runtime credential hash catalog required to start the API."""

    schema_version: Literal["m8-api-credential-catalog-authority-v1"] = (
        "m8-api-credential-catalog-authority-v1"
    )
    revision: int = Field(gt=0, strict=True)
    credentials: tuple[M8ApiCredentialAuthorityV1, ...] = Field(
        min_length=1,
        max_length=MAX_M8_API_CREDENTIALS,
    )
    authentication_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("credential_inventory_sha256", "credential_catalog_id"),
        )
        catalog = handler(payload)
        _verify_computed_claims(catalog, claims)
        return catalog

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        credential_ids = tuple(item.credential_id for item in self.credentials)
        token_hashes = tuple(item.bearer_token_sha256 for item in self.credentials)
        if credential_ids != tuple(sorted(credential_ids)):
            raise ValueError("M8 API credentials must use stable credential_id order")
        if len(credential_ids) != len(set(credential_ids)):
            raise ValueError("M8 API credential_id values must be unique")
        if len(token_hashes) != len(set(token_hashes)):
            raise ValueError("M8 API bearer token hashes must be unique")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def credential_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-api-credential-inventory",
                1,
                [item.credential_authority_id for item in self.credentials],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def credential_catalog_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-api-credential-catalog-authority",
                1,
                self.revision,
                self.credential_inventory_sha256,
                self.authentication_manifest_id,
            ]
        )


class M8ApiPrincipalV1(FrozenContractModel):
    """Authenticated identity only; authorization still resolves persisted actor authority."""

    schema_version: Literal["m8-api-principal-v1"] = "m8-api-principal-v1"
    actor_id: ReferenceToken
    credential_id: ReferenceToken
    credential_authority_id: Sha256Hex
    credential_catalog_id: Sha256Hex
    authentication_manifest_id: Sha256Hex

    @field_validator("actor_id", "credential_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 API principal reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("authentication_context_id",))
        principal = handler(payload)
        _verify_computed_claims(principal, claims)
        return principal

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authentication_context_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-api-authentication-context",
                1,
                self.actor_id,
                self.credential_id,
                self.credential_authority_id,
                self.credential_catalog_id,
                self.authentication_manifest_id,
            ]
        )


class M8ApiCaseTransitionRequestV1(FrozenContractModel):
    """Human transition input deliberately excluding actor role/capability authority."""

    schema_version: Literal["m8-api-case-transition-request-v1"] = (
        "m8-api-case-transition-request-v1"
    )
    source_case_version: int = Field(gt=0, strict=True)
    source_case_authority_sha256: Sha256Hex
    source_status: M8OperationalCaseStatus
    case_location_id: ReferenceToken
    subject_actor_id: ReferenceToken | None = None
    action: M8OperationalCaseAction
    reason_code: M8OperationalCaseReasonCode
    reason_summary: str = Field(min_length=1, max_length=2048)
    supporting_authorities: tuple[M8AuthorityReference, ...] = Field(
        min_length=1,
        max_length=MAX_M8_CASE_AUTHORITIES,
    )
    appeal_resolution: M8AppealResolution | None = None
    explicit_human_confirmation: StrictBool
    command_manifest_id: Sha256Hex

    @field_validator("case_location_id")
    @classmethod
    def validate_case_location_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 API case location")

    @field_validator("subject_actor_id")
    @classmethod
    def validate_subject_actor_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 API case subject")

    @field_validator("reason_summary")
    @classmethod
    def validate_reason_summary(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("M8 API reason_summary must be visible text without edge whitespace")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("direct_disciplinary_action_permitted", "transition_request_id"),
        )
        request = handler(payload)
        _verify_computed_claims(request, claims)
        return request

    @model_validator(mode="after")
    def validate_human_request_shape(self) -> Self:
        if self.explicit_human_confirmation is not True:
            raise ValueError("M8 API transition requires explicit human confirmation")
        if self.action == M8OperationalCaseAction.RESOLVE_APPEAL:
            if self.appeal_resolution is None:
                raise ValueError("M8 API RESOLVE_APPEAL requires appeal_resolution")
        elif self.appeal_resolution is not None:
            raise ValueError("M8 API appeal_resolution is only valid for RESOLVE_APPEAL")
        keys = tuple(
            (item.kind.value, item.authority_id, item.document_sha256)
            for item in self.supporting_authorities
        )
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M8 API supporting authorities must be unique and stable")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def transition_request_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-api-case-transition-request",
                1,
                self.source_case_version,
                self.source_case_authority_sha256,
                self.source_status,
                self.case_location_id,
                self.subject_actor_id,
                self.action,
                self.reason_code,
                self.reason_summary,
                [item.model_dump(mode="json") for item in self.supporting_authorities],
                self.appeal_resolution,
                self.explicit_human_confirmation,
                self.command_manifest_id,
                self.direct_disciplinary_action_permitted,
            ]
        )


class M8ApiErrorResponseV1(FrozenContractModel):
    schema_version: Literal["m8-api-error-response-v1"] = "m8-api-error-response-v1"
    reason_code: M8ApiErrorReason
    request_id: Sha256Hex | None = None


__all__ = [
    "MAX_M8_API_CREDENTIALS",
    "M8ApiCaseTransitionRequestV1",
    "M8ApiCredentialAuthorityV1",
    "M8ApiCredentialCatalogAuthorityV1",
    "M8ApiErrorReason",
    "M8ApiErrorResponseV1",
    "M8ApiPrincipalV1",
]
