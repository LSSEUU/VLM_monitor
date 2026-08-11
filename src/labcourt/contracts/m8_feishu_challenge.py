"""Secret-free contracts for Feishu encrypted URL verification challenges."""

from __future__ import annotations

from datetime import datetime, timedelta
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
from labcourt.contracts.m8_feishu_inbound import (
    MAX_M8_FEISHU_INBOUND_BODY_BYTES,
    M8FeishuInboundWebhookProfileV1,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise ValueError(f"M8 Feishu URL challenge {name} must be timezone-aware UTC")
    return value


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
    if not any(present for present, _claimed in claims.values()):
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(
                f"serialized {name} conflicts with derived M8 Feishu URL challenge authority"
            )


class M8FeishuUrlChallengeIngressRequestV1(FrozenContractModel):
    """Exact encrypted URL challenge evidence before decryption or token claims."""

    schema_version: Literal["m8-feishu-url-challenge-ingress-request-v1"] = (
        "m8-feishu-url-challenge-ingress-request-v1"
    )
    inbound_profile_id: Sha256Hex
    encrypted_body_ref: ReferenceToken
    encrypted_body_sha256: Sha256Hex
    encrypted_body_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_FEISHU_INBOUND_BODY_BYTES,
        strict=True,
    )
    received_at: datetime
    ingress_manifest_id: Sha256Hex

    @field_validator("encrypted_body_ref")
    @classmethod
    def validate_body_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu encrypted URL challenge body")

    @field_validator("received_at")
    @classmethod
    def validate_received_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "received_at")

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
                "request_signature_applicable",
                "signature_verified",
                "payload_decrypted",
                "business_event_accepted",
                "credential_material_embedded",
                "ingress_request_id",
            ),
        )
        request = handler(payload)
        _verify_computed_claims(request, claims)
        return request

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_signature_applicable(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def signature_verified(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def payload_decrypted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def business_event_accepted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def credential_material_embedded(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ingress_request_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-url-challenge-ingress-request",
                1,
                self.inbound_profile_id,
                self.encrypted_body_ref,
                self.encrypted_body_sha256,
                self.encrypted_body_size_bytes,
                _canonical_utc(self.received_at),
                self.ingress_manifest_id,
                self.request_signature_applicable,
                self.signature_verified,
                self.payload_decrypted,
                self.business_event_accepted,
                self.credential_material_embedded,
            ]
        )


class M8FeishuUrlChallengeVerificationReceiptV1(FrozenContractModel):
    """Hash-only proof that one encrypted URL challenge may be answered."""

    schema_version: Literal["m8-feishu-url-challenge-verification-receipt-v1"] = (
        "m8-feishu-url-challenge-verification-receipt-v1"
    )
    profile: M8FeishuInboundWebhookProfileV1
    ingress_request: M8FeishuUrlChallengeIngressRequestV1
    challenge_type: Literal["url_verification"] = "url_verification"
    decrypted_challenge_ref: ReferenceToken
    decrypted_challenge_sha256: Sha256Hex
    decrypted_challenge_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_FEISHU_INBOUND_BODY_BYTES,
        strict=True,
    )
    response_document_ref: ReferenceToken
    response_document_sha256: Sha256Hex
    response_document_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_FEISHU_INBOUND_BODY_BYTES,
        strict=True,
    )
    verification_token_sha256: Sha256Hex
    verified_at: datetime
    response_deadline_milliseconds: Literal[1000] = 1_000
    verification_manifest_id: Sha256Hex

    @field_validator("decrypted_challenge_ref", "response_document_ref")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu URL challenge artifact")

    @field_validator("verified_at")
    @classmethod
    def validate_verified_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "verified_at")

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
                "payload_decrypted",
                "verification_token_verified",
                "response_status_code",
                "response_content_type",
                "clear_challenge_value_embedded",
                "challenge_response_permitted",
                "external_ingress_activation_permitted",
                "notification_reply_commit_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "verification_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_verification(self) -> Self:
        if self.ingress_request.inbound_profile_id != self.profile.inbound_profile_id:
            raise ValueError("M8 Feishu URL challenge belongs to another profile")
        if self.verification_token_sha256 != self.profile.verification_token_sha256:
            raise ValueError("M8 Feishu URL challenge belongs to another token")
        if self.verified_at < self.ingress_request.received_at:
            raise ValueError("M8 Feishu URL challenge verification cannot predate ingress")
        if self.verified_at > self.ingress_request.received_at + timedelta(
            milliseconds=self.response_deadline_milliseconds
        ):
            raise ValueError("M8 Feishu URL challenge verification missed its deadline")
        if self.decrypted_challenge_ref == self.response_document_ref:
            raise ValueError("M8 Feishu URL challenge artifacts require distinct references")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def payload_decrypted(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verification_token_verified(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def response_status_code(self) -> int:
        return 200

    @computed_field  # type: ignore[prop-decorator]
    @property
    def response_content_type(self) -> str:
        return "application/json"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def clear_challenge_value_embedded(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def challenge_response_permitted(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_ingress_activation_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_reply_commit_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verification_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-url-challenge-verification-receipt",
                1,
                self.profile.inbound_profile_id,
                self.ingress_request.ingress_request_id,
                self.challenge_type,
                self.decrypted_challenge_ref,
                self.decrypted_challenge_sha256,
                self.decrypted_challenge_size_bytes,
                self.response_document_ref,
                self.response_document_sha256,
                self.response_document_size_bytes,
                self.verification_token_sha256,
                _canonical_utc(self.verified_at),
                self.response_deadline_milliseconds,
                self.verification_manifest_id,
                self.payload_decrypted,
                self.verification_token_verified,
                self.response_status_code,
                self.response_content_type,
                self.clear_challenge_value_embedded,
                self.challenge_response_permitted,
                self.external_ingress_activation_permitted,
                self.notification_reply_commit_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = [
    "M8FeishuUrlChallengeIngressRequestV1",
    "M8FeishuUrlChallengeVerificationReceiptV1",
]
