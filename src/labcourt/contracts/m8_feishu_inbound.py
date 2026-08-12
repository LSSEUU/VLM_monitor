"""Secret-free contracts for verified Feishu inbound message webhook evidence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
from labcourt.contracts.m8_feishu_notification import M8FeishuAdapterProfileV1
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_FEISHU_INBOUND_BODY_BYTES = 262_144
MAX_M8_FEISHU_INBOUND_TIMESTAMP_SKEW_SECONDS = 300
_NONCE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu inbound {name} must be timezone-aware UTC")
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
                f"serialized {name} conflicts with derived M8 Feishu inbound authority"
            )


class M8FeishuInboundWebhookProfileV1(FrozenContractModel):
    """Pinned encrypted webhook profile; never an external-ingress activation."""

    schema_version: Literal["m8-feishu-inbound-webhook-profile-v1"] = (
        "m8-feishu-inbound-webhook-profile-v1"
    )
    outbound_profile: M8FeishuAdapterProfileV1
    request_url_reference_id: ReferenceToken
    encrypt_key_reference_id: ReferenceToken
    encrypt_key_sha256: Sha256Hex
    verification_token_reference_id: ReferenceToken
    verification_token_sha256: Sha256Hex
    delivery_kind: Literal["HTTPS_WEBHOOK"] = "HTTPS_WEBHOOK"
    event_schema: Literal["2.0"] = "2.0"
    event_type: Literal["im.message.receive_v1"] = "im.message.receive_v1"
    required_scope: Literal["im:message.p2p_msg:readonly"] = (
        "im:message.p2p_msg:readonly"
    )
    allowed_chat_type: Literal["p2p"] = "p2p"
    allowed_sender_type: Literal["user"] = "user"
    allowed_message_type: Literal["text"] = "text"
    request_timestamp_max_skew_seconds: Literal[300] = 300
    raw_body_max_bytes: Literal[262144] = 262_144
    encrypt_key_required: Literal[True] = True
    request_signature_required: Literal[True] = True
    message_id_deduplication_required: Literal[True] = True
    secret_material_embedded: Literal[False] = False
    clear_sender_identifier_persisted: Literal[False] = False
    external_ingress_permitted: Literal[False] = False
    profile_manifest_id: Sha256Hex

    @field_validator(
        "request_url_reference_id",
        "encrypt_key_reference_id",
        "verification_token_reference_id",
    )
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu inbound profile reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("inbound_profile_id",))
        profile = handler(payload)
        _verify_computed_claims(profile, claims)
        return profile

    @computed_field  # type: ignore[prop-decorator]
    @property
    def inbound_profile_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-inbound-webhook-profile",
                1,
                self.outbound_profile.profile_id,
                self.request_url_reference_id,
                self.encrypt_key_reference_id,
                self.encrypt_key_sha256,
                self.verification_token_reference_id,
                self.verification_token_sha256,
                self.delivery_kind,
                self.event_schema,
                self.event_type,
                self.required_scope,
                self.allowed_chat_type,
                self.allowed_sender_type,
                self.allowed_message_type,
                self.request_timestamp_max_skew_seconds,
                self.raw_body_max_bytes,
                self.encrypt_key_required,
                self.request_signature_required,
                self.message_id_deduplication_required,
                self.secret_material_embedded,
                self.clear_sender_identifier_persisted,
                self.external_ingress_permitted,
                self.profile_manifest_id,
            ]
        )


class M8FeishuWebhookIngressRequestV1(FrozenContractModel):
    """Exact encrypted request evidence before any signature or payload claim."""

    schema_version: Literal["m8-feishu-webhook-ingress-request-v1"] = (
        "m8-feishu-webhook-ingress-request-v1"
    )
    inbound_profile_id: Sha256Hex
    request_timestamp_seconds: int = Field(gt=0, strict=True)
    request_nonce: str = Field(min_length=1, max_length=128, pattern=_NONCE_PATTERN)
    request_signature: Sha256Hex
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
        return require_reference_token(value, "M8 Feishu encrypted webhook body")

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
                "signature_verified",
                "payload_decrypted",
                "business_event_accepted",
                "credential_material_persisted",
                "ingress_request_id",
            ),
        )
        request = handler(payload)
        _verify_computed_claims(request, claims)
        return request

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
    def credential_material_persisted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ingress_request_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-webhook-ingress-request",
                1,
                self.inbound_profile_id,
                self.request_timestamp_seconds,
                self.request_nonce,
                self.request_signature,
                self.encrypted_body_ref,
                self.encrypted_body_sha256,
                self.encrypted_body_size_bytes,
                _canonical_utc(self.received_at),
                self.ingress_manifest_id,
                self.signature_verified,
                self.payload_decrypted,
                self.business_event_accepted,
                self.credential_material_persisted,
            ]
        )


class M8FeishuInboundMessageVerificationReceiptV1(FrozenContractModel):
    """Hash-only proof of one verified, decrypted, reply-shaped text event."""

    schema_version: Literal["m8-feishu-inbound-message-verification-receipt-v1"] = (
        "m8-feishu-inbound-message-verification-receipt-v1"
    )
    profile: M8FeishuInboundWebhookProfileV1
    ingress_request: M8FeishuWebhookIngressRequestV1
    decrypted_event_ref: ReferenceToken
    decrypted_event_sha256: Sha256Hex
    decrypted_event_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_FEISHU_INBOUND_BODY_BYTES,
        strict=True,
    )
    provider_event_id: ReferenceToken
    provider_message_id: ReferenceToken
    provider_parent_message_id: ReferenceToken
    provider_root_message_id: ReferenceToken | None = None
    event_schema: Literal["2.0"] = "2.0"
    event_type: Literal["im.message.receive_v1"] = "im.message.receive_v1"
    chat_type: Literal["p2p"] = "p2p"
    sender_type: Literal["user"] = "user"
    message_type: Literal["text"] = "text"
    app_id_sha256: Sha256Hex
    tenant_key_sha256: Sha256Hex
    verification_token_sha256: Sha256Hex
    sender_open_id_sha256: Sha256Hex
    event_created_at: datetime
    message_created_at: datetime
    content_document_ref: ReferenceToken
    content_document_sha256: Sha256Hex
    content_size_bytes: int = Field(gt=0, le=MAX_M8_FEISHU_INBOUND_BODY_BYTES, strict=True)
    verification_manifest_id: Sha256Hex

    @field_validator(
        "decrypted_event_ref",
        "provider_event_id",
        "provider_message_id",
        "provider_parent_message_id",
        "provider_root_message_id",
        "content_document_ref",
    )
    @classmethod
    def validate_references(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 Feishu verified inbound reference")

    @field_validator("event_created_at", "message_created_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return _require_utc(value, "provider event time")

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
                "signature_verified",
                "payload_decrypted",
                "verification_token_verified",
                "provider_message_deduplication_key",
                "reply_correlation_message_id",
                "clear_message_content_embedded",
                "clear_sender_identifier_persisted",
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
    def validate_verified_message(self) -> Self:
        ingress = self.ingress_request
        if ingress.inbound_profile_id != self.profile.inbound_profile_id:
            raise ValueError("M8 Feishu inbound request belongs to another profile")
        if ingress.encrypted_body_size_bytes > self.profile.raw_body_max_bytes:
            raise ValueError("M8 Feishu inbound encrypted body exceeds its profile")
        request_time = datetime.fromtimestamp(ingress.request_timestamp_seconds, tz=UTC)
        skew = timedelta(seconds=self.profile.request_timestamp_max_skew_seconds)
        if abs(ingress.received_at - request_time) > skew:
            raise ValueError("M8 Feishu inbound request timestamp is outside the freshness window")
        if (
            self.app_id_sha256 != self.profile.outbound_profile.app_id_sha256
            or self.verification_token_sha256 != self.profile.verification_token_sha256
        ):
            raise ValueError("M8 Feishu inbound event belongs to another app or token")
        if (
            self.event_created_at > ingress.received_at + skew
            or self.message_created_at > ingress.received_at + skew
        ):
            raise ValueError("M8 Feishu inbound provider time is implausibly in the future")
        if self.provider_message_id in {
            self.provider_parent_message_id,
            self.provider_root_message_id,
        }:
            raise ValueError("M8 Feishu inbound reply cannot parent itself")
        references = {
            ingress.encrypted_body_ref,
            self.decrypted_event_ref,
            self.content_document_ref,
        }
        if len(references) != 3:
            raise ValueError("M8 Feishu inbound raw artifacts require distinct references")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def signature_verified(self) -> bool:
        return True

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
    def provider_message_deduplication_key(self) -> ReferenceToken:
        return self.provider_message_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reply_correlation_message_id(self) -> ReferenceToken:
        return self.provider_parent_message_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def clear_message_content_embedded(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def clear_sender_identifier_persisted(self) -> bool:
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
                "m8-feishu-inbound-message-verification-receipt",
                1,
                self.profile.inbound_profile_id,
                self.ingress_request.ingress_request_id,
                self.decrypted_event_ref,
                self.decrypted_event_sha256,
                self.decrypted_event_size_bytes,
                self.provider_event_id,
                self.provider_message_id,
                self.provider_parent_message_id,
                self.provider_root_message_id,
                self.event_schema,
                self.event_type,
                self.chat_type,
                self.sender_type,
                self.message_type,
                self.app_id_sha256,
                self.tenant_key_sha256,
                self.verification_token_sha256,
                self.sender_open_id_sha256,
                _canonical_utc(self.event_created_at),
                _canonical_utc(self.message_created_at),
                self.content_document_ref,
                self.content_document_sha256,
                self.content_size_bytes,
                self.verification_manifest_id,
                self.signature_verified,
                self.payload_decrypted,
                self.verification_token_verified,
                self.provider_message_deduplication_key,
                self.reply_correlation_message_id,
                self.clear_message_content_embedded,
                self.clear_sender_identifier_persisted,
                self.notification_reply_commit_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


class M8FeishuInboundMessageCommitReceiptV1(FrozenContractModel):
    """Append-only persistence proof for exact inbound verification evidence."""

    schema_version: Literal["m8-feishu-inbound-message-commit-receipt-v1"] = (
        "m8-feishu-inbound-message-commit-receipt-v1"
    )
    verification_receipt: M8FeishuInboundMessageVerificationReceiptV1
    committed_at: datetime
    raw_storage_manifest_id: Sha256Hex
    commit_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @field_validator("committed_at")
    @classmethod
    def validate_committed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "commit time")

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
                "provider_message_id",
                "provider_message_deduplication_key",
                "raw_artifact_refs",
                "raw_artifact_sha256s",
                "raw_artifact_sizes_bytes",
                "raw_artifact_inventory_sha256",
                "total_raw_artifact_size_bytes",
                "verified_evidence_persisted",
                "automatic_replay_permitted",
                "notification_reply_commit_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "commit_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_commit(self) -> Self:
        if self.committed_at < self.verification_receipt.ingress_request.received_at:
            raise ValueError("M8 Feishu inbound commit cannot predate ingress")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_message_id(self) -> ReferenceToken:
        return self.verification_receipt.provider_message_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_message_deduplication_key(self) -> ReferenceToken:
        return self.provider_message_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_artifact_refs(self) -> tuple[ReferenceToken, ...]:
        verified = self.verification_receipt
        return (
            verified.ingress_request.encrypted_body_ref,
            verified.decrypted_event_ref,
            verified.content_document_ref,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_artifact_sha256s(self) -> tuple[Sha256Hex, ...]:
        verified = self.verification_receipt
        return (
            verified.ingress_request.encrypted_body_sha256,
            verified.decrypted_event_sha256,
            verified.content_document_sha256,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_artifact_sizes_bytes(self) -> tuple[int, ...]:
        verified = self.verification_receipt
        return (
            verified.ingress_request.encrypted_body_size_bytes,
            verified.decrypted_event_size_bytes,
            verified.content_size_bytes,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_artifact_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            list(
                zip(
                    self.raw_artifact_refs,
                    self.raw_artifact_sha256s,
                    self.raw_artifact_sizes_bytes,
                    strict=True,
                )
            )
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_raw_artifact_size_bytes(self) -> int:
        return sum(self.raw_artifact_sizes_bytes)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verified_evidence_persisted(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_replay_permitted(self) -> bool:
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
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-inbound-message-commit-receipt",
                1,
                self.verification_receipt.verification_receipt_id,
                _canonical_utc(self.committed_at),
                self.raw_artifact_refs,
                self.raw_artifact_sha256s,
                self.raw_artifact_sizes_bytes,
                self.raw_artifact_inventory_sha256,
                self.total_raw_artifact_size_bytes,
                self.raw_storage_manifest_id,
                self.commit_manifest_id,
                self.repository_manifest_id,
                self.verified_evidence_persisted,
                self.automatic_replay_permitted,
                self.notification_reply_commit_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = [
    "MAX_M8_FEISHU_INBOUND_BODY_BYTES",
    "MAX_M8_FEISHU_INBOUND_TIMESTAMP_SKEW_SECONDS",
    "M8FeishuInboundMessageCommitReceiptV1",
    "M8FeishuInboundMessageVerificationReceiptV1",
    "M8FeishuInboundWebhookProfileV1",
    "M8FeishuWebhookIngressRequestV1",
]
