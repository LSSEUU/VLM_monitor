"""Strict offline orchestration for Feishu encrypted inbound message evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_inbound import (
    MAX_M8_FEISHU_INBOUND_BODY_BYTES,
    M8FeishuInboundMessageCommitReceiptV1,
    M8FeishuInboundMessageVerificationReceiptV1,
    M8FeishuInboundWebhookProfileV1,
    M8FeishuWebhookIngressRequestV1,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.m8_feishu_inbound_crypto import (
    M8FeishuInboundCrypto,
    M8FeishuInboundCryptoError,
)
from labcourt.ports.m8_feishu_inbound_repository import M8FeishuInboundRepository
from labcourt.ports.m8_feishu_inbound_secrets import M8FeishuInboundSecretResolver


class _EncryptedEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    encrypt: StrictStr


class _EventHeader(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    event_id: StrictStr
    event_type: Literal["im.message.receive_v1"]
    create_time: StrictStr
    token: StrictStr
    app_id: StrictStr
    tenant_key: StrictStr


class _SenderId(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    open_id: StrictStr
    union_id: StrictStr | None = None
    user_id: StrictStr | None = None


class _Sender(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sender_id: _SenderId
    sender_type: Literal["user"]
    tenant_key: StrictStr | None = None


class _Message(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    message_id: StrictStr
    root_id: StrictStr | None = None
    parent_id: StrictStr
    create_time: StrictStr
    chat_id: StrictStr
    chat_type: Literal["p2p"]
    message_type: Literal["text"]
    content: StrictStr
    mentions: list[dict[str, object]] | None = None


class _Event(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sender: _Sender
    message: _Message


class _EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["2.0"] = Field(alias="schema")
    header: _EventHeader
    event: _Event


class _TextContent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    text: StrictStr


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu inbound {name} must be lowercase SHA-256 hex")
    return value


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu inbound {name} must be timezone-aware UTC")
    return value


def _milliseconds_utc(value: str, name: str) -> datetime:
    if not value.isascii() or not value.isdigit() or value.startswith("0") or len(value) > 16:
        raise ContractViolation(f"M8 Feishu inbound {name} is not canonical milliseconds")
    try:
        return datetime.fromtimestamp(int(value) / 1_000, tz=UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise ContractViolation(f"M8 Feishu inbound {name} is outside UTC range") from error


def _artifact_ref(prefix: str, raw: bytes) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    return f"{prefix}{digest[: 64 - len(prefix)]}"


class M8FeishuInboundVerificationService:
    """Verify one exact fixture/request and persist evidence without creating a reply."""

    def __init__(
        self,
        repository: M8FeishuInboundRepository,
        secret_resolver: M8FeishuInboundSecretResolver,
        crypto: M8FeishuInboundCrypto,
        clock: Callable[[], datetime],
        verification_manifest_id: Sha256Hex,
        raw_storage_manifest_id: Sha256Hex,
        commit_manifest_id: Sha256Hex,
    ) -> None:
        if repository is None or secret_resolver is None or crypto is None:
            raise TypeError("M8 Feishu inbound verification requires explicit ports")
        if not callable(clock):
            raise TypeError("M8 Feishu inbound verification requires a clock")
        self._repository = repository
        self._secrets = secret_resolver
        self._crypto = crypto
        self._clock = clock
        self._verification_manifest_id = _validate_sha256(
            verification_manifest_id,
            "verification manifest",
        )
        self._raw_storage_manifest_id = _validate_sha256(
            raw_storage_manifest_id,
            "raw storage manifest",
        )
        self._commit_manifest_id = _validate_sha256(
            commit_manifest_id,
            "commit manifest",
        )

    def verify_and_commit(
        self,
        profile: M8FeishuInboundWebhookProfileV1,
        ingress_request: M8FeishuWebhookIngressRequestV1,
        encrypted_body: bytes,
    ) -> M8FeishuInboundMessageCommitReceiptV1:
        if not isinstance(profile, M8FeishuInboundWebhookProfileV1):
            raise TypeError("M8 Feishu inbound verification requires a typed profile")
        if not isinstance(ingress_request, M8FeishuWebhookIngressRequestV1):
            raise TypeError("M8 Feishu inbound verification requires a typed ingress request")
        if not isinstance(encrypted_body, bytes):
            raise TypeError("M8 Feishu inbound verification requires exact request bytes")
        if ingress_request.inbound_profile_id != profile.inbound_profile_id:
            raise ContractViolation("M8 Feishu inbound request belongs to another profile")
        try:
            request_time = datetime.fromtimestamp(
                ingress_request.request_timestamp_seconds,
                tz=UTC,
            )
        except (OverflowError, OSError, ValueError) as error:
            raise ContractViolation(
                "M8 Feishu inbound request timestamp is outside UTC range"
            ) from error
        if abs(ingress_request.received_at - request_time) > timedelta(
            seconds=profile.request_timestamp_max_skew_seconds
        ):
            raise ContractViolation(
                "M8 Feishu inbound request timestamp is outside the freshness window"
            )
        if (
            not encrypted_body
            or len(encrypted_body) != ingress_request.encrypted_body_size_bytes
            or len(encrypted_body) > profile.raw_body_max_bytes
            or hashlib.sha256(encrypted_body).hexdigest() != ingress_request.encrypted_body_sha256
        ):
            raise ContractViolation("M8 Feishu inbound encrypted request bytes changed")

        with self._secrets.resolve(profile) as secrets:
            encrypt_key = secrets.encrypt_key_bytes()
            verification_token = secrets.verification_token_bytes()
            self._validate_secrets(profile, secrets, encrypt_key, verification_token)
            claimed = ingress_request.request_signature
            calculated = hashlib.sha256(
                str(ingress_request.request_timestamp_seconds).encode("ascii")
                + ingress_request.request_nonce.encode("utf-8")
                + encrypt_key
                + encrypted_body
            ).hexdigest()
            if not hmac.compare_digest(calculated, claimed):
                raise ContractViolation("M8 Feishu inbound request signature is invalid")
            ciphertext = self._parse_encrypted_body(encrypted_body)
            try:
                decrypted_event = self._crypto.decrypt_aes_256_cbc(
                    ciphertext,
                    hashlib.sha256(encrypt_key).digest(),
                )
            except M8FeishuInboundCryptoError as error:
                raise ContractViolation("M8 Feishu inbound event decryption failed") from error
            event, content_bytes = self._parse_event(
                profile,
                verification_token,
                decrypted_event,
            )

        message = event.event.message
        try:
            receipt = M8FeishuInboundMessageVerificationReceiptV1(
                profile=profile,
                ingress_request=ingress_request,
                decrypted_event_ref=_artifact_ref("m8-feishu-decrypted-", decrypted_event),
                decrypted_event_sha256=hashlib.sha256(decrypted_event).hexdigest(),
                decrypted_event_size_bytes=len(decrypted_event),
                provider_event_id=event.header.event_id,
                provider_message_id=message.message_id,
                provider_parent_message_id=message.parent_id,
                provider_root_message_id=message.root_id,
                app_id_sha256=hashlib.sha256(event.header.app_id.encode("utf-8")).hexdigest(),
                tenant_key_sha256=hashlib.sha256(
                    event.header.tenant_key.encode("utf-8")
                ).hexdigest(),
                verification_token_sha256=hashlib.sha256(verification_token).hexdigest(),
                sender_open_id_sha256=hashlib.sha256(
                    event.event.sender.sender_id.open_id.encode("utf-8")
                ).hexdigest(),
                event_created_at=_milliseconds_utc(
                    event.header.create_time,
                    "event create_time",
                ),
                message_created_at=_milliseconds_utc(
                    message.create_time,
                    "message create_time",
                ),
                content_document_ref=_artifact_ref("m8-feishu-content-", content_bytes),
                content_document_sha256=hashlib.sha256(content_bytes).hexdigest(),
                content_size_bytes=len(content_bytes),
                verification_manifest_id=self._verification_manifest_id,
            )
        except ValidationError as error:
            raise ContractViolation("M8 Feishu inbound verified event is invalid") from error
        committed_at = _require_utc(self._clock(), "commit time")
        return self._repository.commit_verification(
            receipt,
            (encrypted_body, decrypted_event, content_bytes),
            self._raw_storage_manifest_id,
            committed_at,
            self._commit_manifest_id,
        )

    @staticmethod
    def _validate_secrets(
        profile: M8FeishuInboundWebhookProfileV1,
        secrets: object,
        encrypt_key: bytes,
        verification_token: bytes,
    ) -> None:
        if (
            getattr(secrets, "inbound_profile_id", None) != profile.inbound_profile_id
            or getattr(secrets, "encrypt_key_reference_id", None)
            != profile.encrypt_key_reference_id
            or getattr(secrets, "verification_token_reference_id", None)
            != profile.verification_token_reference_id
            or not encrypt_key
            or not verification_token
            or not hmac.compare_digest(
                hashlib.sha256(encrypt_key).hexdigest(),
                profile.encrypt_key_sha256,
            )
            or not hmac.compare_digest(
                hashlib.sha256(verification_token).hexdigest(),
                profile.verification_token_sha256,
            )
        ):
            raise ContractViolation("M8 Feishu inbound secret authority mismatch")

    @staticmethod
    def _parse_encrypted_body(encrypted_body: bytes) -> bytes:
        try:
            envelope = _EncryptedEnvelope.model_validate_json(encrypted_body)
            encoded = envelope.encrypt.encode("ascii")
            ciphertext = base64.b64decode(encoded, validate=True)
        except (ValidationError, UnicodeEncodeError, binascii.Error) as error:
            raise ContractViolation("M8 Feishu inbound encrypted envelope is invalid") from error
        if (
            len(ciphertext) < 32
            or len(ciphertext) > MAX_M8_FEISHU_INBOUND_BODY_BYTES
            or (len(ciphertext) - 16) % 16 != 0
        ):
            raise ContractViolation("M8 Feishu inbound ciphertext is outside AES-CBC bounds")
        return ciphertext

    @staticmethod
    def _parse_event(
        profile: M8FeishuInboundWebhookProfileV1,
        verification_token: bytes,
        decrypted_event: bytes,
    ) -> tuple[_EventEnvelope, bytes]:
        if not decrypted_event or len(decrypted_event) > profile.raw_body_max_bytes:
            raise ContractViolation("M8 Feishu inbound decrypted event is outside its bound")
        try:
            event = _EventEnvelope.model_validate_json(decrypted_event)
            content_bytes = event.event.message.content.encode("utf-8")
            _TextContent.model_validate_json(content_bytes)
        except (ValidationError, UnicodeEncodeError) as error:
            raise ContractViolation("M8 Feishu inbound decrypted event is invalid") from error
        if not hmac.compare_digest(event.header.token.encode("utf-8"), verification_token):
            raise ContractViolation("M8 Feishu inbound verification token is invalid")
        app_id_sha256 = hashlib.sha256(event.header.app_id.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(app_id_sha256, profile.outbound_profile.app_id_sha256):
            raise ContractViolation("M8 Feishu inbound event app is invalid")
        if not content_bytes or len(content_bytes) > profile.raw_body_max_bytes:
            raise ContractViolation("M8 Feishu inbound text content is outside its bound")
        return event, content_bytes


__all__ = ["M8FeishuInboundVerificationService"]
