"""Activation-gated, single-attempt delivery worker for Feishu Agent replies."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_live import (
    M8FeishuAgentReplyCompletionV1,
    M8FeishuLiveFailureCode,
)
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.ports.m8_feishu_activation_repository import M8FeishuActivationRepository
from labcourt.ports.m8_feishu_http import M8FeishuHttpError, M8FeishuHttpResponse
from labcourt.ports.m8_feishu_live import M8FeishuAgentReplyClaim, M8FeishuLiveRepository
from labcourt.ports.m8_feishu_secrets import M8FeishuResolvedSecrets, M8FeishuSecretResolver


class _ReplyHttpTransport(Protocol):
    def acquire_tenant_access_token(
        self,
        profile: M8FeishuAdapterProfileV1,
        secrets: M8FeishuResolvedSecrets,
    ) -> M8FeishuHttpResponse: ...

    def send_text_reply(
        self,
        profile: M8FeishuAdapterProfileV1,
        tenant_access_token: bytes,
        reply_to_provider_message_id: str,
        provider_uuid: str,
        text: str,
        timeout_ms: int,
    ) -> M8FeishuHttpResponse: ...


class _TokenWire(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    code: StrictInt
    msg: StrictStr | None = None
    tenant_access_token: StrictStr | None = None
    expire: StrictInt | None = None


class _MessageData(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    message_id: StrictStr


class _MessageWire(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    code: StrictInt
    msg: StrictStr | None = None
    data: _MessageData | None = None


class M8FeishuAgentReplyDeliveryWorker:
    """Consume one claimed reply and never retry uncertain delivery."""

    def __init__(
        self,
        repository: M8FeishuLiveRepository,
        activations: M8FeishuActivationRepository,
        secrets: M8FeishuSecretResolver,
        http: _ReplyHttpTransport,
        profile: M8FeishuAdapterProfileV1,
        binding_resolver: Callable[[str], M8FeishuRecipientBindingAuthorityV1],
        clock: Callable[[], datetime],
        completion_manifest_id: Sha256Hex,
        timeout_ms: int = 10_000,
    ) -> None:
        self._repository = repository
        self._activations = activations
        self._secrets = secrets
        self._http = http
        self._profile = profile
        self._binding_resolver = binding_resolver
        self._clock = clock
        self._completion_manifest_id = completion_manifest_id
        self._timeout_ms = timeout_ms

    def run_one(self, worker_token: bytes) -> M8FeishuAgentReplyCompletionV1 | None:
        if not 32 <= len(worker_token) <= 256:
            raise ValueError("M8 Feishu Agent reply worker token length is invalid")
        claim = self._repository.claim_agent_reply(hashlib.sha256(worker_token).hexdigest())
        if claim is None:
            return None
        envelope = claim.envelope
        try:
            binding = self._binding_resolver(envelope.recipient_binding_authority_id)
            if binding.binding_authority_id != envelope.recipient_binding_authority_id:
                raise ValueError("M8 Feishu Agent reply binding authority changed")
            status = self._activations.get_current_status(
                self._profile.candidate.candidate_authority_id, self._clock()
            )
            runtime = status.activation_receipt.runtime_config
            if (
                not status.sandbox_external_call_permitted
                or runtime.profile != self._profile
                or binding not in runtime.recipient_allowlist
            ):
                raise ValueError("M8 Feishu Agent reply activation is not current")
            with self._secrets.resolve(self._profile, binding) as resolved:
                if (
                    resolved.profile_id != self._profile.profile_id
                    or resolved.binding_authority_id != binding.binding_authority_id
                ):
                    raise ValueError("M8 Feishu Agent reply secret lease changed authority")
                token_response = self._http.acquire_tenant_access_token(self._profile, resolved)
                token_wire = _TokenWire.model_validate_json(token_response.body)
                if (
                    token_response.status_code != 200
                    or token_wire.code != 0
                    or token_wire.tenant_access_token is None
                ):
                    return self._complete_failure(
                        claim,
                        M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                        M8FeishuLiveFailureCode.WORKER_UNAVAILABLE,
                        self._redacted_token_response(token_response.body),
                    )
                response = self._http.send_text_reply(
                    self._profile,
                    token_wire.tenant_access_token.encode("utf-8"),
                    envelope.reply_to_provider_message_id,
                    envelope.outbox_id[:50],
                    claim.content.decode("utf-8", errors="strict"),
                    self._timeout_ms,
                )
            return self._complete_response(claim, response)
        except M8FeishuHttpError as error:
            disposition = (
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
                if error.stage.value == "TOKEN"
                else M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
            )
            failure = (
                M8FeishuLiveFailureCode.WORKER_UNAVAILABLE
                if disposition == M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
                else M8FeishuLiveFailureCode.SEND_UNCERTAIN
            )
            return self._complete_failure(
                claim,
                disposition,
                failure,
                canonical_json(
                    {
                        "stage": error.stage,
                        "failure_code": error.failure_code,
                        "delivery_certainty": error.delivery_certainty,
                    }
                ).encode(),
            )
        except (UnicodeDecodeError, ValidationError, ValueError):
            return self._complete_failure(
                claim,
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                M8FeishuLiveFailureCode.WORKER_UNAVAILABLE,
                b'{"failure":"authority_or_response_invalid"}',
            )

    def _complete_response(
        self, claim: M8FeishuAgentReplyClaim, response: M8FeishuHttpResponse
    ) -> M8FeishuAgentReplyCompletionV1:
        try:
            wire = _MessageWire.model_validate_json(response.body)
        except ValidationError:
            return self._complete_failure(
                claim,
                M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
                M8FeishuLiveFailureCode.SEND_UNCERTAIN,
                response.body,
            )
        if response.status_code == 200 and wire.code == 0 and wire.data is not None:
            return self._commit(
                claim,
                M8NotificationDispatchDisposition.ACCEPTED,
                None,
                response.body,
                wire.data.message_id,
            )
        return self._complete_failure(
            claim,
            M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
            M8FeishuLiveFailureCode.SEND_REJECTED,
            response.body,
        )

    def _complete_failure(
        self,
        claim: M8FeishuAgentReplyClaim,
        disposition: M8NotificationDispatchDisposition,
        failure: M8FeishuLiveFailureCode,
        raw_response: bytes,
    ) -> M8FeishuAgentReplyCompletionV1:
        return self._commit(claim, disposition, failure, raw_response, None)

    def _commit(
        self,
        claim: M8FeishuAgentReplyClaim,
        disposition: M8NotificationDispatchDisposition,
        failure: M8FeishuLiveFailureCode | None,
        raw_response: bytes,
        provider_message_id: str | None,
    ) -> M8FeishuAgentReplyCompletionV1:
        digest = hashlib.sha256(raw_response).hexdigest()
        completion = M8FeishuAgentReplyCompletionV1(
            envelope=claim.envelope,
            disposition=disposition,
            provider_message_id=provider_message_id,
            failure_code=failure,
            completed_at=self._clock(),
            raw_response_ref=f"feishu-agent-reply-response-{digest[:24]}",
            raw_response_sha256=digest,
            completion_manifest_id=self._completion_manifest_id,
        )
        self._repository.complete_agent_reply(claim, completion, raw_response)
        return completion

    @staticmethod
    def _redacted_token_response(raw: bytes) -> bytes:
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return b'{"token_response":"invalid"}'
        if isinstance(payload, dict) and isinstance(payload.get("tenant_access_token"), str):
            token = payload.pop("tenant_access_token")
            payload["tenant_access_token_sha256"] = hashlib.sha256(token.encode()).hexdigest()
        return canonical_json(payload).encode()


__all__ = ["M8FeishuAgentReplyDeliveryWorker"]
