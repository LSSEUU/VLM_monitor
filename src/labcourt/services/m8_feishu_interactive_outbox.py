"""One-shot Feishu notification outbox runner with interactive action cards."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timedelta
from math import ceil
from typing import Protocol

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxRuntimeConfigV1
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuNotificationCardV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_notification_cards import M8NotificationWorkflowManifestAuthorityV1
from labcourt.contracts.m8_notification_dispatch_claims import (
    M8NotificationDispatchCompletionReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationChannelFailureCode,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationChannelKind,
    M8NotificationPurpose,
    M8NotificationStatus,
)
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m8_feishu_activation_repository import M8FeishuActivationRepository
from labcourt.ports.m8_feishu_http import M8FeishuHttpError, M8FeishuHttpResponse
from labcourt.ports.m8_feishu_secrets import (
    M8FeishuResolvedSecrets,
    M8FeishuSecretResolver,
)
from labcourt.ports.m8_notification_dispatch_claim_repository import (
    M8NotificationDispatchClaimRepository,
)
from labcourt.ports.m8_notification_repository import M8NotificationRepository
from labcourt.services.m8_feishu_action_cards import M8FeishuActionCardService


class _LiveHttp(Protocol):
    def acquire_tenant_access_token(
        self,
        profile: M8FeishuAdapterProfileV1,
        secrets: M8FeishuResolvedSecrets,
    ) -> M8FeishuHttpResponse: ...

    def send_personal_demo_card(
        self,
        open_id: bytes,
        tenant_access_token: bytes,
        provider_uuid: str,
        rendered_card: bytes,
        timeout_ms: int,
    ) -> M8FeishuHttpResponse: ...


class M8FeishuInteractiveOutboxRunner:
    """Reuse notification claim/fence/completion and perform exactly one provider attempt."""

    def __init__(
        self,
        notifications: M8NotificationRepository,
        claims: M8NotificationDispatchClaimRepository,
        activations: M8FeishuActivationRepository,
        secrets: M8FeishuSecretResolver,
        http: _LiveHttp,
        profile: M8FeishuAdapterProfileV1,
        workflow: M8NotificationWorkflowManifestAuthorityV1,
        action_cards: M8FeishuActionCardService,
        clock: Callable[[], datetime],
        claim_manifest_id: Sha256Hex,
        call_fence_manifest_id: Sha256Hex,
        completion_manifest_id: Sha256Hex,
        result_manifest_id: Sha256Hex,
    ) -> None:
        self._notifications = notifications
        self._claims = claims
        self._activations = activations
        self._secrets = secrets
        self._http = http
        self._profile = profile
        self._workflow = workflow
        self._action_cards = action_cards
        self._clock = clock
        self._claim_manifest = claim_manifest_id
        self._fence_manifest = call_fence_manifest_id
        self._completion_manifest = completion_manifest_id
        self._result_manifest = result_manifest_id

    def run_one(
        self,
        notification_id: str,
        binding: M8FeishuRecipientBindingAuthorityV1,
        worker_token: bytes,
    ) -> M8NotificationDispatchCompletionReceiptV1:
        current = self._notifications.get_current_notification(notification_id)
        if current.status != M8NotificationStatus.QUEUED:
            raise ConcurrentModification("Feishu interactive outbox requires QUEUED")
        plan = current.audit_event.notification_authority.plan
        if plan.target.channel != M8NotificationChannelKind.FEISHU:
            raise ConcurrentModification("Feishu interactive outbox requires FEISHU target")
        card = self._render(notification_id, plan.purpose)
        now = self._clock()
        capability = M8NotificationChannelCapabilityAuthorityV1(
            adapter_id=self._profile.candidate.adapter_id,
            adapter_revision=self._profile.candidate.adapter_revision,
            channel=M8NotificationChannelKind.FEISHU,
            request_timeout_ms=self._profile.candidate.request_timeout_ms,
            network_required=True,
            offline_capable=False,
            simulated=False,
            inbound_response_supported=True,
            adapter_manifest_id=self._profile.candidate.adapter_manifest_id,
        )
        request = M8NotificationDispatchRequestV1(
            plan=plan,
            source_notification_version=current.notification_version,
            source_notification_authority_sha256=current.notification_document_sha256,
            attempt_number=1,
            channel_capability=capability,
            rendered_card_ref=f"m8-feishu-live-card-{hashlib.sha256(card).hexdigest()[:24]}",
            rendered_card_sha256=hashlib.sha256(card).hexdigest(),
            dispatched_at=now,
            timeout_ms=capability.request_timeout_ms,
            idempotency_key=current.notification_id,
            request_manifest_id=self._workflow.dispatch_request_manifest_id,
        )
        lease_seconds = ceil(request.timeout_ms / 1_000) + 5
        claim = self._claims.claim_dispatch(
            request,
            worker_token,
            now + timedelta(seconds=lease_seconds),
            self._claim_manifest,
        )
        status = self._activations.get_current_status(
            self._profile.candidate.candidate_authority_id, self._clock()
        )
        runtime = status.activation_receipt.runtime_config
        if (
            not status.sandbox_external_call_permitted
            or runtime.profile != self._profile
            or binding not in runtime.recipient_allowlist
            or binding.binding_authority_id
            != self._binding_for_plan(plan.target.external_subject_binding_sha256, runtime)
        ):
            raise ConcurrentModification("Feishu interactive activation or recipient changed")
        fence = self._claims.fence_dispatch_call(
            claim.claim_id,
            worker_token,
            status.activation_receipt.activation_commit_id,
            self._clock(),
            self._fence_manifest,
        )
        result, raw = self._send(request, binding, card)
        transition = current.audit_event.transition_command
        if transition is None:
            raise ConcurrentModification("Feishu interactive queue transition is absent")
        return self._claims.complete_dispatch(
            claim.claim_id,
            fence.call_fence_id,
            worker_token,
            result,
            (card, raw),
            self._workflow.raw_storage_manifest_id,
            transition.supporting_authorities,
            self._workflow.transition_command_manifest_id,
            self._workflow.audit_manifest_id,
            self._clock(),
            self._completion_manifest,
        )

    def _render(self, notification_id: str, purpose: M8NotificationPurpose) -> bytes:
        if purpose == M8NotificationPurpose.CASE_ACTION_REQUIRED:
            return self._action_cards.render_initial_alert(notification_id)[0]
        current = self._notifications.get_current_notification(notification_id)
        card = M8FeishuNotificationCardV1(
            plan=current.audit_event.notification_authority.plan,
            card_renderer_manifest_id=self._workflow.card_renderer_manifest_id,
        )
        return card.provider_content_json.encode("utf-8")

    def _send(
        self,
        request: M8NotificationDispatchRequestV1,
        binding: M8FeishuRecipientBindingAuthorityV1,
        card: bytes,
    ) -> tuple[M8NotificationDispatchResultV1, bytes]:
        raw: bytes
        disposition: M8NotificationDispatchDisposition
        failure: M8NotificationChannelFailureCode | None
        provider_id: str | None = None
        with self._secrets.resolve(self._profile, binding) as resolved:
            try:
                token_response = self._http.acquire_tenant_access_token(self._profile, resolved)
            except M8FeishuHttpError as error:
                raw = self._error_raw(error)
                disposition = M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
                failure = M8NotificationChannelFailureCode.CHANNEL_UNAVAILABLE
            else:
                token, redacted = self._token(token_response.body)
                if token is None:
                    raw = redacted
                    disposition = M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
                    failure = M8NotificationChannelFailureCode.RECEIPT_INVALID
                else:
                    try:
                        response = self._http.send_personal_demo_card(
                            resolved.open_id_bytes(),
                            token,
                            request.idempotency_key[:50],
                            card,
                            request.timeout_ms,
                        )
                    except M8FeishuHttpError as error:
                        raw = self._combined_raw(redacted, self._error_raw(error))
                        disposition = M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
                        failure = M8NotificationChannelFailureCode.UNKNOWN_DELIVERY
                    else:
                        raw = self._combined_raw(redacted, response.body)
                        code, provider_id = self._message(response.body)
                        if response.status_code == 200 and code == 0 and provider_id is not None:
                            disposition = M8NotificationDispatchDisposition.ACCEPTED
                            failure = None
                        else:
                            disposition = M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
                            failure = M8NotificationChannelFailureCode.CHANNEL_REJECTED
        digest = hashlib.sha256(raw).hexdigest()
        result = M8NotificationDispatchResultV1(
            request=request,
            disposition=disposition,
            provider_receipt_id=provider_id,
            raw_response_ref=f"m8-feishu-live-response-{digest[:24]}",
            raw_response_sha256=digest,
            failure_code=failure,
            completed_at=self._clock(),
            result_manifest_id=self._result_manifest,
        )
        return result, raw

    @staticmethod
    def _token(raw: bytes) -> tuple[bytes | None, bytes]:
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, b'{"token_response":"invalid"}'
        if not isinstance(payload, dict):
            return None, b'{"token_response":"invalid"}'
        token = payload.pop("tenant_access_token", None)
        if isinstance(token, str):
            payload["tenant_access_token_sha256"] = hashlib.sha256(token.encode()).hexdigest()
        redacted = canonical_json(payload).encode()
        if payload.get("code") != 0 or not isinstance(token, str) or not token:
            return None, redacted
        return token.encode(), redacted

    @staticmethod
    def _message(raw: bytes) -> tuple[int | None, str | None]:
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, None
        if not isinstance(payload, dict):
            return None, None
        code = payload.get("code")
        data = payload.get("data")
        message_id = data.get("message_id") if isinstance(data, dict) else None
        return (
            code if isinstance(code, int) and not isinstance(code, bool) else None,
            message_id if isinstance(message_id, str) and message_id else None,
        )

    @staticmethod
    def _combined_raw(token: bytes, message: bytes) -> bytes:
        return canonical_json(
            {
                "token_response_redacted": token.decode("utf-8", errors="replace"),
                "message_response": message.decode("utf-8", errors="replace"),
            }
        ).encode()

    @staticmethod
    def _error_raw(error: M8FeishuHttpError) -> bytes:
        return canonical_json(
            {
                "stage": error.stage,
                "failure_code": error.failure_code,
                "delivery_certainty": error.delivery_certainty,
            }
        ).encode()

    @staticmethod
    def _binding_for_plan(subject_sha256: str, runtime: M8FeishuSandboxRuntimeConfigV1) -> str:
        allowlist = runtime.recipient_allowlist
        matching = [
            item.binding_authority_id
            for item in allowlist
            if item.receive_id_sha256 == subject_sha256 and item.active
        ]
        if len(matching) != 1:
            raise ConcurrentModification("Feishu target does not resolve uniquely")
        return matching[0]


__all__ = ["M8FeishuInteractiveOutboxRunner"]
