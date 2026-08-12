"""One-shot activated Feishu sandbox runner over the persistent M8 outbox."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from math import ceil

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxActivationStatusV1
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuCardDispatchPreflightV1,
    M8FeishuNotificationCardV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_feishu_outbox import M8FeishuSandboxOutboxRunReceiptV1
from labcourt.contracts.m8_notification_cards import M8NotificationWorkflowManifestAuthorityV1
from labcourt.contracts.m8_notification_dispatch_claims import (
    MAX_M8_NOTIFICATION_DISPATCH_CLAIM_SECONDS,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationDispatchRequestV1,
)
from labcourt.contracts.m8_notifications import M8NotificationChannelKind, M8NotificationStatus
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m8_feishu_activation_repository import M8FeishuActivationRepository
from labcourt.ports.m8_feishu_sandbox_sender import M8FeishuSandboxSender
from labcourt.ports.m8_notification_dispatch_claim_repository import (
    M8NotificationDispatchClaimRepository,
)
from labcourt.ports.m8_notification_repository import M8NotificationRepository


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu {name} must be lowercase SHA-256 hex")
    return value


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu {name} must be timezone-aware UTC")
    return value


class M8FeishuSandboxOutboxRunner:
    """Claim, fence, send, and atomically complete one exact QUEUED version."""

    def __init__(
        self,
        notification_repository: M8NotificationRepository,
        claim_repository: M8NotificationDispatchClaimRepository,
        activation_repository: M8FeishuActivationRepository,
        sender: M8FeishuSandboxSender,
        profile: M8FeishuAdapterProfileV1,
        workflow: M8NotificationWorkflowManifestAuthorityV1,
        clock: Callable[[], datetime],
        preflight_manifest_id: Sha256Hex,
        claim_manifest_id: Sha256Hex,
        call_fence_manifest_id: Sha256Hex,
        completion_manifest_id: Sha256Hex,
        runner_manifest_id: Sha256Hex,
        claim_lease_seconds: int = 60,
    ) -> None:
        if any(
            port is None
            for port in (
                notification_repository,
                claim_repository,
                activation_repository,
                sender,
            )
        ):
            raise TypeError("M8 Feishu outbox runner requires explicit ports")
        if not isinstance(profile, M8FeishuAdapterProfileV1):
            raise TypeError("M8 Feishu outbox runner requires a typed profile")
        if not isinstance(workflow, M8NotificationWorkflowManifestAuthorityV1):
            raise TypeError("M8 Feishu outbox runner requires a typed workflow authority")
        if not callable(clock):
            raise TypeError("M8 Feishu outbox runner requires a clock")
        minimum_lease = ceil(profile.candidate.request_timeout_ms / 1_000) + 1
        if (
            not isinstance(claim_lease_seconds, int)
            or isinstance(claim_lease_seconds, bool)
            or not minimum_lease
            <= claim_lease_seconds
            <= MAX_M8_NOTIFICATION_DISPATCH_CLAIM_SECONDS
        ):
            raise ValueError("M8 Feishu outbox claim lease is outside the bounded window")
        self._notifications = notification_repository
        self._claims = claim_repository
        self._activations = activation_repository
        self._sender = sender
        self._profile = profile
        self._workflow = workflow
        self._clock = clock
        self._preflight_manifest_id = _validate_sha256(
            preflight_manifest_id, "preflight manifest"
        )
        self._claim_manifest_id = _validate_sha256(claim_manifest_id, "claim manifest")
        self._call_fence_manifest_id = _validate_sha256(
            call_fence_manifest_id, "call fence manifest"
        )
        self._completion_manifest_id = _validate_sha256(
            completion_manifest_id, "completion manifest"
        )
        self._runner_manifest_id = _validate_sha256(runner_manifest_id, "runner manifest")
        self._claim_lease_seconds = claim_lease_seconds

    def run_one(
        self,
        notification_id: str,
        recipient_binding: M8FeishuRecipientBindingAuthorityV1,
        worker_owner_token: bytes,
    ) -> M8FeishuSandboxOutboxRunReceiptV1:
        if not isinstance(recipient_binding, M8FeishuRecipientBindingAuthorityV1):
            raise TypeError("M8 Feishu outbox runner requires a typed recipient binding")
        if (
            not isinstance(worker_owner_token, bytes)
            or not 32 <= len(worker_owner_token) <= 256
        ):
            raise ValueError("M8 Feishu outbox worker token must be 32 through 256 bytes")

        before = self._notifications.get_current_notification(notification_id)
        if before.status != M8NotificationStatus.QUEUED:
            raise ConcurrentModification(
                "M8 Feishu outbox runner requires current QUEUED notification"
            )
        queue_transition = before.audit_event.transition_command
        if queue_transition is None:
            raise ConcurrentModification("M8 Feishu outbox runner requires a queue transition")
        plan = before.audit_event.notification_authority.plan
        if plan.target.channel != M8NotificationChannelKind.FEISHU:
            raise ConcurrentModification("M8 Feishu outbox runner requires a FEISHU notification")

        claimed_at = _require_utc(self._clock(), "claim time")
        initial_status = self._activations.get_current_status(
            self._profile.candidate.candidate_authority_id,
            claimed_at,
        )
        self._validate_activation(initial_status, recipient_binding)

        card = M8FeishuNotificationCardV1(
            plan=plan,
            card_renderer_manifest_id=self._workflow.card_renderer_manifest_id,
        )
        card_bytes = card.provider_content_json.encode("utf-8")
        attempt_number = 1 + sum(
            event.transition_command is not None
            and event.transition_command.dispatch_result is not None
            for event in self._notifications.list_notification_audit(notification_id)
        )
        candidate = self._profile.candidate
        capability = M8NotificationChannelCapabilityAuthorityV1(
            adapter_id=candidate.adapter_id,
            adapter_revision=candidate.adapter_revision,
            channel=M8NotificationChannelKind.FEISHU,
            request_timeout_ms=candidate.request_timeout_ms,
            network_required=True,
            offline_capable=False,
            simulated=False,
            inbound_response_supported=True,
            adapter_manifest_id=candidate.adapter_manifest_id,
        )
        request = M8NotificationDispatchRequestV1(
            plan=plan,
            source_notification_version=before.notification_version,
            source_notification_authority_sha256=before.notification_document_sha256,
            attempt_number=attempt_number,
            channel_capability=capability,
            rendered_card_ref=card.raw_card_ref,
            rendered_card_sha256=card.provider_content_sha256,
            dispatched_at=claimed_at,
            timeout_ms=capability.request_timeout_ms,
            idempotency_key=before.notification_id,
            request_manifest_id=self._workflow.dispatch_request_manifest_id,
        )
        preflight = M8FeishuCardDispatchPreflightV1(
            notification_request=request,
            profile=self._profile,
            recipient_binding=recipient_binding,
            card=card,
            preflight_manifest_id=self._preflight_manifest_id,
        )
        claim = self._claims.claim_dispatch(
            request,
            worker_owner_token,
            claimed_at + timedelta(seconds=self._claim_lease_seconds),
            self._claim_manifest_id,
        )

        fenced_at = _require_utc(self._clock(), "call fence time")
        current_status = self._activations.get_current_status(
            candidate.candidate_authority_id,
            fenced_at,
        )
        self._validate_activation(current_status, recipient_binding)
        activation_commit_id = current_status.activation_receipt.activation_commit_id
        if activation_commit_id != initial_status.activation_receipt.activation_commit_id:
            raise ConcurrentModification("M8 Feishu sandbox activation changed after claim")
        fence = self._claims.fence_dispatch_call(
            claim.claim_id,
            worker_owner_token,
            activation_commit_id,
            fenced_at,
            self._call_fence_manifest_id,
        )

        send_receipt = self._sender.send_authorized(
            preflight,
            card_bytes,
            fence.dispatch_authorization_id,
        )
        if (
            send_receipt.preflight != preflight
            or send_receipt.dispatch_result.request != claim.request
            or send_receipt.activation_status.activation_receipt.activation_commit_id
            != fence.dispatch_authorization_id
        ):
            raise ConcurrentModification("M8 Feishu send receipt grafts another authority")
        raw_response = self._sender.read_raw_response(
            send_receipt.dispatch_result.raw_response_ref
        )
        committed_at = _require_utc(self._clock(), "completion time")
        completion = self._claims.complete_dispatch(
            claim.claim_id,
            fence.call_fence_id,
            worker_owner_token,
            send_receipt.dispatch_result,
            (card_bytes, raw_response),
            self._workflow.raw_storage_manifest_id,
            queue_transition.supporting_authorities,
            self._workflow.transition_command_manifest_id,
            self._workflow.audit_manifest_id,
            committed_at,
            self._completion_manifest_id,
        )
        return M8FeishuSandboxOutboxRunReceiptV1(
            claim=claim,
            call_fence=fence,
            send_receipt=send_receipt,
            completion=completion,
            runner_manifest_id=self._runner_manifest_id,
        )

    def _validate_activation(
        self,
        status: M8FeishuSandboxActivationStatusV1,
        recipient_binding: M8FeishuRecipientBindingAuthorityV1,
    ) -> None:
        runtime = status.activation_receipt.runtime_config
        if (
            not status.sandbox_external_call_permitted
            or runtime.profile != self._profile
            or recipient_binding not in runtime.recipient_allowlist
        ):
            raise ConcurrentModification(
                "M8 Feishu sandbox activation does not authorize this profile and recipient"
            )


__all__ = ["M8FeishuSandboxOutboxRunner"]
