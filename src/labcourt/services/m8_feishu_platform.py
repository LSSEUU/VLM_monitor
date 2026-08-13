"""Secret-free façade over existing Feishu commissioning, activation, and audit authority."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from datetime import datetime

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import (
    M8CommissioningReadiness,
    M8ProductionAdapterKind,
)
from labcourt.contracts.m8_feishu_personal_demo import (
    M8FeishuPersonalDemoOutcome,
    M8FeishuPersonalDemoProbeReceiptV1,
    M8FeishuPersonalDemoProbeV1,
)
from labcourt.contracts.m8_feishu_platform import (
    M8FeishuInboundDisplayStatus,
    M8FeishuLastAuditedAttemptV1,
    M8FeishuPlatformDisplayStatus,
    M8FeishuPlatformStatusV1,
    M8FeishuTestCardCheckReceiptV1,
    M8FeishuTestCardCheckRequestV1,
)
from labcourt.contracts.m8_notifications import M8NotificationChannelKind
from labcourt.exceptions import EvidenceMissing
from labcourt.ports.m8_adapter_commissioning_repository import (
    M8AdapterCommissioningRepository,
)
from labcourt.ports.m8_feishu_activation_repository import M8FeishuActivationRepository
from labcourt.ports.m8_feishu_inbound_activation_repository import (
    M8FeishuInboundActivationRepository,
)
from labcourt.ports.m8_notification_repository import M8NotificationRepository
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService
from labcourt.services.m8_operations_api import M8ApiServiceError, M8ApiServiceFailureCode


class M8FeishuPlatformService:
    def __init__(
        self,
        commissioning_repository: M8AdapterCommissioningRepository,
        readiness_service: M8AdapterReadinessService,
        activation_repository: M8FeishuActivationRepository,
        inbound_activation_repository: M8FeishuInboundActivationRepository,
        notification_repository: M8NotificationRepository,
        operations_actor_id: str,
        clock: Callable[[], datetime],
        probe_manifest_id: Sha256Hex,
    ) -> None:
        if any(
            item is None
            for item in (
                commissioning_repository,
                readiness_service,
                activation_repository,
                inbound_activation_repository,
                notification_repository,
            )
        ) or not callable(clock):
            raise TypeError("M8 Feishu platform façade requires existing typed ports")
        self._commissioning = commissioning_repository
        self._readiness = readiness_service
        self._activations = activation_repository
        self._inbound = inbound_activation_repository
        self._notifications = notification_repository
        self._operations_actor_id = operations_actor_id
        self._clock = clock
        self._probe_manifest_id = probe_manifest_id

    def status(self) -> M8FeishuPlatformStatusV1:
        assessed_at = self._clock()
        candidate = next(
            (
                receipt.candidate
                for receipt in self._commissioning.list_candidates(1_000)
                if receipt.candidate.adapter_kind == M8ProductionAdapterKind.EXTERNAL_NOTIFICATION
                and receipt.candidate.provider_id == "feishu-open-platform"
            ),
            None,
        )
        if candidate is None:
            return M8FeishuPlatformStatusV1(
                display_status=M8FeishuPlatformDisplayStatus.NOT_CONFIGURED,
                assessed_at=assessed_at,
                test_card_check_available=False,
                external_call_permitted=False,
            )
        readiness = self._readiness.assess(
            candidate.candidate_authority_id,
            self._operations_actor_id,
            assessed_at,
        )
        activation = None
        with suppress(EvidenceMissing):
            activation = self._activations.get_current_status(
                candidate.candidate_authority_id,
                assessed_at,
            )
        display = (
            M8FeishuPlatformDisplayStatus.READINESS_BLOCKED
            if readiness.readiness == M8CommissioningReadiness.BLOCKED
            else M8FeishuPlatformDisplayStatus.READY_NOT_ACTIVE
        )
        activation_revision = None
        activation_status_id = None
        recipients = 0
        external_permitted = False
        if activation is not None:
            activation_revision = activation.activation_receipt.activation_revision
            # The repository status receipt includes ``assessed_at`` and is
            # therefore different on every read.  Exposing that transient hash
            # as an HTTP action fence makes a GET followed by a POST
            # impossible: the POST necessarily recomputes another status ID.
            # Fence user actions with the immutable activation commit instead;
            # every action still recomputes current actors, commissioning and
            # recipient authority before accepting the commit ID.
            activation_status_id = activation.activation_receipt.activation_commit_id
            recipients = len(activation.activation_receipt.runtime_config.recipient_allowlist)
            display = {
                "REVOKED": M8FeishuPlatformDisplayStatus.REVOKED,
                "INVALIDATED": M8FeishuPlatformDisplayStatus.INVALIDATED,
                "SANDBOX_ACTIVE": M8FeishuPlatformDisplayStatus.ACTIVE,
            }[activation.activation_state]
            external_permitted = activation.sandbox_external_call_permitted
        inbound_status = M8FeishuInboundDisplayStatus.NOT_CONFIGURED
        inbound_status_id = None
        try:
            inbound = self._inbound.get_current_inbound_status(
                candidate.candidate_authority_id,
                assessed_at,
            )
        except EvidenceMissing:
            pass
        else:
            inbound_status = {
                "REVOKED": M8FeishuInboundDisplayStatus.REVOKED,
                "INVALIDATED": M8FeishuInboundDisplayStatus.INVALIDATED,
                "SANDBOX_INBOUND_ACTIVE": M8FeishuInboundDisplayStatus.ACTIVE,
            }[inbound.activation_state]
            inbound_status_id = inbound.activation_receipt.activation_commit_id
        return M8FeishuPlatformStatusV1(
            display_status=display,
            candidate_authority_id=candidate.candidate_authority_id,
            readiness=readiness.readiness,
            readiness_assessment_id=readiness.assessment_id,
            missing_evidence_kinds=readiness.missing_evidence_kinds,
            failed_evidence_kinds=readiness.failed_evidence_kinds,
            expired_evidence_kinds=readiness.expired_evidence_kinds,
            activation_revision=activation_revision,
            activation_status_id=activation_status_id,
            recipient_binding_count=recipients,
            inbound_status=inbound_status,
            inbound_status_id=inbound_status_id,
            last_audited_attempt=self._last_audited_attempt(),
            assessed_at=assessed_at,
            test_card_check_available=external_permitted,
            external_call_permitted=external_permitted,
        )

    def check_test_card(
        self,
        request: M8FeishuTestCardCheckRequestV1,
    ) -> M8FeishuTestCardCheckReceiptV1:
        if not isinstance(request, M8FeishuTestCardCheckRequestV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        current = self.status()
        if (
            current.display_status != M8FeishuPlatformDisplayStatus.ACTIVE
            or current.activation_revision != request.activation_revision
            or current.activation_status_id != request.activation_status_id
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        assert current.candidate_authority_id is not None
        assessed_at = current.assessed_at
        activation = self._activations.get_current_status(
            current.candidate_authority_id,
            assessed_at,
        )
        config = activation.activation_receipt.runtime_config
        binding = config.recipient_allowlist[0]
        probe = M8FeishuPersonalDemoProbeV1(
            app_id_sha256=config.profile.app_id_sha256,
            recipient_open_id_sha256=binding.receive_id_sha256,
            requested_at=assessed_at,
            timeout_ms=min(config.profile.candidate.request_timeout_ms, 10_000),
            probe_manifest_id=self._probe_manifest_id,
        )
        receipt = M8FeishuPersonalDemoProbeReceiptV1(
            probe=probe,
            outcome=M8FeishuPersonalDemoOutcome.CHECKED,
            completed_at=assessed_at,
            token_call_attempted=False,
            message_call_attempted=False,
        )
        return M8FeishuTestCardCheckReceiptV1(
            activation_revision=request.activation_revision,
            activation_status_id=request.activation_status_id,
            probe_receipt=receipt,
        )

    def _last_audited_attempt(self) -> M8FeishuLastAuditedAttemptV1 | None:
        for snapshot_attempt in range(2):
            try:
                return self._scan_last_audited_attempt()
            except EvidenceMissing:
                if snapshot_attempt:
                    raise
        raise AssertionError("bounded Feishu audit reread did not return")

    def _scan_last_audited_attempt(self) -> M8FeishuLastAuditedAttemptV1 | None:
        attempts: list[M8FeishuLastAuditedAttemptV1] = []
        for current in self._notifications.list_current_notifications(20_000):
            plan = current.audit_event.notification_authority.plan
            if plan.target.channel != M8NotificationChannelKind.FEISHU:
                continue
            for event in self._notifications.list_notification_audit(current.notification_id):
                command = event.transition_command
                result = command.dispatch_result if command is not None else None
                if result is None:
                    continue
                attempts.append(
                    M8FeishuLastAuditedAttemptV1(
                        notification_id=current.notification_id,
                        notification_version=event.notification_authority.notification_version,
                        dispatch_request_id=result.request.dispatch_request_id,
                        dispatch_result_id=result.dispatch_result_id,
                        disposition=result.disposition,
                        completed_at=result.completed_at,
                        raw_response_ref=result.raw_response_ref,
                        audit_event_id=event.audit_event_id,
                    )
                )
        if not attempts:
            return None
        return max(attempts, key=lambda item: (item.completed_at, item.dispatch_result_id))


__all__ = ["M8FeishuPlatformService"]
