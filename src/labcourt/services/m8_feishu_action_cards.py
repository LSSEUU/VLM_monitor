"""Two-stage Feishu acknowledgement and case-action cards."""

# ruff: noqa: RUF001 - Chinese product copy intentionally uses full-width punctuation.

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from datetime import datetime, timedelta

from labcourt.contracts.canonical import canonical_bytes, canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8OperationalCaseAction,
    M8OperationalCaseReasonCode,
)
from labcourt.contracts.m8_api import M8ApiCaseTransitionRequestV1
from labcourt.contracts.m8_case_persistence import (
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.m8_feishu_live import (
    M8FeishuCardActionIntentV1,
    M8FeishuCardActionReceiptV1,
    M8FeishuCardStage,
    M8FeishuLiveFailureCode,
)
from labcourt.contracts.m8_feishu_notification import M8FeishuRecipientBindingAuthorityV1
from labcourt.contracts.m8_feishu_platform import (
    M8FeishuPlatformDisplayStatus,
    M8FeishuPlatformStatusV1,
)
from labcourt.contracts.m8_notification_persistence import M8NotificationCommitReceiptV1
from labcourt.contracts.m8_notifications import M8NotificationStatus
from labcourt.exceptions import ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_feishu_live import M8FeishuLiveRepository
from labcourt.ports.m8_notification_repository import M8NotificationRepository
from labcourt.services.m8_notifications import M8NotificationService
from labcourt.services.m8_operations_api import M8ApiServiceError, M8OperationsApiService

_REASON_BY_ACTION = {
    M8OperationalCaseAction.CONFIRM: M8OperationalCaseReasonCode.VERIFIED_VIOLATION,
    M8OperationalCaseAction.REJECT: M8OperationalCaseReasonCode.FALSE_POSITIVE,
    M8OperationalCaseAction.REQUEST_EVIDENCE: (
        M8OperationalCaseReasonCode.MORE_EVIDENCE_REQUIRED
    ),
}
_SUMMARY_BY_ACTION = {
    M8OperationalCaseAction.CONFIRM: "值班安全管理员通过飞书双重确认核实事件。",
    M8OperationalCaseAction.REJECT: "值班安全管理员通过飞书双重确认判定为误报。",
    M8OperationalCaseAction.REQUEST_EVIDENCE: "值班安全管理员通过飞书请求补充证据。",
}
_LABEL_BY_ACTION = {
    M8OperationalCaseAction.CONFIRM: "确认事件",
    M8OperationalCaseAction.REJECT: "误报驳回",
    M8OperationalCaseAction.REQUEST_EVIDENCE: "请求补充证据",
}


class M8FeishuActionCardService:
    """Keep opaque tokens outside Qwen and execute only bounded local transitions."""

    def __init__(
        self,
        live_repository: M8FeishuLiveRepository,
        notification_repository: M8NotificationRepository,
        notification_service: M8NotificationService,
        operations: M8OperationsApiService,
        case_reader: Callable[[str], M8OperationalCaseCommitReceiptV1],
        platform_status: Callable[[], M8FeishuPlatformStatusV1],
        sender_binding: Callable[[str], M8FeishuRecipientBindingAuthorityV1],
        actor_authority: Callable[[str], M8ActorAuthorityCommitReceiptV1],
        clock: Callable[[], datetime],
        token_key: bytes,
        intent_manifest_id: Sha256Hex,
        command_manifest_id: Sha256Hex,
    ) -> None:
        if len(token_key) < 32:
            raise ValueError("M8 Feishu card token key must contain at least 32 bytes")
        self._live = live_repository
        self._notifications = notification_repository
        self._notification_service = notification_service
        self._operations = operations
        self._case_reader = case_reader
        self._platform_status = platform_status
        self._sender_binding = sender_binding
        self._actor_authority = actor_authority
        self._clock = clock
        self._token_key = token_key
        self._intent_manifest = intent_manifest_id
        self._command_manifest = command_manifest_id

    def render_initial_alert(
        self, notification_id: str
    ) -> tuple[bytes, M8FeishuCardActionIntentV1]:
        notification = self._notifications.get_current_notification(notification_id)
        case = self._case(notification)
        token = self._token("ACK", notification.notification_id, notification.notification_version)
        intent = self._intent(notification, case, token, None, M8FeishuCardStage.AWAITING_ACK)
        self._live.commit_card_intent(intent)
        card = self._card(
            "安全告警 · 待接手",
            notification,
            (
                self._button("查看案件", "default", None, case.case_id),
                self._button("确认接手", "primary", token, None),
            ),
        )
        return canonical_json(card).encode("utf-8"), intent

    def execute(self, opaque_token: str, sender_open_id_sha256: str) -> dict[str, object]:
        token_sha256 = hashlib.sha256(opaque_token.encode()).hexdigest()
        intent = self._live.card_intent_for_token(token_sha256)
        if intent is None:
            return self._toast("error", "操作令牌无效或已失效")
        previous = self._live.card_receipt(intent.intent_id)
        if previous is not None:
            return self._toast("info", "该操作已经处理")
        if self._clock() > intent.expires_at:
            self._stale(intent, M8FeishuLiveFailureCode.CARD_EXPIRED)
            return self._toast("error", "操作已超过十分钟，请刷新状态")
        try:
            actor = self._validate_sender(intent, sender_open_id_sha256)
            if intent.stage == M8FeishuCardStage.AWAITING_ACK:
                return self._acknowledge(intent, actor)
            if intent.stage == M8FeishuCardStage.ACTIONS_AVAILABLE:
                return self._confirm_action(intent)
            return self._execute_case_action(intent, actor)
        except (ConcurrentModification, EvidenceMissing, M8ApiServiceError, ValueError):
            self._stale(intent, M8FeishuLiveFailureCode.VERSION_CONFLICT)
            return self._toast("error", "状态已变化，请在平台查看最新结果")

    def _acknowledge(
        self,
        intent: M8FeishuCardActionIntentV1,
        actor: M8ActorAuthorityCommitReceiptV1,
    ) -> dict[str, object]:
        notification = self._notifications.get_current_notification(intent.notification_id)
        self._require_source_notification(intent, notification, allow_dispatch_progress=True)
        case = self._case(notification)
        acknowledged = self._notification_service.acknowledge(
            notification.notification_id,
            actor.authority.actor_id,
            self._clock(),
            case.audit_event.case_authority.create_command.trigger_authorities,
        )
        buttons = []
        for action in _REASON_BY_ACTION:
            token = self._token(
                "CASE_ACTION",
                acknowledged.notification_id,
                acknowledged.notification_version,
                case.case_id,
                case.case_version,
                action,
            )
            action_intent = self._intent(
                acknowledged,
                case,
                token,
                action,
                M8FeishuCardStage.ACTIONS_AVAILABLE,
            )
            self._live.commit_card_intent(action_intent)
            buttons.append(self._button(_LABEL_BY_ACTION[action], "default", token, None))
        card = self._card("安全告警 · 已接手", acknowledged, tuple(buttons))
        result = self._toast("success", "已确认接手，案件操作仍需再次确认")
        result["card"] = card
        return result

    def _confirm_action(self, intent: M8FeishuCardActionIntentV1) -> dict[str, object]:
        if intent.action is None:
            raise ValueError("M8 Feishu selected action is absent")
        notification = self._notifications.get_current_notification(intent.notification_id)
        self._require_source_notification(intent, notification, allow_dispatch_progress=False)
        case = self._case(notification)
        if (
            case.case_version != intent.case_version
            or case.case_document_sha256 != intent.case_authority_sha256
        ):
            raise ConcurrentModification("case authority changed before confirmation")
        token = self._token("EXECUTE", intent.intent_id, intent.action)
        final_intent = self._intent(
            notification,
            case,
            token,
            intent.action,
            M8FeishuCardStage.AWAITING_CONFIRMATION,
        )
        self._live.commit_card_intent(final_intent)
        card = self._card(
            "请确认最终操作",
            notification,
            (
                self._button(
                    f"确认执行：{_LABEL_BY_ACTION[intent.action]}",
                    "primary",
                    token,
                    None,
                ),
            ),
        )
        result = self._toast("info", "请再次确认，状态变化后操作会自动失效")
        result["card"] = card
        return result

    def _execute_case_action(
        self,
        intent: M8FeishuCardActionIntentV1,
        actor: M8ActorAuthorityCommitReceiptV1,
    ) -> dict[str, object]:
        if intent.action is None:
            raise ValueError("M8 Feishu final action is absent")
        notification = self._notifications.get_current_notification(intent.notification_id)
        self._require_source_notification(intent, notification, allow_dispatch_progress=False)
        if notification.status != M8NotificationStatus.ACKNOWLEDGED:
            raise ConcurrentModification("notification acknowledgement changed")
        case = self._case(notification)
        if (
            case.case_version != intent.case_version
            or case.case_document_sha256 != intent.case_authority_sha256
        ):
            raise ConcurrentModification("case authority changed")
        authority = case.audit_event.case_authority
        request = M8ApiCaseTransitionRequestV1(
            source_case_version=case.case_version,
            source_case_authority_sha256=case.case_document_sha256,
            source_status=case.status,
            case_location_id=authority.location_id,
            subject_actor_id=authority.subject_actor_id,
            action=intent.action,
            reason_code=_REASON_BY_ACTION[intent.action],
            reason_summary=_SUMMARY_BY_ACTION[intent.action],
            supporting_authorities=authority.create_command.trigger_authorities,
            explicit_human_confirmation=True,
            command_manifest_id=self._command_manifest,
        )
        committed = self._operations.transition_case_with_authority(
            actor, case.case_id, request
        )
        receipt = M8FeishuCardActionReceiptV1(
            intent=intent,
            stage=M8FeishuCardStage.COMPLETED,
            resulting_case_version=committed.case_version,
            case_commit_receipt_id=committed.commit_receipt_id,
            completed_at=self._clock(),
        )
        self._live.commit_card_receipt(receipt)
        result = self._toast("success", f"已执行：{_LABEL_BY_ACTION[intent.action]}")
        result["card"] = self._completed_card(notification, committed.status.value)
        return result

    def _validate_sender(
        self, intent: M8FeishuCardActionIntentV1, sender_sha256: str
    ) -> M8ActorAuthorityCommitReceiptV1:
        status = self._platform_status()
        route = self._live.current_duty_route()
        if (
            status.display_status != M8FeishuPlatformDisplayStatus.ACTIVE
            or route is None
            or not route.active
            or status.activation_revision != route.activation_revision
            or status.activation_status_id != route.activation_status_id
            or route.actor_id != intent.actor_id
        ):
            raise ConcurrentModification("Feishu route or activation changed")
        binding = self._sender_binding(sender_sha256)
        if (
            not binding.active
            or binding.receive_id_sha256 != sender_sha256
            or binding.binding_authority_id != route.recipient_binding_authority_id
            or binding.target.actor_id != route.actor_id
        ):
            raise ConcurrentModification("Feishu sender is not the current duty recipient")
        actor = self._actor_authority(route.actor_id)
        if actor.commit_receipt_id != route.actor_authority_commit_receipt_id:
            raise ConcurrentModification("duty actor authority changed")
        return actor

    def _require_source_notification(
        self,
        intent: M8FeishuCardActionIntentV1,
        current: M8NotificationCommitReceiptV1,
        *,
        allow_dispatch_progress: bool,
    ) -> None:
        if not allow_dispatch_progress:
            if (
                current.notification_version != intent.notification_version
                or current.notification_document_sha256
                != intent.notification_authority_sha256
            ):
                raise ConcurrentModification("notification authority changed")
            return
        if current.notification_version < intent.notification_version:
            raise ConcurrentModification("notification history regressed")
        if current.notification_version == intent.notification_version:
            matches = current.notification_document_sha256 == intent.notification_authority_sha256
        else:
            matches = any(
                event.notification_authority.notification_version == intent.notification_version
                and event.notification_document_sha256 == intent.notification_authority_sha256
                for event in self._notifications.list_notification_audit(intent.notification_id)
            )
        if not matches:
            raise ConcurrentModification("notification source authority changed")

    def _intent(
        self,
        notification: M8NotificationCommitReceiptV1,
        case: M8OperationalCaseCommitReceiptV1,
        token: str,
        action: M8OperationalCaseAction | None,
        stage: M8FeishuCardStage,
    ) -> M8FeishuCardActionIntentV1:
        now = self._clock()
        return M8FeishuCardActionIntentV1(
            notification_id=notification.notification_id,
            notification_version=notification.notification_version,
            notification_authority_sha256=notification.notification_document_sha256,
            case_id=case.case_id,
            case_version=case.case_version,
            case_authority_sha256=case.case_document_sha256,
            actor_id=notification.audit_event.notification_authority.plan.target.actor_id,
            action=action,
            stage=stage,
            confirmation_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            created_at=now,
            expires_at=now + timedelta(minutes=10),
            intent_manifest_id=self._intent_manifest,
        )

    def _stale(
        self, intent: M8FeishuCardActionIntentV1, failure: M8FeishuLiveFailureCode
    ) -> None:
        if intent.stage != M8FeishuCardStage.AWAITING_CONFIRMATION:
            return
        self._live.commit_card_receipt(
            M8FeishuCardActionReceiptV1(
                intent=intent,
                stage=M8FeishuCardStage.STALE,
                failure_code=failure,
                completed_at=self._clock(),
            )
        )

    def _token(self, *parts: object) -> str:
        return hmac.new(self._token_key, canonical_bytes(parts), hashlib.sha256).hexdigest()

    def _case(
        self, notification: M8NotificationCommitReceiptV1
    ) -> M8OperationalCaseCommitReceiptV1:
        plan = notification.audit_event.notification_authority.plan
        case = self._case_reader(plan.case_id)
        if case.case_id != plan.case_id:
            raise ConcurrentModification("notification points to another case")
        return case

    @staticmethod
    def _button(
        text: str, button_type: str, token: str | None, case_id: str | None
    ) -> dict[str, object]:
        if case_id is not None:
            return {
                "tag": "button",
                "text": {"tag": "plain_text", "content": text},
                "type": button_type,
                "url": f"http://127.0.0.1/app/cases/{case_id}",
            }
        return {
            "tag": "button",
            "text": {"tag": "plain_text", "content": text},
            "type": button_type,
            "behaviors": [{"type": "callback", "value": {"confirmation_token": token}}],
        }

    @staticmethod
    def _card(
        title: str,
        notification: M8NotificationCommitReceiptV1,
        buttons: tuple[dict[str, object], ...],
    ) -> dict[str, object]:
        plan = notification.audit_event.notification_authority.plan
        return {
            "schema": "2.0",
            "config": {"update_multi": True},
            "header": {
                "title": {"tag": "plain_text", "content": title},
                "template": "red" if plan.risk_level.value == "EMERGENCY" else "orange",
            },
            "body": {
                "elements": [
                    {
                        "tag": "markdown",
                        "content": (
                            f"**等级**：{plan.risk_level.value}\n"
                            f"**位置**：{plan.location_id}\n"
                            f"**案件状态**：{plan.case_status.value}\n"
                            f"**通知状态**：{notification.status.value}"
                        ),
                    },
                    {"tag": "action", "actions": list(buttons)},
                ]
            },
        }

    @staticmethod
    def _completed_card(
        notification: M8NotificationCommitReceiptV1, case_status: str
    ) -> dict[str, object]:
        return {
            "schema": "2.0",
            "header": {
                "title": {"tag": "plain_text", "content": "安全告警 · 操作完成"},
                "template": "green",
            },
            "body": {
                "elements": [
                    {
                        "tag": "markdown",
                        "content": (
                            f"案件操作已经提交。\n**当前案件状态**：{case_status}\n"
                            f"**通知**：{notification.notification_id[:12]}…"
                        ),
                    }
                ]
            },
        }

    @staticmethod
    def _toast(kind: str, content: str) -> dict[str, object]:
        return {"toast": {"type": kind, "content": content}}


__all__ = ["M8FeishuActionCardService"]
