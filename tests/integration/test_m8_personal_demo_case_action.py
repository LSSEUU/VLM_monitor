from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path

from labcourt.application.m8_personal_demo_api import (
    M8_PERSONAL_DEMO_ROLE_TOKENS,
    M8PersonalDemoApiAssembly,
    assemble_m8_personal_demo_api,
)
from labcourt.application.m8_personal_demo_appeal_resolution import (
    execute_m8_personal_demo_appeal_resolution,
)
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.application.m8_personal_demo_case_action import (
    execute_m8_personal_demo_case_action,
)
from labcourt.application.m8_personal_demo_media import bind_m8_personal_demo_recorded_media
from labcourt.application.m8_personal_demo_ppe_case import create_m8_personal_demo_ppe_case
from labcourt.application.m8_personal_demo_ppe_notification import (
    deliver_m8_personal_demo_ppe_notification,
    deliver_m8_personal_demo_ppe_outcome_notification,
    respond_m8_personal_demo_ppe_notification,
    route_m8_personal_demo_ppe_notification,
    route_m8_personal_demo_ppe_outcome_notification,
)
from labcourt.application.m8_personal_demo_student_appeal import (
    execute_m8_personal_demo_student_appeal,
)
from labcourt.contracts.m8_access_cases import M8AppealResolution
from labcourt.contracts.m8_notification_lifecycle import M8NotificationReplyKind
from labcourt.contracts.m8_personal_demo_api import M8PersonalDemoOperatorAction


def _documents(
    root: Path,
    assembly: M8PersonalDemoApiAssembly,
) -> tuple[Path, Path]:
    access = root / "api-access.json"
    bootstrap = root / "bootstrap-receipt.json"
    access.write_text(
        json.dumps(assembly.local_access_document()),
        encoding="utf-8",
    )
    run = bootstrap_m8_personal_demo(root / "labcourt.sqlite3")
    bootstrap.write_text(run.receipt.model_dump_json(), encoding="utf-8")
    return access, bootstrap


def _execute(
    access: Path,
    bootstrap: Path,
    action: M8PersonalDemoOperatorAction,
) -> str:
    run = execute_m8_personal_demo_case_action(
        access_path=access,
        bootstrap_receipt_path=bootstrap,
        action=action,
        reason_summary=f"安全负责人明确执行演示动作 {action.value}。",
        confirmed=True,
    )
    return run.receipt.status.value


def test_safety_officer_can_request_evidence_confirm_and_resolve(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    root = tmp_path / "demo"
    assembly = assemble_m8_personal_demo_api(root / "labcourt.sqlite3", 0)
    access, bootstrap = _documents(root, assembly)
    thread = threading.Thread(target=assembly.server.serve_forever, daemon=True)
    thread.start()
    try:
        assert _execute(access, bootstrap, M8PersonalDemoOperatorAction.REQUEST_EVIDENCE) == (
            "EVIDENCE_REQUESTED"
        )
        assert (
            _execute(access, bootstrap, M8PersonalDemoOperatorAction.RETURN_TO_VERIFICATION)
            == "PENDING_VERIFICATION"
        )
        assert _execute(access, bootstrap, M8PersonalDemoOperatorAction.CONFIRM) == "CONFIRMED"
        assert _execute(access, bootstrap, M8PersonalDemoOperatorAction.RESOLVE) == "RESOLVED"
    finally:
        assembly.server.shutdown()
        assembly.server.server_close()
        thread.join(timeout=3)


def test_safety_officer_can_reject_pending_demo_case(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    root = tmp_path / "reject-demo"
    assembly = assemble_m8_personal_demo_api(root / "labcourt.sqlite3", 0)
    access, bootstrap = _documents(root, assembly)
    thread = threading.Thread(target=assembly.server.serve_forever, daemon=True)
    thread.start()
    try:
        assert _execute(access, bootstrap, M8PersonalDemoOperatorAction.REJECT) == "REJECTED"
    finally:
        assembly.server.shutdown()
        assembly.server.server_close()
        thread.join(timeout=3)


def test_safety_officer_can_explicitly_target_the_ppe_candidate(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    root = tmp_path / "ppe-review"
    media = tmp_path / "ppe-review.mp4"
    media.write_bytes(
        b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"
        b"\x00\x00\x00\x08mdat"
    )
    binding = bind_m8_personal_demo_recorded_media(root / "labcourt.sqlite3", media, root)
    ppe = create_m8_personal_demo_ppe_case(root / "labcourt.sqlite3", root, binding)
    ppe_path = root / "ppe-case-receipt.json"
    ppe_path.write_text(ppe.model_dump_json(), encoding="utf-8")
    assembly = assemble_m8_personal_demo_api(root / "labcourt.sqlite3", 0)
    access = root / "api-access.json"
    access.write_text(json.dumps(assembly.local_access_document()), encoding="utf-8")
    thread = threading.Thread(target=assembly.server.serve_forever, daemon=True)
    thread.start()
    try:
        run = execute_m8_personal_demo_case_action(
            access_path=access,
            target_case_id=ppe.case_id,
            action=M8PersonalDemoOperatorAction.CONFIRM,
            reason_summary="Safety officer explicitly verified the simulated PPE candidate.",
            confirmed=True,
        )
        assert run.receipt.case_id == ppe.case_id
        assert run.receipt.status.value == "CONFIRMED"
        assert run.request.explicit_human_confirmation is True

        notification = route_m8_personal_demo_ppe_notification(
            root / "labcourt.sqlite3",
            ppe,
        )
        replay = route_m8_personal_demo_ppe_notification(
            root / "labcourt.sqlite3",
            ppe,
        )
        assert replay == notification
        assert notification.receipt.notification_status.value == "QUEUED"
        assert notification.receipt.target_actor_id == "student-demo"
        assert notification.card.case_transition_permitted is False
        assert {action.value for action in notification.card.available_actions} == {
            "ACKNOWLEDGE",
            "REQUEST_APPEAL",
            "SUBMIT_EXPLANATION",
        }
        connection = http.client.HTTPConnection(
            "127.0.0.1", assembly.server.server_port, timeout=3
        )
        connection.request(
            "GET",
            "/api/m8/notifications",
            headers={
                "Authorization": (
                    f"Bearer {M8_PERSONAL_DEMO_ROLE_TOKENS['student']}"
                )
            },
        )
        response = connection.getresponse()
        student_notifications = json.loads(response.read())
        connection.close()
        assert response.status == 200
        assert len(student_notifications) == 1
        assert student_notifications[0]["notification_id"] == (
            notification.receipt.notification_id
        )

        delivered = deliver_m8_personal_demo_ppe_notification(
            root / "labcourt.sqlite3",
            notification.receipt,
        )
        delivered_replay = deliver_m8_personal_demo_ppe_notification(
            root / "labcourt.sqlite3",
            notification.receipt,
        )
        assert delivered_replay == delivered
        assert delivered.status.value == "DELIVERED"
        assert delivered.audit_event.transition_command is not None
        delivery_receipt = delivered.audit_event.transition_command.delivery_receipt
        assert delivery_receipt is not None
        assert delivery_receipt.real_delivery_confirmed is False

        reply = respond_m8_personal_demo_ppe_notification(
            root / "labcourt.sqlite3",
            notification.receipt,
            reply_kind=M8NotificationReplyKind.EXPLANATION,
            reply_text="I wore prescription safety glasses and request a manual review.",
            confirmed=True,
        )
        reply_replay = respond_m8_personal_demo_ppe_notification(
            root / "labcourt.sqlite3",
            notification.receipt,
            reply_kind=M8NotificationReplyKind.EXPLANATION,
            reply_text="I wore prescription safety glasses and request a manual review.",
            confirmed=True,
        )
        assert reply_replay == reply
        assert reply.status.value == "RESPONDED"
        assert reply.audit_event.transition_command is not None
        reply_authority = reply.audit_event.transition_command.reply
        assert reply_authority is not None
        assert reply_authority.reply_kind == M8NotificationReplyKind.EXPLANATION
        assert reply_authority.case_transition_permitted is False
        assert reply_authority.direct_disciplinary_action_permitted is False

        appeal = execute_m8_personal_demo_student_appeal(
            access_path=access,
            ppe_case_receipt_path=ppe_path,
            reason_summary="The student explicitly disputes the simulated PPE finding.",
            confirmed=True,
        )
        assert appeal.receipt.case_id == ppe.case_id
        assert appeal.receipt.status.value == "APPEALED"

        resolution = execute_m8_personal_demo_appeal_resolution(
            access_path=access,
            ppe_case_receipt_path=ppe_path,
            resolution=M8AppealResolution.UPHELD,
            reason_summary="The safety officer reviewed the explanation and original evidence.",
            confirmed=True,
        )
        assert resolution.request.action.value == "RESOLVE_APPEAL"
        assert resolution.request.appeal_resolution == M8AppealResolution.UPHELD
        assert resolution.receipt.case_id == ppe.case_id
        assert resolution.receipt.status.value == "APPEAL_RESOLVED"
        assert resolution.receipt.audit_event.transition_intent is not None
        assert resolution.request.direct_disciplinary_action_permitted is False

        outcome = route_m8_personal_demo_ppe_outcome_notification(
            root / "labcourt.sqlite3",
            ppe,
        )
        outcome_replay = route_m8_personal_demo_ppe_outcome_notification(
            root / "labcourt.sqlite3",
            ppe,
        )
        assert outcome_replay == outcome
        assert outcome.receipt.appeal_resolution == M8AppealResolution.UPHELD
        assert outcome.receipt.notification_status.value == "QUEUED"
        assert outcome.card.available_actions == ()
        outcome_delivery = deliver_m8_personal_demo_ppe_outcome_notification(
            root / "labcourt.sqlite3",
            outcome.receipt,
        )
        assert (
            deliver_m8_personal_demo_ppe_outcome_notification(
                root / "labcourt.sqlite3",
                outcome.receipt,
            )
            == outcome_delivery
        )
        assert outcome_delivery.status.value == "DELIVERED"
        assert outcome_delivery.audit_event.transition_command is not None
        outcome_delivery_receipt = (
            outcome_delivery.audit_event.transition_command.delivery_receipt
        )
        assert outcome_delivery_receipt is not None
        assert outcome_delivery_receipt.real_delivery_confirmed is False
        assert appeal.request.action.value == "SUBMIT_APPEAL"
        assert appeal.request.reason_code.value == "SUBJECT_DISPUTE"
        assert appeal.request.explicit_human_confirmation is True
    finally:
        assembly.server.shutdown()
        assembly.server.server_close()
        thread.join(timeout=3)
