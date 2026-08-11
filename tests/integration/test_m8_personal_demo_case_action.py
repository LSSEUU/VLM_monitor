from __future__ import annotations

import json
import threading
from pathlib import Path

from labcourt.application.m8_personal_demo_api import (
    M8PersonalDemoApiAssembly,
    assemble_m8_personal_demo_api,
)
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.application.m8_personal_demo_case_action import (
    execute_m8_personal_demo_case_action,
)
from labcourt.application.m8_personal_demo_media import bind_m8_personal_demo_recorded_media
from labcourt.application.m8_personal_demo_ppe_case import create_m8_personal_demo_ppe_case
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
    finally:
        assembly.server.shutdown()
        assembly.server.server_close()
        thread.join(timeout=3)
