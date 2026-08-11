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
