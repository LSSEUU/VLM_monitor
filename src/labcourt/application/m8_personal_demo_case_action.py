"""Explicit safety-officer actions through the real personal Demo HTTP API."""

from __future__ import annotations

import hashlib
import http.client
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8OperationalCaseAction,
    M8OperationalCaseReasonCode,
)
from labcourt.contracts.m8_api import M8ApiCaseTransitionRequestV1
from labcourt.contracts.m8_case_persistence import M8OperationalCaseCommitReceiptV1
from labcourt.contracts.m8_personal_demo import M8PersonalDemoBootstrapReceiptV1
from labcourt.contracts.m8_personal_demo_api import (
    M8PersonalDemoLocalAccessV1,
    M8PersonalDemoOperatorAction,
)
from labcourt.contracts.references import require_reference_token

_MAX_LOCAL_DOCUMENT_BYTES = 1024 * 1024
_HTTP_TIMEOUT_SECONDS = 3
_REASON_CODES = {
    M8PersonalDemoOperatorAction.CONFIRM: M8OperationalCaseReasonCode.VERIFIED_VIOLATION,
    M8PersonalDemoOperatorAction.REJECT: M8OperationalCaseReasonCode.FALSE_POSITIVE,
    M8PersonalDemoOperatorAction.REQUEST_EVIDENCE: (
        M8OperationalCaseReasonCode.MORE_EVIDENCE_REQUIRED
    ),
    M8PersonalDemoOperatorAction.RETURN_TO_VERIFICATION: (
        M8OperationalCaseReasonCode.EVIDENCE_RECEIVED
    ),
    M8PersonalDemoOperatorAction.RESOLVE: M8OperationalCaseReasonCode.HAZARD_CLEARED,
}


class M8PersonalDemoCaseActionError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class M8PersonalDemoCaseActionRun:
    request: M8ApiCaseTransitionRequestV1
    receipt: M8OperationalCaseCommitReceiptV1


def _read_bounded(path: Path) -> bytes:
    data = path.read_bytes()
    if not 0 < len(data) <= _MAX_LOCAL_DOCUMENT_BYTES:
        raise ValueError("M8 personal Demo local document is outside the allowed bound")
    return data


def _call(
    access: M8PersonalDemoLocalAccessV1,
    method: str,
    path: str,
    payload: bytes | None = None,
) -> bytes:
    parsed = urlsplit(access.base_url)
    host = parsed.hostname
    port = parsed.port
    if host != "127.0.0.1" or port is None:
        raise ValueError("M8 personal Demo API access URL changed after validation")
    connection = http.client.HTTPConnection(
        host,
        port,
        timeout=_HTTP_TIMEOUT_SECONDS,
    )
    headers = {
        "Authorization": f"Bearer {access.tokens.safety.get_secret_value()}",
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        body = response.read(_MAX_LOCAL_DOCUMENT_BYTES + 1)
    finally:
        connection.close()
    if len(body) > _MAX_LOCAL_DOCUMENT_BYTES:
        raise M8PersonalDemoCaseActionError("personal Demo API response exceeded the bound")
    if response.status != 200:
        raise M8PersonalDemoCaseActionError(
            f"personal Demo API rejected the action with HTTP {response.status}"
        )
    return body


def execute_m8_personal_demo_case_action(
    *,
    access_path: Path,
    action: M8PersonalDemoOperatorAction,
    reason_summary: str,
    confirmed: bool,
    bootstrap_receipt_path: Path | None = None,
    target_case_id: str | None = None,
) -> M8PersonalDemoCaseActionRun:
    """Read current authority, then submit one explicitly confirmed safety action."""

    if confirmed is not True:
        raise ValueError("M8 personal Demo Case action requires explicit confirmation")
    if not isinstance(action, M8PersonalDemoOperatorAction):
        raise TypeError("M8 personal Demo Case action must use the closed action enum")
    if (bootstrap_receipt_path is None) == (target_case_id is None):
        raise ValueError("M8 personal Demo Case action requires exactly one target authority")
    access = M8PersonalDemoLocalAccessV1.model_validate_json(_read_bounded(access_path))
    if bootstrap_receipt_path is not None:
        bootstrap = M8PersonalDemoBootstrapReceiptV1.model_validate_json(
            _read_bounded(bootstrap_receipt_path)
        )
        resolved_case_id = bootstrap.case_id
    else:
        assert target_case_id is not None
        resolved_case_id = require_reference_token(target_case_id, "M8 Demo target case_id")
    case_path = f"/api/m8/cases/{resolved_case_id}"
    try:
        case = M8OperationalCaseCommitReceiptV1.model_validate_json(_call(access, "GET", case_path))
        request = M8ApiCaseTransitionRequestV1(
            source_case_version=case.case_version,
            source_case_authority_sha256=case.case_document_sha256,
            source_status=case.status,
            case_location_id=case.audit_event.case_authority.location_id,
            subject_actor_id=case.audit_event.case_authority.subject_actor_id,
            action=M8OperationalCaseAction(action.value),
            reason_code=_REASON_CODES[action],
            reason_summary=reason_summary,
            supporting_authorities=(
                case.audit_event.case_authority.create_command.trigger_authorities[0],
            ),
            explicit_human_confirmation=True,
            command_manifest_id=hashlib.sha256(
                b"labcourt-personal-demo-human-case-action-v1"
            ).hexdigest(),
        )
        receipt = M8OperationalCaseCommitReceiptV1.model_validate_json(
            _call(
                access,
                "POST",
                f"{case_path}/transitions",
                request.model_dump_json().encode("utf-8"),
            )
        )
    except ValidationError as error:
        raise M8PersonalDemoCaseActionError(
            "personal Demo API returned an invalid typed response"
        ) from error
    return M8PersonalDemoCaseActionRun(request=request, receipt=receipt)


__all__ = [
    "M8PersonalDemoCaseActionError",
    "M8PersonalDemoCaseActionRun",
    "execute_m8_personal_demo_case_action",
]
