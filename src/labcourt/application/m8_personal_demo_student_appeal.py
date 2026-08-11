"""Explicit student appeal through the authenticated personal Demo API."""

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
from labcourt.contracts.m8_personal_demo import M8PersonalDemoPpeCaseReceiptV1
from labcourt.contracts.m8_personal_demo_api import M8PersonalDemoLocalAccessV1

_MAX_LOCAL_DOCUMENT_BYTES = 1024 * 1024
_HTTP_TIMEOUT_SECONDS = 3


class M8PersonalDemoStudentAppealError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class M8PersonalDemoStudentAppealRun:
    request: M8ApiCaseTransitionRequestV1
    receipt: M8OperationalCaseCommitReceiptV1


def _read_bounded(path: Path) -> bytes:
    data = path.read_bytes()
    if not 0 < len(data) <= _MAX_LOCAL_DOCUMENT_BYTES:
        raise ValueError("M8 personal Demo student document is outside the allowed bound")
    return data


def _call(
    access: M8PersonalDemoLocalAccessV1,
    method: str,
    path: str,
    payload: bytes | None = None,
) -> bytes:
    parsed = urlsplit(access.base_url)
    if parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise ValueError("M8 personal Demo API access URL changed after validation")
    connection = http.client.HTTPConnection(
        parsed.hostname,
        parsed.port,
        timeout=_HTTP_TIMEOUT_SECONDS,
    )
    headers = {"Authorization": f"Bearer {access.tokens.student.get_secret_value()}"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        body = response.read(_MAX_LOCAL_DOCUMENT_BYTES + 1)
    finally:
        connection.close()
    if len(body) > _MAX_LOCAL_DOCUMENT_BYTES:
        raise M8PersonalDemoStudentAppealError("personal Demo API response exceeded the bound")
    if response.status != 200:
        raise M8PersonalDemoStudentAppealError(
            f"personal Demo API rejected the student appeal with HTTP {response.status}"
        )
    return body


def execute_m8_personal_demo_student_appeal(
    *,
    access_path: Path,
    ppe_case_receipt_path: Path,
    reason_summary: str,
    confirmed: bool,
) -> M8PersonalDemoStudentAppealRun:
    """Submit one student-controlled appeal against the exact PPE Demo Case."""

    if confirmed is not True:
        raise ValueError("M8 personal Demo student appeal requires explicit confirmation")
    access = M8PersonalDemoLocalAccessV1.model_validate_json(_read_bounded(access_path))
    ppe = M8PersonalDemoPpeCaseReceiptV1.model_validate_json(
        _read_bounded(ppe_case_receipt_path)
    )
    case_path = f"/api/m8/cases/{ppe.case_id}"
    try:
        case = M8OperationalCaseCommitReceiptV1.model_validate_json(
            _call(access, "GET", case_path)
        )
        request = M8ApiCaseTransitionRequestV1(
            source_case_version=case.case_version,
            source_case_authority_sha256=case.case_document_sha256,
            source_status=case.status,
            case_location_id=case.audit_event.case_authority.location_id,
            subject_actor_id=case.audit_event.case_authority.subject_actor_id,
            action=M8OperationalCaseAction.SUBMIT_APPEAL,
            reason_code=M8OperationalCaseReasonCode.SUBJECT_DISPUTE,
            reason_summary=reason_summary,
            supporting_authorities=(
                case.audit_event.case_authority.create_command.trigger_authorities[0],
            ),
            explicit_human_confirmation=True,
            command_manifest_id=hashlib.sha256(
                b"labcourt-personal-demo-student-appeal-v1"
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
        raise M8PersonalDemoStudentAppealError(
            "personal Demo API returned an invalid student appeal response"
        ) from error
    return M8PersonalDemoStudentAppealRun(request=request, receipt=receipt)


__all__ = [
    "M8PersonalDemoStudentAppealError",
    "M8PersonalDemoStudentAppealRun",
    "execute_m8_personal_demo_student_appeal",
]
