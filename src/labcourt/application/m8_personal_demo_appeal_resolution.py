"""Explicit safety-officer resolution of the personal Demo PPE appeal."""

from __future__ import annotations

import hashlib
import http.client
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8AppealResolution,
    M8OperationalCaseAction,
    M8OperationalCaseReasonCode,
    M8OperationalCaseStatus,
)
from labcourt.contracts.m8_api import M8ApiCaseTransitionRequestV1
from labcourt.contracts.m8_case_persistence import M8OperationalCaseCommitReceiptV1
from labcourt.contracts.m8_personal_demo import M8PersonalDemoPpeCaseReceiptV1
from labcourt.contracts.m8_personal_demo_api import M8PersonalDemoLocalAccessV1

_MAX_LOCAL_DOCUMENT_BYTES = 1024 * 1024
_HTTP_TIMEOUT_SECONDS = 3


class M8PersonalDemoAppealResolutionError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class M8PersonalDemoAppealResolutionRun:
    request: M8ApiCaseTransitionRequestV1
    receipt: M8OperationalCaseCommitReceiptV1


def _read_bounded(path: Path) -> bytes:
    data = path.read_bytes()
    if not 0 < len(data) <= _MAX_LOCAL_DOCUMENT_BYTES:
        raise ValueError("M8 personal Demo appeal resolution document is outside the bound")
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
    headers = {"Authorization": f"Bearer {access.tokens.safety.get_secret_value()}"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        body = response.read(_MAX_LOCAL_DOCUMENT_BYTES + 1)
    finally:
        connection.close()
    if len(body) > _MAX_LOCAL_DOCUMENT_BYTES:
        raise M8PersonalDemoAppealResolutionError("personal Demo API response exceeded bound")
    if response.status != 200:
        raise M8PersonalDemoAppealResolutionError(
            f"personal Demo API rejected appeal resolution with HTTP {response.status}"
        )
    return body


def execute_m8_personal_demo_appeal_resolution(
    *,
    access_path: Path,
    ppe_case_receipt_path: Path,
    resolution: M8AppealResolution,
    reason_summary: str,
    confirmed: bool,
) -> M8PersonalDemoAppealResolutionRun:
    """Resolve the exact PPE appeal as the authenticated safety officer."""

    if confirmed is not True:
        raise ValueError("M8 personal Demo appeal resolution requires explicit confirmation")
    if not isinstance(resolution, M8AppealResolution):
        raise TypeError("M8 personal Demo appeal resolution must be closed and typed")
    access = M8PersonalDemoLocalAccessV1.model_validate_json(_read_bounded(access_path))
    ppe = M8PersonalDemoPpeCaseReceiptV1.model_validate_json(
        _read_bounded(ppe_case_receipt_path)
    )
    case_path = f"/api/m8/cases/{ppe.case_id}"
    reason_code = {
        M8AppealResolution.UPHELD: M8OperationalCaseReasonCode.APPEAL_UPHELD,
        M8AppealResolution.OVERTURNED: M8OperationalCaseReasonCode.APPEAL_OVERTURNED,
    }[resolution]
    try:
        case = M8OperationalCaseCommitReceiptV1.model_validate_json(
            _call(access, "GET", case_path)
        )
        if case.status != M8OperationalCaseStatus.APPEALED:
            raise ValueError("M8 personal Demo appeal resolution requires an appealed PPE Case")
        authority = case.audit_event.case_authority
        if (
            authority.subject_actor_id != "student-demo"
            or authority.create_command.source_ids != (ppe.source_id,)
        ):
            raise ValueError("M8 personal Demo appeal Case is not the exact PPE authority")
        request = M8ApiCaseTransitionRequestV1(
            source_case_version=case.case_version,
            source_case_authority_sha256=case.case_document_sha256,
            source_status=case.status,
            case_location_id=authority.location_id,
            subject_actor_id=authority.subject_actor_id,
            action=M8OperationalCaseAction.RESOLVE_APPEAL,
            reason_code=reason_code,
            reason_summary=reason_summary,
            supporting_authorities=authority.create_command.trigger_authorities,
            appeal_resolution=resolution,
            explicit_human_confirmation=True,
            command_manifest_id=hashlib.sha256(
                b"labcourt-personal-demo-ppe-appeal-resolution-v1"
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
        raise M8PersonalDemoAppealResolutionError(
            "personal Demo API returned an invalid appeal resolution response"
        ) from error
    if receipt.status != M8OperationalCaseStatus.APPEAL_RESOLVED:
        raise M8PersonalDemoAppealResolutionError(
            "personal Demo appeal resolution did not reach the final Case status"
        )
    return M8PersonalDemoAppealResolutionRun(request=request, receipt=receipt)


__all__ = [
    "M8PersonalDemoAppealResolutionError",
    "M8PersonalDemoAppealResolutionRun",
    "execute_m8_personal_demo_appeal_resolution",
]
