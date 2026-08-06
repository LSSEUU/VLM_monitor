"""Construct one immutable candidate-run cut from sealed trusted authorities."""

from __future__ import annotations

import hashlib
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.artifact_validation import M3ArtifactValidationReport
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateRunCutAuthority,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.ports.m6_upgrade_candidate_run_cut import (
    M6UpgradeCandidateRunCutError,
    M6UpgradeCandidateRunCutFailureCode,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _fail(code: M6UpgradeCandidateRunCutFailureCode) -> NoReturn:
    raise M6UpgradeCandidateRunCutError(code) from None


def _canonical_exact(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT)
    return controlled


def _document(value: BaseModel) -> tuple[str, str, int]:
    document = canonical_json(value.model_dump(mode="json"))
    payload = document.encode("utf-8")
    return document, hashlib.sha256(payload).hexdigest(), len(payload)


def build_m6_upgrade_candidate_run_cut(
    *,
    execution_scope: M6UpgradeExecutionScopeAuthority,
    execution_ledger: M6UpgradeExecutionLedgerSealV2,
    validation_report: M5ArtifactValidationReport,
) -> M6UpgradeCandidateRunCutAuthority:
    """Bind the exact sealed V3 scope to one passing M5 validation report.

    This pure constructor does not query current run heads and does not read any
    artifact body. The storage adapter is responsible for obtaining all three
    inputs from trusted, bounded authorities and for persisting the result.
    """

    scope = _canonical_exact(execution_scope, M6UpgradeExecutionScopeAuthority)
    if (
        isinstance(execution_ledger, M6UpgradeExecutionLedgerSeal)
        and type(execution_ledger) is not M6UpgradeExecutionLedgerSealV2
    ):
        _fail(M6UpgradeCandidateRunCutFailureCode.LEDGER_VERSION_UNSUPPORTED)
    ledger = _canonical_exact(execution_ledger, M6UpgradeExecutionLedgerSealV2)
    report = _canonical_exact(validation_report, M5ArtifactValidationReport)

    if ledger.execution_scope != scope:
        _fail(M6UpgradeCandidateRunCutFailureCode.SCOPE_MISMATCH)

    predecessor = report.predecessor_report
    if type(predecessor) is not M4ArtifactValidationReport:
        _fail(M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED)
    m4_report = predecessor
    m3_report = m4_report.m3_report
    if type(m3_report) is not M3ArtifactValidationReport:
        _fail(M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED)
    m2_report = m3_report.m2_report

    if (
        not report.passed
        or not m4_report.passed
        or not m3_report.passed
        or not m2_report.passed
        or report.run_id != scope.candidate_run_id
        or report.manifest_id != scope.candidate_manifest.manifest_id
        or report.config_sha256 != scope.candidate_config.config_sha256
        or m2_report.manifest_id != scope.candidate_manifest.manifest_id
        or report.counts.case_roots != ledger.candidate_case_count
    ):
        _fail(M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED)
    if (
        m2_report.audit_head_sequence != ledger.source_audit_head_sequence
        or m2_report.audit_head_hash != ledger.source_audit_head_hash
    ):
        _fail(M6UpgradeCandidateRunCutFailureCode.AUDIT_HEAD_MISMATCH)

    _report_document, report_sha256, report_size = _document(report)
    if report_size > MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES:
        _fail(M6UpgradeCandidateRunCutFailureCode.DOCUMENT_TOO_LARGE)
    try:
        authority = M6UpgradeCandidateRunCutAuthority(
            candidate_run_id=scope.candidate_run_id,
            candidate_manifest=scope.candidate_manifest,
            candidate_manifest_content_sha256=scope.candidate_manifest_content_sha256,
            candidate_config=scope.candidate_config,
            candidate_config_content_sha256=scope.candidate_config_content_sha256,
            execution_component_manifest_id=(scope.execution_component.component_authority_id),
            audit_head_sequence=ledger.source_audit_head_sequence,
            audit_head_hash=ledger.source_audit_head_hash,
            validation_report=report,
            validation_report_content_sha256=report_sha256,
        )
        controlled = M6UpgradeCandidateRunCutAuthority.model_validate(
            authority.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED)
    if controlled != authority:
        _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)
    _authority_document, _authority_sha256, authority_size = _document(authority)
    if authority_size > MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES:
        _fail(M6UpgradeCandidateRunCutFailureCode.DOCUMENT_TOO_LARGE)
    return authority


__all__ = ["build_m6_upgrade_candidate_run_cut"]
