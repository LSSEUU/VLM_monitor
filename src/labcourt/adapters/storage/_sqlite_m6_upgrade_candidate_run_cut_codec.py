"""Canonical SQLite codec for the immutable M6 candidate-run cut."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_execution import M6UpgradeCandidateRunCutAuthority
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
)

from .sqlite_repository import RepositoryIntegrityError, _row_int, _row_str

MAX_M6_UPGRADE_CANDIDATE_RUN_CUT_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES


@dataclass(frozen=True, slots=True)
class StoredM6UpgradeCandidateRunCut:
    authority: M6UpgradeCandidateRunCutAuthority
    document: str
    document_sha256: str
    size_bytes: int


def _document(value: BaseModel) -> tuple[str, str, int]:
    try:
        document = canonical_json(value.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise RepositoryIntegrityError("invalid M6 candidate run-cut authority") from exc
    payload = document.encode("utf-8")
    return document, hashlib.sha256(payload).hexdigest(), len(payload)


def candidate_run_cut_documents(
    authority: M6UpgradeCandidateRunCutAuthority,
) -> StoredM6UpgradeCandidateRunCut:
    if type(authority) is not M6UpgradeCandidateRunCutAuthority:
        raise RepositoryIntegrityError("invalid M6 candidate run-cut authority type")
    try:
        controlled = M6UpgradeCandidateRunCutAuthority.model_validate(
            authority.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise RepositoryIntegrityError("invalid M6 candidate run-cut authority") from exc
    if controlled != authority:
        raise RepositoryIntegrityError("noncanonical M6 candidate run-cut authority")
    document, document_sha256, size_bytes = _document(controlled)
    if size_bytes > MAX_M6_UPGRADE_CANDIDATE_RUN_CUT_BYTES:
        raise RepositoryIntegrityError("M6 candidate run-cut document exceeds its budget")
    return StoredM6UpgradeCandidateRunCut(
        authority=controlled,
        document=document,
        document_sha256=document_sha256,
        size_bytes=size_bytes,
    )


def candidate_run_cut_from_row(
    row: sqlite3.Row,
    *,
    execution_scope: M6UpgradeExecutionScopeAuthority,
    execution_ledger: M6UpgradeExecutionLedgerSealV2,
) -> StoredM6UpgradeCandidateRunCut:
    """Decode one row and cross-check every normalized scope/seal projection."""

    try:
        raw = _row_str(row, "run_cut_json")
        document_sha256 = _row_str(row, "document_sha256")
        size_bytes = _row_int(row, "size_bytes")
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise RepositoryIntegrityError("invalid stored M6 candidate run-cut row") from exc
    payload = raw.encode("utf-8")
    if (
        size_bytes < 1
        or size_bytes > MAX_M6_UPGRADE_CANDIDATE_RUN_CUT_BYTES
        or len(payload) != size_bytes
        or hashlib.sha256(payload).hexdigest() != document_sha256
    ):
        raise RepositoryIntegrityError("invalid stored M6 candidate run-cut document identity")
    try:
        authority = M6UpgradeCandidateRunCutAuthority.model_validate_json(raw)
        canonical = canonical_json(authority.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError) as exc:
        raise RepositoryIntegrityError("invalid stored M6 candidate run-cut document") from exc
    if canonical != raw:
        raise RepositoryIntegrityError("stored M6 candidate run-cut document is noncanonical")
    report_document, report_sha256, report_size = _document(authority.validation_report)
    del report_document
    try:
        observed = (
            _row_str(row, "run_id"),
            _row_str(row, "execution_scope_authority_id"),
            _row_str(row, "ledger_seal_authority_id"),
            _row_str(row, "candidate_manifest_id"),
            _row_str(row, "candidate_manifest_content_sha256"),
            _row_str(row, "candidate_config_sha256"),
            _row_str(row, "candidate_config_content_sha256"),
            _row_str(row, "execution_component_manifest_id"),
            _row_int(row, "audit_head_sequence"),
            _row_str(row, "audit_head_hash"),
            _row_str(row, "validation_report_id"),
            _row_str(row, "validation_report_content_sha256"),
            _row_int(row, "validation_report_size_bytes"),
            _row_str(row, "candidate_run_cut_authority_id"),
        )
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise RepositoryIntegrityError("invalid stored M6 candidate run-cut projections") from exc
    expected = (
        execution_scope.candidate_run_id,
        execution_scope.execution_scope_authority_id,
        execution_ledger.ledger_seal_authority_id,
        authority.candidate_manifest.manifest_id,
        authority.candidate_manifest_content_sha256,
        authority.candidate_config.config_sha256,
        authority.candidate_config_content_sha256,
        authority.execution_component_manifest_id,
        authority.audit_head_sequence,
        authority.audit_head_hash,
        authority.validation_report.report_id,
        report_sha256,
        report_size,
        authority.candidate_run_cut_authority_id,
    )
    if observed != expected or (
        authority.candidate_run_id != execution_scope.candidate_run_id
        or authority.candidate_manifest != execution_scope.candidate_manifest
        or authority.candidate_manifest_content_sha256
        != execution_scope.candidate_manifest_content_sha256
        or authority.candidate_config != execution_scope.candidate_config
        or authority.candidate_config_content_sha256
        != execution_scope.candidate_config_content_sha256
        or authority.execution_component_manifest_id
        != execution_scope.execution_component.component_authority_id
        or authority.audit_head_sequence != execution_ledger.source_audit_head_sequence
        or authority.audit_head_hash != execution_ledger.source_audit_head_hash
        or authority.validation_report_content_sha256 != report_sha256
    ):
        raise RepositoryIntegrityError("stored M6 candidate run-cut projections differ")
    return StoredM6UpgradeCandidateRunCut(
        authority=authority,
        document=raw,
        document_sha256=document_sha256,
        size_bytes=size_bytes,
    )


__all__ = [
    "MAX_M6_UPGRADE_CANDIDATE_RUN_CUT_BYTES",
    "StoredM6UpgradeCandidateRunCut",
    "candidate_run_cut_documents",
    "candidate_run_cut_from_row",
]
