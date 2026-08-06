"""Shared same-connection decoder for frozen M5 exposure authorities."""

from __future__ import annotations

import sqlite3
from typing import Protocol

from pydantic import ValidationError

from labcourt.contracts.hearing_state import HearingPrecedentRetrievalReceipt
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.exceptions import EvidenceMissing

from .sqlite_repository import (
    RepositoryIntegrityError,
    _document,
    _row_int,
    _row_str,
    _verify_contract_document,
)


class _ExposureRepository(Protocol):
    def _load_m5_precedent_revision(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        precedent_id: str,
        revision: int,
    ) -> M5PrecedentAuthority | None: ...


class _ExposureHearingRepository(Protocol):
    def _load_precedent_retrieval(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        receipt_id: str,
    ) -> HearingPrecedentRetrievalReceipt: ...


def load_m5_precedent_exposure_in_connection(
    connection: sqlite3.Connection,
    *,
    repository: _ExposureRepository,
    hearing_repository: _ExposureHearingRepository,
    run_id: str,
    cycle_scope_id: str,
) -> M5PrecedentExposureBatchAuthority | None:
    row = connection.execute(
        """
        SELECT * FROM m5_precedent_exposures
        WHERE run_id = ? AND cycle_scope_id = ?
        """,
        (run_id, cycle_scope_id),
    ).fetchone()
    if row is None:
        return None
    raw = _row_str(row, "exposure_json")
    try:
        exposure = M5PrecedentExposureBatchAuthority.model_validate_json(raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError("stored M5 precedent exposure is invalid") from exc
    _verify_contract_document(raw, exposure)
    canonical_raw, canonical_sha256 = _document(exposure)
    m4 = exposure.m4_retrieval_outcome
    m5 = exposure.m5_retrieval_result
    indexed = (
        exposure.run_id == run_id,
        exposure.cycle_scope_id == cycle_scope_id,
        exposure.exposure_id == _row_str(row, "exposure_id"),
        exposure.exposure_sha256 == _row_str(row, "exposure_sha256"),
        raw == canonical_raw,
        canonical_sha256 == _row_str(row, "document_sha256"),
        exposure.case_id == _row_str(row, "case_id"),
        exposure.hearing_session_id == _row_str(row, "hearing_id"),
        exposure.cycle_index == _row_int(row, "cycle_index"),
        exposure.cycle_scope_sha256 == _row_str(row, "cycle_scope_sha256"),
        m4.receipt.receipt_id == _row_str(row, "retrieval_receipt_id"),
        m4.query.query_id == _row_str(row, "m4_query_id"),
        m5.query.query_id == _row_str(row, "m5_query_id"),
        m5.result_id == _row_str(row, "m5_result_id"),
        m5.candidate_count == _row_int(row, "candidate_count"),
        len(exposure.exposed_precedents) == _row_int(row, "exposed_count"),
        exposure.policy_id == _row_str(row, "policy_id"),
        exposure.bridge_manifest_id == _row_str(row, "bridge_manifest_id"),
        exposure.manifest_id == _row_str(row, "manifest_id"),
    )
    if not all(indexed):
        raise RepositoryIntegrityError(
            "M5 precedent exposure indexes conflict with its canonical document"
        )
    try:
        durable_receipt = hearing_repository._load_precedent_retrieval(
            connection,
            run_id,
            m4.receipt.receipt_id,
        )
    except EvidenceMissing as exc:
        raise RepositoryIntegrityError(
            "M5 precedent exposure references a missing M4 receipt"
        ) from exc
    if durable_receipt != m4.receipt:
        raise RepositoryIntegrityError("M5 precedent exposure rewrites its durable M4 receipt")
    for evaluation in m5.candidate_evaluations:
        authority = evaluation.authority
        durable = repository._load_m5_precedent_revision(
            connection,
            run_id,
            authority.precedent.precedent_id,
            authority.revision,
        )
        if durable != authority:
            raise RepositoryIntegrityError(
                "M5 precedent exposure rewrites a historical candidate authority"
            )
    return exposure


__all__ = ["load_m5_precedent_exposure_in_connection"]
