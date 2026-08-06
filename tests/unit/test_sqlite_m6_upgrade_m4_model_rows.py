from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from typing import cast

import pytest

from labcourt.adapters.storage import _sqlite_m6_live_read_cut as cut_subject
from labcourt.adapters.storage import _sqlite_m6_upgrade_m4_model_rows as subject
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveDocumentColumn,
    M6LiveReader,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan import (
    MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES,
    M6SQLiteM4DocumentRoute,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4SupportDocumentRoute,
    _M6SQLiteM4MetadataFailure,
)


class _Cursor:
    def __init__(self, rows: Iterable[sqlite3.Row]) -> None:
        self._rows = tuple(rows)
        self.closed = False
        self.fetch_sizes: list[int] = []

    def fetchmany(self, size: int) -> list[sqlite3.Row]:
        self.fetch_sizes.append(size)
        return list(self._rows[:size])

    def close(self) -> None:
        self.closed = True


class _Reader:
    def __init__(self, rows: Iterable[sqlite3.Row] = ()) -> None:
        self.rows = tuple(rows)
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.cursors: list[_Cursor] = []
        self.length_calls: list[tuple[M6LiveDocumentColumn, int]] = []
        self.length = 7

    def execute(self, sql: str, parameters: tuple[object, ...]) -> _Cursor:
        self.queries.append((sql, parameters))
        cursor = _Cursor(self.rows)
        self.cursors.append(cursor)
        return cursor

    def document_octet_length(
        self,
        column: M6LiveDocumentColumn,
        rowid: int,
    ) -> int:
        self.length_calls.append((column, rowid))
        return self.length


def _reader(value: _Reader) -> M6LiveReader:
    return cast(M6LiveReader, value)


def _row(value: dict[str, object]) -> sqlite3.Row:
    return cast(sqlite3.Row, value)


def _strip_allowed_body_uses(sql: str, column: str) -> str:
    without_type = re.sub(rf"typeof\(\s*{column}\s*\)", "", sql)
    return re.sub(rf"octet_length\(\s*{column}\s*\)", "", without_type)


def test_live_document_column_routes_are_exhaustive_unique_and_m4_closed() -> None:
    expected = {
        M6LiveDocumentColumn.M4_MODEL_REQUEST_DOCUMENT: (
            "m4_model_call_claims",
            "request_json",
        ),
        M6LiveDocumentColumn.M4_MODEL_RESPONSE_DOCUMENT: (
            "m4_model_responses",
            "response_json",
        ),
        M6LiveDocumentColumn.M4_MODEL_CACHE_REQUEST_DOCUMENT: (
            "m4_model_cache",
            "request_json",
        ),
        M6LiveDocumentColumn.M4_MODEL_CACHE_ENTRY_DOCUMENT: (
            "m4_model_cache",
            "entry_json",
        ),
        M6LiveDocumentColumn.M4_MODEL_PARSE_RECEIPT_DOCUMENT: (
            "m4_model_parse_receipts",
            "receipt_json",
        ),
        M6LiveDocumentColumn.M4_ROLE_OUTPUT_DOCUMENT: (
            "m4_parsed_hearing_outputs",
            "output_json",
        ),
        M6LiveDocumentColumn.M4_MODEL_CALL_FAILURE_DOCUMENT: (
            "m4_model_call_failure_authorities",
            "authority_json",
        ),
        M6LiveDocumentColumn.M4_MODEL_USAGE_DOCUMENT: (
            "m4_hearing_usage_receipts",
            "usage_json",
        ),
        M6LiveDocumentColumn.M4_HEARING_SESSION_DOCUMENT: (
            "m4_hearings",
            "hearing_json",
        ),
        M6LiveDocumentColumn.M4_HEARING_CYCLE_DOCUMENT: (
            "m4_hearing_cycles",
            "cycle_json",
        ),
        M6LiveDocumentColumn.M4_PRECEDENT_RETRIEVAL_DOCUMENT: (
            "m4_precedent_retrieval_receipts",
            "receipt_json",
        ),
        M6LiveDocumentColumn.M4_HEARING_ROUND_DOCUMENT: (
            "m4_hearing_rounds",
            "round_json",
        ),
        M6LiveDocumentColumn.M4_HEARING_CHECKPOINT_DOCUMENT: (
            "m4_hearing_checkpoints",
            "checkpoint_json",
        ),
        M6LiveDocumentColumn.M4_BACKLOG_ITEM_DOCUMENT: (
            "backlog_items",
            "initial_json",
        ),
        M6LiveDocumentColumn.M4_BACKLOG_ITEM_VERSION_DOCUMENT: (
            "backlog_item_versions",
            "item_json",
        ),
        M6LiveDocumentColumn.M4_BACKLOG_RETRY_OUTCOME_DOCUMENT: (
            "m4_hearing_backlog_retry_outcomes",
            "outcome_json",
        ),
        M6LiveDocumentColumn.M4_BACKLOG_COMPLETION_RECEIPT_DOCUMENT: (
            "m4_backlog_completion_receipts",
            "receipt_json",
        ),
        M6LiveDocumentColumn.M4_STRICT_PARSE_FAILURE_ATTEMPT_DOCUMENT: (
            "m4_hearing_strict_parse_failure_attempts",
            "attempt_json",
        ),
        M6LiveDocumentColumn.M4_STRICT_PARSE_FAILURE_PROOF_DOCUMENT: (
            "m4_hearing_strict_parse_failure_proofs",
            "proof_json",
        ),
        M6LiveDocumentColumn.M4_HEARING_HUMAN_REVIEW_RECEIPT_DOCUMENT: (
            "m4_hearing_human_review_receipts",
            "receipt_json",
        ),
        M6LiveDocumentColumn.M4_ACQUISITION_REQUEST_DOCUMENT: (
            "m4_acquisition_requests",
            "request_json",
        ),
        M6LiveDocumentColumn.M4_ACQUISITION_CLAIM_REQUEST_DOCUMENT: (
            "m4_acquisition_execution_claims",
            "request_json",
        ),
        M6LiveDocumentColumn.M4_ACQUISITION_CLAIM_DOCUMENT: (
            "m4_acquisition_execution_claims",
            "claim_json",
        ),
        M6LiveDocumentColumn.M4_TOOL_EXECUTION_MANIFEST_DOCUMENT: (
            "m4_tool_execution_manifests",
            "manifest_json",
        ),
        M6LiveDocumentColumn.M4_ACQUISITION_PUBLICATION_DOCUMENT: (
            "m4_acquisition_execution_publications",
            "publication_json",
        ),
        M6LiveDocumentColumn.M4_TOOL_EXECUTION_RECEIPT_DOCUMENT: (
            "m4_tool_execution_receipts",
            "receipt_json",
        ),
        M6LiveDocumentColumn.M4_EVIDENCE_PACK_DERIVATION_DOCUMENT: (
            "m4_evidence_pack_derivations",
            "derivation_json",
        ),
    }
    routes = cut_subject._DOCUMENT_COLUMN_ROUTES
    assert set(routes) == set(M6LiveDocumentColumn)
    assert len(set(routes.values())) == len(routes)
    assert {route: routes[route] for route in expected} == expected


def test_primary_enumeration_is_bounded_body_free_and_case_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    reader = _Reader()
    rows = subject.read_primary_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert not any(
        (
            rows.claims,
            rows.responses,
            rows.caches,
            rows.receipts,
            rows.outputs,
            rows.failures,
            rows.usages,
        )
    )
    assert len(reader.queries) == 7
    expected_bodies = {
        "m4_model_call_claims": ("request_json",),
        "m4_model_responses": ("response_json",),
        "m4_model_cache": ("request_json", "entry_json"),
        "m4_model_parse_receipts": ("receipt_json",),
        "m4_parsed_hearing_outputs": ("output_json",),
        "m4_model_call_failure_authorities": ("authority_json",),
        "m4_hearing_usage_receipts": ("usage_json",),
    }
    seen: set[str] = set()
    for sql, parameters in reader.queries:
        assert parameters == ("run-1", "case-1")
        assert "SELECT *" not in sql.upper()
        assert "WHERE run_id = ? AND case_id = ?" in sql
        assert "LIMIT 257" in sql
        table = next(table for table in expected_bodies if f"FROM {table}" in sql)
        seen.add(table)
        for body in expected_bodies[table]:
            assert f"typeof({body})" in sql
            assert f"octet_length({body})" in sql
            assert body not in _strip_allowed_body_uses(sql, body)
    assert seen == set(expected_bodies)


def test_257th_primary_row_is_rejected_with_closed_reason() -> None:
    row = _row({})
    reader = _Reader([row] * 257)
    with pytest.raises(_M6SQLiteM4MetadataFailure) as caught:
        subject.read_primary_rows(
            _reader(reader),
            run_id="run-1",
            case_id="case-1",
        )
    assert caught.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.ROW_LIMIT_EXCEEDED
    assert reader.queries[0][0].find("LIMIT 257") > 0
    assert reader.cursors[0].fetch_sizes == [257]
    assert reader.cursors[0].closed


def test_exact_256_row_boundary_is_accepted_and_every_cursor_is_closed() -> None:
    reader = _Reader([_row({})] * 256)
    result = subject.read_primary_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert all(
        len(group) == 256
        for group in (
            result.claims,
            result.responses,
            result.caches,
            result.receipts,
            result.outputs,
            result.failures,
            result.usages,
        )
    )
    assert all(cursor.fetch_sizes == [257] and cursor.closed for cursor in reader.cursors)


def test_core_hearing_support_enumeration_is_body_free_and_stably_ordered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    reader = _Reader()
    rows = subject.read_hearing_support_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert not any((rows.sessions, rows.cycles, rows.retrievals, rows.rounds, rows.checkpoints))
    expected = {
        "m4_hearings": ("hearing_json", "ORDER BY hearing_id"),
        "m4_hearing_cycles": (
            "cycle_json",
            "ORDER BY hearing_id, cycle_index, cycle_id",
        ),
        "m4_precedent_retrieval_receipts": (
            "receipt_json",
            "ORDER BY hearing_id, cycle_scope_id, retrieval_receipt_id",
        ),
        "m4_hearing_rounds": (
            "round_json",
            "ORDER BY hearing_id, round_index, round_id",
        ),
        "m4_hearing_checkpoints": (
            "checkpoint_json",
            "ORDER BY hearing_id, version, checkpoint_id",
        ),
    }
    assert len(reader.queries) == len(expected)
    for sql, parameters in reader.queries:
        table = next(table for table in expected if f"FROM {table}" in sql)
        body, ordering = expected[table]
        assert parameters == ("run-1", "case-1")
        assert ordering in sql
        assert "LIMIT 257" in sql
        assert f"typeof({body})" in sql
        assert f"octet_length({body})" in sql
        assert body not in _strip_allowed_body_uses(sql, body)
        assert " AS body_commitment_sha256" in sql
        assert not any(
            forbidden in sql
            for forbidden in (
                "initial_defect_codes_json",
                "rework_defect_codes_json",
                "candidate_precedent_refs_json",
                "visible_precedent_refs_json",
                "scored_precedents_json",
                "model_request_refs_json",
                "model_response_refs_json",
            )
        )


def test_old_sqlite_support_sql_keeps_type_but_uses_null_length_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", False)
    reader = _Reader()
    subject.read_hearing_support_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
    )
    for sql, _ in reader.queries:
        assert "typeof(" in sql
        assert "NULL AS support_document_bytes" in sql
        assert "octet_length(" not in sql


def test_backlog_support_enumeration_closes_seven_bodies_and_one_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    reader = _Reader()
    rows = subject.read_backlog_support_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert not any(
        (
            rows.items,
            rows.versions,
            rows.heads,
            rows.retry_outcomes,
            rows.completions,
            rows.strict_attempts,
            rows.strict_proofs,
            rows.human_reviews,
        )
    )
    expected = {
        "backlog_items": ("initial_json", "ORDER BY item_id"),
        "backlog_item_versions": (
            "version.item_json",
            "ORDER BY version.item_id, version.version",
        ),
        "backlog_heads": (None, "ORDER BY head.item_id"),
        "m4_hearing_backlog_retry_outcomes": (
            "outcome_json",
            "ORDER BY backlog_item_id, source_checkpoint_version, outcome_id",
        ),
        "m4_backlog_completion_receipts": (
            "receipt_json",
            "ORDER BY item_id, attempt_count, retry_generation, receipt_id",
        ),
        "m4_hearing_strict_parse_failure_attempts": (
            "attempt_json",
            "ORDER BY backlog_item_id, retry_generation, attempt_index, attempt_id",
        ),
        "m4_hearing_strict_parse_failure_proofs": (
            "proof_json",
            "ORDER BY backlog_item_id, retry_generation, proof_id",
        ),
        "m4_hearing_human_review_receipts": (
            "receipt_json",
            "ORDER BY hearing_id, judge_cycle, receipt_id",
        ),
    }
    assert len(reader.queries) == len(expected)
    seen: set[str] = set()
    for sql, parameters in reader.queries:
        table = next(table for table in expected if f"FROM {table}" in sql)
        seen.add(table)
        body, ordering = expected[table]
        assert parameters == ("run-1", "case-1")
        assert ordering in sql
        assert "LIMIT 257" in sql
        if table in {"backlog_items", "backlog_item_versions", "backlog_heads"}:
            assert "stage = 'HEARING'" in sql
        if body is None:
            assert "support_document_type" not in sql
            assert "support_document_bytes" not in sql
        else:
            assert f"typeof({body})" in sql
            assert f"octet_length({body})" in sql
            assert body not in _strip_allowed_body_uses(sql, body)
            assert " AS body_commitment_sha256" in sql
        assert "response_refs_json" not in sql
    assert seen == set(expected)


def test_base_support_enumeration_uses_exact_authority_and_bounded_case_sets() -> None:
    reader = _Reader()
    rows = subject.read_base_support_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
        selected_case_revision=4,
        selected_audit_sequence=17,
    )
    assert not any(
        (
            rows.run,
            rows.case_version,
            rows.audit,
            rows.case_history,
            rows.audit_history,
            rows.packs,
            rows.screenings,
            rows.reviews,
        )
    )
    assert len(reader.queries) == 8
    by_table = {}
    for sql, parameters in reader.queries:
        if "FROM case_versions" in sql:
            key = "case_history" if "revision <= ?" in sql else "case_versions"
        elif "FROM audit_entries AS audit" in sql:
            key = "audit_history"
        elif "FROM audit_entries" in sql:
            key = "audit_entries"
        else:
            key = next(
                table
                for table in (
                    "runs",
                    "evidence_packs",
                    "screening_results",
                    "procedural_reviews",
                )
                if f"FROM {table}" in sql
            )
        by_table[key] = (sql, parameters)
    assert by_table["runs"][1] == ("run-1",)
    assert by_table["case_versions"][1] == ("run-1", "case-1", 4)
    assert by_table["audit_entries"][1] == ("run-1", 17)
    assert by_table["case_history"][1] == ("run-1", "case-1", 4)
    assert by_table["audit_history"][1] == ("run-1", "case-1", 4)
    assert all(
        by_table[table][1] == ("run-1", "case-1")
        for table in ("evidence_packs", "screening_results", "procedural_reviews")
    )
    assert "LIMIT 2" in by_table["runs"][0]
    assert "LIMIT 2" in by_table["case_versions"][0]
    assert "LIMIT 2" in by_table["audit_entries"][0]
    assert "LIMIT 257" in by_table["case_history"][0]
    assert "LIMIT 257" in by_table["audit_history"][0]
    assert all(
        "LIMIT 257" in by_table[table][0]
        for table in ("evidence_packs", "screening_results", "procedural_reviews")
    )
    assert all("_json" not in sql for sql, _ in reader.queries)


def test_old_sqlite_fallback_uses_every_exact_m4_document_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", False)
    reader = _Reader()
    for index, route in enumerate(M6SQLiteM4DocumentRoute, start=1):
        row = _row(
            {
                "document_rowid": index,
                subject._DOCUMENT_TYPE_ALIAS[route]: "text",
                subject._DOCUMENT_SIZE_ALIAS[route]: None,
            }
        )
        assert subject.document_bytes(_reader(reader), row, route) == reader.length
    for index, route in enumerate(M6SQLiteM4SupportDocumentRoute, start=101):
        row = _row(
            {
                "support_rowid": index,
                "support_document_type": "text",
                "support_document_bytes": None,
            }
        )
        assert subject.support_document_bytes(_reader(reader), row, route) == reader.length
    expected = [
        (subject._LIVE_DOCUMENT_ROUTE[route], index)
        for index, route in enumerate(M6SQLiteM4DocumentRoute, start=1)
    ] + [
        (subject._LIVE_SUPPORT_DOCUMENT_ROUTE[route], index)
        for index, route in enumerate(M6SQLiteM4SupportDocumentRoute, start=101)
    ]
    assert reader.length_calls == expected
    assert set(subject._LIVE_DOCUMENT_ROUTE) == set(M6SQLiteM4DocumentRoute)
    assert set(subject._LIVE_SUPPORT_DOCUMENT_ROUTE) == set(M6SQLiteM4SupportDocumentRoute)


@pytest.mark.parametrize(
    ("row", "length", "expected"),
    [
        (
            {
                "document_rowid": 1,
                "request_document_type": "blob",
                "request_document_bytes": 1,
            },
            1,
            M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID,
        ),
        (
            {
                "document_rowid": 0,
                "request_document_type": "text",
                "request_document_bytes": 1,
            },
            1,
            M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            {
                "document_rowid": 1,
                "request_document_type": "text",
                "request_document_bytes": 0,
            },
            0,
            M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID,
        ),
        (
            {
                "document_rowid": 1,
                "request_document_type": "text",
                "request_document_bytes": MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES + 1,
            },
            MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES + 1,
            M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_TOO_LARGE,
        ),
    ],
)
def test_document_length_metadata_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    row: dict[str, object],
    length: int,
    expected: M6SQLiteM4ModelDocumentFailureCode,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    reader = _Reader()
    reader.length = length
    with pytest.raises(_M6SQLiteM4MetadataFailure) as caught:
        subject.document_bytes(
            _reader(reader),
            _row(row),
            M6SQLiteM4DocumentRoute.MODEL_REQUEST,
        )
    assert caught.value.reason_code == expected
    assert reader.length_calls == []
