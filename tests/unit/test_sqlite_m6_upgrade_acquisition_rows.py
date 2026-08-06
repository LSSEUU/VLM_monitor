from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from typing import cast

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_acquisition_rows as subject
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveDocumentColumn,
    M6LiveReader,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_plan import (
    MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES,
    M6SQLiteAcquisitionPlanFailureCode,
    _M6SQLiteAcquisitionMetadataFailure,
)
from labcourt.contracts.enums import AcquisitionAction, ArtifactKind
from labcourt.contracts.evidence import (
    AcquisitionParameters,
    RecropParameters,
    RedetectHighResolutionParameters,
    RequestMoreFramesParameters,
    ToolResult,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.storage import ArtifactRef


class _Cursor:
    def __init__(self, rows: Iterable[sqlite3.Row]) -> None:
        self._rows = tuple(rows)
        self.fetch_sizes: list[int] = []
        self.closed = False

    def fetchmany(self, size: int) -> list[sqlite3.Row]:
        self.fetch_sizes.append(size)
        return list(self._rows[:size])

    def close(self) -> None:
        self.closed = True


class _Reader:
    def __init__(
        self,
        rows: Iterable[sqlite3.Row] = (),
        *,
        rows_by_table: dict[str, Iterable[sqlite3.Row]] | None = None,
    ) -> None:
        self.rows = tuple(rows)
        self.rows_by_table = {
            table: tuple(values) for table, values in (rows_by_table or {}).items()
        }
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.cursors: list[_Cursor] = []
        self.length_calls: list[tuple[M6LiveDocumentColumn, int]] = []
        self.length = 7

    def execute(self, sql: str, parameters: tuple[object, ...]) -> _Cursor:
        self.queries.append((sql, parameters))
        matching = next(
            (values for table, values in self.rows_by_table.items() if f"FROM {table}" in sql),
            self.rows,
        )
        cursor = _Cursor(matching)
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


def _sha(value: int) -> str:
    return f"{value:064x}"


def _ref(kind: ArtifactKind, artifact_id: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


def _result(
    *,
    index: int,
    action: AcquisitionAction,
) -> ToolResult:
    pack = _ref(ArtifactKind.EVIDENCE_PACK, _sha(100))
    parameters: AcquisitionParameters
    inputs: tuple[ArtifactRef, ...]
    outputs: tuple[ArtifactRef, ...]
    if action == AcquisitionAction.REQUEST_MORE_FRAMES:
        parameters = RequestMoreFramesParameters(
            action=action,
            camera_id="cam-1",
            stream_id="stream-1",
            start_frame=1,
            end_frame_exclusive=3,
        )
        inputs = (pack,)
        outputs = (
            _ref(ArtifactKind.FRAME, "cam-1:stream-1:1"),
            _ref(ArtifactKind.FRAME, "cam-1:stream-1:2"),
        )
    elif action == AcquisitionAction.RECROP:
        frame = _ref(ArtifactKind.FRAME, "cam-1:stream-1:1")
        parameters = RecropParameters(
            action=action,
            frame_id=frame.artifact_id,
            bbox=BBoxXYXY(x1=1, y1=2, x2=3, y2=4),
        )
        inputs = tuple(sorted((pack, frame), key=lambda value: value.sort_key))
        outputs = (_ref(ArtifactKind.CROP, _sha(201)),)
    elif action == AcquisitionAction.REDETECT_HIGH_RES:
        crop = _ref(ArtifactKind.CROP, _sha(201))
        parameters = RedetectHighResolutionParameters(
            action=action,
            crop_id=crop.artifact_id,
            prompts=("goggles",),
        )
        inputs = tuple(sorted((pack, crop), key=lambda value: value.sort_key))
        outputs = (_ref(ArtifactKind.DETECTION, "detection-1"),)
    else:
        parameters = TrackConfidenceCurveParameters(
            action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
            track_ref="cam-1:epoch-1:track-1",
            start_frame=1,
            end_frame_exclusive=3,
        )
        inputs = (pack,)
        outputs = (_ref(ArtifactKind.OBJECTIVE_FACT, "objective-fact-1"),)
    return ToolResult(
        tool_result_id=_sha(index),
        action=action,
        input_refs=inputs,
        output_refs=tuple(sorted(outputs, key=lambda value: value.sort_key)),
        validated_parameters=parameters,
        execution_manifest_id=_sha(500 + index),
    )


def _strip_allowed_body_uses(sql: str, column: str) -> str:
    without_type = re.sub(rf"typeof\(\s*(?:\w+\.)?{column}\s*\)", "", sql)
    return re.sub(rf"octet_length\(\s*(?:\w+\.)?{column}\s*\)", "", without_type)


def test_primary_enumerates_six_case_tables_and_packs_without_bodies(
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
            rows.requests,
            rows.claims,
            rows.manifests,
            rows.publications,
            rows.receipts,
            rows.derivations,
            rows.packs,
        )
    )
    expected = {
        "m4_acquisition_requests": ("request_json", "ORDER BY acquisition_request_id", 65),
        "m4_acquisition_execution_claims": (
            "request_json claim_json",
            "ORDER BY acquisition_request_id",
            65,
        ),
        "m4_tool_execution_manifests": (
            "manifest_json",
            "ORDER BY acquisition_request_id, execution_manifest_id",
            65,
        ),
        "m4_acquisition_execution_publications": (
            "publication_json",
            "ORDER BY acquisition_request_id, execution_publication_id",
            65,
        ),
        "m4_tool_execution_receipts": (
            "receipt_json",
            "ORDER BY acquisition_request_id, receipt_id",
            65,
        ),
        "m4_evidence_pack_derivations": (
            "derivation_json",
            "ORDER BY new_pack_version, new_pack_id, derivation_id",
            65,
        ),
        "evidence_packs": ("pack_json", "ORDER BY version, pack_id", 66),
    }
    assert len(reader.queries) == len(expected)
    seen: set[str] = set()
    for sql, parameters in reader.queries:
        table = next(table for table in expected if f"FROM {table}" in sql)
        seen.add(table)
        body_names, ordering, limit = expected[table]
        assert parameters == ("run-1", "case-1")
        assert "SELECT *" not in sql.upper()
        assert "WHERE run_id = ? AND case_id = ?" in sql
        assert ordering in sql
        assert f"LIMIT {limit}" in sql
        assert "json_extract" not in sql
        assert re.search(r"\bIN\s*\(", sql, re.IGNORECASE) is None
        for body in body_names.split():
            assert f"typeof({body})" in sql
            assert f"octet_length({body})" in sql
            assert body not in _strip_allowed_body_uses(sql, body)
    assert seen == set(expected)


def test_primary_exact_64_is_accepted_and_65th_row_fails_closed() -> None:
    accepted_reader = _Reader([_row({})] * 64)
    accepted = subject.read_primary_rows(
        _reader(accepted_reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert all(
        len(group) == 64
        for group in (
            accepted.requests,
            accepted.claims,
            accepted.manifests,
            accepted.publications,
            accepted.receipts,
            accepted.derivations,
        )
    )
    assert len(accepted.packs) == 64
    assert all(cursor.closed for cursor in accepted_reader.cursors)

    rejected_reader = _Reader([_row({})] * 65)
    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as caught:
        subject.read_primary_rows(
            _reader(rejected_reader),
            run_id="run-1",
            case_id="case-1",
        )
    assert caught.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.ROW_LIMIT_EXCEEDED
    assert rejected_reader.cursors[0].fetch_sizes == [65]
    assert rejected_reader.cursors[0].closed


def test_pack_exact_65_is_accepted_and_66th_pack_fails_closed() -> None:
    accepted_reader = _Reader(rows_by_table={"evidence_packs": [_row({})] * 65})
    accepted = subject.read_primary_rows(
        _reader(accepted_reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert len(accepted.packs) == 65
    pack_cursor = accepted_reader.cursors[-1]
    assert pack_cursor.fetch_sizes == [66]
    assert pack_cursor.closed

    rejected_reader = _Reader(rows_by_table={"evidence_packs": [_row({})] * 66})
    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as caught:
        subject.read_primary_rows(
            _reader(rejected_reader),
            run_id="run-1",
            case_id="case-1",
        )
    assert caught.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.ROW_LIMIT_EXCEEDED
    assert rejected_reader.cursors[-1].fetch_sizes == [66]
    assert rejected_reader.cursors[-1].closed


def test_claim_freezes_distinct_request_and_claim_lengths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    reader = _Reader()
    row = _row(
        {
            "document_rowid": 9,
            "claim_request_document_type": "text",
            "claim_request_document_bytes": 11,
            "claim_document_type": "text",
            "claim_document_bytes": 17,
        }
    )
    assert (
        subject.document_bytes(
            _reader(reader),
            row,
            subject.M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM_REQUEST,
        )
        == 11
    )
    assert (
        subject.document_bytes(
            _reader(reader),
            row,
            subject.M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM,
        )
        == 17
    )
    assert reader.length_calls == []


def test_old_sqlite_fallback_uses_all_seven_closed_acquisition_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", False)
    reader = _Reader()
    routes = (
        subject.M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_REQUEST,
        subject.M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM_REQUEST,
        subject.M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM,
        subject.M6SQLiteAcquisitionRowDocumentRoute.TOOL_EXECUTION_MANIFEST,
        subject.M6SQLiteAcquisitionRowDocumentRoute.EXECUTION_PUBLICATION,
        subject.M6SQLiteAcquisitionRowDocumentRoute.TOOL_EXECUTION_RECEIPT,
        subject.M6SQLiteAcquisitionRowDocumentRoute.EVIDENCE_PACK_DERIVATION,
    )
    for rowid, route in enumerate(routes, start=1):
        rowid_alias, type_alias, size_alias = subject._DOCUMENT_METADATA[route]
        row = _row({rowid_alias: rowid, type_alias: "text", size_alias: None})
        assert subject.document_bytes(_reader(reader), row, route) == reader.length
    assert reader.length_calls == [
        (subject._LIVE_DOCUMENT_ROUTE[route], rowid) for rowid, route in enumerate(routes, start=1)
    ]


def test_old_sqlite_primary_sql_keeps_types_and_uses_null_lengths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", False)
    reader = _Reader()
    subject.read_primary_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert all("typeof(" in sql and "octet_length(" not in sql for sql, _ in reader.queries)
    claim_sql = next(
        sql for sql, _ in reader.queries if "FROM m4_acquisition_execution_claims" in sql
    )
    assert "NULL AS claim_request_document_bytes" in claim_sql
    assert "NULL AS claim_document_bytes" in claim_sql


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        (
            {
                "document_rowid": 1,
                "request_document_type": "blob",
                "request_document_bytes": 1,
            },
            M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID,
        ),
        (
            {
                "document_rowid": 0,
                "request_document_type": "text",
                "request_document_bytes": 1,
            },
            M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            {
                "document_rowid": 1,
                "request_document_type": "text",
                "request_document_bytes": 0,
            },
            M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID,
        ),
        (
            {
                "document_rowid": 1,
                "request_document_type": "text",
                "request_document_bytes": MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES + 1,
            },
            M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_TOO_LARGE,
        ),
    ],
)
def test_document_metadata_types_and_caps_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    row: dict[str, object],
    expected: M6SQLiteAcquisitionPlanFailureCode,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as caught:
        subject.document_bytes(
            _reader(_Reader()),
            _row(row),
            subject.M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_REQUEST,
        )
    assert caught.value.reason_code == expected


def test_hearing_support_fully_enumerates_case_with_stable_literal_sql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    reader = _Reader()
    rows = subject.read_hearing_support_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert not rows.checkpoints and not rows.rounds
    expected = {
        "m4_hearing_checkpoints": (
            "checkpoint_json",
            "ORDER BY hearing_id, version, checkpoint_id",
        ),
        "m4_hearing_rounds": ("round_json", "ORDER BY hearing_id, round_index, round_id"),
    }
    assert len(reader.queries) == 2
    for sql, parameters in reader.queries:
        table = next(table for table in expected if f"FROM {table}" in sql)
        body, ordering = expected[table]
        assert parameters == ("run-1", "case-1")
        assert ordering in sql
        assert "LIMIT 20001" in sql
        assert f"typeof({body})" in sql
        assert f"octet_length({body})" in sql
        assert body not in _strip_allowed_body_uses(sql, body)
        assert re.search(r"\bIN\s*\(", sql, re.IGNORECASE) is None
        assert "json_extract" not in sql


def test_transition_support_is_case_scoped_and_ends_at_selected_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    reader = _Reader()
    rows = subject.read_transition_support_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
        selected_case_revision=7,
    )
    assert not rows.case_versions and not rows.audits
    assert len(reader.queries) == 2
    case_sql, case_parameters = reader.queries[0]
    audit_sql, audit_parameters = reader.queries[1]
    assert case_parameters == audit_parameters == ("run-1", "case-1", 7)
    assert "version.revision <= ?" in case_sql
    assert "ORDER BY version.revision" in case_sql
    assert "typeof(version.case_json)" in case_sql
    assert "version.case_json" not in _strip_allowed_body_uses(case_sql, "case_json")
    assert "JOIN case_versions AS version" in audit_sql
    assert "version.revision <= ?" in audit_sql
    assert "ORDER BY version.revision, audit.sequence" in audit_sql
    assert "typeof(audit.entry_json)" in audit_sql
    assert "audit.entry_json" not in _strip_allowed_body_uses(audit_sql, "entry_json")
    assert all("LIMIT 20001" in sql for sql, _ in reader.queries)


def test_output_support_is_targeted_only_by_typed_tool_results_and_bounded() -> None:
    reader = _Reader([_row({"support_rowid": 1})])
    tool_results = (
        _result(index=1, action=AcquisitionAction.REQUEST_MORE_FRAMES),
        _result(index=2, action=AcquisitionAction.RECROP),
        _result(index=3, action=AcquisitionAction.REDETECT_HIGH_RES),
        _result(index=4, action=AcquisitionAction.TRACK_CONFIDENCE_CURVE),
    )
    rows = subject.read_selected_tool_result_output_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
        selected_case_tool_results=tool_results,
    )
    assert len(rows.frames) == 2
    assert len(rows.detections) == 1
    assert len(rows.crops) == 1
    assert len(reader.queries) == 4
    assert [parameters for _, parameters in reader.queries] == [
        ("run-1", "cam-1:stream-1:1"),
        ("run-1", "cam-1:stream-1:2"),
        ("run-1", "detection-1"),
        ("run-1", "case-1", _sha(201)),
    ]
    assert all("LIMIT 2" in sql for sql, _ in reader.queries)
    assert all("SELECT *" not in sql.upper() for sql, _ in reader.queries)
    assert all(re.search(r"\bIN\s*\(", sql, re.IGNORECASE) is None for sql, _ in reader.queries)
    assert all("json_extract" not in sql for sql, _ in reader.queries)
    assert all(
        body not in sql
        for sql, _ in reader.queries
        for body in ("document_json", "crop_json", "pack_json")
    )


def test_output_support_rejects_non_tool_result_input_before_sql() -> None:
    reader = _Reader()
    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as caught:
        subject.read_selected_tool_result_output_rows(
            _reader(reader),
            run_id="run-1",
            case_id="case-1",
            selected_case_tool_results=cast(tuple[ToolResult, ...], (object(),)),
        )
    assert caught.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT
    assert reader.queries == []


def test_output_support_preflights_total_and_per_route_before_sql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_SUPPORT_LIMIT", 1)
    reader = _Reader()
    with pytest.raises(_M6SQLiteAcquisitionMetadataFailure) as caught:
        subject.read_selected_tool_result_output_rows(
            _reader(reader),
            run_id="run-1",
            case_id="case-1",
            selected_case_tool_results=(
                _result(index=1, action=AcquisitionAction.REQUEST_MORE_FRAMES),
            ),
        )
    assert caught.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.ROW_LIMIT_EXCEEDED
    assert reader.queries == []
