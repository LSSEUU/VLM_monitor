from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from typing import cast

import pytest

from labcourt.adapters.storage import _sqlite_m6_live_read_cut as cut_subject
from labcourt.adapters.storage import _sqlite_m6_upgrade_m5_precedent_rows as subject
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveDocumentColumn,
    M6LiveReader,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_plan import (
    MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_BYTES,
    M6SQLiteM5PrecedentPlanFailureCode,
    _M6SQLiteM5PrecedentMetadataFailure,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
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
        rows_by_parameters: dict[tuple[object, ...], Iterable[sqlite3.Row]] | None = None,
    ) -> None:
        self.rows = tuple(rows)
        self.rows_by_table = {
            table: tuple(values) for table, values in (rows_by_table or {}).items()
        }
        self.rows_by_parameters = {
            parameters: tuple(values) for parameters, values in (rows_by_parameters or {}).items()
        }
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.cursors: list[_Cursor] = []
        self.length_calls: list[tuple[M6LiveDocumentColumn, int]] = []
        self.length = 7

    def execute(self, sql: str, parameters: tuple[object, ...]) -> _Cursor:
        self.queries.append((sql, parameters))
        matching = self.rows_by_parameters.get(parameters)
        if matching is None:
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


def _strip_allowed_body_uses(sql: str, column: str) -> str:
    without_type = re.sub(rf"typeof\(\s*{column}\s*\)", "", sql)
    return re.sub(rf"octet_length\(\s*{column}\s*\)", "", without_type)


def _observation(
    kind: M6UpgradePhysicalArtifactKind,
    artifact_id: str,
) -> M6UpgradeObservedArtifactIdentity:
    return M6UpgradeObservedArtifactIdentity(
        source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        kind=kind,
        artifact_id=artifact_id,
        usage=(
            M6UpgradeArtifactUsage.PRODUCED
            if kind != M6UpgradePhysicalArtifactKind.EMBEDDING
            else M6UpgradeArtifactUsage.CONSUMED
        ),
    )


def test_live_cut_adds_exact_three_m5_document_length_routes() -> None:
    expected = {
        M6LiveDocumentColumn.M5_PRECEDENT_EMBEDDING_DOCUMENT: (
            "precedent_embeddings",
            "embedding_json",
        ),
        M6LiveDocumentColumn.M5_PRECEDENT_AUTHORITY_DOCUMENT: (
            "precedents",
            "authority_json",
        ),
        M6LiveDocumentColumn.M5_PRECEDENT_EXPOSURE_DOCUMENT: (
            "m5_precedent_exposures",
            "exposure_json",
        ),
    }
    assert {route: cut_subject._DOCUMENT_COLUMN_ROUTES[route] for route in expected} == expected
    assert set(cut_subject._DOCUMENT_COLUMN_ROUTES) == set(M6LiveDocumentColumn)


def test_case_inventory_enumerates_three_tables_without_canonical_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    reader = _Reader()
    result = subject.read_case_retrieval_rows(
        _reader(reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert not result.hearings and not result.cycles and not result.retrievals
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
    }
    assert len(reader.queries) == 3
    for sql, parameters in reader.queries:
        table = next(table for table in expected if f"FROM {table}" in sql)
        body, ordering = expected[table]
        assert parameters == ("run-1", "case-1")
        assert "SELECT *" not in sql.upper()
        assert "WHERE run_id = ? AND case_id = ?" in sql
        assert ordering in sql
        assert "LIMIT 257" in sql
        assert f"typeof({body})" in sql
        assert f"octet_length({body})" in sql
        assert body not in _strip_allowed_body_uses(sql, body)
        assert "json_extract" not in sql
        assert re.search(r"\bIN\s*\(", sql, re.IGNORECASE) is None


def test_case_inventory_exact_limit_and_sentinel_are_closed() -> None:
    accepted_reader = _Reader([_row({})] * 256)
    accepted = subject.read_case_retrieval_rows(
        _reader(accepted_reader),
        run_id="run-1",
        case_id="case-1",
    )
    assert all(
        len(group) == 256 for group in (accepted.hearings, accepted.cycles, accepted.retrievals)
    )
    assert all(cursor.fetch_sizes == [257] and cursor.closed for cursor in accepted_reader.cursors)

    rejected_reader = _Reader([_row({})] * 257)
    with pytest.raises(_M6SQLiteM5PrecedentMetadataFailure) as caught:
        subject.read_case_retrieval_rows(
            _reader(rejected_reader),
            run_id="run-1",
            case_id="case-1",
        )
    assert caught.value.reason_code == M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED
    assert rejected_reader.cursors[0].fetch_sizes == [257]
    assert rejected_reader.cursors[0].closed


def test_old_sqlite_fallback_uses_all_six_closed_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", False)
    reader = _Reader()
    for rowid, route in enumerate(subject.M6SQLiteM5PrecedentRowDocumentRoute, start=1):
        row = _row(
            {
                "document_rowid": rowid,
                "document_type": "text",
                "document_bytes": None,
            }
        )
        assert subject.document_bytes(_reader(reader), row, route) == reader.length
    assert reader.length_calls == [
        (subject._LIVE_DOCUMENT_ROUTE[route], rowid)
        for rowid, route in enumerate(subject.M6SQLiteM5PrecedentRowDocumentRoute, start=1)
    ]


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        (
            {"document_rowid": 1, "document_type": "blob", "document_bytes": 1},
            M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_INVALID,
        ),
        (
            {"document_rowid": 0, "document_type": "text", "document_bytes": 1},
            M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            {"document_rowid": 1, "document_type": "text", "document_bytes": 0},
            M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_INVALID,
        ),
        (
            {
                "document_rowid": 1,
                "document_type": "text",
                "document_bytes": MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_BYTES + 1,
            },
            M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_TOO_LARGE,
        ),
    ],
)
def test_document_metadata_failures_are_typed_and_closed(
    monkeypatch: pytest.MonkeyPatch,
    row: dict[str, object],
    expected: M6SQLiteM5PrecedentPlanFailureCode,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    with pytest.raises(_M6SQLiteM5PrecedentMetadataFailure) as caught:
        subject.document_bytes(
            _reader(_Reader()),
            _row(row),
            subject.M6SQLiteM5PrecedentRowDocumentRoute.PRECEDENT_EXPOSURE,
        )
    assert caught.value.reason_code == expected
    assert caught.value.__cause__ is None


def test_point_reads_use_exact_ids_fixed_sql_and_no_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    exposure_id = _sha(1)
    embedding_id = _sha(2)
    reader = _Reader(
        rows_by_parameters={
            ("run-1", exposure_id): (_row({"exposure_id": exposure_id}),),
            ("run-1", embedding_id): (_row({"embedding_id": embedding_id}),),
        }
    )
    assert (
        len(
            subject.read_exposure_rows(
                _reader(reader),
                run_id="run-1",
                exposure_ids=(exposure_id,),
            )
        )
        == 1
    )
    assert (
        len(
            subject.read_durable_embedding_rows(
                _reader(reader),
                run_id="run-1",
                embedding_ids=(embedding_id,),
            )
        )
        == 1
    )
    assert len(reader.queries) == 2
    for sql, parameters in reader.queries:
        assert parameters in {("run-1", exposure_id), ("run-1", embedding_id)}
        assert "LIMIT 2" in sql
        assert "SELECT *" not in sql.upper()
        assert "json_extract" not in sql
        body = "exposure_json" if "m5_precedent_exposures" in sql else "embedding_json"
        assert body not in _strip_allowed_body_uses(sql, body)


def test_point_read_missing_identity_fails_closed() -> None:
    with pytest.raises(_M6SQLiteM5PrecedentMetadataFailure) as caught:
        subject.read_exposure_rows(
            _reader(_Reader()),
            run_id="run-1",
            exposure_ids=(_sha(1),),
        )
    assert caught.value.reason_code == M6SQLiteM5PrecedentPlanFailureCode.SCOPE_NOT_FOUND


def test_observed_rows_exclude_derived_query_from_durable_sql() -> None:
    exposure_id = _sha(1)
    query_embedding_id = _sha(2)
    reader = _Reader(
        rows_by_parameters={
            ("run-1", exposure_id): (_row({"exposure_id": exposure_id}),),
        }
    )
    observations = tuple(
        sorted(
            (
                _observation(
                    M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
                    exposure_id,
                ),
                _observation(M6UpgradePhysicalArtifactKind.EMBEDDING, query_embedding_id),
            ),
            key=lambda value: value.sort_key,
        )
    )
    rows = subject.read_observed_artifact_rows(
        _reader(reader),
        run_id="run-1",
        observations=observations,
        derived_query_embedding_ids=(query_embedding_id,),
    )
    assert len(rows.exposures) == 1
    assert not rows.durable_embeddings
    assert len(reader.queries) == 1
    assert "m5_precedent_exposures" in reader.queries[0][0]


def test_candidate_refs_parse_exact_stable_precedent_ids() -> None:
    refs = [
        ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id="precedent-1").model_dump(mode="json"),
        ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id="precedent-2").model_dump(mode="json"),
    ]
    rows = (
        _row({"candidate_precedent_refs_json": canonical_json(refs)}),
        _row({"candidate_precedent_refs_json": canonical_json(refs[:1])}),
    )
    assert subject.candidate_precedent_ids(rows) == ("precedent-1", "precedent-2")
    assert subject.normalized_json_sha256(rows[0], "candidate_precedent_refs_json")


def test_candidate_refs_reject_wrong_kind_or_unstable_order() -> None:
    wrong = [
        ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="cam-1:s-1:1").model_dump(mode="json")
    ]
    with pytest.raises(_M6SQLiteM5PrecedentMetadataFailure) as wrong_kind:
        subject.candidate_precedent_ids(
            (_row({"candidate_precedent_refs_json": canonical_json(wrong)}),)
        )
    assert wrong_kind.value.reason_code == (
        M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH
    )

    unstable = [
        ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id="precedent-2").model_dump(mode="json"),
        ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id="precedent-1").model_dump(mode="json"),
    ]
    with pytest.raises(_M6SQLiteM5PrecedentMetadataFailure) as unordered:
        subject.candidate_precedent_ids(
            (_row({"candidate_precedent_refs_json": canonical_json(unstable)}),)
        )
    assert unordered.value.reason_code == (
        M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH
    )


def test_candidate_revision_ranges_ignore_unrelated_run_tail_and_are_globally_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_USE_SQLITE_OCTET_LENGTH", True)
    reader = _Reader(
        rows_by_parameters={
            ("run-1", "precedent-1"): (
                _row({"precedent_id": "precedent-1", "revision": 1}),
                _row({"precedent_id": "precedent-1", "revision": 2}),
            ),
            ("run-1", "precedent-2"): (_row({"precedent_id": "precedent-2", "revision": 1}),),
        }
    )
    rows = subject.read_candidate_precedent_revision_rows(
        _reader(reader),
        run_id="run-1",
        precedent_ids=("precedent-1", "precedent-2"),
    )
    assert len(rows) == 3
    assert len(reader.queries) == 2
    assert all("WHERE run_id = ? AND precedent_id = ?" in sql for sql, _ in reader.queries)
    assert all("ORDER BY revision" in sql for sql, _ in reader.queries)
    assert all("LIMIT 20001" in sql for sql, _ in reader.queries)
    assert all(
        "authority_json" not in _strip_allowed_body_uses(sql, "authority_json")
        for sql, _ in reader.queries
    )

    monkeypatch.setattr(subject, "_SUPPORT_LIMIT", 1)
    bounded = _Reader(
        rows_by_parameters={
            ("run-1", "precedent-1"): (_row({"precedent_id": "precedent-1"}),),
            ("run-1", "precedent-2"): (_row({"precedent_id": "precedent-2"}),),
        }
    )
    with pytest.raises(_M6SQLiteM5PrecedentMetadataFailure) as caught:
        subject.read_candidate_precedent_revision_rows(
            _reader(bounded),
            run_id="run-1",
            precedent_ids=("precedent-1", "precedent-2"),
        )
    assert caught.value.reason_code == M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED


def test_precedent_revision_embedding_ids_are_exact_stable_sha_union() -> None:
    rows = (
        _row(
            {
                "text_embedding_id": _sha(1),
                "visual_embedding_ids_json": canonical_json([_sha(2), _sha(3)]),
            }
        ),
        _row(
            {
                "text_embedding_id": None,
                "visual_embedding_ids_json": canonical_json([_sha(3)]),
            }
        ),
    )
    assert subject.precedent_revision_embedding_ids(rows) == (_sha(1), _sha(2), _sha(3))

    invalid = (
        _row(
            {
                "text_embedding_id": None,
                "visual_embedding_ids_json": canonical_json([_sha(3), _sha(2)]),
            }
        ),
    )
    with pytest.raises(_M6SQLiteM5PrecedentMetadataFailure) as caught:
        subject.precedent_revision_embedding_ids(invalid)
    assert caught.value.reason_code == (M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)

    crossed_channels = (
        _row(
            {
                "text_embedding_id": _sha(2),
                "visual_embedding_ids_json": canonical_json([_sha(2)]),
            }
        ),
    )
    with pytest.raises(_M6SQLiteM5PrecedentMetadataFailure) as crossed:
        subject.precedent_revision_embedding_ids(crossed_channels)
    assert crossed.value.reason_code == (M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
