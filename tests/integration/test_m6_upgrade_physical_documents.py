from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import cast

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_physical_documents as physical_documents
from labcourt.adapters.storage._sqlite_m6_upgrade_physical_documents import (
    M6SQLitePhysicalDocumentError,
    M6SQLitePhysicalDocumentFailureCode,
    M6SQLitePhysicalRouteCapability,
    m6_sqlite_physical_route_capability,
    resolve_m6_sqlite_canonical_physical_document,
    resolve_m6_sqlite_canonical_physical_identity,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import Detection
from labcourt.contracts.hearing import ToolExecutionManifest
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m5_precedents import M5EmbeddingVector
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
    m6_upgrade_physical_byte_authority_for,
)
from tests.integration.test_m4_acquisition_execution_fencing import _committed_successor
from tests.integration.test_m5_precedent_exposure_sqlite import _proposed, _runtime
from tests.integration.test_m5_sqlite_precedents import RUN_ID, _authority


def _sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _claim(
    *,
    source: M6UpgradePhysicalArtifactSource,
    kind: M6UpgradePhysicalArtifactKind,
    artifact_id: str,
    document: str,
    container_id: str | None = None,
) -> M6UpgradePhysicalArtifactRef:
    digest = _sha256(document)
    return M6UpgradePhysicalArtifactRef(
        source=source,
        kind=kind,
        artifact_id=artifact_id,
        container_id=container_id,
        document_sha256=digest,
        content_sha256=digest,
        size_bytes=len(document.encode("utf-8")),
    )


def _snapshot(database: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database, isolation_level=None)
    connection.execute("BEGIN")
    assert connection.in_transaction
    return connection


def _preflight_detection_connection(document: str) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute(
        """
        CREATE TABLE detections(
            run_id TEXT NOT NULL,
            detection_id TEXT NOT NULL,
            document_json TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "INSERT INTO detections VALUES (?, ?, ?)",
        ("run-preflight", "detection-1", document),
    )
    connection.execute("BEGIN")
    return connection


def _raw_row(database: Path, sql: str, parameters: tuple[object, ...]) -> tuple[object, ...]:
    with sqlite3.connect(database) as connection:
        row = connection.execute(sql, parameters).fetchone()
    assert row is not None
    return cast(tuple[object, ...], row)


def test_route_matrix_separates_four_generic_documents_from_selected_case_pack_plan() -> None:
    legal: set[tuple[M6UpgradePhysicalArtifactSource, M6UpgradePhysicalArtifactKind]] = set()
    for source in M6UpgradePhysicalArtifactSource:
        for kind in M6UpgradePhysicalArtifactKind:
            try:
                m6_upgrade_physical_byte_authority_for(source, kind)
            except ValueError:
                continue
            legal.add((source, kind))

    assert len(legal) == 21
    supported = {
        (
            M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            M6UpgradePhysicalArtifactKind.DETECTION,
        ),
        (
            M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        ),
        (
            M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            M6UpgradePhysicalArtifactKind.EMBEDDING,
        ),
        (
            M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
        ),
    }
    observed = {
        route
        for route in legal
        if m6_sqlite_physical_route_capability(*route)
        == M6SQLitePhysicalRouteCapability.SUPPORTED_CANONICAL
    }
    assert observed == supported
    assert (
        m6_sqlite_physical_route_capability(
            M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
            M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
        )
        == M6SQLitePhysicalRouteCapability.SUPPORTED_SELECTED_CASE_PLAN
    )
    assert (
        sum(
            m6_sqlite_physical_route_capability(*route)
            == M6SQLitePhysicalRouteCapability.UNSUPPORTED_MODEL_CLOSURE
            for route in legal
        )
        == 12
    )
    assert (
        sum(
            m6_sqlite_physical_route_capability(*route)
            == M6SQLitePhysicalRouteCapability.UNSUPPORTED_PHYSICAL_BYTES
            for route in legal
        )
        == 4
    )
    assert all(
        m6_sqlite_physical_route_capability(*route)
        != M6SQLitePhysicalRouteCapability.SUPPORTED_CANONICAL
        for route in legal - supported
    )
    with pytest.raises(ValueError, match="not legal"):
        m6_sqlite_physical_route_capability(
            M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
            M6UpgradePhysicalArtifactKind.DETECTION,
        )


@pytest.mark.parametrize(
    "claim",
    (
        M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            kind=M6UpgradePhysicalArtifactKind.FRAME,
            artifact_id="cam-01:stream-01:0",
            document_sha256="a" * 64,
            content_sha256="b" * 64,
            size_bytes=1,
        ),
        M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
            kind=M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            artifact_id="response-screening",
            document_sha256="a" * 64,
            content_sha256="b" * 64,
            size_bytes=1,
        ),
        M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
            kind=M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            artifact_id="response-hearing",
            document_sha256="a" * 64,
            content_sha256="b" * 64,
            size_bytes=1,
        ),
        M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            kind=M6UpgradePhysicalArtifactKind.TOOL_RESULT,
            artifact_id="tool-result",
            document_sha256="a" * 64,
            content_sha256="a" * 64,
            size_bytes=1,
        ),
    ),
)
def test_frame_model_response_and_tool_result_are_explicitly_unsupported(
    claim: M6UpgradePhysicalArtifactRef,
) -> None:
    with (
        sqlite3.connect(":memory:") as connection,
        pytest.raises(M6SQLitePhysicalDocumentError) as failure,
    ):
        resolve_m6_sqlite_canonical_physical_document(
            connection=connection,
            claim=claim,
            expected_run_id="run-physical",
            expected_manifest_id="c" * 64,
        )
    assert failure.value.reason_code == M6SQLitePhysicalDocumentFailureCode.UNSUPPORTED


def test_supported_lookup_requires_a_caller_owned_sqlite_snapshot() -> None:
    claim = M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        kind=M6UpgradePhysicalArtifactKind.DETECTION,
        artifact_id="detection-1",
        container_id="cam-01:stream-01:0",
        document_sha256="a" * 64,
        content_sha256="a" * 64,
        size_bytes=1,
    )
    with (
        sqlite3.connect(":memory:") as connection,
        pytest.raises(M6SQLitePhysicalDocumentError) as failure,
    ):
        resolve_m6_sqlite_canonical_physical_document(
            connection=connection,
            claim=claim,
            expected_run_id="run-physical",
            expected_manifest_id="c" * 64,
        )
    assert failure.value.reason_code == (M6SQLitePhysicalDocumentFailureCode.TRANSACTION_REQUIRED)


def test_resolves_detection_from_one_real_authority_snapshot(
    tmp_path: Path,
) -> None:
    source = tmp_path / "m2"
    source.mkdir()
    from tests.integration.test_m4_hearing_coordinator import _escalated_case

    database, _repository, pack, _case = _escalated_case(source)
    detection_id, frame_id, detection_json = _raw_row(
        database,
        "SELECT detection_id, frame_id, document_json FROM detections WHERE run_id = ?",
        (RUN_ID,),
    )
    assert isinstance(detection_id, str)
    assert isinstance(frame_id, str)
    assert isinstance(detection_json, str)
    detection_claim = _claim(
        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        kind=M6UpgradePhysicalArtifactKind.DETECTION,
        artifact_id=detection_id,
        container_id=frame_id,
        document=detection_json,
    )
    connection = _snapshot(database)
    try:
        detection = resolve_m6_sqlite_canonical_physical_identity(
            connection=connection,
            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            kind=M6UpgradePhysicalArtifactKind.DETECTION,
            artifact_id=detection_id,
            expected_run_id=RUN_ID,
            expected_manifest_id=pack.manifest_id,
        )
    finally:
        connection.rollback()
        connection.close()

    assert detection.artifact_ref == detection_claim
    assert isinstance(detection.document, Detection)
    assert detection.canonical_document == detection_json


def test_generic_resolver_cannot_bypass_the_selected_case_evidence_pack_plan() -> None:
    claim = M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
        kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
        artifact_id="e" * 64,
        document_sha256="a" * 64,
        content_sha256="a" * 64,
        size_bytes=1,
    )
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute("BEGIN")
    try:
        with pytest.raises(M6SQLitePhysicalDocumentError) as failure:
            resolve_m6_sqlite_canonical_physical_document(
                connection=connection,
                claim=claim,
                expected_run_id="run-physical",
                expected_manifest_id="c" * 64,
            )
    finally:
        connection.rollback()
        connection.close()
    assert failure.value.reason_code == M6SQLitePhysicalDocumentFailureCode.UNSUPPORTED


def test_identity_first_lookup_rejects_untyped_or_unsupported_routes() -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.execute("BEGIN")
        with pytest.raises(M6SQLitePhysicalDocumentError) as untyped:
            resolve_m6_sqlite_canonical_physical_identity(
                connection=connection,
                source="M2_PERCEPTION",  # type: ignore[arg-type]
                kind=M6UpgradePhysicalArtifactKind.DETECTION,
                artifact_id="detection-1",
                expected_run_id="run-physical",
                expected_manifest_id="c" * 64,
            )
        with pytest.raises(M6SQLitePhysicalDocumentError) as unsupported:
            resolve_m6_sqlite_canonical_physical_identity(
                connection=connection,
                source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                kind=M6UpgradePhysicalArtifactKind.FRAME,
                artifact_id="cam-01:stream-01:0",
                expected_run_id="run-physical",
                expected_manifest_id="c" * 64,
            )
    assert untyped.value.reason_code == M6SQLitePhysicalDocumentFailureCode.INVALID_ARGUMENT
    assert unsupported.value.reason_code == M6SQLitePhysicalDocumentFailureCode.UNSUPPORTED


def test_resolves_m4_tool_execution_manifest_from_real_authority_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "m4"
    source.mkdir()
    database, _host, _request, publication, _committed = _committed_successor(
        source,
        monkeypatch,
    )
    manifest = publication.execution_manifest
    raw = canonical_json(manifest.model_dump(mode="json"))
    claim = _claim(
        source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
        kind=M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        artifact_id=manifest.execution_manifest_id,
        document=raw,
    )

    connection = _snapshot(database)
    try:
        resolved = resolve_m6_sqlite_canonical_physical_document(
            connection=connection,
            claim=claim,
            expected_run_id=manifest.run_id,
            expected_manifest_id=manifest.manifest_id,
        )
    finally:
        connection.rollback()
        connection.close()

    assert resolved.artifact_ref == claim
    assert isinstance(resolved.document, ToolExecutionManifest)
    assert resolved.document == manifest


def test_resolves_m5_embedding_and_exposure_from_one_real_authority_snapshot(
    tmp_path: Path,
) -> None:
    source = tmp_path / "m5"
    source.mkdir()
    runtime = _runtime(source)
    authority = _authority(runtime.manifest, "canonical-route-precedent")
    runtime.m5.append_authority(authority, None)
    runtime.committer.commit(_proposed(runtime))
    exposure = runtime.committer.load_exposure(
        RUN_ID,
        runtime.prepared.cycle_scope.cycle_id,
    )
    embedding = authority.text_embedding
    assert exposure is not None
    assert embedding is not None
    embedding_raw = canonical_json(embedding.model_dump(mode="json"))
    exposure_raw = canonical_json(exposure.model_dump(mode="json"))
    embedding_claim = _claim(
        source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
        artifact_id=embedding.embedding_id,
        document=embedding_raw,
    )
    exposure_claim = _claim(
        source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        kind=M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
        artifact_id=exposure.exposure_id,
        document=exposure_raw,
    )

    connection = _snapshot(runtime.database)
    try:
        resolved_embedding = resolve_m6_sqlite_canonical_physical_document(
            connection=connection,
            claim=embedding_claim,
            expected_run_id=RUN_ID,
            expected_manifest_id=runtime.manifest.manifest_id,
        )
        resolved_exposure = resolve_m6_sqlite_canonical_physical_document(
            connection=connection,
            claim=exposure_claim,
            expected_run_id=RUN_ID,
            expected_manifest_id=runtime.manifest.manifest_id,
        )
    finally:
        connection.rollback()
        connection.close()

    assert isinstance(resolved_embedding.document, M5EmbeddingVector)
    assert resolved_embedding.document == embedding
    assert resolved_embedding.artifact_ref == embedding_claim
    assert isinstance(resolved_exposure.document, M5PrecedentExposureBatchAuthority)
    assert resolved_exposure.document == exposure
    assert resolved_exposure.artifact_ref == exposure_claim


def test_sql_preflight_rejects_oversized_document_before_typed_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_id = "d" * 64
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.executescript(
        """
        CREATE TABLE runs(run_id TEXT PRIMARY KEY, manifest_id TEXT NOT NULL);
        CREATE TABLE detections(
            run_id TEXT NOT NULL,
            detection_id TEXT NOT NULL,
            document_json TEXT NOT NULL
        );
        INSERT INTO runs VALUES ('run-preflight',
            'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');
        INSERT INTO detections VALUES ('run-preflight', 'detection-1', 'not-json-at-all');
        """
    )
    connection.execute("BEGIN")
    monkeypatch.setattr(
        physical_documents,
        "MAX_M6_SQLITE_CANONICAL_PHYSICAL_DOCUMENT_BYTES",
        4,
    )
    claim = M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        kind=M6UpgradePhysicalArtifactKind.DETECTION,
        artifact_id="detection-1",
        container_id="cam-01:stream-01:0",
        document_sha256="a" * 64,
        content_sha256="a" * 64,
        size_bytes=1,
    )
    try:
        with pytest.raises(M6SQLitePhysicalDocumentError) as failure:
            resolve_m6_sqlite_canonical_physical_document(
                connection=connection,
                claim=claim,
                expected_run_id="run-preflight",
                expected_manifest_id=manifest_id,
            )
    finally:
        connection.rollback()
        connection.close()
    assert failure.value.reason_code == M6SQLitePhysicalDocumentFailureCode.DOCUMENT_TOO_LARGE


def test_canonical_preflight_uses_sqlite_octet_length_metadata_shortcut() -> None:
    if sqlite3.sqlite_version_info < physical_documents._SQLITE_OCTET_LENGTH_MIN_VERSION:
        pytest.skip("SQLite octet_length is unavailable")
    document = '{"label":"护目镜"}'
    connection = _preflight_detection_connection(document)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        observed_bytes = physical_documents._preflight_document(
            connection,
            physical_documents._DETECTION_ROUTE,
            "run-preflight",
            "detection-1",
        )
        bytecode = connection.execute(
            """
            EXPLAIN
            SELECT octet_length(document_json)
            FROM detections
            WHERE run_id = ? AND detection_id = ?
            """,
            ("run-preflight", "detection-1"),
        ).fetchall()
    finally:
        connection.rollback()
        connection.close()

    assert observed_bytes == len(document.encode("utf-8"))
    assert any("octet_length(document_json)" in statement for statement in statements)
    document_column_ops = [row for row in bytecode if row[1] == "Column" and row[3] == 2]
    assert document_column_ops
    assert all(int(row[6]) & 0x40 for row in document_column_ops)


def test_canonical_preflight_has_a_pre_343_incremental_blob_size_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(physical_documents, "_USE_SQLITE_OCTET_LENGTH", False)
    document = '{"label":"护目镜"}'
    connection = _preflight_detection_connection(document)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        observed_bytes = physical_documents._preflight_document(
            connection,
            physical_documents._DETECTION_ROUTE,
            "run-preflight",
            "detection-1",
        )
    finally:
        connection.rollback()
        connection.close()

    assert observed_bytes == len(document.encode("utf-8"))
    assert all("octet_length" not in statement for statement in statements)


def test_sql_preflight_rejects_more_than_one_matching_authority_row() -> None:
    manifest_id = "d" * 64
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.executescript(
        """
        CREATE TABLE runs(run_id TEXT PRIMARY KEY, manifest_id TEXT NOT NULL);
        CREATE TABLE detections(
            run_id TEXT NOT NULL,
            detection_id TEXT NOT NULL,
            document_json TEXT NOT NULL
        );
        INSERT INTO runs VALUES ('run-row-limit',
            'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');
        INSERT INTO detections VALUES ('run-row-limit', 'detection-1', '{}');
        INSERT INTO detections VALUES ('run-row-limit', 'detection-1', '{}');
        """
    )
    connection.execute("BEGIN")
    claim = M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        kind=M6UpgradePhysicalArtifactKind.DETECTION,
        artifact_id="detection-1",
        container_id="cam-01:stream-01:0",
        document_sha256="a" * 64,
        content_sha256="a" * 64,
        size_bytes=1,
    )
    try:
        with pytest.raises(M6SQLitePhysicalDocumentError) as failure:
            resolve_m6_sqlite_canonical_physical_document(
                connection=connection,
                claim=claim,
                expected_run_id="run-row-limit",
                expected_manifest_id=manifest_id,
            )
    finally:
        connection.rollback()
        connection.close()
    assert failure.value.reason_code == M6SQLitePhysicalDocumentFailureCode.ROW_LIMIT_EXCEEDED


def test_reconstructed_ref_and_typed_index_checks_reject_two_forgery_classes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "claim"
    source.mkdir()
    from tests.integration.test_m4_hearing_coordinator import _escalated_case

    database, _repository, pack, _case = _escalated_case(source)
    detection_id, frame_id, detection_json = _raw_row(
        database,
        "SELECT detection_id, frame_id, document_json FROM detections WHERE run_id = ?",
        (RUN_ID,),
    )
    assert isinstance(detection_id, str)
    assert isinstance(frame_id, str)
    assert isinstance(detection_json, str)
    forged = M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        kind=M6UpgradePhysicalArtifactKind.DETECTION,
        artifact_id=detection_id,
        container_id=frame_id,
        document_sha256="f" * 64,
        content_sha256="f" * 64,
        size_bytes=len(detection_json.encode("utf-8")),
    )
    connection = _snapshot(database)
    try:
        with pytest.raises(M6SQLitePhysicalDocumentError) as failure:
            resolve_m6_sqlite_canonical_physical_document(
                connection=connection,
                claim=forged,
                expected_run_id=RUN_ID,
                expected_manifest_id=pack.manifest_id,
            )
    finally:
        connection.rollback()
        connection.close()
    assert failure.value.reason_code == M6SQLitePhysicalDocumentFailureCode.CLAIM_MISMATCH

    correct = _claim(
        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        kind=M6UpgradePhysicalArtifactKind.DETECTION,
        artifact_id=detection_id,
        container_id=frame_id,
        document=detection_json,
    )
    with sqlite3.connect(database) as writer:
        writer.execute("DROP TRIGGER detections_no_update")
        changed = writer.execute(
            "UPDATE detections SET label = ? WHERE run_id = ? AND detection_id = ?",
            ("forged-index-label", RUN_ID, detection_id),
        )
        assert changed.rowcount == 1
    connection = _snapshot(database)
    try:
        with pytest.raises(M6SQLitePhysicalDocumentError) as index_failure:
            resolve_m6_sqlite_canonical_physical_document(
                connection=connection,
                claim=correct,
                expected_run_id=RUN_ID,
                expected_manifest_id=pack.manifest_id,
            )
    finally:
        connection.rollback()
        connection.close()
    assert index_failure.value.reason_code == (
        M6SQLitePhysicalDocumentFailureCode.INDEX_BINDING_MISMATCH
    )
