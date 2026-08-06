from __future__ import annotations

import hashlib
import inspect
import sqlite3
import traceback
from pathlib import Path
from typing import Literal

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_evidence_pack_document as pack_document
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseAuthorityDocument,
    read_m6_sqlite_case_authority,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_evidence_pack_document import (
    M6SQLiteEvidencePackDocumentError,
    M6SQLiteEvidencePackDocumentFailureCode,
    M6SQLiteEvidencePackPhysicalPlan,
    plan_m6_sqlite_evidence_pack_physical_identity,
    resolve_m6_sqlite_evidence_pack_physical_plan,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_physical_documents import (
    M6SQLiteCanonicalPhysicalDocument,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from tests.integration import test_m2_sqlite_repository as m2_fixture
from tests.integration.test_m6_upgrade_case_document import _real_m2_published_case


class _RuntimeBoundaryConnection(sqlite3.Connection):
    rejected_boundary: Literal["transaction", "cursor", "blobopen"] | None = None
    secret = ""

    @property
    def in_transaction(self) -> bool:
        if self.rejected_boundary == "transaction":
            raise RuntimeError(self.secret)
        return super().in_transaction

    def cursor(self, *args: object, **kwargs: object) -> sqlite3.Cursor:
        if self.rejected_boundary == "cursor":
            raise RuntimeError(self.secret)
        return super().cursor(*args, **kwargs)  # type: ignore[arg-type]

    def blobopen(
        self,
        table: str,
        column: str,
        row: int,
        /,
        *,
        readonly: bool = False,
        name: str = "main",
    ) -> sqlite3.Blob:
        if self.rejected_boundary == "blobopen":
            raise RuntimeError(self.secret)
        return super().blobopen(table, column, row, readonly=readonly, name=name)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _selected_authority(
    tmp_path: Path,
) -> tuple[
    Path,
    sqlite3.Connection,
    M6SQLiteCaseAuthorityDocument,
    EvidencePack,
    M6UpgradeCandidateCaseBinding,
]:
    database, _case, pack, binding = _real_m2_published_case(tmp_path)
    manifest = m2_fixture._manifest()
    connection = sqlite3.connect(database, isolation_level=None)
    connection.execute("BEGIN")
    authority = read_m6_sqlite_case_authority(
        connection=connection,
        expected_run_id=m2_fixture.RUN_ID,
        expected_manifest_id=manifest.manifest_id,
        expected_manifest_rule_version=manifest.rule_version,
        candidate_case_binding=binding,
    )
    return database, connection, authority, pack, binding


def _close(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        connection.rollback()
    connection.close()


def _metadata_connection(
    authority: M6SQLiteCaseAuthorityDocument,
    pack: EvidencePack,
    *,
    pack_json: object,
    connection_factory: type[sqlite3.Connection] = sqlite3.Connection,
) -> sqlite3.Connection:
    manifest_id = m2_fixture._manifest().manifest_id
    canonical_pack = canonical_json(pack.model_dump(mode="json"))
    connection = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=connection_factory,
    )
    connection.executescript(
        """
        CREATE TABLE runs(run_id, manifest_id);
        CREATE TABLE evidence_packs(
            run_id, pack_id, case_id, manifest_id, version, complete,
            pack_input_sha256, closure_input_sha256, pack_json,
            document_sha256, created_audit_sequence
        );
        """
    )
    connection.execute("INSERT INTO runs VALUES (?, ?)", (m2_fixture.RUN_ID, manifest_id))
    connection.execute(
        "INSERT INTO evidence_packs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            m2_fixture.RUN_ID,
            pack.pack_id,
            pack.case_id,
            manifest_id,
            pack.version,
            int(pack.complete),
            pack.pack_input_sha256,
            pack.closure_input_sha256,
            pack_json,
            _sha256(canonical_pack),
            authority.candidate_case_binding.case_audit_sequence,
        ),
    )
    connection.execute("BEGIN")
    return connection


def _plan(
    connection: sqlite3.Connection,
    authority: M6SQLiteCaseAuthorityDocument,
    pack_id: str,
) -> M6SQLiteEvidencePackPhysicalPlan:
    return plan_m6_sqlite_evidence_pack_physical_identity(
        connection=connection,
        expected_run_id=m2_fixture.RUN_ID,
        expected_manifest_id=m2_fixture._manifest().manifest_id,
        selected_case_authority=authority,
        pack_id=pack_id,
    )


def test_selected_case_plan_is_metadata_only_and_late_resolution_matches_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _database, connection, authority, pack, binding = _selected_authority(tmp_path)
    original_decoder = pack_document._decode_evidence_pack

    def forbidden_decoder(*_args: object, **_kwargs: object) -> EvidencePack:
        raise AssertionError("physical planning must not decode independent pack_json")

    monkeypatch.setattr(pack_document, "_decode_evidence_pack", forbidden_decoder)
    original_rows = pack_document._rows
    evidence_row_keys: list[set[str]] = []

    def guarded_rows(
        read_connection: object,
        sql: str,
        parameters: tuple[object, ...],
        *,
        limit: int,
    ):
        rows = original_rows(read_connection, sql, parameters, limit=limit)
        if "FROM evidence_packs" in sql:
            evidence_row_keys.extend(set(row.keys()) for row in rows)
        return rows

    monkeypatch.setattr(pack_document, "_rows", guarded_rows)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        plan = _plan(connection, authority, pack.pack_id)
        assert connection.in_transaction
        connection.set_trace_callback(None)
        planning_evidence_row_keys = tuple(evidence_row_keys)
        monkeypatch.setattr(pack_document, "_rows", original_rows)
        monkeypatch.setattr(pack_document, "_decode_evidence_pack", original_decoder)
        resolved = resolve_m6_sqlite_evidence_pack_physical_plan(
            connection=connection,
            physical_plan=plan,
        )
        assert connection.in_transaction
    finally:
        connection.set_trace_callback(None)
        _close(connection)

    canonical_pack = canonical_json(pack.model_dump(mode="json"))
    assert isinstance(plan, M6SQLiteEvidencePackPhysicalPlan)
    assert plan.selected_case_binding == binding
    assert plan.pack_authority == pack
    assert plan.expected_canonical_document == canonical_pack
    assert plan.document_rowid > 0
    assert 0 <= plan.created_audit_sequence <= binding.case_audit_sequence
    assert plan.planned_artifact_ref.source == M6UpgradePhysicalArtifactSource.M2_EVIDENCE
    assert plan.planned_artifact_ref.kind == M6UpgradePhysicalArtifactKind.EVIDENCE_PACK
    assert plan.planned_artifact_ref.artifact_id == pack.pack_id
    assert plan.planned_artifact_ref.container_id is None
    assert plan.planned_artifact_ref.document_sha256 == _sha256(canonical_pack)
    assert plan.planned_artifact_ref.content_sha256 == _sha256(canonical_pack)
    assert plan.planned_artifact_ref.size_bytes == len(canonical_pack.encode("utf-8"))
    assert planning_evidence_row_keys
    assert all("pack_json" not in keys for keys in planning_evidence_row_keys)
    evidence_selects = [statement for statement in statements if "FROM evidence_packs" in statement]
    assert evidence_selects
    assert all("SELECT pack_json" not in statement for statement in evidence_selects)

    assert isinstance(resolved, M6SQLiteCanonicalPhysicalDocument)
    assert resolved.artifact_ref == plan.planned_artifact_ref
    assert resolved.document == pack
    assert resolved.canonical_document == canonical_pack


def test_plan_requires_exact_selected_case_membership_before_storage_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _database, connection, authority, _pack, _binding = _selected_authority(tmp_path)

    def forbidden_rows(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("non-member pack must fail before SQLite lookup")

    monkeypatch.setattr(pack_document, "_rows", forbidden_rows)
    try:
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as failure:
            _plan(connection, authority, "f" * 64)
    finally:
        _close(connection)
    assert failure.value.reason_code == (
        M6SQLiteEvidencePackDocumentFailureCode.SELECTED_CASE_MEMBERSHIP_MISMATCH
    )


@pytest.mark.parametrize(
    ("assignment", "expected"),
    (
        (
            "version = version + 1",
            M6SQLiteEvidencePackDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            "document_sha256 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
            M6SQLiteEvidencePackDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        (
            "created_audit_sequence = created_audit_sequence + 1000",
            M6SQLiteEvidencePackDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
    ),
)
def test_plan_distinguishes_persisted_index_and_document_type_drift(
    tmp_path: Path,
    assignment: str,
    expected: M6SQLiteEvidencePackDocumentFailureCode,
) -> None:
    _database, connection, authority, pack, _binding = _selected_authority(tmp_path)
    connection.execute("DROP TRIGGER evidence_packs_no_update")
    connection.execute(
        f"UPDATE evidence_packs SET {assignment} WHERE run_id = ? AND pack_id = ?",
        (m2_fixture.RUN_ID, pack.pack_id),
    )
    try:
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as failure:
            _plan(connection, authority, pack.pack_id)
    finally:
        _close(connection)
    assert failure.value.reason_code == expected
    assert "secret-binary-pack" not in str(failure.value)


def test_plan_rejects_non_text_independent_pack_body_metadata(tmp_path: Path) -> None:
    _database, real_connection, authority, pack, _binding = _selected_authority(tmp_path)
    _close(real_connection)
    connection = _metadata_connection(
        authority,
        pack,
        pack_json=sqlite3.Binary(b"secret-binary-pack"),
    )
    try:
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as failure:
            _plan(connection, authority, pack.pack_id)
    finally:
        _close(connection)
    assert failure.value.reason_code == M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID
    assert "secret-binary-pack" not in str(failure.value)


def test_plan_preflights_stored_oversize_without_materializing_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _database, connection, authority, pack, _binding = _selected_authority(tmp_path)
    canonical_pack = canonical_json(pack.model_dump(mode="json"))
    monkeypatch.setattr(
        pack_document,
        "MAX_M6_SQLITE_EVIDENCE_PACK_DOCUMENT_BYTES",
        len(canonical_pack.encode("utf-8")) + 8,
    )
    connection.execute("DROP TRIGGER evidence_packs_no_update")
    connection.execute(
        "UPDATE evidence_packs SET pack_json = ? WHERE run_id = ? AND pack_id = ?",
        (canonical_pack + (" " * 32), m2_fixture.RUN_ID, pack.pack_id),
    )

    def forbidden_decoder(*_args: object, **_kwargs: object) -> EvidencePack:
        raise AssertionError("oversize preflight must precede body decode")

    monkeypatch.setattr(pack_document, "_decode_evidence_pack", forbidden_decoder)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as failure:
            _plan(connection, authority, pack.pack_id)
    finally:
        connection.set_trace_callback(None)
        _close(connection)
    assert failure.value.reason_code == (M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_TOO_LARGE)
    assert all("SELECT pack_json" not in statement for statement in statements)


def test_late_resolution_rejects_body_drift_against_selected_case_bytes(
    tmp_path: Path,
) -> None:
    _database, connection, authority, pack, _binding = _selected_authority(tmp_path)
    plan = _plan(connection, authority, pack.pack_id)
    connection.execute("DROP TRIGGER evidence_packs_no_update")
    connection.execute(
        "UPDATE evidence_packs SET pack_json = ? WHERE run_id = ? AND pack_id = ?",
        ("secret-corrupt-pack-body", m2_fixture.RUN_ID, pack.pack_id),
    )
    try:
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as failure:
            resolve_m6_sqlite_evidence_pack_physical_plan(
                connection=connection,
                physical_plan=plan,
            )
    finally:
        _close(connection)
    assert failure.value.reason_code == M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID
    assert "secret-corrupt-pack-body" not in str(failure.value)


def test_late_resolution_rejects_a_mutated_or_untyped_physical_plan_before_sql(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _database, connection, authority, pack, _binding = _selected_authority(tmp_path)
    plan = _plan(connection, authority, pack.pack_id)
    object.__setattr__(plan, "document_rowid", 0)

    def forbidden_rows(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("invalid plan must fail before SQLite lookup")

    monkeypatch.setattr(pack_document, "_rows", forbidden_rows)
    try:
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as mutated:
            resolve_m6_sqlite_evidence_pack_physical_plan(
                connection=connection,
                physical_plan=plan,
            )
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as untyped:
            resolve_m6_sqlite_evidence_pack_physical_plan(
                connection=connection,
                physical_plan=object(),  # type: ignore[arg-type]
            )
    finally:
        _close(connection)
    assert mutated.value.reason_code == (
        M6SQLiteEvidencePackDocumentFailureCode.PHYSICAL_PLAN_INVALID
    )
    assert untyped.value.reason_code == M6SQLiteEvidencePackDocumentFailureCode.INVALID_ARGUMENT


def test_plan_and_resolve_require_caller_owned_transaction_and_fixed_signatures(
    tmp_path: Path,
) -> None:
    assert tuple(inspect.signature(plan_m6_sqlite_evidence_pack_physical_identity).parameters) == (
        "connection",
        "expected_run_id",
        "expected_manifest_id",
        "selected_case_authority",
        "pack_id",
    )
    assert tuple(inspect.signature(resolve_m6_sqlite_evidence_pack_physical_plan).parameters) == (
        "connection",
        "physical_plan",
    )
    _database, connection, authority, pack, _binding = _selected_authority(tmp_path)
    plan = _plan(connection, authority, pack.pack_id)
    connection.rollback()
    try:
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as planning:
            _plan(connection, authority, pack.pack_id)
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as resolving:
            resolve_m6_sqlite_evidence_pack_physical_plan(
                connection=connection,
                physical_plan=plan,
            )
    finally:
        connection.close()
    assert planning.value.reason_code == (
        M6SQLiteEvidencePackDocumentFailureCode.TRANSACTION_REQUIRED
    )
    assert resolving.value.reason_code == (
        M6SQLiteEvidencePackDocumentFailureCode.TRANSACTION_REQUIRED
    )


def test_pre_343_blob_fallback_and_late_read_share_one_live_reader_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, _case, pack, binding = _real_m2_published_case(tmp_path)
    manifest = m2_fixture._manifest()
    monkeypatch.setattr(pack_document, "_USE_SQLITE_OCTET_LENGTH", False)
    with m6_live_committed_read_cut(database, m2_fixture.BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            selected = selector.execute(
                "SELECT COUNT(*) AS count FROM evidence_packs WHERE run_id = ? AND pack_id = ?",
                (m2_fixture.RUN_ID, pack.pack_id),
            ).fetchone()
            assert selected is not None and selected["count"] == 1
        with cut.reader() as reader:
            authority = read_m6_sqlite_case_authority(
                connection=reader,
                expected_run_id=m2_fixture.RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                expected_manifest_rule_version=manifest.rule_version,
                candidate_case_binding=binding,
            )
            plan = plan_m6_sqlite_evidence_pack_physical_identity(
                connection=reader,
                expected_run_id=m2_fixture.RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                selected_case_authority=authority,
                pack_id=pack.pack_id,
            )
            resolved = resolve_m6_sqlite_evidence_pack_physical_plan(
                connection=reader,
                physical_plan=plan,
            )
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS value").fetchone()["value"] == 1
    assert resolved.document == pack
    assert resolved.artifact_ref == plan.planned_artifact_ref


def test_storage_text_factory_runtime_payload_is_suppressed(tmp_path: Path) -> None:
    _database, real_connection, authority, pack, _binding = _selected_authority(tmp_path)
    _close(real_connection)
    canonical_pack = canonical_json(pack.model_dump(mode="json"))
    connection = _metadata_connection(authority, pack, pack_json=canonical_pack)
    secret = "../private/person/evidence-pack-text.json"

    def rejecting_text_factory(_value: bytes) -> str:
        raise RuntimeError(secret)

    connection.text_factory = rejecting_text_factory
    try:
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as raised:
            _plan(connection, authority, pack.pack_id)
    finally:
        _close(connection)
    rendered = "".join(
        traceback.format_exception(
            type(raised.value),
            raised.value,
            raised.value.__traceback__,
        )
    )
    assert raised.value.reason_code == (M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ is True
    assert secret not in rendered
    assert "RuntimeError" not in rendered


@pytest.mark.parametrize("boundary", ("transaction", "cursor", "blobopen"))
def test_storage_boundary_runtime_payload_is_suppressed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: Literal["transaction", "cursor", "blobopen"],
) -> None:
    _database, real_connection, authority, pack, _binding = _selected_authority(tmp_path)
    _close(real_connection)
    canonical_pack = canonical_json(pack.model_dump(mode="json"))
    connection = _metadata_connection(
        authority,
        pack,
        pack_json=canonical_pack,
        connection_factory=_RuntimeBoundaryConnection,
    )
    assert isinstance(connection, _RuntimeBoundaryConnection)
    if boundary == "blobopen":
        monkeypatch.setattr(pack_document, "_USE_SQLITE_OCTET_LENGTH", False)
    secret = "../private/person/evidence-pack-boundary.json"
    connection.secret = secret
    connection.rejected_boundary = boundary
    try:
        with pytest.raises(M6SQLiteEvidencePackDocumentError) as raised:
            _plan(connection, authority, pack.pack_id)
    finally:
        connection.rejected_boundary = None
        _close(connection)
    rendered = "".join(
        traceback.format_exception(
            type(raised.value),
            raised.value,
            raised.value.__traceback__,
        )
    )
    assert raised.value.reason_code == (M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ is True
    assert secret not in rendered
    assert "RuntimeError" not in rendered


def test_failures_are_typed_payload_free() -> None:
    error = M6SQLiteEvidencePackDocumentError(
        M6SQLiteEvidencePackDocumentFailureCode.SELECTED_CASE_MEMBERSHIP_MISMATCH
    )
    assert error.args == (
        "M6 SQLite EvidencePack document failed: SELECTED_CASE_MEMBERSHIP_MISMATCH",
    )
    assert vars(error) == {"reason_code": error.reason_code}
    with pytest.raises(TypeError, match="reason_code"):
        M6SQLiteEvidencePackDocumentError("DOCUMENT_INVALID")  # type: ignore[arg-type]
