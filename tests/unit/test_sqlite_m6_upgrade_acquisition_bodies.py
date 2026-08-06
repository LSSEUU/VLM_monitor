"""Same-snapshot body tests for the frozen M6 acquisition plan."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_bodies as bodies
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveCursor,
    M6LiveReader,
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_documents import (
    M6SQLiteAcquisitionDocumentError,
    plan_m6_sqlite_acquisition_documents,
    resolve_m6_sqlite_acquisition_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_plan import (
    M6SQLiteAcquisitionDocumentsPlan,
    M6SQLiteAcquisitionPlanFailureCode,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    read_m6_sqlite_case_authority,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_documents import (
    plan_m6_sqlite_m4_model_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4ModelDocumentsPlan,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.hearing_acquisition import AcquisitionRequest, ToolExecutionManifest
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument
from tests.integration.test_m3_sqlite_repository import BUSY_TIMEOUT_MS, RUN_ID
from tests.integration.test_m4_acquisition_execution_fencing import _committed_successor
from tests.integration.test_sqlite_m6_upgrade_acquisition_documents import (
    _acquisition_observations,
    _case_binding,
    _m4_inputs,
)
from tests.unit.test_sqlite_m6_upgrade_acquisition_plan import (
    _case_with_two_acquisitions,
    _plan,
)


@dataclass(frozen=True, slots=True)
class _Prepared:
    reader: M6LiveReader
    plan: M6SQLiteAcquisitionDocumentsPlan
    upstream: M6SQLiteM4ModelDocumentsPlan


@pytest.fixture
def prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_Prepared]:
    database, repository, request, publication, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )
    manifest = repository.load_run_manifest(RUN_ID)
    binding = _case_binding(repository, committed.case)
    role_bindings, model_observations = _m4_inputs(
        repository,
        hearing_id=request.hearing_session_id,
    )
    acquisition_observations = _acquisition_observations(
        publication.execution_manifest.execution_manifest_id,
        publication.tool_result.tool_result_id,
    )

    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            assert selector.execute("SELECT 1 AS ready").fetchone()["ready"] == 1
        with cut.reader() as reader:
            authority = read_m6_sqlite_case_authority(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                expected_manifest_rule_version=manifest.rule_version,
                candidate_case_binding=binding,
            )
            upstream = plan_m6_sqlite_m4_model_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                expected_role_model_manifests=role_bindings,
                selected_case_authority=authority,
                observed_model_calls=model_observations,
            )
            plan = plan_m6_sqlite_acquisition_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                upstream_m4_model_plan=upstream,
                selected_case_authority=authority,
                observed_acquisition_artifacts=acquisition_observations,
            )
            yield _Prepared(reader=reader, plan=plan, upstream=upstream)
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS ready").fetchone()["ready"] == 1


class _RowsCursor:
    def __init__(self, rows: tuple[object, ...]) -> None:
        self._rows = rows

    def fetchmany(self, _size: int) -> tuple[object, ...]:
        return self._rows

    def close(self) -> None:
        return None


def _resolve(value: _Prepared) -> bodies.M6SQLiteAcquisitionAuthoritySnapshot:
    return resolve_m6_sqlite_acquisition_documents(
        connection=value.reader,
        metadata_plan=value.plan,
        upstream_m4_model_plan=value.upstream,
    )


def test_resolves_exact_acquisition_closure_and_manifest_pins(prepared: _Prepared) -> None:
    snapshot = _resolve(prepared)

    assert snapshot.source_identity_sha256 == prepared.plan.plan_identity_sha256
    assert snapshot.upstream_m4_model_plan_identity_sha256 == (
        prepared.upstream.plan_identity_sha256
    )
    assert len(snapshot.locked_tool_results) == 1
    assert len(snapshot.resolved_acquisitions) == 1
    assert snapshot.planned_artifact_refs == prepared.plan.planned_artifact_refs
    resolved = snapshot.resolved_acquisitions[0]
    manifest_slot = prepared.plan.closures[0].manifest
    assert resolved.execution_manifest.component_manifest_id == manifest_slot.component_manifest_id
    assert resolved.execution_manifest.model_manifest_id == manifest_slot.model_manifest_id


def test_two_transitions_read_each_planned_pack_body_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(_case_with_two_acquisitions())
    assert len(plan.closures) == 2
    packs = {pack.pack_id: pack for pack in plan.selected_case.evidence_packs}
    reads: list[str] = []

    def pack_body_spy(
        _connection: object,
        *,
        rowid: int,
        pack_id: str,
        document_bytes: int,
        document_sha256: str,
    ) -> tuple[object, str]:
        del rowid, document_bytes, document_sha256
        reads.append(pack_id)
        pack = packs[pack_id]
        return pack, canonical_json(pack.model_dump(mode="json"))

    monkeypatch.setattr(bodies, "_pack_body", pack_body_spy)
    cache: bodies._PackBodyCache = {}
    for closure in plan.closures:
        bodies._cached_pack_body(  # type: ignore[arg-type]
            object(),
            closure.pack_transition.previous_pack,
            cache,
        )
        bodies._cached_pack_body(  # type: ignore[arg-type]
            object(),
            closure.pack_transition.resulting_pack,
            cache,
        )

    assert len(reads) == 3
    assert len(set(reads)) == 3
    assert reads.count(plan.closures[0].pack_transition.resulting_pack.pack_id) == 1


@pytest.mark.parametrize("failure", ("tampered", "missing"))
def test_tampered_or_missing_planned_body_fails_closed(
    prepared: _Prepared,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    original_execute = M6LiveReader.execute

    def execute_spy(
        self: M6LiveReader,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        if (
            "manifest_json FROM m4_tool_execution_manifests" in statement
            and "octet_length" not in statement
        ):
            cursor = original_execute(self, statement, parameters)
            try:
                rows = tuple(cursor.fetchmany(2))
            finally:
                cursor.close()
            if failure == "missing":
                return _RowsCursor(())  # type: ignore[return-value]
            assert len(rows) == 1
            row = dict(rows[0])
            row["manifest_json"] = f"{row['manifest_json']} "
            return _RowsCursor((row,))  # type: ignore[return-value]
        return original_execute(self, statement, parameters)

    monkeypatch.setattr(M6LiveReader, "execute", execute_spy)
    with pytest.raises(M6SQLiteAcquisitionDocumentError) as raised:
        _resolve(prepared)

    expected = (
        M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH
        if failure == "missing"
        else M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID
    )
    assert raised.value.reason_code == expected


def test_fresh_metadata_drift_rejects_before_any_body_read(
    prepared: _Prepared,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body_reads: list[str] = []
    original_execute = M6LiveReader.execute

    def execute_spy(
        self: M6LiveReader,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        if (
            any(
                token in statement
                for token in (
                    "request_json FROM",
                    "claim_json FROM",
                    "manifest_json FROM",
                    "publication_json FROM",
                    "receipt_json FROM",
                    "derivation_json FROM",
                    "pack_json FROM",
                    "checkpoint_json FROM",
                    "round_json FROM",
                    "case_json FROM",
                    "entry_json FROM",
                )
            )
            and "octet_length" not in statement
        ):
            body_reads.append(statement)
        return original_execute(self, statement, parameters)

    monkeypatch.setattr(M6LiveReader, "execute", execute_spy)
    monkeypatch.setattr(
        bodies,
        "build_m6_sqlite_acquisition_documents_plan",
        lambda **_kwargs: object(),
    )
    with pytest.raises(M6SQLiteAcquisitionDocumentError) as raised:
        _resolve(prepared)

    assert raised.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH
    assert body_reads == []


def test_extra_scoped_authority_body_has_zero_tolerance(
    prepared: _Prepared,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_resolve = bodies._resolve_closure_bodies

    def add_extra(*args: object, **kwargs: object) -> bodies._ResolvedClosureBodies:
        resolved = original_resolve(*args, **kwargs)  # type: ignore[arg-type]
        request_document = next(
            document
            for document in resolved.documents
            if document.kind == M4ProjectionArtifactKind.ACQUISITION_REQUEST
        )
        request = AcquisitionRequest.model_validate_json(request_document.canonical_document)
        payload = request.model_dump(mode="json", exclude_computed_fields=True)
        payload["request_payload"]["reason_summary"] = "Additional unplanned authority."
        extra = AcquisitionRequest.model_validate(payload)
        extra_document = M6HistoricalAuthorityDocument(
            kind=M4ProjectionArtifactKind.ACQUISITION_REQUEST,
            artifact_id=extra.request_id,
            canonical_document=canonical_json(extra.model_dump(mode="json")),
        )
        return bodies._ResolvedClosureBodies(
            documents=tuple(
                sorted((*resolved.documents, extra_document), key=lambda value: value.sort_key)
            ),
            locked=resolved.locked,
            manifest=resolved.manifest,
        )

    monkeypatch.setattr(bodies, "_resolve_closure_bodies", add_extra)
    with pytest.raises(M6SQLiteAcquisitionDocumentError) as raised:
        _resolve(prepared)

    assert raised.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH


def test_manifest_body_pin_must_equal_frozen_slot(
    prepared: _Prepared,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_manifest = bodies._manifest_body

    def forged_manifest(*args: object, **kwargs: object) -> tuple[ToolExecutionManifest, str]:
        manifest, canonical = original_manifest(*args, **kwargs)  # type: ignore[arg-type]
        return manifest.model_copy(update={"component_manifest_id": "9" * 64}), canonical

    monkeypatch.setattr(bodies, "_manifest_body", forged_manifest)
    with pytest.raises(M6SQLiteAcquisitionDocumentError) as raised:
        _resolve(prepared)

    assert raised.value.reason_code == M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH


def test_public_failure_does_not_retain_body_payload(
    prepared: _Prepared,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "private-body-marker"
    original_execute = M6LiveReader.execute

    def execute_spy(
        self: M6LiveReader,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        if "manifest_json FROM m4_tool_execution_manifests" in statement:
            return _RowsCursor(({"document_rowid": 1, "manifest_json": marker},))  # type: ignore[return-value]
        return original_execute(self, statement, parameters)

    monkeypatch.setattr(M6LiveReader, "execute", execute_spy)
    with pytest.raises(M6SQLiteAcquisitionDocumentError) as raised:
        _resolve(prepared)

    assert raised.value.reason_code in {
        M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID,
        M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH,
    }
    assert marker not in str(raised.value)
    assert not hasattr(raised.value, "connection")
