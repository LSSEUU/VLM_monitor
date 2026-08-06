from __future__ import annotations

import hashlib
import re
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveCursor,
    M6LiveReader,
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_documents import (
    plan_m6_sqlite_acquisition_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_acquisition_plan import (
    M6SQLiteAcquisitionSupportRoute,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    read_m6_sqlite_case_authority,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_documents import (
    M6SQLiteM4RoleModelManifestBinding,
    plan_m6_sqlite_m4_model_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4SupportRoute,
)
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import VlmRole
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeObservedModelCall,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.evidence_repository import CaseSnapshot
from tests.integration.test_m3_sqlite_repository import BUSY_TIMEOUT_MS, RUN_ID
from tests.integration.test_m4_acquisition_execution_fencing import (
    _committed_successor,
)


def _case_binding(
    repository: SQLiteEvidenceRepository,
    snapshot: CaseSnapshot,
) -> M6UpgradeCandidateCaseBinding:
    document = canonical_json(snapshot.case.model_dump(mode="json"))
    digest = hashlib.sha256(document.encode("utf-8")).hexdigest()
    matching = tuple(
        entry for entry in repository.list_audit_entries(RUN_ID) if entry.after_sha256 == digest
    )
    assert len(matching) == 1
    audit = matching[0]
    return M6UpgradeCandidateCaseBinding(
        case_id=snapshot.case.case_id,
        case_revision=snapshot.revision,
        case_document_sha256=digest,
        case_audit_sequence=audit.sequence,
        case_audit_entry_hash=audit.entry_hash,
    )


def _historical_binding(
    database: Path,
    *,
    case_id: str,
    revision: int,
) -> M6UpgradeCandidateCaseBinding:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT version.case_id, version.revision, version.document_sha256,
                   version.audit_sequence, audit.entry_hash
            FROM case_versions AS version
            JOIN audit_entries AS audit
              ON audit.run_id = version.run_id
             AND audit.sequence = version.audit_sequence
            WHERE version.run_id = ? AND version.case_id = ?
              AND version.revision = ?
            """,
            (RUN_ID, case_id, revision),
        ).fetchone()
    assert row is not None
    return M6UpgradeCandidateCaseBinding(
        case_id=str(row["case_id"]),
        case_revision=int(row["revision"]),
        case_document_sha256=str(row["document_sha256"]),
        case_audit_sequence=int(row["audit_sequence"]),
        case_audit_entry_hash=str(row["entry_hash"]),
    )


def _m4_inputs(
    repository: SQLiteEvidenceRepository,
    *,
    hearing_id: str,
) -> tuple[
    tuple[M6SQLiteM4RoleModelManifestBinding, ...],
    tuple[M6UpgradeObservedModelCall, ...],
]:
    manifest = repository.load_run_manifest(RUN_ID)
    role_map = {
        VlmRole.PROSECUTOR: M6LockedModelRole.PROSECUTOR,
        VlmRole.DEFENDER: M6LockedModelRole.DEFENDER,
        VlmRole.JUDGE: M6LockedModelRole.JUDGE,
    }
    requests = repository.list_hearing_model_requests(RUN_ID, hearing_id)
    assert len(requests) == 3
    observations = tuple(
        sorted(
            (
                M6UpgradeObservedModelCall(
                    request_id=request.request_id,
                    layer=M6LockedModelCallLayer.HEARING,
                    role=role_map[request.role],
                    attempt_index=request.attempt_index,
                    result_kind=M6LockedModelCallResultKind.RESPONSE,
                    provider_invoked=True,
                )
                for request in requests
            ),
            key=lambda value: value.sort_key,
        )
    )
    bindings = tuple(
        M6SQLiteM4RoleModelManifestBinding(
            role=role,
            model_manifest_id=manifest.models[role.value.lower()].model_manifest_id,
        )
        for role in (
            M6LockedModelRole.PROSECUTOR,
            M6LockedModelRole.DEFENDER,
            M6LockedModelRole.JUDGE,
        )
    )
    return bindings, observations


def _acquisition_observations(
    manifest_id: str,
    tool_result_id: str,
) -> tuple[M6UpgradeObservedArtifactIdentity, ...]:
    return tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                    kind=M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
                    artifact_id=manifest_id,
                    usage=M6UpgradeArtifactUsage.PRODUCED,
                ),
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                    kind=M6UpgradePhysicalArtifactKind.TOOL_RESULT,
                    artifact_id=tool_result_id,
                    usage=M6UpgradeArtifactUsage.PRODUCED,
                ),
            ),
            key=lambda value: value.sort_key,
        )
    )


_BODY_COLUMNS = (
    "request_json",
    "claim_json",
    "manifest_json",
    "publication_json",
    "receipt_json",
    "derivation_json",
    "pack_json",
    "checkpoint_json",
    "round_json",
    "case_json",
    "entry_json",
)


def _assert_metadata_only(statements: list[str]) -> None:
    assert statements
    for statement in statements:
        assert "json_extract" not in statement.lower()
        for column in _BODY_COLUMNS:
            stripped = re.sub(
                rf"(?:typeof|octet_length)\(\s*(?:\w+\.)?{column}\s*\)",
                "",
                statement,
                flags=re.IGNORECASE,
            )
            assert (
                re.search(
                    rf"\b(?:\w+\.)?{column}\b",
                    stripped,
                    flags=re.IGNORECASE,
                )
                is None
            )


def test_real_no_round_acquisition_builds_current_and_historical_metadata_plans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, repository, request, publication, committed = _committed_successor(
        tmp_path,
        monkeypatch,
    )
    manifest = repository.load_run_manifest(RUN_ID)
    current_snapshot = committed.case
    current_binding = _case_binding(repository, current_snapshot)
    historical_binding = _historical_binding(
        database,
        case_id=request.case_id,
        revision=current_snapshot.revision - 1,
    )
    role_bindings, model_observations = _m4_inputs(
        repository,
        hearing_id=request.hearing_session_id,
    )
    acquisition_observations = _acquisition_observations(
        publication.execution_manifest.execution_manifest_id,
        publication.tool_result.tool_result_id,
    )

    statements: list[str] = []
    recording = [False]
    original_execute = M6LiveReader.execute

    def execute_spy(
        self: M6LiveReader,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        if recording[0]:
            statements.append(statement)
        return original_execute(self, statement, parameters)

    monkeypatch.setattr(M6LiveReader, "execute", execute_spy)

    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            selected = selector.execute("SELECT 1 AS ready").fetchone()
            assert selected is not None and selected["ready"] == 1
        with cut.reader() as reader:
            current_authority = read_m6_sqlite_case_authority(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                expected_manifest_rule_version=manifest.rule_version,
                candidate_case_binding=current_binding,
            )
            current_m4_plan = plan_m6_sqlite_m4_model_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                expected_role_model_manifests=role_bindings,
                selected_case_authority=current_authority,
                observed_model_calls=model_observations,
            )
            recording[0] = True
            current_plan = plan_m6_sqlite_acquisition_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                upstream_m4_model_plan=current_m4_plan,
                selected_case_authority=current_authority,
                observed_acquisition_artifacts=acquisition_observations,
            )
            recording[0] = False

            historical_authority = read_m6_sqlite_case_authority(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                expected_manifest_rule_version=manifest.rule_version,
                candidate_case_binding=historical_binding,
            )
            historical_m4_plan = plan_m6_sqlite_m4_model_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                expected_role_model_manifests=role_bindings,
                selected_case_authority=historical_authority,
                observed_model_calls=model_observations,
            )
            recording[0] = True
            historical_plan = plan_m6_sqlite_acquisition_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                upstream_m4_model_plan=historical_m4_plan,
                selected_case_authority=historical_authority,
                observed_acquisition_artifacts=(),
            )
            historical_retry = plan_m6_sqlite_acquisition_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                upstream_m4_model_plan=historical_m4_plan,
                selected_case_authority=historical_authority,
                observed_acquisition_artifacts=(),
            )
            recording[0] = False
        with cut.writer() as writer:
            written = writer.execute("SELECT 1 AS ready").fetchone()
            assert written is not None and written["ready"] == 1

    assert len(current_plan.closures) == 1
    assert len(current_plan.planned_artifact_refs) == 2
    assert current_plan.upstream_m4_model_plan_identity_sha256 == (
        current_m4_plan.plan_identity_sha256
    )
    closure = current_plan.closures[0]
    assert closure.round_id is None
    assert all(
        slot.route != M6SQLiteAcquisitionSupportRoute.HEARING_ROUND
        for slot in closure.support_slots
    )
    assert {ref.kind for ref in current_plan.planned_artifact_refs} == {
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
    }
    assert all(
        ref.source == M6UpgradePhysicalArtifactSource.M4_ACQUISITION
        for ref in current_plan.planned_artifact_refs
    )

    judge_graphs = tuple(
        graph
        for graph in current_m4_plan.call_graphs
        if graph.role_output is not None
        and graph.role_output.artifact_id == request.source_judge_output_id
    )
    assert len(judge_graphs) == 1
    judge_graph = judge_graphs[0]
    assert judge_graph.role_output is not None
    assert closure.upstream_m4.judge_output_id == judge_graph.role_output.artifact_id
    assert closure.upstream_m4.judge_output_rowid == judge_graph.role_output.rowid
    assert closure.upstream_m4.judge_output_document_sha256 == (
        judge_graph.role_output.document_sha256
    )
    hearing_slot = next(
        slot
        for slot in current_m4_plan.support_slots
        if slot.route == M6SQLiteM4SupportRoute.HEARING_SESSION
        and slot.identity == closure.upstream_m4.hearing_id
    )
    cycle_slot = next(
        slot
        for slot in current_m4_plan.support_slots
        if slot.route == M6SQLiteM4SupportRoute.HEARING_CYCLE
        and slot.identity == closure.upstream_m4.cycle_scope_id
    )
    assert closure.upstream_m4.hearing_rowid == hearing_slot.rowid
    assert closure.upstream_m4.hearing_support_index_identity_sha256 == (
        hearing_slot.index_identity_sha256
    )
    assert closure.upstream_m4.cycle_rowid == cycle_slot.rowid
    assert closure.upstream_m4.cycle_support_index_identity_sha256 == (
        cycle_slot.index_identity_sha256
    )

    assert historical_plan.closures == ()
    assert historical_plan.planned_artifact_refs == ()
    assert historical_plan.plan_identity_sha256 == historical_retry.plan_identity_sha256
    assert historical_plan.upstream_m4_model_plan_identity_sha256 == (
        historical_m4_plan.plan_identity_sha256
    )
    _assert_metadata_only(statements)
