from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    read_m6_sqlite_case_authority_v3,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_gate_documents import (
    assemble_m6_sqlite_m4_gate_history_snapshot,
    plan_m6_sqlite_m4_gate_documents,
    resolve_m6_sqlite_m4_gate_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_documents import (
    resolve_m6_sqlite_m4_model_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_metadata import (
    assemble_m6_sqlite_historical_retrieval_snapshots,
    resolve_m6_sqlite_m5_precedent_documents,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
    load_m6_upgrade_v3_state_from_connection,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder import (
    SQLiteM6UpgradeWholeSampleRecordBuilderV3,
)
from labcourt.application.m6_historical_retrieval_cut import (
    assemble_m6_historical_retrieval_cut,
)
from labcourt.application.m6_model_reference_authority import (
    resolve_m6_hearing_model_reference_bindings,
)
from labcourt.contracts.hearing import HearingCheckpoint, HearingCheckpointPhase
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_replay_locked import M6LockedModelCallLayer
from labcourt.ports.m6_acquisition_authority import M6ValidatedM4ReplayAuthoritySnapshot
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3_m4 import (
    BUSY_TIMEOUT_MS,
    _prepare_v3_m4_builder,
)


def test_gate_plan_rebuilds_exact_successful_hearing_documents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _prepare_v3_m4_builder(tmp_path, monkeypatch, events=[])
    repository = SQLiteM6UpgradeExecutionLedgerV3Repository(
        fixture.database,
        BUSY_TIMEOUT_MS,
    )

    with m6_live_committed_read_cut(fixture.database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector():
            pass
        with cut.reader() as reader:
            state = load_m6_upgrade_v3_state_from_connection(
                repository,
                reader,
                fixture.scope_run_id,
                fixture.scope_id,
            )
            observed = fixture.observation
            assert observed.candidate_case is not None
            assert observed.selected_case_audit_anchor is not None
            scope = state.stored_scope.authority
            selected_case = read_m6_sqlite_case_authority_v3(
                connection=reader,
                expected_run_id=scope.candidate_run_id,
                expected_manifest_id=scope.candidate_manifest.manifest_id,
                expected_manifest_rule_version=scope.candidate_manifest.rule_version,
                candidate_case_binding=observed.candidate_case,
                selected_case_audit_anchor=observed.selected_case_audit_anchor,
            )
            hearing_calls = tuple(
                item
                for item in observed.model_calls
                if item.layer == M6LockedModelCallLayer.HEARING
            )
            m4_plan = SQLiteM6UpgradeWholeSampleRecordBuilderV3._plan_v3_m4_documents(
                reader,
                state,
                hearing_calls,
                selected_case,
            )
            gate_plan = plan_m6_sqlite_m4_gate_documents(
                connection=reader,
                upstream_m4_model_plan=m4_plan,
            )
            m5_plan = SQLiteM6UpgradeWholeSampleRecordBuilderV3._plan_v3_m5_precedent_documents(
                reader,
                state,
                (),
                selected_case,
                m4_plan,
            )
            m4_snapshot = resolve_m6_sqlite_m4_model_documents(
                connection=reader,
                metadata_plan=m4_plan,
            )
            gate = resolve_m6_sqlite_m4_gate_documents(
                connection=reader,
                metadata_plan=gate_plan,
                upstream_m4_model_snapshot=m4_snapshot,
            )
            history = assemble_m6_sqlite_m4_gate_history_snapshot(
                gate_snapshot=gate,
                upstream_m4_model_snapshot=m4_snapshot,
                source_m4_authority_root_sha256="a" * 64,
            )
            m5_snapshot = resolve_m6_sqlite_m5_precedent_documents(
                connection=reader,
                metadata_plan=m5_plan,
                selected_case=selected_case.case,
                config=scope.candidate_config,
                manifest=scope.candidate_manifest,
                upstream_m4_model_plan=m4_plan,
            )
            historical = assemble_m6_sqlite_historical_retrieval_snapshots(
                gate_history_snapshot=history,
                m5_precedent_snapshot=m5_snapshot,
                expected_upstream_m4_plan_identity_sha256=m4_plan.plan_identity_sha256,
            )
        with cut.writer():
            pass

    assert gate.source_identity_sha256 == gate_plan.plan_identity_sha256
    assert gate.upstream_m4_model_plan_identity_sha256 == m4_plan.plan_identity_sha256
    assert gate.verdicts == selected_case.case.verdicts
    assert gate.procedural_reviews == selected_case.case.procedural_reviews
    assert len(gate.hearing_sessions) == 1
    assert len(gate.hearing_cycles) == 1
    assert len(gate.retrieval_receipts) == 1
    assert len(gate.hearing_rounds) == 1
    assert len(gate.completed_checkpoints) == 1
    assert gate.completed_checkpoints[0].phase == HearingCheckpointPhase.ROUND_COMPLETE
    assert len(gate.hearing_records) == 1
    assert len(gate.verdict_bindings) == 1
    assert gate.hearing_records[0].rounds == gate.hearing_rounds
    assert gate.verdict_bindings[0].hearing_record_id == gate.hearing_records[0].record_id
    checkpoint_documents = tuple(
        HearingCheckpoint.model_validate_json(item.canonical_document)
        for item in gate.documents
        if item.kind == M4ProjectionArtifactKind.HEARING_CHECKPOINT
    )
    assert len(checkpoint_documents) == 2
    terminal = tuple(
        item for item in checkpoint_documents if item.phase == HearingCheckpointPhase.COMPLETE
    )
    assert len(terminal) == 1
    assert terminal[0].procedural_review_ref is not None
    assert terminal[0].procedural_review_ref.artifact_id == gate.procedural_reviews[0].review_id
    reference_bindings = resolve_m6_hearing_model_reference_bindings(
        source_case=selected_case.case,
        snapshot=M6ValidatedM4ReplayAuthoritySnapshot(
            source_identity_sha256=history.source_identity_sha256,
            run_id=history.run_id,
            documents=history.documents,
        ),
    )
    assert len(reference_bindings) == 1
    assert reference_bindings[0].verdict_id == gate.verdicts[0].verdict_id
    assert len(reference_bindings[0].role_bindings) == 3
    assert any(item.kind == M4ProjectionArtifactKind.EVIDENCE_PACK for item in history.documents)
    retrieval_cut = assemble_m6_historical_retrieval_cut(
        source_case=selected_case.case,
        snapshots=historical,
    )
    assert retrieval_cut.retrieval_cycle_count == 1
    assert retrieval_cut.degraded_retrieval_count == 1
    assert retrieval_cut.successful_exposure_count == 0
