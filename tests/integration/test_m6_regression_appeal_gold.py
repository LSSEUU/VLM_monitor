from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from labcourt.adapters.storage.readonly_m6_regression_appeals import (
    M6RegressionAppealReadError,
    M6RegressionAppealReadErrorCode,
    ReadonlyM6RegressionAppealRepository,
)
from labcourt.adapters.storage.readonly_m6_regression_source_scope import (
    ReadonlyM6RegressionSourceScopeRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.application.m6_regression_gold import build_m6_appeal_gold_truth_authority
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import CaseStatus, VerdictDecision
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6RegressionStage,
    M6SemanticStageRoot,
)
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionSourceInventoryCutAuthority,
    M6RegressionSourceInventoryItem,
    M6RegressionSourceRunCut,
)
from labcourt.ports.m6_regression_appeals import M6RegressionAppealState
from labcourt.services.m5_artifact_validation import validate_m5_artifacts
from labcourt.services.m5_projection import rebuild_m5_projection
from tests.integration.test_m5_readonly_projection import _config
from tests.integration.test_m5_sqlite_appeals import _prepare_overturn


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _cut(scope):  # type: ignore[no-untyped-def]
    required = scope.required_sources[0]
    report = scope.m5_validation_report
    report_content_sha256 = _sha(scope.m5_validation_report_document)
    item = M6RegressionSourceInventoryItem(
        sample_id=_sha(f"sample:{required.source_run_id}:{required.source_case_id}"),
        source_run_id=required.source_run_id,
        source_case_id=required.source_case_id,
        source_case_revision=required.source_case_revision,
        source_case_document_sha256=required.source_case_document_sha256,
        source_manifest_id=required.source_manifest_id,
        sealed_source_validation_report_id=report.report_id,
        sealed_source_validation_report_document_sha256=report_content_sha256,
        sealed_source_m5_authority_root_sha256=report.authority_root_sha256,
        sealed_audit_head_sequence=scope.audit_head_sequence,
        sealed_audit_head_hash=scope.audit_head_hash,
        source_seal_id=_sha("source-seal-id"),
        source_seal_content_sha256=_sha("source-seal-content"),
        source_seal_size_bytes=1,
        input_authority_id=_sha("input-authority-id"),
        input_authority_document_sha256=_sha("input-authority-document"),
        input_authority_content_sha256=_sha("input-authority-content"),
        input_authority_size_bytes=1,
        replay_input_closure_authority_id=_sha("closure-id"),
        replay_input_closure_document_sha256=_sha("closure-document"),
        replay_input_closure_content_sha256=_sha("closure-content"),
        replay_input_closure_size_bytes=1,
    )
    run_cut = M6RegressionSourceRunCut(
        source_run_id=required.source_run_id,
        baseline_manifest_id=required.source_manifest_id,
        source_config_sha256=report.config_sha256,
        audit_head_sequence=scope.audit_head_sequence,
        audit_head_hash=scope.audit_head_hash,
        m5_validation_report_id=report.report_id,
        m5_validation_report_content_sha256=report_content_sha256,
        m5_authority_root_sha256=report.authority_root_sha256,
        source_item_count=1,
        source_scope_root_sha256=sha256_hex(
            [
                "m6-regression-source-run-scope",
                1,
                required.source_run_id,
                [item.source_scope_key],
            ]
        ),
    )
    return M6RegressionSourceInventoryCutAuthority(
        baseline_manifest_id=required.source_manifest_id,
        run_cuts=(run_cut,),
        items=(item,),
    )


def _baseline(observation):  # type: ignore[no-untyped-def]
    appeal = observation.current_appeal_authority
    assert appeal is not None
    item = observation.source_item
    return M6CaseReplaySnapshot(
        sample_id=item.sample_id,
        source_run_id=item.source_run_id,
        source_case_id=item.source_case_id,
        source_case_revision=item.source_case_revision,
        source_case_document_sha256=item.source_case_document_sha256,
        manifest_id=item.source_manifest_id,
        stage_roots=tuple(
            M6SemanticStageRoot(
                stage=stage,
                projection_sha256=_sha(f"appeal-baseline:{stage.value}"),
            )
            for stage in M6RegressionStage
        ),
        case_status=CaseStatus.CLOSED,
        final_decision=appeal.source_decision,
    )


def _report(tmp_path: Path, *, commit_resolution: bool):  # type: ignore[no-untyped-def]
    database, repository, closed, _, _, _, _, _, _, intent = _prepare_overturn(tmp_path)
    if commit_resolution:
        repository.commit_resolution(intent)
    output = tmp_path / "projection"
    rebuild_m5_projection(
        config=_config(),
        run_id=closed.case.run_id,
        database_path=database,
        workspace_root=output,
    )
    report = validate_m5_artifacts(
        config=_config(),
        run_id=closed.case.run_id,
        database_path=database,
        workspace_root=output,
    )
    assert report.passed
    return database, closed.case.run_id, report


def test_terminal_appeal_resolves_exact_v3_intent_commit_and_gold(tmp_path: Path) -> None:
    database, run_id, report = _report(tmp_path, commit_resolution=True)
    report_document = canonical_json(report.model_dump(mode="json"))

    with readonly_sqlite_snapshot(database) as snapshot:
        scope = ReadonlyM6RegressionSourceScopeRepository(
            snapshot,
            config=_config(),
        ).observe(
            run_id,
            m5_validation_report=report,
            m5_validation_report_document=report_document,
        )
        cut = _cut(scope)
        observations = ReadonlyM6RegressionAppealRepository(
            snapshot,
            config=_config(),
        ).observe(cut)

    assert len(observations) == 1
    observation = observations[0]
    assert observation.state == M6RegressionAppealState.TERMINAL
    assert observation.current_appeal_authority is not None
    assert observation.resolution_intent is not None
    assert observation.resolution_commit is not None
    assert observation.current_appeal_authority == (observation.resolution_intent.appeal_authority)
    result = build_m6_appeal_gold_truth_authority(
        appeal_history=observation,
        baseline_snapshot=_baseline(observation),
    )
    truth = result.authority.gold_truth
    assert truth.expected_decision == VerdictDecision.NOT_ESTABLISHED
    assert truth.expected_decision == observation.current_appeal_authority.appeal.resolved_decision
    assert truth.decision_authority_document_sha256 == _sha(
        observation.current_appeal_document or ""
    )
    assert truth.resolution_commit_document_sha256 == _sha(
        observation.resolution_commit_document or ""
    )


def test_pending_appeal_is_observed_as_blocking_not_stability(tmp_path: Path) -> None:
    database, run_id, report = _report(tmp_path, commit_resolution=False)
    report_document = canonical_json(report.model_dump(mode="json"))

    with readonly_sqlite_snapshot(database) as snapshot:
        scope = ReadonlyM6RegressionSourceScopeRepository(
            snapshot,
            config=_config(),
        ).observe(
            run_id,
            m5_validation_report=report,
            m5_validation_report_document=report_document,
        )
        observation = ReadonlyM6RegressionAppealRepository(
            snapshot,
            config=_config(),
        ).observe(_cut(scope))[0]

    assert observation.state == M6RegressionAppealState.PENDING
    assert observation.current_case_status == CaseStatus.APPEALED
    assert observation.current_appeal_authority is not None
    assert observation.current_appeal_authority.version == 2
    assert observation.resolution_intent is None
    assert observation.resolution_commit is None


@pytest.mark.parametrize("attack", ["m5_root", "audit_head"])
def test_cross_snapshot_source_cut_is_rejected(tmp_path: Path, attack: str) -> None:
    database, run_id, report = _report(tmp_path, commit_resolution=True)
    report_document = canonical_json(report.model_dump(mode="json"))

    with readonly_sqlite_snapshot(database) as snapshot:
        scope = ReadonlyM6RegressionSourceScopeRepository(
            snapshot,
            config=_config(),
        ).observe(
            run_id,
            m5_validation_report=report,
            m5_validation_report_document=report_document,
        )
        cut = _cut(scope)
        item = cut.items[0]
        run_cut = cut.run_cuts[0]
        if attack == "m5_root":
            forged = _sha("foreign-m5-root")
            item = item.model_copy(update={"sealed_source_m5_authority_root_sha256": forged})
            run_cut = run_cut.model_copy(update={"m5_authority_root_sha256": forged})
            expected = M6RegressionAppealReadErrorCode.M5_AUTHORITY_INVALID
        else:
            forged = _sha("foreign-audit-head")
            item = item.model_copy(update={"sealed_audit_head_hash": forged})
            run_cut = run_cut.model_copy(update={"audit_head_hash": forged})
            expected = M6RegressionAppealReadErrorCode.SOURCE_CUT_INVALID
        attacked = cut.model_copy(update={"run_cuts": (run_cut,), "items": (item,)})

        with pytest.raises(M6RegressionAppealReadError) as raised:
            ReadonlyM6RegressionAppealRepository(
                snapshot,
                config=_config(),
            ).observe(attacked)
    assert raised.value.code == expected
