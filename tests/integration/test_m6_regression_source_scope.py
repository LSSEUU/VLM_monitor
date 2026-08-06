from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.adapters.storage.readonly_m6_regression_source_scope import (
    M6RegressionSourceScopeBudget,
    M6RegressionSourceScopeReadError,
    M6RegressionSourceScopeReadErrorCode,
    ReadonlyM6RegressionSourceScopeRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.contracts.canonical import canonical_json
from labcourt.services.m5_artifact_validation import validate_m5_artifacts
from labcourt.services.m5_projection import rebuild_m5_projection
from tests.integration.test_m5_readonly_projection import _config
from tests.integration.test_m5_sqlite_appeals import _prepare_overturn


def _validated_report(
    tmp_path: Path,
    *,
    commit_resolution: bool,
):  # type: ignore[no-untyped-def]
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
    return database, closed, report


@pytest.mark.parametrize("commit_resolution", [False, True])
def test_scope_uses_exact_pre_appeal_case_for_pending_and_terminal_appeal(
    tmp_path: Path,
    commit_resolution: bool,
) -> None:
    database, closed, report = _validated_report(
        tmp_path,
        commit_resolution=commit_resolution,
    )
    report_document = canonical_json(report.model_dump(mode="json"))

    with readonly_sqlite_snapshot(database) as snapshot:
        observation = ReadonlyM6RegressionSourceScopeRepository(
            snapshot,
            config=_config(),
        ).observe(
            closed.case.run_id,
            m5_validation_report=report,
            m5_validation_report_document=report_document,
        )

    assert len(observation.required_sources) == 1
    required = observation.required_sources[0]
    assert required.source_case_id == closed.case.case_id
    assert required.source_case_revision == closed.revision
    assert required.source_case_document_sha256 != "0" * 64
    assert observation.m5_validation_report.authority_root_sha256 == (report.authority_root_sha256)


def test_scope_rejects_forged_report_and_audit_budget_exhaustion(tmp_path: Path) -> None:
    database, closed, report = _validated_report(tmp_path, commit_resolution=True)
    report_document = canonical_json(report.model_dump(mode="json"))

    with readonly_sqlite_snapshot(database) as snapshot:
        repository = ReadonlyM6RegressionSourceScopeRepository(
            snapshot,
            config=_config(),
        )
        forged = report.model_copy(update={"authority_root_sha256": "f" * 64})
        forged_document = canonical_json(forged.model_dump(mode="json"))
        with pytest.raises(M6RegressionSourceScopeReadError) as report_error:
            repository.observe(
                closed.case.run_id,
                m5_validation_report=forged,
                m5_validation_report_document=forged_document,
            )
        assert report_error.value.code == M6RegressionSourceScopeReadErrorCode.M5_REPORT_INVALID

        bounded = ReadonlyM6RegressionSourceScopeRepository(
            snapshot,
            config=_config(),
            budget=M6RegressionSourceScopeBudget(max_audit_entries=1),
        )
        with pytest.raises(M6RegressionSourceScopeReadError) as budget_error:
            bounded.observe(
                closed.case.run_id,
                m5_validation_report=report,
                m5_validation_report_document=report_document,
            )
        assert budget_error.value.code == M6RegressionSourceScopeReadErrorCode.BUDGET_EXCEEDED
