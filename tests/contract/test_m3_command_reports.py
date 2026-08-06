from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from labcourt.contracts.backlog import BacklogRetryDisposition, BacklogRetryReport
from labcourt.contracts.m3_command_reports import (
    M3BacklogRetryCommandReport,
    M3ProcessCommandReport,
    M3ProjectionBudget,
    M3ProjectionCounts,
    M3ProjectionDisposition,
    M3ProjectionOutcome,
    M3ProjectionReasonCode,
)
from labcourt.contracts.m3_operations import M3ProcessCounts, M3ProcessReport
from labcourt.schema_export import expected_schema_files


def _budget() -> M3ProjectionBudget:
    return M3ProjectionBudget(
        max_database_bytes=1024,
        max_audit_entries=20,
        max_cases=10,
        max_packs=20,
        max_document_bytes=4096,
        max_projection_file_bytes=64 * 1024,
        max_materialization_bytes=4 * 1024 * 1024,
    )


def _counts() -> M3ProjectionCounts:
    return M3ProjectionCounts(
        snapshot_database_bytes=512,
        audit_entries=4,
        cases=1,
        packs=1,
        max_document_bytes=2048,
    )


def _projection() -> M3ProjectionOutcome:
    return M3ProjectionOutcome(
        disposition=M3ProjectionDisposition.REBUILT,
        reason_code=None,
        budget=_budget(),
        counts=_counts(),
    )


def _process_report() -> M3ProcessReport:
    return M3ProcessReport(
        run_id="run-command",
        manifest_id="1" * 64,
        provider_profile="fake-screening",
        perception_mode="SIMULATED PERCEPTION",
        model_mode="FAKE VLM",
        fixture_bundle_id="2" * 64,
        fixture_entry_count=0,
        requested_case_id=None,
        selection_limit=1,
        available_case_count=0,
        selection_truncated=False,
        outcomes=(),
        counts=M3ProcessCounts(
            selected_cases=0,
            pipeline_invocations=0,
            processed_cases=0,
            deferred_to_backlog_cases=0,
            observed_existing_cases=0,
            skipped_not_ready_cases=0,
            cache_hits=0,
            recovered_responses=0,
            repair_attempts=0,
        ),
    )


def test_projection_counts_reject_forged_derived_bounds() -> None:
    counts = _counts()
    assert counts.projected_document_count == 7
    assert counts.largest_jsonl_upper_bound_bytes == 4 * 2049
    assert counts.materialization_upper_bound_bytes > counts.largest_jsonl_upper_bound_bytes

    payload = counts.model_dump(mode="python")
    for name in (
        "projected_document_count",
        "largest_jsonl_upper_bound_bytes",
        "materialization_upper_bound_bytes",
    ):
        forged = dict(payload)
        forged[name] = 1
        with pytest.raises(ValidationError, match=name):
            M3ProjectionCounts.model_validate(forged)


def test_projection_outcome_cannot_claim_false_success_or_untyped_pending() -> None:
    with pytest.raises(ValidationError, match="requires counts"):
        M3ProjectionOutcome(
            disposition=M3ProjectionDisposition.REBUILT,
            reason_code=None,
            budget=_budget(),
            counts=None,
        )
    with pytest.raises(ValidationError, match="controlled reason"):
        M3ProjectionOutcome(
            disposition=M3ProjectionDisposition.PENDING_REBUILD,
            reason_code=None,
            budget=_budget(),
            counts=_counts(),
        )

    pending = M3ProjectionOutcome(
        disposition=M3ProjectionDisposition.PENDING_REBUILD,
        reason_code=M3ProjectionReasonCode.PROJECTION_REBUILD_FAILED,
        budget=_budget(),
        counts=_counts(),
    )
    assert pending.disposition == M3ProjectionDisposition.PENDING_REBUILD


def test_process_command_envelope_preserves_original_report_and_modes() -> None:
    authority = _process_report()
    report = M3ProcessCommandReport(
        run_id=authority.run_id,
        authority_report=authority,
        projection=_projection(),
    )
    assert M3ProcessCommandReport.model_validate_json(report.model_dump_json()) == report
    assert report.authority_report is authority
    assert report.authority_complete is True
    assert report.perception_mode == "SIMULATED PERCEPTION"
    assert report.model_mode == "FAKE VLM"

    payload = report.model_dump(mode="python")
    payload["run_id"] = "another-run"
    with pytest.raises(ValidationError, match="inconsistent authority bindings"):
        M3ProcessCommandReport.model_validate(payload)


def test_backlog_command_envelope_binds_no_work_report() -> None:
    authority = BacklogRetryReport(
        run_id="run-command",
        reclaimed_expired_count=3,
        reclaimed_exhausted_count=1,
        disposition=BacklogRetryDisposition.NO_WORK,
    )
    report = M3BacklogRetryCommandReport(
        run_id=authority.run_id,
        authority_report=authority,
        projection=_projection(),
    )
    assert M3BacklogRetryCommandReport.model_validate_json(report.model_dump_json()) == report
    assert report.authority_report.reclaimed_exhausted_count == 1
    assert report.authority_complete is True


def test_command_schemas_expose_modes_and_nested_unmodified_reports() -> None:
    schemas = expected_schema_files()
    process = json.loads(schemas["m3-process-command-report.schema.json"])
    backlog = json.loads(schemas["m3-backlog-retry-command-report.schema.json"])

    assert process["properties"]["perception_mode"]["const"] == "SIMULATED PERCEPTION"
    assert process["properties"]["model_mode"]["const"] == "FAKE VLM"
    assert process["properties"]["authority_complete"]["const"] is True
    assert process["properties"]["authority_report"]["$ref"].endswith("M3ProcessReport")
    assert backlog["properties"]["authority_report"]["$ref"].endswith("BacklogRetryReport")
