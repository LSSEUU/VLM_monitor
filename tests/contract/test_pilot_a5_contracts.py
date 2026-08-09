from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.backlog import BacklogRetryDisposition, BacklogRetryReport
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.m3_operations import M3ProcessCounts
from labcourt.contracts.m5_operations import M5DispatchCommandReport
from labcourt.contracts.pilot import PilotA3Report
from labcourt.contracts.pilot_a5 import PilotA5RunReport
from labcourt.contracts.pilot_report import PilotA4Metrics, PilotA4PublicationReport
from labcourt.schema_export import expected_schema_files
from tests.contract.test_pilot_contracts import _a2_report
from tests.contract.test_pilot_report_contracts import _case_view, _closure


def _report() -> PilotA5RunReport:
    evidence = _a2_report().model_copy(
        update={
            "config_sha256": "7" * 64,
            "run_manifest_id": "6" * 64,
        }
    )
    screening = PilotA3Report(
        run_id="pilot-001",
        manifest_id="6" * 64,
        provider_profile="pilot-screening",
        provider="openai-compatible",
        model="vision-model",
        revision="2026-08-01",
        model_manifest_id="4" * 64,
        execution_location="EXTERNAL",
        transport="HTTP",
        requested_case_id=None,
        selection_limit=20,
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
    case = _case_view()
    publication = PilotA4PublicationReport(
        closure=_closure(),
        dispatch=M5DispatchCommandReport(
            run_id="pilot-001",
            selected_count=0,
            succeeded_count=0,
            retryable_failure_count=0,
            unknown_delivery_count=0,
            attention_required_count=0,
            receipts=(),
        ),
        metrics=PilotA4Metrics(
            run_id="pilot-001",
            manifest_id="6" * 64,
            config_sha256="7" * 64,
            case_count=1,
            closed_count=1,
            human_review_count=0,
            established_count=1,
            not_established_count=0,
            insufficient_evidence_count=0,
            unresolved_count=0,
            verified_local_alert_count=1,
            cases=(case,),
        ),
        index_path="runs/pilot-001/report/index.html",
        metrics_path="runs/pilot-001/metrics.json",
        case_paths=("runs/pilot-001/report/cases/case-001.html",),
        local_alert_paths=(f"runs/pilot-001/alerts/{'8' * 64}.json",),
        projection_paths=(
            "runs/pilot-001/projections/current.json",
            "runs/pilot-001/m5-projections/current.json",
        ),
    )
    return PilotA5RunReport(
        run_id="pilot-001",
        reproducibility_mode=ReproducibilityMode.REPLAY_LOCKED,
        state="COMPLETE",
        evidence=evidence,
        backlog_retry=BacklogRetryReport(
            run_id="pilot-001",
            reclaimed_expired_count=0,
            reclaimed_exhausted_count=0,
            disposition=BacklogRetryDisposition.NO_WORK,
        ),
        screening=screening,
        publication=publication,
    )


def test_pilot_a5_report_is_content_bound_and_exported() -> None:
    report = _report()

    assert PilotA5RunReport.model_validate_json(report.model_dump_json()) == report
    assert report.production_delivery_count == 0
    assert "pilot-a5-run-report.schema.json" in expected_schema_files()

    payload = report.model_dump(mode="python")
    payload["report_id"] = "0" * 64
    with pytest.raises(ValidationError, match="report_id"):
        PilotA5RunReport.model_validate(payload)


def test_pilot_a5_report_rejects_cross_run_components_and_false_state() -> None:
    payload = _report().model_dump(mode="python", exclude_computed_fields=True)
    payload["backlog_retry"]["run_id"] = "another-run"
    with pytest.raises(ValidationError, match="different runs"):
        PilotA5RunReport.model_validate(payload)

    payload = _report().model_dump(mode="python", exclude_computed_fields=True)
    payload["state"] = "ATTENTION_REQUIRED"
    with pytest.raises(ValidationError, match="state conflicts"):
        PilotA5RunReport.model_validate(payload)
