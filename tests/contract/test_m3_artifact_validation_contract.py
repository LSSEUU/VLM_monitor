from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from labcourt.contracts.artifact_validation import (
    ARTIFACT_VALIDATOR_VERSION,
    M3_ARTIFACT_VALIDATOR_VERSION,
    ArtifactValidationIssue,
    ArtifactValidationIssueCode,
    ArtifactValidationReport,
    M3ArtifactInventoryKind,
    M3ArtifactValidationArea,
    M3ArtifactValidationBudget,
    M3ArtifactValidationCounts,
    M3ArtifactValidationIssue,
    M3ArtifactValidationIssueCode,
    M3ArtifactValidationReport,
)

RUN_ID = "m3-artifact-validation-run"


def _m2_report() -> ArtifactValidationReport:
    return ArtifactValidationReport(run_id=RUN_ID)


def _authority_issue() -> M3ArtifactValidationIssue:
    return M3ArtifactValidationIssue(
        code=M3ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
        area=M3ArtifactValidationArea.RESPONSE,
        inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
        record_identity_sha256="1" * 64,
        artifact_id="2" * 64,
        reason_code="NON_CANONICAL_DOCUMENT",
    )


def test_m3_artifact_report_is_a_new_root_without_widening_m2() -> None:
    assert ARTIFACT_VALIDATOR_VERSION == "m2-artifacts-v1"
    assert M3_ARTIFACT_VALIDATOR_VERSION == "m3-artifacts-v1"
    assert ArtifactValidationReport(run_id=RUN_ID).validator_version == "m2-artifacts-v1"

    report = M3ArtifactValidationReport(run_id=RUN_ID, m2_report=_m2_report())
    assert report.validator_version == "m3-artifacts-v1"
    assert report.passed is True
    assert report.scope.raw_response_locator_binding is True
    assert report.scope.raw_response_content_and_size is True
    assert report.scope.raw_response_physical_inventory is True
    assert report.scope.raw_response_bidirectional_closure is True
    assert report.scope.raw_response_inventory_consistency == "FAIL_CLOSED_RESCAN"
    assert report.physical_raw_response_inventory_complete is True
    assert report.scope.provider_replay is False
    assert report.scope.model_semantic_replay is False


def test_m3_artifact_passed_combines_embedded_m2_and_m3_issues() -> None:
    report = M3ArtifactValidationReport(
        run_id=RUN_ID,
        m2_report=_m2_report(),
        issues=(_authority_issue(),),
    )
    assert report.passed is False
    payload = report.model_dump(mode="json")
    payload["passed"] = True
    with pytest.raises(ValidationError, match="passed conflicts"):
        M3ArtifactValidationReport.model_validate(payload)

    failed_m2 = ArtifactValidationReport(
        run_id=RUN_ID,
        issues=(
            ArtifactValidationIssue(
                code=ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
                area="AUTHORITY",
            ),
        ),
    )
    assert M3ArtifactValidationReport(run_id=RUN_ID, m2_report=failed_m2).passed is False


def test_m3_artifact_counts_cover_all_fifteen_durable_inventories() -> None:
    counts = M3ArtifactValidationCounts(
        model_call_claims=1,
        model_call_failure_authorities=15,
        model_responses=2,
        parsed_screening_outputs=3,
        model_parse_receipts=4,
        model_cache_entries=5,
        model_call_usage=6,
        screening_results=7,
        verdicts=8,
        procedural_reviews=9,
        procedural_defects=10,
        backlog_items=11,
        backlog_item_versions=12,
        backlog_heads=13,
        backlog_completion_receipts=14,
    )
    assert len(M3ArtifactInventoryKind) == 15
    assert counts.documents == sum(range(1, 16))


def test_m3_physical_raw_inventory_contract_is_bounded_and_computed() -> None:
    budget = M3ArtifactValidationBudget()
    assert budget.max_raw_response_files == 1_000_000
    assert budget.max_raw_response_name_bytes == 255

    counts = M3ArtifactValidationCounts(
        physical_raw_response_entries=2,
        physical_raw_response_files=1,
        physical_raw_response_bytes=7,
        max_physical_raw_response_bytes=7,
    )
    payload = counts.model_dump(mode="json")
    assert M3ArtifactValidationCounts.model_validate(payload) == counts
    payload["documents"] = 1
    with pytest.raises(ValidationError, match="document count conflicts"):
        M3ArtifactValidationCounts.model_validate(payload)

    with pytest.raises(ValidationError, match="cannot exceed directory entries"):
        M3ArtifactValidationCounts(
            physical_raw_response_entries=0,
            physical_raw_response_files=1,
        )


def test_m3_physical_inventory_issues_use_only_opaque_source_identity() -> None:
    orphan = M3ArtifactValidationIssue(
        code=M3ArtifactValidationIssueCode.RAW_RESPONSE_UNREFERENCED,
        area=M3ArtifactValidationArea.RAW_RESPONSE,
        artifact_id="2" * 64,
        source_token="3" * 64,
    )
    unsafe = M3ArtifactValidationIssue(
        code=M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE,
        area=M3ArtifactValidationArea.RAW_RESPONSE,
        source_token="4" * 64,
        reason_code="INVALID_ENTRY_NAME",
    )
    report = M3ArtifactValidationReport(
        run_id=RUN_ID,
        m2_report=_m2_report(),
        issues=tuple(sorted((orphan, unsafe), key=lambda issue: issue.sort_key)),
    )
    assert report.passed is False
    assert report.physical_raw_response_inventory_complete is False
    serialized = report.model_dump(mode="json")
    serialized["physical_raw_response_inventory_complete"] = True
    with pytest.raises(ValidationError, match="inventory completeness conflicts"):
        M3ArtifactValidationReport.model_validate(serialized)

    with pytest.raises(ValidationError, match="opaque source token"):
        M3ArtifactValidationIssue(
            code=M3ArtifactValidationIssueCode.RAW_RESPONSE_UNREFERENCED,
            area=M3ArtifactValidationArea.RAW_RESPONSE,
            artifact_id="2" * 64,
        )


def test_m3_physical_file_count_budget_is_typed() -> None:
    issue = M3ArtifactValidationIssue(
        code=M3ArtifactValidationIssueCode.RAW_RESPONSE_FILE_COUNT_BUDGET_EXCEEDED,
        area=M3ArtifactValidationArea.BUDGET,
        limit=1,
        observed=2,
    )
    report = M3ArtifactValidationReport(
        run_id=RUN_ID,
        m2_report=_m2_report(),
        issues=(issue,),
    )
    assert report.physical_raw_response_inventory_complete is False

    preflight_issue = M3ArtifactValidationIssue(
        code=M3ArtifactValidationIssueCode.DOCUMENT_COUNT_BUDGET_EXCEEDED,
        area=M3ArtifactValidationArea.BUDGET,
        limit=1,
        observed=2,
    )
    preflight_report = M3ArtifactValidationReport(
        run_id=RUN_ID,
        m2_report=_m2_report(),
        issues=(preflight_issue,),
    )
    assert preflight_report.physical_raw_response_inventory_complete is False


def test_m3_artifact_issue_context_is_fail_closed_and_typed() -> None:
    with pytest.raises(ValidationError, match="typed record identity"):
        M3ArtifactValidationIssue(
            code=M3ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
            area=M3ArtifactValidationArea.RESPONSE,
            inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
        )

    with pytest.raises(ValidationError, match="typed model-response"):
        M3ArtifactValidationIssue(
            code=M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING,
            area=M3ArtifactValidationArea.RAW_RESPONSE,
            inventory_kind=M3ArtifactInventoryKind.MODEL_CACHE_ENTRY,
            record_identity_sha256="1" * 64,
            artifact_id="2" * 64,
        )

    with pytest.raises(ValidationError, match="reason code"):
        M3ArtifactValidationIssue(
            code=M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING,
            area=M3ArtifactValidationArea.RAW_RESPONSE,
            inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
            record_identity_sha256="1" * 64,
            artifact_id="2" * 64,
        )

    with pytest.raises(ValidationError, match="complete expected and actual receipts"):
        M3ArtifactValidationIssue(
            code=M3ArtifactValidationIssueCode.RAW_RESPONSE_CONTENT_MISMATCH,
            area=M3ArtifactValidationArea.RAW_RESPONSE,
            inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
            record_identity_sha256="1" * 64,
            artifact_id="2" * 64,
            expected_sha256="3" * 64,
            actual_sha256="4" * 64,
        )

    with pytest.raises(ValidationError, match="distinct hash or size"):
        M3ArtifactValidationIssue(
            code=M3ArtifactValidationIssueCode.RAW_RESPONSE_CONTENT_MISMATCH,
            area=M3ArtifactValidationArea.RAW_RESPONSE,
            inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
            record_identity_sha256="1" * 64,
            artifact_id="2" * 64,
            expected_sha256="3" * 64,
            actual_sha256="3" * 64,
            expected_size_bytes=10,
            actual_size_bytes=10,
        )

    with pytest.raises(ValidationError, match="cannot carry artifact context"):
        M3ArtifactValidationIssue(
            code=M3ArtifactValidationIssueCode.DOCUMENT_COUNT_BUDGET_EXCEEDED,
            area=M3ArtifactValidationArea.BUDGET,
            inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
            limit=1,
            observed=2,
        )

    mismatch = M3ArtifactValidationIssue(
        code=M3ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
        area=M3ArtifactValidationArea.CACHE,
        inventory_kind=M3ArtifactInventoryKind.MODEL_CACHE_ENTRY,
        authoritative_count=2,
        traversed_count=1,
    )
    with pytest.raises(ValidationError, match="conflicts with report authority counts"):
        M3ArtifactValidationReport(
            run_id=RUN_ID,
            m2_report=_m2_report(),
            counts=M3ArtifactValidationCounts(model_cache_entries=3),
            issues=(mismatch,),
        )


def test_m3_artifact_issues_require_stable_unique_order_and_matching_run() -> None:
    authority = _authority_issue()
    raw = M3ArtifactValidationIssue(
        code=M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING,
        area=M3ArtifactValidationArea.RAW_RESPONSE,
        inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
        record_identity_sha256="1" * 64,
        artifact_id="2" * 64,
        reason_code="FILE_MISSING",
    )
    ordered = tuple(sorted((authority, raw), key=lambda issue: issue.sort_key))
    assert (
        M3ArtifactValidationReport(
            run_id=RUN_ID,
            m2_report=_m2_report(),
            issues=ordered,
        ).issues
        == ordered
    )
    with pytest.raises(ValidationError, match="stable order"):
        M3ArtifactValidationReport(
            run_id=RUN_ID,
            m2_report=_m2_report(),
            issues=tuple(reversed(ordered)),
        )
    with pytest.raises(ValidationError, match="unique"):
        M3ArtifactValidationReport(
            run_id=RUN_ID,
            m2_report=_m2_report(),
            issues=(authority, authority),
        )
    with pytest.raises(ValidationError, match="run IDs differ"):
        M3ArtifactValidationReport(
            run_id=RUN_ID,
            m2_report=ArtifactValidationReport(run_id="another-run"),
        )


def test_m3_artifact_schema_excludes_host_paths_and_is_registered() -> None:
    serialized = str(M3ArtifactValidationReport.model_json_schema(mode="serialization"))
    assert "host_path" not in serialized
    assert "exception" not in serialized
    assert "message" not in serialized

    project_root = Path(__file__).parents[2]
    assert (project_root / "schemas" / "m3-artifact-validation-report.schema.json").is_file()
