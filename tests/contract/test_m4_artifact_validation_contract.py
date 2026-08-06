from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.artifact_validation import (
    M3_ARTIFACT_VALIDATOR_VERSION,
    ArtifactValidationReport,
    M3ArtifactValidationReport,
)
from labcourt.contracts.m4_artifact_validation import (
    M4_ARTIFACT_VALIDATOR_VERSION,
    M4ArtifactValidationArea,
    M4ArtifactValidationCounts,
    M4ArtifactValidationInventoryCount,
    M4ArtifactValidationIssue,
    M4ArtifactValidationIssueCode,
    M4ArtifactValidationReport,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind

RUN_ID = "m4-artifact-validation-run"


def _m3_report() -> M3ArtifactValidationReport:
    return M3ArtifactValidationReport(
        run_id=RUN_ID,
        m2_report=ArtifactValidationReport(run_id=RUN_ID),
    )


def test_m4_report_is_an_independent_root_embedding_the_frozen_m3_report() -> None:
    report = M4ArtifactValidationReport(
        run_id=RUN_ID,
        m3_report=_m3_report(),
        authority_root_sha256="1" * 64,
    )

    assert M3_ARTIFACT_VALIDATOR_VERSION == "m3-artifacts-v1"
    assert M4_ARTIFACT_VALIDATOR_VERSION == "m4-artifacts-v1"
    assert report.validator_version == "m4-artifacts-v1"
    assert report.passed is True
    assert report.scope.authority == "SQLITE_SNAPSHOT"
    assert report.scope.embedded_m3_gating is False
    assert report.scope.current_projection_exact_inventory is True
    assert report.scope.projection_rebuild is False
    assert report.scope.authority_mutation is False
    assert report.scope.projection_mutation is False
    assert (
        "authority_root_sha256" not in M3ArtifactValidationReport.model_json_schema()["properties"]
    )


def test_m4_passed_is_derived_and_requires_a_same_run_authority_root() -> None:
    with pytest.raises(ValidationError, match="requires an authority root"):
        M4ArtifactValidationReport(run_id=RUN_ID, m3_report=_m3_report())

    report = M4ArtifactValidationReport(
        run_id=RUN_ID,
        m3_report=_m3_report(),
        authority_root_sha256="2" * 64,
        issues=(
            M4ArtifactValidationIssue(
                code=M4ArtifactValidationIssueCode.PROJECTION_MISSING,
                area=M4ArtifactValidationArea.PROJECTION,
                source_token="3" * 64,
                reason_code="FILE_MISSING",
            ),
        ),
    )
    assert report.passed is False
    payload = report.model_dump(mode="json")
    payload["passed"] = True
    with pytest.raises(ValidationError, match="passed conflicts"):
        M4ArtifactValidationReport.model_validate(payload)


def test_m4_counts_bind_authority_and_projection_inventories() -> None:
    inventories = tuple(
        sorted(
            (
                M4ArtifactValidationInventoryCount(
                    inventory_kind=M4ProjectionArtifactKind.FRAME,
                    authoritative_count=1,
                    projected_count=1,
                ),
                M4ArtifactValidationInventoryCount(
                    inventory_kind=M4ProjectionArtifactKind.HEARING_SESSION,
                    authoritative_count=2,
                    projected_count=1,
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    counts = M4ArtifactValidationCounts(
        validated_authority_documents=3,
        projection_files=4,
        projection_documents=2,
        projection_bytes=80,
        max_projection_file_bytes=40,
        inventories=inventories,
    )
    assert counts.validated_authority_documents == 3
    payload = counts.model_dump(mode="json")
    payload["validated_authority_documents"] = 4
    with pytest.raises(ValidationError, match="validated document count conflicts"):
        M4ArtifactValidationCounts.model_validate(payload)


def test_m4_issues_accept_frame_ids_and_require_typed_context() -> None:
    issue = M4ArtifactValidationIssue(
        code=M4ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID,
        area=M4ArtifactValidationArea.AUTHORITY,
        inventory_kind=M4ProjectionArtifactKind.FRAME,
        record_identity_sha256="4" * 64,
        artifact_id="camera-a:stream-a:42",
        reason_code="REFERENCE_MISSING",
    )
    assert issue.artifact_id == "camera-a:stream-a:42"

    with pytest.raises(ValidationError, match="observed value above"):
        M4ArtifactValidationIssue(
            code=M4ArtifactValidationIssueCode.PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED,
            area=M4ArtifactValidationArea.BUDGET,
            limit=10,
            observed=10,
        )


def test_m4_projection_content_receipt_must_describe_a_real_mismatch() -> None:
    with pytest.raises(ValidationError, match="real mismatch"):
        M4ArtifactValidationIssue(
            code=M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
            area=M4ArtifactValidationArea.PROJECTION,
            source_token="5" * 64,
            reason_code="DOCUMENT_CONTENT_MISMATCH",
            expected_sha256="6" * 64,
            actual_sha256="6" * 64,
            expected_size_bytes=7,
            actual_size_bytes=7,
        )
