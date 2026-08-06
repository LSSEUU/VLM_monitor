from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from labcourt.contracts.artifact_validation import (
    ArtifactInventoryKind,
    ArtifactValidationArea,
    ArtifactValidationCounts,
    ArtifactValidationIssue,
    ArtifactValidationIssueCode,
    ArtifactValidationReport,
    ProjectionArtifactKind,
)
from labcourt.contracts.enums import ArtifactKind, ClosureDefectCode
from labcourt.contracts.storage import ArtifactRef

RUN_ID = "artifact-validation-run"
PACK_ID = "1" * 64
MANIFEST_ID = "2" * 64
HEAD_HASH = "3" * 64


def _closure_issue() -> ArtifactValidationIssue:
    return ArtifactValidationIssue(
        code=ArtifactValidationIssueCode.CURRENT_CLOSURE_DEFECT,
        area=ArtifactValidationArea.PACK,
        root_ref=ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=PACK_ID),
        artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id="4" * 64),
        closure_defect_code=ClosureDefectCode.PIXEL_HASH_MISMATCH,
    )


def test_artifact_validation_passed_is_computed_and_cannot_be_forged() -> None:
    report = ArtifactValidationReport(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        audit_head_sequence=2,
        audit_head_hash=HEAD_HASH,
        issues=(_closure_issue(),),
    )
    assert report.passed is False

    payload = report.model_dump(mode="json")
    payload["passed"] = True
    with pytest.raises(ValidationError, match="passed conflicts"):
        ArtifactValidationReport.model_validate(payload)


def test_artifact_validation_issues_require_stable_unique_order() -> None:
    first = ArtifactValidationIssue(
        code=ArtifactValidationIssueCode.PROJECTION_MISSING,
        area=ArtifactValidationArea.PROJECTION,
        projection_kind=ProjectionArtifactKind.EVENTS_JSONL,
        projection_id=RUN_ID,
    )
    second = _closure_issue()
    ordered = tuple(sorted((first, second), key=lambda issue: issue.sort_key))
    assert ArtifactValidationReport(run_id=RUN_ID, issues=ordered).issues == ordered

    with pytest.raises(ValidationError, match="stable order"):
        ArtifactValidationReport(run_id=RUN_ID, issues=tuple(reversed(ordered)))
    with pytest.raises(ValidationError, match="unique"):
        ArtifactValidationReport(run_id=RUN_ID, issues=(first, first))


def test_authority_inventory_mismatch_has_typed_unforgeable_counts() -> None:
    mismatch = ArtifactValidationIssue(
        code=ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
        area=ArtifactValidationArea.MEDIA,
        inventory_kind=ArtifactInventoryKind.MEDIA,
        authoritative_count=2,
        traversed_count=1,
    )
    report = ArtifactValidationReport(
        run_id=RUN_ID,
        counts=ArtifactValidationCounts(media=2),
        issues=(mismatch,),
    )
    assert report.passed is False

    payload = report.model_dump(mode="json")
    payload["counts"]["media"] = 3
    with pytest.raises(ValidationError, match="conflicts with report authority counts"):
        ArtifactValidationReport.model_validate(payload)

    with pytest.raises(ValidationError, match="distinct authoritative and traversed"):
        ArtifactValidationIssue(
            code=ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
            area=ArtifactValidationArea.MEDIA,
            inventory_kind=ArtifactInventoryKind.MEDIA,
            authoritative_count=1,
            traversed_count=1,
        )
    with pytest.raises(ValidationError, match="area conflicts"):
        ArtifactValidationIssue(
            code=ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
            area=ArtifactValidationArea.PACK,
            inventory_kind=ArtifactInventoryKind.MEDIA,
            authoritative_count=2,
            traversed_count=1,
        )


def test_authority_inventory_mismatch_is_unique_per_inventory_kind() -> None:
    issues = tuple(
        sorted(
            (
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
                    area=ArtifactValidationArea.PACK,
                    inventory_kind=ArtifactInventoryKind.PACK,
                    authoritative_count=2,
                    traversed_count=1,
                ),
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
                    area=ArtifactValidationArea.PACK,
                    inventory_kind=ArtifactInventoryKind.PACK,
                    authoritative_count=2,
                    traversed_count=0,
                ),
            ),
            key=lambda issue: issue.sort_key,
        )
    )
    with pytest.raises(ValidationError, match="inventory kinds must be unique"):
        ArtifactValidationReport(
            run_id=RUN_ID,
            counts=ArtifactValidationCounts(packs=2),
            issues=issues,
        )


def test_artifact_validation_contract_excludes_host_paths_and_open_error_text() -> None:
    schema = ArtifactValidationReport.model_json_schema(mode="serialization")
    serialized = str(schema)
    assert "host_path" not in serialized
    assert "exception" not in serialized
    assert "message" not in serialized

    with pytest.raises(ValidationError):
        ArtifactValidationIssue(
            code=ArtifactValidationIssueCode.PROJECTION_UNSAFE,
            area=ArtifactValidationArea.PROJECTION,
            projection_kind=ProjectionArtifactKind.CASE_JSON,
            projection_id="C:\\private\\case.json",
            reason_code="WINDOWS_OPEN_32",
        )


def test_artifact_validation_scope_explicitly_excludes_source_and_privacy_replay() -> None:
    scope = ArtifactValidationReport(run_id=RUN_ID).scope
    assert scope.database_documents is True
    assert scope.audit_chain_and_head is True
    assert scope.current_closure is True
    assert scope.canonical_projections is True
    assert scope.stored_media is True
    assert scope.source_pixel_replay is False
    assert scope.privacy_transform_replay is False
    assert scope.creation_privacy_basis == "IMMUTABLE_DB_AND_CREATION_CLOSURE"


def test_artifact_validation_schema_is_registered_in_committed_output() -> None:
    project_root = Path(__file__).parents[2]
    assert (project_root / "schemas" / "artifact-validation-report.schema.json").is_file()
