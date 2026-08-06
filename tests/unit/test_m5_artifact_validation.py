from __future__ import annotations

from dataclasses import dataclass, replace

from labcourt.adapters.storage.readonly_m5_artifacts import (
    M5ArtifactAuthorityFailure,
    M5ArtifactAuthoritySnapshot,
    M5AuthorityFailureType,
    M5TraversedInventory,
    M5ValidatedDocument,
)
from labcourt.application.m5_artifact_validation import M5ArtifactValidator
from labcourt.contracts.m5_artifact_validation import (
    M5ActivationAuthorityReasonCode,
    M5ArtifactValidationBudget,
    M5ArtifactValidationIssueCode,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.exceptions import PathBoundaryViolation


@dataclass(frozen=True)
class _Snapshot:
    size_bytes: int
    sha256: str
    bytes: bytes


@dataclass(frozen=True)
class _Hint:
    name: str | None
    source_token: str
    reason_code: str | None


@dataclass(frozen=True)
class _MissingReader:
    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> _Snapshot:
        del expected_sha256, max_bytes
        raise PathBoundaryViolation("FILE_MISSING", relative_path)

    def list_projection_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[_Hint, ...]:
        del relative_path, max_items, max_name_bytes
        return ()


def test_m5_validator_reports_missing_projection_and_bounded_authority() -> None:
    run_id = "m5-validation-unit"
    documents = (
        M5ValidatedDocument(M5AuthorityKind.ALERT, "alert-a", "{}"),
        M5ValidatedDocument(M5AuthorityKind.PRECEDENT, "precedent-a", "{}"),
    )
    snapshot = M5ArtifactAuthoritySnapshot(
        run_id=run_id,
        manifest_id="a" * 64,
        config_sha256="b" * 64,
        traversed=tuple(
            M5TraversedInventory(kind, int(kind in {item.kind for item in documents}))
            for kind in sorted(M5AuthorityKind, key=lambda item: item.value)
        ),
        documents=documents,
        case_roots=(),
        failures=(),
        training_labels=(),
        dataset_reports=(),
        training_cases=(),
        dataset_histories=(),
        dataset_retention_failures=(),
        dataset_retention_hold_count=0,
        orphan_retention_hold_count=0,
        retention_rows=0,
        retention_bytes=0,
        max_retention_record_bytes=0,
        retention_root_sha256="c" * 64,
        authority_bytes=4,
        max_authority_record_bytes=2,
    )
    report = M5ArtifactValidator(
        artifact_reader=_MissingReader(),
        budget=M5ArtifactValidationBudget(max_authority_records=1),
    ).validate(run_id, snapshot)

    assert report.passed is False
    assert report.authority_root_sha256 == snapshot.authority_root_sha256
    assert {issue.code for issue in report.issues} == {
        M5ArtifactValidationIssueCode.AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED,
        M5ArtifactValidationIssueCode.PROJECTION_MISSING,
    }
    assert report.counts.authority_rows == report.counts.validated_authority_documents == 2

    activation_failure = M5ArtifactAuthorityFailure(
        M5AuthorityFailureType.REFERENCE_INVALID,
        M5AuthorityKind.PRECEDENT_LIFECYCLE,
        "d" * 64,
        "activation-receipt",
        M5ActivationAuthorityReasonCode.ACTIVATION_REPLAY_MISMATCH.value,
    )
    activation_report = M5ArtifactValidator(
        artifact_reader=_MissingReader(),
        budget=M5ArtifactValidationBudget(max_authority_records=10),
    ).validate(run_id, replace(snapshot, failures=(activation_failure,)))
    assert M5ArtifactValidationIssueCode.PRECEDENT_ACTIVATION_INVALID in {
        issue.code for issue in activation_report.issues
    }
    assert activation_report.authority_root_sha256 is None
