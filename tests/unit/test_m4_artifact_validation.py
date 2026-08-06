from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from labcourt.adapters.storage.readonly_sqlite import ReadOnlySnapshotError
from labcourt.application.m4_artifact_validation import M4ArtifactValidator
from labcourt.application.m4_current_projection_validation import (
    M4CurrentProjectionValidator,
)
from labcourt.contracts.artifact_validation import (
    ArtifactValidationReport,
    M3ArtifactInventoryKind,
    M3ArtifactValidationArea,
    M3ArtifactValidationIssue,
    M3ArtifactValidationIssueCode,
    M3ArtifactValidationReport,
)
from labcourt.contracts.m4_artifact_validation import (
    M4ArtifactValidationBudget,
    M4ArtifactValidationIssueCode,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.exceptions import PathBoundaryViolation

RUN_ID = "m4-unit-validation"


def _m3_report() -> M3ArtifactValidationReport:
    return M3ArtifactValidationReport(
        run_id=RUN_ID,
        m2_report=ArtifactValidationReport(run_id=RUN_ID),
    )


class _UnusedProjectionReader:
    def read_verified(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("projection reads must be skipped")

    def list_projection_directory(self, *args: object, **kwargs: object) -> tuple[()]:
        raise AssertionError("projection listings must be skipped")


class _UnusedAuthority:
    def scan(self, run_id: str) -> object:
        raise AssertionError("authority scan must be skipped")


class _UnusedMediaVerifier:
    def verify_crop(self, crop: object) -> object:
        raise AssertionError("media verification must be skipped")


@dataclass(frozen=True, slots=True)
class _Failure:
    failure_type: str
    inventory_kind: M4ProjectionArtifactKind
    record_identity_sha256: str
    artifact_id: str | None
    reason_code: str


@dataclass(frozen=True, slots=True)
class _Snapshot:
    run_id: str
    documents: tuple[()] = ()
    failures: tuple[_Failure, ...] = ()
    hearing_roots: tuple[()] = ()
    authority_root_sha256: str = "a" * 64


@dataclass(frozen=True, slots=True)
class _Authority:
    snapshot: _Snapshot

    def scan(self, run_id: str) -> _Snapshot:
        assert run_id == RUN_ID
        return self.snapshot


class _BrokenAuthority:
    def scan(self, run_id: str) -> object:
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")


@dataclass(frozen=True, slots=True)
class _Document:
    kind: M4ProjectionArtifactKind
    artifact_id: str
    canonical_document: str

    @property
    def document_sha256(self) -> str:
        return hashlib.sha256(self.canonical_document.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class _ProjectionAuthority:
    run_id: str
    documents: tuple[_Document, ...]
    authority_root_sha256: str


class _UnsafeProjectionReader:
    def read_verified(self, *args: object, **kwargs: object) -> object:
        raise PathBoundaryViolation("WINDOWS_REPARSE_POINT")

    def list_projection_directory(self, *args: object, **kwargs: object) -> tuple[()]:
        raise AssertionError("an unsafe pointer must stop traversal")


def test_m4_preflight_budget_stops_before_scan_or_projection_reads() -> None:
    report = M4ArtifactValidator(
        authority=_UnusedAuthority(),
        artifact_reader=_UnusedProjectionReader(),
        authority_rows=2,
        preflight_max_document_bytes=17,
        media_verifier=_UnusedMediaVerifier(),
        budget=M4ArtifactValidationBudget(max_authority_documents=1),
    ).validate(RUN_ID, _m3_report())

    assert report.passed is False
    assert report.counts.authority_rows == 2
    assert report.issues[0].code == (
        M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_COUNT_BUDGET_EXCEEDED
    )


@pytest.mark.parametrize(
    ("failure_type", "expected_code"),
    (
        (
            "DOCUMENT_INVALID",
            M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
        ),
        ("INDEX_MISMATCH", M4ArtifactValidationIssueCode.AUTHORITY_INDEX_MISMATCH),
        (
            "REFERENCE_INVALID",
            M4ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID,
        ),
        (
            "SCHEMA_UNSUPPORTED",
            M4ArtifactValidationIssueCode.AUTHORITY_SCHEMA_UNSUPPORTED,
        ),
    ),
)
def test_m4_authority_failure_is_typed_and_projection_is_skipped(
    failure_type: str,
    expected_code: M4ArtifactValidationIssueCode,
) -> None:
    failure = _Failure(
        failure_type=failure_type,
        inventory_kind=M4ProjectionArtifactKind.FRAME,
        record_identity_sha256="b" * 64,
        artifact_id="camera-a:stream-a:42",
        reason_code="REFERENCE_MISSING",
    )
    report = M4ArtifactValidator(
        authority=_Authority(_Snapshot(run_id=RUN_ID, failures=(failure,))),
        artifact_reader=_UnusedProjectionReader(),
        authority_rows=1,
        preflight_max_document_bytes=9,
        media_verifier=_UnusedMediaVerifier(),
    ).validate(RUN_ID, _m3_report())

    assert report.authority_root_sha256 is None
    assert report.counts.authority_failures == 1
    assert report.issues[0].code == expected_code


def test_m4_schema_failure_becomes_a_report_instead_of_a_cli_boundary_error() -> None:
    report = M4ArtifactValidator(
        authority=_BrokenAuthority(),
        artifact_reader=_UnusedProjectionReader(),
        authority_rows=1,
        preflight_max_document_bytes=0,
        media_verifier=_UnusedMediaVerifier(),
    ).validate(RUN_ID, _m3_report())

    assert report.issues[0].code == M4ArtifactValidationIssueCode.AUTHORITY_SCHEMA_INVALID
    assert report.issues[0].reason_code == "DATABASE_SCHEMA_INVALID"


def test_m4_projection_path_boundary_failure_is_typed_as_unsafe() -> None:
    authority = _ProjectionAuthority(
        run_id=RUN_ID,
        documents=(
            _Document(
                kind=M4ProjectionArtifactKind.HEARING_SESSION,
                artifact_id="hearing-session",
                canonical_document='{"hearing":"fixture"}',
            ),
        ),
        authority_root_sha256="c" * 64,
    )
    result = M4CurrentProjectionValidator(
        artifact_reader=_UnsafeProjectionReader(),
        budget=M4ArtifactValidationBudget(),
    ).validate(RUN_ID, authority)

    assert result.issues[0].code == M4ArtifactValidationIssueCode.PROJECTION_UNSAFE
    assert result.issues[0].reason_code == "WINDOWS_REPARSE_POINT"


def test_non_successor_embedded_m3_defect_remains_gating() -> None:
    m3_report = M3ArtifactValidationReport(
        run_id=RUN_ID,
        m2_report=ArtifactValidationReport(run_id=RUN_ID),
        issues=(
            M3ArtifactValidationIssue(
                code=M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING,
                area=M3ArtifactValidationArea.RAW_RESPONSE,
                inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
                record_identity_sha256="d" * 64,
                artifact_id="e" * 64,
                reason_code="FILE_MISSING",
            ),
        ),
    )
    report = M4ArtifactValidator(
        authority=_Authority(_Snapshot(run_id=RUN_ID)),
        artifact_reader=_UnusedProjectionReader(),
        authority_rows=1,
        preflight_max_document_bytes=0,
        media_verifier=_UnusedMediaVerifier(),
    ).validate(RUN_ID, m3_report)

    assert report.passed is False
    assert report.counts.embedded_m3_issues == 1
    assert report.counts.embedded_m3_superseded_issues == 0
    assert report.counts.embedded_m3_gating_issues == 1
    assert report.issues[0].code == M4ArtifactValidationIssueCode.EMBEDDED_M3_DEFECT
