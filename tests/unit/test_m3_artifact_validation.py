from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from labcourt.adapters.storage.readonly_m3_artifacts import (
    M3ArtifactAuthorityFailure,
    M3ArtifactAuthoritySnapshot,
    M3AuthorityFailureType,
    M3TraversedInventory,
    M3ValidatedRawResponse,
)
from labcourt.application.artifact_validation import M3ArtifactValidator
from labcourt.contracts.artifact_validation import (
    ArtifactValidationReport,
    M3ArtifactInventoryKind,
    M3ArtifactValidationBudget,
    M3ArtifactValidationCounts,
    M3ArtifactValidationIssueCode,
    M3ArtifactValidationReport,
)
from labcourt.contracts.enums import VlmCallPurpose
from labcourt.contracts.recovery import recovery_source_token
from labcourt.contracts.screening import VLMResponse, derive_model_response_id
from labcourt.exceptions import BudgetExceeded, ContractViolation, PathBoundaryViolation

RUN_ID = "m3-artifact-unit"
RAW_BYTES = b'{"strict":true}'
RAW_SHA256 = hashlib.sha256(RAW_BYTES).hexdigest()
REQUEST_ID = "1" * 64


def _response() -> VLMResponse:
    response_id = derive_model_response_id(RUN_ID, REQUEST_ID, RAW_SHA256)
    return VLMResponse(
        run_id=RUN_ID,
        case_id="case-01",
        evidence_pack_id="2" * 64,
        evidence_pack_version=1,
        request_id=REQUEST_ID,
        request_sha256="3" * 64,
        cache_key="4" * 64,
        purpose=VlmCallPurpose.SCREENING,
        attempt_index=0,
        raw_response_ref=f"{RUN_ID}/model_responses/{response_id}.json",
        content_sha256=RAW_SHA256,
        size_bytes=len(RAW_BYTES),
        model_manifest_id="5" * 64,
        manifest_id="6" * 64,
    )


def _traversed(*, responses: int = 1) -> tuple[M3TraversedInventory, ...]:
    return tuple(
        M3TraversedInventory(
            inventory_kind=kind,
            count=responses if kind == M3ArtifactInventoryKind.MODEL_RESPONSE else 0,
        )
        for kind in M3ArtifactInventoryKind
    )


class _Authority:
    def __init__(
        self,
        *,
        failures: tuple[M3ArtifactAuthorityFailure, ...] = (),
        traversed: tuple[M3TraversedInventory, ...] | None = None,
        raw_responses: tuple[M3ValidatedRawResponse, ...] | None = None,
    ) -> None:
        response = _response()
        default_raw_responses = (
            M3ValidatedRawResponse(
                response=response,
                record_identity_sha256="7" * 64,
            ),
        )
        self.snapshot = M3ArtifactAuthoritySnapshot(
            traversed=traversed or _traversed(),
            raw_responses=(default_raw_responses if raw_responses is None else raw_responses),
            failures=failures,
        )
        self.calls = 0

    def scan(self, run_id: str) -> M3ArtifactAuthoritySnapshot:
        assert run_id == RUN_ID
        self.calls += 1
        return self.snapshot


@dataclass(frozen=True, slots=True)
class _Snapshot:
    bytes: bytes
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _Hint:
    name: str | None
    source_token: str
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class _Metadata:
    relative_path: str
    size_bytes: int
    identity_token: str


class _Reader:
    def __init__(self, body: bytes = RAW_BYTES) -> None:
        self.body = body
        self.calls: list[tuple[str, str | None, int | None]] = []
        self.error: Exception | None = None
        name = f"{_response().response_id}.json"
        relative_path = f"{RUN_ID}/model_responses/{name}"
        self.hints: tuple[_Hint, ...] = (
            _Hint(name=name, source_token=recovery_source_token(relative_path)),
        )
        self.second_hints: tuple[_Hint, ...] | None = None
        self.inventory_error: Exception | None = None
        self.metadata_errors: dict[str, Exception] = {}
        self.metadata_sizes: dict[str, int] = {relative_path: len(body)}
        self.inventory_calls = 0
        self.inspect_calls: list[str] = []

    def list_model_response_recovery_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[_Hint, ...]:
        assert relative_path == f"{RUN_ID}/model_responses"
        self.inventory_calls += 1
        if self.inventory_error is not None:
            raise self.inventory_error
        if len(self.hints) > max_items:
            raise BudgetExceeded("inventory limit")
        if self.second_hints is not None and self.inventory_calls > 1:
            return self.second_hints
        return self.hints

    def inspect_verified(self, relative_path: str) -> _Metadata:
        self.inspect_calls.append(relative_path)
        error = self.metadata_errors.get(relative_path)
        if error is not None:
            raise error
        return _Metadata(
            relative_path=relative_path,
            size_bytes=self.metadata_sizes[relative_path],
            identity_token=hashlib.sha256(relative_path.encode()).hexdigest(),
        )

    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> _Snapshot:
        self.calls.append((relative_path, expected_sha256, max_bytes))
        if self.error is not None:
            raise self.error
        return _Snapshot(
            bytes=self.body,
            size_bytes=len(self.body),
            sha256=hashlib.sha256(self.body).hexdigest(),
        )


def _counts(*, responses: int = 1, raw_bytes: int = len(RAW_BYTES)) -> M3ArtifactValidationCounts:
    return M3ArtifactValidationCounts(
        max_document_bytes=1024,
        raw_response_bytes=raw_bytes,
        max_raw_response_bytes=raw_bytes,
        model_responses=responses,
    )


def _validate(
    authority: _Authority,
    reader: _Reader,
    *,
    counts: M3ArtifactValidationCounts | None = None,
    budget: M3ArtifactValidationBudget | None = None,
) -> M3ArtifactValidationReport:
    return M3ArtifactValidator(
        authority=authority,
        artifact_reader=reader,
        authority_counts=counts or _counts(),
        budget=budget,
    ).validate(RUN_ID, ArtifactValidationReport(run_id=RUN_ID))


def test_m3_artifact_validator_reads_exact_raw_response_with_size_bound() -> None:
    authority = _Authority()
    reader = _Reader()
    report = _validate(authority, reader)

    assert report.passed is True
    assert authority.calls == 1
    assert reader.calls == [
        (
            _response().raw_response_ref,
            RAW_SHA256,
            len(RAW_BYTES),
        )
    ]
    assert reader.inventory_calls == 2


def test_m3_artifact_validator_reports_missing_and_mismatched_raw_bytes() -> None:
    missing_reader = _Reader()
    missing_reader.error = PathBoundaryViolation(
        "FILE_MISSING",
        _response().raw_response_ref,
    )
    missing = _validate(_Authority(), missing_reader)
    assert {issue.code for issue in missing.issues} == {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING
    }

    mismatched = _validate(_Authority(), _Reader(b"different-body"))
    assert {issue.code for issue in mismatched.issues} == {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_CONTENT_MISMATCH
    }


def test_m3_artifact_validator_maps_authority_and_inventory_failures() -> None:
    failure = M3ArtifactAuthorityFailure(
        failure_type=M3AuthorityFailureType.DOCUMENT_INVALID,
        inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
        record_identity_sha256="7" * 64,
        artifact_id=_response().response_id,
        reason_code="DOCUMENT_NOT_CANONICAL",
    )
    traversed = tuple(
        M3TraversedInventory(
            inventory_kind=kind,
            count=(
                1
                if kind
                in {
                    M3ArtifactInventoryKind.MODEL_RESPONSE,
                    M3ArtifactInventoryKind.MODEL_CALL_CLAIM,
                }
                else 0
            ),
        )
        for kind in M3ArtifactInventoryKind
    )
    report = _validate(
        _Authority(failures=(failure,), traversed=traversed, raw_responses=()),
        _Reader(),
    )
    assert {issue.code for issue in report.issues} == {
        M3ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
        M3ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
    }


def test_m3_artifact_budget_preflight_does_not_scan_or_read() -> None:
    authority = _Authority()
    reader = _Reader()
    report = _validate(
        authority,
        reader,
        counts=_counts(raw_bytes=11),
        budget=M3ArtifactValidationBudget(
            max_documents=100,
            max_document_bytes=1024,
            max_raw_response_bytes=10,
            max_raw_response_total_bytes=10,
        ),
    )
    assert {issue.code for issue in report.issues} == {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_BYTES_BUDGET_EXCEEDED,
        M3ArtifactValidationIssueCode.RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED,
    }
    assert authority.calls == 0
    assert reader.calls == []


def test_m3_artifact_validator_rejects_unaccounted_raw_response_rows() -> None:
    authority = _Authority(raw_responses=())

    with pytest.raises(ContractViolation, match="every traversed response row"):
        _validate(authority, _Reader())


def test_m3_artifact_validator_types_reader_limit_rejection() -> None:
    reader = _Reader()
    reader.error = ValueError("workspace limit is lower than declared response size")

    report = _validate(_Authority(), reader)

    assert len(report.issues) == 1
    assert report.issues[0].code == M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE
    assert report.issues[0].reason_code == "READER_LIMIT_REJECTED"


def test_m3_artifact_validator_reports_extra_physical_response_without_reading_it() -> None:
    reader = _Reader()
    orphan_id = "a" * 64
    orphan_path = f"{RUN_ID}/model_responses/{orphan_id}.json"
    reader.hints += (
        _Hint(
            name=f"{orphan_id}.json",
            source_token=recovery_source_token(orphan_path),
        ),
    )
    reader.metadata_sizes[orphan_path] = 10_000_000

    report = _validate(_Authority(), reader)

    orphan = next(
        issue
        for issue in report.issues
        if issue.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_UNREFERENCED
    )
    assert orphan.artifact_id == orphan_id
    assert orphan.source_token == recovery_source_token(orphan_path)
    assert all(call[0] != orphan_path for call in reader.calls)
    assert report.counts.physical_raw_response_entries == 2
    assert report.counts.physical_raw_response_files == 2


def test_m3_artifact_validator_types_sanitized_invalid_inventory_hints() -> None:
    reader = _Reader()
    token = "a" * 64
    reader.hints += (_Hint(name=None, source_token=token, reason_code="NAME_BUDGET_EXCEEDED"),)

    report = _validate(_Authority(), reader)

    unsafe = next(
        issue
        for issue in report.issues
        if issue.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE
    )
    assert unsafe.source_token == token
    assert unsafe.reason_code == "NAME_BUDGET_EXCEEDED"
    serialized = report.model_dump_json()
    assert "host_path" not in serialized


def test_m3_artifact_validator_types_physical_file_and_byte_budgets_before_reads() -> None:
    count_reader = _Reader()
    count_reader.hints += (_Hint(name="b" * 64 + ".json", source_token="b" * 64),)
    count_report = _validate(
        _Authority(),
        count_reader,
        budget=M3ArtifactValidationBudget(max_raw_response_files=1),
    )
    assert {issue.code for issue in count_report.issues} == {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_FILE_COUNT_BUDGET_EXCEEDED
    }
    assert count_reader.calls == []
    assert count_report.counts.physical_raw_response_entries == 2

    bytes_reader = _Reader()
    response_path = _response().raw_response_ref
    bytes_reader.metadata_sizes[response_path] = 11
    bytes_report = _validate(
        _Authority(),
        bytes_reader,
        budget=M3ArtifactValidationBudget(
            max_raw_response_bytes=10,
            max_raw_response_total_bytes=10,
        ),
    )
    assert {issue.code for issue in bytes_report.issues} == {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_BYTES_BUDGET_EXCEEDED,
        M3ArtifactValidationIssueCode.RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED,
    }
    assert bytes_reader.calls == []


def test_m3_artifact_validator_missing_physical_directory_is_empty_only_for_empty_db() -> None:
    empty_reader = _Reader()
    empty_reader.inventory_error = PathBoundaryViolation("DIRECTORY_MISSING")
    empty_report = _validate(
        _Authority(traversed=_traversed(responses=0), raw_responses=()),
        empty_reader,
        counts=_counts(responses=0, raw_bytes=0),
    )
    assert empty_report.passed is True
    assert empty_report.counts.physical_raw_response_entries == 0

    nonempty_reader = _Reader()
    nonempty_reader.inventory_error = PathBoundaryViolation("DIRECTORY_MISSING")
    nonempty_reader.error = PathBoundaryViolation("FILE_MISSING")
    nonempty_report = _validate(_Authority(), nonempty_reader)
    assert {issue.code for issue in nonempty_report.issues} == {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING
    }
    assert nonempty_report.physical_raw_response_inventory_complete is False


def test_m3_artifact_validator_fails_closed_when_directory_changes_between_scans() -> None:
    reader = _Reader()
    extra_id = "c" * 64
    extra_path = f"{RUN_ID}/model_responses/{extra_id}.json"
    reader.second_hints = (
        *reader.hints,
        _Hint(
            name=f"{extra_id}.json",
            source_token=recovery_source_token(extra_path),
        ),
    )
    reader.metadata_sizes[extra_path] = 1

    report = _validate(_Authority(), reader)

    assert M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE in {
        issue.code for issue in report.issues
    }
    assert any(
        issue.reason_code == "DIRECTORY_CHANGED_DURING_VALIDATION" for issue in report.issues
    )


def test_m3_artifact_validator_converts_reader_budget_exceptions_to_typed_issues() -> None:
    metadata_reader = _Reader()
    metadata_reader.metadata_errors[_response().raw_response_ref] = BudgetExceeded(
        "metadata budget"
    )
    metadata_report = _validate(_Authority(), metadata_reader)
    assert any(
        issue.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE
        and issue.reason_code == "INVENTORY_METADATA_BUDGET_EXCEEDED"
        for issue in metadata_report.issues
    )

    body_reader = _Reader()
    body_reader.error = BudgetExceeded("body budget")
    body_report = _validate(_Authority(), body_reader)
    assert any(
        issue.code == M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE
        and issue.reason_code == "READER_BUDGET_EXCEEDED"
        for issue in body_report.issues
    )


def test_m3_document_preflight_marks_physical_inventory_not_scanned() -> None:
    authority = _Authority()
    reader = _Reader()
    report = _validate(
        authority,
        reader,
        counts=_counts(responses=2),
        budget=M3ArtifactValidationBudget(max_documents=1),
    )
    assert {issue.code for issue in report.issues} == {
        M3ArtifactValidationIssueCode.DOCUMENT_COUNT_BUDGET_EXCEEDED
    }
    assert report.physical_raw_response_inventory_complete is False
    assert authority.calls == 0
    assert reader.inventory_calls == 0
