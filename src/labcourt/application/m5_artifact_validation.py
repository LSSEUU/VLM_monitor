"""Read-only M5 authority and selected-projection validation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol

from pydantic import ValidationError

from labcourt.application.dataset_export import DatasetExportError
from labcourt.application.m5_dataset_integrity import (
    M5DatasetIntegrityError,
    M5DatasetIntegrityFailureCode,
    rebuild_and_verify_m5_dataset,
)
from labcourt.contracts.artifact_validation import M3ArtifactValidationReport
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ArtifactKind, VerificationStatus
from labcourt.contracts.evidence import Crop
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_artifact_validation import (
    M5ActivationAuthorityReasonCode,
    M5AlertAuthorityReasonCode,
    M5ArtifactValidationArea,
    M5ArtifactValidationBudget,
    M5ArtifactValidationCounts,
    M5ArtifactValidationInventoryCount,
    M5ArtifactValidationIssue,
    M5ArtifactValidationIssueCode,
    M5ArtifactValidationProjectionCount,
    M5ArtifactValidationReport,
    M5PrecedentCausalLedgerReasonCode,
    M5TrainingHistoryReasonCode,
)
from labcourt.contracts.m5_projection import (
    M5AuthorityKind,
    M5ProjectionCurrentPointer,
    M5ProjectionFileKind,
    M5ProjectionGenerationEntry,
    M5ProjectionGenerationManifest,
    M5ProjectionRecordReceipt,
    m5_projection_authority_kinds,
    m5_projection_relative_path,
)
from labcourt.contracts.m5_training import DatasetExportReport, TrainingCropAuthority
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.contracts.training import TrainingLabel
from labcourt.exceptions import ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation


class M5ProjectionArtifactSnapshot(Protocol):
    size_bytes: int
    sha256: str
    bytes: bytes


class M5ProjectionDirectoryHint(Protocol):
    name: str | None
    source_token: str
    reason_code: str | None


class M5DatasetDirectoryHint(Protocol):
    name: str | None
    source_token: str
    reason_code: str | None


class M5DatasetArtifactMetadata(Protocol):
    size_bytes: int


class M5ProjectionArtifactReader(Protocol):
    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> M5ProjectionArtifactSnapshot: ...

    def list_projection_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[M5ProjectionDirectoryHint, ...]: ...


class M5DatasetArtifactReader(Protocol):
    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> M5ProjectionArtifactSnapshot: ...

    def list_dataset_directory(
        self,
        run_id: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[M5DatasetDirectoryHint, ...]: ...

    def inspect_verified(self, relative_path: str) -> M5DatasetArtifactMetadata: ...

    def verify_crop(self, crop: Crop) -> ArtifactVerification: ...


class M5AuthorityFailureObservation(Protocol):
    failure_type: str
    authority_kind: M5AuthorityKind
    record_identity_sha256: str
    reason_code: str


class M5AuthorityInventoryObservation(Protocol):
    authority_kind: M5AuthorityKind
    count: int


class M5AuthorityDocumentObservation(Protocol):
    kind: M5AuthorityKind
    artifact_id: str
    canonical_document: str

    @property
    def document_sha256(self) -> str: ...


class M5TrainingCaseAuthorityObservation(Protocol):
    case_id: str
    revision: int
    document_sha256: str
    case: Case


class M5DatasetHistoricalAuthorityObservation(Protocol):
    dataset_id: str
    registration_snapshot_authority_id: str
    labels: Sequence[TrainingLabel]
    crop_authorities: Sequence[TrainingCropAuthority]


class M5DatasetRetentionFailureObservation(Protocol):
    failure_type: str
    hold_identity_sha256: str
    dataset_id: str | None
    reason_code: str


class M5AuthoritySnapshotObservation(Protocol):
    run_id: str
    manifest_id: str
    config_sha256: str
    traversed: Sequence[M5AuthorityInventoryObservation]
    documents: Sequence[M5AuthorityDocumentObservation]
    case_roots: Sequence[object]
    failures: Sequence[M5AuthorityFailureObservation]
    training_labels: Sequence[TrainingLabel]
    dataset_reports: Sequence[DatasetExportReport]
    training_cases: Sequence[M5TrainingCaseAuthorityObservation]
    dataset_histories: Sequence[M5DatasetHistoricalAuthorityObservation]
    dataset_retention_failures: Sequence[M5DatasetRetentionFailureObservation]
    dataset_retention_hold_count: int
    orphan_retention_hold_count: int
    retention_rows: int
    retention_bytes: int
    max_retention_record_bytes: int
    authority_bytes: int
    max_authority_record_bytes: int

    @property
    def authority_root_sha256(self) -> str: ...


class M5AuthorityPreflightObservation(Protocol):
    run_id: str
    manifest_id: str
    config_sha256: str
    traversed: Sequence[M5AuthorityInventoryObservation]
    authority_rows: int
    authority_bytes: int
    max_authority_record_bytes: int
    retention_rows: int
    retention_bytes: int
    max_retention_record_bytes: int


_ALERT_POLICY_REASONS = frozenset(
    {
        M5AlertAuthorityReasonCode.ALERT_POLICY_INPUT_ROOT_INVALID.value,
        M5AlertAuthorityReasonCode.ALERT_PRIOR_COOLDOWN_CAUSAL_HEAD_MISMATCH.value,
        M5AlertAuthorityReasonCode.ALERT_COOLDOWN_WRITE_CAUSAL_CLOSURE_INVALID.value,
        M5AlertAuthorityReasonCode.ALERT_POLICY_REPLAY_MISMATCH.value,
    }
)
_ALERT_AUTOMATIC_PRECEDENT_REASONS = frozenset(
    reason.value
    for reason in M5AlertAuthorityReasonCode
    if reason.value not in _ALERT_POLICY_REASONS
)
_PRECEDENT_ACTIVATION_REASONS = frozenset(
    reason.value for reason in M5ActivationAuthorityReasonCode
)
_PRECEDENT_CAUSAL_LEDGER_REASONS = frozenset(
    reason.value for reason in M5PrecedentCausalLedgerReasonCode
)
_TRAINING_CAUSAL_LEDGER_REASONS = frozenset(
    {
        M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_MISSING.value,
        M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_DUPLICATE.value,
        M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_ORPHAN.value,
        M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_SOURCE_MISMATCH.value,
        M5TrainingHistoryReasonCode.TRAINING_CAUSAL_EVENT_CHAIN_INVALID.value,
    }
)
_DATASET_SNAPSHOT_CLOSURE_REASONS = frozenset(
    reason.value
    for reason in M5TrainingHistoryReasonCode
    if reason.value not in _TRAINING_CAUSAL_LEDGER_REASONS
)


def _authority_issue_code(
    failure: M5AuthorityFailureObservation,
) -> M5ArtifactValidationIssueCode:
    if failure.reason_code in _ALERT_POLICY_REASONS:
        return M5ArtifactValidationIssueCode.ALERT_POLICY_REPLAY_INVALID
    if failure.reason_code in _ALERT_AUTOMATIC_PRECEDENT_REASONS:
        return M5ArtifactValidationIssueCode.ALERT_AUTOMATIC_PRECEDENT_INVALID
    if failure.reason_code in _PRECEDENT_ACTIVATION_REASONS:
        return M5ArtifactValidationIssueCode.PRECEDENT_ACTIVATION_INVALID
    if failure.reason_code in _PRECEDENT_CAUSAL_LEDGER_REASONS:
        return M5ArtifactValidationIssueCode.PRECEDENT_CAUSAL_LEDGER_INVALID
    if failure.reason_code in _TRAINING_CAUSAL_LEDGER_REASONS:
        return M5ArtifactValidationIssueCode.TRAINING_CAUSAL_LEDGER_INVALID
    if failure.reason_code in _DATASET_SNAPSHOT_CLOSURE_REASONS:
        return M5ArtifactValidationIssueCode.DATASET_SNAPSHOT_CLOSURE_INVALID
    return {
        "DOCUMENT_INVALID": M5ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
        "INDEX_MISMATCH": M5ArtifactValidationIssueCode.AUTHORITY_INDEX_MISMATCH,
        "REFERENCE_INVALID": M5ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID,
        "HEAD_INVALID": M5ArtifactValidationIssueCode.AUTHORITY_HEAD_INVALID,
    }[str(failure.failure_type)]


@dataclass(frozen=True, slots=True)
class _ProjectionObservation:
    issues: tuple[M5ArtifactValidationIssue, ...]
    files: int
    records: int
    bytes: int
    max_file_bytes: int
    counts: tuple[M5ArtifactValidationProjectionCount, ...]


@dataclass(frozen=True, slots=True)
class _DatasetObservation:
    issues: tuple[M5ArtifactValidationIssue, ...]
    registrations: int
    verified_files: int
    bytes: int
    max_file_bytes: int
    unregistered_files: int


@dataclass(frozen=True, slots=True)
class _ExpectedJsonlFile:
    file_kind: M5ProjectionFileKind
    documents: tuple[M5AuthorityDocumentObservation, ...]
    payload: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def entry(self) -> M5ProjectionGenerationEntry:
        return M5ProjectionGenerationEntry(
            file_kind=self.file_kind,
            relative_path=m5_projection_relative_path(self.file_kind),
            sha256=self.sha256,
            size_bytes=len(self.payload),
            record_count=len(self.documents),
            authority_kinds=m5_projection_authority_kinds(self.file_kind),
            records=tuple(
                M5ProjectionRecordReceipt(
                    authority_kind=item.kind,
                    artifact_id=item.artifact_id,
                    sha256=item.document_sha256,
                )
                for item in self.documents
            ),
        )


class M5ArtifactValidator:
    """Validate one already-open SQLite snapshot and never rebuild either side."""

    def __init__(
        self,
        *,
        artifact_reader: M5ProjectionArtifactReader | None = None,
        dataset_reader: M5DatasetArtifactReader | None = None,
        budget: M5ArtifactValidationBudget | None = None,
    ) -> None:
        self._reader = artifact_reader
        self._dataset_reader = dataset_reader
        self._budget = budget or M5ArtifactValidationBudget()

    def validate(
        self,
        run_id: str,
        authority: M5AuthoritySnapshotObservation,
        predecessor_report: M3ArtifactValidationReport | M4ArtifactValidationReport | None = None,
    ) -> M5ArtifactValidationReport:
        controlled = require_reference_token(run_id, "M5 validation run reference")
        if authority.run_id != controlled:
            raise ValueError("M5 validation authority belongs to another run")
        authority_issues = tuple(
            M5ArtifactValidationIssue(
                code=_authority_issue_code(failure),
                area=M5ArtifactValidationArea.AUTHORITY,
                authority_kind=failure.authority_kind,
                record_identity_sha256=failure.record_identity_sha256,
                reason_code=failure.reason_code,
            )
            for failure in authority.failures
        )
        budget_issues = self._authority_budget_issues(authority)
        retention_issues = self._retention_issues(authority)
        datasets = self._validate_datasets(controlled, authority)
        projection = self._validate_projection(controlled, authority)
        inventories = tuple(
            M5ArtifactValidationInventoryCount(
                authority_kind=item.authority_kind,
                authoritative_count=item.count,
            )
            for item in authority.traversed
        )
        authority_rows = sum(item.count for item in authority.traversed)
        max_record_bytes = authority.max_authority_record_bytes
        issues = tuple(
            sorted(
                (
                    *authority_issues,
                    *budget_issues,
                    *retention_issues,
                    *datasets.issues,
                    *projection.issues,
                ),
                key=lambda item: item.sort_key,
            )
        )
        return M5ArtifactValidationReport(
            run_id=controlled,
            manifest_id=authority.manifest_id,
            config_sha256=authority.config_sha256,
            predecessor_report=predecessor_report,
            authority_root_sha256=(
                authority.authority_root_sha256 if not authority_issues else None
            ),
            counts=M5ArtifactValidationCounts(
                authority_rows=authority_rows,
                authority_bytes=authority.authority_bytes,
                validated_authority_documents=len(authority.documents),
                authority_failures=len(authority.failures),
                case_roots=len(authority.case_roots),
                max_authority_record_bytes=max_record_bytes,
                projection_files=projection.files,
                projection_records=projection.records,
                projection_bytes=projection.bytes,
                max_projection_file_bytes=projection.max_file_bytes,
                dataset_registrations=datasets.registrations,
                verified_dataset_files=datasets.verified_files,
                dataset_bytes=datasets.bytes,
                max_dataset_file_bytes=datasets.max_file_bytes,
                unregistered_dataset_files=datasets.unregistered_files,
                dataset_retention_holds=authority.dataset_retention_hold_count,
                orphan_retention_holds=authority.orphan_retention_hold_count,
                retention_rows=authority.retention_rows,
                retention_bytes=authority.retention_bytes,
                max_retention_record_bytes=authority.max_retention_record_bytes,
                inventories=inventories,
                projections=projection.counts,
            ),
            issues=issues,
        )

    def validate_preflight_failure(
        self,
        run_id: str,
        preflight: M5AuthorityPreflightObservation,
        issue_codes: Sequence[M5ArtifactValidationIssueCode],
        predecessor_report: M3ArtifactValidationReport | M4ArtifactValidationReport | None = None,
    ) -> M5ArtifactValidationReport:
        """Report SQL budget failure without reading any authority document."""

        controlled = require_reference_token(run_id, "M5 validation run reference")
        if preflight.run_id != controlled:
            raise ValueError("M5 preflight belongs to another run")
        issues = tuple(
            sorted(
                (
                    _budget_issue(code, *self._budget_observation(code, preflight))
                    for code in set(issue_codes)
                ),
                key=lambda item: item.sort_key,
            )
        )
        inventories = tuple(
            M5ArtifactValidationInventoryCount(
                authority_kind=item.authority_kind,
                authoritative_count=item.count,
            )
            for item in preflight.traversed
        )
        return M5ArtifactValidationReport(
            run_id=controlled,
            manifest_id=preflight.manifest_id,
            config_sha256=preflight.config_sha256,
            predecessor_report=predecessor_report,
            counts=M5ArtifactValidationCounts(
                authority_rows=preflight.authority_rows,
                authority_bytes=preflight.authority_bytes,
                max_authority_record_bytes=preflight.max_authority_record_bytes,
                retention_rows=preflight.retention_rows,
                retention_bytes=preflight.retention_bytes,
                max_retention_record_bytes=preflight.max_retention_record_bytes,
                inventories=inventories,
            ),
            issues=issues,
        )

    def _authority_budget_issues(
        self,
        authority: M5AuthoritySnapshotObservation,
    ) -> tuple[M5ArtifactValidationIssue, ...]:
        issues: list[M5ArtifactValidationIssue] = []
        count = sum(item.count for item in authority.traversed)
        maximum = authority.max_authority_record_bytes
        if count > self._budget.max_authority_records:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED,
                    self._budget.max_authority_records,
                    count,
                )
            )
        if maximum > self._budget.max_authority_record_bytes:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.AUTHORITY_RECORD_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_authority_record_bytes,
                    maximum,
                )
            )
        if authority.authority_bytes > self._budget.max_authority_total_bytes:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.AUTHORITY_TOTAL_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_authority_total_bytes,
                    authority.authority_bytes,
                )
            )
        if authority.retention_rows > self._budget.max_retention_records:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.RETENTION_RECORD_COUNT_BUDGET_EXCEEDED,
                    self._budget.max_retention_records,
                    authority.retention_rows,
                )
            )
        if authority.max_retention_record_bytes > self._budget.max_retention_record_bytes:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.RETENTION_RECORD_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_retention_record_bytes,
                    authority.max_retention_record_bytes,
                )
            )
        if authority.retention_bytes > self._budget.max_retention_total_bytes:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.RETENTION_TOTAL_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_retention_total_bytes,
                    authority.retention_bytes,
                )
            )
        return tuple(issues)

    def _budget_observation(
        self,
        code: M5ArtifactValidationIssueCode,
        preflight: M5AuthorityPreflightObservation,
    ) -> tuple[int, int]:
        if code == M5ArtifactValidationIssueCode.AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED:
            return self._budget.max_authority_records, preflight.authority_rows
        if code == M5ArtifactValidationIssueCode.AUTHORITY_RECORD_BYTES_BUDGET_EXCEEDED:
            return (
                self._budget.max_authority_record_bytes,
                preflight.max_authority_record_bytes,
            )
        if code == M5ArtifactValidationIssueCode.AUTHORITY_TOTAL_BYTES_BUDGET_EXCEEDED:
            return self._budget.max_authority_total_bytes, preflight.authority_bytes
        if code == M5ArtifactValidationIssueCode.RETENTION_RECORD_COUNT_BUDGET_EXCEEDED:
            return self._budget.max_retention_records, preflight.retention_rows
        if code == M5ArtifactValidationIssueCode.RETENTION_RECORD_BYTES_BUDGET_EXCEEDED:
            return (
                self._budget.max_retention_record_bytes,
                preflight.max_retention_record_bytes,
            )
        if code == M5ArtifactValidationIssueCode.RETENTION_TOTAL_BYTES_BUDGET_EXCEEDED:
            return self._budget.max_retention_total_bytes, preflight.retention_bytes
        raise ValueError("unsupported M5 authority preflight issue code")

    @staticmethod
    def _retention_issues(
        authority: M5AuthoritySnapshotObservation,
    ) -> tuple[M5ArtifactValidationIssue, ...]:
        codes = {
            "HOLD_MISSING": M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_MISSING,
            "HOLD_EXTRA": M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_EXTRA,
            "HOLD_RELEASED": M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_RELEASED,
            "HOLD_OWNER_MISMATCH": (
                M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_OWNER_MISMATCH
            ),
            "HOLD_DOCUMENT_MISMATCH": (
                M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_DOCUMENT_MISMATCH
            ),
            "AUDIT_LINK_INVALID": (
                M5ArtifactValidationIssueCode.DATASET_RETENTION_AUDIT_LINK_INVALID
            ),
            "ORPHAN_APPEAL_HOLD": (M5ArtifactValidationIssueCode.ORPHAN_APPEAL_RETENTION_HOLD),
            "ORPHAN_DATASET_HOLD": (M5ArtifactValidationIssueCode.ORPHAN_DATASET_RETENTION_HOLD),
        }
        return tuple(
            M5ArtifactValidationIssue(
                code=codes[str(failure.failure_type)],
                area=M5ArtifactValidationArea.RETENTION,
                dataset_id=failure.dataset_id,
                hold_identity_sha256=failure.hold_identity_sha256,
                reason_code=failure.reason_code,
            )
            for failure in authority.dataset_retention_failures
        )

    def _validate_datasets(
        self,
        run_id: str,
        authority: M5AuthoritySnapshotObservation,
    ) -> _DatasetObservation:
        reports = tuple(authority.dataset_reports)
        reader = self._dataset_reader
        if reader is None:
            if reports:
                raise ValueError("M5 dataset reader is required for registered datasets")
            return _DatasetObservation((), 0, 0, 0, 0, 0)

        issues: list[M5ArtifactValidationIssue] = []
        registrations = len(reports)
        claimed_total = sum(item.content_size_bytes for item in reports)
        claimed_maximum = max((item.content_size_bytes for item in reports), default=0)
        blocked = False
        if registrations > self._budget.max_dataset_files:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.DATASET_FILE_COUNT_BUDGET_EXCEEDED,
                    self._budget.max_dataset_files,
                    registrations,
                )
            )
            blocked = True
        if claimed_maximum > self._budget.max_dataset_file_bytes:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.DATASET_FILE_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_dataset_file_bytes,
                    claimed_maximum,
                )
            )
            blocked = True
        histories = {item.dataset_id: item for item in authority.dataset_histories}
        verified_files = 0
        total_bytes = 0
        maximum_bytes = 0
        canonical_paths: set[str] = set()
        canonical_reports: list[DatasetExportReport] = []
        for report in reports:
            if not _is_canonical_dataset_path(run_id, report.dataset.relative_path):
                issues.append(
                    _dataset_issue(
                        report,
                        M5ArtifactValidationIssueCode.DATASET_PATH_UNSAFE,
                        "NONCANONICAL_DATASET_PATH",
                    )
                )
                continue
            canonical_paths.add(report.dataset.relative_path)
            canonical_reports.append(report)
        inventory = _dataset_directory_inventory(
            reader=reader,
            run_id=run_id,
            canonical_paths=canonical_paths,
            max_items=self._budget.max_dataset_files,
        )
        issues.extend(inventory.issues)
        if any(item.area == M5ArtifactValidationArea.BUDGET for item in inventory.issues):
            blocked = True
        observed_total = max(claimed_total, inventory.physical_bytes)
        if observed_total > self._budget.max_dataset_total_bytes:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.DATASET_TOTAL_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_dataset_total_bytes,
                    observed_total,
                )
            )
            blocked = True
        if not blocked:
            for report in canonical_reports:
                history = histories.get(report.dataset.dataset_id)
                if history is None:
                    continue
                physical = _read_dataset_file(reader, report)
                issues.extend(physical.issues)
                if physical.content is None:
                    continue
                verified_files += 1
                total_bytes += len(physical.content)
                maximum_bytes = max(maximum_bytes, len(physical.content))
                try:
                    crop_authorities = _verify_dataset_crop_authorities(
                        crop_authorities=tuple(history.crop_authorities),
                        reader=reader,
                    )
                    rebuild_and_verify_m5_dataset(
                        report=report,
                        content=physical.content,
                        labels=tuple(history.labels),
                        crop_authorities=crop_authorities,
                    )
                except _DatasetCropAuthorityFailure as error:
                    issues.append(
                        _dataset_issue(
                            report,
                            M5ArtifactValidationIssueCode.DATASET_CROP_AUTHORITY_INVALID,
                            error.reason_code,
                        )
                    )
                except M5DatasetIntegrityError as error:
                    code = (
                        M5ArtifactValidationIssueCode.DATASET_CONTENT_REBUILD_MISMATCH
                        if error.reason_code
                        == M5DatasetIntegrityFailureCode.CONTENT_REBUILD_MISMATCH
                        else M5ArtifactValidationIssueCode.DATASET_REPORT_REBUILD_MISMATCH
                    )
                    issues.append(_dataset_issue(report, code, error.reason_code.value))
                except DatasetExportError as error:
                    issues.append(
                        _dataset_issue(
                            report,
                            M5ArtifactValidationIssueCode.DATASET_REPORT_REBUILD_MISMATCH,
                            error.reason_code.value,
                        )
                    )
                except (TypeError, ValueError, ValidationError):
                    issues.append(
                        _dataset_issue(
                            report,
                            M5ArtifactValidationIssueCode.DATASET_REPORT_REBUILD_MISMATCH,
                            "DURABLE_REBUILD_INVALID",
                        )
                    )

        return _DatasetObservation(
            issues=tuple(sorted(set(issues), key=lambda item: item.sort_key)),
            registrations=registrations,
            verified_files=verified_files,
            bytes=total_bytes,
            max_file_bytes=maximum_bytes,
            unregistered_files=inventory.unregistered_files,
        )

    def _validate_projection(
        self,
        run_id: str,
        authority: M5AuthoritySnapshotObservation,
    ) -> _ProjectionObservation:
        if self._reader is None:
            raise ValueError("M5 projection reader is required for full validation")
        pointer_path = f"{run_id}/m5-projections/current.json"
        try:
            pointer_snapshot = self._reader.read_verified(pointer_path, max_bytes=8 * 1024)
        except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation) as error:
            return _missing_projection(pointer_path, error)
        try:
            pointer = M5ProjectionCurrentPointer.model_validate_json(pointer_snapshot.bytes)
        except ValidationError:
            return _invalid_projection(pointer_path, "CURRENT_POINTER_INVALID")
        if canonical_bytes(pointer.model_dump(mode="json")) != pointer_snapshot.bytes:
            return _invalid_projection(pointer_path, "CURRENT_POINTER_NON_CANONICAL")
        if (
            pointer.run_id != run_id
            or pointer.authority_root_sha256 != authority.authority_root_sha256
        ):
            return _root_mismatch(pointer_path)
        try:
            manifest_snapshot = self._reader.read_verified(
                pointer.manifest_relative_path,
                pointer.manifest_sha256,
                max_bytes=pointer.manifest_size_bytes,
            )
        except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation) as error:
            return _missing_projection(pointer.manifest_relative_path, error)
        try:
            manifest = M5ProjectionGenerationManifest.model_validate_json(manifest_snapshot.bytes)
        except ValidationError:
            return _invalid_projection(pointer.manifest_relative_path, "MANIFEST_INVALID")
        if (
            canonical_bytes(manifest.model_dump(mode="json")) != manifest_snapshot.bytes
            or manifest.generation_id != pointer.generation_id
            or manifest.authority_root_sha256 != authority.authority_root_sha256
            or manifest.authority_record_count != len(authority.documents)
            or manifest.case_root_count != len(authority.case_roots)
        ):
            return _root_mismatch(pointer.manifest_relative_path)

        expected_files = _expected_jsonl_files(authority.documents)
        expected_by_kind = {item.file_kind: item for item in expected_files}
        generation = pointer.manifest_relative_path.rsplit("/", maxsplit=1)[0]
        issues: list[M5ArtifactValidationIssue] = []
        total = pointer_snapshot.size_bytes + manifest_snapshot.size_bytes
        maximum = max(pointer_snapshot.size_bytes, manifest_snapshot.size_bytes)
        counts: list[M5ArtifactValidationProjectionCount] = []
        for entry in manifest.entries:
            expected = expected_by_kind[entry.file_kind]
            path = f"{generation}/{entry.relative_path}"
            if entry != expected.entry():
                issues.append(_projection_issue(path, "MANIFEST_ENTRY_MISMATCH"))
                continue
            try:
                snapshot = self._reader.read_verified(
                    path,
                    entry.sha256,
                    max_bytes=entry.size_bytes,
                )
            except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation) as error:
                issues.extend(_missing_projection(path, error).issues)
                continue
            total += snapshot.size_bytes
            maximum = max(maximum, snapshot.size_bytes)
            counts.append(
                M5ArtifactValidationProjectionCount(
                    file_kind=entry.file_kind,
                    record_count=entry.record_count,
                )
            )
            if snapshot.bytes != expected.payload:
                issues.append(
                    M5ArtifactValidationIssue(
                        code=M5ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                        area=M5ArtifactValidationArea.PROJECTION,
                        file_kind=entry.file_kind,
                        source_token=_source_token(path),
                        reason_code="JSONL_CONTENT_MISMATCH",
                        expected_sha256=hashlib.sha256(expected.payload).hexdigest(),
                        actual_sha256=hashlib.sha256(snapshot.bytes).hexdigest(),
                    )
                )
        expected_names = {
            *(entry.relative_path for entry in manifest.entries),
            pointer.manifest_relative_path.rsplit("/", maxsplit=1)[-1],
        }
        try:
            hints = self._reader.list_projection_directory(
                generation,
                max_items=len(expected_names) + 1,
                max_name_bytes=512,
            )
            names = {item.name for item in hints if item.name is not None}
            if any(item.name is None for item in hints) or names != expected_names:
                issues.append(_projection_issue(generation, "GENERATION_INVENTORY_MISMATCH"))
        except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation):
            issues.append(_projection_issue(generation, "GENERATION_INVENTORY_UNSAFE"))
        if maximum > self._budget.max_projection_file_bytes:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.PROJECTION_FILE_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_projection_file_bytes,
                    maximum,
                )
            )
        if total > self._budget.max_projection_total_bytes:
            issues.append(
                _budget_issue(
                    M5ArtifactValidationIssueCode.PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_projection_total_bytes,
                    total,
                )
            )
        return _ProjectionObservation(
            issues=tuple(issues),
            files=len(counts) + 2,
            records=sum(item.record_count for item in counts),
            bytes=total,
            max_file_bytes=maximum,
            counts=tuple(sorted(counts, key=lambda item: item.sort_key)),
        )


@dataclass(frozen=True, slots=True)
class _DatasetReadObservation:
    content: bytes | None
    issues: tuple[M5ArtifactValidationIssue, ...]


@dataclass(frozen=True, slots=True)
class _DatasetInventoryObservation:
    issues: tuple[M5ArtifactValidationIssue, ...]
    unregistered_files: int
    physical_bytes: int


class _DatasetCropAuthorityFailure(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _is_canonical_dataset_path(run_id: str, relative_path: str) -> bool:
    parts = PurePosixPath(relative_path).parts
    return (
        len(parts) == 3
        and parts[:2] == (run_id, "datasets")
        and parts[2].endswith(".json")
        and parts[2] not in {".json", "..json"}
    )


def _read_dataset_file(
    reader: M5DatasetArtifactReader,
    report: DatasetExportReport,
) -> _DatasetReadObservation:
    path = report.dataset.relative_path
    try:
        snapshot = reader.read_verified(
            path,
            report.dataset.content_sha256,
            max_bytes=report.content_size_bytes,
        )
    except PathBoundaryViolation as error:
        reason = getattr(error, "reason_code", "DATASET_PATH_UNSAFE")
        if reason == "FILE_MISSING":
            code = M5ArtifactValidationIssueCode.DATASET_CONTENT_MISSING
        elif "TOO_LARGE" in reason or "SIZE" in reason:
            code = M5ArtifactValidationIssueCode.DATASET_CONTENT_SIZE_MISMATCH
        else:
            code = M5ArtifactValidationIssueCode.DATASET_PATH_UNSAFE
        return _DatasetReadObservation(None, (_dataset_issue(report, code, reason),))
    except ArtifactIntegrityViolation as error:
        return _DatasetReadObservation(
            None,
            (
                _dataset_issue(
                    report,
                    M5ArtifactValidationIssueCode.DATASET_CONTENT_HASH_MISMATCH,
                    getattr(error, "reason_code", "CONTENT_HASH_MISMATCH"),
                ),
            ),
        )
    except BudgetExceeded:
        return _DatasetReadObservation(
            None,
            (
                _dataset_issue(
                    report,
                    M5ArtifactValidationIssueCode.DATASET_CONTENT_SIZE_MISMATCH,
                    "CONTENT_SIZE_BUDGET_EXCEEDED",
                ),
            ),
        )
    if (
        snapshot.size_bytes != report.content_size_bytes
        or len(snapshot.bytes) != snapshot.size_bytes
    ):
        return _DatasetReadObservation(
            None,
            (
                _dataset_issue(
                    report,
                    M5ArtifactValidationIssueCode.DATASET_CONTENT_SIZE_MISMATCH,
                    "REGISTERED_CONTENT_SIZE_MISMATCH",
                ),
            ),
        )
    actual_sha256 = hashlib.sha256(snapshot.bytes).hexdigest()
    if (
        snapshot.sha256 != report.dataset.content_sha256
        or actual_sha256 != report.dataset.content_sha256
    ):
        return _DatasetReadObservation(
            None,
            (
                _dataset_issue(
                    report,
                    M5ArtifactValidationIssueCode.DATASET_CONTENT_HASH_MISMATCH,
                    "REGISTERED_CONTENT_HASH_MISMATCH",
                    expected_sha256=report.dataset.content_sha256,
                    actual_sha256=actual_sha256,
                ),
            ),
        )
    return _DatasetReadObservation(snapshot.bytes, ())


def _verify_dataset_crop_authorities(
    *,
    crop_authorities: tuple[TrainingCropAuthority, ...],
    reader: M5DatasetArtifactReader,
) -> tuple[TrainingCropAuthority, ...]:
    verified: list[TrainingCropAuthority] = []
    for authority in crop_authorities:
        crop = authority.crop
        try:
            verification = reader.verify_crop(crop)
        except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation):
            raise _DatasetCropAuthorityFailure("HISTORICAL_CROP_VERIFIER_FAILED") from None
        crop_ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
        if (
            not isinstance(verification, ArtifactVerification)
            or verification.artifact_ref != crop_ref
            or verification.status != VerificationStatus.CURRENT_MEDIA_VERIFIED
        ):
            reason = getattr(verification, "reason_code", None)
            raise _DatasetCropAuthorityFailure(reason or "HISTORICAL_CROP_BYTES_INVALID")
        try:
            current = TrainingCropAuthority(
                run_id=authority.run_id,
                case_id=authority.case_id,
                crop=crop,
                verification=verification,
                detector_manifest_id=authority.detector_manifest_id,
                manifest_id=authority.manifest_id,
                rule_version=authority.rule_version,
            )
        except (TypeError, ValueError, ValidationError):
            raise _DatasetCropAuthorityFailure("HISTORICAL_CROP_AUTHORITY_INVALID") from None
        if current != authority:
            raise _DatasetCropAuthorityFailure("HISTORICAL_CROP_AUTHORITY_CONFLICT")
        verified.append(current)
    return tuple(verified)


def _dataset_directory_inventory(
    *,
    reader: M5DatasetArtifactReader,
    run_id: str,
    canonical_paths: set[str],
    max_items: int,
) -> _DatasetInventoryObservation:
    directory = f"{run_id}/datasets"
    try:
        hints = reader.list_dataset_directory(
            run_id,
            max_items=max_items,
            max_name_bytes=512,
        )
    except BudgetExceeded:
        return _DatasetInventoryObservation(
            (
                _budget_issue(
                    M5ArtifactValidationIssueCode.DATASET_FILE_COUNT_BUDGET_EXCEEDED,
                    max_items,
                    max_items + 1,
                ),
            ),
            0,
            0,
        )
    except PathBoundaryViolation as error:
        reason = getattr(error, "reason_code", "DATASET_DIRECTORY_UNSAFE")
        if reason in {"DIRECTORY_MISSING", "FILE_MISSING"}:
            return _DatasetInventoryObservation((), 0, 0)
        return _DatasetInventoryObservation(
            (
                M5ArtifactValidationIssue(
                    code=M5ArtifactValidationIssueCode.DATASET_DIRECTORY_UNSAFE,
                    area=M5ArtifactValidationArea.DATASET,
                    source_token=_dataset_source_token(directory),
                    reason_code=reason,
                ),
            ),
            0,
            0,
        )

    issues: list[M5ArtifactValidationIssue] = []
    unregistered = 0
    physical_bytes = 0
    for hint in hints:
        if hint.name is None:
            issues.append(
                M5ArtifactValidationIssue(
                    code=M5ArtifactValidationIssueCode.DATASET_DIRECTORY_UNSAFE,
                    area=M5ArtifactValidationArea.DATASET,
                    source_token=hint.source_token,
                    reason_code=hint.reason_code or "UNSAFE_DATASET_DIRECTORY_ENTRY",
                )
            )
            continue
        path = f"{directory}/{hint.name}"
        try:
            metadata = reader.inspect_verified(path)
        except (ArtifactIntegrityViolation, PathBoundaryViolation) as error:
            issues.append(
                M5ArtifactValidationIssue(
                    code=M5ArtifactValidationIssueCode.DATASET_DIRECTORY_UNSAFE,
                    area=M5ArtifactValidationArea.DATASET,
                    source_token=hint.source_token,
                    reason_code=getattr(error, "reason_code", "UNSAFE_DATASET_DIRECTORY_ENTRY"),
                )
            )
        else:
            physical_bytes += metadata.size_bytes
        if path not in canonical_paths:
            unregistered += 1
            issues.append(
                M5ArtifactValidationIssue(
                    code=M5ArtifactValidationIssueCode.DATASET_UNREGISTERED_FILE,
                    area=M5ArtifactValidationArea.DATASET,
                    source_token=hint.source_token,
                    reason_code="UNREGISTERED_DATASET_FILE",
                )
            )
    return _DatasetInventoryObservation(tuple(issues), unregistered, physical_bytes)


def _dataset_issue(
    report: DatasetExportReport,
    code: M5ArtifactValidationIssueCode,
    reason_code: str,
    *,
    expected_sha256: str | None = None,
    actual_sha256: str | None = None,
) -> M5ArtifactValidationIssue:
    return M5ArtifactValidationIssue(
        code=code,
        area=M5ArtifactValidationArea.DATASET,
        dataset_id=report.dataset.dataset_id,
        source_token=_dataset_source_token(report.dataset.relative_path),
        reason_code=reason_code,
        expected_sha256=expected_sha256,
        actual_sha256=actual_sha256,
    )


def _dataset_source_token(path: str) -> str:
    return hashlib.sha256(canonical_bytes(["m5-dataset-source", 1, path])).hexdigest()


def _missing_projection(path: str, error: BaseException) -> _ProjectionObservation:
    reason = getattr(error, "reason_code", "FILE_MISSING")
    code = (
        M5ArtifactValidationIssueCode.PROJECTION_MISSING
        if reason == "FILE_MISSING"
        else M5ArtifactValidationIssueCode.PROJECTION_UNSAFE
    )
    return _ProjectionObservation(
        issues=(
            M5ArtifactValidationIssue(
                code=code,
                area=M5ArtifactValidationArea.PROJECTION,
                source_token=_source_token(path),
                reason_code=reason,
            ),
        ),
        files=0,
        records=0,
        bytes=0,
        max_file_bytes=0,
        counts=(),
    )


def _invalid_projection(path: str, reason: str) -> _ProjectionObservation:
    return _ProjectionObservation(
        issues=(_projection_issue(path, reason),),
        files=0,
        records=0,
        bytes=0,
        max_file_bytes=0,
        counts=(),
    )


def _root_mismatch(path: str) -> _ProjectionObservation:
    issue = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.PROJECTION_ROOT_MISMATCH,
        area=M5ArtifactValidationArea.PROJECTION,
        source_token=_source_token(path),
        reason_code="AUTHORITY_ROOT_MISMATCH",
    )
    return _ProjectionObservation((issue,), 0, 0, 0, 0, ())


def _projection_issue(path: str, reason: str) -> M5ArtifactValidationIssue:
    return M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.PROJECTION_INVENTORY_MISMATCH,
        area=M5ArtifactValidationArea.PROJECTION,
        source_token=_source_token(path),
        reason_code=reason,
    )


def _budget_issue(
    code: M5ArtifactValidationIssueCode,
    limit: int,
    observed: int,
) -> M5ArtifactValidationIssue:
    return M5ArtifactValidationIssue(
        code=code,
        area=M5ArtifactValidationArea.BUDGET,
        reason_code="BUDGET_EXCEEDED",
        limit=limit,
        observed=observed,
    )


def _source_token(path: str) -> str:
    return hashlib.sha256(canonical_bytes(["m5-projection-source", 1, path])).hexdigest()


def _expected_jsonl_files(
    documents: Sequence[M5AuthorityDocumentObservation],
) -> tuple[_ExpectedJsonlFile, ...]:
    result: list[_ExpectedJsonlFile] = []
    for file_kind in sorted(M5ProjectionFileKind, key=m5_projection_relative_path):
        kinds = m5_projection_authority_kinds(file_kind)
        selected = tuple(item for item in documents if item.kind in kinds)
        lines = (
            canonical_bytes(
                {
                    "authority_kind": item.kind.value,
                    "artifact_id": item.artifact_id,
                    "document_sha256": item.document_sha256,
                    "document": json.loads(item.canonical_document),
                }
            )
            for item in selected
        )
        result.append(
            _ExpectedJsonlFile(
                file_kind,
                selected,
                b"".join(line + b"\n" for line in lines),
            )
        )
    return tuple(result)


__all__ = [
    "M5ArtifactValidator",
    "M5AuthorityPreflightObservation",
    "M5AuthoritySnapshotObservation",
    "M5DatasetHistoricalAuthorityObservation",
    "M5ProjectionArtifactReader",
    "M5ProjectionArtifactSnapshot",
    "M5ProjectionDirectoryHint",
]
