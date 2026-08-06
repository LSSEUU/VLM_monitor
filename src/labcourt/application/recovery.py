"""Bounded startup recovery for staged files and unreferenced final media."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol

from labcourt.contracts.enums import (
    RecoveryArea,
    RecoveryDisposition,
    RecoveryReasonCode,
)
from labcourt.contracts.recovery import (
    RecoveryItemResult,
    RecoveryReport,
    StartupRecoveryReport,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import PurgeItemResult
from labcourt.exceptions import BudgetExceeded, ContractViolation
from labcourt.ports.recovery import (
    MAX_RECOVERY_DEPTH,
    MAX_RECOVERY_ITEMS,
    MAX_RECOVERY_NAME_BYTES,
    OrphanRecoveryFileOps,
    OrphanReferenceRepository,
    RecoveryCandidate,
    RecoveryScan,
    StagingCleanupCandidate,
)


class _RetentionRecovery(Protocol):
    def recover(self, run_id: str) -> tuple[PurgeItemResult, ...]: ...


class _OrphanRecovery(Protocol):
    def recover(
        self,
        run_id: str,
        now: datetime,
        minimum_age: timedelta,
    ) -> RecoveryReport: ...


class OrphanRecoveryCoordinator:
    """Recover only the two fixed M2 locations after a complete bounded scan."""

    __slots__ = (
        "_file_ops",
        "_max_depth",
        "_max_items",
        "_max_name_bytes",
        "_repository",
    )

    def __init__(
        self,
        repository: OrphanReferenceRepository,
        file_ops: OrphanRecoveryFileOps,
        *,
        max_items: int = MAX_RECOVERY_ITEMS,
        max_depth: int = MAX_RECOVERY_DEPTH,
        max_name_bytes: int = MAX_RECOVERY_NAME_BYTES,
    ) -> None:
        self._repository = repository
        self._file_ops = file_ops
        self._max_items = self._bounded_positive(max_items, MAX_RECOVERY_ITEMS, "max_items")
        self._max_depth = self._bounded_positive(max_depth, MAX_RECOVERY_DEPTH, "max_depth")
        self._max_name_bytes = self._bounded_positive(
            max_name_bytes,
            MAX_RECOVERY_NAME_BYTES,
            "max_name_bytes",
        )

    def recover(
        self,
        run_id: str,
        now: datetime,
        minimum_age: timedelta,
    ) -> RecoveryReport:
        controlled_run_id = require_reference_token(run_id, "recovery run_id")
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("recovery now must be a timezone-aware datetime")
        if not isinstance(minimum_age, timedelta) or minimum_age <= timedelta(0):
            raise ValueError("recovery minimum_age must be a positive timedelta")
        not_modified_after = now - minimum_age

        scan = self._file_ops.discover(
            controlled_run_id,
            self._max_items,
            self._max_depth,
            self._max_name_bytes,
        )
        self._require_scan(scan, controlled_run_id)

        results = list(scan.anomalies)
        for cleanup_candidate in scan.staging_cleanup_candidates:
            result = self._file_ops.cleanup_empty_staging(
                cleanup_candidate,
                not_modified_after,
            )
            self._require_cleanup_result(result, cleanup_candidate)
            results.append(result)
        for candidate in scan.candidates:
            if candidate.area == RecoveryArea.FINAL_MEDIA:
                referenced = self._repository.media_is_referenced(
                    controlled_run_id,
                    candidate.content_sha256,
                )
                if type(referenced) is not bool:
                    raise ContractViolation("recovery reference query must return a boolean")
                if referenced:
                    results.append(
                        RecoveryItemResult(
                            run_id=controlled_run_id,
                            area=candidate.area,
                            source_token=candidate.source_token,
                            disposition=RecoveryDisposition.RETAINED,
                            reason_code=RecoveryReasonCode.REFERENCED_MEDIA,
                            content_sha256=candidate.content_sha256,
                        )
                    )
                    continue

            result = self._file_ops.quarantine(candidate, not_modified_after)
            self._require_quarantine_result(result, candidate)
            results.append(result)

        stable_results = tuple(sorted(results, key=lambda item: item.sort_key))
        return RecoveryReport(
            run_id=controlled_run_id,
            not_modified_after=not_modified_after,
            items=stable_results,
        )

    def _require_scan(self, scan: RecoveryScan, run_id: str) -> None:
        if not isinstance(scan, RecoveryScan) or scan.run_id != run_id:
            raise ContractViolation("recovery file scan is outside the requested run")
        staging_count = (
            len(scan.staging_cleanup_candidates)
            + sum(candidate.area == RecoveryArea.STAGING for candidate in scan.candidates)
            + sum(item.area == RecoveryArea.STAGING for item in scan.anomalies)
        )
        final_count = sum(
            candidate.area == RecoveryArea.FINAL_MEDIA for candidate in scan.candidates
        ) + sum(item.area == RecoveryArea.FINAL_MEDIA for item in scan.anomalies)
        if staging_count > self._max_items or final_count > self._max_items:
            raise BudgetExceeded("recovery file scan exceeded a controlled-area item budget")

    @staticmethod
    def _require_cleanup_result(
        result: RecoveryItemResult,
        candidate: StagingCleanupCandidate,
    ) -> None:
        if not isinstance(result, RecoveryItemResult):
            raise ContractViolation("staging cleanup returned an invalid result")
        if (
            result.run_id != candidate.run_id
            or result.area != RecoveryArea.STAGING
            or result.source_token != candidate.source_token
            or result.content_sha256 is not None
            or result.quarantine_relative_path is not None
        ):
            raise ContractViolation("staging cleanup result conflicts with its candidate")
        allowed = (
            (
                result.disposition == RecoveryDisposition.CLEANED
                and result.reason_code == RecoveryReasonCode.EMPTY_STAGING_CLEANED
            )
            or (
                result.disposition == RecoveryDisposition.RETAINED
                and result.reason_code == RecoveryReasonCode.MINIMUM_AGE_NOT_MET
            )
            or (
                result.disposition == RecoveryDisposition.ANOMALY
                and result.reason_code
                in {
                    RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY,
                    RecoveryReasonCode.ENTRY_CHANGED_DURING_RECOVERY,
                }
            )
        )
        if not allowed:
            raise ContractViolation("staging cleanup returned an unauthorized disposition")

    @staticmethod
    def _require_quarantine_result(
        result: RecoveryItemResult,
        candidate: RecoveryCandidate,
    ) -> None:
        if not isinstance(result, RecoveryItemResult):
            raise ContractViolation("recovery file operation returned an invalid result")
        if (
            result.run_id != candidate.run_id
            or result.area != candidate.area
            or result.source_token != candidate.source_token
            or result.content_sha256 != candidate.content_sha256
        ):
            raise ContractViolation("recovery file result conflicts with its candidate")
        allowed = (
            result.disposition == RecoveryDisposition.QUARANTINED
            or (
                result.disposition == RecoveryDisposition.RETAINED
                and result.reason_code == RecoveryReasonCode.MINIMUM_AGE_NOT_MET
            )
            or (
                result.disposition == RecoveryDisposition.ANOMALY
                and result.reason_code
                in {
                    RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY,
                    RecoveryReasonCode.CONTENT_IDENTITY_MISMATCH,
                    RecoveryReasonCode.ENTRY_CHANGED_DURING_RECOVERY,
                }
            )
        )
        if not allowed:
            raise ContractViolation("recovery file result has an unauthorized disposition")

    @staticmethod
    def _bounded_positive(value: int, upper_bound: int, name: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= upper_bound:
            raise ValueError(f"{name} must be an integer from 1 through {upper_bound}")
        return value


class StartupRecoveryCoordinator:
    """Run durable retention recovery before bounded orphan quarantine."""

    __slots__ = ("_orphan", "_retention")

    def __init__(
        self,
        *,
        retention: _RetentionRecovery,
        orphan: _OrphanRecovery,
    ) -> None:
        self._retention = retention
        self._orphan = orphan

    def recover(
        self,
        run_id: str,
        started_at: datetime,
        minimum_age: timedelta,
    ) -> StartupRecoveryReport:
        controlled_run_id = require_reference_token(run_id, "startup recovery run_id")
        if (
            not isinstance(started_at, datetime)
            or started_at.tzinfo is None
            or started_at.utcoffset() is None
        ):
            raise ValueError("startup recovery time must be a timezone-aware datetime")
        if not isinstance(minimum_age, timedelta) or minimum_age <= timedelta(0):
            raise ValueError("startup recovery minimum_age must be a positive timedelta")

        retention_items = self._retention.recover(controlled_run_id)
        stable_retention_items = self._validated_retention_items(
            retention_items,
            controlled_run_id,
        )

        orphan_report = self._orphan.recover(
            controlled_run_id,
            started_at,
            minimum_age,
        )
        self._require_orphan_report(
            orphan_report,
            controlled_run_id,
            expected_cutoff=started_at - minimum_age,
        )
        return StartupRecoveryReport(
            run_id=controlled_run_id,
            started_at=started_at,
            retention_items=stable_retention_items,
            orphan_report=orphan_report,
        )

    @staticmethod
    def _validated_retention_items(
        items: object,
        run_id: str,
    ) -> tuple[PurgeItemResult, ...]:
        if not isinstance(items, tuple) or any(
            not isinstance(item, PurgeItemResult) for item in items
        ):
            raise ContractViolation("retention recovery returned invalid results")
        typed_items = items
        if any(item.run_id != run_id for item in typed_items):
            raise ContractViolation("retention recovery returned results outside the run")
        identities = tuple(item.media_ref.sort_key for item in typed_items)
        if len(identities) != len(set(identities)):
            raise ContractViolation("retention recovery returned duplicate media results")
        return tuple(sorted(typed_items, key=lambda item: item.media_ref.sort_key))

    @staticmethod
    def _require_orphan_report(
        report: object,
        run_id: str,
        *,
        expected_cutoff: datetime,
    ) -> None:
        if not isinstance(report, RecoveryReport):
            raise ContractViolation("orphan recovery returned an invalid report")
        if report.run_id != run_id:
            raise ContractViolation("orphan recovery returned a report outside the run")
        if report.not_modified_after != expected_cutoff:
            raise ContractViolation("orphan recovery returned a report for the wrong cutoff")


__all__ = [
    "MAX_RECOVERY_DEPTH",
    "MAX_RECOVERY_ITEMS",
    "MAX_RECOVERY_NAME_BYTES",
    "OrphanRecoveryCoordinator",
    "StartupRecoveryCoordinator",
]
