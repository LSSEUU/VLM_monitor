"""Bounded crash-recoverable orchestration for media retention."""

from __future__ import annotations

import re
from datetime import datetime

from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    PurgeDisposition,
    PurgeReasonCode,
    PurgeRecoveryKind,
)
from labcourt.contracts.frames import SHA256_PATTERN
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef, PurgeItemResult
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    ConcurrentModification,
    ContractViolation,
    PathBoundaryViolation,
    ProviderUnavailable,
)
from labcourt.ports.retention import (
    PurgeLease,
    PurgeRecoveryCandidate,
    RetentionFileOps,
    RetentionRepository,
)

MAX_RETENTION_ITEMS = 10_000
_SHA256 = re.compile(SHA256_PATTERN)
_MISSING_PATH_REASONS = frozenset(
    {
        "FILE_MISSING",
        "PARENT_MISSING",
        "SOURCE_OR_PARENT_MISSING",
    }
)


class RetentionCoordinator:
    """Coordinate repository intent, verified file deletion, and crash recovery."""

    __slots__ = ("_file_ops", "_max_items", "_repository")

    def __init__(
        self,
        *,
        repository: RetentionRepository,
        file_ops: RetentionFileOps,
        max_items: int = 100,
    ) -> None:
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or not 1 <= max_items <= MAX_RETENTION_ITEMS
        ):
            raise ValueError(f"max_items must be an integer within [1, {MAX_RETENTION_ITEMS}]")
        self._repository = repository
        self._file_ops = file_ops
        self._max_items = max_items

    def purge_expired(
        self,
        run_id: str,
        *,
        expires_before: datetime,
        policy_version: str,
    ) -> tuple[PurgeItemResult, ...]:
        """Attempt at most ``max_items`` new retention decisions in stable order."""

        run_id = require_reference_token(run_id, "retention run_id")
        self._require_aware_datetime(expires_before)
        policy_version = require_reference_token(policy_version, "retention policy_version")
        media_ids = self._bounded_media_ids(
            self._repository.list_expirable_media(
                run_id,
                expires_before,
                self._max_items,
            ),
            limit=self._max_items,
        )

        results: list[PurgeItemResult] = []
        for media_sha256 in media_ids:
            decision = self._repository.begin_media_purge(
                run_id,
                media_sha256,
                expires_before,
                policy_version,
            )
            if isinstance(decision, PurgeItemResult):
                self._require_begin_result(decision, run_id, media_sha256)
                results.append(decision)
                continue
            if not isinstance(decision, PurgeLease):
                raise ContractViolation("retention repository returned an invalid purge decision")
            self._require_lease_scope(decision, run_id, media_sha256)
            results.append(self._process_lease(decision, recovered=False))
        return tuple(results)

    def recover(self, run_id: str) -> tuple[PurgeItemResult, ...]:
        """Process a bounded, durable round-robin of incomplete recovery work."""

        run_id = require_reference_token(run_id, "retention run_id")
        seen: set[tuple[str, int]] = set()
        results: list[PurgeItemResult] = []
        for _ in range(self._max_items):
            candidate = self._repository.claim_next_recovery(run_id)
            if candidate is None:
                break
            if not isinstance(candidate, PurgeRecoveryCandidate):
                raise ContractViolation(
                    "retention repository returned an invalid recovery candidate"
                )
            lease = candidate.lease
            self._require_lease_scope(lease, run_id, lease.media_sha256)
            identity = (lease.media_sha256, lease.intent_audit_sequence)
            if identity in seen:
                break
            seen.add(identity)
            if candidate.kind == PurgeRecoveryKind.INCOMPLETE_PURGE:
                results.append(self._process_lease(lease, recovered=True))
            else:
                results.append(self._recover_cleanup(candidate))
        return tuple(results)

    def _process_lease(
        self,
        lease: PurgeLease,
        *,
        recovered: bool,
    ) -> PurgeItemResult:
        try:
            self._file_ops.stage_for_purge(lease)
        except ArtifactIntegrityViolation:
            return self._recovery_required(
                lease,
                PurgeReasonCode.MEDIA_INTEGRITY_FAILURE,
            )
        except ArtifactConflict:
            return self._recovery_required(
                lease,
                PurgeReasonCode.MEDIA_INTEGRITY_FAILURE,
            )
        except PathBoundaryViolation as error:
            reason = (
                PurgeReasonCode.MEDIA_FILE_MISSING
                if error.reason_code in _MISSING_PATH_REASONS
                else PurgeReasonCode.WORKSPACE_OPERATION_FAILED
            )
            return self._recovery_required(lease, reason)
        except ProviderUnavailable:
            return self._recovery_required(
                lease,
                PurgeReasonCode.WORKSPACE_OPERATION_FAILED,
            )

        result = self._repository.complete_media_purge(
            lease.run_id,
            lease.media_sha256,
            lease.intent_audit_sequence,
            recovered,
        )
        self._require_completed_result(result, lease, recovered=recovered)
        cleanup_failure = self._destroy_and_ack(
            lease,
            completion_audit_sequence=result.audit_sequences[1],
        )
        if cleanup_failure is not None:
            return cleanup_failure
        return result

    def _recover_cleanup(self, candidate: PurgeRecoveryCandidate) -> PurgeItemResult:
        completion_audit_sequence = candidate.completion_audit_sequence
        if completion_audit_sequence is None:
            raise ContractViolation("trash cleanup candidate lacks its completion audit")
        failure = self._destroy_and_ack(
            candidate.lease,
            completion_audit_sequence=completion_audit_sequence,
        )
        if failure is not None:
            return failure
        return self._already_purged(candidate.lease, completion_audit_sequence)

    def _destroy_and_ack(
        self,
        lease: PurgeLease,
        *,
        completion_audit_sequence: int,
    ) -> PurgeItemResult | None:
        try:
            self._file_ops.destroy_purged(lease)
            self._repository.mark_trash_cleaned(
                lease.run_id,
                lease.media_sha256,
                lease.intent_audit_sequence,
            )
        except (
            ArtifactConflict,
            ArtifactIntegrityViolation,
            ConcurrentModification,
            PathBoundaryViolation,
            ProviderUnavailable,
        ):
            return self._cleanup_failed(
                lease,
                completion_audit_sequence,
            )
        return None

    @staticmethod
    def _already_purged(
        lease: PurgeLease,
        completion_audit_sequence: int,
    ) -> PurgeItemResult:
        return PurgeItemResult(
            run_id=lease.run_id,
            media_ref=ArtifactRef(
                kind=ArtifactKind.MEDIA,
                artifact_id=lease.media_sha256,
            ),
            crop_refs=lease.crop_refs,
            disposition=PurgeDisposition.RETAINED,
            reason_code=PurgeReasonCode.ALREADY_PURGED,
            previous_availability=MediaAvailability.PURGED_BY_RETENTION,
            current_availability=MediaAvailability.PURGED_BY_RETENTION,
            audit_sequences=(
                lease.intent_audit_sequence,
                completion_audit_sequence,
            ),
        )

    @staticmethod
    def _cleanup_failed(
        lease: PurgeLease,
        completion_audit_sequence: int,
    ) -> PurgeItemResult:
        return PurgeItemResult(
            run_id=lease.run_id,
            media_ref=ArtifactRef(
                kind=ArtifactKind.MEDIA,
                artifact_id=lease.media_sha256,
            ),
            crop_refs=lease.crop_refs,
            disposition=PurgeDisposition.RECOVERY_REQUIRED,
            reason_code=PurgeReasonCode.TRASH_CLEANUP_FAILED,
            previous_availability=MediaAvailability.PURGED_BY_RETENTION,
            current_availability=MediaAvailability.PURGED_BY_RETENTION,
            audit_sequences=(
                lease.intent_audit_sequence,
                completion_audit_sequence,
            ),
        )

    @staticmethod
    def _recovery_required(
        lease: PurgeLease,
        reason_code: PurgeReasonCode,
    ) -> PurgeItemResult:
        return PurgeItemResult(
            run_id=lease.run_id,
            media_ref=ArtifactRef(
                kind=ArtifactKind.MEDIA,
                artifact_id=lease.media_sha256,
            ),
            crop_refs=lease.crop_refs,
            disposition=PurgeDisposition.RECOVERY_REQUIRED,
            reason_code=reason_code,
            previous_availability=MediaAvailability.PURGING,
            current_availability=MediaAvailability.PURGING,
            audit_sequences=(lease.intent_audit_sequence,),
        )

    @staticmethod
    def _require_aware_datetime(value: datetime) -> None:
        if not isinstance(value, datetime):
            raise TypeError("expires_before must be a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_before must be timezone-aware")

    @staticmethod
    def _bounded_media_ids(values: tuple[str, ...], *, limit: int) -> tuple[str, ...]:
        if not isinstance(values, tuple) or any(not isinstance(value, str) for value in values):
            raise ContractViolation("retention media listing must be a tuple of SHA-256 values")
        if len(values) > limit:
            raise BudgetExceeded("retention repository exceeded the requested media limit")
        if len(values) != len(set(values)):
            raise ContractViolation("retention media listing contains duplicate values")
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ContractViolation("retention media listing contains an invalid SHA-256 value")
        if values != tuple(sorted(values)):
            raise ContractViolation("retention media listing must use stable SHA-256 order")
        return values

    @staticmethod
    def _require_lease_scope(
        lease: PurgeLease,
        run_id: str,
        media_sha256: str,
    ) -> None:
        if lease.run_id != run_id or lease.media_sha256 != media_sha256:
            raise ContractViolation("retention purge lease is outside the requested scope")

    @staticmethod
    def _require_result_scope(
        result: PurgeItemResult,
        run_id: str,
        media_sha256: str,
    ) -> None:
        if (
            result.run_id != run_id
            or result.media_ref.kind != ArtifactKind.MEDIA
            or result.media_ref.artifact_id != media_sha256
        ):
            raise ContractViolation("retention purge result is outside the requested scope")

    @classmethod
    def _require_begin_result(
        cls,
        result: PurgeItemResult,
        run_id: str,
        media_sha256: str,
    ) -> None:
        cls._require_result_scope(result, run_id, media_sha256)
        allowed_retained = frozenset(
            {
                PurgeReasonCode.ACTIVE_RETENTION_HOLD,
                PurgeReasonCode.RETENTION_NOT_EXPIRED,
                PurgeReasonCode.ALREADY_PURGED,
            }
        )
        if result.disposition == PurgeDisposition.RETAINED:
            valid = result.reason_code in allowed_retained
        else:
            valid = (
                result.disposition == PurgeDisposition.RECOVERY_REQUIRED
                and result.reason_code == PurgeReasonCode.PURGE_ALREADY_IN_PROGRESS
            )
        if not valid:
            raise ContractViolation(
                "retention repository returned an invalid pre-file purge decision"
            )

    @classmethod
    def _require_completed_result(
        cls,
        result: PurgeItemResult,
        lease: PurgeLease,
        *,
        recovered: bool,
    ) -> None:
        if not isinstance(result, PurgeItemResult):
            raise ContractViolation("retention repository returned an invalid completion result")
        cls._require_result_scope(result, lease.run_id, lease.media_sha256)
        expected_reason = (
            PurgeReasonCode.RECOVERED_PURGE_COMPLETED
            if recovered
            else PurgeReasonCode.EXPIRED_AND_PURGED
        )
        expected_previous = MediaAvailability.PURGING if recovered else MediaAvailability.AVAILABLE
        audit_sequences = result.audit_sequences
        if (
            result.crop_refs != lease.crop_refs
            or result.disposition != PurgeDisposition.PURGED
            or result.reason_code != expected_reason
            or result.previous_availability != expected_previous
            or result.current_availability != MediaAvailability.PURGED_BY_RETENTION
            or len(audit_sequences) != 2
            or audit_sequences[0] != lease.intent_audit_sequence
            or audit_sequences[1] <= lease.intent_audit_sequence
        ):
            raise ContractViolation(
                "retention completion result conflicts with its authorized purge lease"
            )


__all__ = ["MAX_RETENTION_ITEMS", "RetentionCoordinator"]
