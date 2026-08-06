"""Fail-closed orphan recovery for model-response files and journals."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from labcourt.contracts.model_response_recovery import (
    MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
    MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryItem,
    ModelResponseRecoveryReason,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ContractViolation
from labcourt.ports.model_response_artifacts import (
    MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
    MAX_MODEL_RESPONSE_RECOVERY_NAME_BYTES,
    ModelResponseArtifactCandidate,
    ModelResponseArtifactFileOps,
    ModelResponseArtifactReferenceRepository,
    ModelResponseArtifactScan,
    ModelResponseEmptyOperationCandidate,
)
from labcourt.ports.model_response_recovery import ModelResponseRecoveryIdentity

_RecoveryCandidate = ModelResponseArtifactCandidate | ModelResponseEmptyOperationCandidate


@dataclass(frozen=True, slots=True)
class ModelResponseArtifactRecoveryResult:
    run_id: str
    limit: int
    artifacts_scanned: int
    file_bytes_limit: int
    total_bytes_limit: int
    bytes_scanned: int
    scan_complete: bool
    items: tuple[ModelResponseRecoveryItem, ...]

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "model response artifact result run reference")
        if (
            not isinstance(self.limit, int)
            or isinstance(self.limit, bool)
            or not 1 <= self.limit <= MAX_MODEL_RESPONSE_RECOVERY_ITEMS
        ):
            raise ValueError("model response artifact result limit is invalid")
        if (
            not isinstance(self.artifacts_scanned, int)
            or isinstance(self.artifacts_scanned, bool)
            or not 0 <= self.artifacts_scanned <= self.limit
        ):
            raise ValueError("model response artifact result count must be non-negative")
        if (
            not isinstance(self.file_bytes_limit, int)
            or isinstance(self.file_bytes_limit, bool)
            or not 1 <= self.file_bytes_limit <= MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES
        ):
            raise ValueError("model response artifact result file-byte limit is invalid")
        if (
            not isinstance(self.total_bytes_limit, int)
            or isinstance(self.total_bytes_limit, bool)
            or not self.file_bytes_limit
            <= self.total_bytes_limit
            <= MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES
        ):
            raise ValueError("model response artifact result total-byte limit is invalid")
        if (
            not isinstance(self.bytes_scanned, int)
            or isinstance(self.bytes_scanned, bool)
            or not 0 <= self.bytes_scanned <= self.total_bytes_limit
        ):
            raise ValueError("model response artifact result byte count is invalid")
        if type(self.scan_complete) is not bool:
            raise TypeError("model response artifact result complete flag must be a boolean")
        if (
            not isinstance(self.items, tuple)
            or len(self.items) != self.artifacts_scanned
            or any(
                not isinstance(item, ModelResponseRecoveryItem)
                or item.run_id != self.run_id
                or item.area == ModelResponseRecoveryArea.MODEL_CALL
                for item in self.items
            )
        ):
            raise ValueError("model response artifact result items do not match its scan")
        keys = tuple(item.sort_key for item in self.items)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(key[:2] for key in keys)):
            raise ValueError("model response artifact result items must be stable and unique")
        anomalies = tuple(
            item
            for item in self.items
            if item.disposition == ModelResponseRecoveryDisposition.ANOMALY
        )
        if not self.scan_complete:
            if any(
                item.disposition
                in {
                    ModelResponseRecoveryDisposition.QUARANTINED,
                    ModelResponseRecoveryDisposition.CLEANED,
                }
                for item in self.items
            ):
                raise ValueError("incomplete artifact result cannot claim a filesystem mutation")
            expected_candidate_reason = (
                ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED
                if anomalies
                else ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE
            )
            if any(
                item.disposition != ModelResponseRecoveryDisposition.ANOMALY
                and item.reason_code
                not in {
                    expected_candidate_reason,
                    ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED,
                }
                for item in self.items
            ):
                raise ValueError("incomplete artifact result has an invalid candidate outcome")
        elif any(
            item.reason_code
            in {
                ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE,
                ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED,
            }
            for item in self.items
        ):
            raise ValueError("complete artifact result cannot contain scan-incomplete outcomes")
        if (
            any(
                item.reason_code == ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED
                for item in self.items
            )
            and not anomalies
        ):
            raise ValueError("artifact mutation suppression requires a typed anomaly")

    @property
    def has_anomaly(self) -> bool:
        return any(
            item.disposition == ModelResponseRecoveryDisposition.ANOMALY for item in self.items
        )


class ModelResponseArtifactRecoveryCoordinator:
    """Mutate only after a complete, anomaly-free bounded artifact inventory."""

    __slots__ = (
        "_file_ops",
        "_max_file_bytes",
        "_max_items",
        "_max_name_bytes",
        "_max_total_bytes",
        "_recovery_identity",
        "_repository",
    )

    def __init__(
        self,
        repository: ModelResponseArtifactReferenceRepository,
        file_ops: ModelResponseArtifactFileOps,
        *,
        max_items: int = MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
        max_name_bytes: int = MAX_MODEL_RESPONSE_RECOVERY_NAME_BYTES,
        max_file_bytes: int = MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        max_total_bytes: int | None = None,
        recovery_identity: ModelResponseRecoveryIdentity | None = None,
    ) -> None:
        self._repository = repository
        self._file_ops = file_ops
        if recovery_identity is not None and not isinstance(
            recovery_identity,
            ModelResponseRecoveryIdentity,
        ):
            raise TypeError("recovery_identity must be an opaque recovery identity")
        self._recovery_identity = recovery_identity or ModelResponseRecoveryIdentity()
        self._max_items = self._bounded_positive(
            max_items,
            MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
            "max_items",
        )
        self._max_name_bytes = self._bounded_positive(
            max_name_bytes,
            MAX_MODEL_RESPONSE_RECOVERY_NAME_BYTES,
            "max_name_bytes",
        )
        self._max_file_bytes = self._bounded_positive(
            max_file_bytes,
            MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
            "max_file_bytes",
        )
        derived_total_bytes = (
            min(
                self._max_items * self._max_file_bytes,
                MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
            )
            if max_total_bytes is None
            else max_total_bytes
        )
        self._max_total_bytes = self._bounded_positive(
            derived_total_bytes,
            MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
            "max_total_bytes",
        )
        if self._max_total_bytes < self._max_file_bytes:
            raise ValueError("max_total_bytes must cover at least one maximum-size file")

    @property
    def recovery_identity(self) -> ModelResponseRecoveryIdentity:
        """Return a capability-free token for composition identity checks."""

        return self._recovery_identity

    def recover(
        self,
        run_id: str,
        not_modified_after: datetime,
    ) -> ModelResponseArtifactRecoveryResult:
        controlled_run_id = require_reference_token(
            run_id,
            "model response artifact recovery run reference",
        )
        if (
            not isinstance(not_modified_after, datetime)
            or not_modified_after.tzinfo is None
            or not_modified_after.utcoffset() is None
            or not_modified_after.utcoffset() != timedelta(0)
        ):
            raise ValueError("model response artifact cutoff must use timezone-aware UTC")

        scan = self._file_ops.discover_model_response_artifacts(
            controlled_run_id,
            self._max_items,
            self._max_name_bytes,
            self._max_file_bytes,
            self._max_total_bytes,
        )
        self._require_scan(scan, controlled_run_id)
        results = [*scan.anomalies, *scan.budget_exhaustions]
        candidates: tuple[_RecoveryCandidate, ...] = tuple(
            sorted(
                (*scan.candidates, *scan.cleanup_candidates),
                key=lambda candidate: candidate.sort_key,
            )
        )

        if not scan.complete:
            reason = (
                ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED
                if scan.anomalies
                else ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE
            )
            results.extend(self._retained(candidate, reason) for candidate in candidates)
            return self._result(scan, results)

        if scan.anomalies:
            results.extend(
                self._retained(
                    candidate,
                    ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED,
                )
                for candidate in candidates
            )
            return self._result(scan, results)

        referenced_sources: set[tuple[str, str]] = set()
        for artifact_candidate in scan.candidates:
            if artifact_candidate.area != ModelResponseRecoveryArea.FINAL_RESPONSE:
                continue
            referenced = self._repository.model_response_is_referenced(
                controlled_run_id,
                artifact_candidate.authority_id,
                artifact_candidate.content_sha256,
            )
            if type(referenced) is not bool:
                raise ContractViolation("model response reference query must return a boolean")
            if referenced:
                referenced_sources.add(artifact_candidate.sort_key)

        for index, candidate in enumerate(candidates):
            if candidate.sort_key in referenced_sources:
                results.append(
                    self._retained(
                        candidate,
                        ModelResponseRecoveryReason.DATABASE_REFERENCED_ARTIFACT,
                    )
                )
                continue

            if isinstance(candidate, ModelResponseEmptyOperationCandidate):
                outcome = self._file_ops.cleanup_empty_model_response_operation(
                    candidate,
                    not_modified_after,
                )
                self._require_cleanup_outcome(outcome, candidate)
            else:
                outcome = self._file_ops.quarantine_model_response_artifact(
                    candidate,
                    not_modified_after,
                    self._max_file_bytes,
                )
                self._require_file_outcome(outcome, candidate)
            results.append(outcome)
            if outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY:
                results.extend(
                    self._retained(
                        remaining,
                        ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED,
                    )
                    for remaining in candidates[index + 1 :]
                )
                break

        return self._result(scan, results)

    @staticmethod
    def _retained(
        candidate: _RecoveryCandidate,
        reason: ModelResponseRecoveryReason,
    ) -> ModelResponseRecoveryItem:
        return ModelResponseRecoveryItem(
            run_id=candidate.run_id,
            area=candidate.area,
            source_token=candidate.source_token,
            content_sha256=(
                candidate.content_sha256
                if isinstance(candidate, ModelResponseArtifactCandidate)
                else None
            ),
            disposition=ModelResponseRecoveryDisposition.RETAINED,
            reason_code=reason,
        )

    def _require_scan(self, scan: object, run_id: str) -> None:
        if (
            not isinstance(scan, ModelResponseArtifactScan)
            or scan.run_id != run_id
            or scan.max_items != self._max_items
            or scan.max_file_bytes != self._max_file_bytes
            or scan.max_total_bytes != self._max_total_bytes
        ):
            raise ContractViolation("model response artifact scan is outside the run")

    @staticmethod
    def _require_file_outcome(
        outcome: object,
        candidate: ModelResponseArtifactCandidate,
    ) -> None:
        if not isinstance(outcome, ModelResponseRecoveryItem):
            raise ContractViolation("model response file operation returned an invalid result")
        if (
            outcome.run_id != candidate.run_id
            or outcome.area != candidate.area
            or outcome.source_token != candidate.source_token
            or outcome.content_sha256 != candidate.content_sha256
        ):
            raise ContractViolation("model response file result conflicts with its exact candidate")
        allowed = (
            outcome.disposition == ModelResponseRecoveryDisposition.QUARANTINED
            or (
                outcome.disposition == ModelResponseRecoveryDisposition.RETAINED
                and outcome.reason_code == ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET
            )
            or outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY
        )
        if not allowed:
            raise ContractViolation("model response file result has an unauthorized disposition")

    @staticmethod
    def _require_cleanup_outcome(
        outcome: object,
        candidate: ModelResponseEmptyOperationCandidate,
    ) -> None:
        if not isinstance(outcome, ModelResponseRecoveryItem):
            raise ContractViolation(
                "model response empty-operation cleanup returned an invalid result"
            )
        if (
            outcome.run_id != candidate.run_id
            or outcome.area != candidate.area
            or outcome.source_token != candidate.source_token
            or outcome.content_sha256 is not None
            or outcome.quarantine_relative_path is not None
        ):
            raise ContractViolation(
                "model response empty-operation result conflicts with its candidate"
            )
        allowed = (
            (
                outcome.disposition == ModelResponseRecoveryDisposition.CLEANED
                and outcome.reason_code == ModelResponseRecoveryReason.EMPTY_OPERATION_CLEANED
            )
            or (
                outcome.disposition == ModelResponseRecoveryDisposition.RETAINED
                and outcome.reason_code == ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET
            )
            or outcome.disposition == ModelResponseRecoveryDisposition.ANOMALY
        )
        if not allowed:
            raise ContractViolation(
                "model response empty-operation result has an unauthorized disposition"
            )

    @staticmethod
    def _result(
        scan: ModelResponseArtifactScan,
        items: list[ModelResponseRecoveryItem],
    ) -> ModelResponseArtifactRecoveryResult:
        return ModelResponseArtifactRecoveryResult(
            run_id=scan.run_id,
            limit=scan.max_items,
            artifacts_scanned=scan.artifacts_scanned,
            file_bytes_limit=scan.max_file_bytes,
            total_bytes_limit=scan.max_total_bytes,
            bytes_scanned=scan.bytes_scanned,
            scan_complete=scan.complete,
            items=tuple(sorted(items, key=lambda item: item.sort_key)),
        )

    @staticmethod
    def _bounded_positive(value: int, upper_bound: int, name: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= upper_bound:
            raise ValueError(f"{name} must be an integer from 1 through {upper_bound}")
        return value


__all__ = [
    "ModelResponseArtifactRecoveryCoordinator",
    "ModelResponseArtifactRecoveryResult",
]
