"""Ordered M2/M3 startup recovery composition with one public report."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol

from labcourt.application.model_response_artifacts import (
    ModelResponseArtifactRecoveryResult,
)
from labcourt.application.model_response_recovery import (
    MAX_MODEL_CALL_RECOVERY_ITEMS,
    ModelCallRecoveryResult,
)
from labcourt.contracts.model_response_recovery import (
    MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
    MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
    MaintenanceRecoveryReport,
    ModelResponseArtifactPhase,
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryReport,
)
from labcourt.contracts.recovery import StartupRecoveryReport
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ContractViolation
from labcourt.ports.model_response_artifacts import (
    MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
    ModelResponseArtifactRecoveryFence,
)
from labcourt.ports.model_response_recovery import ModelResponseRecoveryIdentity


class _StorageRecovery(Protocol):
    def recover(
        self,
        run_id: str,
        started_at: datetime,
        minimum_age: timedelta,
    ) -> StartupRecoveryReport: ...


class _ModelCallRecovery(Protocol):
    @property
    def recovery_identity(self) -> ModelResponseRecoveryIdentity: ...

    def recover(
        self,
        run_id: str,
        started_at: datetime,
    ) -> ModelCallRecoveryResult: ...


class _ModelResponseArtifactRecovery(Protocol):
    @property
    def recovery_identity(self) -> ModelResponseRecoveryIdentity: ...

    def recover(
        self,
        run_id: str,
        not_modified_after: datetime,
    ) -> ModelResponseArtifactRecoveryResult: ...


class _IdentityBoundRecoveryFence(ModelResponseArtifactRecoveryFence, Protocol):
    @property
    def recovery_identity(self) -> ModelResponseRecoveryIdentity: ...


class ModelResponseStartupRecoveryCoordinator:
    """Recover claims first and authorize orphan mutation only from a clean inventory."""

    __slots__ = (
        "_artifact_file_bytes_limit",
        "_artifact_limit",
        "_artifact_total_bytes_limit",
        "_artifacts",
        "_claim_limit",
        "_claims",
        "_fence",
    )

    def __init__(
        self,
        *,
        claims: _ModelCallRecovery,
        artifacts: _ModelResponseArtifactRecovery,
        fence: _IdentityBoundRecoveryFence,
        claim_limit: int = MAX_MODEL_CALL_RECOVERY_ITEMS,
        artifact_limit: int = MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
        artifact_file_bytes_limit: int = MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        artifact_total_bytes_limit: int | None = None,
    ) -> None:
        self._claim_limit = self._bounded_limit(
            claim_limit,
            MAX_MODEL_CALL_RECOVERY_ITEMS,
            "claim_limit",
        )
        self._artifact_limit = self._bounded_limit(
            artifact_limit,
            MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
            "artifact_limit",
        )
        self._artifact_file_bytes_limit = self._bounded_limit(
            artifact_file_bytes_limit,
            MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
            "artifact_file_bytes_limit",
        )
        derived_total_bytes = (
            min(
                self._artifact_limit * self._artifact_file_bytes_limit,
                MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
            )
            if artifact_total_bytes_limit is None
            else artifact_total_bytes_limit
        )
        self._artifact_total_bytes_limit = self._bounded_limit(
            derived_total_bytes,
            MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
            "artifact_total_bytes_limit",
        )
        if self._artifact_total_bytes_limit < self._artifact_file_bytes_limit:
            raise ValueError("artifact_total_bytes_limit must cover at least one maximum-size file")
        self._claims = claims
        self._artifacts = artifacts
        if (
            claims.recovery_identity is not fence.recovery_identity
            or artifacts.recovery_identity is not fence.recovery_identity
        ):
            raise ValueError("claim, artifact, and fence recovery must share one authority")
        self._fence = fence

    def recover(
        self,
        run_id: str,
        started_at: datetime,
        minimum_age: timedelta,
    ) -> ModelResponseRecoveryReport:
        controlled_run_id = require_reference_token(
            run_id,
            "model response startup recovery run reference",
        )
        self._require_utc(started_at)
        if not isinstance(minimum_age, timedelta) or minimum_age <= timedelta(0):
            raise ValueError("model response recovery minimum_age must be positive")
        cutoff = started_at - minimum_age

        claim_result = self._claims.recover(controlled_run_id, started_at)
        self._require_claim_result(claim_result, controlled_run_id, started_at)
        blocking_phase = self._claim_blocking_phase(claim_result)
        if blocking_phase is not None:
            return self._report_without_artifacts(
                controlled_run_id,
                started_at,
                cutoff,
                claim_result,
                blocking_phase,
            )

        with self._fence.model_response_artifact_recovery_fence(controlled_run_id):
            fenced_claim_result = self._claims.recover(
                controlled_run_id,
                started_at,
            )
            self._require_claim_result(
                fenced_claim_result,
                controlled_run_id,
                started_at,
            )
            blocking_phase = self._claim_blocking_phase(fenced_claim_result)
            if blocking_phase is not None:
                return self._report_without_artifacts(
                    controlled_run_id,
                    started_at,
                    cutoff,
                    fenced_claim_result,
                    blocking_phase,
                )

            artifact_result = self._artifacts.recover(
                controlled_run_id,
                cutoff,
            )
            self._require_artifact_result(artifact_result, controlled_run_id)
            artifact_anomaly = artifact_result.has_anomaly
            if artifact_anomaly:
                phase = ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE
            elif not artifact_result.scan_complete:
                phase = ModelResponseArtifactPhase.BUDGET_EXHAUSTED
            else:
                phase = ModelResponseArtifactPhase.COMPLETED
            items = tuple(
                sorted(
                    (*fenced_claim_result.items, *artifact_result.items),
                    key=lambda item: item.sort_key,
                )
            )
            return ModelResponseRecoveryReport(
                run_id=controlled_run_id,
                started_at=started_at,
                artifact_not_modified_after=cutoff,
                claim_limit=self._claim_limit,
                claims_scanned=fenced_claim_result.scanned,
                claim_scan_complete=True,
                artifact_limit=self._artifact_limit,
                artifacts_scanned=artifact_result.artifacts_scanned,
                artifact_file_bytes_limit=artifact_result.file_bytes_limit,
                artifact_total_bytes_limit=artifact_result.total_bytes_limit,
                artifact_bytes_scanned=artifact_result.bytes_scanned,
                artifact_scan_complete=artifact_result.scan_complete,
                artifact_phase=phase,
                items=items,
            )

    def _report_without_artifacts(
        self,
        run_id: str,
        started_at: datetime,
        cutoff: datetime,
        claims: ModelCallRecoveryResult,
        phase: ModelResponseArtifactPhase,
    ) -> ModelResponseRecoveryReport:
        return ModelResponseRecoveryReport(
            run_id=run_id,
            started_at=started_at,
            artifact_not_modified_after=cutoff,
            claim_limit=self._claim_limit,
            claims_scanned=claims.scanned,
            claim_scan_complete=claims.scan_complete,
            artifact_limit=self._artifact_limit,
            artifacts_scanned=0,
            artifact_file_bytes_limit=self._artifact_file_bytes_limit,
            artifact_total_bytes_limit=self._artifact_total_bytes_limit,
            artifact_bytes_scanned=0,
            artifact_scan_complete=False,
            artifact_phase=phase,
            items=claims.items,
        )

    def _require_claim_result(
        self,
        result: object,
        run_id: str,
        started_at: datetime,
    ) -> None:
        if (
            not isinstance(result, ModelCallRecoveryResult)
            or result.run_id != run_id
            or result.started_at != started_at
            or result.limit != self._claim_limit
        ):
            raise ContractViolation("model call recovery returned an invalid result")

    @staticmethod
    def _claim_blocking_phase(
        result: ModelCallRecoveryResult,
    ) -> ModelResponseArtifactPhase | None:
        if not result.scan_complete:
            return ModelResponseArtifactPhase.SUPPRESSED_CLAIM_SCAN_INCOMPLETE
        if any(
            item.disposition == ModelResponseRecoveryDisposition.ANOMALY for item in result.items
        ):
            return ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE
        if any(
            item.disposition == ModelResponseRecoveryDisposition.DEFERRED for item in result.items
        ):
            return ModelResponseArtifactPhase.DEFERRED_ACTIVE_CLAIM
        return None

    def _require_artifact_result(
        self,
        result: object,
        run_id: str,
    ) -> None:
        if (
            not isinstance(result, ModelResponseArtifactRecoveryResult)
            or result.run_id != run_id
            or result.limit != self._artifact_limit
            or result.file_bytes_limit != self._artifact_file_bytes_limit
            or result.total_bytes_limit != self._artifact_total_bytes_limit
            or any(item.area == ModelResponseRecoveryArea.MODEL_CALL for item in result.items)
        ):
            raise ContractViolation("model response artifact recovery returned an invalid result")

    @staticmethod
    def _bounded_limit(value: int, maximum: int, name: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
            raise ValueError(f"{name} must be an integer from 1 through {maximum}")
        return value

    @staticmethod
    def _require_utc(value: datetime) -> None:
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset() != timedelta(0)
        ):
            raise ValueError("model response recovery start time must use timezone-aware UTC")


class MaintenanceRecoveryCoordinator:
    """Run the frozen M2 recovery and the M3 response recovery at one startup time."""

    __slots__ = ("_model_responses", "_storage")

    def __init__(
        self,
        *,
        storage: _StorageRecovery,
        model_responses: ModelResponseStartupRecoveryCoordinator,
    ) -> None:
        self._storage = storage
        self._model_responses = model_responses

    def recover(
        self,
        run_id: str,
        started_at: datetime,
        minimum_age: timedelta,
    ) -> MaintenanceRecoveryReport:
        controlled_run_id = require_reference_token(
            run_id,
            "maintenance recovery run reference",
        )
        storage_report = self._storage.recover(
            controlled_run_id,
            started_at,
            minimum_age,
        )
        if (
            not isinstance(storage_report, StartupRecoveryReport)
            or storage_report.run_id != controlled_run_id
            or storage_report.started_at != started_at
        ):
            raise ContractViolation("storage recovery returned an invalid report")
        model_report = self._model_responses.recover(
            controlled_run_id,
            started_at,
            minimum_age,
        )
        return MaintenanceRecoveryReport(
            run_id=controlled_run_id,
            started_at=started_at,
            storage_report=storage_report,
            model_response_report=model_report,
        )


__all__ = [
    "MaintenanceRecoveryCoordinator",
    "ModelResponseStartupRecoveryCoordinator",
]
