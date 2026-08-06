from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from labcourt.application.maintenance_recovery import (
    MaintenanceRecoveryCoordinator,
    ModelResponseStartupRecoveryCoordinator,
)
from labcourt.application.model_response_artifacts import (
    ModelResponseArtifactRecoveryResult,
)
from labcourt.application.model_response_recovery import ModelCallRecoveryResult
from labcourt.contracts.model_response_recovery import (
    MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
    ModelResponseArtifactPhase,
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryItem,
    ModelResponseRecoveryReason,
)
from labcourt.contracts.recovery import RecoveryReport, StartupRecoveryReport
from labcourt.contracts.screening import derive_model_response_id
from labcourt.ports.model_response_recovery import ModelResponseRecoveryIdentity

RUN_ID = "run-maintenance-recovery-01"
STARTED_AT = datetime(2026, 7, 28, 2, tzinfo=UTC)
MINIMUM_AGE = timedelta(minutes=5)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _claim_item(
    reason: ModelResponseRecoveryReason,
    disposition: ModelResponseRecoveryDisposition,
    *,
    request_id: str = SHA_A,
) -> ModelResponseRecoveryItem:
    response_id = None
    content_sha256 = None
    if reason in {
        ModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED,
        ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
    }:
        content_sha256 = SHA_B
        response_id = derive_model_response_id(RUN_ID, request_id, content_sha256)
    return ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=ModelResponseRecoveryArea.MODEL_CALL,
        request_id=request_id,
        response_id=response_id,
        response_content_sha256=content_sha256,
        disposition=disposition,
        reason_code=reason,
    )


def _artifact_item(
    reason: ModelResponseRecoveryReason,
    disposition: ModelResponseRecoveryDisposition,
) -> ModelResponseRecoveryItem:
    return ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=ModelResponseRecoveryArea.FINAL_RESPONSE,
        source_token=SHA_C,
        content_sha256=SHA_D,
        disposition=disposition,
        reason_code=reason,
    )


def _claim_result(
    items: tuple[ModelResponseRecoveryItem, ...],
    *,
    complete: bool = True,
    limit: int = 10,
) -> ModelCallRecoveryResult:
    return ModelCallRecoveryResult(
        run_id=RUN_ID,
        started_at=STARTED_AT,
        limit=limit,
        scanned=len(items),
        scan_complete=complete,
        items=tuple(sorted(items, key=lambda item: item.sort_key)),
    )


def _artifact_result(
    items: tuple[ModelResponseRecoveryItem, ...] = (),
    *,
    complete: bool = True,
    limit: int = 10,
) -> ModelResponseArtifactRecoveryResult:
    return ModelResponseArtifactRecoveryResult(
        run_id=RUN_ID,
        limit=limit,
        artifacts_scanned=len(items),
        file_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        total_bytes_limit=limit * MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        bytes_scanned=len(items),
        scan_complete=complete,
        items=tuple(sorted(items, key=lambda item: item.sort_key)),
    )


class _Claims:
    def __init__(
        self,
        result: ModelCallRecoveryResult,
        recovery_identity: ModelResponseRecoveryIdentity,
        fenced_result: ModelCallRecoveryResult | None = None,
    ) -> None:
        self.results = (result, fenced_result or result)
        self.recovery_identity = recovery_identity
        self.calls = 0

    def recover(self, run_id: str, started_at: datetime) -> ModelCallRecoveryResult:
        assert (run_id, started_at) == (RUN_ID, STARTED_AT)
        self.calls += 1
        return self.results[min(self.calls - 1, 1)]


class _Artifacts:
    def __init__(
        self,
        result: ModelResponseArtifactRecoveryResult,
        recovery_identity: ModelResponseRecoveryIdentity,
    ) -> None:
        self.result = result
        self.recovery_identity = recovery_identity
        self.calls = 0

    def recover(
        self,
        run_id: str,
        not_modified_after: datetime,
    ) -> ModelResponseArtifactRecoveryResult:
        assert (run_id, not_modified_after) == (
            RUN_ID,
            STARTED_AT - MINIMUM_AGE,
        )
        self.calls += 1
        return self.result


class _Fence:
    def __init__(self, recovery_identity: ModelResponseRecoveryIdentity) -> None:
        self.recovery_identity = recovery_identity
        self.calls = 0
        self.active = False

    @contextmanager
    def model_response_artifact_recovery_fence(
        self,
        run_id: str,
    ) -> Iterator[None]:
        assert run_id == RUN_ID
        assert self.active is False
        self.calls += 1
        self.active = True
        try:
            yield
        finally:
            self.active = False


def _coordinator(
    claims: ModelCallRecoveryResult,
    artifacts: ModelResponseArtifactRecoveryResult | None = None,
    *,
    fenced_claims: ModelCallRecoveryResult | None = None,
) -> tuple[ModelResponseStartupRecoveryCoordinator, _Claims, _Artifacts]:
    recovery_identity = ModelResponseRecoveryIdentity()
    fence = _Fence(recovery_identity)
    claim_dependency = _Claims(claims, recovery_identity, fenced_claims)
    artifact_dependency = _Artifacts(artifacts or _artifact_result(), recovery_identity)
    return (
        ModelResponseStartupRecoveryCoordinator(
            claims=claim_dependency,
            artifacts=artifact_dependency,
            fence=fence,
            claim_limit=claims.limit,
            artifact_limit=artifact_dependency.result.limit,
            artifact_file_bytes_limit=artifact_dependency.result.file_bytes_limit,
            artifact_total_bytes_limit=artifact_dependency.result.total_bytes_limit,
        ),
        claim_dependency,
        artifact_dependency,
    )


def test_startup_composition_rejects_mismatched_opaque_recovery_identity() -> None:
    first_identity = ModelResponseRecoveryIdentity()
    second_identity = ModelResponseRecoveryIdentity()
    claims = _Claims(_claim_result(()), first_identity)
    artifacts = _Artifacts(_artifact_result(), first_identity)

    try:
        ModelResponseStartupRecoveryCoordinator(
            claims=claims,
            artifacts=artifacts,
            fence=_Fence(second_identity),
        )
    except ValueError as error:
        assert str(error) == "claim, artifact, and fence recovery must share one authority"
    else:
        raise AssertionError("mismatched recovery identity must be rejected")

    assert not hasattr(claims, "recovery_authority")
    assert not hasattr(claims.recovery_identity, "claim_model_call")


def test_incomplete_claim_scan_suppresses_artifact_recovery() -> None:
    claim = _claim_item(
        ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE,
        ModelResponseRecoveryDisposition.DEFERRED,
    )
    coordinator, _claims, artifacts = _coordinator(_claim_result((claim,), complete=False, limit=1))

    report = coordinator.recover(RUN_ID, STARTED_AT, MINIMUM_AGE)

    assert report.artifact_phase == ModelResponseArtifactPhase.SUPPRESSED_CLAIM_SCAN_INCOMPLETE
    assert report.requires_attention is True
    assert artifacts.calls == 0


def test_claim_anomaly_suppresses_artifact_recovery() -> None:
    anomaly = _claim_item(
        ModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT,
        ModelResponseRecoveryDisposition.ANOMALY,
    )
    coordinator, _, artifacts = _coordinator(_claim_result((anomaly,)))

    report = coordinator.recover(RUN_ID, STARTED_AT, MINIMUM_AGE)

    assert report.artifact_phase == ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE
    assert artifacts.calls == 0


def test_expected_active_claim_defers_artifacts_without_marking_integrity_failure() -> None:
    active = _claim_item(
        ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED,
        ModelResponseRecoveryDisposition.DEFERRED,
    )
    coordinator, _, artifacts = _coordinator(_claim_result((active,)))

    report = coordinator.recover(RUN_ID, STARTED_AT, MINIMUM_AGE)

    assert report.artifact_phase == ModelResponseArtifactPhase.DEFERRED_ACTIVE_CLAIM
    assert report.passed is True
    assert artifacts.calls == 0


def test_terminal_claims_authorize_complete_artifact_recovery() -> None:
    terminal = _claim_item(
        ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
        ModelResponseRecoveryDisposition.VERIFIED,
    )
    retained = _artifact_item(
        ModelResponseRecoveryReason.DATABASE_REFERENCED_ARTIFACT,
        ModelResponseRecoveryDisposition.RETAINED,
    )
    coordinator, claims, artifacts = _coordinator(
        _claim_result((terminal,)),
        _artifact_result((retained,)),
    )

    report = coordinator.recover(RUN_ID, STARTED_AT, MINIMUM_AGE)

    assert report.artifact_phase == ModelResponseArtifactPhase.COMPLETED
    assert report.passed is True
    assert artifacts.calls == 1
    assert claims.calls == 2
    assert report.artifacts_scanned == 1


def test_fenced_rescan_catches_a_claim_created_after_preflight() -> None:
    terminal = _claim_item(
        ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
        ModelResponseRecoveryDisposition.VERIFIED,
    )
    raced = _claim_item(
        ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED,
        ModelResponseRecoveryDisposition.DEFERRED,
        request_id=SHA_B,
    )
    coordinator, claims, artifacts = _coordinator(
        _claim_result((terminal,)),
        fenced_claims=_claim_result((raced,)),
    )

    report = coordinator.recover(RUN_ID, STARTED_AT, MINIMUM_AGE)

    assert claims.calls == 2
    assert artifacts.calls == 0
    assert report.artifact_phase == ModelResponseArtifactPhase.DEFERRED_ACTIVE_CLAIM


def test_artifact_budget_and_anomaly_phases_require_attention() -> None:
    terminal = _claim_item(
        ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
        ModelResponseRecoveryDisposition.VERIFIED,
    )
    deferred = _artifact_item(
        ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE,
        ModelResponseRecoveryDisposition.RETAINED,
    )
    coordinator, _, _ = _coordinator(
        _claim_result((terminal,)),
        _artifact_result((deferred,), complete=False),
    )
    budget = coordinator.recover(RUN_ID, STARTED_AT, MINIMUM_AGE)
    assert budget.artifact_phase == ModelResponseArtifactPhase.BUDGET_EXHAUSTED
    assert budget.requires_attention is True

    anomaly = _artifact_item(
        ModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE,
        ModelResponseRecoveryDisposition.ANOMALY,
    )
    coordinator, _, _ = _coordinator(
        _claim_result((terminal,)),
        _artifact_result((anomaly,), complete=True),
    )
    failed = coordinator.recover(RUN_ID, STARTED_AT, MINIMUM_AGE)
    assert failed.artifact_phase == ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE
    assert failed.requires_attention is True


class _Storage:
    def __init__(self) -> None:
        self.calls = 0

    def recover(
        self,
        run_id: str,
        started_at: datetime,
        minimum_age: timedelta,
    ) -> StartupRecoveryReport:
        assert (run_id, started_at, minimum_age) == (
            RUN_ID,
            STARTED_AT,
            MINIMUM_AGE,
        )
        self.calls += 1
        return StartupRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT,
            orphan_report=RecoveryReport(
                run_id=RUN_ID,
                not_modified_after=STARTED_AT - MINIMUM_AGE,
            ),
        )


def test_maintenance_envelope_preserves_frozen_storage_report() -> None:
    claims = _claim_result(())
    model, _, _ = _coordinator(claims)
    storage = _Storage()

    report = MaintenanceRecoveryCoordinator(
        storage=storage,
        model_responses=model,
    ).recover(RUN_ID, STARTED_AT, MINIMUM_AGE)

    assert storage.calls == 1
    assert report.storage_report.passed is True
    assert report.model_response_report.passed is True
    assert report.passed is True
