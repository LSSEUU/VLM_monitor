from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment_v3 import (
    SQLiteM6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.application.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderServiceV3,
)
from labcourt.ports.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderError,
    M6UpgradeDurableSampleAppenderFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Status,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3 import (
    BUSY_TIMEOUT_MS,
    _builder,
    _ExactArtifactVerifier,
    _PixelProvider,
    _prepare_v3,
)


class _FailSecondPixelRead(_PixelProvider):
    def read_rgb8(self, frame_id: str):  # type: ignore[no-untyped-def]
        if self.requested_ids:
            self.requested_ids.append(frame_id)
            raise RuntimeError("simulated post-Pending physical drift")
        return super().read_rgb8(frame_id)


def _fail_at(expected_phase: str) -> Callable[[str], None]:
    def inject(phase: str) -> None:
        if phase == expected_phase:
            raise RuntimeError("simulated crash without authority payload")

    return inject


def _service(
    database: Path,
    pixels: _PixelProvider,
    *,
    commitment_fault: Callable[[str], None] | None = None,
    ledger_fault: Callable[[str], None] | None = None,
) -> tuple[
    M6UpgradeDurableSampleAppenderServiceV3,
    SQLiteM6UpgradeExecutionLedgerV3Repository,
    SQLiteM6UpgradePendingSampleCommitmentV3Repository,
    _ExactArtifactVerifier,
]:
    verifier = _ExactArtifactVerifier()
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        fault_injector=ledger_fault,
        sample_artifact_verifier=verifier,  # type: ignore[arg-type]
    )
    commitments = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        fault_injector=commitment_fault,
    )
    service = M6UpgradeDurableSampleAppenderServiceV3(
        ledger_repository=ledger,
        commitment_repository=commitments,
        record_builder=_builder(database, pixels),
    )
    return service, ledger, commitments, verifier


def test_v3_appender_closes_one_real_sqlite_observation_and_advances_exactly(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _prepare_v3(database, case_replayed=False)
    service, ledger, commitments, verifier = _service(database, pixels)

    record = service.append_pending_sample(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    resumed = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert record.observation_authority_id == observation.observation_authority_id
    assert resumed.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION
    assert resumed.committed_sample_count == 1
    assert resumed.ledger_head_hash == record.sample_execution_record_id
    assert resumed.next_execution_entry == scope.execution_dataset.entries[1]
    assert resumed.pending_observation is None
    assert resumed.pending_commitment is None
    assert (
        commitments.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        ).sample_execution_record
        == record
    )
    assert verifier.calls == [record]
    assert pixels.requested_ids == [
        observation.artifacts[0].artifact_id,
        observation.artifacts[0].artifact_id,
    ]


def test_v3_appender_revalidates_physical_bytes_after_pending_is_durable(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _prepare_v3(database, case_replayed=False)
    drifting_pixels = _FailSecondPixelRead(pixels.frame)
    service, ledger, commitments, verifier = _service(database, drifting_pixels)

    with pytest.raises(M6UpgradeDurableSampleAppenderError) as rejected:
        service.append_pending_sample(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )

    assert rejected.value.reason_code == (
        M6UpgradeDurableSampleAppenderFailureCode.PHYSICAL_ARTIFACT_REJECTED
    )
    resumed = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert resumed.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND
    assert resumed.pending_commitment == commitments.load(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
        0,
    )
    assert drifting_pixels.requested_ids == [
        observation.artifacts[0].artifact_id,
        observation.artifacts[0].artifact_id,
    ]
    assert verifier.calls == []


def test_v3_appender_recovers_after_pending_transaction_rolls_back(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _prepare_v3(database, case_replayed=False)
    crashing, ledger, _commitments, _verifier = _service(
        database,
        pixels,
        commitment_fault=_fail_at("m6_upgrade_pending_sample_commitment_v3.append.before_commit"),
    )

    with pytest.raises(M6UpgradeDurableSampleAppenderError) as rejected:
        crashing.append_pending_sample(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert rejected.value.reason_code == M6UpgradeDurableSampleAppenderFailureCode.STORAGE_REJECTED
    assert rejected.value.__context__ is None
    assert rejected.value.__cause__ is None
    rolled_back = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert rolled_back.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT
    assert rolled_back.pending_commitment is None

    fresh_pixels = _PixelProvider(pixels.frame)
    recovered, fresh_ledger, _fresh_commitments, _fresh_verifier = _service(
        database,
        fresh_pixels,
    )
    record = recovered.append_pending_sample(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    advanced = fresh_ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert advanced.committed_sample_count == 1
    assert advanced.ledger_head_hash == record.sample_execution_record_id
    assert fresh_pixels.requested_ids == [
        observation.artifacts[0].artifact_id,
        observation.artifacts[0].artifact_id,
    ]


def test_v3_appender_revalidates_with_fresh_builder_after_ledger_rollback(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _prepare_v3(database, case_replayed=False)
    crashing, ledger, commitments, _verifier = _service(
        database,
        pixels,
        ledger_fault=_fail_at(
            "m6_upgrade_execution_ledger_v3.append_committed_sample.before_commit"
        ),
    )

    with pytest.raises(M6UpgradeDurableSampleAppenderError) as rejected:
        crashing.append_pending_sample(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert rejected.value.reason_code == M6UpgradeDurableSampleAppenderFailureCode.STORAGE_REJECTED
    waiting = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert waiting.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND
    assert waiting.pending_commitment is not None
    durable_commitment = commitments.load(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
        0,
    )
    assert waiting.pending_commitment == durable_commitment

    fresh_pixels = _PixelProvider(pixels.frame)
    recovered, fresh_ledger, fresh_commitments, verifier = _service(database, fresh_pixels)
    record = recovered.append_pending_sample(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    advanced = fresh_ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert record == durable_commitment.sample_execution_record
    assert (
        fresh_commitments.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        )
        == durable_commitment
    )
    assert advanced.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION
    assert advanced.ledger_head_hash == record.sample_execution_record_id
    assert verifier.calls == [record]
    assert fresh_pixels.requested_ids == [observation.artifacts[0].artifact_id]
