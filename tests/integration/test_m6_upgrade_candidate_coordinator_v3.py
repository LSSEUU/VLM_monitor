from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.sqlite_m6_upgrade_candidate_output import (
    SQLiteM6UpgradeCandidateOutputBuilderV3,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_candidate_run_cut import (
    SQLiteM6UpgradeCandidateRunCutRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
)
from labcourt.application.m6_upgrade_candidate_coordinator import (
    M6UpgradeCandidateCoordinatorServiceV3,
)
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
    M6UpgradeCandidateRunCutAuthority,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import M6UpgradeExecutionResumeV3
from tests.integration.test_m6_upgrade_candidate_output_builder_v3 import (
    BUSY_TIMEOUT_MS,
    _prepare_no_case_pipeline,
    _terminal_builder,
)
from tests.integration.test_m6_upgrade_candidate_run_cut_migration import (
    _run_cut_for_seal,
)


class _TrackingLedger:
    def __init__(
        self,
        delegate: SQLiteM6UpgradeExecutionLedgerV3Repository,
        events: list[str],
    ) -> None:
        self.delegate = delegate
        self.events = events

    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        self.events.append("begin")
        return self.delegate.begin_execution(scope)

    def resume(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResumeV3:
        self.events.append("resume")
        return self.delegate.resume(candidate_run_id, execution_scope_authority_id)

    def seal(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSealV2:
        self.events.append("seal")
        return self.delegate.seal(candidate_run_id, execution_scope_authority_id)


class _PostSealValidationReportProvider:
    def __init__(
        self,
        ledger: SQLiteM6UpgradeExecutionLedgerV3Repository,
        scope: M6UpgradeExecutionScopeAuthority,
        events: list[str],
    ) -> None:
        self.ledger = ledger
        self.scope = scope
        self.events = events

    def load_m6_upgrade_candidate_validation_report(
        self,
        candidate_run_id: str,
        audit_head_sequence: int,
        audit_head_hash: str,
    ) -> M5ArtifactValidationReport:
        self.events.append("validation-report")
        seal = self.ledger.load_sealed(
            candidate_run_id,
            self.scope.execution_scope_authority_id,
        )
        assert seal.source_audit_head_sequence == audit_head_sequence
        assert seal.source_audit_head_hash == audit_head_hash
        return _run_cut_for_seal(self.scope, seal).validation_report


class _TrackingRunCuts:
    def __init__(
        self,
        delegate: SQLiteM6UpgradeCandidateRunCutRepository,
        events: list[str],
    ) -> None:
        self.delegate = delegate
        self.events = events

    def build_or_load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateRunCutAuthority:
        self.events.append("run-cut")
        return self.delegate.build_or_load(candidate_run_id, execution_scope_authority_id)


class _TrackingOutput:
    def __init__(
        self,
        delegate: SQLiteM6UpgradeCandidateOutputBuilderV3,
        events: list[str],
    ) -> None:
        self.delegate = delegate
        self.events = events

    def build_terminal_inventory(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        self.events.append("inventory")
        return self.delegate.build_terminal_inventory(
            candidate_run_id,
            execution_scope_authority_id,
        )


class _ForbiddenObservationRepository:
    def append(self, _observation: object) -> object:
        raise AssertionError("READY_TO_SEAL must not append another observation")


class _ForbiddenObservationProducer:
    def produce_next_observation(self, *_identities: str) -> object:
        raise AssertionError("READY_TO_SEAL must not execute another sample")


class _ForbiddenSampleAppender:
    def append_pending_sample(self, *_identities: str) -> object:
        raise AssertionError("READY_TO_SEAL must not append another sample")


def test_real_sqlite_coordinator_seals_then_cuts_then_builds_terminal_inventory(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_no_case_pipeline(database, sealed=False)
    pipeline.pixels.requested_ids.clear()
    events: list[str] = []
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)
    run_cuts = SQLiteM6UpgradeCandidateRunCutRepository(
        database,
        BUSY_TIMEOUT_MS,
        validation_report_provider=_PostSealValidationReportProvider(
            ledger,
            pipeline.scope,
            events,
        ),
    )
    coordinator = M6UpgradeCandidateCoordinatorServiceV3(
        ledger_repository=_TrackingLedger(ledger, events),  # type: ignore[arg-type]
        observation_repository=_ForbiddenObservationRepository(),  # type: ignore[arg-type]
        observation_producer=_ForbiddenObservationProducer(),  # type: ignore[arg-type]
        sample_appender=_ForbiddenSampleAppender(),  # type: ignore[arg-type]
        run_cut_repository=_TrackingRunCuts(run_cuts, events),
        candidate_output_builder=_TrackingOutput(
            _terminal_builder(database, pipeline.pixels),
            events,
        ),
    )

    inventory = coordinator.run_to_terminal(pipeline.scope)

    assert events == [
        "begin",
        "resume",
        "seal",
        "run-cut",
        "validation-report",
        "inventory",
    ]
    assert inventory.schema_version == "m6-upgrade-candidate-output-inventory-authority-v3"
    assert inventory.execution_ledger.execution_scope == pipeline.scope
    assert inventory.output_count == len(pipeline.scope.execution_dataset.entries)
    assert inventory.candidate_case_count == 0
    assert inventory.model_call_count == 0
    assert all(output.outcome == M6ReplayExecutionOutcome.NO_CASE for output in inventory.outputs)
    assert (
        ledger.load_sealed(
            pipeline.scope.candidate_run_id,
            pipeline.scope.execution_scope_authority_id,
        )
        == inventory.execution_ledger
    )
    assert set(pipeline.pixels.requested_ids) == {
        frame.frame.frame_id for frame in pipeline.rgb_frames
    }
