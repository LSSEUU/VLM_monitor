"""Unified offline acceptance nodes for the 16 named M6 demo scenarios.

Every node executes an existing deterministic workflow test.  Inputs and model
outputs are synthetic/precomputed fixtures; these tests make no real-world
accuracy, latency, throughput, cost, or safety claim.
"""

from __future__ import annotations

from pathlib import Path

from labcourt.contracts.enums import (
    CaseStatus,
    ProceduralDefectCode,
    ScreeningDecision,
    VerdictDecision,
)
from labcourt.contracts.m6_regression import (
    M6RegressionDisposition,
    M6RegressionGateReason,
)
from tests.contract import test_m6_regression_contracts as regression_contracts
from tests.e2e import test_m3_pipeline_scenarios as m3_scenarios
from tests.e2e import test_m5_appeal_cli as appeal_cli
from tests.integration import test_m6_replay_locked_closed_policy_fast_e2e as closed_replay
from tests.unit import test_m1_fsm as m1_fsm
from tests.unit import test_m1_sources_reminders as m1_sources
from tests.unit import test_m4_hearing_domain as hearing_domain
from tests.unit import test_procedural_gate as procedural_gate


def test_presence_true_positive(tmp_path: Path) -> None:
    m3_scenarios.test_presence_threshold_scenarios_use_the_complete_offline_pipeline(
        tmp_path,
        0.95,
        ScreeningDecision.ESTABLISHED,
        CaseStatus.READY_FOR_ALERT_POLICY,
    )


def test_presence_false_positive(tmp_path: Path) -> None:
    m3_scenarios.test_presence_threshold_scenarios_use_the_complete_offline_pipeline(
        tmp_path,
        0.05,
        ScreeningDecision.NOT_ESTABLISHED,
        CaseStatus.READY_FOR_ALERT_POLICY,
    )


def test_absence_true_violation(tmp_path: Path) -> None:
    m3_scenarios.test_absence_aggregation_scenarios_respect_pack_observation_authority(
        tmp_path,
        "enough_not_worn",
        ScreeningDecision.ESTABLISHED,
        CaseStatus.READY_FOR_ALERT_POLICY,
        VerdictDecision.ESTABLISHED,
    )


def test_absence_detector_miss_but_worn(tmp_path: Path) -> None:
    m3_scenarios.test_absence_aggregation_scenarios_respect_pack_observation_authority(
        tmp_path,
        "clear_worn",
        ScreeningDecision.NOT_ESTABLISHED,
        CaseStatus.READY_FOR_ALERT_POLICY,
        VerdictDecision.NOT_ESTABLISHED,
    )


def test_absence_all_unclear(tmp_path: Path) -> None:
    m3_scenarios.test_absence_aggregation_scenarios_respect_pack_observation_authority(
        tmp_path,
        "all_unclear",
        ScreeningDecision.ESCALATE,
        CaseStatus.ESCALATED,
        None,
    )


def test_absence_don_after_threshold() -> None:
    m1_fsm.test_strict_recovery_and_track_loss_cannot_erase_pending_history()


def test_late_result_inside_interval() -> None:
    m1_fsm.test_late_positive_batch_is_typed_atomic_stable_and_auditable()


def test_fabricated_crop_reference(tmp_path: Path) -> None:
    m3_scenarios.test_unknown_crop_in_failed_attempt_survives_repair_and_is_rejected_by_l5(tmp_path)


def test_objective_person_count_conflict(tmp_path: Path) -> None:
    m3_scenarios.test_objective_person_count_conflict_is_persisted_as_l5_rework(tmp_path)


def test_unanswered_defense() -> None:
    hearing_domain.test_missing_defense_response_is_preserved_for_l5()


def test_precedent_direction_mismatch() -> None:
    procedural_gate.test_precedent_lookup_and_direction_are_authoritative(
        "direction",
        ProceduralDefectCode.PRECEDENT_DIRECTION_MISMATCH,
    )


def test_provider_outage(tmp_path: Path) -> None:
    m3_scenarios.test_provider_outage_enters_typed_screening_backlog_offline(tmp_path)


def test_hard_signal_uncertified() -> None:
    m1_sources.test_video_heuristic_is_downgraded_to_non_hard_candidate()


def test_appeal_overturn(tmp_path: Path, monkeypatch) -> None:
    appeal_cli.test_m5_appeal_cli_runs_explicit_overturn_chain_and_rejects_terminal_reopen(
        tmp_path,
        monkeypatch,
    )


def test_replay_locked_identical(tmp_path: Path) -> None:
    closed_replay.test_real_fast_closed_policy_replay_reaches_pending_record_and_seal(tmp_path)


def test_upgrade_flip_gate() -> None:
    regression_contracts.test_upgrade_machine_flip_gate_uses_exact_five_percent_decimal_boundary(
        19,
        M6RegressionDisposition.FAILED,
        M6RegressionGateReason.MACHINE_FLIP_RATE_EXCEEDED,
    )
