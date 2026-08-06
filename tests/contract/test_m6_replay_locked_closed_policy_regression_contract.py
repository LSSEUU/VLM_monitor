from __future__ import annotations

from labcourt.application.m6_replay_locked_closed_policy_regression import (
    assemble_m6_replay_locked_closed_policy_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6RegressionReport
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
)
from tests.unit.test_m6_replay_locked_closed_policy_regression import (
    _document,
    _facts,
)


def test_closed_policy_seal_v2_is_compatible_with_frozen_report_v1() -> None:
    facts = _facts()

    bundle = assemble_m6_replay_locked_closed_policy_regression_report(
        stored_source_catalog=facts.stored_catalog,
        evaluator_dataset=facts.dataset,
        evaluator_dataset_document=_document(facts.dataset),
        execution_seal=facts.seal,
        execution_seal_document=_document(facts.seal),
    )
    round_trip = M6RegressionReport.model_validate_json(bundle.report_document)

    assert round_trip == bundle.report
    assert round_trip.schema_version == "m6-regression-report-v1"
    assert facts.seal.schema_version == (
        "m6-replay-locked-closed-policy-execution-seal-authority-v2"
    )
    assert round_trip.execution_receipts == facts.seal.execution_receipts
    assert len(round_trip.results) == facts.seal.sample_execution_count
    assert "candidate_output_inventory" not in bundle.report_document


def test_closed_policy_seal_receipts_are_derived_and_canonical() -> None:
    seal = _facts().seal
    round_trip = M6ReplayLockedClosedPolicyExecutionSealAuthorityV2.model_validate_json(
        canonical_json(seal.model_dump(mode="json"))
    )

    assert round_trip == seal
    assert round_trip.execution_receipt_count == round_trip.sample_execution_count
    assert tuple(item.sample_id for item in round_trip.execution_receipts) == tuple(
        item.sample_id for item in round_trip.sample_executions
    )
