from __future__ import annotations

import pytest

from labcourt.application.hearing_session import (
    HearingSessionPreparationError,
    HearingSessionPreparationFailureCode,
    prepare_hearing_session,
)
from labcourt.contracts.enums import CaseStatus
from labcourt.ports.evidence_repository import CaseSnapshot
from tests.unit.test_m3_screening_coordinator import (
    _harness,
    _raw_payload,
    _replace_case,
    _screening_fixture,
)
from tests.unit.test_m4_hearing_request import _catalog


def test_escalated_case_prepares_exact_first_cycle_without_side_effects() -> None:
    harness = _harness()
    screening, _ = _screening_fixture(harness, 0.5)
    snapshot = _replace_case(
        harness.evidence.snapshot,
        status=CaseStatus.ESCALATED.value,
        screening_results=[screening.model_dump(mode="json")],
    )

    prepared = prepare_hearing_session(
        snapshot,
        config=harness.config,
        run_manifest=harness.manifest,
        catalog=_catalog(),
    )

    assert prepared.source_case == snapshot
    assert prepared.evidence_pack == harness.pack
    assert prepared.session.screening_id == screening.screening_id
    assert prepared.session.initial_trigger_review_ref is None
    assert prepared.session.initial_defect_codes == ()
    assert prepared.session.acquisition_round_limit == 2
    assert prepared.session.rework_round_limit == 2
    assert prepared.cycle_scope.cycle_index == 1
    assert prepared.checkpoint.judge_cycle == 1
    assert prepared.checkpoint.prior_acquisition_rounds == 0
    assert prepared.checkpoint.prior_rework_rounds == 0


def test_failed_m3_fast_verdict_enters_cycle_one_without_spending_m4_rework() -> None:
    base = _harness()
    invalid = _raw_payload(
        base.pack,
        0.95,
        unknown_reference=True,
        missing_required_field=True,
    )
    repaired = _raw_payload(base.pack, 0.95)
    harness = _harness(results=[invalid, repaired])
    outcome = harness.coordinator.process_case(
        harness.pack.run_id,
        harness.pack.case_id,
    )
    assert outcome.case.case.status == CaseStatus.REWORK_REQUIRED
    assert outcome.procedural_review is not None
    assert not outcome.procedural_review.passed

    prepared = prepare_hearing_session(
        outcome.case,
        config=harness.config,
        run_manifest=harness.manifest,
        catalog=_catalog(),
    )

    assert prepared.session.initial_trigger_review_ref is not None
    assert prepared.session.initial_trigger_review_ref.artifact_id == (
        outcome.procedural_review.review_id
    )
    assert prepared.session.initial_defect_codes
    assert prepared.cycle_scope.prior_rework_rounds == 0
    assert prepared.checkpoint.prior_rework_rounds == 0
    assert prepared.checkpoint.judge_cycle == 1


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            {"status": CaseStatus.EVIDENCE_READY},
            HearingSessionPreparationFailureCode.INVALID_CASE_STATE,
        ),
        (
            {"screening_results": ()},
            HearingSessionPreparationFailureCode.CASE_AUTHORITY_MISMATCH,
        ),
    ],
)
def test_invalid_entry_authority_fails_closed(
    mutation: dict[str, object],
    expected: HearingSessionPreparationFailureCode,
) -> None:
    harness = _harness()
    screening, _ = _screening_fixture(harness, 0.5)
    valid_case = _replace_case(
        harness.evidence.snapshot,
        status=CaseStatus.ESCALATED.value,
        screening_results=[screening.model_dump(mode="json")],
    ).case
    # ``model_construct`` deliberately bypasses aggregate validation; the
    # application boundary must not rely only on Case's original constructor.
    corrupt_payload = {**valid_case.__dict__, **mutation}
    corrupted = CaseSnapshot(
        case=type(valid_case).model_construct(**corrupt_payload),
        revision=3,
    )

    with pytest.raises(HearingSessionPreparationError) as captured:
        prepare_hearing_session(
            corrupted,
            config=harness.config,
            run_manifest=harness.manifest,
            catalog=_catalog(),
        )
    assert captured.value.reason_code == expected


def test_config_manifest_drift_is_not_opened_as_a_hearing() -> None:
    harness = _harness()
    screening, _ = _screening_fixture(harness, 0.5)
    snapshot = _replace_case(
        harness.evidence.snapshot,
        status=CaseStatus.ESCALATED.value,
        screening_results=[screening.model_dump(mode="json")],
    )
    drifted_hearing = harness.config.hearing.model_copy(
        update={"max_total_images": harness.config.hearing.max_total_images + 1}
    )
    drifted_config = harness.config.model_copy(update={"hearing": drifted_hearing})

    with pytest.raises(HearingSessionPreparationError) as captured:
        prepare_hearing_session(
            snapshot,
            config=drifted_config,
            run_manifest=harness.manifest,
            catalog=_catalog(),
        )
    assert (
        captured.value.reason_code == HearingSessionPreparationFailureCode.CONFIG_MANIFEST_MISMATCH
    )
