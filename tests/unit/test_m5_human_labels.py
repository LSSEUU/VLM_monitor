from __future__ import annotations

import pytest

from labcourt.application.m5_human_labels import build_m5_appeal_training_labels
from labcourt.contracts.enums import AppealStatus, TrainingLabelQuality
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_appeals import AppealSubmissionCommand
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.domain.appeal_fsm import submit_appeal
from labcourt.exceptions import ContractViolation
from tests.unit.test_m5_appeal_resolution import _case, _reviewed


def _input(*, crop_id: str = "e" * 64) -> M5AppealTrainingLabelInput:
    return M5AppealTrainingLabelInput(
        crop_id=crop_id,
        bbox=BBoxXYXY(x1=1, y1=2, x2=20, y2=30),
        label_name="reagent_container_closed",
        label_value=True,
    )


def test_human_label_input_binds_reviewer_case_manifest_and_quality() -> None:
    reviewed = _reviewed(_case())
    labels = build_m5_appeal_training_labels(
        appeal_authority=reviewed,
        terminal_status=AppealStatus.OVERTURNED,
        authored_inputs=(_input(),),
    )

    assert len(labels) == 1
    label = labels[0]
    assert label.case_id == reviewed.appeal.case_id
    assert label.reviewer_id == reviewed.assigned_reviewer_id
    assert label.quality == TrainingLabelQuality.APPEAL_CONFIRMED
    assert label.detector_manifest_id == reviewed.source_case_authority.detector_manifest_id
    assert label.source == "appeal-review:appeal-1"


def test_upheld_human_label_is_confirmed_but_never_weak_ground_truth() -> None:
    labels = build_m5_appeal_training_labels(
        appeal_authority=_reviewed(_case()),
        terminal_status=AppealStatus.UPHELD,
        authored_inputs=(_input(),),
    )
    assert labels[0].quality == TrainingLabelQuality.HUMAN_CONFIRMED


def test_human_label_builder_requires_current_review_and_unique_facts() -> None:
    case = _case()
    reviewed = _reviewed(case)
    with pytest.raises(ContractViolation, match="duplicate"):
        build_m5_appeal_training_labels(
            appeal_authority=reviewed,
            terminal_status=AppealStatus.OVERTURNED,
            authored_inputs=(_input(), _input()),
        )
    submitted = submit_appeal(
        case,
        AppealSubmissionCommand(
            run_id=case.run_id,
            case_id=case.case_id,
            appeal_id="appeal-other",
            expected_case_revision=case.case_revision,
            expected_case_authority_sha256=case.authority_sha256,
            reason="Explicit human-authored appeal reason.",
            submitted_by="subject-1",
        ),
        None,
    )
    with pytest.raises(ContractViolation, match="UNDER_REVIEW"):
        build_m5_appeal_training_labels(
            appeal_authority=submitted,
            terminal_status=AppealStatus.OVERTURNED,
            authored_inputs=(_input(),),
        )
