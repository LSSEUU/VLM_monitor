from __future__ import annotations

import pytest

from labcourt.contracts.acquisition_matrix import (
    ACQUISITION_TOOL_RULES,
    AcquisitionOutputKind,
    AcquisitionSourceBinding,
    AcquisitionToolRule,
    acquisition_output_counts_match,
    acquisition_parameter_matches_action,
    acquisition_tool_rule,
)
from labcourt.contracts.enums import AcquisitionAction
from labcourt.contracts.evidence import RequestMoreFramesParameters
from labcourt.contracts.hearing import MAX_ACQUISITION_RETURNED_FRAMES

_COUNT_FIELD = {
    AcquisitionOutputKind.FRAME: "frames",
    AcquisitionOutputKind.CROP: "crops",
    AcquisitionOutputKind.OBJECTIVE_FACT: "objective_facts",
    AcquisitionOutputKind.DETECTION: "detections",
}


def _counts(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "frames": 0,
        "crops": 0,
        "objective_facts": 0,
        "detections": 0,
    }
    values.update(updates)
    return values


def test_frozen_matrix_covers_every_action_once_in_stable_order() -> None:
    actions = tuple(rule.action for rule in ACQUISITION_TOOL_RULES)

    assert actions == tuple(sorted(AcquisitionAction, key=lambda item: item.value))
    assert len(actions) == len(set(actions))
    assert {
        rule.action: (rule.output_kind, rule.source_binding) for rule in ACQUISITION_TOOL_RULES
    } == {
        AcquisitionAction.REQUEST_MORE_FRAMES: (
            AcquisitionOutputKind.FRAME,
            AcquisitionSourceBinding.CURRENT_PACK_ONLY,
        ),
        AcquisitionAction.RECROP: (
            AcquisitionOutputKind.CROP,
            AcquisitionSourceBinding.RECROP_DERIVED_SOURCES,
        ),
        AcquisitionAction.OTHER_CAMERA_SAME_TIME: (
            AcquisitionOutputKind.FRAME,
            AcquisitionSourceBinding.SOURCE_FRAME,
        ),
        AcquisitionAction.TRACK_CONFIDENCE_CURVE: (
            AcquisitionOutputKind.OBJECTIVE_FACT,
            AcquisitionSourceBinding.CURRENT_PACK_ONLY,
        ),
        AcquisitionAction.REDETECT_HIGH_RES: (
            AcquisitionOutputKind.DETECTION,
            AcquisitionSourceBinding.SOURCE_CROP,
        ),
    }


@pytest.mark.parametrize("rule", ACQUISITION_TOOL_RULES)
def test_parameter_discriminator_and_output_cardinality_are_exact(
    rule: AcquisitionToolRule,
) -> None:
    correct = rule.parameters_type.model_construct()
    wrong_type = next(
        candidate.parameters_type
        for candidate in ACQUISITION_TOOL_RULES
        if candidate.parameters_type is not rule.parameters_type
    )
    selected = _COUNT_FIELD[rule.output_kind]

    assert acquisition_tool_rule(rule.action) == rule
    assert acquisition_parameter_matches_action(rule.action, correct)
    assert not acquisition_parameter_matches_action(
        rule.action,
        wrong_type.model_construct(),
    )
    assert acquisition_output_counts_match(
        rule.action,
        **_counts(**{selected: rule.min_outputs}),
    )
    assert acquisition_output_counts_match(
        rule.action,
        **_counts(**{selected: rule.max_outputs}),
    )
    assert not acquisition_output_counts_match(rule.action, **_counts())
    assert not acquisition_output_counts_match(
        rule.action,
        **_counts(**{selected: rule.max_outputs + 1}),
    )
    mixed = "crops" if selected != "crops" else "frames"
    assert not acquisition_output_counts_match(
        rule.action,
        **_counts(**{selected: rule.min_outputs, mixed: 1}),
    )


@pytest.mark.parametrize("value", (-1, True, 1.5, "1"))
def test_output_counts_are_strict_nonnegative_integers(value: object) -> None:
    assert not acquisition_output_counts_match(
        AcquisitionAction.REQUEST_MORE_FRAMES,
        **_counts(frames=value),
    )


def test_rule_lookup_rejects_non_enum_action() -> None:
    with pytest.raises(TypeError):
        acquisition_tool_rule("RECROP")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("updates", "error"),
    (
        ({"action": "RECROP"}, TypeError),
        ({"output_kind": "CROP"}, TypeError),
        ({"source_binding": "SOURCE_CROP"}, TypeError),
        ({"parameters_type": object()}, TypeError),
        ({"min_outputs": True}, TypeError),
        ({"max_outputs": True}, TypeError),
        ({"min_outputs": 0}, ValueError),
        ({"min_outputs": 2, "max_outputs": 1}, ValueError),
        (
            {"max_outputs": MAX_ACQUISITION_RETURNED_FRAMES + 1},
            ValueError,
        ),
    ),
)
def test_rule_contract_rejects_impossible_rows(
    updates: dict[str, object],
    error: type[Exception],
) -> None:
    values: dict[str, object] = {
        "action": AcquisitionAction.REQUEST_MORE_FRAMES,
        "parameters_type": RequestMoreFramesParameters,
        "output_kind": AcquisitionOutputKind.FRAME,
        "min_outputs": 1,
        "max_outputs": 2,
        "source_binding": AcquisitionSourceBinding.CURRENT_PACK_ONLY,
    }
    values.update(updates)

    with pytest.raises(error):
        AcquisitionToolRule(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", (-1, True, 1.5))
def test_rule_count_predicate_is_strict(value: object) -> None:
    assert not ACQUISITION_TOOL_RULES[0].accepts_output_count(value)
