"""Frozen five-action M4 acquisition parameter/input/output matrix."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from labcourt.contracts.enums import AcquisitionAction
from labcourt.contracts.evidence import (
    AcquisitionParameters,
    OtherCameraSameTimeParameters,
    RecropParameters,
    RedetectHighResolutionParameters,
    RequestMoreFramesParameters,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.hearing_common import MAX_ACQUISITION_RETURNED_FRAMES


class AcquisitionOutputKind(StrEnum):
    """The only typed object group an action may publish."""

    FRAME = "FRAME"
    CROP = "CROP"
    OBJECTIVE_FACT = "OBJECTIVE_FACT"
    DETECTION = "DETECTION"


class AcquisitionSourceBinding(StrEnum):
    """Additional evidence authority consumed beside the current pack."""

    CURRENT_PACK_ONLY = "CURRENT_PACK_ONLY"
    RECROP_DERIVED_SOURCES = "RECROP_DERIVED_SOURCES"
    SOURCE_FRAME = "SOURCE_FRAME"
    SOURCE_CROP = "SOURCE_CROP"


@dataclass(frozen=True, slots=True)
class AcquisitionToolRule:
    """One immutable row in the five-action tool matrix."""

    action: AcquisitionAction
    parameters_type: type[AcquisitionParameters]
    output_kind: AcquisitionOutputKind
    min_outputs: int
    max_outputs: int
    source_binding: AcquisitionSourceBinding

    def __post_init__(self) -> None:
        if not isinstance(self.action, AcquisitionAction):
            raise TypeError("action must be an AcquisitionAction")
        if not isinstance(self.output_kind, AcquisitionOutputKind):
            raise TypeError("output_kind must be an AcquisitionOutputKind")
        if not isinstance(self.source_binding, AcquisitionSourceBinding):
            raise TypeError("source_binding must be an AcquisitionSourceBinding")
        if (
            not isinstance(self.parameters_type, type)
            or not isinstance(self.min_outputs, int)
            or isinstance(self.min_outputs, bool)
            or not isinstance(self.max_outputs, int)
            or isinstance(self.max_outputs, bool)
        ):
            raise TypeError("tool matrix parameter and cardinality types are invalid")
        if not 1 <= self.min_outputs <= self.max_outputs <= MAX_ACQUISITION_RETURNED_FRAMES:
            raise ValueError("tool matrix output cardinality is invalid")

    def accepts_output_count(self, value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and self.min_outputs <= value <= self.max_outputs
        )


_RULES = (
    AcquisitionToolRule(
        action=AcquisitionAction.REQUEST_MORE_FRAMES,
        parameters_type=RequestMoreFramesParameters,
        output_kind=AcquisitionOutputKind.FRAME,
        min_outputs=1,
        max_outputs=MAX_ACQUISITION_RETURNED_FRAMES,
        source_binding=AcquisitionSourceBinding.CURRENT_PACK_ONLY,
    ),
    AcquisitionToolRule(
        action=AcquisitionAction.RECROP,
        parameters_type=RecropParameters,
        output_kind=AcquisitionOutputKind.CROP,
        min_outputs=1,
        max_outputs=1,
        source_binding=AcquisitionSourceBinding.RECROP_DERIVED_SOURCES,
    ),
    AcquisitionToolRule(
        action=AcquisitionAction.OTHER_CAMERA_SAME_TIME,
        parameters_type=OtherCameraSameTimeParameters,
        output_kind=AcquisitionOutputKind.FRAME,
        min_outputs=1,
        max_outputs=MAX_ACQUISITION_RETURNED_FRAMES,
        source_binding=AcquisitionSourceBinding.SOURCE_FRAME,
    ),
    AcquisitionToolRule(
        action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
        parameters_type=TrackConfidenceCurveParameters,
        output_kind=AcquisitionOutputKind.OBJECTIVE_FACT,
        min_outputs=1,
        max_outputs=MAX_ACQUISITION_RETURNED_FRAMES,
        source_binding=AcquisitionSourceBinding.CURRENT_PACK_ONLY,
    ),
    AcquisitionToolRule(
        action=AcquisitionAction.REDETECT_HIGH_RES,
        parameters_type=RedetectHighResolutionParameters,
        output_kind=AcquisitionOutputKind.DETECTION,
        min_outputs=1,
        max_outputs=MAX_ACQUISITION_RETURNED_FRAMES,
        source_binding=AcquisitionSourceBinding.SOURCE_CROP,
    ),
)
ACQUISITION_TOOL_RULES = tuple(sorted(_RULES, key=lambda item: item.action.value))
_RULE_BY_ACTION = {rule.action: rule for rule in ACQUISITION_TOOL_RULES}


def acquisition_tool_rule(action: AcquisitionAction) -> AcquisitionToolRule:
    """Return the one frozen rule for an exact enum action."""

    if not isinstance(action, AcquisitionAction):
        raise TypeError("action must be an AcquisitionAction")
    return _RULE_BY_ACTION[action]


def acquisition_parameter_matches_action(
    action: AcquisitionAction,
    parameters: object,
) -> bool:
    """Reject action/parameter discriminator drift."""

    return type(parameters) is acquisition_tool_rule(action).parameters_type


def acquisition_output_counts_match(
    action: AcquisitionAction,
    *,
    frames: object,
    crops: object,
    objective_facts: object,
    detections: object,
) -> bool:
    """Check cardinality and exclusive output kind without inspecting content."""

    counts = {
        AcquisitionOutputKind.FRAME: frames,
        AcquisitionOutputKind.CROP: crops,
        AcquisitionOutputKind.OBJECTIVE_FACT: objective_facts,
        AcquisitionOutputKind.DETECTION: detections,
    }
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in counts.values()
    ):
        return False
    rule = acquisition_tool_rule(action)
    return rule.accepts_output_count(counts[rule.output_kind]) and all(
        value == 0 for kind, value in counts.items() if kind != rule.output_kind
    )


__all__ = [
    "ACQUISITION_TOOL_RULES",
    "AcquisitionOutputKind",
    "AcquisitionSourceBinding",
    "AcquisitionToolRule",
    "acquisition_output_counts_match",
    "acquisition_parameter_matches_action",
    "acquisition_tool_rule",
]
