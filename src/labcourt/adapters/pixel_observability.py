"""Bounded deterministic RGB8 observability measurements for pilot evidence ranking."""

from __future__ import annotations

from math import isqrt

from labcourt.contracts.config import ObservabilityWeights
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import ObservationSource
from labcourt.contracts.evidence import ObservabilityComponents, ObservabilityScore
from labcourt.domain.observability import score_observability
from labcourt.ports.pixels import RGB8Frame

PILOT_PIXEL_OBSERVABILITY_POLICY = "RGB8_PERSON_GRID_MAE_V1"
_MAX_SAMPLED_PIXELS = 4_096
_SHARPNESS_NORMALIZER = 64.0
_FACE_KEYPOINTS = frozenset({"left_eye", "right_eye", "nose", "left_ear", "right_ear"})


def _luma(pixels: bytes, offset: int) -> int:
    return (77 * pixels[offset] + 150 * pixels[offset + 1] + 29 * pixels[offset + 2]) >> 8


def _pixel_scores(frame: RGB8Frame, person: Detection) -> tuple[float, float]:
    bbox = person.bbox
    bbox.require_within(frame.frame.width, frame.frame.height)
    area = bbox.width * bbox.height
    step = max(1, isqrt(max(1, area // _MAX_SAMPLED_PIXELS)))
    stride = frame.frame.width * 3
    luma_sum = 0
    sample_count = 0
    difference_sum = 0
    difference_count = 0
    for y in range(bbox.y1, bbox.y2, step):
        for x in range(bbox.x1, bbox.x2, step):
            offset = y * stride + x * 3
            value = _luma(frame.pixels, offset)
            luma_sum += value
            sample_count += 1
            right = x + step
            if right < bbox.x2:
                difference_sum += abs(value - _luma(frame.pixels, y * stride + right * 3))
                difference_count += 1
            below = y + step
            if below < bbox.y2:
                difference_sum += abs(value - _luma(frame.pixels, below * stride + x * 3))
                difference_count += 1
    mean_luma = luma_sum / sample_count
    exposure = max(0.0, 1.0 - abs(mean_luma - 127.5) / 127.5)
    mean_difference = difference_sum / difference_count if difference_count else 0.0
    sharpness = min(1.0, mean_difference / _SHARPNESS_NORMALIZER)
    return float(sharpness), float(exposure)


def _keypoint_scores(person: Detection) -> tuple[float, float]:
    visible = tuple(keypoint for keypoint in person.keypoints if keypoint.name in _FACE_KEYPOINTS)
    visibility = (
        sum(float(keypoint.score) for keypoint in visible) / len(_FACE_KEYPOINTS)
        if visible
        else 0.0
    )
    by_name = {keypoint.name: keypoint for keypoint in visible}
    left_eye = by_name.get("left_eye")
    right_eye = by_name.get("right_eye")
    if left_eye is None or right_eye is None:
        return float(visibility), 0.0
    eye_span = max(1.0, abs(float(right_eye.x) - float(left_eye.x)))
    vertical_difference = abs(float(right_eye.y) - float(left_eye.y))
    frontality = max(0.0, 1.0 - vertical_difference / eye_span)
    return float(visibility), float(frontality)


def score_person_rgb8_observability(
    frame: RGB8Frame,
    person: Detection,
    weights: ObservabilityWeights,
) -> ObservabilityScore:
    """Score one tracked person without using observability as a trigger gate."""

    if not isinstance(frame, RGB8Frame):
        raise TypeError("pilot observability requires an RGB8Frame")
    if not isinstance(person, Detection) or person.label != "person":
        raise TypeError("pilot observability requires a person Detection")
    if person.frame_id != frame.frame.frame_id:
        raise ValueError("pilot observability detection belongs to another frame")
    sharpness, exposure = _pixel_scores(frame, person)
    keypoint_visibility, frontality = _keypoint_scores(person)
    bbox = person.bbox
    clear_edges = sum(
        (
            bbox.x1 > 0,
            bbox.y1 > 0,
            bbox.x2 < frame.frame.width,
            bbox.y2 < frame.frame.height,
        )
    )
    components = ObservabilityComponents(
        person_confidence=float(person.score),
        keypoint_visibility=keypoint_visibility,
        frontality=frontality,
        sharpness=sharpness,
        exposure=exposure,
        non_occlusion=float(clear_edges / 4.0),
    )
    return score_observability(
        components,
        weights,
        source=ObservationSource.PIXEL_COMPUTED,
    )


__all__ = [
    "PILOT_PIXEL_OBSERVABILITY_POLICY",
    "score_person_rgb8_observability",
]
