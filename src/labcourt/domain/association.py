"""Deterministic PPE anchor construction and detection association."""

from __future__ import annotations

from math import ceil, floor, isfinite

from labcourt.contracts.config import AssociationConfig
from labcourt.contracts.detections import AssociationResult, Detection, FrameBundle
from labcourt.contracts.enums import AssociationMethod, PpeType
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.references import require_track_ref_camera

_PPE_LABELS = {
    PpeType.GOGGLES: "goggles",
    PpeType.GLOVES: "gloves",
    PpeType.LAB_COAT: "lab_coat",
}

_KEYPOINT_NAMES = {
    PpeType.GOGGLES: ("nose", "left_eye", "right_eye", "left_ear", "right_ear"),
    PpeType.GLOVES: ("left_wrist", "right_wrist"),
    PpeType.LAB_COAT: ("left_shoulder", "right_shoulder", "left_hip", "right_hip"),
}

# Fractions of the person box: x1, y1, x2, y2. These are deliberately fixed domain
# constants until calibration produces a versioned configuration contract.
_BODY_FALLBACK_RATIOS = {
    PpeType.GOGGLES: (0.20, 0.00, 0.80, 0.35),
    PpeType.GLOVES: (0.00, 0.30, 1.00, 0.85),
    PpeType.LAB_COAT: (0.10, 0.20, 0.90, 0.80),
}

_KEYPOINT_PADDING_RATIO = 0.05


def _bounded_bbox(
    *,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    frame_width: int,
    frame_height: int,
) -> BBoxXYXY:
    left = max(0, min(frame_width - 1, floor(x1)))
    top = max(0, min(frame_height - 1, floor(y1)))
    right = max(left + 1, min(frame_width, ceil(x2)))
    bottom = max(top + 1, min(frame_height, ceil(y2)))
    return BBoxXYXY(x1=left, y1=top, x2=right, y2=bottom)


def _body_fallback_anchor(
    person: Detection,
    ppe_type: PpeType,
    *,
    frame_width: int,
    frame_height: int,
) -> BBoxXYXY:
    x1_ratio, y1_ratio, x2_ratio, y2_ratio = _BODY_FALLBACK_RATIOS[ppe_type]
    body = person.bbox
    return _bounded_bbox(
        x1=body.x1 + body.width * x1_ratio,
        y1=body.y1 + body.height * y1_ratio,
        x2=body.x1 + body.width * x2_ratio,
        y2=body.y1 + body.height * y2_ratio,
        frame_width=frame_width,
        frame_height=frame_height,
    )


def _ppe_anchor(
    person: Detection,
    ppe_type: PpeType,
    *,
    frame_width: int,
    frame_height: int,
    keypoint_threshold: float,
) -> tuple[BBoxXYXY, AssociationMethod, tuple[str, ...]]:
    expected_names = _KEYPOINT_NAMES[ppe_type]
    keypoints_by_name = {keypoint.name: keypoint for keypoint in person.keypoints}
    qualifying = tuple(
        keypoints_by_name[name]
        for name in expected_names
        if name in keypoints_by_name and keypoints_by_name[name].score >= keypoint_threshold
    )
    if not qualifying:
        return (
            _body_fallback_anchor(
                person,
                ppe_type,
                frame_width=frame_width,
                frame_height=frame_height,
            ),
            AssociationMethod.BODY_FALLBACK,
            ("NO_QUALIFYING_KEYPOINTS",),
        )

    pad_x = max(1, ceil(person.bbox.width * _KEYPOINT_PADDING_RATIO))
    pad_y = max(1, ceil(person.bbox.height * _KEYPOINT_PADDING_RATIO))
    anchor = _bounded_bbox(
        x1=min(keypoint.x for keypoint in qualifying) - pad_x,
        y1=min(keypoint.y for keypoint in qualifying) - pad_y,
        x2=max(keypoint.x for keypoint in qualifying) + pad_x,
        y2=max(keypoint.y for keypoint in qualifying) + pad_y,
        frame_width=frame_width,
        frame_height=frame_height,
    )
    quality_flags = () if len(qualifying) == len(expected_names) else ("PARTIAL_KEYPOINT_SET",)
    return anchor, AssociationMethod.KEYPOINT, quality_flags


def associate_ppe(
    frame: FrameBundle,
    track_ref: str,
    ppe_type: PpeType,
    *,
    score_threshold: float,
    config: AssociationConfig,
) -> AssociationResult:
    """Associate normalized PPE detections with one tracked person's anchor.

    Candidate detections are traversed by ``detection_id`` rather than provider order.
    Observability is intentionally absent: it may rank evidence frames, but must never
    suppress this association signal or a downstream trigger.
    """

    if isinstance(score_threshold, bool) or not isinstance(score_threshold, int | float):
        raise TypeError("score_threshold must be numeric")
    if not isfinite(score_threshold) or not 0 <= score_threshold <= 1:
        raise ValueError("score_threshold must be within [0, 1]")
    require_track_ref_camera(track_ref, frame.frame.camera_id)

    people = sorted(
        (
            detection
            for detection in frame.detections
            if detection.label == "person" and detection.track_ref == track_ref
        ),
        key=lambda detection: detection.detection_id,
    )
    if len(people) != 1:
        raise ValueError("association requires exactly one person detection for track_ref")
    person = people[0]
    person.bbox.require_within(frame.frame.width, frame.frame.height)

    anchor, method, quality_flags = _ppe_anchor(
        person,
        ppe_type,
        frame_width=frame.frame.width,
        frame_height=frame.frame.height,
        keypoint_threshold=config.keypoint_threshold,
    )
    anchor.require_within(frame.frame.width, frame.frame.height)

    ppe_label = _PPE_LABELS[ppe_type]
    candidates = sorted(
        (detection for detection in frame.detections if detection.label == ppe_label),
        key=lambda detection: detection.detection_id,
    )
    matched_detection_ids = tuple(
        detection.detection_id
        for detection in candidates
        if detection.score >= score_threshold and detection.bbox.iou(anchor) >= config.iou_threshold
    )
    return AssociationResult(
        present=bool(matched_detection_ids),
        anchor_bbox=anchor,
        matched_detection_ids=matched_detection_ids,
        method=method,
        quality_flags=quality_flags,
    )
