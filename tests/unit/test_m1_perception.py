from __future__ import annotations

from collections.abc import Iterable

import pytest
from pydantic import ValidationError

from labcourt.contracts.config import AssociationConfig, ObservabilityWeights, ZoneConfig
from labcourt.contracts.detections import Detection, FrameBundle, Keypoint
from labcourt.contracts.enums import (
    AssociationMethod,
    ObservationSource,
    PpeType,
    RiskLevel,
)
from labcourt.contracts.evidence import ObservabilityComponents
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY, Polygon
from labcourt.domain.association import associate_ppe
from labcourt.domain.observability import score_observability
from labcourt.domain.zones import locate_person_zone, person_footpoint, point_in_polygon

TRACK_REF = "cam-01:epoch-01:person-01"
MODEL_MANIFEST_ID = "b" * 64
ASSOCIATION = AssociationConfig(iou_threshold=0.15, keypoint_threshold=0.30)


def _frame(*, width: int = 200, height: int = 200) -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id="stream-01",
        frame_index=7,
        fps_num=30,
        fps_den=1,
        width=width,
        height=height,
        content_sha256="a" * 64,
    )


def _detection(
    detection_id: str,
    label: str,
    bbox: BBoxXYXY,
    *,
    frame: FrameRef | None = None,
    score: float = 0.90,
    track_ref: str | None = None,
    keypoints: Iterable[Keypoint] = (),
) -> Detection:
    source_frame = frame or _frame()
    return Detection(
        detection_id=detection_id,
        frame_id=source_frame.frame_id,
        label=label,
        bbox=bbox,
        score=score,
        track_ref=track_ref,
        keypoints=tuple(keypoints),
        model_manifest_id=MODEL_MANIFEST_ID,
    )


def _person(
    *,
    frame: FrameRef | None = None,
    bbox: BBoxXYXY | None = None,
    keypoints: Iterable[Keypoint] = (),
) -> Detection:
    return _detection(
        "person-01",
        "person",
        bbox or BBoxXYXY(x1=20, y1=10, x2=180, y2=190),
        frame=frame,
        track_ref=TRACK_REF,
        keypoints=keypoints,
    )


def _zone(zone_id: str, points: list[tuple[int, int]]) -> ZoneConfig:
    return ZoneConfig(
        zone_id=zone_id,
        camera_id="cam-01",
        polygon=points,
        risk_level=RiskLevel.HIGH,
        required_ppe=(PpeType.GOGGLES,),
        reminder_channel="display-01",
    )


@pytest.mark.parametrize(
    ("x", "y", "expected"),
    [
        (50, 50, True),
        (0, 0, True),
        (100, 50, True),
        (100.5, 50, False),
        (-0.5, 0, False),
    ],
)
def test_point_in_polygon_uses_closed_boundary_semantics(
    x: float,
    y: float,
    expected: bool,
) -> None:
    polygon = Polygon(points=((0, 0), (100, 0), (100, 100), (0, 100)))
    assert point_in_polygon(x, y, polygon) is expected


def test_person_footpoint_zone_assignment_is_stable_on_shared_boundary() -> None:
    frame = _frame()
    person = _person(bbox=BBoxXYXY(x1=40, y1=10, x2=60, y2=50))
    zone_b = _zone("zone-b", [(50, 0), (100, 0), (100, 100), (50, 100)])
    zone_a = _zone("zone-a", [(0, 0), (50, 0), (50, 100), (0, 100)])

    assert person_footpoint(person.bbox) == (50.0, 50.0)
    assert locate_person_zone(frame, person, (zone_b, zone_a)) == zone_a
    assert locate_person_zone(frame, person, (zone_a, zone_b)) == zone_a


def test_overlapping_zones_with_conflicting_policies_fail_closed() -> None:
    frame = _frame()
    person = _person(bbox=BBoxXYXY(x1=40, y1=10, x2=60, y2=50))
    zone_a = _zone("zone-a", [(0, 0), (60, 0), (60, 100), (0, 100)])
    zone_b = _zone("zone-b", [(40, 0), (100, 0), (100, 100), (40, 100)]).model_copy(
        update={"required_ppe": (PpeType.GLOVES,)}
    )

    with pytest.raises(ValueError, match="conflicting policies"):
        locate_person_zone(frame, person, (zone_a, zone_b))


@pytest.mark.parametrize(
    ("ppe_type", "keypoints", "expected_bbox"),
    [
        (
            PpeType.GOGGLES,
            (
                Keypoint(name="nose", x=100.0, y=35.0, score=0.30),
                Keypoint(name="left_eye", x=90.0, y=30.0, score=0.90),
                Keypoint(name="right_eye", x=110.0, y=30.0, score=0.90),
                Keypoint(name="left_ear", x=80.0, y=32.0, score=0.90),
                Keypoint(name="right_ear", x=120.0, y=32.0, score=0.90),
            ),
            BBoxXYXY(x1=72, y1=21, x2=128, y2=44),
        ),
        (
            PpeType.GLOVES,
            (
                Keypoint(name="left_wrist", x=60.0, y=110.0, score=0.90),
                Keypoint(name="right_wrist", x=140.0, y=110.0, score=0.90),
            ),
            BBoxXYXY(x1=52, y1=101, x2=148, y2=119),
        ),
        (
            PpeType.LAB_COAT,
            (
                Keypoint(name="left_shoulder", x=70.0, y=60.0, score=0.90),
                Keypoint(name="right_shoulder", x=130.0, y=60.0, score=0.90),
                Keypoint(name="left_hip", x=80.0, y=130.0, score=0.90),
                Keypoint(name="right_hip", x=120.0, y=130.0, score=0.90),
            ),
            BBoxXYXY(x1=62, y1=51, x2=138, y2=139),
        ),
    ],
)
def test_each_ppe_type_builds_anchor_from_at_threshold_keypoints(
    ppe_type: PpeType,
    keypoints: tuple[Keypoint, ...],
    expected_bbox: BBoxXYXY,
) -> None:
    frame = _frame()
    result = associate_ppe(
        FrameBundle(frame=frame, detections=(_person(keypoints=keypoints),)),
        TRACK_REF,
        ppe_type,
        score_threshold=0.35,
        config=ASSOCIATION,
    )

    assert result.anchor_bbox == expected_bbox
    assert result.method == AssociationMethod.KEYPOINT
    assert result.quality_flags == ()
    assert result.present is False


def test_missing_qualifying_keypoints_uses_body_fallback_clipped_to_frame() -> None:
    frame = _frame(width=40, height=60)
    person = _person(
        frame=frame,
        bbox=BBoxXYXY(x1=0, y1=0, x2=30, y2=50),
        keypoints=(Keypoint(name="nose", x=0.0, y=0.0, score=0.29),),
    )
    goggles = _detection(
        "goggles-01",
        "goggles",
        BBoxXYXY(x1=8, y1=2, x2=22, y2=14),
        frame=frame,
    )

    result = associate_ppe(
        FrameBundle(frame=frame, detections=(goggles, person)),
        TRACK_REF,
        PpeType.GOGGLES,
        score_threshold=0.35,
        config=ASSOCIATION,
    )

    assert result.method == AssociationMethod.BODY_FALLBACK
    assert result.quality_flags == ("NO_QUALIFYING_KEYPOINTS",)
    assert result.anchor_bbox == BBoxXYXY(x1=6, y1=0, x2=24, y2=18)
    assert result.anchor_bbox.is_within(frame.width, frame.height)
    assert result.present is True


def test_ppe_matches_are_stable_and_respect_score_and_iou_thresholds() -> None:
    frame = _frame()
    head_keypoints = (
        Keypoint(name="nose", x=100.0, y=35.0, score=0.90),
        Keypoint(name="left_eye", x=90.0, y=30.0, score=0.90),
        Keypoint(name="right_eye", x=110.0, y=30.0, score=0.90),
        Keypoint(name="left_ear", x=80.0, y=32.0, score=0.90),
        Keypoint(name="right_ear", x=120.0, y=32.0, score=0.90),
    )
    person = _person(keypoints=head_keypoints)
    detections = (
        _detection("z-match", "goggles", BBoxXYXY(x1=82, y1=23, x2=119, y2=42)),
        _detection("outside", "goggles", BBoxXYXY(x1=0, y1=150, x2=20, y2=170)),
        _detection(
            "low-score",
            "goggles",
            BBoxXYXY(x1=80, y1=22, x2=120, y2=42),
            score=0.34,
        ),
        _detection("a-match", "goggles", BBoxXYXY(x1=80, y1=22, x2=120, y2=42)),
        person,
    )

    forward = associate_ppe(
        FrameBundle(frame=frame, detections=detections),
        TRACK_REF,
        PpeType.GOGGLES,
        score_threshold=0.35,
        config=ASSOCIATION,
    )
    reversed_order = associate_ppe(
        FrameBundle(frame=frame, detections=tuple(reversed(detections))),
        TRACK_REF,
        PpeType.GOGGLES,
        score_threshold=0.35,
        config=ASSOCIATION,
    )

    assert forward == reversed_order
    assert forward.present is True
    assert forward.matched_detection_ids == ("a-match", "z-match")


def test_frame_bundle_rejects_out_of_frame_bbox_and_keypoint() -> None:
    frame = _frame()
    bbox_outside = _person(bbox=BBoxXYXY(x1=20, y1=10, x2=201, y2=190))
    keypoint_outside = _person(keypoints=(Keypoint(name="nose", x=200.0, y=20.0, score=0.90),))

    with pytest.raises(ValidationError, match="bbox exceeds frame bounds"):
        FrameBundle(frame=frame, detections=(bbox_outside,))
    with pytest.raises(ValidationError, match="keypoint outside frame bounds"):
        FrameBundle(frame=frame, detections=(keypoint_outside,))


def test_precomputed_observability_uses_all_six_weights_without_gating() -> None:
    weights = ObservabilityWeights(
        person_confidence=0.15,
        keypoint_visibility=0.25,
        frontality=0.20,
        sharpness=0.20,
        exposure=0.10,
        non_occlusion=0.10,
    )
    components = ObservabilityComponents(
        person_confidence=0.80,
        keypoint_visibility=0.60,
        frontality=0.40,
        sharpness=0.20,
        exposure=1.00,
        non_occlusion=0.50,
    )

    score = score_observability(
        components,
        weights,
        source=ObservationSource.PRECOMPUTED_FIXTURE,
    )

    assert score.total == pytest.approx(0.54)
    assert score.components == components
    assert score.source == ObservationSource.PRECOMPUTED_FIXTURE

    zero = ObservabilityComponents(
        person_confidence=0.0,
        keypoint_visibility=0.0,
        frontality=0.0,
        sharpness=0.0,
        exposure=0.0,
        non_occlusion=0.0,
    )
    low_score = score_observability(
        zero,
        weights,
        source=ObservationSource.PRECOMPUTED_FIXTURE,
    )
    assert low_score.total == 0.0
    # A low score remains a record for evidence ranking; no trigger/presence gate is emitted.
    assert not hasattr(low_score, "trigger_allowed")
