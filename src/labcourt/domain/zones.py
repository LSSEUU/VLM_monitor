"""Deterministic zone membership for tracked people."""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction
from math import isfinite

from labcourt.contracts.config import ZoneConfig
from labcourt.contracts.detections import Detection
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY, Polygon


def _exact_coordinate(value: int | float) -> Fraction:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError("point coordinates must be integers or floats")
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("point coordinates must be finite")
        return Fraction.from_float(value)
    return Fraction(value, 1)


def _on_segment(
    point: tuple[Fraction, Fraction],
    start: tuple[Fraction, Fraction],
    end: tuple[Fraction, Fraction],
) -> bool:
    px, py = point
    ax, ay = start
    bx, by = end
    cross_product = (px - ax) * (by - ay) - (py - ay) * (bx - ax)
    return (
        cross_product == 0 and min(ax, bx) <= px <= max(ax, bx) and min(ay, by) <= py <= max(ay, by)
    )


def point_in_polygon(x: int | float, y: int | float, polygon: Polygon) -> bool:
    """Return membership in a closed polygon; every edge and vertex is inside.

    Coordinates are converted to exact rational values before ray casting. This keeps
    integer and half-pixel foot points deterministic and avoids epsilon-dependent edge
    decisions.
    """

    point = (_exact_coordinate(x), _exact_coordinate(y))
    vertices = tuple((Fraction(vertex.x, 1), Fraction(vertex.y, 1)) for vertex in polygon.points)
    inside = False
    for index, start in enumerate(vertices):
        end = vertices[(index + 1) % len(vertices)]
        if _on_segment(point, start, end):
            return True

        _, py = point
        _, ay = start
        _, by = end
        if (ay > py) == (by > py):
            continue
        ax, _ = start
        bx, _ = end
        crossing_x = ax + (py - ay) * (bx - ax) / (by - ay)
        if point[0] < crossing_x:
            inside = not inside
    return inside


def person_footpoint(bbox: BBoxXYXY) -> tuple[float, float]:
    """Return the bottom-edge centre of a closed-open person bounding box."""

    return ((bbox.x1 + bbox.x2) / 2.0, float(bbox.y2))


def locate_person_zone(
    frame: FrameRef,
    person: Detection,
    zones: Sequence[ZoneConfig],
) -> ZoneConfig | None:
    """Locate a person by foot point, with stable tie-breaking for shared boundaries.

    Polygon boundaries are inclusive. If valid zones overlap or share the foot point,
    the lexicographically smallest ``zone_id`` wins, independent of configuration order.
    """

    if person.label != "person":
        raise ValueError("zone assignment requires a person detection")
    if person.frame_id != frame.frame_id:
        raise ValueError("person detection references a different frame")
    person.bbox.require_within(frame.width, frame.height)
    if any(
        keypoint.x >= frame.width or keypoint.y >= frame.height for keypoint in person.keypoints
    ):
        raise ValueError("person keypoint exceeds frame bounds")

    zone_ids = [zone.zone_id for zone in zones]
    if len(zone_ids) != len(set(zone_ids)):
        raise ValueError("zone_id values must be unique")

    foot_x, foot_y = person_footpoint(person.bbox)
    candidates = sorted(
        (
            zone
            for zone in zones
            if zone.camera_id == frame.camera_id and point_in_polygon(foot_x, foot_y, zone.polygon)
        ),
        key=lambda zone: zone.zone_id,
    )
    policies = {
        (
            zone.risk_level,
            tuple(sorted(zone.required_ppe, key=lambda item: item.value)),
            zone.reminder_channel,
        )
        for zone in candidates
    }
    if len(policies) > 1:
        raise ValueError("overlapping zones at a person footpoint have conflicting policies")
    return candidates[0] if candidates else None
