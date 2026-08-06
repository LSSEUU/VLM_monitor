"""Pure, deterministic geometry plans for M2 evidence crops."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from math import isfinite
from typing import TypeAlias

from labcourt.contracts.enums import CropSource
from labcourt.contracts.geometry import BBoxXYXY

UINT32_MAX = (1 << 32) - 1
Ratio: TypeAlias = Decimal | Fraction | str | int | float


def _require_dimension(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if not 1 <= value <= UINT32_MAX:
        raise ValueError(f"{name} must be within unsigned 32-bit positive range")
    return value


def _require_bbox(value: BBoxXYXY, name: str) -> BBoxXYXY:
    if not isinstance(value, BBoxXYXY):
        raise TypeError(f"{name} must be a BBoxXYXY")
    return value


def _ratio_as_fraction(value: Ratio) -> Fraction:
    if isinstance(value, bool):
        raise TypeError("expand_ratio must be numeric, not bool")
    try:
        if isinstance(value, Fraction):
            ratio = value
        elif isinstance(value, Decimal):
            ratio = Fraction(value)
        elif isinstance(value, float):
            if not isfinite(value):
                raise ValueError("expand_ratio must be finite")
            ratio = Fraction(Decimal(str(value)))
        else:
            ratio = Fraction(value)
    except (InvalidOperation, TypeError, ValueError, ZeroDivisionError) as exc:
        raise ValueError("expand_ratio must be a finite numeric ratio") from exc
    if ratio < 0:
        raise ValueError("expand_ratio must be non-negative")
    return ratio


def _ceil_fraction(value: Fraction) -> int:
    return (value.numerator + value.denominator - 1) // value.denominator


def _round_half_up(value: Fraction) -> int:
    """Round a non-negative fraction to nearest integer, with exact halves upward."""

    return (2 * value.numerator + value.denominator) // (2 * value.denominator)


@dataclass(frozen=True, slots=True)
class ImageSize:
    width: int
    height: int

    def __post_init__(self) -> None:
        _require_dimension(self.width, "width")
        _require_dimension(self.height, "height")


@dataclass(frozen=True, slots=True)
class CropGeometryPlan:
    """A source-space crop rectangle and its deterministic output dimensions."""

    source: CropSource
    frame_size: ImageSize
    bbox: BBoxXYXY
    output_size: ImageSize
    panorama_long_edge_limit: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, CropSource):
            raise TypeError("source must be a CropSource")
        if not isinstance(self.frame_size, ImageSize):
            raise TypeError("frame_size must be an ImageSize")
        if not isinstance(self.output_size, ImageSize):
            raise TypeError("output_size must be an ImageSize")
        _require_bbox(self.bbox, "bbox").require_within(
            self.frame_size.width,
            self.frame_size.height,
        )

        if self.source == CropSource.PANORAMA:
            if self.panorama_long_edge_limit is None:
                raise ValueError("panorama plan requires its long-edge limit")
            expected_bbox = BBoxXYXY(
                x1=0,
                y1=0,
                x2=self.frame_size.width,
                y2=self.frame_size.height,
            )
            if self.bbox != expected_bbox:
                raise ValueError("panorama plan must use the complete frame")
            expected_size = panorama_output_size(
                self.frame_size.width,
                self.frame_size.height,
                self.panorama_long_edge_limit,
            )
            if self.output_size != expected_size:
                raise ValueError("panorama output size does not match its long-edge limit")
        else:
            if self.panorama_long_edge_limit is not None:
                raise ValueError("non-panorama plan cannot carry a panorama limit")
            if self.output_size != ImageSize(self.bbox.width, self.bbox.height):
                raise ValueError("non-panorama output size must equal its crop rectangle")


def expand_bbox(
    bbox: BBoxXYXY,
    *,
    frame_width: int,
    frame_height: int,
    expand_ratio: Ratio,
) -> BBoxXYXY:
    """Expand each side by a ratio of original width/height, then clip.

    The input box is validated against the frame *before* expansion. This prevents clipping
    from laundering an already-invalid source box into an apparently valid result.
    """

    width = _require_dimension(frame_width, "frame_width")
    height = _require_dimension(frame_height, "frame_height")
    source_bbox = _require_bbox(bbox, "bbox")
    source_bbox.require_within(width, height)
    ratio = _ratio_as_fraction(expand_ratio)
    margin_x = _ceil_fraction(Fraction(source_bbox.width) * ratio)
    margin_y = _ceil_fraction(Fraction(source_bbox.height) * ratio)
    return BBoxXYXY(
        x1=max(0, source_bbox.x1 - margin_x),
        y1=max(0, source_bbox.y1 - margin_y),
        x2=min(width, source_bbox.x2 + margin_x),
        y2=min(height, source_bbox.y2 + margin_y),
    )


def panorama_output_size(
    frame_width: int,
    frame_height: int,
    long_edge_limit: int,
) -> ImageSize:
    """Return a no-upscale thumbnail size using rational, half-up rounding."""

    width = _require_dimension(frame_width, "frame_width")
    height = _require_dimension(frame_height, "frame_height")
    limit = _require_dimension(long_edge_limit, "long_edge_limit")
    if max(width, height) <= limit:
        return ImageSize(width, height)
    if width >= height:
        scaled_height = max(1, _round_half_up(Fraction(height * limit, width)))
        return ImageSize(limit, scaled_height)
    scaled_width = max(1, _round_half_up(Fraction(width * limit, height)))
    return ImageSize(scaled_width, limit)


def _plan_unscaled(
    source: CropSource,
    bbox: BBoxXYXY,
    *,
    frame_width: int,
    frame_height: int,
) -> CropGeometryPlan:
    width = _require_dimension(frame_width, "frame_width")
    height = _require_dimension(frame_height, "frame_height")
    checked_bbox = _require_bbox(bbox, "bbox")
    checked_bbox.require_within(width, height)
    return CropGeometryPlan(
        source=source,
        frame_size=ImageSize(width, height),
        bbox=checked_bbox,
        output_size=ImageSize(checked_bbox.width, checked_bbox.height),
    )


def plan_panorama(
    *,
    frame_width: int,
    frame_height: int,
    long_edge_limit: int,
) -> CropGeometryPlan:
    width = _require_dimension(frame_width, "frame_width")
    height = _require_dimension(frame_height, "frame_height")
    limit = _require_dimension(long_edge_limit, "long_edge_limit")
    return CropGeometryPlan(
        source=CropSource.PANORAMA,
        frame_size=ImageSize(width, height),
        bbox=BBoxXYXY(x1=0, y1=0, x2=width, y2=height),
        output_size=panorama_output_size(width, height, limit),
        panorama_long_edge_limit=limit,
    )


def plan_subject(
    subject_bbox: BBoxXYXY,
    *,
    frame_width: int,
    frame_height: int,
    expand_ratio: Ratio,
) -> CropGeometryPlan:
    expanded = expand_bbox(
        subject_bbox,
        frame_width=frame_width,
        frame_height=frame_height,
        expand_ratio=expand_ratio,
    )
    return _plan_unscaled(
        CropSource.SUBJECT,
        expanded,
        frame_width=frame_width,
        frame_height=frame_height,
    )


def plan_presence_focus(
    focus_bbox: BBoxXYXY,
    *,
    frame_width: int,
    frame_height: int,
    source: CropSource = CropSource.DETECTION_FOCUS,
) -> CropGeometryPlan:
    if source not in {CropSource.DETECTION_FOCUS, CropSource.ANCHOR_FOCUS}:
        raise ValueError("presence focus source must be a detection or rule anchor")
    return _plan_unscaled(
        source,
        focus_bbox,
        frame_width=frame_width,
        frame_height=frame_height,
    )


def plan_absence_focus(
    anchor_bbox: BBoxXYXY,
    *,
    frame_width: int,
    frame_height: int,
) -> CropGeometryPlan:
    return _plan_unscaled(
        CropSource.ANCHOR_FOCUS,
        anchor_bbox,
        frame_width=frame_width,
        frame_height=frame_height,
    )


def plan_recrop(
    requested_bbox: BBoxXYXY,
    *,
    frame_width: int,
    frame_height: int,
) -> CropGeometryPlan:
    return _plan_unscaled(
        CropSource.RECROP,
        requested_bbox,
        frame_width=frame_width,
        frame_height=frame_height,
    )


__all__ = [
    "UINT32_MAX",
    "CropGeometryPlan",
    "ImageSize",
    "Ratio",
    "expand_bbox",
    "panorama_output_size",
    "plan_absence_focus",
    "plan_panorama",
    "plan_presence_focus",
    "plan_recrop",
    "plan_subject",
]
