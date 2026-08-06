from dataclasses import FrozenInstanceError

import pytest

from labcourt.contracts.enums import CropSource
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.domain.crop_geometry import (
    UINT32_MAX,
    ImageSize,
    expand_bbox,
    panorama_output_size,
    plan_absence_focus,
    plan_panorama,
    plan_presence_focus,
    plan_recrop,
    plan_subject,
)


def test_subject_expansion_rounds_outward_then_clips() -> None:
    source = BBoxXYXY(x1=1, y1=1, x2=6, y2=4)  # odd 5x3 box

    expanded = expand_bbox(
        source,
        frame_width=9,
        frame_height=7,
        expand_ratio="0.15",
    )
    clipped = expand_bbox(
        BBoxXYXY(x1=0, y1=2, x2=4, y2=6),
        frame_width=8,
        frame_height=8,
        expand_ratio="0.5",
    )

    assert expanded == BBoxXYXY(x1=0, y1=0, x2=7, y2=5)
    assert clipped == BBoxXYXY(x1=0, y1=0, x2=6, y2=8)


def test_invalid_original_bbox_is_rejected_before_expansion_can_clip_it() -> None:
    outside = BBoxXYXY(x1=8, y1=2, x2=11, y2=6)
    with pytest.raises(ValueError, match="exceeds frame bounds"):
        expand_bbox(
            outside,
            frame_width=10,
            frame_height=10,
            expand_ratio=1,
        )


def test_expansion_is_deterministic_for_decimal_float_and_rejects_non_finite() -> None:
    bbox = BBoxXYXY(x1=10, y1=10, x2=21, y2=17)
    from_string = expand_bbox(
        bbox,
        frame_width=40,
        frame_height=40,
        expand_ratio="0.15",
    )
    from_float = expand_bbox(
        bbox,
        frame_width=40,
        frame_height=40,
        expand_ratio=0.15,
    )

    assert from_float == from_string == BBoxXYXY(x1=8, y1=8, x2=23, y2=19)
    with pytest.raises(ValueError, match="finite"):
        expand_bbox(
            bbox,
            frame_width=40,
            frame_height=40,
            expand_ratio=float("nan"),
        )


def test_panorama_scales_long_edge_without_upscaling_and_uses_half_up_rounding() -> None:
    assert panorama_output_size(1_001, 501, 768) == ImageSize(768, 384)
    assert panorama_output_size(501, 1_001, 768) == ImageSize(384, 768)
    assert panorama_output_size(6, 3, 3) == ImageSize(3, 2)  # exact 1.5 tie
    assert panorama_output_size(320, 200, 768) == ImageSize(320, 200)


def test_all_crop_roles_return_frozen_pure_geometry_plans() -> None:
    panorama = plan_panorama(frame_width=1_001, frame_height=501, long_edge_limit=768)
    subject = plan_subject(
        BBoxXYXY(x1=10, y1=10, x2=30, y2=40),
        frame_width=100,
        frame_height=80,
        expand_ratio="0.15",
    )
    presence_detection = plan_presence_focus(
        BBoxXYXY(x1=20, y1=15, x2=35, y2=25),
        frame_width=100,
        frame_height=80,
    )
    presence_anchor = plan_presence_focus(
        BBoxXYXY(x1=20, y1=15, x2=35, y2=25),
        frame_width=100,
        frame_height=80,
        source=CropSource.ANCHOR_FOCUS,
    )
    absence = plan_absence_focus(
        BBoxXYXY(x1=40, y1=10, x2=50, y2=20),
        frame_width=100,
        frame_height=80,
    )
    recrop = plan_recrop(
        BBoxXYXY(x1=1, y1=2, x2=9, y2=12),
        frame_width=100,
        frame_height=80,
    )

    assert panorama.source == CropSource.PANORAMA
    assert panorama.bbox == BBoxXYXY(x1=0, y1=0, x2=1_001, y2=501)
    assert panorama.output_size == ImageSize(768, 384)
    assert subject.source == CropSource.SUBJECT
    assert subject.bbox == BBoxXYXY(x1=7, y1=5, x2=33, y2=45)
    assert subject.output_size == ImageSize(26, 40)
    assert presence_detection.source == CropSource.DETECTION_FOCUS
    assert presence_anchor.source == CropSource.ANCHOR_FOCUS
    assert absence.source == CropSource.ANCHOR_FOCUS
    assert recrop.source == CropSource.RECROP
    assert recrop.output_size == ImageSize(8, 10)
    with pytest.raises(FrozenInstanceError):
        recrop.output_size = ImageSize(1, 1)  # type: ignore[misc]


def test_focus_and_recrop_reject_out_of_bounds_instead_of_clipping() -> None:
    outside = BBoxXYXY(x1=90, y1=10, x2=101, y2=20)
    with pytest.raises(ValueError, match="exceeds frame bounds"):
        plan_presence_focus(outside, frame_width=100, frame_height=80)
    with pytest.raises(ValueError, match="exceeds frame bounds"):
        plan_absence_focus(outside, frame_width=100, frame_height=80)
    with pytest.raises(ValueError, match="exceeds frame bounds"):
        plan_recrop(outside, frame_width=100, frame_height=80)


def test_presence_focus_accepts_only_detection_or_anchor_source() -> None:
    with pytest.raises(ValueError, match="detection or rule anchor"):
        plan_presence_focus(
            BBoxXYXY(x1=1, y1=1, x2=2, y2=2),
            frame_width=10,
            frame_height=10,
            source=CropSource.SUBJECT,
        )


@pytest.mark.parametrize("invalid", [0, -1, True, UINT32_MAX + 1])
def test_dimensions_must_be_positive_uint32(invalid: int) -> None:
    with pytest.raises((TypeError, ValueError)):
        panorama_output_size(invalid, 100, 50)
    with pytest.raises((TypeError, ValueError)):
        panorama_output_size(100, invalid, 50)
    with pytest.raises((TypeError, ValueError)):
        panorama_output_size(100, 100, invalid)
