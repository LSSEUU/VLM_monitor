"""Deterministic RGB8 privacy transforms and PNG encoding with pinned Pillow."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from io import BytesIO

from PIL import Image

from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PpeType,
    PrivacyPolicy,
    PrivacyReasonCode,
)
from labcourt.contracts.evidence import Crop, CropRequest, PrivacyReceipt
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256

PNG_ENCODING_VERSION = "png-v1"
PRIVACY_TRANSFORM_VERSION = "ppe-redaction-v1"
PRIVACY_FILL_RGB = (16, 16, 16)
KEYPOINT_SCORE_THRESHOLD = 0.5


@dataclass(frozen=True, slots=True)
class PreparedCrop:
    """In-memory transform result before any filesystem publication."""

    request: CropRequest
    privacy_receipt: PrivacyReceipt
    width: int
    height: int
    pixels: bytes
    pixel_sha256: str
    png_bytes: bytes
    media_sha256: str


@dataclass(frozen=True, slots=True)
class PreparedMediaCrop:
    """PreparedCrop plus the source-frame pixel hash required by Crop."""

    prepared: PreparedCrop
    source_sha256: str

    def to_persisted_crop(
        self,
        *,
        local_path: str,
        availability: MediaAvailability = MediaAvailability.AVAILABLE,
    ) -> Crop:
        request = self.prepared.request
        if request.privacy_policy == PrivacyPolicy.EPHEMERAL_RAW:
            raise ValueError("ephemeral raw transforms cannot become persisted Crop records")
        return Crop(
            frame_id=request.frame_id,
            source=request.source,
            bbox=request.bbox,
            panorama_long_edge_limit=request.panorama_long_edge_limit,
            source_refs=request.source_refs,
            local_path=local_path,
            availability=availability,
            source_media_sha256=self.source_sha256,
            pixel_sha256=self.prepared.pixel_sha256,
            media_sha256=self.prepared.media_sha256,
            output_width=self.prepared.width,
            output_height=self.prepared.height,
            size_bytes=len(self.prepared.png_bytes),
            media_type=MediaType.IMAGE_PNG,
            encoding_version=request.encoding_version,
            privacy_receipt=self.prepared.privacy_receipt,
            observability=request.observability,
            primary_track_ref=request.primary_track_ref,
            tags=request.tags,
        )


def encode_rgb_png(width: int, height: int, pixels: bytes) -> bytes:
    """Encode a metadata-free RGB PNG using the frozen ``png-v1`` parameters."""

    rgb8_pixel_sha256(width, height, pixels)
    image = Image.frombytes("RGB", (width, height), pixels)
    output = BytesIO()
    image.save(
        output,
        format="PNG",
        optimize=False,
        compress_level=9,
        interlace=False,
    )
    return output.getvalue()


def _extract_rgb_crop(frame: RGB8Frame, bbox: BBoxXYXY) -> bytes:
    bbox.require_within(frame.frame.width, frame.frame.height)
    source_stride = frame.frame.width * 3
    row_size = bbox.width * 3
    output = bytearray(row_size * bbox.height)
    for output_row, source_y in enumerate(range(bbox.y1, bbox.y2)):
        source_start = source_y * source_stride + bbox.x1 * 3
        output_start = output_row * row_size
        output[output_start : output_start + row_size] = frame.pixels[
            source_start : source_start + row_size
        ]
    return bytes(output)


def _decimal(value: int | float) -> Decimal:
    return Decimal(str(value))


def _floor(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_FLOOR))


def _ceil(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _local_box(
    crop_bbox: BBoxXYXY,
    *,
    x1: Decimal,
    y1: Decimal,
    x2_inclusive: Decimal,
    y2_inclusive: Decimal,
) -> BBoxXYXY | None:
    global_x1 = max(crop_bbox.x1, _floor(x1))
    global_y1 = max(crop_bbox.y1, _floor(y1))
    global_x2 = min(crop_bbox.x2, _ceil(x2_inclusive) + 1)
    global_y2 = min(crop_bbox.y2, _ceil(y2_inclusive) + 1)
    if global_x1 >= global_x2 or global_y1 >= global_y2:
        return None
    return BBoxXYXY(
        x1=global_x1 - crop_bbox.x1,
        y1=global_y1 - crop_bbox.y1,
        x2=global_x2 - crop_bbox.x1,
        y2=global_y2 - crop_bbox.y1,
    )


def _visible_keypoints(request: CropRequest) -> dict[str, Keypoint]:
    return {
        keypoint.name: keypoint
        for keypoint in request.keypoints
        if keypoint.score >= KEYPOINT_SCORE_THRESHOLD
    }


def _goggle_region(request: CropRequest, points: dict[str, Keypoint]) -> tuple[BBoxXYXY, ...]:
    if not {"left_eye", "right_eye"}.issubset(points):
        return ()
    left = points["left_eye"]
    right = points["right_eye"]
    min_x = min(_decimal(left.x), _decimal(right.x))
    max_x = max(_decimal(left.x), _decimal(right.x))
    min_y = min(_decimal(left.y), _decimal(right.y))
    max_y = max(_decimal(left.y), _decimal(right.y))
    span = max(max_x - min_x, Decimal(1))
    region = _local_box(
        request.bbox,
        x1=min_x - span * Decimal("0.75"),
        y1=min_y - span * Decimal("0.50"),
        x2_inclusive=max_x + span * Decimal("0.75"),
        y2_inclusive=max_y + span * Decimal("0.50"),
    )
    return (region,) if region is not None else ()


def _glove_regions(request: CropRequest, points: dict[str, Keypoint]) -> tuple[BBoxXYXY, ...]:
    if request.anchor_bbox is None or not {"left_wrist", "right_wrist"}.issubset(points):
        return ()
    radius_x = max(Decimal(1), _decimal(request.anchor_bbox.width) * Decimal("0.18"))
    radius_y = max(Decimal(1), _decimal(request.anchor_bbox.height) * Decimal("0.18"))
    regions: list[BBoxXYXY] = []
    for name in ("left_wrist", "right_wrist"):
        point = points[name]
        x = _decimal(point.x)
        y = _decimal(point.y)
        region = _local_box(
            request.bbox,
            x1=x - radius_x,
            y1=y - radius_y,
            x2_inclusive=x + radius_x,
            y2_inclusive=y + radius_y,
        )
        if region is not None:
            regions.append(region)
    return tuple(regions) if len(regions) == 2 else ()


def _lab_coat_region(
    request: CropRequest,
    points: dict[str, Keypoint],
) -> tuple[BBoxXYXY, ...]:
    required = {"left_shoulder", "right_shoulder", "left_hip", "right_hip"}
    if request.anchor_bbox is None or not required.issubset(points):
        return ()
    selected = [points[name] for name in sorted(required)]
    min_x = min(_decimal(point.x) for point in selected)
    max_x = max(_decimal(point.x) for point in selected)
    min_y = min(_decimal(point.y) for point in selected)
    max_y = max(_decimal(point.y) for point in selected)
    pad_x = _decimal(request.anchor_bbox.width) * Decimal("0.10")
    pad_y = _decimal(request.anchor_bbox.height) * Decimal("0.05")
    region = _local_box(
        request.bbox,
        x1=min_x - pad_x,
        y1=min_y - pad_y,
        x2_inclusive=max_x + pad_x,
        y2_inclusive=max_y + pad_y,
    )
    return (region,) if region is not None else ()


def _merge_regions(regions: tuple[BBoxXYXY, ...]) -> tuple[BBoxXYXY, ...]:
    pending = sorted(regions, key=lambda box: (box.x1, box.y1, box.x2, box.y2))
    merged: list[BBoxXYXY] = []
    for region in pending:
        if not merged:
            merged.append(region)
            continue
        previous = merged[-1]
        overlaps_or_touches = (
            region.x1 <= previous.x2
            and previous.x1 <= region.x2
            and region.y1 <= previous.y2
            and previous.y1 <= region.y2
        )
        if overlaps_or_touches:
            merged[-1] = BBoxXYXY(
                x1=min(previous.x1, region.x1),
                y1=min(previous.y1, region.y1),
                x2=max(previous.x2, region.x2),
                y2=max(previous.y2, region.y2),
            )
        else:
            merged.append(region)
    return tuple(merged)


def _ppe_regions(request: CropRequest) -> tuple[BBoxXYXY, ...]:
    points = _visible_keypoints(request)
    if request.ppe_type == PpeType.GOGGLES:
        regions = _goggle_region(request, points)
    elif request.ppe_type == PpeType.GLOVES:
        regions = _glove_regions(request, points)
    elif request.ppe_type == PpeType.LAB_COAT:
        regions = _lab_coat_region(request, points)
    else:
        return ()
    return _merge_regions(regions)


def _copy_preserved_regions(
    original: bytes,
    *,
    width: int,
    height: int,
    regions: tuple[BBoxXYXY, ...],
    fill_rgb: tuple[int, int, int],
) -> bytes:
    expected_length = width * height * 3
    if len(original) != expected_length:
        raise ValueError("crop RGB8 byte length does not match its dimensions")
    fill_pixel = bytes(fill_rgb)
    output = bytearray(fill_pixel * (width * height))
    stride = width * 3
    for region in regions:
        region.require_within(width, height)
        row_size = region.width * 3
        for y in range(region.y1, region.y2):
            start = y * stride + region.x1 * 3
            output[start : start + row_size] = original[start : start + row_size]
    return bytes(output)


def prepare_crop(
    frame: RGB8Frame,
    request: CropRequest,
) -> PreparedMediaCrop:
    """Apply the requested privacy policy before any persistence boundary."""

    fill_rgb = PRIVACY_FILL_RGB
    if request.frame_id != frame.frame.frame_id:
        raise ValueError("crop request belongs to a different frame")
    request.bbox.require_within(frame.frame.width, frame.frame.height)
    if request.encoding_version != PNG_ENCODING_VERSION:
        raise ValueError("unsupported deterministic PNG encoding version")
    if request.privacy_transform_version != PRIVACY_TRANSFORM_VERSION:
        raise ValueError("unsupported privacy transform version")
    if request.anchor_bbox is not None:
        request.anchor_bbox.require_within(frame.frame.width, frame.frame.height)
    if any(
        keypoint.x >= frame.frame.width or keypoint.y >= frame.frame.height
        for keypoint in request.keypoints
    ):
        raise ValueError("privacy keypoints must be inside the source frame")

    fallback_used = False
    regions: tuple[BBoxXYXY, ...] = ()
    if request.privacy_policy == PrivacyPolicy.EPHEMERAL_RAW:
        original = _extract_rgb_crop(frame, request.bbox)
        transformed = original
        access = MediaAccess.LOCAL_ONLY
        reason = PrivacyReasonCode.POLICY_LOCAL_ONLY
    elif request.privacy_policy == PrivacyPolicy.FULL_REDACTION:
        transformed = bytes(fill_rgb) * (request.output_width * request.output_height)
        access = MediaAccess.LOCAL_ONLY
        reason = (
            PrivacyReasonCode.PANORAMA_FULL_REDACTION
            if request.source == CropSource.PANORAMA
            else PrivacyReasonCode.SUBJECT_FULL_REDACTION
            if request.source == CropSource.SUBJECT
            else PrivacyReasonCode.POLICY_LOCAL_ONLY
        )
    else:
        original = _extract_rgb_crop(frame, request.bbox)
        regions = _ppe_regions(request)
        fallback_used = not regions
        transformed = _copy_preserved_regions(
            original,
            width=request.bbox.width,
            height=request.bbox.height,
            regions=regions,
            fill_rgb=fill_rgb,
        )
        access = MediaAccess.LOCAL_ONLY if fallback_used else MediaAccess.CLOUD_ALLOWED
        reason = (
            PrivacyReasonCode.KEYPOINTS_INSUFFICIENT_LOCAL_ONLY
            if fallback_used
            else PrivacyReasonCode.PPE_REGION_PRESERVED
        )

    receipt = PrivacyReceipt(
        policy=request.privacy_policy,
        transform_version=request.privacy_transform_version,
        media_access=access,
        reason_code=reason,
        input_refs=request.source_refs,
        ppe_type=request.ppe_type,
        anchor_type=request.anchor_type,
        preserved_regions=regions,
        keypoints=request.keypoints,
        anchor_bbox=request.anchor_bbox,
        association_method=request.association_method,
        fill_rgb=fill_rgb,
        fallback_used=fallback_used,
    )
    width = request.output_width
    height = request.output_height
    pixel_sha256 = rgb8_pixel_sha256(width, height, transformed)
    png_bytes = encode_rgb_png(width, height, transformed)
    prepared = PreparedCrop(
        request=request,
        privacy_receipt=receipt,
        width=width,
        height=height,
        pixels=transformed,
        pixel_sha256=pixel_sha256,
        png_bytes=png_bytes,
        media_sha256=hashlib.sha256(png_bytes).hexdigest(),
    )
    assert frame.frame.content_sha256 is not None
    return PreparedMediaCrop(prepared=prepared, source_sha256=frame.frame.content_sha256)


__all__ = [
    "KEYPOINT_SCORE_THRESHOLD",
    "PNG_ENCODING_VERSION",
    "PRIVACY_FILL_RGB",
    "PRIVACY_TRANSFORM_VERSION",
    "PreparedCrop",
    "PreparedMediaCrop",
    "encode_rgb_png",
    "prepare_crop",
]
