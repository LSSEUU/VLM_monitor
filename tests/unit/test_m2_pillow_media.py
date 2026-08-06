from io import BytesIO

import pytest
from PIL import Image
from pydantic import ValidationError

from labcourt.adapters.pillow_media import (
    PNG_ENCODING_VERSION,
    PRIVACY_FILL_RGB,
    PRIVACY_TRANSFORM_VERSION,
    encode_rgb_png,
    prepare_crop,
)
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    AnchorType,
    ArtifactKind,
    AssociationMethod,
    CropSource,
    MediaAccess,
    ObservationSource,
    PpeType,
    PrivacyPolicy,
    PrivacyReasonCode,
)
from labcourt.contracts.evidence import (
    CropRequest,
    ObservabilityComponents,
    ObservabilityScore,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.storage import ArtifactRef
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256

WIDTH = 16
HEIGHT = 12
TRACK_REF = "cam-01:epoch-01:track-01"


def _pixels(width: int = WIDTH, height: int = HEIGHT) -> bytes:
    return bytes(
        channel
        for y in range(height)
        for x in range(width)
        for channel in (x * 11 % 256, y * 17 % 256, (x * 13 + y * 7) % 256)
    )


def _rgb8_frame(
    *,
    frame_index: int = 7,
    width: int = WIDTH,
    height: int = HEIGHT,
) -> RGB8Frame:
    pixels = _pixels(width, height)
    frame = FrameRef(
        camera_id="cam-01",
        stream_id="stream-01",
        frame_index=frame_index,
        fps_num=30,
        fps_den=1,
        width=width,
        height=height,
        content_sha256=rgb8_pixel_sha256(width, height, pixels),
    )
    return RGB8Frame(frame=frame, pixels=pixels)


def _frame_ref(frame: RGB8Frame) -> ArtifactRef:
    return ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame.frame_id)


def _observability() -> ObservabilityScore:
    return ObservabilityScore(
        total=0.9,
        components=ObservabilityComponents(
            person_confidence=0.9,
            keypoint_visibility=0.9,
            frontality=0.9,
            sharpness=0.9,
            exposure=0.9,
            non_occlusion=0.9,
        ),
        source=ObservationSource.PIXEL_COMPUTED,
    )


def _goggle_request(
    frame: RGB8Frame,
    *,
    keypoints: tuple[Keypoint, ...] | None = None,
    encoding_version: str = PNG_ENCODING_VERSION,
    transform_version: str = PRIVACY_TRANSFORM_VERSION,
    anchor_bbox: BBoxXYXY | None = None,
) -> CropRequest:
    return CropRequest(
        frame_id=frame.frame.frame_id,
        source=CropSource.ANCHOR_FOCUS,
        bbox=BBoxXYXY(x1=2, y1=1, x2=14, y2=11),
        output_width=12,
        output_height=10,
        source_refs=(_frame_ref(frame),),
        privacy_policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
        privacy_transform_version=transform_version,
        encoding_version=encoding_version,
        primary_track_ref=TRACK_REF,
        ppe_type=PpeType.GOGGLES,
        anchor_type=AnchorType.HEAD,
        anchor_bbox=anchor_bbox or BBoxXYXY(x1=3, y1=2, x2=13, y2=10),
        keypoints=keypoints
        or (
            Keypoint(name="left_eye", x=6.0, y=4.0, score=0.95),
            Keypoint(name="right_eye", x=9.0, y=4.0, score=0.95),
        ),
        association_method=AssociationMethod.KEYPOINT,
        observability=_observability(),
    )


def _pixel(pixels: bytes, width: int, x: int, y: int) -> bytes:
    start = (y * width + x) * 3
    return pixels[start : start + 3]


def test_goggles_preserve_only_the_receipted_region() -> None:
    frame = _rgb8_frame()
    request = _goggle_request(frame)

    result = prepare_crop(frame, request)

    assert result.prepared.privacy_receipt.preserved_regions == (BBoxXYXY(x1=1, y1=1, x2=11, y2=6),)
    assert result.prepared.privacy_receipt.media_access == MediaAccess.CLOUD_ALLOWED
    assert result.prepared.privacy_receipt.reason_code == PrivacyReasonCode.PPE_REGION_PRESERVED
    source_crop = bytes(
        channel
        for y in range(request.bbox.y1, request.bbox.y2)
        for x in range(request.bbox.x1, request.bbox.x2)
        for channel in _pixel(frame.pixels, WIDTH, x, y)
    )
    region = result.prepared.privacy_receipt.preserved_regions[0]
    fill = bytes(PRIVACY_FILL_RGB)
    for y in range(result.prepared.height):
        for x in range(result.prepared.width):
            actual = _pixel(result.prepared.pixels, result.prepared.width, x, y)
            expected = (
                _pixel(source_crop, result.prepared.width, x, y)
                if region.x1 <= x < region.x2 and region.y1 <= y < region.y2
                else fill
            )
            assert actual == expected


def test_insufficient_goggle_keypoints_fail_closed_without_face_fallback() -> None:
    frame = _rgb8_frame()
    request = _goggle_request(
        frame,
        keypoints=(
            Keypoint(name="left_eye", x=6.0, y=4.0, score=0.95),
            Keypoint(name="right_eye", x=9.0, y=4.0, score=0.49),
        ),
    )

    result = prepare_crop(frame, request)

    receipt = result.prepared.privacy_receipt
    assert receipt.fallback_used is True
    assert receipt.preserved_regions == ()
    assert receipt.media_access == MediaAccess.LOCAL_ONLY
    assert receipt.reason_code == PrivacyReasonCode.KEYPOINTS_INSUFFICIENT_LOCAL_ONLY
    assert result.prepared.pixels == bytes(PRIVACY_FILL_RGB) * (
        result.prepared.width * result.prepared.height
    )


def test_full_redaction_is_local_and_contains_no_source_pixels() -> None:
    frame = _rgb8_frame()
    request = CropRequest(
        frame_id=frame.frame.frame_id,
        source=CropSource.PANORAMA,
        bbox=BBoxXYXY(x1=0, y1=0, x2=WIDTH, y2=HEIGHT),
        output_width=8,
        output_height=6,
        panorama_long_edge_limit=8,
        source_refs=(_frame_ref(frame),),
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version=PRIVACY_TRANSFORM_VERSION,
        encoding_version=PNG_ENCODING_VERSION,
    )

    result = prepare_crop(frame, request)

    receipt = result.prepared.privacy_receipt
    assert receipt.media_access == MediaAccess.LOCAL_ONLY
    assert receipt.reason_code == PrivacyReasonCode.PANORAMA_FULL_REDACTION
    assert receipt.preserved_regions == ()
    assert receipt.keypoints == ()
    assert result.prepared.pixels == bytes(PRIVACY_FILL_RGB) * (8 * 6)


def test_output_geometry_is_revalidated_at_the_crop_request_boundary() -> None:
    frame = _rgb8_frame()
    with pytest.raises(ValidationError, match="non-panorama output dimensions"):
        _goggle_request(frame).model_copy(update={"output_width": 11})
    with pytest.raises(ValidationError, match="long-edge limit"):
        CropRequest(
            frame_id=frame.frame.frame_id,
            source=CropSource.PANORAMA,
            bbox=BBoxXYXY(x1=0, y1=0, x2=WIDTH, y2=HEIGHT),
            output_width=8,
            output_height=7,
            panorama_long_edge_limit=8,
            source_refs=(_frame_ref(frame),),
            privacy_policy=PrivacyPolicy.FULL_REDACTION,
            privacy_transform_version=PRIVACY_TRANSFORM_VERSION,
            encoding_version=PNG_ENCODING_VERSION,
        )


def test_png_encoding_is_deterministic_metadata_free_and_pixel_exact() -> None:
    frame = _rgb8_frame()
    result = prepare_crop(frame, _goggle_request(frame))

    replay = encode_rgb_png(
        result.prepared.width,
        result.prepared.height,
        result.prepared.pixels,
    )

    assert replay == result.prepared.png_bytes
    assert (
        result.prepared.pixel_sha256
        == "201bf88f7d2960661b7ba15470d82aaf5c6a6177d68817a3ca935b89dfebecd0"
    )
    assert (
        result.prepared.media_sha256
        == "67a48e5ef57f26a63aac224e3df1632731194a0f402e3d4b7493c3d5530725d8"
    )
    with Image.open(BytesIO(result.prepared.png_bytes)) as image:
        assert image.mode == "RGB"
        assert image.size == (result.prepared.width, result.prepared.height)
        assert image.info == {}
        assert image.tobytes() == result.prepared.pixels


def test_prepare_crop_rejects_wrong_frame_bounds_and_versions() -> None:
    frame = _rgb8_frame()
    other_frame = _rgb8_frame(frame_index=8)

    with pytest.raises(ValueError, match="different frame"):
        prepare_crop(other_frame, _goggle_request(frame))
    with pytest.raises(ValueError, match="PNG encoding"):
        prepare_crop(frame, _goggle_request(frame, encoding_version="png-v2"))
    with pytest.raises(ValueError, match="privacy transform"):
        prepare_crop(frame, _goggle_request(frame, transform_version="privacy-v2"))
    with pytest.raises(ValueError, match="bbox exceeds frame bounds"):
        prepare_crop(
            frame,
            _goggle_request(
                frame,
                anchor_bbox=BBoxXYXY(x1=3, y1=2, x2=17, y2=10),
            ),
        )
    with pytest.raises(ValueError, match="keypoints must be inside"):
        prepare_crop(
            frame,
            _goggle_request(
                frame,
                keypoints=(
                    Keypoint(name="left_eye", x=6.0, y=4.0, score=0.95),
                    Keypoint(name="right_eye", x=16.0, y=4.0, score=0.95),
                ),
            ),
        )


def test_privacy_fill_is_versioned_and_not_caller_controlled() -> None:
    frame = _rgb8_frame()
    with pytest.raises(TypeError, match="unexpected keyword"):
        prepare_crop(
            frame,
            _goggle_request(frame),
            fill_rgb=(0, 0, 0),  # type: ignore[call-arg]
        )


def test_persisted_crop_carries_all_three_hashes_and_dimensions() -> None:
    frame = _rgb8_frame()
    result = prepare_crop(frame, _goggle_request(frame))

    crop = result.to_persisted_crop(local_path="frames/goggles.png")

    assert crop.source_media_sha256 == frame.frame.content_sha256
    assert crop.pixel_sha256 == result.prepared.pixel_sha256
    assert crop.media_sha256 == result.prepared.media_sha256
    assert crop.output_width == result.prepared.width
    assert crop.output_height == result.prepared.height
    assert crop.size_bytes == len(result.prepared.png_bytes)
    assert crop.local_path == "frames/goggles.png"


def test_ephemeral_raw_can_be_processed_but_never_persisted_as_a_crop() -> None:
    frame = _rgb8_frame()
    source_refs = tuple(
        sorted(
            (
                ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame.frame_id),
                ArtifactRef(kind=ArtifactKind.CROP, artifact_id="a" * 64),
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    request = CropRequest(
        frame_id=frame.frame.frame_id,
        source=CropSource.RECROP,
        bbox=BBoxXYXY(x1=2, y1=1, x2=14, y2=11),
        output_width=12,
        output_height=10,
        source_refs=source_refs,
        privacy_policy=PrivacyPolicy.EPHEMERAL_RAW,
        privacy_transform_version=PRIVACY_TRANSFORM_VERSION,
        encoding_version=PNG_ENCODING_VERSION,
    )

    result = prepare_crop(frame, request)

    assert result.prepared.pixels != bytes(PRIVACY_FILL_RGB) * (
        result.prepared.width * result.prepared.height
    )
    assert result.prepared.privacy_receipt.media_access == MediaAccess.LOCAL_ONLY
    with pytest.raises(ValueError, match="ephemeral raw"):
        result.to_persisted_crop(local_path="frames/raw.png")
