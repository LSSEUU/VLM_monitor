import hashlib
import os
from importlib.metadata import version
from pathlib import Path

import pytest
from pydantic import ValidationError

from labcourt.adapters.pillow_frame_store import PillowFrameStore
from labcourt.adapters.pillow_media import (
    PNG_ENCODING_VERSION,
    PRIVACY_TRANSFORM_VERSION,
    encode_rgb_png,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    AnchorType,
    ArtifactKind,
    AssociationMethod,
    CropSource,
    MediaAvailability,
    ObservationSource,
    PpeType,
    PrivacyPolicy,
    VerificationStatus,
)
from labcourt.contracts.evidence import (
    CropRequest,
    ObservabilityComponents,
    ObservabilityScore,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import (
    EvidenceMissing,
    PathBoundaryViolation,
    PrivacyPolicyViolation,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256

WIDTH = 16
HEIGHT = 12
RUN_ID = "m2-pillow-store"
TRACK_REF = "cam-01:epoch-01:track-01"


def _pixel_bytes(*, offset: int = 0) -> bytes:
    return bytes(
        channel
        for y in range(HEIGHT)
        for x in range(WIDTH)
        for channel in (
            (x * 11 + offset) % 256,
            (y * 17 + offset) % 256,
            (x * 13 + y * 7 + offset) % 256,
        )
    )


def _frame(*, offset: int = 0) -> RGB8Frame:
    pixels = _pixel_bytes(offset=offset)
    frame = FrameRef(
        camera_id="cam-01",
        stream_id="stream-01",
        frame_index=7,
        fps_num=30,
        fps_den=1,
        width=WIDTH,
        height=HEIGHT,
        content_sha256=rgb8_pixel_sha256(WIDTH, HEIGHT, pixels),
    )
    return RGB8Frame(frame=frame, pixels=pixels)


class _PixelProvider:
    def __init__(self, frame: RGB8Frame | None) -> None:
        self.frame = frame
        self.calls = 0

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        self.calls += 1
        if self.frame is None or self.frame.frame.frame_id != frame_id:
            raise EvidenceMissing("frame unavailable")
        return self.frame


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
    bbox: BBoxXYXY | None = None,
) -> CropRequest:
    selected_bbox = bbox or BBoxXYXY(x1=2, y1=1, x2=14, y2=11)
    return CropRequest(
        frame_id=frame.frame.frame_id,
        source=CropSource.ANCHOR_FOCUS,
        bbox=selected_bbox,
        output_width=selected_bbox.width,
        output_height=selected_bbox.height,
        source_refs=(_frame_ref(frame),),
        privacy_policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
        privacy_transform_version=PRIVACY_TRANSFORM_VERSION,
        encoding_version=PNG_ENCODING_VERSION,
        primary_track_ref=TRACK_REF,
        ppe_type=PpeType.GOGGLES,
        anchor_type=AnchorType.HEAD,
        anchor_bbox=BBoxXYXY(x1=3, y1=2, x2=13, y2=10),
        keypoints=(
            Keypoint(name="left_eye", x=6.0, y=4.0, score=0.95),
            Keypoint(name="right_eye", x=9.0, y=4.0, score=0.95),
        ),
        association_method=AssociationMethod.KEYPOINT,
        observability=_observability(),
    )


def _store(
    workspace: SecureWorkspace,
    provider: _PixelProvider,
    *,
    max_image_pixels: int = 10_000,
) -> PillowFrameStore:
    return PillowFrameStore(
        run_id=RUN_ID,
        workspace=workspace,
        pixels=provider,
        max_media_bytes=1_000_000,
        max_image_pixels=max_image_pixels,
    )


def _workspace(tmp_path: Path) -> tuple[Path, SecureWorkspace]:
    root = tmp_path / "workspace"
    root.mkdir()
    return root, SecureWorkspace(root, max_file_bytes=1_000_000)


def test_crop_publication_is_verified_and_idempotent(tmp_path: Path) -> None:
    root, workspace = _workspace(tmp_path)
    frame = _frame()
    provider = _PixelProvider(frame)
    with workspace:
        store = _store(workspace, provider)
        first = store.create_crop(_goggle_request(frame))
        replay = store.create_crop(_goggle_request(frame))
        verification = store.verify_crop(first)
        snapshot = workspace.read_verified(first.local_path or "", first.media_sha256)

    assert replay == first
    assert verification.status == VerificationStatus.VERIFIED
    assert verification.actual_source_pixel_sha256 == first.source_media_sha256
    assert verification.actual_output_pixel_sha256 == first.pixel_sha256
    assert verification.actual_media_sha256 == first.media_sha256
    assert snapshot.size_bytes == first.size_bytes
    assert provider.calls == 5  # prepare+verify for each create, then explicit verify
    assert not tuple((root / ".staging" / RUN_ID).glob("crop-*"))


def test_store_binds_run_namespace_and_actual_pillow_component(tmp_path: Path) -> None:
    _, workspace = _workspace(tmp_path)
    frame = _frame()
    provider = _PixelProvider(frame)
    with workspace:
        store = _store(workspace, provider)
        crop = store.create_crop(_goggle_request(frame))

    assert store.run_id == RUN_ID
    assert crop.local_path == f"{RUN_ID}/frames/{crop.media_sha256}.png"
    assert store.software_component.component == "pillow"
    assert store.software_component.package == "Pillow"
    assert store.software_component.version == version("Pillow")
    assert store.software_component.license_id == "HPND"


def test_store_rejects_an_unsafe_run_namespace(tmp_path: Path) -> None:
    _, workspace = _workspace(tmp_path)
    with workspace, pytest.raises(ValueError, match="run_id"):
        PillowFrameStore(
            run_id="../another-run",
            workspace=workspace,
            pixels=_PixelProvider(_frame()),
            max_media_bytes=1_000_000,
            max_image_pixels=10_000,
        )


def test_store_rejects_an_existing_nonprivate_staging_directory(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    staging = root / ".staging"
    staging.mkdir()
    if os.name != "nt":
        staging.chmod(0o755)
    frame = _frame()

    with (
        SecureWorkspace(root, max_file_bytes=1_000_000) as workspace,
        pytest.raises(PathBoundaryViolation) as captured,
    ):
        _store(workspace, _PixelProvider(frame)).create_crop(_goggle_request(frame))

    assert captured.value.reason_code == "DIRECTORY_NOT_PRIVATE"


def test_verification_replays_privacy_transform_against_self_consistent_forgery(
    tmp_path: Path,
) -> None:
    _, workspace = _workspace(tmp_path)
    frame = _frame()
    provider = _PixelProvider(frame)
    request = _goggle_request(frame)
    bbox = request.bbox
    source_stride = frame.frame.width * 3
    row_size = bbox.width * 3
    raw_pixels = b"".join(
        frame.pixels[
            source_y * source_stride + bbox.x1 * 3 : source_y * source_stride
            + bbox.x1 * 3
            + row_size
        ]
        for source_y in range(bbox.y1, bbox.y2)
    )
    raw_pixel_sha256 = rgb8_pixel_sha256(bbox.width, bbox.height, raw_pixels)
    raw_png = encode_rgb_png(bbox.width, bbox.height, raw_pixels)
    raw_media_sha256 = hashlib.sha256(raw_png).hexdigest()
    raw_path = f"{RUN_ID}/frames/{raw_media_sha256}.png"

    with workspace:
        store = _store(workspace, provider)
        legitimate = store.create_crop(request)
        workspace.create_new(raw_path, raw_png, raw_media_sha256)
        forged = legitimate.model_copy(
            update={
                "local_path": raw_path,
                "pixel_sha256": raw_pixel_sha256,
                "media_sha256": raw_media_sha256,
                "size_bytes": len(raw_png),
            }
        )
        verification = store.verify_crop(forged)
        relocated = legitimate.model_copy(update={"local_path": f"{RUN_ID}/frames/{'f' * 64}.png"})
        locator_verification = store.verify_crop(relocated)

    assert verification.status == VerificationStatus.PRIVACY_POLICY_VIOLATION
    assert verification.reason_code == "PRIVACY_TRANSFORM_REPLAY_MISMATCH"
    assert verification.actual_media_sha256 == raw_media_sha256
    assert locator_verification.status == VerificationStatus.PRIVACY_POLICY_VIOLATION
    assert locator_verification.reason_code == "NONCANONICAL_MEDIA_LOCATOR"


def test_panorama_plan_is_resized_before_persistence(tmp_path: Path) -> None:
    _, workspace = _workspace(tmp_path)
    frame = _frame()
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
    with workspace:
        crop = _store(workspace, _PixelProvider(frame)).create_crop(request)

    assert (crop.output_width, crop.output_height) == (8, 6)
    assert crop.panorama_long_edge_limit == 8


def test_bbox_limits_and_raw_policy_fail_explicitly(tmp_path: Path) -> None:
    root, workspace = _workspace(tmp_path)
    frame = _frame()
    with workspace:
        store = _store(workspace, _PixelProvider(frame))
        with pytest.raises(ValueError, match="bbox exceeds frame bounds"):
            store.create_crop(_goggle_request(frame, bbox=BBoxXYXY(x1=2, y1=1, x2=17, y2=11)))
        with pytest.raises(PathBoundaryViolation, match="SOURCE_FRAME_TOO_LARGE"):
            _store(
                workspace,
                _PixelProvider(frame),
                max_image_pixels=100,
            ).create_crop(_goggle_request(frame))
        source_refs = tuple(
            sorted(
                (
                    _frame_ref(frame),
                    ArtifactRef(kind=ArtifactKind.CROP, artifact_id="a" * 64),
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        raw = CropRequest(
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
        with pytest.raises(PrivacyPolicyViolation, match="TTL cache"):
            store.create_crop(raw)
    assert not list(root.rglob("*.png"))


def test_tampered_canonical_png_returns_complete_pixel_mismatch(tmp_path: Path) -> None:
    root, workspace = _workspace(tmp_path)
    frame = _frame()
    with workspace:
        store = _store(workspace, _PixelProvider(frame))
        crop = store.create_crop(_goggle_request(frame))
        assert crop.local_path is not None
        tampered = encode_rgb_png(crop.output_width, crop.output_height, bytes(12 * 10 * 3))
        (root / Path(crop.local_path)).write_bytes(tampered)

        verification = store.verify_crop(crop)

    assert verification.status == VerificationStatus.PIXEL_HASH_MISMATCH
    assert verification.actual_output_pixel_sha256 is not None
    assert verification.actual_media_sha256 is not None
    assert verification.actual_size_bytes == len(tampered)


def test_invalid_png_and_missing_source_are_typed_results(tmp_path: Path) -> None:
    root, workspace = _workspace(tmp_path)
    frame = _frame()
    provider = _PixelProvider(frame)
    with workspace:
        store = _store(workspace, provider)
        crop = store.create_crop(_goggle_request(frame))
        assert crop.local_path is not None
        (root / Path(crop.local_path)).write_bytes(b"not-a-png")
        invalid = store.verify_crop(crop)
        provider.frame = None
        missing_source = store.verify_crop(crop)

    assert invalid.status == VerificationStatus.INVALID_MEDIA
    assert invalid.actual_media_sha256 is not None
    assert invalid.actual_source_pixel_sha256 is None
    assert missing_source.status == VerificationStatus.MISSING
    assert missing_source.reason_code == "SOURCE_FRAME_UNAVAILABLE"


def test_source_pixel_divergence_is_distinct_from_media_integrity(tmp_path: Path) -> None:
    _, workspace = _workspace(tmp_path)
    original = _frame()
    provider = _PixelProvider(original)
    with workspace:
        store = _store(workspace, provider)
        crop = store.create_crop(_goggle_request(original))
        provider.frame = _frame(offset=1)
        verification = store.verify_crop(crop)

    assert verification.status == VerificationStatus.SOURCE_HASH_MISMATCH
    assert verification.actual_media_sha256 == crop.media_sha256
    assert verification.actual_output_pixel_sha256 == crop.pixel_sha256


def test_purged_and_purging_crops_never_open_media(tmp_path: Path) -> None:
    _, workspace = _workspace(tmp_path)
    frame = _frame()
    provider = _PixelProvider(frame)
    with workspace:
        store = _store(workspace, provider)
        crop = store.create_crop(_goggle_request(frame))
        calls_before = provider.calls
        purged = crop.model_copy(
            update={
                "availability": MediaAvailability.PURGED_BY_RETENTION,
                "local_path": None,
            }
        )
        purging = crop.model_copy(update={"availability": MediaAvailability.PURGING})
        purged_result = store.verify_crop(purged)
        purging_result = store.verify_crop(purging)

    assert purged_result.status == VerificationStatus.PURGED_BY_RETENTION
    assert purging_result.status == VerificationStatus.MISSING
    assert provider.calls == calls_before


def test_hardlinked_media_is_not_treated_as_verified(tmp_path: Path) -> None:
    root, workspace = _workspace(tmp_path)
    frame = _frame()
    with workspace:
        store = _store(workspace, _PixelProvider(frame))
        crop = store.create_crop(_goggle_request(frame))
        assert crop.local_path is not None
        linked_relative = f"{RUN_ID}/frames/linked.png"
        try:
            os.link(root / Path(crop.local_path), root / Path(linked_relative))
        except OSError as error:
            pytest.skip(f"hardlinks unavailable on this test filesystem: {error}")
        verification = store.verify_crop(crop)

    assert verification.status == VerificationStatus.UNSAFE_LINK


def test_crop_contract_rejects_posthoc_non_panorama_resize(tmp_path: Path) -> None:
    _, workspace = _workspace(tmp_path)
    frame = _frame()
    with workspace:
        crop = _store(workspace, _PixelProvider(frame)).create_crop(_goggle_request(frame))
    with pytest.raises(ValidationError, match="dimensions must equal"):
        crop.model_copy(update={"output_width": crop.output_width - 1})
