"""Deterministic Pillow FrameStore backed exclusively by SecureWorkspace."""

from __future__ import annotations

import struct
from importlib.metadata import version
from io import BytesIO

from PIL import Image, UnidentifiedImageError

from labcourt.adapters.pillow_media import encode_rgb_png, prepare_crop
from labcourt.adapters.storage.secure_workspace import SecureFileSnapshot, SecureWorkspace
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    MediaType,
    PrivacyPolicy,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, CropRequest, derive_crop_id
from labcourt.contracts.manifests import SoftwareComponentManifest
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    EvidenceMissing,
    PathBoundaryViolation,
    PrivacyPolicyViolation,
)
from labcourt.ports.pixels import PixelFrameProvider, RGB8Frame, rgb8_pixel_sha256

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_IHDR_PREFIX = _PNG_SIGNATURE + b"\x00\x00\x00\rIHDR"
_UNSAFE_LINK_REASONS = ("LINK", "REPARSE", "HARDLINK")
_NON_REGULAR_REASONS = ("NOT_REGULAR", "NON_REGULAR", "NOT_DISK", "DIRECTORY")
_PILLOW_COMPONENT = "pillow"
_PILLOW_PACKAGE = "Pillow"
_PILLOW_LICENSE = "HPND"


class PillowFrameStore:
    """Create and verify privacy-transformed PNG crops without direct path I/O."""

    __slots__ = (
        "_max_image_pixels",
        "_max_media_bytes",
        "_pixels",
        "_run_id",
        "_software_component",
        "_workspace",
    )

    def __init__(
        self,
        *,
        run_id: str,
        workspace: SecureWorkspace,
        pixels: PixelFrameProvider,
        max_media_bytes: int,
        max_image_pixels: int,
    ) -> None:
        require_reference_token(run_id, "PillowFrameStore run_id")
        if not isinstance(workspace, SecureWorkspace):
            raise TypeError("PillowFrameStore requires a SecureWorkspace")
        if not isinstance(max_media_bytes, int) or isinstance(max_media_bytes, bool):
            raise TypeError("max_media_bytes must be an integer")
        if not isinstance(max_image_pixels, int) or isinstance(max_image_pixels, bool):
            raise TypeError("max_image_pixels must be an integer")
        if max_media_bytes <= 0 or max_image_pixels <= 0:
            raise ValueError("media byte and image-pixel limits must be positive")
        self._run_id = run_id
        self._software_component = SoftwareComponentManifest(
            component=_PILLOW_COMPONENT,
            package=_PILLOW_PACKAGE,
            version=version(_PILLOW_PACKAGE),
            license_id=_PILLOW_LICENSE,
        )
        self._workspace = workspace
        self._pixels = pixels
        self._max_media_bytes = min(max_media_bytes, workspace.max_file_bytes)
        self._max_image_pixels = max_image_pixels

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def software_component(self) -> SoftwareComponentManifest:
        return self._software_component

    def create_crop(self, request: CropRequest) -> Crop:
        if not isinstance(request, CropRequest):
            raise TypeError("create_crop requires a validated CropRequest")
        if request.privacy_policy == PrivacyPolicy.EPHEMERAL_RAW:
            raise PrivacyPolicyViolation(
                "ephemeral raw pixels require the separate TTL cache and cannot be persisted"
            )
        frame = self._pixels.read_rgb8(request.frame_id)
        self._validate_source_frame(frame, request.frame_id)
        self._require_pixel_budget(frame.frame.width, frame.frame.height, "source frame")
        self._require_pixel_budget(request.output_width, request.output_height, "crop output")

        result = prepare_crop(frame, request)
        if len(result.prepared.png_bytes) > self._max_media_bytes:
            raise PathBoundaryViolation("FILE_TOO_LARGE")
        crop_id = derive_crop_id(
            frame_id=request.frame_id,
            bbox=request.bbox,
            output_width=request.output_width,
            output_height=request.output_height,
            crop_source=request.source,
            source_media_sha256=result.source_sha256,
            privacy_policy=request.privacy_policy,
            privacy_transform_version=request.privacy_transform_version,
            encoding_version=request.encoding_version,
        )
        # Media rows are keyed by encoded content, so equal canonical PNG bytes must
        # resolve to one immutable locator even when their semantic crop IDs differ.
        # This is byte-level deduplication, not a hardlink: the single regular file
        # remains subject to SecureWorkspace's link-count checks.
        final_path = self._media_path(result.prepared.media_sha256)
        crop = result.to_persisted_crop(local_path=final_path)
        if crop.crop_id != crop_id:
            raise ArtifactIntegrityViolation("CROP_ID_DIVERGENCE", final_path)

        existing = self._read_existing_final(final_path, result.prepared.media_sha256)
        if existing is None:
            self._stage_and_publish(
                crop_id=crop_id,
                final_path=final_path,
                png_bytes=result.prepared.png_bytes,
                media_sha256=result.prepared.media_sha256,
            )
        verification = self.verify_crop(crop)
        if verification.status != VerificationStatus.VERIFIED:
            raise ArtifactIntegrityViolation("POST_PUBLICATION_VERIFICATION_FAILED", final_path)
        return crop

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        if not isinstance(crop, Crop):
            raise TypeError("verify_crop requires a validated Crop")
        if crop.availability == MediaAvailability.PURGED_BY_RETENTION:
            return self._without_actuals(
                crop,
                status=VerificationStatus.PURGED_BY_RETENTION,
                reason_code="PURGED_BY_RETENTION",
            )
        if crop.availability == MediaAvailability.PURGING:
            return self._without_actuals(
                crop,
                status=VerificationStatus.MISSING,
                reason_code="MEDIA_PURGING",
            )
        local_path = crop.local_path
        assert local_path is not None
        canonical_path = self._media_path(crop.media_sha256)
        if local_path != canonical_path:
            return self._without_actuals(
                crop,
                status=VerificationStatus.PRIVACY_POLICY_VIOLATION,
                reason_code="NONCANONICAL_MEDIA_LOCATOR",
            )

        try:
            source = self._pixels.read_rgb8(crop.frame_id)
            self._validate_source_frame(source, crop.frame_id)
        except (EvidenceMissing, TypeError, ValueError):
            return self._without_actuals(
                crop,
                status=VerificationStatus.MISSING,
                reason_code="SOURCE_FRAME_UNAVAILABLE",
            )

        try:
            snapshot = self._workspace.read_verified(local_path)
        except PathBoundaryViolation as error:
            return self._path_failure(crop, error.reason_code)
        if snapshot.size_bytes > self._max_media_bytes:
            return self._path_failure(crop, "FILE_TOO_LARGE")

        try:
            width, height, output_pixels = self._decode_canonical_png(snapshot)
        except (UnidentifiedImageError, OSError, SyntaxError, ValueError):
            return ArtifactVerification(
                artifact_ref=self._crop_ref(crop),
                status=VerificationStatus.INVALID_MEDIA,
                availability=crop.availability,
                media_type=MediaType.IMAGE_PNG,
                expected_source_pixel_sha256=crop.source_media_sha256,
                expected_output_pixel_sha256=crop.pixel_sha256,
                expected_media_sha256=crop.media_sha256,
                expected_width=crop.output_width,
                expected_height=crop.output_height,
                expected_size_bytes=crop.size_bytes,
                actual_media_sha256=snapshot.sha256,
                actual_size_bytes=snapshot.size_bytes,
                reason_code="INVALID_CANONICAL_PNG",
            )

        actual_source_sha256 = source.frame.content_sha256
        assert actual_source_sha256 is not None
        actual_pixel_sha256 = rgb8_pixel_sha256(width, height, output_pixels)
        status = VerificationStatus.VERIFIED
        if actual_source_sha256 != crop.source_media_sha256:
            status = VerificationStatus.SOURCE_HASH_MISMATCH
        elif (width, height) != (crop.output_width, crop.output_height):
            status = VerificationStatus.DIMENSION_MISMATCH
        elif actual_pixel_sha256 != crop.pixel_sha256:
            status = VerificationStatus.PIXEL_HASH_MISMATCH
        elif snapshot.sha256 != crop.media_sha256:
            status = VerificationStatus.MEDIA_HASH_MISMATCH
        elif snapshot.size_bytes != crop.size_bytes:
            status = VerificationStatus.SIZE_MISMATCH
        reason_code = None
        if status == VerificationStatus.VERIFIED:
            reason_code = self._privacy_replay_failure(crop, source, snapshot)
            if reason_code is not None:
                status = VerificationStatus.PRIVACY_POLICY_VIOLATION
        return ArtifactVerification(
            artifact_ref=self._crop_ref(crop),
            status=status,
            availability=crop.availability,
            media_type=MediaType.IMAGE_PNG,
            expected_source_pixel_sha256=crop.source_media_sha256,
            actual_source_pixel_sha256=actual_source_sha256,
            expected_output_pixel_sha256=crop.pixel_sha256,
            actual_output_pixel_sha256=actual_pixel_sha256,
            expected_media_sha256=crop.media_sha256,
            actual_media_sha256=snapshot.sha256,
            expected_width=crop.output_width,
            actual_width=width,
            expected_height=crop.output_height,
            actual_height=height,
            expected_size_bytes=crop.size_bytes,
            actual_size_bytes=snapshot.size_bytes,
            reason_code=reason_code,
        )

    def _privacy_replay_failure(
        self,
        crop: Crop,
        source: RGB8Frame,
        snapshot: SecureFileSnapshot,
    ) -> str | None:
        """Re-run the frozen transform so self-consistent forged hashes cannot pass."""

        receipt = crop.privacy_receipt
        try:
            request = CropRequest(
                frame_id=crop.frame_id,
                source=crop.source,
                bbox=crop.bbox,
                output_width=crop.output_width,
                output_height=crop.output_height,
                panorama_long_edge_limit=crop.panorama_long_edge_limit,
                source_refs=crop.source_refs,
                privacy_policy=receipt.policy,
                privacy_transform_version=receipt.transform_version,
                encoding_version=crop.encoding_version,
                primary_track_ref=crop.primary_track_ref,
                ppe_type=receipt.ppe_type,
                anchor_type=receipt.anchor_type,
                anchor_bbox=receipt.anchor_bbox,
                keypoints=receipt.keypoints,
                association_method=receipt.association_method,
                observability=crop.observability,
                tags=crop.tags,
            )
            replay = prepare_crop(source, request)
            expected_path = self._media_path(crop.media_sha256)
            replayed_crop = replay.to_persisted_crop(local_path=expected_path)
        except (TypeError, ValueError):
            return "PRIVACY_CONTEXT_INVALID"
        if replayed_crop != crop or replay.prepared.png_bytes != snapshot.bytes:
            return "PRIVACY_TRANSFORM_REPLAY_MISMATCH"
        return None

    def _decode_canonical_png(
        self,
        snapshot: SecureFileSnapshot,
    ) -> tuple[int, int, bytes]:
        data = snapshot.bytes
        if len(data) < 33 or not data.startswith(_PNG_IHDR_PREFIX):
            raise ValueError("media is not a canonical PNG")
        width, height = struct.unpack(">II", data[16:24])
        self._require_pixel_budget(width, height, "decoded PNG")
        with Image.open(BytesIO(data)) as image:
            if (
                image.format != "PNG"
                or image.mode != "RGB"
                or image.size != (width, height)
                or getattr(image, "n_frames", 1) != 1
                or image.info
            ):
                raise ValueError("PNG does not match the frozen encoding profile")
            image.load()
            pixels = image.tobytes()
        if encode_rgb_png(width, height, pixels) != data:
            raise ValueError("PNG bytes do not match the deterministic encoder")
        return width, height, pixels

    def _stage_and_publish(
        self,
        *,
        crop_id: str,
        final_path: str,
        png_bytes: bytes,
        media_sha256: str,
    ) -> None:
        self._ensure_directory(".staging")
        self._ensure_directory(f".staging/{self._run_id}")
        self._ensure_directory(self._run_id)
        self._ensure_directory(f"{self._run_id}/frames")
        operation_directory = f".staging/{self._run_id}/crop-{crop_id}"
        self._ensure_directory(operation_directory)
        staged_path = f"{operation_directory}/media.png"
        try:
            self._workspace.create_new(staged_path, png_bytes, media_sha256)
        except ArtifactConflict as error:
            if error.reason_code != "TARGET_ALREADY_EXISTS":
                raise
            try:
                self._workspace.read_verified(staged_path, media_sha256)
            except (ArtifactIntegrityViolation, PathBoundaryViolation):
                raise ArtifactConflict("STAGING_CONTENT_CONFLICT", staged_path) from None
        published = self._workspace.publish_staged(
            staged_path,
            final_path,
            media_sha256,
        )
        if published.sha256 != media_sha256 or published.bytes != png_bytes:
            raise ArtifactIntegrityViolation("PUBLISHED_CONTENT_MISMATCH", final_path)
        self._workspace.remove_empty_staging_directory(operation_directory)

    def _read_existing_final(
        self,
        final_path: str,
        expected_sha256: str,
    ) -> SecureFileSnapshot | None:
        try:
            return self._workspace.read_verified(final_path, expected_sha256)
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                return None
            raise
        except ArtifactIntegrityViolation:
            raise ArtifactConflict("MEDIA_CONTENT_CONFLICT", final_path) from None

    def _ensure_directory(self, relative_path: str) -> None:
        self._workspace.ensure_private_directory(relative_path)

    def _media_path(self, media_sha256: str) -> str:
        return f"{self._run_id}/frames/{media_sha256}.png"

    def _decode_path_status(self, reason_code: str) -> VerificationStatus:
        if reason_code == "FILE_MISSING":
            return VerificationStatus.MISSING
        if any(token in reason_code for token in _UNSAFE_LINK_REASONS):
            return VerificationStatus.UNSAFE_LINK
        if any(token in reason_code for token in _NON_REGULAR_REASONS):
            return VerificationStatus.NOT_REGULAR_FILE
        return VerificationStatus.PATH_BOUNDARY_VIOLATION

    def _path_failure(self, crop: Crop, reason_code: str) -> ArtifactVerification:
        return self._without_actuals(
            crop,
            status=self._decode_path_status(reason_code),
            reason_code=reason_code[:64],
        )

    def _without_actuals(
        self,
        crop: Crop,
        *,
        status: VerificationStatus,
        reason_code: str,
    ) -> ArtifactVerification:
        return ArtifactVerification(
            artifact_ref=self._crop_ref(crop),
            status=status,
            availability=crop.availability,
            media_type=MediaType.IMAGE_PNG,
            expected_source_pixel_sha256=crop.source_media_sha256,
            expected_output_pixel_sha256=crop.pixel_sha256,
            expected_media_sha256=crop.media_sha256,
            expected_width=crop.output_width,
            expected_height=crop.output_height,
            expected_size_bytes=crop.size_bytes,
            reason_code=reason_code,
        )

    @staticmethod
    def _crop_ref(crop: Crop) -> ArtifactRef:
        return ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)

    def _validate_source_frame(self, frame: RGB8Frame, frame_id: str) -> None:
        if not isinstance(frame, RGB8Frame) or frame.frame.frame_id != frame_id:
            raise EvidenceMissing("pixel provider returned a different frame")

    def _require_pixel_budget(self, width: int, height: int, label: str) -> None:
        if width * height > self._max_image_pixels:
            raise PathBoundaryViolation(f"{label.upper().replace(' ', '_')}_TOO_LARGE")


__all__ = ["PillowFrameStore"]
