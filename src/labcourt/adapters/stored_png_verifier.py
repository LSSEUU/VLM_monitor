"""Source-independent verification of persisted, canonical M2 PNG crops."""

from __future__ import annotations

import struct
from io import BytesIO

from PIL import Image, UnidentifiedImageError

from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage.secure_workspace import SecureFileSnapshot, SecureWorkspace
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    MediaType,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.exceptions import ArtifactIntegrityViolation, PathBoundaryViolation
from labcourt.ports.pixels import rgb8_pixel_sha256

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_IHDR_PREFIX = _PNG_SIGNATURE + b"\x00\x00\x00\rIHDR"
_UNSAFE_LINK_REASONS = ("LINK", "REPARSE", "HARDLINK")
_NON_REGULAR_REASONS = ("NOT_REGULAR", "NON_REGULAR", "NOT_DISK", "DIRECTORY")


class StoredPngVerifier:
    """Verify stored media without replaying unavailable source-frame pixels.

    Privacy receipts and creation closure remain protected by the immutable database
    contracts. This adapter verifies the current locator, file identity, canonical PNG
    encoding, dimensions, output-pixel hash, encoded hash, and encoded size only.
    """

    __slots__ = ("_max_image_pixels", "_max_media_bytes", "_run_id", "_workspace")

    def __init__(
        self,
        *,
        run_id: str,
        workspace: SecureWorkspace,
        max_media_bytes: int,
        max_image_pixels: int,
    ) -> None:
        self._run_id = require_reference_token(run_id, "stored PNG verifier run_id")
        if not isinstance(workspace, SecureWorkspace):
            raise TypeError("StoredPngVerifier requires a SecureWorkspace")
        for value, name in (
            (max_media_bytes, "max_media_bytes"),
            (max_image_pixels, "max_image_pixels"),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        self._workspace = workspace
        self._max_media_bytes = min(max_media_bytes, workspace.max_file_bytes)
        self._max_image_pixels = max_image_pixels

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        if not isinstance(crop, Crop):
            raise TypeError("verify_crop requires a validated Crop")
        if crop.availability == MediaAvailability.PURGED_BY_RETENTION:
            return self._without_actuals(
                crop,
                VerificationStatus.PURGED_BY_RETENTION,
                "PURGED_BY_RETENTION",
            )
        if crop.availability == MediaAvailability.PURGING:
            return self._without_actuals(crop, VerificationStatus.MISSING, "MEDIA_PURGING")

        canonical_path = f"{self._run_id}/frames/{crop.media_sha256}.png"
        if crop.local_path != canonical_path:
            return self._without_actuals(
                crop,
                VerificationStatus.PATH_BOUNDARY_VIOLATION,
                "NONCANONICAL_MEDIA_LOCATOR",
            )
        if crop.media_type != MediaType.IMAGE_PNG:
            return self._without_actuals(
                crop,
                VerificationStatus.INVALID_MEDIA,
                "UNSUPPORTED_MEDIA_TYPE",
            )

        try:
            snapshot = self._workspace.read_verified(canonical_path)
        except PathBoundaryViolation as error:
            return self._path_failure(crop, error.reason_code)
        except ArtifactIntegrityViolation:
            return self._without_actuals(
                crop,
                VerificationStatus.PATH_BOUNDARY_VIOLATION,
                "WORKSPACE_INTEGRITY_FAILURE",
            )
        if snapshot.size_bytes > self._max_media_bytes:
            return self._path_failure(crop, "FILE_TOO_LARGE")

        try:
            width, height, pixels = self._decode_canonical_png(snapshot)
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

        actual_pixel_sha256 = rgb8_pixel_sha256(width, height, pixels)
        status = VerificationStatus.CURRENT_MEDIA_VERIFIED
        if (width, height) != (crop.output_width, crop.output_height):
            status = VerificationStatus.DIMENSION_MISMATCH
        elif actual_pixel_sha256 != crop.pixel_sha256:
            status = VerificationStatus.PIXEL_HASH_MISMATCH
        elif snapshot.sha256 != crop.media_sha256:
            status = VerificationStatus.MEDIA_HASH_MISMATCH
        elif snapshot.size_bytes != crop.size_bytes:
            status = VerificationStatus.SIZE_MISMATCH
        return ArtifactVerification(
            artifact_ref=self._crop_ref(crop),
            status=status,
            availability=crop.availability,
            media_type=MediaType.IMAGE_PNG,
            expected_source_pixel_sha256=crop.source_media_sha256,
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
        )

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        require_reference_token(run_id, "stored PNG verifier reference run_id")
        if run_id != self._run_id:
            raise ValueError("reference run_id differs from the stored PNG verifier scope")
        if not isinstance(ref, ArtifactRef):
            raise TypeError("reference_exists requires an ArtifactRef")
        return False

    def _decode_canonical_png(
        self,
        snapshot: SecureFileSnapshot,
    ) -> tuple[int, int, bytes]:
        data = snapshot.bytes
        if len(data) < 33 or not data.startswith(_PNG_IHDR_PREFIX):
            raise ValueError("media is not a canonical PNG")
        width, height = struct.unpack(">II", data[16:24])
        if width <= 0 or height <= 0 or width * height > self._max_image_pixels:
            raise ValueError("decoded PNG exceeds the pixel budget")
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

    @staticmethod
    def _crop_ref(crop: Crop) -> ArtifactRef:
        return ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)

    @classmethod
    def _without_actuals(
        cls,
        crop: Crop,
        status: VerificationStatus,
        reason_code: str,
    ) -> ArtifactVerification:
        return ArtifactVerification(
            artifact_ref=cls._crop_ref(crop),
            status=status,
            availability=crop.availability,
            media_type=crop.media_type,
            expected_source_pixel_sha256=crop.source_media_sha256,
            expected_output_pixel_sha256=crop.pixel_sha256,
            expected_media_sha256=crop.media_sha256,
            expected_width=crop.output_width,
            expected_height=crop.output_height,
            expected_size_bytes=crop.size_bytes,
            reason_code=reason_code,
        )

    @classmethod
    def _path_failure(cls, crop: Crop, reason_code: str) -> ArtifactVerification:
        status = VerificationStatus.PATH_BOUNDARY_VIOLATION
        if any(token in reason_code for token in _UNSAFE_LINK_REASONS):
            status = VerificationStatus.UNSAFE_LINK
        elif any(token in reason_code for token in _NON_REGULAR_REASONS):
            status = VerificationStatus.NOT_REGULAR_FILE
        return cls._without_actuals(crop, status, reason_code[:64])


__all__ = ["StoredPngVerifier"]
