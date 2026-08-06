"""Runtime-only, dependency-free pixel transport boundary."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from struct import pack
from typing import Protocol

from labcourt.contracts.frames import FrameRef

PIXEL_HASH_ALGORITHM = "LCPIX1"
LCPIX1_DOMAIN_SEPARATOR = b"LCPIX1\x00"
LCPIX1_RGB8_FORMAT_TAG = b"RGB8\x00"
LCPIX1_RGB8_HEADER_SIZE_BYTES = len(LCPIX1_DOMAIN_SEPARATOR) + 8 + len(LCPIX1_RGB8_FORMAT_TAG)


def _validate_rgb8_pixels(width: int, height: int, pixels: bytes) -> None:
    if (
        not isinstance(width, int)
        or isinstance(width, bool)
        or not isinstance(height, int)
        or isinstance(height, bool)
    ):
        raise TypeError("RGB8 dimensions must be integers")
    if not 0 < width <= 0xFFFFFFFF or not 0 < height <= 0xFFFFFFFF:
        raise ValueError("RGB8 dimensions must fit positive uint32 values")
    if not isinstance(pixels, bytes):
        raise TypeError("RGB8 pixels must be bytes")
    if len(pixels) != width * height * 3:
        raise ValueError("RGB8 byte length must equal width * height * 3")


def rgb8_pixel_preimage(width: int, height: int, pixels: bytes) -> bytes:
    """Return the complete LCPIX1 content preimage.

    The byte layout is exactly ``LCPIX1\\0 || uint32be(width) ||
    uint32be(height) || RGB8\\0 || pixels``. Pixels are tightly packed,
    row-major RGB8 bytes with no row padding.
    """

    _validate_rgb8_pixels(width, height, pixels)
    return LCPIX1_DOMAIN_SEPARATOR + pack(">II", width, height) + LCPIX1_RGB8_FORMAT_TAG + pixels


def rgb8_pixel_preimage_size_bytes(width: int, height: int, pixels: bytes) -> int:
    """Return LCPIX1 physical ``size_bytes``, including its complete header.

    This is deliberately not the raw RGB payload length. It is the byte length
    of :func:`rgb8_pixel_preimage`, so M6 hash and size attest the same content.
    """

    _validate_rgb8_pixels(width, height, pixels)
    return LCPIX1_RGB8_HEADER_SIZE_BYTES + len(pixels)


def rgb8_pixel_sha256(width: int, height: int, pixels: bytes) -> str:
    """Hash the complete canonical LCPIX1 RGB8 content preimage."""

    return sha256(rgb8_pixel_preimage(width, height, pixels)).hexdigest()


@dataclass(frozen=True, slots=True)
class RGB8Frame:
    """One tightly packed, row-major RGB8 frame.

    ``pixels`` contains exactly three bytes per pixel in RGB channel order, with
    no row padding. This is an in-process value and is deliberately not a
    Pydantic or ndarray-backed persistence contract.
    """

    frame: FrameRef
    pixels: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.frame, FrameRef):
            raise TypeError("RGB8Frame.frame must be a validated FrameRef")
        if not isinstance(self.pixels, bytes):
            raise TypeError("RGB8Frame.pixels must be bytes")
        if not self.frame.content_sha256:
            raise ValueError("FrameRef.content_sha256 is required for RGB8 pixels")

        expected_length = self.frame.width * self.frame.height * 3
        if len(self.pixels) != expected_length:
            raise ValueError("RGB8 byte length must equal width * height * 3")

        actual_sha256 = rgb8_pixel_sha256(
            self.frame.width,
            self.frame.height,
            self.pixels,
        )
        if not compare_digest(self.frame.content_sha256, actual_sha256):
            raise ValueError("FrameRef.content_sha256 does not match RGB8 bytes")


class PixelFrameProvider(Protocol):
    """Resolve authoritative frame IDs to validated RGB8 runtime pixels."""

    def read_rgb8(self, frame_id: str) -> RGB8Frame: ...


__all__ = [
    "LCPIX1_DOMAIN_SEPARATOR",
    "LCPIX1_RGB8_FORMAT_TAG",
    "LCPIX1_RGB8_HEADER_SIZE_BYTES",
    "PIXEL_HASH_ALGORITHM",
    "PixelFrameProvider",
    "RGB8Frame",
    "rgb8_pixel_preimage",
    "rgb8_pixel_preimage_size_bytes",
    "rgb8_pixel_sha256",
]
