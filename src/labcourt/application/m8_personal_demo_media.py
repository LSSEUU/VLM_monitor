"""Bind one authorized local MP4 to the simulated personal Demo camera."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from labcourt.application.m8_personal_demo_camera import register_m8_personal_demo_camera
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_personal_demo import M8PersonalDemoRecordedMediaReceiptV1

_CHUNK_SIZE = 1024 * 1024
_PLAYBACK_RELATIVE_PATH = Path("media/camera-recorded-demo-01.mp4")


def _manifest(name: str) -> Sha256Hex:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def _require_mp4_signature(header: bytes, file_size: int) -> None:
    if len(header) < 16 or header[4:8] != b"ftyp":
        raise ValueError("M8 personal Demo media is not an ISO-BMFF MP4 file")
    ftyp_size = int.from_bytes(header[0:4], "big")
    if ftyp_size < 16 or ftyp_size > file_size:
        raise ValueError("M8 personal Demo media has an invalid ftyp box")


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def bind_m8_personal_demo_recorded_media(
    database_path: Path,
    input_media_path: Path,
    artifact_root: Path,
) -> M8PersonalDemoRecordedMediaReceiptV1:
    """Copy exact local MP4 bytes into the ignored Demo runtime directory."""

    if input_media_path.suffix.lower() != ".mp4":
        raise ValueError("M8 personal Demo recorded media must use the .mp4 extension")
    input_resolved = input_media_path.resolve(strict=True)
    if not input_resolved.is_file():
        raise ValueError("M8 personal Demo recorded media input is not a regular file")

    artifact_root.mkdir(parents=True, exist_ok=True)
    playback_path = artifact_root / _PLAYBACK_RELATIVE_PATH
    playback_path.parent.mkdir(parents=True, exist_ok=True)
    if playback_path.resolve() == input_resolved:
        raise ValueError("M8 personal Demo input and playback paths must be distinct")

    temporary = playback_path.with_name(f".{playback_path.name}.tmp")
    digest = hashlib.sha256()
    copied_size = 0
    try:
        with input_resolved.open("rb") as source:
            stat_before = os.fstat(source.fileno())
            header = source.read(32)
            _require_mp4_signature(header, stat_before.st_size)
            source.seek(0)
            with temporary.open("wb") as target:
                while chunk := source.read(_CHUNK_SIZE):
                    target.write(chunk)
                    digest.update(chunk)
                    copied_size += len(chunk)
                target.flush()
                os.fsync(target.fileno())
            stat_after = os.fstat(source.fileno())
        if (
            stat_before.st_size != stat_after.st_size
            or stat_before.st_mtime_ns != stat_after.st_mtime_ns
            or copied_size != stat_before.st_size
        ):
            raise ValueError("M8 personal Demo recorded media changed during binding")

        input_sha256 = digest.hexdigest()
        if playback_path.exists():
            if not playback_path.is_file():
                raise ValueError("M8 personal Demo playback path is not a regular file")
            playback_sha256, playback_size = _sha256_file(playback_path)
            if playback_sha256 != input_sha256 or playback_size != copied_size:
                raise ValueError("M8 personal Demo playback media conflicts with input authority")
            temporary.unlink()
        else:
            temporary.replace(playback_path)
            playback_sha256 = input_sha256
            playback_size = copied_size
    except Exception:
        if temporary.exists() and temporary.is_file():
            temporary.unlink()
        raise

    camera = register_m8_personal_demo_camera(database_path)
    return M8PersonalDemoRecordedMediaReceiptV1(
        source_catalog_id=camera.source_catalog_id,
        source_catalog_commit_receipt_id=camera.source_catalog_commit_receipt_id,
        raw_media_ref=f"raw-media-{input_sha256[:24]}",
        input_file_sha256=input_sha256,
        input_size_bytes=copied_size,
        playback_file_sha256=playback_sha256,
        playback_size_bytes=playback_size,
        media_binding_manifest_id=_manifest("labcourt-personal-demo-media-binding-v1"),
    )


__all__ = ["bind_m8_personal_demo_recorded_media"]
