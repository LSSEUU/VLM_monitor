"""Deterministic ID constructors backed by explicit semantic projections."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from labcourt.contracts.enums import CropSource, PrivacyPolicy, ViolationType
from labcourt.contracts.events import derive_case_id, derive_event_id
from labcourt.contracts.evidence import EvidencePack, derive_crop_id
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token, require_track_ref_camera
from labcourt.domain.canonical import sha256_hex


def _validate_stream_token(value: str, name: str) -> None:
    require_reference_token(value, name)


def make_event_id(
    *,
    camera_id: str,
    stream_id: str,
    violation_type: ViolationType,
    primary_track_ref: str | None,
    start_frame: int,
    rule_version: str,
) -> str:
    _validate_stream_token(camera_id, "camera_id")
    _validate_stream_token(stream_id, "stream_id")
    if not isinstance(start_frame, int) or isinstance(start_frame, bool):
        raise TypeError("start_frame must be an integer")
    if start_frame < 0:
        raise ValueError("start_frame must be non-negative")
    if not rule_version:
        raise ValueError("rule_version cannot be empty")
    if primary_track_ref is not None:
        require_track_ref_camera(primary_track_ref, camera_id)
    return derive_event_id(
        camera_id=camera_id,
        stream_id=stream_id,
        violation_type=violation_type,
        primary_track_ref=primary_track_ref,
        start_frame=start_frame,
        rule_version=rule_version,
    )


def make_case_id(event_id: str) -> str:
    return derive_case_id(event_id)


def make_crop_id(
    *,
    frame_id: str,
    bbox: BBoxXYXY,
    output_width: int,
    output_height: int,
    crop_source: CropSource,
    source_media_sha256: str,
    privacy_policy: PrivacyPolicy,
    privacy_transform_version: str,
    encoding_version: str,
) -> str:
    return derive_crop_id(
        frame_id=frame_id,
        bbox=bbox,
        output_width=output_width,
        output_height=output_height,
        crop_source=crop_source,
        source_media_sha256=source_media_sha256,
        privacy_policy=privacy_policy,
        privacy_transform_version=privacy_transform_version,
        encoding_version=encoding_version,
    )


def _find_forbidden_keys(
    value: object,
    forbidden: set[str],
    path: str = "$",
) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if isinstance(key, str) and key in forbidden:
                found.append(child_path)
            found.extend(_find_forbidden_keys(item, forbidden, child_path))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            found.extend(_find_forbidden_keys(item, forbidden, f"{path}[{index}]"))
    return found


def _validate_projection(
    payload: Mapping[str, object],
    *,
    name: str,
    forbidden: set[str],
) -> None:
    if not payload:
        raise ValueError(f"{name} hash payload cannot be empty")
    found = _find_forbidden_keys(payload, forbidden)
    if found:
        raise ValueError(f"{name} hash payload contains forbidden fields: {found}")


def make_pack_id(pack: EvidencePack) -> str:
    """Return the identity owned by the validated EvidencePack contract."""

    if not isinstance(pack, EvidencePack):
        raise TypeError("pack must be an EvidencePack")
    return pack.pack_id


def make_manifest_id(manifest: RunManifest) -> str:
    """Return the identity owned by the validated RunManifest contract."""

    if not isinstance(manifest, RunManifest):
        raise TypeError("manifest must be a RunManifest")
    return manifest.manifest_id


def make_semantic_case_hash(case_hash_payload: Mapping[str, object]) -> str:
    forbidden = {
        "semantic_case_hash",
        "run_id",
        "created_at",
        "updated_at",
        "recorded_at",
        "local_path",
    }
    _validate_projection(case_hash_payload, name="case", forbidden=forbidden)
    return sha256_hex(["semantic-case", 1, case_hash_payload])
