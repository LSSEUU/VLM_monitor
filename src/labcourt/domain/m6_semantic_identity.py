"""Run-independent semantic identities used by the M6 replay projection."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.hearing_acquisition import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
)
from labcourt.contracts.references import parse_track_ref


def m6_semantic_detection_attributes(detection: Detection) -> dict[str, object]:
    """Keep detector conclusions while excluding provider/component provenance."""

    return {
        key: detection.attributes[key]
        for key in ("cap_detected", "occluded")
        if key in detection.attributes
    }


def m6_semantic_detection_body(detection: Detection) -> dict[str, object]:
    """Project a detection without its opaque identity or tracker alias."""

    return {
        "frame_id": detection.frame_id,
        "label": detection.label,
        "bbox": detection.bbox.model_dump(mode="json"),
        "score": detection.score,
        "keypoints": sorted(
            (item.model_dump(mode="json") for item in detection.keypoints),
            key=canonical_json,
        ),
        "attributes": m6_semantic_detection_attributes(detection),
    }


def _crop_profile(crop: Crop) -> dict[str, object]:
    return {
        "crop_id": crop.crop_id,
        "frame_id": crop.frame_id,
        "source": crop.source.value,
        "bbox": crop.bbox.model_dump(mode="json"),
        "source_media_sha256": crop.source_media_sha256,
        "pixel_sha256": crop.pixel_sha256,
        "media_sha256": crop.media_sha256,
    }


def _crop_request_profile(request: CropRequest) -> dict[str, object]:
    return {
        "frame_id": request.frame_id,
        "source": request.source.value,
        "bbox": request.bbox.model_dump(mode="json"),
        "output_width": request.output_width,
        "output_height": request.output_height,
        "panorama_long_edge_limit": request.panorama_long_edge_limit,
        "privacy_policy": request.privacy_policy.value,
        "privacy_transform_version": request.privacy_transform_version,
        "encoding_version": request.encoding_version,
        "ppe_type": request.ppe_type.value if request.ppe_type is not None else None,
        "anchor_type": request.anchor_type.value if request.anchor_type is not None else None,
        "anchor_bbox": (
            request.anchor_bbox.model_dump(mode="json") if request.anchor_bbox is not None else None
        ),
        "keypoints": [item.model_dump(mode="json") for item in request.keypoints],
        "association_method": (
            request.association_method.value if request.association_method is not None else None
        ),
        "observability": (
            request.observability.model_dump(mode="json")
            if request.observability is not None
            else None
        ),
    }


@dataclass(frozen=True, slots=True)
class M6SemanticTrackIndex:
    """Map opaque tracker aliases to content-and-relation semantic profiles."""

    entries: tuple[tuple[str, str, str], ...]

    def project(self, track_ref: str | None) -> object:
        if track_ref is None:
            return None
        matches = tuple(
            (camera_id, profile_sha256)
            for raw_ref, camera_id, profile_sha256 in self.entries
            if raw_ref == track_ref
        )
        if len(matches) != 1:
            raise ValueError("M6 semantic projection cannot resolve a track reference")
        camera_id, profile_sha256 = matches[0]
        return {
            "camera_id": camera_id,
            "profile_sha256": profile_sha256,
        }


def build_m6_semantic_track_index(
    *,
    case: Case | None = None,
    perception_detections: tuple[Detection, ...] = (),
    acquisitions: tuple[tuple[AcquisitionRequest, AcquisitionExecutionPublication], ...] = (),
) -> M6SemanticTrackIndex:
    """Build a canonical track profile without using tracker epoch/local IDs."""

    profiles: dict[str, list[object]] = {}

    def add(track_ref: str | None, descriptor: object) -> None:
        if track_ref is None:
            return
        parse_track_ref(track_ref)
        profiles.setdefault(track_ref, []).append(descriptor)

    if case is not None:
        event = case.event
        event_scope = {
            "camera_id": event.camera_id,
            "stream_id": event.stream_id,
            "violation_type": event.violation_type.value,
            "rule_version": event.rule_version,
            "start_frame": event.start_frame,
            "end_frame_exclusive": event.end_frame_exclusive,
            "trigger_frame": event.trigger_frame,
        }
        add(event.primary_track_ref, ["event", "primary", event_scope])
        for track_ref in event.related_track_refs:
            add(track_ref, ["event", "related", event_scope])
        for pack in case.evidence_packs:
            add(
                pack.track_summary.primary_track_ref,
                [
                    "evidence-pack",
                    pack.version,
                    "track-summary",
                    pack.track_summary.start_frame,
                    pack.track_summary.end_frame_exclusive,
                    pack.track_summary.observed_frame_count,
                ],
            )
            for group_name, crops in (
                ("panorama", pack.panorama_crops),
                ("subject", pack.subject_crops),
                ("focus", pack.focus_crops),
                ("temporal", pack.temporal_crops),
            ):
                for crop in crops:
                    add(
                        crop.primary_track_ref,
                        ["evidence-pack", pack.version, group_name, _crop_profile(crop)],
                    )

    for detection in perception_detections:
        add(
            detection.track_ref,
            ["perception-detection", m6_semantic_detection_body(detection)],
        )

    for request, publication in acquisitions:
        round_scope = ["acquisition", request.round_index, request.action.value]
        parameters = request.validated_parameters
        if isinstance(parameters, TrackConfidenceCurveParameters):
            add(
                parameters.track_ref,
                [
                    *round_scope,
                    "track-confidence-parameters",
                    parameters.start_frame,
                    parameters.end_frame_exclusive,
                ],
            )
        for detection in publication.detections:
            add(
                detection.track_ref,
                [*round_scope, "detection", m6_semantic_detection_body(detection)],
            )
        for crop in publication.crops:
            add(
                crop.primary_track_ref,
                [*round_scope, "crop", _crop_profile(crop)],
            )
        if publication.crop_request is not None:
            add(
                publication.crop_request.primary_track_ref,
                [*round_scope, "crop-request", _crop_request_profile(publication.crop_request)],
            )

    entries = tuple(
        sorted(
            (
                raw_ref,
                parse_track_ref(raw_ref)[0],
                sha256_hex(
                    [
                        "m6-semantic-track-profile",
                        1,
                        parse_track_ref(raw_ref)[0],
                        sorted(descriptors, key=canonical_json),
                    ]
                ),
            )
            for raw_ref, descriptors in profiles.items()
        )
    )
    return M6SemanticTrackIndex(entries=entries)


__all__ = [
    "M6SemanticTrackIndex",
    "build_m6_semantic_track_index",
    "m6_semantic_detection_attributes",
    "m6_semantic_detection_body",
]
