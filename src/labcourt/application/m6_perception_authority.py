"""Resolve exact locked Frame and Detection authority for M6 replay."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection, FrameBundle
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import parse_frame_id
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_perception import (
    M6DetectionAuthorityDocument,
    M6FrameAuthorityDocument,
    M6PerceptionAuthoritySnapshot,
)


class M6PerceptionAuthorityErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_IDENTITY_INVALID = "SNAPSHOT_IDENTITY_INVALID"
    SNAPSHOT_SCOPE_MISMATCH = "SNAPSHOT_SCOPE_MISMATCH"
    SOURCE_MANIFEST_INVALID = "SOURCE_MANIFEST_INVALID"
    SOURCE_CASE_INVALID = "SOURCE_CASE_INVALID"
    FRAME_AUTHORITY_DUPLICATE = "FRAME_AUTHORITY_DUPLICATE"
    FRAME_AUTHORITY_UNSTABLE = "FRAME_AUTHORITY_UNSTABLE"
    FRAME_AUTHORITY_MISSING = "FRAME_AUTHORITY_MISSING"
    FRAME_AUTHORITY_EXTRA = "FRAME_AUTHORITY_EXTRA"
    FRAME_AUTHORITY_SCOPE_MISMATCH = "FRAME_AUTHORITY_SCOPE_MISMATCH"
    FRAME_AUTHORITY_DOCUMENT_INVALID = "FRAME_AUTHORITY_DOCUMENT_INVALID"
    FRAME_AUTHORITY_BINDING_MISMATCH = "FRAME_AUTHORITY_BINDING_MISMATCH"
    DETECTION_AUTHORITY_DUPLICATE = "DETECTION_AUTHORITY_DUPLICATE"
    DETECTION_AUTHORITY_UNSTABLE = "DETECTION_AUTHORITY_UNSTABLE"
    DETECTION_AUTHORITY_MISSING = "DETECTION_AUTHORITY_MISSING"
    DETECTION_AUTHORITY_EXTRA = "DETECTION_AUTHORITY_EXTRA"
    DETECTION_AUTHORITY_SCOPE_MISMATCH = "DETECTION_AUTHORITY_SCOPE_MISMATCH"
    DETECTION_AUTHORITY_DOCUMENT_INVALID = "DETECTION_AUTHORITY_DOCUMENT_INVALID"
    DETECTION_AUTHORITY_BINDING_MISMATCH = "DETECTION_AUTHORITY_BINDING_MISMATCH"
    DETECTION_FRAME_INVALID = "DETECTION_FRAME_INVALID"
    RESOLVED_PERCEPTION_INVALID = "RESOLVED_PERCEPTION_INVALID"


class M6PerceptionAuthorityError(LabCourtError):
    """One locked perception inventory cannot be proven from its snapshot."""

    def __init__(self, code: M6PerceptionAuthorityErrorCode) -> None:
        if not isinstance(code, M6PerceptionAuthorityErrorCode):
            raise TypeError("code must be an M6PerceptionAuthorityErrorCode")
        self.code = code
        super().__init__(f"M6 perception authority failed: {code.value}")


def _fail(code: M6PerceptionAuthorityErrorCode) -> NoReturn:
    raise M6PerceptionAuthorityError(code)


def _document_sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validated_arguments(
    closure: object,
    snapshot: object,
) -> tuple[M6ReplayInputClosureAuthority, M6PerceptionAuthoritySnapshot]:
    if not isinstance(closure, M6ReplayInputClosureAuthority) or not isinstance(
        snapshot, M6PerceptionAuthoritySnapshot
    ):
        _fail(M6PerceptionAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        canonical_closure = M6ReplayInputClosureAuthority.model_validate(
            closure.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6PerceptionAuthorityErrorCode.INVALID_ARGUMENT)
    if canonical_closure != closure:
        _fail(M6PerceptionAuthorityErrorCode.INVALID_ARGUMENT)
    if not _is_sha256(snapshot.source_identity_sha256):
        _fail(M6PerceptionAuthorityErrorCode.SNAPSHOT_IDENTITY_INVALID)
    return canonical_closure, snapshot


def _validated_manifest(
    closure: M6ReplayInputClosureAuthority,
    snapshot: M6PerceptionAuthoritySnapshot,
) -> RunManifest:
    if (
        snapshot.run_id != closure.source_run_id
        or snapshot.manifest_id != closure.source_manifest_id
        or snapshot.manifest_document_sha256 != closure.source_manifest_document_sha256
    ):
        _fail(M6PerceptionAuthorityErrorCode.SNAPSHOT_SCOPE_MISMATCH)
    try:
        manifest = RunManifest.model_validate_json(snapshot.manifest_canonical_document)
    except (TypeError, ValueError, ValidationError):
        _fail(M6PerceptionAuthorityErrorCode.SOURCE_MANIFEST_INVALID)
    if (
        canonical_json(manifest.model_dump(mode="json")) != snapshot.manifest_canonical_document
        or _document_sha256(snapshot.manifest_canonical_document)
        != snapshot.manifest_document_sha256
        or manifest.manifest_id != snapshot.manifest_id
    ):
        _fail(M6PerceptionAuthorityErrorCode.SOURCE_MANIFEST_INVALID)
    return manifest


def _validate_source_case(
    closure: M6ReplayInputClosureAuthority,
    snapshot: M6PerceptionAuthoritySnapshot,
) -> None:
    snapshot_case_values = (
        snapshot.source_case_id,
        snapshot.source_case_revision,
        snapshot.source_case_canonical_document,
        snapshot.source_case_document_sha256,
    )
    if closure.source_case_id is None:
        if any(value is not None for value in snapshot_case_values):
            _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)
        return
    if any(value is None for value in snapshot_case_values):
        _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)
    assert snapshot.source_case_id is not None
    assert snapshot.source_case_revision is not None
    assert snapshot.source_case_canonical_document is not None
    assert snapshot.source_case_document_sha256 is not None
    if not isinstance(snapshot.source_case_revision, int) or isinstance(
        snapshot.source_case_revision, bool
    ):
        _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)
    if (
        snapshot.source_case_id != closure.source_case_id
        or snapshot.source_case_revision != closure.source_case_revision
        or snapshot.source_case_document_sha256 != closure.source_case_document_sha256
    ):
        _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)
    try:
        source_case = Case.model_validate_json(snapshot.source_case_canonical_document)
    except (TypeError, ValueError, ValidationError):
        _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)
    if (
        canonical_json(source_case.model_dump(mode="json"))
        != snapshot.source_case_canonical_document
        or _document_sha256(snapshot.source_case_canonical_document)
        != snapshot.source_case_document_sha256
        or source_case.run_id != closure.source_run_id
        or source_case.case_id != closure.source_case_id
        or source_case.manifest_id != closure.source_manifest_id
    ):
        _fail(M6PerceptionAuthorityErrorCode.SOURCE_CASE_INVALID)


def _require_exact_frame_inventory(
    closure: M6ReplayInputClosureAuthority,
    documents: tuple[M6FrameAuthorityDocument, ...],
) -> None:
    if not isinstance(documents, tuple) or any(
        not isinstance(document, M6FrameAuthorityDocument) for document in documents
    ):
        _fail(M6PerceptionAuthorityErrorCode.INVALID_ARGUMENT)
    actual_ids = tuple(document.frame_id for document in documents)
    if len(actual_ids) != len(set(actual_ids)):
        _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_DUPLICATE)
    try:
        actual_keys = tuple(parse_frame_id(frame_id) for frame_id in actual_ids)
    except (TypeError, ValueError):
        _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_DOCUMENT_INVALID)
    if actual_keys != tuple(sorted(actual_keys)):
        _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_UNSTABLE)
    expected_ids = tuple(item.frame_id for item in closure.frames)
    if set(expected_ids) - set(actual_ids):
        _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_MISSING)
    if set(actual_ids) - set(expected_ids):
        _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_EXTRA)


def _require_exact_detection_inventory(
    closure: M6ReplayInputClosureAuthority,
    documents: tuple[M6DetectionAuthorityDocument, ...],
) -> None:
    if not isinstance(documents, tuple) or any(
        not isinstance(document, M6DetectionAuthorityDocument) for document in documents
    ):
        _fail(M6PerceptionAuthorityErrorCode.INVALID_ARGUMENT)
    actual_ids = tuple(document.detection_id for document in documents)
    if len(actual_ids) != len(set(actual_ids)):
        _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_DUPLICATE)
    try:
        actual_keys = tuple(
            (parse_frame_id(document.frame_id), document.detection_id) for document in documents
        )
    except (TypeError, ValueError):
        _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_DOCUMENT_INVALID)
    if actual_keys != tuple(sorted(actual_keys)):
        _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_UNSTABLE)
    expected_ids = tuple(item.detection_id for item in closure.detections)
    if set(expected_ids) - set(actual_ids):
        _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_MISSING)
    if set(actual_ids) - set(expected_ids):
        _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_EXTRA)


def _resolve_frames(
    closure: M6ReplayInputClosureAuthority,
    snapshot: M6PerceptionAuthoritySnapshot,
) -> tuple[FrameRef, ...]:
    expected = {item.frame_id: item for item in closure.frames}
    frames: list[FrameRef] = []
    for document in snapshot.frames:
        if document.run_id != closure.source_run_id or document.manifest_id != (
            closure.source_manifest_id
        ):
            _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_SCOPE_MISMATCH)
        try:
            frame = FrameRef.model_validate_json(document.canonical_document)
        except (TypeError, ValueError, ValidationError):
            _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_DOCUMENT_INVALID)
        item = expected[document.frame_id]
        if (
            canonical_json(frame.model_dump(mode="json")) != document.canonical_document
            or _document_sha256(document.canonical_document) != document.document_sha256
            or document.document_sha256 != item.document_sha256
        ):
            _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_DOCUMENT_INVALID)
        if (
            frame.frame_id != document.frame_id
            or frame.content_sha256 is None
            or frame.content_sha256 != document.content_sha256
            or frame.content_sha256 != item.content_sha256
        ):
            _fail(M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_BINDING_MISMATCH)
        frames.append(frame)
    return tuple(frames)


def _resolve_detections(
    closure: M6ReplayInputClosureAuthority,
    snapshot: M6PerceptionAuthoritySnapshot,
    manifest: RunManifest,
    frames: tuple[FrameRef, ...],
) -> tuple[Detection, ...]:
    expected = {item.detection_id: item for item in closure.detections}
    frame_by_id = {frame.frame_id: frame for frame in frames}
    detector_manifest = manifest.models.get("detector")
    if detector_manifest is None:
        _fail(M6PerceptionAuthorityErrorCode.SOURCE_MANIFEST_INVALID)
    detections: list[Detection] = []
    for document in snapshot.detections:
        if document.run_id != closure.source_run_id or document.manifest_id != (
            closure.source_manifest_id
        ):
            _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_SCOPE_MISMATCH)
        try:
            detection = Detection.model_validate_json(document.canonical_document)
        except (TypeError, ValueError, ValidationError):
            _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_DOCUMENT_INVALID)
        item = expected[document.detection_id]
        if (
            canonical_json(detection.model_dump(mode="json")) != document.canonical_document
            or _document_sha256(document.canonical_document) != document.document_sha256
            or document.document_sha256 != item.document_sha256
        ):
            _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_DOCUMENT_INVALID)
        if (
            detection.detection_id != document.detection_id
            or detection.frame_id != document.frame_id
            or detection.frame_id != item.frame_id
            or detection.model_manifest_id != document.model_manifest_id
            or detection.model_manifest_id != item.model_manifest_id
            or detection.model_manifest_id != detector_manifest.model_manifest_id
        ):
            _fail(M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_BINDING_MISMATCH)
        frame = frame_by_id.get(detection.frame_id)
        if frame is None:
            _fail(M6PerceptionAuthorityErrorCode.DETECTION_FRAME_INVALID)
        try:
            FrameBundle(frame=frame, detections=(detection,))
        except (TypeError, ValueError, ValidationError):
            _fail(M6PerceptionAuthorityErrorCode.DETECTION_FRAME_INVALID)
        detections.append(detection)
    return tuple(detections)


def assemble_m6_resolved_perception(
    *,
    closure: M6ReplayInputClosureAuthority,
    snapshot: M6PerceptionAuthoritySnapshot,
) -> M6ResolvedPerception:
    """Reconstruct exactly the perception inventory admitted by one closure."""

    controlled_closure, authority = _validated_arguments(closure, snapshot)
    manifest = _validated_manifest(controlled_closure, authority)
    _validate_source_case(controlled_closure, authority)
    _require_exact_frame_inventory(controlled_closure, authority.frames)
    _require_exact_detection_inventory(controlled_closure, authority.detections)
    frames = _resolve_frames(controlled_closure, authority)
    detections = _resolve_detections(
        controlled_closure,
        authority,
        manifest,
        frames,
    )
    try:
        return M6ResolvedPerception(frames=frames, detections=detections)
    except (TypeError, ValueError, ValidationError):
        _fail(M6PerceptionAuthorityErrorCode.RESOLVED_PERCEPTION_INVALID)


__all__ = [
    "M6PerceptionAuthorityError",
    "M6PerceptionAuthorityErrorCode",
    "assemble_m6_resolved_perception",
]
