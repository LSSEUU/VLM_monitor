from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from labcourt.application.m6_perception_authority import (
    M6PerceptionAuthorityError,
    M6PerceptionAuthorityErrorCode,
    assemble_m6_resolved_perception,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import Detection
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m6_replay_locked import (
    M6LockedDetectionInput,
    M6LockedFrameInput,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.ports.m6_perception import (
    M6DetectionAuthorityDocument,
    M6FrameAuthorityDocument,
    M6PerceptionAuthoritySnapshot,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "m2" / "run-manifest-fake.json"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _manifest() -> tuple[RunManifest, str]:
    manifest = RunManifest.model_validate_json(FIXTURE.read_text(encoding="utf-8"))
    return manifest, canonical_json(manifest.model_dump(mode="json"))


def _frame(index: int) -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id="demo-ntsc",
        frame_index=index,
        fps_num=30,
        fps_den=1,
        width=640,
        height=480,
        content_sha256=_sha(f"pixels:{index}"),
    )


def _detection(
    frame: FrameRef,
    *,
    detection_id: str = "det-090",
    bbox: BBoxXYXY | None = None,
) -> Detection:
    manifest, _raw = _manifest()
    return Detection(
        detection_id=detection_id,
        frame_id=frame.frame_id,
        label="person",
        bbox=bbox or BBoxXYXY(x1=10, y1=20, x2=100, y2=200),
        score=0.9,
        model_manifest_id=manifest.models["detector"].model_manifest_id,
    )


def _frame_document(frame: FrameRef, *, run_id: str = "run-source") -> M6FrameAuthorityDocument:
    raw = canonical_json(frame.model_dump(mode="json"))
    assert frame.content_sha256 is not None
    manifest, _manifest_raw = _manifest()
    return M6FrameAuthorityDocument(
        run_id=run_id,
        manifest_id=manifest.manifest_id,
        frame_id=frame.frame_id,
        content_sha256=frame.content_sha256,
        canonical_document=raw,
        document_sha256=_sha(raw),
    )


def _detection_document(
    detection: Detection,
    *,
    run_id: str = "run-source",
) -> M6DetectionAuthorityDocument:
    raw = canonical_json(detection.model_dump(mode="json"))
    manifest, _manifest_raw = _manifest()
    return M6DetectionAuthorityDocument(
        run_id=run_id,
        manifest_id=manifest.manifest_id,
        detection_id=detection.detection_id,
        frame_id=detection.frame_id,
        model_manifest_id=detection.model_manifest_id,
        canonical_document=raw,
        document_sha256=_sha(raw),
    )


def _authority(
    *,
    frames: tuple[FrameRef, ...] | None = None,
    detections: tuple[Detection, ...] | None = None,
) -> tuple[M6ReplayInputClosureAuthority, M6PerceptionAuthoritySnapshot]:
    manifest, manifest_raw = _manifest()
    source_frames = frames or (_frame(90), _frame(91))
    source_detections = detections if detections is not None else (_detection(source_frames[0]),)
    frame_documents = tuple(_frame_document(frame) for frame in source_frames)
    detection_documents = tuple(_detection_document(detection) for detection in source_detections)
    closure = M6ReplayInputClosureAuthority(
        sample_id="sample-perception",
        source_run_id="run-source",
        source_manifest_id=manifest.manifest_id,
        source_manifest_document_sha256=_sha(manifest_raw),
        input_authority_id=_sha("input-authority"),
        input_authority_document_sha256=_sha("input-authority-document"),
        source_validation_report_id=_sha("validation-report"),
        source_validation_report_document_sha256=_sha("validation-report-document"),
        frames=tuple(
            M6LockedFrameInput(
                frame_id=document.frame_id,
                document_sha256=document.document_sha256,
                content_sha256=document.content_sha256,
            )
            for document in frame_documents
        ),
        detections=tuple(
            M6LockedDetectionInput(
                detection_id=document.detection_id,
                frame_id=document.frame_id,
                document_sha256=document.document_sha256,
                model_manifest_id=document.model_manifest_id,
            )
            for document in detection_documents
        ),
    )
    snapshot = M6PerceptionAuthoritySnapshot(
        source_identity_sha256=_sha("private-snapshot"),
        run_id=closure.source_run_id,
        manifest_id=manifest.manifest_id,
        manifest_canonical_document=manifest_raw,
        manifest_document_sha256=_sha(manifest_raw),
        source_case_id=None,
        source_case_revision=None,
        source_case_canonical_document=None,
        source_case_document_sha256=None,
        frames=frame_documents,
        detections=detection_documents,
    )
    return closure, snapshot


def _error_code(
    closure: M6ReplayInputClosureAuthority,
    snapshot: M6PerceptionAuthoritySnapshot,
) -> M6PerceptionAuthorityErrorCode:
    with pytest.raises(M6PerceptionAuthorityError) as raised:
        assemble_m6_resolved_perception(closure=closure, snapshot=snapshot)
    return raised.value.code


def test_assembler_returns_exact_stably_ordered_perception() -> None:
    closure, snapshot = _authority()

    resolved = assemble_m6_resolved_perception(closure=closure, snapshot=snapshot)

    assert tuple(frame.frame_id for frame in resolved.frames) == tuple(
        item.frame_id for item in closure.frames
    )
    assert tuple(detection.detection_id for detection in resolved.detections) == tuple(
        item.detection_id for item in closure.detections
    )


def test_assembler_rejects_forged_frame_document_hash() -> None:
    closure, snapshot = _authority()
    forged = replace(snapshot.frames[0], document_sha256=_sha("forged"))

    assert (
        _error_code(
            closure,
            replace(snapshot, frames=(forged, *snapshot.frames[1:])),
        )
        == M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_DOCUMENT_INVALID
    )


def test_assembler_requires_a_typed_single_snapshot_identity() -> None:
    closure, snapshot = _authority()

    assert (
        _error_code(
            closure,
            replace(snapshot, source_identity_sha256="not-a-snapshot-identity"),
        )
        == M6PerceptionAuthorityErrorCode.SNAPSHOT_IDENTITY_INVALID
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda snapshot: replace(snapshot, frames=snapshot.frames[:-1]),
            M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_MISSING,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                frames=(*snapshot.frames, _frame_document(_frame(92))),
            ),
            M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_EXTRA,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                frames=(replace(snapshot.frames[0], run_id="run-foreign"), *snapshot.frames[1:]),
            ),
            M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_SCOPE_MISMATCH,
        ),
        (
            lambda snapshot: replace(snapshot, frames=tuple(reversed(snapshot.frames))),
            M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_UNSTABLE,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                frames=(snapshot.frames[0], snapshot.frames[0], *snapshot.frames[1:]),
            ),
            M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_DUPLICATE,
        ),
    ],
)
def test_assembler_fails_closed_on_frame_inventory_anomalies(
    mutation: object,
    expected: M6PerceptionAuthorityErrorCode,
) -> None:
    closure, snapshot = _authority()
    assert callable(mutation)

    assert _error_code(closure, mutation(snapshot)) == expected


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda snapshot: replace(snapshot, detections=()),
            M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_MISSING,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                detections=(
                    *snapshot.detections,
                    _detection_document(_detection(_frame(91), detection_id="det-091")),
                ),
            ),
            M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_EXTRA,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                detections=(replace(snapshot.detections[0], run_id="run-foreign"),),
            ),
            M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_SCOPE_MISMATCH,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                detections=(snapshot.detections[0], snapshot.detections[0]),
            ),
            M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_DUPLICATE,
        ),
    ],
)
def test_assembler_fails_closed_on_detection_inventory_anomalies(
    mutation: object,
    expected: M6PerceptionAuthorityErrorCode,
) -> None:
    closure, snapshot = _authority()
    assert callable(mutation)

    assert _error_code(closure, mutation(snapshot)) == expected


def test_assembler_rejects_detection_geometry_outside_its_frame() -> None:
    frame = _frame(90)
    detection = _detection(
        frame,
        bbox=BBoxXYXY(x1=10, y1=20, x2=700, y2=200),
    )
    closure, snapshot = _authority(frames=(frame,), detections=(detection,))

    assert (
        _error_code(
            closure,
            snapshot,
        )
        == M6PerceptionAuthorityErrorCode.DETECTION_FRAME_INVALID
    )


def test_assembler_rejects_known_non_detector_manifest_for_detection() -> None:
    frame = _frame(90)
    manifest, _raw = _manifest()
    detection = _detection(frame).model_copy(
        update={"model_manifest_id": manifest.models["screening"].model_manifest_id}
    )
    closure, snapshot = _authority(frames=(frame,), detections=(detection,))

    assert (
        _error_code(closure, snapshot)
        == M6PerceptionAuthorityErrorCode.DETECTION_AUTHORITY_BINDING_MISMATCH
    )


def test_assembler_revalidates_forged_closure_instances() -> None:
    closure, snapshot = _authority()
    forged_frame = copy.deepcopy(closure.frames[0])
    object.__setattr__(forged_frame, "frame_id", "not-a-frame-id")
    forged = copy.deepcopy(closure)
    object.__setattr__(forged, "frames", (forged_frame, *closure.frames[1:]))

    assert (
        _error_code(
            forged,
            snapshot,
        )
        == M6PerceptionAuthorityErrorCode.INVALID_ARGUMENT
    )
