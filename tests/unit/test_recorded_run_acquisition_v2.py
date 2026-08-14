from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest

from labcourt.adapters.m8_acquisition_outcomes import (
    PersistedM8AcquisitionOutcomeRepository,
)
from labcourt.adapters.m8_run_source import (
    M8RecordedRunSourceResolutionError,
    PersistedM8RecordedRunSourceResolver,
)
from labcourt.adapters.opencv_video import BGR8Frame, OpenCvVideoSource
from labcourt.adapters.pillow_frame_store import PillowFrameStore
from labcourt.adapters.recorded_run_acquisition import (
    RecordedRunFrameAcquisitionExecutor,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    AcquisitionAction,
    ArtifactKind,
    CropSource,
    PrivacyPolicy,
)
from labcourt.contracts.evidence import (
    CropRequest,
    EvidencePack,
    EvidencePackDraft,
    RecropParameters,
    RedetectHighResolutionParameters,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m8_acquisition_v2 import (
    M8AcquisitionFailureCode,
    M8AcquisitionOutcomeStatus,
    M8HearingAcquisitionResultV2,
    M8RedetectionCandidateV1,
    M8RedetectionOutcomeV1,
)
from labcourt.contracts.m8_evaluation import (
    M8EvaluationRunSourceKind,
    M8RunSourceRefV1,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.domain.evidence_authority import (
    LoadedEvidenceObjects,
    derive_evidence_authority,
)
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionDeliveryCertainty,
    HearingAcquisitionExecutorError,
    HearingAcquisitionExecutorFailureCode,
    HearingAcquisitionRecoveryStatus,
)
from tests.unit import test_m4_evidence_authority as evidence_helpers
from tests.unit.test_m4_evidence_authority import _execution
from tests.unit.test_m4_hearing_request import _closed_pack
from tests.unit.test_recorded_run_acquisition import _Backend, _manifest


@dataclass(frozen=True)
class _Harness:
    project_root: Path
    workspace_root: Path
    manifest: RunManifest
    pack: EvidencePack
    backend: _Backend
    source_sha256: str
    frame_count: int


def _materialized_harness(tmp_path: Path) -> _Harness:
    width = 256
    height = 240
    frame_count = 100
    video = b"sealed-recorded-video-v2"
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "demo.mp4").write_bytes(video)
    bgr = bytes((11, 22, 33)) * (width * height)
    frames = tuple(BGR8Frame(width=width, height=height, pixels=bgr) for _ in range(frame_count))
    backend = _Backend(frames)
    source_sha256 = hashlib.sha256(video).hexdigest()
    manifest = _manifest(
        source_sha256,
        frame_count,
        width=width,
        height=height,
    )
    base = _closed_pack(manifest)
    template = base.focus_crops[0]
    crop_request = CropRequest(
        frame_id=template.frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=template.bbox,
        output_width=template.bbox.width,
        output_height=template.bbox.height,
        source_refs=template.source_refs,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version=manifest.privacy_transform_version,
        encoding_version=manifest.image_encoding_version,
        primary_track_ref=template.primary_track_ref,
        tags=template.tags,
    )
    workspace_root = tmp_path / "runs"
    workspace_root.mkdir()
    with (
        SecureWorkspace(tmp_path, max_file_bytes=1024 * 1024) as input_workspace,
        SecureWorkspace(workspace_root, max_file_bytes=1024 * 1024) as output_workspace,
    ):
        source = OpenCvVideoSource(
            manifest=manifest.streams[0],
            verified_input=input_workspace,
            relative_path="inputs/demo.mp4",
            max_input_bytes=1024 * 1024,
            max_frame_pixels=width * height,
            max_total_decoded_pixels=width * height * frame_count,
            backend=backend,
        )
        store = PillowFrameStore(
            run_id=base.run_id,
            workspace=output_workspace,
            pixels=source,
            max_media_bytes=1024 * 1024,
            max_image_pixels=width * height,
        )
        materialized = store.create_crop(crop_request)
    draft = EvidencePackDraft(
        run_id=base.run_id,
        case_id=base.case_id,
        version=base.version,
        event=base.event,
        key_frame_ids=base.key_frame_ids,
        focus_crops=(materialized,),
        objective_facts=base.event.objective_facts,
        track_summary=base.track_summary,
        confirmation_record=base.confirmation_record,
        manifest_id=base.manifest_id,
    )
    pack = evidence_helpers._close(draft)
    return _Harness(
        project_root=tmp_path,
        workspace_root=workspace_root,
        manifest=manifest,
        pack=pack,
        backend=backend,
        source_sha256=source_sha256,
        frame_count=frame_count,
    )


def _repository(harness: _Harness) -> PersistedM8AcquisitionOutcomeRepository:
    return PersistedM8AcquisitionOutcomeRepository(
        workspace_root=harness.workspace_root,
        max_document_bytes=4 * 1024 * 1024,
    )


def _executor(
    harness: _Harness,
    workspace: SecureWorkspace,
    *,
    redetector=None,
) -> RecordedRunFrameAcquisitionExecutor:
    return RecordedRunFrameAcquisitionExecutor(
        project_root=harness.project_root,
        input_relative_path="inputs/demo.mp4",
        manifest=harness.manifest,
        max_input_bytes=1024 * 1024,
        max_frame_pixels=256 * 240,
        max_media_bytes=1024 * 1024,
        workspace=workspace,
        outcome_repository=_repository(harness),
        redetector=redetector,
        decoder_backend=harness.backend,
    )


class _Detector:
    component_manifest_id = sha256_hex(["test-redetector-component"])

    def __init__(self, *, model_manifest_id: str, empty: bool) -> None:
        self.model_manifest_id = model_manifest_id
        self.empty = empty
        self.execute_calls = 0
        self.recover_calls = 0
        self._raw: bytes | None = None

    def execute(self, request, *, idempotency_key: str) -> bytes:
        assert idempotency_key == request.request_id
        self.execute_calls += 1
        detections = (
            ()
            if self.empty
            else (
                M8RedetectionCandidateV1(
                    label=request.prompts[0],
                    bbox=BBoxXYXY(x1=5, y1=5, x2=20, y2=20),
                    score=0.8,
                ),
            )
        )
        response = M8RedetectionOutcomeV1(
            request_id=request.request_id,
            crop_id=request.crop_id,
            crop_media_sha256=request.crop_media_sha256,
            model_manifest_id=self.model_manifest_id,
            status="SUCCEEDED",
            detections=detections,
        )
        self._raw = canonical_json(response.model_dump(mode="json")).encode("utf-8")
        return self._raw

    def recover(self, request, *, idempotency_key: str) -> bytes | None:
        assert idempotency_key == request.request_id
        self.recover_calls += 1
        return self._raw


class _InvalidDetector(_Detector):
    def execute(self, request, *, idempotency_key: str) -> bytes:
        assert idempotency_key == request.request_id
        self.execute_calls += 1
        return b'{"status":"SUCCEEDED","status":"SUCCEEDED"}'


class _UnavailableDetector(_Detector):
    def execute(self, request, *, idempotency_key: str) -> bytes:
        assert idempotency_key == request.request_id
        self.execute_calls += 1
        raise RuntimeError("sanitized test worker failure")

    def recover(self, request, *, idempotency_key: str) -> bytes | None:
        assert idempotency_key == request.request_id
        self.recover_calls += 1
        return None


class _UnexpectedLabelDetector(_Detector):
    def execute(self, request, *, idempotency_key: str) -> bytes:
        assert idempotency_key == request.request_id
        self.execute_calls += 1
        response = M8RedetectionOutcomeV1(
            request_id=request.request_id,
            crop_id=request.crop_id,
            crop_media_sha256=request.crop_media_sha256,
            model_manifest_id=self.model_manifest_id,
            status="SUCCEEDED",
            detections=(
                M8RedetectionCandidateV1(
                    label="not-disclosed-by-request",
                    bbox=BBoxXYXY(x1=5, y1=5, x2=20, y2=20),
                    score=0.8,
                ),
            ),
        )
        return canonical_json(response.model_dump(mode="json")).encode("utf-8")


def test_persisted_source_resolver_rejects_sidecar_and_media_drift(tmp_path: Path) -> None:
    harness = _materialized_harness(tmp_path)
    state_root = tmp_path / "state"
    snapshots = state_root / "scenario-runs"
    snapshots.mkdir(parents=True)
    resolver = PersistedM8RecordedRunSourceResolver(
        project_root=harness.project_root,
        source_state_root=state_root,
    )
    with pytest.raises(M8RecordedRunSourceResolutionError) as missing_binding:
        resolver.resolve(
            harness.pack.run_id,
            harness.manifest,
            max_input_bytes=1024 * 1024,
        )
    assert missing_binding.value.reason_code == M8AcquisitionFailureCode.SOURCE_BINDING_MISSING

    source = M8RunSourceRefV1(
        run_id=harness.pack.run_id,
        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
        asset_id=harness.source_sha256,
        media_sha256=harness.source_sha256,
        relative_path="inputs/demo.mp4",
        frame_count=harness.frame_count,
        source_manifest_id=sha256_hex(["media-source"]),
    )
    source_path = snapshots / f"{harness.pack.run_id}.source.json"
    source_path.write_text(
        canonical_json(source.model_dump(mode="json", exclude_computed_fields=True)),
        encoding="utf-8",
    )
    resolved = resolver.resolve(
        harness.pack.run_id,
        harness.manifest,
        max_input_bytes=1024 * 1024,
    )
    assert resolved.input_file_sha256 == harness.source_sha256

    source_path.write_text(
        canonical_json(
            source.model_copy(update={"frame_count": harness.frame_count - 1}).model_dump(
                mode="json", exclude_computed_fields=True
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(M8RecordedRunSourceResolutionError) as drift:
        resolver.resolve(
            harness.pack.run_id,
            harness.manifest,
            max_input_bytes=1024 * 1024,
        )
    assert drift.value.reason_code == M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH

    source_path.write_text(
        canonical_json(source.model_dump(mode="json", exclude_computed_fields=True)),
        encoding="utf-8",
    )
    (harness.project_root / source.relative_path).unlink()
    with pytest.raises(M8RecordedRunSourceResolutionError) as missing_media:
        resolver.resolve(
            harness.pack.run_id,
            harness.manifest,
            max_input_bytes=1024 * 1024,
        )
    assert missing_media.value.reason_code == M8AcquisitionFailureCode.SOURCE_MEDIA_UNAVAILABLE


def test_real_recrop_is_persisted_and_recovered_after_restart(tmp_path: Path) -> None:
    harness = _materialized_harness(tmp_path)
    authority = derive_evidence_authority(harness.pack)
    parameters = RecropParameters(
        action=AcquisitionAction.RECROP,
        frame_id=harness.pack.key_frame_ids[0],
        bbox=BBoxXYXY(x1=5, y1=10, x2=85, y2=170),
    )
    request = _execution(
        harness.pack,
        AcquisitionAction.RECROP,
        parameters=parameters,
    ).request
    with SecureWorkspace(harness.workspace_root, max_file_bytes=4 * 1024 * 1024) as workspace:
        executor = _executor(harness, workspace)
        execution = executor.execute(request, authority, idempotency_key=request.request_id)
        crop = execution.output_objects.crops[0]
        assert crop.source == CropSource.RECROP
        assert workspace.read_verified(crop.local_path, crop.media_sha256).size_bytes > 0

    with SecureWorkspace(harness.workspace_root, max_file_bytes=4 * 1024 * 1024) as workspace:
        restarted = _executor(harness, workspace)
        recovery = restarted.recover(request, authority, idempotency_key=request.request_id)
        assert recovery.status == HearingAcquisitionRecoveryStatus.COMPLETED
        assert recovery.execution == execution
        outcomes = restarted.list_m8_outcomes(harness.pack.run_id, harness.pack.case_id)
        assert tuple(item.acquisition_request_id for item in outcomes) == (request.request_id,)


def test_track_curve_persists_typed_points_and_bridges_one_aggregate_fact(
    tmp_path: Path,
) -> None:
    harness = _materialized_harness(tmp_path)
    crop = harness.pack.focus_crops[0]
    detection_ref = next(ref for ref in crop.source_refs if ref.kind == ArtifactKind.DETECTION)
    detection = Detection(
        detection_id=detection_ref.artifact_id,
        frame_id=crop.frame_id,
        label="person",
        bbox=BBoxXYXY(x1=10, y1=20, x2=30, y2=60),
        score=0.73,
        track_ref=harness.pack.event.primary_track_ref,
        model_manifest_id=harness.manifest.models["detector"].model_manifest_id,
    )
    loaded = LoadedEvidenceObjects(detections=(detection,))
    authority = derive_evidence_authority(harness.pack, loaded_objects=loaded)
    frame_index = int(crop.frame_id.rsplit(":", 1)[1])
    parameters = TrackConfidenceCurveParameters(
        action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
        track_ref=detection.track_ref,
        start_frame=frame_index - 1,
        end_frame_exclusive=frame_index + 1,
    )
    request = _execution(
        harness.pack,
        AcquisitionAction.TRACK_CONFIDENCE_CURVE,
        loaded=loaded,
        parameters=parameters,
    ).request
    with SecureWorkspace(harness.workspace_root, max_file_bytes=4 * 1024 * 1024) as workspace:
        executor = _executor(harness, workspace)
        execution = executor.execute(request, authority, idempotency_key=request.request_id)
        outcome = executor.load_m8_outcome(request.request_id, request.run_id)

    assert len(execution.output_objects.objective_facts) == 1
    assert execution.output_objects.objective_facts[0].value == 0.73
    assert outcome is not None and outcome.track_confidence_series is not None
    assert tuple(point.status.value for point in outcome.track_confidence_series.points) == (
        "MISSING",
        "OBSERVED",
    )


def test_public_result_contract_uses_planned_v2_names(tmp_path: Path) -> None:
    harness = _materialized_harness(tmp_path)
    authority = derive_evidence_authority(harness.pack)
    request = _execution(harness.pack, AcquisitionAction.OTHER_CAMERA_SAME_TIME).request
    with SecureWorkspace(harness.workspace_root, max_file_bytes=4 * 1024 * 1024) as workspace:
        executor = _executor(harness, workspace)
        with pytest.raises(HearingAcquisitionExecutorError):
            executor.execute(request, authority, idempotency_key=request.request_id)
        result = executor.load_m8_outcome(request.request_id, request.run_id)

    assert isinstance(result, M8HearingAcquisitionResultV2)
    assert result.schema_version == "m8-hearing-acquisition-result-v2"
    payload = result.model_dump(mode="json")
    assert "result_id" in payload
    assert "outcome_id" not in payload
    assert "redetection_outcome" in payload
    assert "track_confidence_series" in payload


@pytest.mark.parametrize("empty", [False, True])
def test_redetection_has_strict_raw_recovery_and_honest_empty_semantics(
    tmp_path: Path,
    empty: bool,
) -> None:
    harness = _materialized_harness(tmp_path)
    authority = derive_evidence_authority(harness.pack)
    detector = _Detector(
        model_manifest_id=harness.manifest.models["detector"].model_manifest_id,
        empty=empty,
    )
    parameters = RedetectHighResolutionParameters(
        action=AcquisitionAction.REDETECT_HIGH_RES,
        crop_id=harness.pack.focus_crops[0].crop_id,
        prompts=("open reagent container",),
    )
    request = _execution(
        harness.pack,
        AcquisitionAction.REDETECT_HIGH_RES,
        parameters=parameters,
    ).request
    with SecureWorkspace(harness.workspace_root, max_file_bytes=4 * 1024 * 1024) as workspace:
        executor = _executor(harness, workspace, redetector=detector)
        if empty:
            with pytest.raises(HearingAcquisitionExecutorError) as raised:
                executor.execute(request, authority, idempotency_key=request.request_id)
            assert raised.value.reason_code == HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID
            assert raised.value.delivery_certainty == HearingAcquisitionDeliveryCertainty.COMPLETED
            execution = None
        else:
            execution = executor.execute(
                request,
                authority,
                idempotency_key=request.request_id,
            )
            assert len(execution.output_objects.detections) == 1
        outcome = executor.load_m8_outcome(request.request_id, request.run_id)

    assert detector.execute_calls == 1
    assert outcome is not None and outcome.raw_receipt is not None
    if empty:
        assert outcome.status == M8AcquisitionOutcomeStatus.SUCCEEDED_EMPTY
        assert outcome.failure_code == M8AcquisitionFailureCode.V1_EMPTY_OUTPUT_UNREPRESENTABLE
        assert outcome.m4_execution is None
    else:
        assert outcome.status == M8AcquisitionOutcomeStatus.SUCCEEDED
        with SecureWorkspace(
            harness.workspace_root,
            max_file_bytes=4 * 1024 * 1024,
        ) as workspace:
            restarted = _executor(harness, workspace, redetector=detector)
            recovery = restarted.recover(
                request,
                authority,
                idempotency_key=request.request_id,
            )
            assert recovery.status == HearingAcquisitionRecoveryStatus.COMPLETED
            assert recovery.execution == execution
        assert detector.execute_calls == 1


def test_other_camera_is_explicitly_unavailable(tmp_path: Path) -> None:
    harness = _materialized_harness(tmp_path)
    authority = derive_evidence_authority(harness.pack)
    request = _execution(harness.pack, AcquisitionAction.OTHER_CAMERA_SAME_TIME).request
    with SecureWorkspace(harness.workspace_root, max_file_bytes=4 * 1024 * 1024) as workspace:
        executor = _executor(harness, workspace)
        with pytest.raises(HearingAcquisitionExecutorError) as raised:
            executor.execute(request, authority, idempotency_key=request.request_id)
        outcome = executor.load_m8_outcome(request.request_id, request.run_id)
    assert raised.value.reason_code == HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE
    assert outcome is not None
    assert outcome.failure_code == M8AcquisitionFailureCode.OTHER_CAMERA_UNAVAILABLE


def test_invalid_detector_json_keeps_raw_receipt_and_never_becomes_empty_success(
    tmp_path: Path,
) -> None:
    harness = _materialized_harness(tmp_path)
    authority = derive_evidence_authority(harness.pack)
    detector = _InvalidDetector(
        model_manifest_id=harness.manifest.models["detector"].model_manifest_id,
        empty=False,
    )
    parameters = RedetectHighResolutionParameters(
        action=AcquisitionAction.REDETECT_HIGH_RES,
        crop_id=harness.pack.focus_crops[0].crop_id,
        prompts=("open reagent container",),
    )
    request = _execution(
        harness.pack,
        AcquisitionAction.REDETECT_HIGH_RES,
        parameters=parameters,
    ).request
    with SecureWorkspace(harness.workspace_root, max_file_bytes=4 * 1024 * 1024) as workspace:
        executor = _executor(harness, workspace, redetector=detector)
        with pytest.raises(HearingAcquisitionExecutorError) as raised:
            executor.execute(request, authority, idempotency_key=request.request_id)
        outcome = executor.load_m8_outcome(request.request_id, request.run_id)
    assert raised.value.delivery_certainty == HearingAcquisitionDeliveryCertainty.COMPLETED
    assert outcome is not None
    assert outcome.status == M8AcquisitionOutcomeStatus.FAILED
    assert outcome.failure_code == M8AcquisitionFailureCode.DETECTOR_OUTPUT_INVALID
    assert outcome.raw_receipt is not None
    assert outcome.redetection is None


def test_detector_invocation_failure_is_typed_and_never_falls_back(tmp_path: Path) -> None:
    harness = _materialized_harness(tmp_path)
    authority = derive_evidence_authority(harness.pack)
    detector = _UnavailableDetector(
        model_manifest_id=harness.manifest.models["detector"].model_manifest_id,
        empty=False,
    )
    parameters = RedetectHighResolutionParameters(
        action=AcquisitionAction.REDETECT_HIGH_RES,
        crop_id=harness.pack.focus_crops[0].crop_id,
        prompts=("open reagent container",),
    )
    request = _execution(
        harness.pack,
        AcquisitionAction.REDETECT_HIGH_RES,
        parameters=parameters,
    ).request
    with SecureWorkspace(harness.workspace_root, max_file_bytes=4 * 1024 * 1024) as workspace:
        executor = _executor(harness, workspace, redetector=detector)
        with pytest.raises(HearingAcquisitionExecutorError) as raised:
            executor.execute(request, authority, idempotency_key=request.request_id)
        outcome = executor.load_m8_outcome(request.request_id, request.run_id)

    assert raised.value.delivery_certainty == HearingAcquisitionDeliveryCertainty.UNKNOWN
    assert detector.execute_calls == 1
    assert detector.recover_calls == 1
    assert outcome is not None
    assert outcome.status == M8AcquisitionOutcomeStatus.FAILED
    assert outcome.failure_code == M8AcquisitionFailureCode.DETECTOR_FAILED
    assert outcome.raw_receipt is None


def test_detector_semantic_output_violation_keeps_receipt_and_fails_typed(
    tmp_path: Path,
) -> None:
    harness = _materialized_harness(tmp_path)
    authority = derive_evidence_authority(harness.pack)
    detector = _UnexpectedLabelDetector(
        model_manifest_id=harness.manifest.models["detector"].model_manifest_id,
        empty=False,
    )
    parameters = RedetectHighResolutionParameters(
        action=AcquisitionAction.REDETECT_HIGH_RES,
        crop_id=harness.pack.focus_crops[0].crop_id,
        prompts=("open reagent container",),
    )
    request = _execution(
        harness.pack,
        AcquisitionAction.REDETECT_HIGH_RES,
        parameters=parameters,
    ).request
    with SecureWorkspace(harness.workspace_root, max_file_bytes=4 * 1024 * 1024) as workspace:
        executor = _executor(harness, workspace, redetector=detector)
        with pytest.raises(HearingAcquisitionExecutorError):
            executor.execute(request, authority, idempotency_key=request.request_id)
        outcome = executor.load_m8_outcome(request.request_id, request.run_id)

    assert outcome is not None
    assert outcome.status == M8AcquisitionOutcomeStatus.FAILED
    assert outcome.failure_code == M8AcquisitionFailureCode.DETECTOR_OUTPUT_INVALID
    assert outcome.raw_receipt is not None
    assert outcome.redetection_outcome is not None
