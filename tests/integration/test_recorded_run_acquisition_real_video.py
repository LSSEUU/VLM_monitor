from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from labcourt.adapters.m8_acquisition_outcomes import (
    PersistedM8AcquisitionOutcomeRepository,
)
from labcourt.adapters.m8_run_source import PersistedM8RecordedRunSourceResolver
from labcourt.adapters.opencv_video import (
    OpenCvDecoderBackend,
    OpenCvVideoSource,
    probe_caller_attested_stream_manifest,
)
from labcourt.adapters.pillow_frame_store import PillowFrameStore
from labcourt.adapters.recorded_run_acquisition import (
    RecordedRunFrameAcquisitionExecutor,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import AcquisitionAction, CropSource, PrivacyPolicy
from labcourt.contracts.evidence import CropRequest, EvidencePackDraft, RecropParameters
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m8_evaluation import (
    M8EvaluationRunSourceKind,
    M8RunSourceRefV1,
)
from labcourt.contracts.manifests import (
    RunManifest,
    SoftwareComponentManifest,
)
from labcourt.domain.evidence_authority import derive_evidence_authority
from tests.unit import test_m4_evidence_authority as evidence_helpers
from tests.unit.test_m4_evidence_authority import _execution
from tests.unit.test_m4_hearing_request import ROOT, _closed_pack

cv2 = pytest.importorskip("cv2")
np = pytest.importorskip("numpy")


def _write_real_mp4(path: Path, *, frame_count: int, width: int, height: int) -> None:
    writer = cv2.VideoWriter(
        str(path),
        cv2.VideoWriter_fourcc(*"mp4v"),
        30.0,
        (width, height),
    )
    if not writer.isOpened():
        pytest.skip("local OpenCV build cannot encode MP4V")
    try:
        for index in range(frame_count):
            frame = np.zeros((height, width, 3), dtype=np.uint8)
            frame[:, :, 0] = (index * 3) % 255
            frame[:, :, 1] = 80
            frame[:, :, 2] = 180
            cv2.rectangle(frame, (20, 20), (110, 220), (0, 255, 0), 2)
            writer.write(frame)
    finally:
        writer.release()


def test_real_mp4_recrop_uses_persisted_source_hash_and_real_pixels(tmp_path: Path) -> None:
    width = 256
    height = 240
    frame_count = 100
    max_bytes = 16 * 1024 * 1024
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    video_path = inputs / "recorded.mp4"
    _write_real_mp4(video_path, frame_count=frame_count, width=width, height=height)
    video_sha256 = hashlib.sha256(video_path.read_bytes()).hexdigest()
    backend = OpenCvDecoderBackend()
    with SecureWorkspace(tmp_path, max_file_bytes=max_bytes) as input_workspace:
        stream = probe_caller_attested_stream_manifest(
            camera_id="cam-01",
            stream_id="demo-ntsc",
            input_file_sha256=video_sha256,
            verified_input=input_workspace,
            relative_path="inputs/recorded.mp4",
            max_input_bytes=max_bytes,
            max_frame_pixels=width * height,
            max_total_decoded_pixels=width * height * frame_count,
            backend=backend,
        )
    assert stream.frame_count == frame_count
    base = RunManifest.model_validate_json(
        (ROOT / "tests/fixtures/m2/run-manifest-fake.json").read_text(encoding="utf-8")
    )
    payload = base.model_dump(mode="python", exclude={"manifest_id"})
    payload["streams"] = (stream,)
    payload["software_components"] = {
        stream.software_component: SoftwareComponentManifest(
            component=stream.software_component,
            package=stream.library,
            version=stream.library_version,
            license_id="Apache-2.0",
        )
    }
    manifest = RunManifest.model_validate(payload)
    base_pack = _closed_pack(manifest)
    template = base_pack.focus_crops[0]
    initial_request = CropRequest(
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
        SecureWorkspace(tmp_path, max_file_bytes=max_bytes) as input_workspace,
        SecureWorkspace(workspace_root, max_file_bytes=max_bytes) as output_workspace,
    ):
        source = OpenCvVideoSource(
            manifest=stream,
            verified_input=input_workspace,
            relative_path="inputs/recorded.mp4",
            max_input_bytes=max_bytes,
            max_frame_pixels=width * height,
            max_total_decoded_pixels=width * height * frame_count,
            backend=backend,
        )
        initial_crop = PillowFrameStore(
            run_id=base_pack.run_id,
            workspace=output_workspace,
            pixels=source,
            max_media_bytes=max_bytes,
            max_image_pixels=width * height,
        ).create_crop(initial_request)
    pack = evidence_helpers._close(
        EvidencePackDraft(
            run_id=base_pack.run_id,
            case_id=base_pack.case_id,
            version=base_pack.version,
            event=base_pack.event,
            key_frame_ids=base_pack.key_frame_ids,
            focus_crops=(initial_crop,),
            objective_facts=base_pack.event.objective_facts,
            track_summary=base_pack.track_summary,
            confirmation_record=base_pack.confirmation_record,
            manifest_id=base_pack.manifest_id,
        )
    )

    state_root = tmp_path / "platform-state"
    source_dir = state_root / "scenario-runs"
    source_dir.mkdir(parents=True)
    source_ref = M8RunSourceRefV1(
        run_id=pack.run_id,
        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
        asset_id=video_sha256,
        media_sha256=video_sha256,
        relative_path="inputs/recorded.mp4",
        frame_count=frame_count,
        source_manifest_id=sha256_hex(["real-mp4-source", video_sha256]),
    )
    (source_dir / f"{pack.run_id}.source.json").write_text(
        canonical_json(source_ref.model_dump(mode="json", exclude_computed_fields=True)),
        encoding="utf-8",
    )
    resolver = PersistedM8RecordedRunSourceResolver(
        project_root=tmp_path,
        source_state_root=state_root,
    )
    repository = PersistedM8AcquisitionOutcomeRepository(
        workspace_root=workspace_root,
        max_document_bytes=4 * 1024 * 1024,
    )
    authority = derive_evidence_authority(pack)
    parameters = RecropParameters(
        action=AcquisitionAction.RECROP,
        frame_id=pack.key_frame_ids[0],
        bbox=BBoxXYXY(x1=5, y1=10, x2=85, y2=170),
    )
    request = _execution(pack, AcquisitionAction.RECROP, parameters=parameters).request
    with SecureWorkspace(workspace_root, max_file_bytes=max_bytes) as workspace:
        executor = RecordedRunFrameAcquisitionExecutor(
            project_root=tmp_path,
            source_resolver=resolver,
            manifest=manifest,
            max_input_bytes=max_bytes,
            max_frame_pixels=width * height,
            max_media_bytes=max_bytes,
            workspace=workspace,
            outcome_repository=repository,
            decoder_backend=backend,
        )
        execution = executor.execute(
            request,
            authority,
            idempotency_key=request.request_id,
        )
        recrop = execution.output_objects.crops[0]
        assert recrop.source == CropSource.RECROP
        assert recrop.source_media_sha256 != "0" * 64
        assert workspace.read_verified(recrop.local_path, recrop.media_sha256).size_bytes > 0
        listed = executor.list_m8_outcomes(pack.run_id, pack.case_id)
        assert listed[0].m4_execution is not None
