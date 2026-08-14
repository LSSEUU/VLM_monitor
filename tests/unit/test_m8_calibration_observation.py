from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from datetime import UTC, datetime
from pathlib import Path

import pytest

from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import EvidenceClass, ViolationType
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m8_calibration import (
    M8CalibrationTrainingExclusionReason,
    M8CalibrationTrainingStage,
    M8DetectorScoreObservationV1,
    M8EvidenceFeatureReason,
    M8EvidenceFeatureStatus,
)
from labcourt.contracts.m8_evaluation import (
    M8EvaluationExpectedRoute,
    M8EvaluationGroundTruthV1,
    M8EvaluationLabelIntervalV1,
    M8EvaluationMediaAssetV1,
    M8EvaluationMediaOrigin,
    M8EvaluationPpeState,
    M8EvaluationReviewState,
)
from labcourt.contracts.manifests import StreamManifest
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionFrameReceipt,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotWorkerBox,
    PilotWorkerDetection,
)
from labcourt.domain.m8_calibration import build_human_confirmed_dataset
from labcourt.ports.m8_calibration_observation import (
    M8CalibrationMediaAuthority,
    M8CalibrationWorkerTransport,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256
from labcourt.services.m8_calibration_observation import (
    M8CalibrationObservationService,
    derive_calibration_collection_config,
)
from labcourt.services.pilot_operations import build_expected_perception_manifest

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 8, 14, 8, tzinfo=UTC)


class _Frames:
    def __init__(self, frames: tuple[RGB8Frame, ...]) -> None:
        self._frames = frames

    def iter_rgb8(self) -> Iterator[RGB8Frame]:
        yield from self._frames


class _Repository:
    def __init__(self) -> None:
        self._observations: dict[str, M8DetectorScoreObservationV1] = {}

    def put_detector_observation(
        self,
        observation: M8DetectorScoreObservationV1,
    ) -> M8DetectorScoreObservationV1:
        prior = self._observations.setdefault(observation.observation_id, observation)
        if prior != observation:
            raise AssertionError("content identity collision")
        return prior

    def list_detector_observations(
        self,
        run_id: str,
    ) -> tuple[M8DetectorScoreObservationV1, ...]:
        return tuple(item for item in self._observations.values() if item.run_id == run_id)


class _Transport:
    def __init__(self, manifest: PilotPerceptionExecutionManifest, run_id: str) -> None:
        self._manifest = manifest
        self._run_id = run_id
        self._receipts: dict[str, PilotPerceptionFrameReceipt] = {}
        self.frame_indexes: list[int] = []

    @property
    def manifest(self) -> PilotPerceptionExecutionManifest:
        return self._manifest

    @property
    def receipts(self) -> tuple[PilotPerceptionFrameReceipt, ...]:
        return tuple(self._receipts.values())

    def exchange(self, request: PilotPerceptionWorkerRequest) -> PilotPerceptionWorkerResponse:
        frame_index = int(request.frame_id.rsplit(":", 1)[1])
        self.frame_indexes.append(frame_index)
        detections: tuple[PilotWorkerDetection, ...]
        if frame_index == 0:
            detections = ()
        else:
            local_track_id = "track-01" if frame_index < 3 else "track-02"
            person = PilotWorkerDetection(
                label="person",
                source_label="person",
                bbox=PilotWorkerBox(x1=2.0, y1=2.0, x2=18.0, y2=18.0),
                score=0.8,
                local_track_id=local_track_id,
            )
            goggles = (
                (
                    PilotWorkerDetection(
                        label="goggles",
                        source_label="safety goggles",
                        bbox=PilotWorkerBox(x1=6.0, y1=3.0, x2=14.0, y2=7.0),
                        score=0.2,
                    ),
                )
                if frame_index == 1
                else ()
            )
            detections = (person, *goggles)
        response = PilotPerceptionWorkerResponse(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            manifest_id=request.expected_manifest_id,
            detections=detections,
        )
        raw = canonical_json(response.model_dump(mode="json")).encode("utf-8")
        self._receipts[request.frame_id] = PilotPerceptionFrameReceipt(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            raw_response_ref=(f"runs/{self._run_id}/raw/perception/{request.request_id}.json"),
            raw_response_sha256=hashlib.sha256(raw).hexdigest(),
            cache_hit=False,
        )
        return response

    def close(self) -> None:
        return None


class _TransportFactory:
    def __init__(self) -> None:
        self.transports: list[_Transport] = []

    def __call__(
        self,
        config: AppConfig,
        expected_manifest: PilotPerceptionExecutionManifest,
        collection_run_id: str,
    ) -> AbstractContextManager[M8CalibrationWorkerTransport]:
        del config
        transport = _Transport(expected_manifest, collection_run_id)
        self.transports.append(transport)
        return _transport_context(transport)


@contextmanager
def _transport_context(transport: _Transport) -> Iterator[M8CalibrationWorkerTransport]:
    try:
        yield transport
    finally:
        transport.close()


class _AssetResolver:
    def __init__(self, authority: M8CalibrationMediaAuthority) -> None:
        self._authority = authority

    def __call__(self, asset_id: str) -> AbstractContextManager[M8CalibrationMediaAuthority]:
        assert asset_id == self._authority.asset.asset_id
        return nullcontext(self._authority)


def _authority(frame_count: int = 4) -> M8CalibrationMediaAuthority:
    asset_id = sha256_hex(["m8-calibration-test-asset", 1])
    stream = StreamManifest(
        camera_id="camera-recorded-demo-01",
        stream_id=f"evaluation-{asset_id[:16]}",
        input_file_sha256=asset_id,
        fps_num=1,
        fps_den=1,
        timing_mode="CFR",
        timing_authority="CALLER_ATTESTED",
        timing_evidence_type="CALLER_DECLARATION",
        timing_evidence_sha256=sha256_hex(["timing", 1]),
        width=20,
        height=20,
        frame_count=frame_count,
        decoder="test-decoder",
        decoder_version="1.0.0",
        backend="test-backend",
        software_component="test-video",
        library="test-video-library",
        library_version="1.0.0",
        codec="mp4v",
        color_conversion="TEST_BGR8_TO_RGB8_V1",
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )
    media_manifest_id = sha256_hex(
        [
            "m8-evaluation-media-manifest",
            1,
            stream.model_dump(mode="json", exclude_computed_fields=True),
        ]
    )
    asset = M8EvaluationMediaAssetV1(
        asset_id=asset_id,
        display_name="calibration.mp4",
        media_sha256=asset_id,
        size_bytes=1_024,
        relative_path=f"inputs/evaluation-{asset_id}.mp4",
        origin=M8EvaluationMediaOrigin.SERVER_DIRECTORY,
        codec=stream.codec,
        width=stream.width,
        height=stream.height,
        fps_num=stream.fps_num,
        fps_den=stream.fps_den,
        frame_count=frame_count,
        duration_millis=frame_count * 1_000,
        imported_by_actor_id="operations-demo",
        imported_at=NOW,
        media_manifest_id=media_manifest_id,
    )
    frames = []
    for frame_index in range(frame_count):
        pixels = bytes([frame_index + 1, 2, 3]) * (stream.width * stream.height)
        frames.append(
            RGB8Frame(
                frame=FrameRef(
                    camera_id=stream.camera_id,
                    stream_id=stream.stream_id,
                    frame_index=frame_index,
                    fps_num=stream.fps_num,
                    fps_den=stream.fps_den,
                    width=stream.width,
                    height=stream.height,
                    content_sha256=rgb8_pixel_sha256(stream.width, stream.height, pixels),
                ),
                pixels=pixels,
            )
        )
    return M8CalibrationMediaAuthority(
        asset=asset, stream_manifest=stream, frames=_Frames(tuple(frames))
    )


def _dataset(
    asset_id: str,
    state: M8EvaluationPpeState,
    *,
    start: int = 0,
    end: int = 4,
):
    truth = M8EvaluationGroundTruthV1(
        asset_id=asset_id,
        revision=1,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
        evidence_class=EvidenceClass.ABSENCE,
        intervals=(
            M8EvaluationLabelIntervalV1(
                start_frame=start,
                end_frame_exclusive=end,
                ppe_state=state,
            ),
        ),
        expected_route=M8EvaluationExpectedRoute.FAST_VERDICT,
        review_state=M8EvaluationReviewState.HUMAN_CONFIRMED,
        reviewer_actor_id="safety-officer-demo",
        reviewed_at=NOW,
        label_manifest_id=sha256_hex(["human-label", asset_id, start, end, state]),
    )
    return build_human_confirmed_dataset((truth,), created_at=NOW)


def _service(
    authority: M8CalibrationMediaAuthority,
    repository: _Repository,
    factory: _TransportFactory,
) -> M8CalibrationObservationService:
    return M8CalibrationObservationService(
        config=load_config(ROOT / "configs" / "pilot.yaml"),
        repository=repository,
        asset_resolver=_AssetResolver(authority),
        worker_transport_factory=factory,
    )


def test_collection_config_is_lower_and_does_not_mutate_formal_a1() -> None:
    config = load_config(ROOT / "configs" / "pilot.yaml")
    formal_hash = config.config_sha256
    formal_manifest = build_expected_perception_manifest(config)
    derived, floor = derive_calibration_collection_config(config)

    assert floor == 0.05
    assert config.config_sha256 == formal_hash
    assert config.perception.detector.score_threshold == 0.5
    assert config.perception.tracker_thresholds is not None
    assert config.perception.tracker_thresholds.track_activation_threshold == 0.25
    assert derived.perception.detector.score_threshold == floor
    assert derived.perception.tracker_thresholds is not None
    assert derived.perception.tracker_thresholds.track_activation_threshold == floor
    assert derived.config_sha256 != formal_hash
    assert build_expected_perception_manifest(derived).manifest_id != formal_manifest.manifest_id


def test_collector_persists_real_worker_semantics_and_is_restart_idempotent() -> None:
    authority = _authority()
    dataset = _dataset(authority.asset.asset_id, M8EvaluationPpeState.NOT_WORN)
    repository = _Repository()
    factory = _TransportFactory()
    service = _service(authority, repository, factory)

    observations = service.collect(run_id="evaluation-calibration-real", dataset=dataset)
    replayed = _service(authority, repository, factory).collect(
        run_id="evaluation-calibration-real",
        dataset=dataset,
    )

    assert replayed == observations
    assert len(observations) == 4
    assert [item.frame_index for item in observations] == [0, 1, 2, 3]
    assert [transport.frame_indexes for transport in factory.transports] == [
        [0, 1, 2, 3],
    ]
    first = observations[0]
    assert first.evidence_feature_status == M8EvidenceFeatureStatus.NOT_APPLICABLE
    assert first.evidence_feature_reason == M8EvidenceFeatureReason.PERSON_DETECTION_MISSING
    assert first.evidence_features is None
    assert first.raw_response_ref.endswith(f"/{first.worker_request_id}.json")
    assert observations[1].postprocessed_goggles_score == 0.2
    assert observations[2].goggles_detected is False
    assert observations[2].postprocessed_goggles_score is None
    assert all(item.llm_output_used is False for item in observations)

    aggregation = service.aggregate(run_id="evaluation-calibration-real", dataset=dataset)
    assert len(aggregation.evidence_examples) == 1
    assert len(aggregation.event_examples) == 1
    assert aggregation.exclusions == ()
    event = aggregation.event_examples[0].features
    assert event.temporal_coverage_ratio == pytest.approx(0.75)
    assert event.track_continuity_ratio == pytest.approx(1 / 3)
    assert event.goggles_detection_ratio == pytest.approx(0.25)
    assert event.max_goggles_score == pytest.approx(0.2)
    assert event.mean_goggles_score == pytest.approx(0.05)
    assert event.longest_absence_ratio == pytest.approx(0.5)
    assert event.recovery_detected is True


def test_aggregate_types_fully_unscoped_sample_and_never_fills_features_with_zero() -> None:
    authority = _authority()
    dataset = _dataset(
        authority.asset.asset_id,
        M8EvaluationPpeState.WORN,
        start=0,
        end=1,
    )
    repository = _Repository()
    service = _service(authority, repository, _TransportFactory())
    service.collect(run_id="evaluation-calibration-unscoped", dataset=dataset)

    aggregation = service.aggregate(run_id="evaluation-calibration-unscoped", dataset=dataset)
    assert aggregation.evidence_examples == ()
    assert aggregation.event_examples == ()
    assert tuple((item.stage, item.reason) for item in aggregation.exclusions) == (
        (
            M8CalibrationTrainingStage.EVIDENCE_QUALITY,
            M8CalibrationTrainingExclusionReason.EVIDENCE_FEATURE_NOT_APPLICABLE,
        ),
        (
            M8CalibrationTrainingStage.EVENT_RISK,
            M8CalibrationTrainingExclusionReason.TRACK_SCOPE_INSUFFICIENT,
        ),
    )
