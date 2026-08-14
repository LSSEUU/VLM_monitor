"""Low-floor local detector collection and non-LLM calibration feature aggregation."""

from __future__ import annotations

import math
from collections.abc import Sequence
from enum import StrEnum
from itertools import pairwise

from labcourt.adapters.perception.local_worker import LocalWorkerPerceptionProvider
from labcourt.adapters.pixel_observability import score_person_rgb8_observability
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Detection, FrameBundle
from labcourt.contracts.frames import FrameData
from labcourt.contracts.m8_calibration import (
    M8_EVIDENCE_QUALITY_FEATURE_NAMES,
    M8CalibrationDatasetEntryV1,
    M8CalibrationDatasetManifestV1,
    M8CalibrationTrainingAggregationV1,
    M8CalibrationTrainingExclusionReason,
    M8CalibrationTrainingExclusionV1,
    M8CalibrationTrainingStage,
    M8DetectorScoreObservationV1,
    M8EventRiskFeaturesV1,
    M8EventRiskTrainingExampleV1,
    M8EvidenceFeatureReason,
    M8EvidenceFeatureStatus,
    M8EvidenceQualityFeaturesV1,
    M8EvidenceQualityTrainingExampleV1,
    detector_score_observation_id,
)
from labcourt.contracts.m8_evaluation import M8EvaluationPpeState
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionFrameReceipt,
)
from labcourt.contracts.references import require_portable_run_id
from labcourt.exceptions import LabCourtError
from labcourt.ports.m8_calibration_observation import (
    M8CalibrationAssetResolver,
    M8CalibrationMediaAuthority,
    M8CalibrationObservationRepository,
    M8CalibrationWorkerTransportFactory,
)
from labcourt.ports.pixels import RGB8Frame
from labcourt.services.pilot_operations import build_expected_perception_manifest

M8_CALIBRATION_DEFAULT_COLLECTION_FLOOR = 0.05


class M8CalibrationCollectionFailureCode(StrEnum):
    FORMAL_THRESHOLD_HAS_NO_LOWER_FLOOR = "FORMAL_THRESHOLD_HAS_NO_LOWER_FLOOR"
    ASSET_AUTHORITY_MISMATCH = "ASSET_AUTHORITY_MISMATCH"
    DATASET_FRAME_OUT_OF_RANGE = "DATASET_FRAME_OUT_OF_RANGE"
    FRAME_SEQUENCE_INVALID = "FRAME_SEQUENCE_INVALID"
    WORKER_MANIFEST_MISMATCH = "WORKER_MANIFEST_MISMATCH"
    EXISTING_RUN_BINDING_MISMATCH = "EXISTING_RUN_BINDING_MISMATCH"


class M8CalibrationCollectionError(LabCourtError):
    def __init__(self, code: M8CalibrationCollectionFailureCode) -> None:
        self.code = code
        super().__init__(code.value)


def derive_calibration_collection_config(
    config: AppConfig,
    *,
    requested_floor: float = M8_CALIBRATION_DEFAULT_COLLECTION_FLOOR,
) -> tuple[AppConfig, float]:
    """Derive a manifest-bound low-floor config without mutating formal A1 authority."""

    if (
        isinstance(requested_floor, bool)
        or not isinstance(requested_floor, int | float)
        or not math.isfinite(float(requested_floor))
        or float(requested_floor) <= 0
    ):
        raise ValueError("M8 calibration collection floor must be finite and positive")
    formal_threshold = float(config.perception.detector.score_threshold)
    tracker = config.perception.tracker_thresholds
    if formal_threshold <= 0 or tracker is None:
        raise M8CalibrationCollectionError(
            M8CalibrationCollectionFailureCode.FORMAL_THRESHOLD_HAS_NO_LOWER_FLOOR
        )
    floor = min(float(requested_floor), formal_threshold / 2.0)
    if not 0 < floor < formal_threshold:
        raise M8CalibrationCollectionError(
            M8CalibrationCollectionFailureCode.FORMAL_THRESHOLD_HAS_NO_LOWER_FLOOR
        )
    detector = config.perception.detector.model_copy(update={"score_threshold": floor})
    shadow_tracker = tracker.model_copy(
        update={"track_activation_threshold": min(float(tracker.track_activation_threshold), floor)}
    )
    perception = config.perception.model_copy(
        update={
            "detector": detector,
            "tracker_thresholds": shadow_tracker,
        }
    )
    derived = config.model_copy(update={"perception": perception})
    if derived.config_sha256 == config.config_sha256:
        raise M8CalibrationCollectionError(
            M8CalibrationCollectionFailureCode.FORMAL_THRESHOLD_HAS_NO_LOWER_FLOOR
        )
    return derived, floor


class _CurrentRGB8Pixels:
    def __init__(self) -> None:
        self._current: RGB8Frame | None = None

    def set(self, frame: RGB8Frame) -> None:
        self._current = frame

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        current = self._current
        if current is None or current.frame.frame_id != frame_id:
            raise ValueError("M8 calibration pixel request is outside the current frame")
        return current


def _project_evidence_features(
    frame: RGB8Frame,
    person: Detection,
    config: AppConfig,
) -> tuple[M8EvidenceQualityFeaturesV1, float]:
    score = score_person_rgb8_observability(
        frame,
        person,
        config.perception.observability.weights,
    )
    components = score.components
    return (
        M8EvidenceQualityFeaturesV1(
            person_score=float(components.person_confidence),
            keypoint_visibility=float(components.keypoint_visibility),
            frontality=float(components.frontality),
            sharpness=float(components.sharpness),
            exposure=float(components.exposure),
            inverse_occlusion=float(components.non_occlusion),
        ),
        float(score.total),
    )


def build_detector_score_observation(
    *,
    run_id: str,
    dataset_manifest_id: str,
    asset_id: str,
    source_manifest_id: str,
    frame: RGB8Frame,
    detections: Sequence[Detection],
    receipt: PilotPerceptionFrameReceipt,
    authority_config: AppConfig,
    collection_config: AppConfig,
    collection_manifest: PilotPerceptionExecutionManifest,
    collection_floor: float,
) -> M8DetectorScoreObservationV1:
    """Project one real worker result without inventing missing evidence features."""

    content_sha256 = frame.frame.content_sha256
    assert content_sha256 is not None
    if receipt.frame_id != frame.frame.frame_id or receipt.frame_content_sha256 != content_sha256:
        raise M8CalibrationCollectionError(
            M8CalibrationCollectionFailureCode.WORKER_MANIFEST_MISMATCH
        )
    bundle = FrameBundle(frame=frame.frame, detections=tuple(detections))
    people = tuple(item for item in bundle.detections if item.label == "person")
    goggles = tuple(item for item in bundle.detections if item.label == "goggles")
    score = max((float(item.score) for item in goggles), default=None)
    goggles_detected = score is not None

    track_ref: str | None = None
    feature_status = M8EvidenceFeatureStatus.NOT_APPLICABLE
    feature_reason: M8EvidenceFeatureReason | None
    evidence_features: M8EvidenceQualityFeaturesV1 | None = None
    observability_score: float | None = None
    if not people:
        feature_reason = M8EvidenceFeatureReason.PERSON_DETECTION_MISSING
    elif len(people) != 1:
        feature_reason = M8EvidenceFeatureReason.PERSON_AMBIGUOUS
    elif people[0].track_ref is None:
        feature_reason = M8EvidenceFeatureReason.TRACK_UNAVAILABLE
    else:
        track_ref = people[0].track_ref
        feature_status = M8EvidenceFeatureStatus.AVAILABLE
        feature_reason = None
        evidence_features, observability_score = _project_evidence_features(
            frame,
            people[0],
            authority_config,
        )

    detector_manifest_id = collection_manifest.detector.model_manifest_id
    controlled_run_id = require_portable_run_id(run_id, "M8 calibration collection run")
    authoritative_score_threshold = float(authority_config.perception.detector.score_threshold)
    evidence_clear_threshold = float(
        authority_config.perception.observability.clear_frame_threshold
    )
    observation_id = detector_score_observation_id(
        run_id=controlled_run_id,
        dataset_manifest_id=dataset_manifest_id,
        asset_id=asset_id,
        frame_index=frame.frame.frame_index,
        frame_content_sha256=content_sha256,
        worker_request_id=receipt.request_id,
        raw_response_ref=receipt.raw_response_ref,
        raw_response_sha256=receipt.raw_response_sha256,
        track_ref=track_ref,
        detector_model_manifest_id=detector_manifest_id,
        source_manifest_id=source_manifest_id,
        collection_manifest_id=collection_manifest.manifest_id,
        authority_config_sha256=authority_config.config_sha256,
        collection_config_sha256=collection_config.config_sha256,
        collection_floor=float(collection_floor),
        authoritative_score_threshold=authoritative_score_threshold,
        evidence_clear_threshold=evidence_clear_threshold,
        goggles_detected=goggles_detected,
        postprocessed_goggles_score=score,
        evidence_feature_status=feature_status,
        evidence_feature_reason=feature_reason,
        evidence_features=evidence_features,
        observability_score=observability_score,
    )
    return M8DetectorScoreObservationV1(
        observation_id=observation_id,
        run_id=controlled_run_id,
        dataset_manifest_id=dataset_manifest_id,
        asset_id=asset_id,
        frame_index=frame.frame.frame_index,
        frame_content_sha256=content_sha256,
        worker_request_id=receipt.request_id,
        raw_response_ref=receipt.raw_response_ref,
        raw_response_sha256=receipt.raw_response_sha256,
        track_ref=track_ref,
        detector_model_manifest_id=detector_manifest_id,
        source_manifest_id=source_manifest_id,
        collection_manifest_id=collection_manifest.manifest_id,
        authority_config_sha256=authority_config.config_sha256,
        collection_config_sha256=collection_config.config_sha256,
        collection_floor=float(collection_floor),
        authoritative_score_threshold=authoritative_score_threshold,
        evidence_clear_threshold=evidence_clear_threshold,
        goggles_detected=goggles_detected,
        postprocessed_goggles_score=score,
        evidence_feature_status=feature_status,
        evidence_feature_reason=feature_reason,
        evidence_features=evidence_features,
        observability_score=observability_score,
    )


class M8CalibrationObservationService:
    """Collect persisted low-floor observations with restart-safe append-only identities."""

    def __init__(
        self,
        *,
        config: AppConfig,
        repository: M8CalibrationObservationRepository,
        asset_resolver: M8CalibrationAssetResolver,
        worker_transport_factory: M8CalibrationWorkerTransportFactory,
        requested_floor: float = M8_CALIBRATION_DEFAULT_COLLECTION_FLOOR,
    ) -> None:
        self.authority_config = config
        self.collection_config, self.collection_floor = derive_calibration_collection_config(
            config,
            requested_floor=requested_floor,
        )
        self.authority_manifest = build_expected_perception_manifest(config)
        self.collection_manifest = build_expected_perception_manifest(self.collection_config)
        if self.collection_manifest.score_threshold != self.collection_floor:
            raise M8CalibrationCollectionError(
                M8CalibrationCollectionFailureCode.WORKER_MANIFEST_MISMATCH
            )
        self._repository = repository
        self._asset_resolver = asset_resolver
        self._worker_transport_factory = worker_transport_factory

    def collect(
        self,
        *,
        run_id: str,
        dataset: M8CalibrationDatasetManifestV1,
    ) -> tuple[M8DetectorScoreObservationV1, ...]:
        controlled_run_id = require_portable_run_id(run_id, "M8 calibration collection run")
        existing = self._repository.list_detector_observations(controlled_run_id)
        self._validate_existing(existing, dataset)
        entries_by_asset: dict[str, list[M8CalibrationDatasetEntryV1]] = {}
        for entry in dataset.entries:
            entries_by_asset.setdefault(entry.asset_id, []).append(entry)

        for asset_id in sorted(entries_by_asset):
            entries = entries_by_asset[asset_id]
            target_indexes = {
                index
                for entry in entries
                for index in range(entry.start_frame, entry.end_frame_exclusive)
            }
            max_end = max(entry.end_frame_exclusive for entry in entries)
            with self._asset_resolver(asset_id) as authority:
                if authority.asset.asset_id != asset_id:
                    raise M8CalibrationCollectionError(
                        M8CalibrationCollectionFailureCode.ASSET_AUTHORITY_MISMATCH
                    )
                if max_end > authority.asset.frame_count:
                    raise M8CalibrationCollectionError(
                        M8CalibrationCollectionFailureCode.DATASET_FRAME_OUT_OF_RANGE
                    )
                prior_for_asset = tuple(item for item in existing if item.asset_id == asset_id)
                if any(
                    item.source_manifest_id != authority.source_manifest_id
                    for item in prior_for_asset
                ):
                    raise M8CalibrationCollectionError(
                        M8CalibrationCollectionFailureCode.EXISTING_RUN_BINDING_MISMATCH
                    )
                prior_indexes = tuple(item.frame_index for item in prior_for_asset)
                if len(prior_indexes) != len(set(prior_indexes)):
                    raise M8CalibrationCollectionError(
                        M8CalibrationCollectionFailureCode.EXISTING_RUN_BINDING_MISMATCH
                    )
                if target_indexes.issubset(prior_indexes):
                    continue
                with self._worker_transport_factory(
                    self.collection_config,
                    self.collection_manifest,
                    controlled_run_id,
                ) as transport:
                    if transport.manifest != self.collection_manifest:
                        raise M8CalibrationCollectionError(
                            M8CalibrationCollectionFailureCode.WORKER_MANIFEST_MISMATCH
                        )
                    pixels = _CurrentRGB8Pixels()
                    tracker_epoch = (
                        "m8cal-"
                        + sha256_hex(
                            ["m8-calibration-tracker-epoch", 1, controlled_run_id, asset_id]
                        )[:24]
                    )
                    provider = LocalWorkerPerceptionProvider(
                        pixels=pixels,
                        transport=transport,
                        tracker_epoch=tracker_epoch,
                    )
                    expected_frame_index = 0
                    collected_indexes: set[int] = set()
                    for frame in authority.frames.iter_rgb8():
                        if not self._frame_matches_authority(
                            frame, authority, expected_frame_index
                        ):
                            raise M8CalibrationCollectionError(
                                M8CalibrationCollectionFailureCode.FRAME_SEQUENCE_INVALID
                            )
                        frame_index = frame.frame.frame_index
                        expected_frame_index += 1
                        if frame_index >= max_end:
                            continue
                        pixels.set(frame)
                        detections = tuple(
                            provider.detect(
                                FrameData(
                                    frame=frame.frame,
                                    media_ref=f"m8-calibration/{asset_id}/{frame_index}",
                                    ephemeral=True,
                                )
                            )
                        )
                        receipt = self._receipt_for_frame(transport.receipts, frame)
                        if frame_index not in target_indexes:
                            continue
                        observation = build_detector_score_observation(
                            run_id=controlled_run_id,
                            dataset_manifest_id=dataset.dataset_manifest_id,
                            asset_id=asset_id,
                            source_manifest_id=authority.source_manifest_id,
                            frame=frame,
                            detections=detections,
                            receipt=receipt,
                            authority_config=self.authority_config,
                            collection_config=self.collection_config,
                            collection_manifest=self.collection_manifest,
                            collection_floor=self.collection_floor,
                        )
                        self._repository.put_detector_observation(observation)
                        collected_indexes.add(frame_index)
                    if (
                        expected_frame_index != authority.asset.frame_count
                        or collected_indexes != target_indexes
                    ):
                        raise M8CalibrationCollectionError(
                            M8CalibrationCollectionFailureCode.FRAME_SEQUENCE_INVALID
                        )
        return tuple(
            item
            for item in self._repository.list_detector_observations(controlled_run_id)
            if item.dataset_manifest_id == dataset.dataset_manifest_id
        )

    def aggregate(
        self,
        *,
        run_id: str,
        dataset: M8CalibrationDatasetManifestV1,
    ) -> M8CalibrationTrainingAggregationV1:
        observations = self._repository.list_detector_observations(run_id)
        return aggregate_calibration_training_examples(dataset, observations)

    def _validate_existing(
        self,
        existing: Sequence[M8DetectorScoreObservationV1],
        dataset: M8CalibrationDatasetManifestV1,
    ) -> None:
        if any(
            item.dataset_manifest_id != dataset.dataset_manifest_id
            or item.authority_config_sha256 != self.authority_config.config_sha256
            or item.collection_config_sha256 != self.collection_config.config_sha256
            or item.collection_manifest_id != self.collection_manifest.manifest_id
            or item.detector_model_manifest_id
            != self.collection_manifest.detector.model_manifest_id
            or item.collection_floor != self.collection_floor
            for item in existing
        ):
            raise M8CalibrationCollectionError(
                M8CalibrationCollectionFailureCode.EXISTING_RUN_BINDING_MISMATCH
            )

    @staticmethod
    def _receipt_for_frame(
        receipts: Sequence[PilotPerceptionFrameReceipt],
        frame: RGB8Frame,
    ) -> PilotPerceptionFrameReceipt:
        matches = tuple(item for item in receipts if item.frame_id == frame.frame.frame_id)
        if len(matches) != 1:
            raise M8CalibrationCollectionError(
                M8CalibrationCollectionFailureCode.WORKER_MANIFEST_MISMATCH
            )
        return matches[0]

    @staticmethod
    def _frame_matches_authority(
        frame: RGB8Frame,
        authority: M8CalibrationMediaAuthority,
        expected: int,
    ) -> bool:
        stream = authority.stream_manifest
        ref = frame.frame
        return (
            ref.frame_index == expected
            and ref.camera_id == stream.camera_id
            and ref.stream_id == stream.stream_id
            and ref.fps_num == stream.fps_num
            and ref.fps_den == stream.fps_den
            and ref.width == stream.width
            and ref.height == stream.height
        )


def _mean_evidence_features(
    observations: Sequence[M8DetectorScoreObservationV1],
) -> M8EvidenceQualityFeaturesV1:
    available = tuple(
        item.evidence_features
        for item in observations
        if item.evidence_feature_status == M8EvidenceFeatureStatus.AVAILABLE
        and item.evidence_features is not None
    )
    if not available:
        raise ValueError("M8 evidence feature aggregation requires one available frame")
    means = tuple(
        float(sum(float(getattr(item, name)) for item in available) / len(available))
        for name in M8_EVIDENCE_QUALITY_FEATURE_NAMES
    )
    return M8EvidenceQualityFeaturesV1(
        person_score=means[0],
        keypoint_visibility=means[1],
        frontality=means[2],
        sharpness=means[3],
        exposure=means[4],
        inverse_occlusion=means[5],
    )


def _longest_false_run(values: Sequence[bool]) -> int:
    longest = 0
    current = 0
    for value in values:
        if value:
            current = 0
        else:
            current += 1
            longest = max(longest, current)
    return longest


def _event_features(
    observations: Sequence[M8DetectorScoreObservationV1],
) -> M8EventRiskFeaturesV1:
    """Use tracked-frame coverage and adjacent same-track continuity over the full interval."""

    detected = tuple(item.goggles_detected for item in observations)
    scores = tuple(
        float(item.postprocessed_goggles_score)
        if item.postprocessed_goggles_score is not None
        else 0.0
        for item in observations
    )
    clear = tuple(
        item.observability_score is not None
        and item.observability_score >= item.evidence_clear_threshold
        for item in observations
    )
    count = len(observations)
    tracked = tuple(item.track_ref is not None for item in observations)
    if count == 1:
        continuity = 1.0 if tracked[0] else 0.0
    else:
        continuity = sum(
            previous.track_ref is not None and previous.track_ref == current.track_ref
            for previous, current in pairwise(observations)
        ) / (count - 1)
    return M8EventRiskFeaturesV1(
        clear_frame_ratio=float(sum(clear) / count),
        temporal_coverage_ratio=float(sum(tracked) / count),
        track_continuity_ratio=float(continuity),
        goggles_detection_ratio=float(sum(detected) / count),
        max_goggles_score=float(max(scores, default=0.0)),
        mean_goggles_score=float(sum(scores) / count),
        recovery_detected=any(not previous and current for previous, current in pairwise(detected)),
        longest_absence_ratio=float(_longest_false_run(detected) / count),
    )


def aggregate_calibration_training_examples(
    dataset: M8CalibrationDatasetManifestV1,
    observations: Sequence[M8DetectorScoreObservationV1],
) -> M8CalibrationTrainingAggregationV1:
    """Purely aggregate persisted local observations; never fill missing scope with zeros."""

    by_frame: dict[tuple[str, int], M8DetectorScoreObservationV1] = {}
    run_ids: set[str] = set()
    for observation in observations:
        if observation.dataset_manifest_id != dataset.dataset_manifest_id:
            raise ValueError("M8 calibration observation belongs to another dataset")
        key = (observation.asset_id, observation.frame_index)
        if key in by_frame:
            raise ValueError("M8 calibration observation inventory contains a duplicate frame")
        by_frame[key] = observation
        run_ids.add(observation.run_id)
    if len(run_ids) > 1:
        raise ValueError("M8 calibration aggregation cannot mix collection runs")

    evidence_examples: list[M8EvidenceQualityTrainingExampleV1] = []
    event_examples: list[M8EventRiskTrainingExampleV1] = []
    exclusions: list[M8CalibrationTrainingExclusionV1] = []
    for entry in dataset.entries:
        indexes = tuple(range(entry.start_frame, entry.end_frame_exclusive))
        missing = tuple(index for index in indexes if (entry.asset_id, index) not in by_frame)
        if missing:
            for stage in M8CalibrationTrainingStage:
                exclusions.append(
                    M8CalibrationTrainingExclusionV1(
                        sample_id=entry.sample_id,
                        stage=stage,
                        reason=M8CalibrationTrainingExclusionReason.OBSERVATION_MISSING,
                        frame_indexes=missing,
                    )
                )
            continue
        sample = tuple(by_frame[(entry.asset_id, index)] for index in indexes)
        if any(item.source_manifest_id != sample[0].source_manifest_id for item in sample):
            raise ValueError("M8 calibration sample crosses immutable source manifests")
        available = tuple(
            item
            for item in sample
            if item.evidence_feature_status == M8EvidenceFeatureStatus.AVAILABLE
        )
        if available:
            evidence_examples.append(
                M8EvidenceQualityTrainingExampleV1(
                    sample_id=entry.sample_id,
                    group_id=entry.group_id,
                    features=_mean_evidence_features(available),
                    human_clear=entry.ppe_state != M8EvaluationPpeState.UNCLEAR,
                )
            )
        else:
            exclusions.append(
                M8CalibrationTrainingExclusionV1(
                    sample_id=entry.sample_id,
                    stage=M8CalibrationTrainingStage.EVIDENCE_QUALITY,
                    reason=(M8CalibrationTrainingExclusionReason.EVIDENCE_FEATURE_NOT_APPLICABLE),
                    frame_indexes=indexes,
                )
            )

        if entry.ppe_state == M8EvaluationPpeState.UNCLEAR:
            exclusions.append(
                M8CalibrationTrainingExclusionV1(
                    sample_id=entry.sample_id,
                    stage=M8CalibrationTrainingStage.EVENT_RISK,
                    reason=M8CalibrationTrainingExclusionReason.HUMAN_LABEL_UNCLEAR,
                    frame_indexes=indexes,
                )
            )
            continue
        if not any(item.track_ref is not None for item in sample):
            exclusions.append(
                M8CalibrationTrainingExclusionV1(
                    sample_id=entry.sample_id,
                    stage=M8CalibrationTrainingStage.EVENT_RISK,
                    reason=M8CalibrationTrainingExclusionReason.TRACK_SCOPE_INSUFFICIENT,
                    frame_indexes=indexes,
                )
            )
            continue
        event_examples.append(
            M8EventRiskTrainingExampleV1(
                sample_id=entry.sample_id,
                group_id=entry.group_id,
                features=_event_features(sample),
                violation=entry.ppe_state == M8EvaluationPpeState.NOT_WORN,
            )
        )

    return M8CalibrationTrainingAggregationV1(
        dataset_manifest_id=dataset.dataset_manifest_id,
        evidence_examples=tuple(evidence_examples),
        event_examples=tuple(event_examples),
        exclusions=tuple(exclusions),
    )


__all__ = [
    "M8_CALIBRATION_DEFAULT_COLLECTION_FLOOR",
    "M8CalibrationCollectionError",
    "M8CalibrationCollectionFailureCode",
    "M8CalibrationObservationService",
    "aggregate_calibration_training_examples",
    "build_detector_score_observation",
    "derive_calibration_collection_config",
]
