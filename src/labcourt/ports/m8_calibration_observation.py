"""Runtime boundaries for additive M8 detector-score collection."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m8_calibration import M8DetectorScoreObservationV1
from labcourt.contracts.m8_evaluation import M8EvaluationMediaAssetV1
from labcourt.contracts.manifests import StreamManifest
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionFrameReceipt,
    PilotPerceptionWorkerFailure,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
)
from labcourt.ports.pixels import RGB8Frame


class M8CalibrationRGB8Source(Protocol):
    def iter_rgb8(self) -> Iterator[RGB8Frame]: ...


@dataclass(frozen=True, slots=True)
class M8CalibrationMediaAuthority:
    """One immutable evaluation asset opened through its verified stream manifest."""

    asset: M8EvaluationMediaAssetV1
    stream_manifest: StreamManifest
    frames: M8CalibrationRGB8Source

    def __post_init__(self) -> None:
        stream = self.stream_manifest
        asset = self.asset
        expected_media_manifest_id = sha256_hex(
            [
                "m8-evaluation-media-manifest",
                1,
                stream.model_dump(mode="json", exclude_computed_fields=True),
            ]
        )
        if asset.media_manifest_id != expected_media_manifest_id:
            raise ValueError("M8 calibration media manifest does not match the evaluation asset")
        if (
            asset.asset_id != stream.input_file_sha256
            or asset.media_sha256 != stream.input_file_sha256
            or asset.codec != stream.codec
            or asset.width != stream.width
            or asset.height != stream.height
            or asset.fps_num != stream.fps_num
            or asset.fps_den != stream.fps_den
            or asset.frame_count != stream.frame_count
        ):
            raise ValueError("M8 calibration stream metadata does not match the evaluation asset")

    @property
    def source_manifest_id(self) -> str:
        return self.asset.media_manifest_id


class M8CalibrationObservationRepository(Protocol):
    def put_detector_observation(
        self,
        observation: M8DetectorScoreObservationV1,
    ) -> M8DetectorScoreObservationV1: ...

    def list_detector_observations(
        self,
        run_id: str,
    ) -> tuple[M8DetectorScoreObservationV1, ...]: ...


class M8CalibrationAssetResolver(Protocol):
    def __call__(
        self,
        asset_id: str,
    ) -> AbstractContextManager[M8CalibrationMediaAuthority]: ...


class M8CalibrationWorkerTransport(Protocol):
    @property
    def manifest(self) -> PilotPerceptionExecutionManifest: ...

    @property
    def receipts(self) -> tuple[PilotPerceptionFrameReceipt, ...]: ...

    def exchange(
        self,
        request: PilotPerceptionWorkerRequest,
    ) -> PilotPerceptionWorkerResponse | PilotPerceptionWorkerFailure: ...

    def close(self) -> None: ...


class M8CalibrationWorkerTransportFactory(Protocol):
    def __call__(
        self,
        config: AppConfig,
        expected_manifest: PilotPerceptionExecutionManifest,
        collection_run_id: str,
    ) -> AbstractContextManager[M8CalibrationWorkerTransport]: ...


M8CalibrationAssetLookup = Callable[[str], M8EvaluationMediaAssetV1]


__all__ = [
    "M8CalibrationAssetLookup",
    "M8CalibrationAssetResolver",
    "M8CalibrationMediaAuthority",
    "M8CalibrationObservationRepository",
    "M8CalibrationRGB8Source",
    "M8CalibrationWorkerTransport",
    "M8CalibrationWorkerTransportFactory",
]
