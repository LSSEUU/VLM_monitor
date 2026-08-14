"""Real local media and worker adapters for M8 shadow-score collection."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from labcourt.adapters.opencv_video import (
    OpenCvVideoSource,
    VerifiedVideoInput,
    probe_caller_attested_stream_manifest,
)
from labcourt.adapters.perception.local_worker import (
    CachedPerceptionWorkerTransport,
    JsonlPerceptionWorkerClient,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m8_evaluation import M8EvaluationMediaAssetV1
from labcourt.contracts.pilot import PilotPerceptionExecutionManifest
from labcourt.exceptions import PerceptionWorkerCrashed
from labcourt.ports.m8_calibration_observation import (
    M8CalibrationAssetLookup,
    M8CalibrationMediaAuthority,
    M8CalibrationWorkerTransport,
)


@contextmanager
def open_evaluation_calibration_media(
    *,
    project_root: Path,
    config: AppConfig,
    asset: M8EvaluationMediaAssetV1,
) -> Iterator[M8CalibrationMediaAuthority]:
    """Open one content-addressed evaluation asset as a verified RGB8 source."""

    if asset.size_bytes > config.storage.max_media_bytes:
        raise ValueError("M8 calibration asset exceeds the configured media byte authority")
    root = project_root.absolute()
    with SecureWorkspace(
        root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        manifest = probe_caller_attested_stream_manifest(
            camera_id="camera-recorded-demo-01",
            stream_id=f"evaluation-{asset.media_sha256[:16]}",
            input_file_sha256=asset.media_sha256,
            verified_input=cast(VerifiedVideoInput, workspace),
            relative_path=asset.relative_path,
            max_input_bytes=config.storage.max_media_bytes,
            max_frame_pixels=config.storage.max_image_pixels,
            max_total_decoded_pixels=config.storage.max_image_pixels * asset.frame_count,
        )
        source = OpenCvVideoSource(
            manifest=manifest,
            verified_input=cast(VerifiedVideoInput, workspace),
            relative_path=asset.relative_path,
            max_input_bytes=config.storage.max_media_bytes,
            max_frame_pixels=config.storage.max_image_pixels,
            max_total_decoded_pixels=config.storage.max_image_pixels * asset.frame_count,
        )
        yield M8CalibrationMediaAuthority(
            asset=asset,
            stream_manifest=manifest,
            frames=source,
        )


class EvaluationCalibrationAssetResolver:
    """Resolve persisted evaluation assets without introducing a second media catalog."""

    def __init__(
        self,
        *,
        project_root: Path,
        config: AppConfig,
        asset_lookup: M8CalibrationAssetLookup,
    ) -> None:
        self._project_root = project_root.absolute()
        self._config = config
        self._asset_lookup = asset_lookup

    def __call__(self, asset_id: str) -> AbstractContextManager[M8CalibrationMediaAuthority]:
        asset = self._asset_lookup(asset_id)
        if asset.asset_id != asset_id:
            raise ValueError("M8 calibration asset lookup returned another asset")
        return open_evaluation_calibration_media(
            project_root=self._project_root,
            config=self._config,
            asset=asset,
        )


def _resolve_worker_python(config: AppConfig, project_root: Path) -> str:
    worker = config.perception.worker
    if worker is None:
        raise PerceptionWorkerCrashed("perception worker configuration is unavailable")
    configured = os.environ.get(worker.python_executable_env)
    candidates: tuple[Path, ...] = ((Path(configured),) if configured else ()) + (
        project_root / ".venv-perception" / "Scripts" / "python.exe",
        project_root / ".venv-perception" / "bin" / "python",
    )
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file():
            return str(resolved)
    raise PerceptionWorkerCrashed("isolated perception Python is unavailable")


class RealM8CalibrationWorkerTransportFactory:
    """Launch the pinned local Grounding DINO worker with a derived shadow config."""

    def __init__(self, project_root: Path) -> None:
        self._project_root = project_root.absolute()

    def __call__(
        self,
        config: AppConfig,
        expected_manifest: PilotPerceptionExecutionManifest,
        collection_run_id: str,
    ) -> AbstractContextManager[M8CalibrationWorkerTransport]:
        return self._open(config, expected_manifest, collection_run_id)

    @contextmanager
    def _open(
        self,
        config: AppConfig,
        expected_manifest: PilotPerceptionExecutionManifest,
        collection_run_id: str,
    ) -> Iterator[M8CalibrationWorkerTransport]:
        worker = config.perception.worker
        if worker is None:
            raise PerceptionWorkerCrashed("perception worker configuration is unavailable")
        python = _resolve_worker_python(config, self._project_root)
        workspace_root = self._project_root / config.run.workspace
        with (
            TemporaryDirectory(prefix="labcourt-m8-calibration-") as temporary,
            SecureWorkspace(
                workspace_root,
                max_file_bytes=config.storage.max_media_bytes,
            ) as workspace,
        ):
            config_path = Path(temporary) / "collection-config.json"
            config_path.write_text(
                canonical_json(config.model_dump(mode="json", exclude_computed_fields=True)),
                encoding="utf-8",
            )
            client = JsonlPerceptionWorkerClient(
                command=(
                    python,
                    "-u",
                    "-m",
                    worker.module,
                    "--config",
                    str(config_path),
                ),
                expected_manifest=expected_manifest,
                startup_timeout_seconds=float(worker.startup_timeout_seconds),
                frame_timeout_seconds=float(worker.frame_timeout_seconds),
                max_request_bytes=worker.max_request_bytes,
                max_response_bytes=worker.max_response_bytes,
            )
            cached = CachedPerceptionWorkerTransport(
                transport=client,
                workspace=workspace,
                run_id=collection_run_id,
            )
            try:
                yield cast(M8CalibrationWorkerTransport, cached)
            finally:
                cached.close()


__all__ = [
    "EvaluationCalibrationAssetResolver",
    "RealM8CalibrationWorkerTransportFactory",
    "open_evaluation_calibration_media",
]
