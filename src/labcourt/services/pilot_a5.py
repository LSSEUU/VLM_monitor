"""Restart-safe A5 orchestration for the complete local pilot command."""

from __future__ import annotations

import sqlite3
from enum import StrEnum
from pathlib import Path

from pydantic import ValidationError

from labcourt.adapters.opencv_video import VideoDecoderBackend
from labcourt.adapters.perception.local_worker import RawPerceptionWorkerTransport
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.vlm import OpenAICompatibleTransport
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.pilot import PilotRunRequest
from labcourt.contracts.pilot_a5 import PilotA5RunReport, derive_pilot_a5_run_state
from labcourt.exceptions import LabCourtError, ManifestMismatch, PathBoundaryViolation
from labcourt.services.m3_operations import open_pilot_a3_operations_service
from labcourt.services.pilot_a4 import publish_pilot_run
from labcourt.services.pilot_evidence import run_pilot_a2


class PilotA5FailureCode(StrEnum):
    """Sanitized full-run failure stages safe for the CLI boundary."""

    REPLAY_MODE_REQUIRED = "REPLAY_MODE_REQUIRED"
    SCREENING_FAILED = "SCREENING_FAILED"
    REPORTING_FAILED = "REPORTING_FAILED"


class PilotA5OperationsError(LabCourtError):
    """A full-run stage failed before it could return a typed report."""

    def __init__(self, code: PilotA5FailureCode) -> None:
        self.code = code
        super().__init__(code.value)


def _locked_code_commit(
    *,
    config: AppConfig,
    request: PilotRunRequest,
    runs_root: Path,
    override: str | None,
) -> str | None:
    if override is not None or not request.resume:
        return override
    with SecureWorkspace(
        runs_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        try:
            snapshot = workspace.read_verified(f"{request.run_id}/pilot/run-manifest.json")
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                return None
            raise
    try:
        manifest = RunManifest.model_validate_json(snapshot.bytes)
    except ValidationError:
        raise ManifestMismatch("persisted pilot A5 run manifest is invalid") from None
    if (
        manifest.config_sha256 != request.config_sha256
        or manifest.reproducibility_mode is not ReproducibilityMode.REPLAY_LOCKED
    ):
        raise ManifestMismatch("persisted pilot A5 run manifest is outside the replay scope")
    return manifest.code_commit


def run_pilot_a5(
    *,
    config: AppConfig,
    request: PilotRunRequest,
    config_path: Path,
    project_root: Path,
    decoder_backend: VideoDecoderBackend | None = None,
    perception_transport: RawPerceptionWorkerTransport | None = None,
    screening_transport: OpenAICompatibleTransport | None = None,
    code_commit: str | None = None,
) -> PilotA5RunReport:
    """Run or resume A2, retry one old backlog item, screen new work, and publish A4."""

    if config.run.reproducibility_mode is not ReproducibilityMode.REPLAY_LOCKED:
        raise PilotA5OperationsError(PilotA5FailureCode.REPLAY_MODE_REQUIRED)
    if request.config_sha256 != config.config_sha256:
        raise ManifestMismatch("pilot A5 request configuration identity changed")

    runs_root = project_root.absolute() / config.run.workspace
    evidence = run_pilot_a2(
        config=config,
        request=request,
        config_path=config_path,
        project_root=project_root,
        decoder_backend=decoder_backend,
        raw_transport=perception_transport,
        code_commit=_locked_code_commit(
            config=config,
            request=request,
            runs_root=runs_root,
            override=code_commit,
        ),
    )
    database = runs_root / request.run_id / config.storage.database_filename

    try:
        with open_pilot_a3_operations_service(
            config=config,
            run_id=request.run_id,
            workspace_root=runs_root,
            database_path=database,
            transport=screening_transport,
        ) as service:
            backlog_retry = service.backlog_retry_run_once(worker_id="pilot-a5-screening-worker")
            screening = service.process_run(max_cases=request.max_cases)
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        raise PilotA5OperationsError(PilotA5FailureCode.SCREENING_FAILED) from error

    try:
        publication = publish_pilot_run(
            config=config,
            runs_root=runs_root,
            database_path=database,
            run_id=request.run_id,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        raise PilotA5OperationsError(PilotA5FailureCode.REPORTING_FAILED) from error

    return PilotA5RunReport(
        run_id=request.run_id,
        reproducibility_mode=config.run.reproducibility_mode,
        state=derive_pilot_a5_run_state(
            backlog_retry=backlog_retry,
            screening=screening,
            publication=publication,
        ),
        evidence=evidence,
        backlog_retry=backlog_retry,
        screening=screening,
        publication=publication,
    )


__all__ = [
    "PilotA5FailureCode",
    "PilotA5OperationsError",
    "run_pilot_a5",
]
