"""Fail-closed A0 preflight for the v0.2 real-video pilot."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.config import AppConfig
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.pilot import PilotRunRequest
from labcourt.contracts.references import require_portable_run_id
from labcourt.exceptions import LabCourtError, PathBoundaryViolation

MAX_PILOT_VIDEO_BYTES = 8 * 1024 * 1024 * 1024


class PilotOperationsBoundaryCode(StrEnum):
    PILOT_CONFIG_MISSING = "PILOT_CONFIG_MISSING"
    RUN_ID_INVALID = "RUN_ID_INVALID"
    VIDEO_PATH_INVALID = "VIDEO_PATH_INVALID"
    VIDEO_MISSING = "VIDEO_MISSING"
    VIDEO_EMPTY = "VIDEO_EMPTY"
    VIDEO_BOUNDARY_REJECTED = "VIDEO_BOUNDARY_REJECTED"
    WORKSPACE_BOUNDARY_REJECTED = "WORKSPACE_BOUNDARY_REJECTED"
    STAGE_NOT_AVAILABLE = "STAGE_NOT_AVAILABLE"


class PilotOperationsBoundaryError(LabCourtError):
    """A sanitized pilot boundary failure safe for CLI output."""

    def __init__(self, code: PilotOperationsBoundaryCode) -> None:
        self.code = code
        super().__init__(code.value)


def require_pilot_config(config: AppConfig) -> None:
    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    if config.pilot is None:
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.PILOT_CONFIG_MISSING)


def validate_pilot_run_scope(
    *,
    config: AppConfig,
    run_id: str,
    project_root: Path,
) -> str:
    """Validate one future run root without creating files or directories."""

    require_pilot_config(config)
    try:
        controlled_run_id = require_portable_run_id(run_id, "pilot run_id")
    except (TypeError, ValueError):
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.RUN_ID_INVALID) from None

    workspace_root = project_root.absolute() / config.run.workspace
    try:
        with SecureWorkspace(
            workspace_root,
            max_file_bytes=config.storage.max_media_bytes,
        ):
            pass
    except (OSError, PathBoundaryViolation):
        raise PilotOperationsBoundaryError(
            PilotOperationsBoundaryCode.WORKSPACE_BOUNDARY_REJECTED
        ) from None
    return controlled_run_id


def build_pilot_run_request(
    *,
    config: AppConfig,
    run_id: str,
    video_path: Path,
    project_root: Path,
    resume: bool,
) -> PilotRunRequest:
    """Bind a safe local MP4 to its content hash and the validated pilot config."""

    controlled_run_id = validate_pilot_run_scope(
        config=config,
        run_id=run_id,
        project_root=project_root,
    )
    if not isinstance(video_path, Path) or video_path.is_absolute():
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.VIDEO_PATH_INVALID)
    try:
        relative_video = require_safe_relative_posix_path(video_path.as_posix())
    except (TypeError, ValueError):
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.VIDEO_PATH_INVALID) from None
    if not relative_video.lower().endswith(".mp4"):
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.VIDEO_PATH_INVALID)

    try:
        with (
            SecureWorkspace(
                project_root.absolute(),
                max_file_bytes=MAX_PILOT_VIDEO_BYTES,
            ) as input_workspace,
            input_workspace.open_verified_video(
                relative_video,
                max_bytes=MAX_PILOT_VIDEO_BYTES,
            ) as video,
        ):
            if video.size_bytes == 0:
                raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.VIDEO_EMPTY)
            video_sha256 = video.input_file_sha256
    except PilotOperationsBoundaryError:
        raise
    except PathBoundaryViolation as error:
        code = (
            PilotOperationsBoundaryCode.VIDEO_MISSING
            if error.reason_code == "FILE_MISSING"
            else PilotOperationsBoundaryCode.VIDEO_BOUNDARY_REJECTED
        )
        raise PilotOperationsBoundaryError(code) from None
    except OSError:
        raise PilotOperationsBoundaryError(
            PilotOperationsBoundaryCode.VIDEO_BOUNDARY_REJECTED
        ) from None

    pilot = config.pilot
    if pilot is None:  # Kept local so type narrowing survives future refactors.
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.PILOT_CONFIG_MISSING)
    return PilotRunRequest(
        run_id=controlled_run_id,
        config_sha256=config.config_sha256,
        video_relative_path=relative_video,
        video_sha256=video_sha256,
        selected_rules=pilot.selected_rules,
        resume=resume,
        max_cases=pilot.max_cases,
    )
