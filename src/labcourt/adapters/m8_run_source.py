"""Strict resolvers for immutable recorded-run media authority."""

from __future__ import annotations

from hmac import compare_digest
from pathlib import Path

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.m8_acquisition_v2 import (
    M8AcquisitionFailureCode,
    M8ResolvedRecordedRunSourceV1,
)
from labcourt.contracts.m8_evaluation import (
    M8EvaluationRunSourceKind,
    M8RunSourceRefV1,
)
from labcourt.contracts.manifests import RunManifest, StreamManifest
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import require_portable_run_id
from labcourt.exceptions import PathBoundaryViolation

_MAX_SOURCE_SIDECAR_BYTES = 1024 * 1024


class M8RecordedRunSourceResolutionError(ValueError):
    """Sanitized typed failure while closing a run against persisted media."""

    def __init__(self, reason_code: M8AcquisitionFailureCode) -> None:
        if reason_code not in {
            M8AcquisitionFailureCode.SOURCE_BINDING_MISSING,
            M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH,
            M8AcquisitionFailureCode.SOURCE_MEDIA_UNAVAILABLE,
        }:
            raise ValueError("invalid recorded-run source failure code")
        self.reason_code = reason_code
        super().__init__(f"recorded-run source resolution failed: {reason_code.value}")


def _source_failure(reason_code: M8AcquisitionFailureCode) -> M8RecordedRunSourceResolutionError:
    return M8RecordedRunSourceResolutionError(reason_code)


def _single_stream(manifest: RunManifest) -> StreamManifest:
    if not isinstance(manifest, RunManifest) or len(manifest.streams) != 1:
        raise ValueError("recorded run acquisition requires exactly one stream")
    return manifest.streams[0]


class PersistedM8RecordedRunSourceResolver:
    """Load `scenario-runs/{run_id}.source.json` and revalidate its MP4 bytes."""

    __slots__ = ("_project_root", "_source_state_root")

    def __init__(self, *, project_root: Path, source_state_root: Path) -> None:
        if not isinstance(project_root, Path) or not isinstance(source_state_root, Path):
            raise TypeError("persisted source resolver roots must be Paths")
        self._project_root = project_root.absolute()
        self._source_state_root = source_state_root.absolute()

    @property
    def project_root(self) -> Path:
        return self._project_root

    def resolve(
        self,
        run_id: str,
        manifest: RunManifest,
        *,
        max_input_bytes: int,
    ) -> M8ResolvedRecordedRunSourceV1:
        controlled_run_id = require_portable_run_id(run_id, "recorded acquisition run_id")
        if (
            not isinstance(max_input_bytes, int)
            or isinstance(max_input_bytes, bool)
            or max_input_bytes <= 0
        ):
            raise ValueError("recorded source byte limit must be positive")
        try:
            stream = _single_stream(manifest)
        except (TypeError, ValueError):
            raise _source_failure(M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH) from None
        relative_sidecar = f"scenario-runs/{controlled_run_id}.source.json"
        try:
            with SecureWorkspace(
                self._source_state_root,
                max_file_bytes=_MAX_SOURCE_SIDECAR_BYTES,
            ) as state_workspace:
                snapshot = state_workspace.read_verified(
                    relative_sidecar,
                    max_bytes=_MAX_SOURCE_SIDECAR_BYTES,
                )
        except PathBoundaryViolation as error:
            code = (
                M8AcquisitionFailureCode.SOURCE_BINDING_MISSING
                if error.reason_code == "FILE_MISSING"
                else M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH
            )
            raise _source_failure(code) from None
        try:
            source = M8RunSourceRefV1.model_validate_json(snapshot.bytes)
        except (TypeError, ValueError):
            raise _source_failure(M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH) from None
        if (
            source.run_id != controlled_run_id
            or source.source_kind != M8EvaluationRunSourceKind.RECORDED_ASSET
            or source.media_sha256 != stream.input_file_sha256
            or source.frame_count != stream.frame_count
        ):
            raise _source_failure(M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH)

        try:
            with (
                SecureWorkspace(
                    self._project_root,
                    max_file_bytes=max_input_bytes,
                ) as media_workspace,
                media_workspace.open_verified_video(
                    source.relative_path,
                    max_input_bytes,
                ) as lease,
            ):
                if not compare_digest(lease.input_file_sha256, source.media_sha256):
                    raise _source_failure(M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH)
        except M8RecordedRunSourceResolutionError:
            raise
        except (OSError, PathBoundaryViolation):
            raise _source_failure(M8AcquisitionFailureCode.SOURCE_MEDIA_UNAVAILABLE) from None
        return M8ResolvedRecordedRunSourceV1(
            source=source,
            run_manifest_id=manifest.manifest_id,
            camera_id=stream.camera_id,
            stream_id=stream.stream_id,
            input_file_sha256=stream.input_file_sha256,
            frame_count=stream.frame_count,
        )


class ManifestBoundRecordedRunSourceResolver:
    """Compatibility resolver for an explicitly configured immutable MP4.

    New M8 evaluation composition should use PersistedM8RecordedRunSourceResolver.
    This resolver keeps the pre-existing constructor operational while still
    revalidating the exact media hash on every execution/recovery boundary.
    """

    __slots__ = ("_project_root", "_relative_path")

    def __init__(self, *, project_root: Path, input_relative_path: str) -> None:
        if not isinstance(project_root, Path):
            raise TypeError("manifest-bound source project_root must be a Path")
        self._project_root = project_root.absolute()
        self._relative_path = require_safe_relative_posix_path(input_relative_path)
        if not self._relative_path.startswith(
            "inputs/"
        ) or not self._relative_path.casefold().endswith(".mp4"):
            raise ValueError("recorded run source must be a controlled MP4 input")

    @property
    def project_root(self) -> Path:
        return self._project_root

    def resolve(
        self,
        run_id: str,
        manifest: RunManifest,
        *,
        max_input_bytes: int,
    ) -> M8ResolvedRecordedRunSourceV1:
        controlled_run_id = require_portable_run_id(run_id, "recorded acquisition run_id")
        try:
            stream = _single_stream(manifest)
        except (TypeError, ValueError):
            raise _source_failure(M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH) from None
        try:
            with (
                SecureWorkspace(
                    self._project_root,
                    max_file_bytes=max_input_bytes,
                ) as media_workspace,
                media_workspace.open_verified_video(
                    self._relative_path,
                    max_input_bytes,
                ) as lease,
            ):
                if not compare_digest(lease.input_file_sha256, stream.input_file_sha256):
                    raise _source_failure(M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH)
        except M8RecordedRunSourceResolutionError:
            raise
        except (OSError, PathBoundaryViolation):
            raise _source_failure(M8AcquisitionFailureCode.SOURCE_MEDIA_UNAVAILABLE) from None
        source_manifest_id = sha256_hex(
            [
                "manifest-bound-recorded-run-source",
                1,
                controlled_run_id,
                self._relative_path,
                stream.input_file_sha256,
                stream.frame_count,
                manifest.manifest_id,
            ]
        )
        source = M8RunSourceRefV1(
            run_id=controlled_run_id,
            source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
            asset_id=stream.input_file_sha256,
            media_sha256=stream.input_file_sha256,
            relative_path=self._relative_path,
            frame_count=stream.frame_count,
            source_manifest_id=source_manifest_id,
        )
        return M8ResolvedRecordedRunSourceV1(
            source=source,
            run_manifest_id=manifest.manifest_id,
            camera_id=stream.camera_id,
            stream_id=stream.stream_id,
            input_file_sha256=stream.input_file_sha256,
            frame_count=stream.frame_count,
        )


__all__ = [
    "M8RecordedRunSourceResolutionError",
    "ManifestBoundRecordedRunSourceResolver",
    "PersistedM8RecordedRunSourceResolver",
]
