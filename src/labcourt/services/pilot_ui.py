"""Fail-closed local UI projection and one-at-a-time A5 execution boundary."""

from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from pydantic import ValidationError

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.config_loader import load_config
from labcourt.contracts.base import ContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.manifests import RunManifest, StreamManifest
from labcourt.contracts.pilot import (
    PilotA2Report,
    PilotPerceptionCompletionManifest,
    PilotPerceptionReport,
)
from labcourt.contracts.pilot_a5 import PilotA5RunReport
from labcourt.contracts.pilot_report import (
    PILOT_OPERATOR_DISCLAIMER,
    PilotA4CaseView,
    PilotA4Metrics,
    PilotLocalAlertDocument,
)
from labcourt.contracts.pilot_ui import (
    PilotUiAlertView,
    PilotUiCaseSummary,
    PilotUiDashboard,
    PilotUiEvidenceView,
    PilotUiJobStartRequest,
    PilotUiJobStatus,
    PilotUiRunOption,
    PilotUiRunState,
    PilotUiStageKey,
    PilotUiStageProgress,
    PilotUiTimelineItem,
    PilotUiVideoOption,
)
from labcourt.contracts.references import (
    parse_frame_id,
    require_portable_run_id,
    require_reference_token,
)
from labcourt.exceptions import (
    ArtifactIntegrityViolation,
    ContractViolation,
    LabCourtError,
    PathBoundaryViolation,
)
from labcourt.services.pilot_a5 import PilotA5OperationsError, run_pilot_a5
from labcourt.services.pilot_operations import (
    PilotOperationsBoundaryError,
    build_pilot_run_request,
    require_pilot_config,
)

_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_INPUTS = 100
_MAX_RUNS = 100
_ALERT_NAME = re.compile(r"^[0-9a-f]{64}\.json$")
_ContractT = TypeVar("_ContractT", bound=ContractModel)
_Runner = Callable[..., PilotA5RunReport]


class PilotUiBoundaryError(LabCourtError):
    """Sanitized UI boundary failure that never includes host paths or secrets."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_reference_token(reason_code, "pilot UI boundary reason")
        super().__init__(self.reason_code)


@dataclass(frozen=True, slots=True)
class PilotUiBinaryAsset:
    bytes: bytes
    media_type: str
    expected_sha256: str


@dataclass(frozen=True, slots=True)
class PilotUiVideoSource:
    workspace_root: Path
    relative_path: str
    media_type: str
    expected_sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class _VideoRecord:
    option: PilotUiVideoOption
    content_sha256: str


@dataclass(frozen=True, slots=True)
class _RunProjection:
    option: PilotUiRunOption
    manifest: RunManifest | None
    stream: StreamManifest | None
    perception: PilotPerceptionReport | None
    completion: PilotPerceptionCompletionManifest | None
    evidence: PilotA2Report | None
    metrics: PilotA4Metrics | None
    alerts: tuple[PilotLocalAlertDocument, ...]


def _frame_millis(frame_index: int, stream: StreamManifest) -> int:
    return (frame_index * 1000 * stream.fps_den) // stream.fps_num


def _duration_millis(stream: StreamManifest) -> int:
    return (stream.frame_count * 1000 * stream.fps_den + stream.fps_num - 1) // stream.fps_num


def _media_type(path: str) -> str:
    return "image/png" if path.lower().endswith(".png") else "video/mp4"


class PilotUiService:
    """Read verified pilot artifacts and project them into a non-authoritative UI model."""

    def __init__(
        self,
        *,
        project_root: Path,
        config_path: Path,
        config_override: AppConfig | None = None,
    ) -> None:
        self.project_root = project_root.absolute()
        self.config_path = config_path.absolute()
        try:
            self.config: AppConfig = config_override or load_config(self.config_path)
            if not isinstance(self.config, AppConfig):
                raise TypeError("pilot UI config override must be AppConfig")
            require_pilot_config(self.config)
        except (ContractViolation, OSError, TypeError, ValueError) as error:
            raise PilotUiBoundaryError("CONFIG_INVALID") from error
        self.runs_root = self.project_root / self.config.run.workspace
        self.runs_root.mkdir(parents=True, exist_ok=True)

    def dashboard(
        self,
        *,
        run_id: str | None = None,
        video_id: str | None = None,
        job: PilotUiJobStatus | None = None,
    ) -> PilotUiDashboard:
        projections = self._discover_runs(job)
        videos = self._discover_videos(projections)
        selected_run_id = self._select_run(run_id, projections)
        selected = (
            next(item for item in projections if item.option.run_id == selected_run_id)
            if selected_run_id is not None
            else None
        )
        selected_video_id = self._select_video(video_id, selected, videos)
        stages = self._stages(selected, job)
        preview_kind, preview_url = self._preview(selected, selected_video_id)
        stream = selected.stream if selected is not None else None
        cases = self._case_summaries(selected)
        timeline = self._timeline(cases)
        alerts = self._alert_views(selected)
        return PilotUiDashboard(
            selected_run_id=selected_run_id,
            selected_video_id=selected_video_id,
            videos=tuple(record.option for record in videos),
            runs=tuple(item.option for item in projections),
            stages=stages,
            preview_kind=preview_kind,
            preview_url=preview_url,
            fps_num=stream.fps_num if stream is not None else None,
            fps_den=stream.fps_den if stream is not None else None,
            frame_count=stream.frame_count if stream is not None else None,
            duration_millis=_duration_millis(stream) if stream is not None else None,
            manifest_id=(selected.manifest.manifest_id if selected and selected.manifest else None),
            metrics_id=(selected.metrics.metrics_id if selected and selected.metrics else None),
            cases=cases,
            timeline=timeline,
            alerts=alerts,
            disclaimer=PILOT_OPERATOR_DISCLAIMER,
        )

    def infer_active_stage(self, run_id: str) -> PilotUiStageKey:
        controlled = require_portable_run_id(run_id, "pilot UI active run")
        run_root = self.runs_root / controlled
        projection = self._load_run(controlled, None) if run_root.is_dir() else None
        if projection is None or projection.manifest is None:
            return "VIDEO"
        if projection.perception is None or projection.completion is None:
            return "PERCEPTION"
        if projection.evidence is None:
            return "EVIDENCE"
        if projection.metrics is None:
            return "SCREENING"
        return "REPORT"

    def video_source(self, video_id: str) -> PilotUiVideoSource:
        controlled = str(video_id)
        record = next(
            (
                item
                for item in self._discover_videos(self._discover_runs(None))
                if item.option.video_id == controlled
            ),
            None,
        )
        if record is None:
            raise PilotUiBoundaryError("VIDEO_NOT_FOUND")
        return PilotUiVideoSource(
            workspace_root=self.project_root,
            relative_path=record.option.relative_path,
            media_type="video/mp4",
            expected_sha256=record.content_sha256,
            size_bytes=record.option.size_bytes,
        )

    def preview_source(self, run_id: str) -> PilotUiVideoSource:
        projection = self._require_run(run_id)
        if projection.perception is None or projection.completion is None:
            raise PilotUiBoundaryError("PREVIEW_NOT_AVAILABLE")
        path = projection.perception.preview_path
        if path is None:
            raise PilotUiBoundaryError("PREVIEW_NOT_AVAILABLE")
        prefix = f"runs/{projection.option.run_id}/"
        if not path.startswith(prefix):
            raise PilotUiBoundaryError("PREVIEW_NOT_VERIFIED")
        run_relative = path[len("runs/") :]
        receipt = next(
            (
                item
                for item in projection.completion.artifacts
                if item.role == "PREVIEW" and item.artifact_ref == path
            ),
            None,
        )
        if receipt is None:
            raise PilotUiBoundaryError("PREVIEW_NOT_VERIFIED")
        self._inspect_expected(self.runs_root, run_relative, receipt.artifact_sha256)
        return PilotUiVideoSource(
            workspace_root=self.runs_root,
            relative_path=run_relative,
            media_type="video/mp4",
            expected_sha256=receipt.artifact_sha256,
            size_bytes=receipt.artifact_size_bytes,
        )

    def read_evidence(self, run_id: str, crop_id: str) -> PilotUiBinaryAsset:
        controlled_crop = require_reference_token(crop_id, "pilot UI crop")
        projection = self._require_run(run_id)
        if projection.metrics is None:
            raise PilotUiBoundaryError("EVIDENCE_NOT_AVAILABLE")
        media = next(
            (
                item
                for case in projection.metrics.cases
                for item in case.key_crops
                if item.crop_id == controlled_crop
            ),
            None,
        )
        if media is None or media.integrity != "VERIFIED" or media.run_relative_path is None:
            raise PilotUiBoundaryError("EVIDENCE_NOT_VERIFIED")
        relative = f"{projection.option.run_id}/{media.run_relative_path}"
        try:
            with SecureWorkspace(
                self.runs_root,
                max_file_bytes=self.config.storage.max_media_bytes,
            ) as workspace:
                snapshot = workspace.read_verified(relative, media.media_sha256)
        except (ArtifactIntegrityViolation, PathBoundaryViolation) as error:
            raise PilotUiBoundaryError("EVIDENCE_NOT_VERIFIED") from error
        return PilotUiBinaryAsset(
            bytes=snapshot.bytes,
            media_type=_media_type(media.run_relative_path),
            expected_sha256=media.media_sha256,
        )

    def _discover_videos(self, runs: tuple[_RunProjection, ...]) -> tuple[_VideoRecord, ...]:
        input_root = self.project_root / "inputs"
        if not input_root.is_dir():
            return ()
        sha_to_runs: dict[str, list[str]] = {}
        for run in runs:
            if run.stream is not None:
                sha_to_runs.setdefault(run.stream.input_file_sha256, []).append(run.option.run_id)
        records: list[_VideoRecord] = []
        try:
            candidates = sorted(input_root.iterdir(), key=lambda path: path.name.casefold())
        except OSError:
            return ()
        with SecureWorkspace(
            self.project_root,
            max_file_bytes=self.config.storage.max_media_bytes,
        ) as workspace:
            for candidate in candidates[:_MAX_INPUTS]:
                if not candidate.name.lower().endswith(".mp4"):
                    continue
                relative = f"inputs/{candidate.name}"
                try:
                    with workspace.open_verified_video(
                        relative,
                        self.config.storage.max_media_bytes,
                    ) as opened:
                        content_sha256 = opened.input_file_sha256
                        size_bytes = opened.size_bytes
                except (PathBoundaryViolation, OSError, TypeError, ValueError):
                    continue
                option = PilotUiVideoOption(
                    video_id=sha256_hex(
                        ["pilot-ui-video", 1, relative, size_bytes, content_sha256]
                    ),
                    display_name=candidate.name,
                    relative_path=relative,
                    size_bytes=size_bytes,
                    matching_run_ids=tuple(sorted(sha_to_runs.get(content_sha256, ()))),
                )
                records.append(_VideoRecord(option=option, content_sha256=content_sha256))
        return tuple(records)

    def _discover_runs(self, job: PilotUiJobStatus | None) -> tuple[_RunProjection, ...]:
        try:
            candidates = sorted(self.runs_root.iterdir(), key=lambda path: path.name)
        except OSError:
            return ()
        projections: list[_RunProjection] = []
        for candidate in candidates:
            if len(projections) >= _MAX_RUNS:
                break
            try:
                run_id = require_portable_run_id(candidate.name, "pilot UI discovered run")
            except (TypeError, ValueError):
                continue
            if not candidate.is_dir():
                continue
            projection = self._load_run(run_id, job)
            running = job is not None and job.state == "RUNNING" and job.run_id == run_id
            if projection.metrics is not None or running:
                projections.append(projection)
        if (
            job is not None
            and job.state == "RUNNING"
            and job.run_id is not None
            and not any(item.option.run_id == job.run_id for item in projections)
        ):
            projections.append(
                _RunProjection(
                    option=PilotUiRunOption(
                        run_id=job.run_id,
                        state="RUNNING",
                        case_count=0,
                        alert_count=0,
                    ),
                    manifest=None,
                    stream=None,
                    perception=None,
                    completion=None,
                    evidence=None,
                    metrics=None,
                    alerts=(),
                )
            )
            projections.sort(key=lambda item: item.option.run_id)
        return tuple(projections)

    def _load_run(self, run_id: str, job: PilotUiJobStatus | None) -> _RunProjection:
        invalid = False
        try:
            manifest = self._read_contract(
                f"{run_id}/pilot/run-manifest.json", RunManifest, required=False
            )
            perception = self._read_contract(
                f"{run_id}/perception/report.json", PilotPerceptionReport, required=False
            )
            completion = self._read_contract(
                f"{run_id}/perception/completion-manifest.json",
                PilotPerceptionCompletionManifest,
                required=False,
            )
            evidence = self._read_contract(
                f"{run_id}/pilot/a2-report.json", PilotA2Report, required=False
            )
            metrics = self._read_contract(f"{run_id}/metrics.json", PilotA4Metrics, required=False)
        except PilotUiBoundaryError:
            invalid = True
            manifest = None
            perception = None
            completion = None
            evidence = None
            metrics = None
        if manifest is not None and len(manifest.streams) != 1:
            invalid = True
            manifest = None
        stream = manifest.streams[0] if manifest is not None else None
        if not invalid:
            try:
                self._validate_run_chain(
                    run_id,
                    manifest,
                    stream,
                    perception,
                    completion,
                    evidence,
                    metrics,
                )
            except PilotUiBoundaryError:
                invalid = True
                perception = None
                completion = None
                evidence = None
                metrics = None
        alerts: tuple[PilotLocalAlertDocument, ...] = ()
        if metrics is not None:
            try:
                alerts = self._load_alerts(run_id, metrics)
            except PilotUiBoundaryError:
                invalid = True
                metrics = None
                alerts = ()
        running = job is not None and job.state == "RUNNING" and job.run_id == run_id
        if invalid:
            state: PilotUiRunState = "INVALID"
        elif running:
            state = "RUNNING"
        elif metrics is not None:
            state = (
                "ATTENTION_REQUIRED"
                if metrics.human_review_count or metrics.unresolved_count
                else "COMPLETE"
            )
        else:
            state = "INCOMPLETE"
        return _RunProjection(
            option=PilotUiRunOption(
                run_id=run_id,
                state=state,
                case_count=metrics.case_count if metrics is not None else 0,
                alert_count=len(alerts),
            ),
            manifest=manifest,
            stream=stream,
            perception=perception,
            completion=completion,
            evidence=evidence,
            metrics=metrics,
            alerts=alerts,
        )

    def _validate_run_chain(
        self,
        run_id: str,
        manifest: RunManifest | None,
        stream: StreamManifest | None,
        perception: PilotPerceptionReport | None,
        completion: PilotPerceptionCompletionManifest | None,
        evidence: PilotA2Report | None,
        metrics: PilotA4Metrics | None,
    ) -> None:
        if manifest is None or stream is None:
            if any(item is not None for item in (perception, completion, evidence, metrics)):
                raise PilotUiBoundaryError("RUN_AUTHORITY_INVALID")
            return
        if (perception is None) != (completion is None):
            raise PilotUiBoundaryError("PERCEPTION_AUTHORITY_INVALID")
        if (
            perception is not None
            and completion is not None
            and (
                perception.run_id != run_id
                or completion.run_id != run_id
                or perception.manifest_id != completion.manifest_id
                or completion.config_sha256 != manifest.config_sha256
                or completion.video_sha256 != stream.input_file_sha256
            )
        ):
            raise PilotUiBoundaryError("PERCEPTION_AUTHORITY_INVALID")
        if evidence is not None and (
            evidence.run_id != run_id
            or evidence.run_manifest_id != manifest.manifest_id
            or evidence.config_sha256 != manifest.config_sha256
            or evidence.video_sha256 != stream.input_file_sha256
            or completion is None
            or evidence.perception_completion_id != completion.completion_id
        ):
            raise PilotUiBoundaryError("EVIDENCE_AUTHORITY_INVALID")
        if metrics is not None and (
            metrics.run_id != run_id
            or metrics.manifest_id != manifest.manifest_id
            or metrics.config_sha256 != manifest.config_sha256
            or evidence is None
        ):
            raise PilotUiBoundaryError("REPORT_AUTHORITY_INVALID")

    def _load_alerts(
        self, run_id: str, metrics: PilotA4Metrics
    ) -> tuple[PilotLocalAlertDocument, ...]:
        alert_dir = self.runs_root / run_id / "alerts"
        if not alert_dir.exists():
            names: list[str] = []
        else:
            try:
                names = sorted(
                    path.name for path in alert_dir.iterdir() if _ALERT_NAME.fullmatch(path.name)
                )
            except OSError as error:
                raise PilotUiBoundaryError("ALERT_AUTHORITY_INVALID") from error
        alerts: list[PilotLocalAlertDocument] = []
        case_ids = {case.case_id for case in metrics.cases}
        for name in names:
            alert = self._read_contract(
                f"{run_id}/alerts/{name}", PilotLocalAlertDocument, required=True
            )
            assert alert is not None
            if (
                alert.run_id != run_id
                or alert.manifest_id != metrics.manifest_id
                or alert.config_sha256 != metrics.config_sha256
                or alert.case_id not in case_ids
            ):
                raise PilotUiBoundaryError("ALERT_AUTHORITY_INVALID")
            alerts.append(alert)
        if len(alerts) != metrics.verified_local_alert_count:
            raise PilotUiBoundaryError("ALERT_AUTHORITY_INVALID")
        return tuple(alerts)

    def _read_contract(
        self,
        relative: str,
        model: type[_ContractT],
        *,
        required: bool,
    ) -> _ContractT | None:
        try:
            with SecureWorkspace(
                self.runs_root,
                max_file_bytes=max(self.config.storage.max_media_bytes, _MAX_JSON_BYTES),
            ) as workspace:
                snapshot = workspace.read_verified(relative, max_bytes=_MAX_JSON_BYTES)
            return model.model_validate_json(snapshot.bytes)
        except PathBoundaryViolation as error:
            if not required and error.reason_code == "FILE_MISSING":
                return None
            raise PilotUiBoundaryError("RUN_ARTIFACT_UNAVAILABLE") from error
        except (ArtifactIntegrityViolation, ValidationError, UnicodeError, ValueError) as error:
            raise PilotUiBoundaryError("RUN_ARTIFACT_INVALID") from error

    def _inspect_expected(self, root: Path, relative: str, expected_sha256: str) -> None:
        try:
            with SecureWorkspace(
                root,
                max_file_bytes=self.config.storage.max_media_bytes,
            ) as workspace:
                workspace.read_verified(relative, expected_sha256)
        except (ArtifactIntegrityViolation, PathBoundaryViolation) as error:
            raise PilotUiBoundaryError("MEDIA_NOT_VERIFIED") from error

    def _require_run(self, run_id: str) -> _RunProjection:
        controlled = require_portable_run_id(run_id, "pilot UI selected run")
        projection = next(
            (item for item in self._discover_runs(None) if item.option.run_id == controlled),
            None,
        )
        if projection is None:
            raise PilotUiBoundaryError("RUN_NOT_FOUND")
        if projection.option.state == "INVALID":
            raise PilotUiBoundaryError("RUN_ARTIFACT_INVALID")
        return projection

    def _select_run(
        self, requested: str | None, projections: tuple[_RunProjection, ...]
    ) -> str | None:
        if requested is not None:
            if requested == "":
                return None
            try:
                controlled = require_portable_run_id(requested, "pilot UI selected run")
            except (TypeError, ValueError) as error:
                raise PilotUiBoundaryError("RUN_NOT_FOUND") from error
            if not any(item.option.run_id == controlled for item in projections):
                raise PilotUiBoundaryError("RUN_NOT_FOUND")
            return controlled
        completed = [
            item.option.run_id
            for item in projections
            if item.option.state in {"COMPLETE", "ATTENTION_REQUIRED"}
        ]
        if completed:
            return completed[-1]
        return projections[-1].option.run_id if projections else None

    @staticmethod
    def _select_video(
        requested: str | None,
        selected: _RunProjection | None,
        videos: tuple[_VideoRecord, ...],
    ) -> str | None:
        if requested is not None:
            if not any(item.option.video_id == requested for item in videos):
                raise PilotUiBoundaryError("VIDEO_NOT_FOUND")
            return requested
        if selected is not None and selected.stream is not None:
            matching = next(
                (
                    item.option.video_id
                    for item in videos
                    if item.content_sha256 == selected.stream.input_file_sha256
                ),
                None,
            )
            if matching is not None:
                return matching
        return videos[0].option.video_id if videos else None

    def _stages(
        self,
        selected: _RunProjection | None,
        job: PilotUiJobStatus | None,
    ) -> tuple[PilotUiStageProgress, ...]:
        labels: tuple[tuple[PilotUiStageKey, str], ...] = (
            ("VIDEO", "视频就绪"),
            ("PERCEPTION", "视觉感知"),
            ("EVIDENCE", "证据构建"),
            ("SCREENING", "模型初审"),
            ("REPORT", "案件与告警"),
        )
        complete = {
            "VIDEO": selected is not None and selected.manifest is not None,
            "PERCEPTION": selected is not None
            and selected.perception is not None
            and selected.completion is not None,
            "EVIDENCE": selected is not None and selected.evidence is not None,
            "SCREENING": selected is not None and selected.metrics is not None,
            "REPORT": selected is not None and selected.metrics is not None,
        }
        summaries = {
            "VIDEO": "输入与运行清单已绑定",
            "PERCEPTION": "本地检测与匿名轨迹已封存",
            "EVIDENCE": "候选事件与隐私证据已构建",
            "SCREENING": "结构化模型初审已完成",
            "REPORT": "案件、报告与本地告警已发布",
        }
        active = (
            job.active_stage
            if job is not None
            and job.state == "RUNNING"
            and selected is not None
            and job.run_id == selected.option.run_id
            else None
        )
        attention = selected is not None and selected.option.state == "ATTENTION_REQUIRED"
        invalid = selected is not None and selected.option.state == "INVALID"
        stages: list[PilotUiStageProgress] = []
        for key, label in labels:
            if invalid:
                state = "UNAVAILABLE"
                summary = "权威产物校验失败"
            elif complete[key]:
                state = "ATTENTION_REQUIRED" if attention and key == "REPORT" else "COMPLETE"
                summary = summaries[key]
            elif active == key:
                state = "IN_PROGRESS"
                summary = "正在执行; 请保持此页面打开"
            else:
                state = "PENDING"
                summary = "等待上一阶段完成"
            stages.append(PilotUiStageProgress(key=key, state=state, label=label, summary=summary))
        return tuple(stages)

    @staticmethod
    def _preview(
        selected: _RunProjection | None,
        selected_video_id: str | None,
    ) -> tuple[str, str | None]:
        # OpenCV's sealed debug preview uses the portable ``mp4v`` writer and
        # remains available through ``preview_source`` for desktop inspection.
        # Chromium does not reliably decode that codec, so the UI prefers the
        # matching H.264 source and presents verified evidence crops beside it.
        if selected_video_id is not None:
            return "SOURCE", f"/api/videos/{selected_video_id}"
        if (
            selected is not None
            and selected.perception is not None
            and selected.completion is not None
            and selected.perception.preview_path is not None
            and any(item.role == "PREVIEW" for item in selected.completion.artifacts)
        ):
            return "DEBUG", f"/api/runs/{selected.option.run_id}/preview"
        return "NONE", None

    def _case_summaries(self, selected: _RunProjection | None) -> tuple[PilotUiCaseSummary, ...]:
        if selected is None or selected.metrics is None or selected.stream is None:
            return ()
        return tuple(
            self._case_summary(selected.option.run_id, case, selected.stream)
            for case in selected.metrics.cases
        )

    def _case_summary(
        self, run_id: str, case: PilotA4CaseView, stream: StreamManifest
    ) -> PilotUiCaseSummary:
        evidence: list[PilotUiEvidenceView] = []
        for media in case.key_crops:
            _, _, frame_index = parse_frame_id(media.frame_id)
            integrity = media.integrity
            media_url: str | None = None
            if integrity == "VERIFIED" and media.run_relative_path is not None:
                relative = f"{run_id}/{media.run_relative_path}"
                try:
                    self._inspect_expected(self.runs_root, relative, media.media_sha256)
                    media_url = f"/api/runs/{run_id}/evidence/{media.crop_id}"
                except PilotUiBoundaryError as error:
                    integrity = (
                        "MISSING"
                        if error.__cause__
                        and isinstance(error.__cause__, PathBoundaryViolation)
                        and error.__cause__.reason_code == "FILE_MISSING"
                        else "HASH_MISMATCH"
                    )
            evidence.append(
                PilotUiEvidenceView(
                    crop_id=media.crop_id,
                    role=media.role,
                    frame_index=frame_index,
                    time_millis=_frame_millis(frame_index, stream),
                    integrity=integrity,
                    media_url=media_url,
                    width=media.width,
                    height=media.height,
                )
            )
        return PilotUiCaseSummary(
            case_id=case.case_id,
            revision=case.revision,
            status=case.status,
            violation_type=case.violation_type,
            start_frame=case.start_frame,
            end_frame_exclusive=case.end_frame_exclusive,
            start_time_millis=_frame_millis(case.start_frame, stream),
            end_time_millis=_frame_millis(case.end_frame_exclusive, stream),
            screening_decision=case.screening_decision,
            screening_probability=case.screening_probability,
            final_decision=case.final_decision,
            alert_level=case.alert_level,
            alert_rescinded=case.alert_rescinded,
            human_review_required=case.human_review_required,
            appeal_status=case.appeal_status,
            evidence=tuple(evidence),
        )

    @staticmethod
    def _timeline(cases: tuple[PilotUiCaseSummary, ...]) -> tuple[PilotUiTimelineItem, ...]:
        items: list[PilotUiTimelineItem] = []
        for case in cases:
            items.append(
                PilotUiTimelineItem(
                    item_id=sha256_hex(["pilot-ui-timeline", 1, case.case_id, "start"]),
                    kind="CASE_START",
                    case_id=case.case_id,
                    frame_index=case.start_frame,
                    time_millis=case.start_time_millis,
                    label="候选事件开始",
                )
            )
            for evidence in case.evidence:
                items.append(
                    PilotUiTimelineItem(
                        item_id=sha256_hex(
                            ["pilot-ui-timeline", 1, case.case_id, evidence.crop_id]
                        ),
                        kind="EVIDENCE",
                        case_id=case.case_id,
                        frame_index=evidence.frame_index,
                        time_millis=evidence.time_millis,
                        label={
                            "PANORAMA": "现场全景",
                            "SUBJECT": "主体证据",
                            "FOCUS": "头部与护目镜区域",
                            "TEMPORAL": "时序证据",
                        }[evidence.role],
                        evidence_crop_id=evidence.crop_id,
                        media_url=evidence.media_url,
                    )
                )
            items.append(
                PilotUiTimelineItem(
                    item_id=sha256_hex(["pilot-ui-timeline", 1, case.case_id, "end"]),
                    kind="CASE_END",
                    case_id=case.case_id,
                    frame_index=case.end_frame_exclusive,
                    time_millis=case.end_time_millis,
                    label="候选事件结束",
                )
            )
        kind_order = {"CASE_START": 0, "EVIDENCE": 1, "CASE_END": 2}
        return tuple(
            sorted(
                items,
                key=lambda item: (item.time_millis, kind_order[item.kind], item.item_id),
            )
        )

    @staticmethod
    def _alert_views(selected: _RunProjection | None) -> tuple[PilotUiAlertView, ...]:
        if selected is None:
            return ()
        return tuple(
            PilotUiAlertView(
                alert_id=document.alert.alert_id,
                case_id=document.case_id,
                level=document.alert.level,
                final_decision=document.final_decision,
                recipients=document.alert.recipients,
                rescinded=document.alert.rescinded,
                production_action_prohibited=document.production_action_prohibited,
            )
            for document in selected.alerts
        )


class PilotUiJobManager:
    """Run the existing A5 service in one bounded background worker."""

    def __init__(self, *, service: PilotUiService, runner: _Runner = run_pilot_a5) -> None:
        self._service = service
        self._runner = runner
        self._lock = threading.Lock()
        self._status = PilotUiJobStatus()
        self._thread: threading.Thread | None = None

    def start(self, request: PilotUiJobStartRequest) -> PilotUiJobStatus:
        source = self._service.video_source(request.video_id)
        with self._lock:
            if self._status.state == "RUNNING":
                raise PilotUiBoundaryError("JOB_ALREADY_RUNNING")
            status = PilotUiJobStatus(
                job_id=f"job-{uuid.uuid4().hex}",
                state="RUNNING",
                run_id=request.run_id,
                video_id=request.video_id,
                active_stage="VIDEO",
            )
            self._status = status
            self._thread = threading.Thread(
                target=self._execute,
                args=(status, source, request),
                name="labcourt-pilot-ui-runner",
                daemon=True,
            )
            self._thread.start()
            return status

    def snapshot(self) -> PilotUiJobStatus:
        with self._lock:
            status = self._status
        if status.state != "RUNNING" or status.run_id is None:
            return status
        try:
            active = self._service.infer_active_stage(status.run_id)
        except (LabCourtError, OSError, TypeError, ValueError):
            active = status.active_stage or "VIDEO"
        refreshed = status.model_copy(update={"active_stage": active})
        with self._lock:
            if self._status.job_id == status.job_id and self._status.state == "RUNNING":
                self._status = refreshed
                return refreshed
            return self._status

    def wait(self, timeout: float | None = None) -> PilotUiJobStatus:
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        return self.snapshot()

    def _execute(
        self,
        initial: PilotUiJobStatus,
        source: PilotUiVideoSource,
        request: PilotUiJobStartRequest,
    ) -> None:
        try:
            run_request = build_pilot_run_request(
                config=self._service.config,
                run_id=request.run_id,
                video_path=Path(source.relative_path),
                project_root=self._service.project_root,
                resume=request.resume,
            )
            report = self._runner(
                config=self._service.config,
                request=run_request,
                config_path=self._service.config_path,
                project_root=self._service.project_root,
            )
            if report.run_id != request.run_id:
                raise PilotUiBoundaryError("RUN_REPORT_MISMATCH")
            final = PilotUiJobStatus(
                job_id=initial.job_id,
                state=("SUCCEEDED" if report.state == "COMPLETE" else "ATTENTION_REQUIRED"),
                run_id=request.run_id,
                video_id=request.video_id,
                report_id=report.report_id,
            )
        except PilotA5OperationsError as error:
            final = self._failed(initial, error.code.value)
        except PilotOperationsBoundaryError as error:
            final = self._failed(initial, error.code.value)
        except PilotUiBoundaryError as error:
            final = self._failed(initial, error.reason_code)
        except (LabCourtError, OSError, TypeError, ValueError):
            final = self._failed(initial, "PILOT_RUN_FAILED")
        with self._lock:
            if self._status.job_id == initial.job_id:
                self._status = final

    @staticmethod
    def _failed(initial: PilotUiJobStatus, reason_code: str) -> PilotUiJobStatus:
        return PilotUiJobStatus(
            job_id=initial.job_id,
            state="FAILED",
            run_id=initial.run_id,
            video_id=initial.video_id,
            reason_code=reason_code,
        )


__all__ = [
    "PilotUiBinaryAsset",
    "PilotUiBoundaryError",
    "PilotUiJobManager",
    "PilotUiService",
    "PilotUiVideoSource",
]
