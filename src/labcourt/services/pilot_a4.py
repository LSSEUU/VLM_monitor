"""Run-scoped A4 composition root for safe local pilot closure."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from labcourt.adapters.local_json_alert_channel import LocalJsonAlertChannel
from labcourt.adapters.storage.pilot_report_source import (
    load_pilot_case_snapshots,
    verified_local_alert_paths,
)
from labcourt.adapters.storage.pilot_static_report_store import PilotStaticReportStore
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.application.m5_appeal_operations import build_m5_appeal_resolution_report
from labcourt.application.pilot_operator_report import (
    build_pilot_case_views,
    build_pilot_metrics,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import AppealStatus, VerdictDecision
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m3_models import require_bounded_public_text
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.pilot import PilotA4CloseReport
from labcourt.contracts.pilot_report import (
    PilotA4PublicationReport,
    PilotA4ReviewReport,
)
from labcourt.contracts.references import require_portable_run_id, require_reference_token
from labcourt.contracts.training import TrainingLabel
from labcourt.exceptions import LabCourtError
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.services.m5_human_appeals import (
    begin_human_appeal_review,
    resolve_human_appeal,
    submit_human_appeal,
)
from labcourt.services.m5_operations import dispatch_m5_alerts, finalize_m5_run

PILOT_REVIEW_ACTOR = "pilot-local-operator"


class PilotA4ReviewFailureCode(StrEnum):
    CASE_EVIDENCE_UNAVAILABLE = "CASE_EVIDENCE_UNAVAILABLE"
    REVIEW_AUTHORITY_CONFLICT = "REVIEW_AUTHORITY_CONFLICT"
    REVIEW_INPUT_INVALID = "REVIEW_INPUT_INVALID"


class PilotA4ReviewError(LabCourtError):
    def __init__(self, reason_code: PilotA4ReviewFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"pilot A4 review failed: {reason_code.value}")


def close_pilot_run(
    *,
    config: AppConfig,
    runs_root: str | Path,
    database_path: str | Path,
    run_id: str,
    limit: int = 256,
    clock: Callable[[], datetime] | None = None,
) -> PilotA4CloseReport:
    """Close READY cases inside one pilot run without dispatching its local outbox."""

    root, run_root, database, controlled_run_id = _pilot_paths(
        config=config,
        runs_root=runs_root,
        database_path=database_path,
        run_id=run_id,
    )
    del root

    finalization = finalize_m5_run(
        config=config,
        workspace_root=run_root,
        database_path=database,
        run_id=controlled_run_id,
        limit=limit,
        clock=clock,
    )
    return PilotA4CloseReport(
        run_id=finalization.run_id,
        manifest_id=finalization.manifest_id,
        config_sha256=finalization.config_sha256,
        selected_count=finalization.selected_count,
        outcomes=finalization.outcomes,
    )


def publish_pilot_run(
    *,
    config: AppConfig,
    runs_root: str | Path,
    database_path: str | Path,
    run_id: str,
    limit: int = 256,
    clock: Callable[[], datetime] | None = None,
) -> PilotA4PublicationReport:
    """Close, locally dispatch, and atomically publish one pilot run."""

    root, run_root, database, controlled_run_id = _pilot_paths(
        config=config,
        runs_root=runs_root,
        database_path=database_path,
        run_id=run_id,
    )
    closure = close_pilot_run(
        config=config,
        runs_root=root,
        database_path=database,
        run_id=controlled_run_id,
        limit=limit,
        clock=clock,
    )
    evidence = SQLiteEvidenceRepository(database, config.storage.busy_timeout_ms)
    manifest = evidence.load_run_manifest(controlled_run_id)
    channel = LocalJsonAlertChannel(
        output_directory=run_root / "alerts",
        run_id=controlled_run_id,
        manifest_id=manifest.manifest_id,
        config_sha256=manifest.config_sha256,
    )
    dispatch = dispatch_m5_alerts(
        config=config,
        workspace_root=run_root,
        database_path=database,
        run_id=controlled_run_id,
        worker_id="pilot-local-json-report-v1",
        limit=limit,
        channel=channel,
    )
    snapshots = load_pilot_case_snapshots(
        database_path=database,
        busy_timeout_ms=config.storage.busy_timeout_ms,
        run_id=controlled_run_id,
    )
    local_alert_paths = verified_local_alert_paths(
        cases=tuple(snapshot.case for snapshot in snapshots),
        run_root=run_root,
        manifest=manifest,
    )
    views = build_pilot_case_views(
        snapshots=snapshots,
        manifest=manifest,
        runs_root=root,
        run_id=controlled_run_id,
    )
    metrics = build_pilot_metrics(
        views=views,
        manifest=manifest,
        run_id=controlled_run_id,
        verified_local_alert_count=len(local_alert_paths),
    )
    PilotStaticReportStore(run_root=run_root, run_id=controlled_run_id).publish(metrics)
    return PilotA4PublicationReport(
        closure=closure,
        dispatch=dispatch,
        metrics=metrics,
        index_path=f"runs/{controlled_run_id}/report/index.html",
        metrics_path=f"runs/{controlled_run_id}/metrics.json",
        case_paths=tuple(
            f"runs/{controlled_run_id}/report/cases/{case.case_id}.html" for case in views
        ),
        local_alert_paths=local_alert_paths,
    )


def review_pilot_case(
    *,
    config: AppConfig,
    runs_root: str | Path,
    database_path: str | Path,
    run_id: str,
    case_id: str,
    decision: VerdictDecision,
    reason: str,
    clock: Callable[[], datetime] | None = None,
) -> PilotA4ReviewReport:
    """Map one explicit local review onto the existing M5 appeal FSM and republish."""

    root, run_root, database, controlled_run_id = _pilot_paths(
        config=config,
        runs_root=runs_root,
        database_path=database_path,
        run_id=run_id,
    )
    try:
        controlled_case_id = require_reference_token(case_id, "pilot A4 review case_id")
        controlled_reason = require_bounded_public_text(
            reason,
            "pilot A4 review reason",
            max_length=2_048,
        )
    except (TypeError, ValueError) as exc:
        raise PilotA4ReviewError(PilotA4ReviewFailureCode.REVIEW_INPUT_INVALID) from exc
    if not isinstance(decision, VerdictDecision):
        raise PilotA4ReviewError(PilotA4ReviewFailureCode.REVIEW_INPUT_INVALID)

    repository = SQLiteM5Repository(database, config.storage.busy_timeout_ms)
    evidence = SQLiteEvidenceRepository(database, config.storage.busy_timeout_ms)
    source = repository.load_closed_case_authority(controlled_run_id, controlled_case_id)
    snapshot = evidence.load_case(controlled_run_id, controlled_case_id)
    manifest = evidence.load_run_manifest(controlled_run_id)
    label = _pilot_review_label(
        snapshot=snapshot,
        manifest=manifest,
        runs_root=root,
        run_id=controlled_run_id,
        source_decision=source.final_decision,
        requested_decision=decision,
    )
    current = repository.load_current_appeal(controlled_run_id, controlled_case_id)
    if current is not None and (
        current.appeal.reason != controlled_reason
        or current.appeal.submitted_by != PILOT_REVIEW_ACTOR
    ):
        raise PilotA4ReviewError(PilotA4ReviewFailureCode.REVIEW_AUTHORITY_CONFLICT)
    if current is None:
        submitted = submit_human_appeal(
            config=config,
            workspace_root=run_root,
            database_path=database,
            run_id=controlled_run_id,
            case_id=controlled_case_id,
            reason=controlled_reason,
            submitted_by=PILOT_REVIEW_ACTOR,
        )
        current = repository.load_appeal_by_id(controlled_run_id, submitted.appeal_id)
    if current is None:
        raise PilotA4ReviewError(PilotA4ReviewFailureCode.REVIEW_AUTHORITY_CONFLICT)
    if current.version == 1 and current.appeal.status == AppealStatus.SUBMITTED:
        begin_human_appeal_review(
            config=config,
            workspace_root=run_root,
            database_path=database,
            run_id=controlled_run_id,
            appeal_id=current.appeal.appeal_id,
            reviewer_id=PILOT_REVIEW_ACTOR,
        )
        current = repository.load_appeal_by_id(controlled_run_id, current.appeal.appeal_id)
    if current is None:
        raise PilotA4ReviewError(PilotA4ReviewFailureCode.REVIEW_AUTHORITY_CONFLICT)
    expected_status = (
        AppealStatus.UPHELD if decision == source.final_decision else AppealStatus.OVERTURNED
    )
    if current.version == 2 and current.appeal.status == AppealStatus.UNDER_REVIEW:
        if current.assigned_reviewer_id != PILOT_REVIEW_ACTOR:
            raise PilotA4ReviewError(PilotA4ReviewFailureCode.REVIEW_AUTHORITY_CONFLICT)
        resolve_human_appeal(
            config=config,
            workspace_root=run_root,
            database_path=database,
            run_id=controlled_run_id,
            appeal_id=current.appeal.appeal_id,
            reviewer_id=PILOT_REVIEW_ACTOR,
            status=expected_status,
            resolved_decision=decision,
            resolution_summary=controlled_reason,
            authored_labels=(label,) if label is not None else (),
            precedent_situation=(controlled_reason if label is not None else None),
            clock=clock,
        )
        current = repository.load_appeal_by_id(controlled_run_id, current.appeal.appeal_id)
    if (
        current is None
        or current.version != 3
        or current.appeal.status != expected_status
        or current.assigned_reviewer_id != PILOT_REVIEW_ACTOR
        or current.appeal.resolved_decision != decision
        or current.appeal.resolution_summary != controlled_reason
    ):
        raise PilotA4ReviewError(PilotA4ReviewFailureCode.REVIEW_AUTHORITY_CONFLICT)
    intent = repository.load_resolution(controlled_run_id, current.appeal.appeal_id)
    if intent is None or not _review_label_matches_intent(label, intent.training_labels):
        raise PilotA4ReviewError(PilotA4ReviewFailureCode.REVIEW_AUTHORITY_CONFLICT)
    resolution = build_m5_appeal_resolution_report(intent)
    publication = publish_pilot_run(
        config=config,
        runs_root=root,
        database_path=database,
        run_id=controlled_run_id,
    )
    return PilotA4ReviewReport(
        run_id=controlled_run_id,
        case_id=controlled_case_id,
        source_decision=source.final_decision,
        requested_decision=decision,
        reason_sha256=hashlib.sha256(controlled_reason.encode("utf-8")).hexdigest(),
        manifest_id=manifest.manifest_id,
        resolution=resolution,
        review_label=label,
        publication_id=publication.publication_id,
        metrics_id=publication.metrics.metrics_id,
        index_path=publication.index_path,
    )


def _pilot_review_label(
    *,
    snapshot: CaseSnapshot,
    manifest: RunManifest,
    runs_root: Path,
    run_id: str,
    source_decision: VerdictDecision,
    requested_decision: VerdictDecision,
) -> M5AppealTrainingLabelInput | None:
    if requested_decision == source_decision:
        return None
    views = build_pilot_case_views(
        snapshots=(snapshot,),
        manifest=manifest,
        runs_root=runs_root,
        run_id=run_id,
    )
    case = snapshot.case
    pack = case.evidence_packs[-1] if case.evidence_packs else None
    crops = {
        crop.crop_id: crop
        for attribute in ("subject_crops", "focus_crops", "temporal_crops", "panorama_crops")
        for crop in (getattr(pack, attribute, ()) if pack is not None else ())
    }
    role_rank = {"SUBJECT": 0, "FOCUS": 1, "TEMPORAL": 2, "PANORAMA": 3}
    verified = sorted(
        (item for item in views[0].key_crops if item.integrity == "VERIFIED"),
        key=lambda item: (role_rank[item.role], item.crop_id),
    )
    if not verified or verified[0].crop_id not in crops:
        raise PilotA4ReviewError(PilotA4ReviewFailureCode.CASE_EVIDENCE_UNAVAILABLE)
    crop = crops[verified[0].crop_id]
    return M5AppealTrainingLabelInput(
        crop_id=crop.crop_id,
        bbox=BBoxXYXY(x1=0, y1=0, x2=crop.output_width, y2=crop.output_height),
        label_name=f"pilot_review:{case.event.violation_type.value}",
        label_value=requested_decision.value,
    )


def _review_label_matches_intent(
    label: M5AppealTrainingLabelInput | None,
    training_labels: tuple[TrainingLabel, ...],
) -> bool:
    if label is None:
        return not training_labels
    if len(training_labels) != 1:
        return False
    durable = training_labels[0]
    return all(
        getattr(durable, field, None) == getattr(label, field)
        for field in ("crop_id", "bbox", "label_name", "label_value")
    )


def _pilot_paths(
    *,
    config: AppConfig,
    runs_root: str | Path,
    database_path: str | Path,
    run_id: str,
) -> tuple[Path, Path, Path, str]:
    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    controlled_run_id = require_portable_run_id(run_id, "pilot A4 run_id")
    supplied_root = Path(runs_root)
    supplied_database = Path(database_path)
    if ".." in supplied_root.parts or ".." in supplied_database.parts:
        raise ValueError("pilot A4 paths cannot contain parent traversal")
    root = supplied_root.absolute()
    run_root = root / controlled_run_id
    database = supplied_database.absolute()
    expected_database = run_root / config.storage.database_filename
    if database != expected_database or database.parent != run_root:
        raise ValueError("database_path must be the selected pilot run authority")
    return root, run_root, database, controlled_run_id


__all__ = [
    "PILOT_REVIEW_ACTOR",
    "PilotA4ReviewError",
    "PilotA4ReviewFailureCode",
    "close_pilot_run",
    "publish_pilot_run",
    "review_pilot_case",
]
