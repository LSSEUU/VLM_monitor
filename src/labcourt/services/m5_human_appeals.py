"""User-oriented composition for explicit, non-guessed M5 human appeal inputs."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.application.m5_appeal_precedent import build_appeal_overturn_precedent
from labcourt.application.m5_human_labels import build_m5_appeal_training_labels
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import AppealStatus, VerdictDecision
from labcourt.contracts.m5_appeal_operations import (
    M5AppealResolutionCommandReport,
    M5AppealReviewCommandReport,
    M5AppealSubmissionCommandReport,
)
from labcourt.contracts.m5_appeals import (
    AppealResolutionCommand,
    AppealReviewCommand,
    AppealSubmissionCommand,
    AppealVersionAuthority,
)
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.exceptions import LabCourtError
from labcourt.services.m5_appeal_operations import (
    begin_m5_appeal_review,
    resolve_m5_appeal,
    submit_m5_appeal,
)


class M5HumanAppealFailureCode(StrEnum):
    APPEAL_NOT_FOUND = "APPEAL_NOT_FOUND"
    INVALID_OPERATION_CLOCK = "INVALID_OPERATION_CLOCK"
    REPLACEMENT_SITUATION_REQUIRED = "REPLACEMENT_SITUATION_REQUIRED"
    TRANSITION_NOT_ALLOWED = "TRANSITION_NOT_ALLOWED"
    UNUSED_REPLACEMENT_SITUATION = "UNUSED_REPLACEMENT_SITUATION"


class M5HumanAppealError(LabCourtError):
    def __init__(self, reason_code: M5HumanAppealFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"M5 human appeal failed: {reason_code.value}")


def _controlled_authority(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
) -> tuple[Path, SQLiteM5Repository]:
    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    supplied_root = Path(workspace_root)
    supplied_database = Path(database_path)
    if ".." in supplied_root.parts or ".." in supplied_database.parts:
        raise ValueError("M5 human appeal paths cannot contain parent traversal")
    root = supplied_root.absolute()
    database = supplied_database.absolute()
    if database != root / config.storage.database_filename or database.parent != root:
        raise ValueError("database_path must be the configured authority inside workspace_root")
    return root, SQLiteM5Repository(database, config.storage.busy_timeout_ms)


def _load_appeal(
    repository: SQLiteM5Repository,
    run_id: str,
    appeal_id: str,
) -> AppealVersionAuthority:
    authority = repository.load_appeal_by_id(run_id, appeal_id)
    if authority is None:
        raise M5HumanAppealError(M5HumanAppealFailureCode.APPEAL_NOT_FOUND)
    return authority


def submit_human_appeal(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    run_id: str,
    case_id: str,
    reason: str,
    submitted_by: str,
    appeal_id: str | None = None,
) -> M5AppealSubmissionCommandReport:
    """Submit explicit human text, deriving a replay-stable identity when omitted."""

    root, repository = _controlled_authority(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    )
    source = repository.load_closed_case_authority(run_id, case_id)
    resolved_appeal_id = appeal_id or sha256_hex(
        [
            "m5-human-appeal",
            1,
            run_id,
            case_id,
            source.authority_sha256,
            submitted_by,
            reason,
        ]
    )
    command = AppealSubmissionCommand(
        run_id=run_id,
        case_id=case_id,
        appeal_id=resolved_appeal_id,
        expected_case_revision=source.case_revision,
        expected_case_authority_sha256=source.authority_sha256,
        reason=reason,
        submitted_by=submitted_by,
    )
    return submit_m5_appeal(
        config=config,
        workspace_root=root,
        database_path=database_path,
        command=command,
    )


def begin_human_appeal_review(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    run_id: str,
    appeal_id: str,
    reviewer_id: str,
) -> M5AppealReviewCommandReport:
    """Begin review using the current durable appeal identity as the CAS authority."""

    root, repository = _controlled_authority(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    )
    current = _load_appeal(repository, run_id, appeal_id)
    expected = (
        current.previous_authority_sha256
        if current.version == 2 and current.previous_authority_sha256 is not None
        else current.authority_sha256
    )
    command = AppealReviewCommand(
        run_id=run_id,
        case_id=current.appeal.case_id,
        appeal_id=appeal_id,
        expected_appeal_authority_sha256=expected,
        reviewer_id=reviewer_id,
    )
    return begin_m5_appeal_review(
        config=config,
        workspace_root=root,
        database_path=database_path,
        command=command,
    )


def resolve_human_appeal(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    run_id: str,
    appeal_id: str,
    reviewer_id: str,
    status: AppealStatus,
    resolved_decision: VerdictDecision,
    resolution_summary: str,
    authored_labels: tuple[M5AppealTrainingLabelInput, ...] = (),
    precedent_situation: str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> M5AppealResolutionCommandReport:
    """Resolve from concise human inputs while binding all authority boilerplate locally."""

    root, repository = _controlled_authority(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    )
    current = _load_appeal(repository, run_id, appeal_id)
    if current.version != 2 or current.appeal.status != AppealStatus.UNDER_REVIEW:
        raise M5HumanAppealError(M5HumanAppealFailureCode.TRANSITION_NOT_ALLOWED)
    operation_time = clock() if clock is not None else datetime.now(UTC)
    if (
        not isinstance(operation_time, datetime)
        or operation_time.tzinfo is None
        or operation_time.utcoffset() != UTC.utcoffset(operation_time)
    ):
        raise M5HumanAppealError(M5HumanAppealFailureCode.INVALID_OPERATION_CLOCK)
    labels = build_m5_appeal_training_labels(
        appeal_authority=current,
        terminal_status=status,
        authored_inputs=authored_labels,
    )
    replacement = None
    if status == AppealStatus.OVERTURNED:
        if precedent_situation is None:
            raise M5HumanAppealError(M5HumanAppealFailureCode.REPLACEMENT_SITUATION_REQUIRED)
        manifest = SQLiteEvidenceRepository(
            Path(database_path).absolute(),
            config.storage.busy_timeout_ms,
        ).load_run_manifest(run_id)
        replacement = build_appeal_overturn_precedent(
            case_authority=current.source_case_authority,
            manifest=manifest,
            appeal_id=appeal_id,
            situation_text=precedent_situation,
            resolved_decision=resolved_decision,
            config=config,
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
            created_at=operation_time,
        )
    elif precedent_situation is not None:
        raise M5HumanAppealError(M5HumanAppealFailureCode.UNUSED_REPLACEMENT_SITUATION)
    command = AppealResolutionCommand(
        run_id=run_id,
        case_id=current.appeal.case_id,
        appeal_id=appeal_id,
        expected_appeal_authority_sha256=current.authority_sha256,
        status=status,
        reviewer_id=reviewer_id,
        resolution_summary=resolution_summary,
        resolved_decision=resolved_decision,
        appeal_precedent_authority=replacement,
        training_labels=labels,
    )
    return resolve_m5_appeal(
        config=config,
        workspace_root=root,
        database_path=database_path,
        command=command,
    )


__all__ = [
    "M5HumanAppealError",
    "M5HumanAppealFailureCode",
    "begin_human_appeal_review",
    "resolve_human_appeal",
    "submit_human_appeal",
]
