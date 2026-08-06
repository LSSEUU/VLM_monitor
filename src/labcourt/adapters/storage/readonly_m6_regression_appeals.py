"""Resolve complete M6 appeal histories from one frozen SQLite snapshot."""

from __future__ import annotations

import sqlite3
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import AppealStatus, CaseStatus
from labcourt.contracts.m5_appeals import (
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    M5AppealResolutionCommitReceipt,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionSourceInventoryCutAuthority,
    M6RegressionSourceInventoryItem,
    M6RegressionSourceRunCut,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_regression_appeals import (
    M6RegressionAppealHistoryObservation,
    M6RegressionAppealState,
)

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity
from .readonly_m5_artifacts import (
    M5ArtifactAuthoritySnapshot,
    M5CaseAuthorityRoot,
    M5ValidatedDocument,
    ReadonlyM5ArtifactRepository,
)
from .readonly_sqlite import ReadOnlySnapshotError

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6RegressionAppealReadErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_CHANGED = "SNAPSHOT_CHANGED"
    DATABASE_INVALID = "DATABASE_INVALID"
    SOURCE_CUT_INVALID = "SOURCE_CUT_INVALID"
    M5_AUTHORITY_INVALID = "M5_AUTHORITY_INVALID"
    CASE_ROOT_MISSING = "CASE_ROOT_MISSING"
    CASE_STATE_INVALID = "CASE_STATE_INVALID"
    APPEAL_HISTORY_INVALID = "APPEAL_HISTORY_INVALID"
    TERMINAL_CHAIN_INVALID = "TERMINAL_CHAIN_INVALID"


class M6RegressionAppealReadError(LabCourtError):
    """The current appeal graph could not be proven from the source cut."""

    def __init__(self, code: M6RegressionAppealReadErrorCode) -> None:
        if not isinstance(code, M6RegressionAppealReadErrorCode):
            raise TypeError("code must be an M6RegressionAppealReadErrorCode")
        self.code = code
        super().__init__(f"M6 regression appeal read failed: {code.value}")


def _fail(code: M6RegressionAppealReadErrorCode) -> NoReturn:
    raise M6RegressionAppealReadError(code)


def _canonical_cut(value: object) -> M6RegressionSourceInventoryCutAuthority:
    if not isinstance(value, M6RegressionSourceInventoryCutAuthority):
        _fail(M6RegressionAppealReadErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6RegressionSourceInventoryCutAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6RegressionAppealReadErrorCode.SOURCE_CUT_INVALID)
    if controlled != value:
        _fail(M6RegressionAppealReadErrorCode.SOURCE_CUT_INVALID)
    return controlled


def _parsed_documents(
    snapshot: M5ArtifactAuthoritySnapshot,
    kind: M5AuthorityKind,
    expected: type[_ModelT],
) -> tuple[tuple[M5ValidatedDocument, _ModelT], ...]:
    parsed: list[tuple[M5ValidatedDocument, _ModelT]] = []
    for document in snapshot.documents:
        if document.kind != kind:
            continue
        try:
            value = expected.model_validate_json(document.canonical_document)
        except (TypeError, ValueError, ValidationError):
            _fail(M6RegressionAppealReadErrorCode.M5_AUTHORITY_INVALID)
        if canonical_json(value.model_dump(mode="json")) != document.canonical_document:
            _fail(M6RegressionAppealReadErrorCode.M5_AUTHORITY_INVALID)
        parsed.append((document, value))
    return tuple(parsed)


def _require_snapshot_matches_run_cut(
    snapshot: M5ArtifactAuthoritySnapshot,
    run_cut: M6RegressionSourceRunCut,
) -> None:
    if (
        snapshot.failures
        or snapshot.dataset_retention_failures
        or snapshot.orphan_retention_hold_count
        or snapshot.run_id != run_cut.source_run_id
        or snapshot.manifest_id != run_cut.baseline_manifest_id
        or snapshot.config_sha256 != run_cut.source_config_sha256
        or snapshot.authority_root_sha256 != run_cut.m5_authority_root_sha256
    ):
        _fail(M6RegressionAppealReadErrorCode.M5_AUTHORITY_INVALID)


def _require_audit_head(
    snapshot_path: Path,
    run_cut: M6RegressionSourceRunCut,
) -> None:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"{snapshot_path.as_uri()}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        row = connection.execute(
            """
            SELECT manifest_id, audit_head_sequence, audit_head_hash
            FROM runs WHERE run_id = ?
            """,
            (run_cut.source_run_id,),
        ).fetchone()
        if (
            row is None
            or row["manifest_id"] != run_cut.baseline_manifest_id
            or row["audit_head_sequence"] != run_cut.audit_head_sequence
            or row["audit_head_hash"] != run_cut.audit_head_hash
        ):
            _fail(M6RegressionAppealReadErrorCode.SOURCE_CUT_INVALID)
        connection.commit()
    except M6RegressionAppealReadError:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        raise
    except sqlite3.Error:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        _fail(M6RegressionAppealReadErrorCode.DATABASE_INVALID)
    finally:
        if connection is not None:
            connection.close()


def _case_root(
    snapshot: M5ArtifactAuthoritySnapshot,
    item: M6RegressionSourceInventoryItem,
) -> M5CaseAuthorityRoot:
    matches = tuple(root for root in snapshot.case_roots if root.case_id == item.source_case_id)
    if len(matches) != 1:
        _fail(M6RegressionAppealReadErrorCode.CASE_ROOT_MISSING)
    return matches[0]


def _require_exact_appeal_versions(
    values: tuple[tuple[M5ValidatedDocument, AppealVersionAuthority], ...],
    current: AppealVersionAuthority,
    item: M6RegressionSourceInventoryItem,
) -> None:
    appeal_id = current.appeal.appeal_id
    versions = tuple(
        sorted(
            (value for _, value in values if value.appeal.appeal_id == appeal_id),
            key=lambda value: value.version,
        )
    )
    if tuple(value.version for value in versions) != tuple(range(1, current.version + 1)):
        _fail(M6RegressionAppealReadErrorCode.APPEAL_HISTORY_INVALID)
    if any(
        value.run_id != item.source_run_id
        or value.appeal.case_id != item.source_case_id
        or value.source_case_revision != item.source_case_revision
        or value.manifest_id != item.source_manifest_id
        or value.source_case_authority != current.source_case_authority
        for value in versions
    ):
        _fail(M6RegressionAppealReadErrorCode.APPEAL_HISTORY_INVALID)
    previous: str | None = None
    for value in versions:
        if value.previous_authority_sha256 != previous:
            _fail(M6RegressionAppealReadErrorCode.APPEAL_HISTORY_INVALID)
        previous = value.authority_sha256
    if versions[-1] != current:
        _fail(M6RegressionAppealReadErrorCode.APPEAL_HISTORY_INVALID)


def _current_appeal(
    values: tuple[tuple[M5ValidatedDocument, AppealVersionAuthority], ...],
    root: M5CaseAuthorityRoot,
    item: M6RegressionSourceInventoryItem,
) -> tuple[M5ValidatedDocument, AppealVersionAuthority]:
    matches = tuple(
        pair
        for pair in values
        if pair[1].appeal.case_id == item.source_case_id
        and pair[1].authority_sha256 == root.current_appeal_authority_sha256
    )
    if len(matches) != 1:
        _fail(M6RegressionAppealReadErrorCode.APPEAL_HISTORY_INVALID)
    document, current = matches[0]
    expected_artifact_id = f"{current.appeal.appeal_id}-version-{current.version:06d}"
    if document.artifact_id != expected_artifact_id:
        _fail(M6RegressionAppealReadErrorCode.APPEAL_HISTORY_INVALID)
    _require_exact_appeal_versions(values, current, item)
    case_appeals = tuple(
        value for _, value in values if value.appeal.case_id == item.source_case_id
    )
    if any(value.appeal.appeal_id != current.appeal.appeal_id for value in case_appeals):
        _fail(M6RegressionAppealReadErrorCode.APPEAL_HISTORY_INVALID)
    return document, current


def _no_appeal_observation(
    *,
    identity_sha256: str,
    cut: M6RegressionSourceInventoryCutAuthority,
    run_cut: M6RegressionSourceRunCut,
    item: M6RegressionSourceInventoryItem,
    root: M5CaseAuthorityRoot,
    appeals: tuple[tuple[M5ValidatedDocument, AppealVersionAuthority], ...],
) -> M6RegressionAppealHistoryObservation:
    if (
        root.current_case_status != CaseStatus.CLOSED.value
        or root.current_case_revision != item.source_case_revision
        or root.current_case_sha256 != item.source_case_document_sha256
        or root.current_appeal_authority_sha256 is not None
        or root.resolution_intent_id is not None
        or any(value.appeal.case_id == item.source_case_id for _, value in appeals)
    ):
        _fail(M6RegressionAppealReadErrorCode.CASE_STATE_INVALID)
    return M6RegressionAppealHistoryObservation(
        source_identity_sha256=identity_sha256,
        source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
        source_item=item,
        run_cut=run_cut,
        m5_authority_root_sha256=run_cut.m5_authority_root_sha256,
        current_case_revision=root.current_case_revision,
        current_case_document_sha256=root.current_case_sha256,
        current_case_status=CaseStatus.CLOSED,
        current_case_root_sha256=root.root_sha256,
        state=M6RegressionAppealState.NONE,
    )


def _pending_observation(
    *,
    identity_sha256: str,
    cut: M6RegressionSourceInventoryCutAuthority,
    run_cut: M6RegressionSourceRunCut,
    item: M6RegressionSourceInventoryItem,
    root: M5CaseAuthorityRoot,
    appeals: tuple[tuple[M5ValidatedDocument, AppealVersionAuthority], ...],
    intents: tuple[tuple[M5ValidatedDocument, AppealResolutionSideEffectIntent], ...],
    commits: tuple[tuple[M5ValidatedDocument, M5AppealResolutionCommitReceipt], ...],
) -> M6RegressionAppealHistoryObservation:
    document, current = _current_appeal(appeals, root, item)
    if (
        root.current_case_status != CaseStatus.APPEALED.value
        or root.resolution_intent_id is not None
        or current.version not in {1, 2}
        or current.appeal.status not in {AppealStatus.SUBMITTED, AppealStatus.UNDER_REVIEW}
        or any(value.case_id == item.source_case_id for _, value in intents)
        or any(value.case_id == item.source_case_id for _, value in commits)
    ):
        _fail(M6RegressionAppealReadErrorCode.CASE_STATE_INVALID)
    return M6RegressionAppealHistoryObservation(
        source_identity_sha256=identity_sha256,
        source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
        source_item=item,
        run_cut=run_cut,
        m5_authority_root_sha256=run_cut.m5_authority_root_sha256,
        current_case_revision=root.current_case_revision,
        current_case_document_sha256=root.current_case_sha256,
        current_case_status=CaseStatus.APPEALED,
        current_case_root_sha256=root.root_sha256,
        state=M6RegressionAppealState.PENDING,
        current_appeal_authority=current,
        current_appeal_document=document.canonical_document,
    )


def _terminal_observation(
    *,
    identity_sha256: str,
    cut: M6RegressionSourceInventoryCutAuthority,
    run_cut: M6RegressionSourceRunCut,
    item: M6RegressionSourceInventoryItem,
    root: M5CaseAuthorityRoot,
    appeals: tuple[tuple[M5ValidatedDocument, AppealVersionAuthority], ...],
    intents: tuple[tuple[M5ValidatedDocument, AppealResolutionSideEffectIntent], ...],
    commits: tuple[tuple[M5ValidatedDocument, M5AppealResolutionCommitReceipt], ...],
) -> M6RegressionAppealHistoryObservation:
    appeal_document, current = _current_appeal(appeals, root, item)
    intent_matches = tuple(
        pair
        for pair in intents
        if pair[0].artifact_id == root.resolution_intent_id
        and pair[1].intent_id == root.resolution_intent_id
        and pair[1].case_id == item.source_case_id
    )
    if len(intent_matches) != 1:
        _fail(M6RegressionAppealReadErrorCode.TERMINAL_CHAIN_INVALID)
    intent_document, intent = intent_matches[0]
    commit_matches = tuple(
        pair
        for pair in commits
        if pair[1].resolution_intent_id == intent.intent_id
        and pair[1].case_id == item.source_case_id
    )
    if len(commit_matches) != 1:
        _fail(M6RegressionAppealReadErrorCode.TERMINAL_CHAIN_INVALID)
    commit_document, commit = commit_matches[0]
    if (
        root.current_case_status != CaseStatus.APPEAL_RESOLVED.value
        or current.version != 3
        or current.appeal.status not in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
        or intent.appeal_authority != current
        or commit_document.artifact_id != commit.receipt_id
        or commit.resulting_case_revision != root.current_case_revision
        or commit.resulting_case_document_sha256 != root.current_case_sha256
        or len(tuple(value for _, value in intents if value.case_id == item.source_case_id)) != 1
        or len(tuple(value for _, value in commits if value.case_id == item.source_case_id)) != 1
    ):
        _fail(M6RegressionAppealReadErrorCode.TERMINAL_CHAIN_INVALID)
    return M6RegressionAppealHistoryObservation(
        source_identity_sha256=identity_sha256,
        source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
        source_item=item,
        run_cut=run_cut,
        m5_authority_root_sha256=run_cut.m5_authority_root_sha256,
        current_case_revision=root.current_case_revision,
        current_case_document_sha256=root.current_case_sha256,
        current_case_status=CaseStatus.APPEAL_RESOLVED,
        current_case_root_sha256=root.root_sha256,
        state=M6RegressionAppealState.TERMINAL,
        current_appeal_authority=current,
        current_appeal_document=appeal_document.canonical_document,
        resolution_intent=intent,
        resolution_intent_document=intent_document.canonical_document,
        resolution_commit=commit,
        resolution_commit_document=commit_document.canonical_document,
    )


class ReadonlyM6RegressionAppealRepository:
    """Classify every source item from exact M5 Case and appeal heads."""

    __slots__ = ("_config", "_snapshot")

    def __init__(self, snapshot: str | Path, *, config: AppConfig) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be a fully resolved AppConfig")
        self._snapshot = Path(snapshot).absolute()
        self._config = AppConfig.model_validate(config.model_dump(mode="json"))

    def observe(
        self,
        source_inventory_cut: object,
    ) -> tuple[M6RegressionAppealHistoryObservation, ...]:
        cut = _canonical_cut(source_inventory_cut)
        try:
            before = capture_m6_readonly_snapshot_identity(self._snapshot)
            observations: list[M6RegressionAppealHistoryObservation] = []
            for run_cut in cut.run_cuts:
                snapshot = ReadonlyM5ArtifactRepository(
                    self._snapshot,
                    config=self._config,
                    immutable=True,
                ).scan(run_cut.source_run_id)
                _require_snapshot_matches_run_cut(snapshot, run_cut)
                _require_audit_head(self._snapshot, run_cut)
                appeals = _parsed_documents(
                    snapshot,
                    M5AuthorityKind.APPEAL,
                    AppealVersionAuthority,
                )
                intents = _parsed_documents(
                    snapshot,
                    M5AuthorityKind.APPEAL_RESOLUTION,
                    AppealResolutionSideEffectIntent,
                )
                commits = _parsed_documents(
                    snapshot,
                    M5AuthorityKind.APPEAL_RESOLUTION_COMMIT,
                    M5AppealResolutionCommitReceipt,
                )
                for item in cut.items:
                    if item.source_run_id != run_cut.source_run_id:
                        continue
                    root = _case_root(snapshot, item)
                    if root.current_case_status == CaseStatus.CLOSED.value:
                        observation = _no_appeal_observation(
                            identity_sha256=before.identity_sha256,
                            cut=cut,
                            run_cut=run_cut,
                            item=item,
                            root=root,
                            appeals=appeals,
                        )
                    elif root.current_case_status == CaseStatus.APPEALED.value:
                        observation = _pending_observation(
                            identity_sha256=before.identity_sha256,
                            cut=cut,
                            run_cut=run_cut,
                            item=item,
                            root=root,
                            appeals=appeals,
                            intents=intents,
                            commits=commits,
                        )
                    elif root.current_case_status == CaseStatus.APPEAL_RESOLVED.value:
                        observation = _terminal_observation(
                            identity_sha256=before.identity_sha256,
                            cut=cut,
                            run_cut=run_cut,
                            item=item,
                            root=root,
                            appeals=appeals,
                            intents=intents,
                            commits=commits,
                        )
                    else:
                        _fail(M6RegressionAppealReadErrorCode.CASE_STATE_INVALID)
                    observations.append(observation)
            after = capture_m6_readonly_snapshot_identity(self._snapshot)
        except M6RegressionAppealReadError:
            raise
        except ReadOnlySnapshotError as exc:
            raise M6RegressionAppealReadError(
                M6RegressionAppealReadErrorCode.DATABASE_INVALID
            ) from exc
        except (OSError, sqlite3.Error, TypeError, ValueError, ValidationError) as exc:
            raise M6RegressionAppealReadError(
                M6RegressionAppealReadErrorCode.DATABASE_INVALID
            ) from exc
        if after != before:
            _fail(M6RegressionAppealReadErrorCode.SNAPSHOT_CHANGED)
        result = tuple(sorted(observations, key=lambda item: item.source_item.sample_id))
        if tuple(item.source_item.sample_id for item in result) != tuple(
            item.sample_id for item in cut.items
        ):
            _fail(M6RegressionAppealReadErrorCode.SOURCE_CUT_INVALID)
        return result


__all__ = [
    "M6RegressionAppealReadError",
    "M6RegressionAppealReadErrorCode",
    "ReadonlyM6RegressionAppealRepository",
]
