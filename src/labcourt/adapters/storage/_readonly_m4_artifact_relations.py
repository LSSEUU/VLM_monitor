"""Bidirectional graph validation for canonical M4 SQLite records."""

from __future__ import annotations

import hashlib
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, cast

from pydantic import BaseModel, ValidationError

from labcourt.contracts.audit import AuditEntry, verify_audit_chain
from labcourt.contracts.backlog import BacklogItem
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    BacklogStatus,
    CaseStatus,
    VlmRole,
)
from labcourt.contracts.evidence import Crop, EvidencePack, OtherCameraSameTimeParameters
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing import (
    AcquisitionExecutionClaimAuthority,
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    EvidencePackDerivation,
    HearingBacklogCompletionReceipt,
    HearingBacklogRetryFailure,
    HearingBacklogRetrySuccess,
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingCycleScope,
    HearingHumanReviewReceipt,
    HearingInitialStrictParseFailureProof,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingRecord,
    HearingReworkReceipt,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingStrictParseFailureAttempt,
    HearingStrictParseFailureProof,
    HearingUsageReceipt,
    HearingVerdictBinding,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ToolExecutionManifest,
    ToolExecutionReceipt,
    validate_hearing_cycle_scope_binding,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.screening import ScreeningResult
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.evidence_authority import (
    EvidencePackSuccessorError,
    validate_evidence_pack_successor,
)

from ._readonly_m4_artifact_codec import M4Record
from .readonly_m4_artifacts import (
    M4ArtifactAuthorityFailure,
    M4AuthorityFailureType,
    M4HearingAuthorityRoot,
    M4ValidatedDocument,
)


@dataclass(frozen=True, slots=True)
class M4RelationValidation:
    documents: tuple[M4ValidatedDocument, ...]
    hearing_roots: tuple[M4HearingAuthorityRoot, ...]
    failures: tuple[M4ArtifactAuthorityFailure, ...]


@dataclass(frozen=True, slots=True)
class _BaseRecord:
    kind: M4ProjectionArtifactKind
    artifact_id: str
    document: BaseModel
    canonical_document: str
    row: sqlite3.Row

    def projected(self) -> M4ValidatedDocument:
        return M4ValidatedDocument(self.kind, self.artifact_id, self.canonical_document)


class M4ArtifactReferenceValidator:
    """Reconstruct every reachable root and reject missing reverse references."""

    def validate(
        self,
        *,
        connection: sqlite3.Connection,
        run_id: str,
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
    ) -> M4RelationValidation:
        failures: list[M4ArtifactAuthorityFailure] = []
        sessions = _typed_map(records, M4ProjectionArtifactKind.HEARING_SESSION, HearingSession)
        case_ids = {item.case_id for item in sessions.values()}
        base = self._load_base_authority(connection, run_id, case_ids, failures)

        self._validate_current_case_heads(connection, run_id, case_ids, base, failures)
        self._validate_session_roots(records, sessions, base, failures)
        self._validate_session_scope(records, sessions, failures)
        cycles = _typed_map(records, M4ProjectionArtifactKind.HEARING_CYCLE, HearingCycleScope)
        self._validate_cycles(records, sessions, cycles, base, failures)
        checkpoints = _typed_map(
            records,
            M4ProjectionArtifactKind.HEARING_CHECKPOINT,
            HearingCheckpoint,
        )
        self._validate_checkpoints(sessions, cycles, checkpoints, base, failures)
        self._validate_checkpoint_closure(records, checkpoints, base, failures)
        self._validate_model_calls(records, sessions, cycles, failures)
        self._validate_rounds_and_acquisition(
            records,
            cycles,
            checkpoints,
            base,
            failures,
        )
        hearing_records = self._rebuild_hearing_records(records, sessions, failures)
        self._validate_verdicts_and_reviews(
            records,
            checkpoints,
            hearing_records,
            base,
            failures,
        )
        self._validate_reworks(records, cycles, checkpoints, base, failures)
        self._validate_backlog_history(connection, records, base, failures)
        self._validate_backlog_retry_graph(records, checkpoints, base, failures)
        self._validate_human_review(records, checkpoints, base, failures)
        self._validate_backlog_completion(records, checkpoints, base, failures)
        self._validate_foreign_camera_boundary(records, base, failures)
        self._validate_unique_active_hearings(sessions, checkpoints, failures)

        roots = self._build_roots(
            records,
            sessions,
            checkpoints,
            hearing_records,
            base,
            failures,
        )
        documents = tuple(
            sorted(
                (
                    *(item.projected() for values in base.values() for item in values.values()),
                    *(
                        M4ValidatedDocument(
                            M4ProjectionArtifactKind.HEARING_RECORD,
                            record.record_id,
                            canonical_json(record.model_dump(mode="json")),
                        )
                        for record in hearing_records.values()
                    ),
                ),
                key=lambda item: item.sort_key,
            )
        )
        return M4RelationValidation(
            documents=documents,
            hearing_roots=roots,
            failures=tuple(failures),
        )

    def _load_base_authority(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        case_ids: set[str],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]]:
        result: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]] = defaultdict(dict)
        if not case_ids:
            return result
        placeholders = ", ".join("?" for _ in case_ids)
        parameters = (run_id, *sorted(case_ids))
        specifications: tuple[
            tuple[str, M4ProjectionArtifactKind, str, str, str, type[BaseModel], str], ...
        ] = (
            (
                "case_versions",
                M4ProjectionArtifactKind.CASE_VERSION,
                "case_id || '-revision-' || printf('%06d', revision)",
                "case_json",
                "document_sha256",
                Case,
                "case_id IN ({})",
            ),
            (
                "evidence_packs",
                M4ProjectionArtifactKind.EVIDENCE_PACK,
                "pack_id",
                "pack_json",
                "document_sha256",
                EvidencePack,
                "case_id IN ({})",
            ),
            (
                "screening_results",
                M4ProjectionArtifactKind.SCREENING_RESULT,
                "screening_id",
                "result_json",
                "document_sha256",
                ScreeningResult,
                "case_id IN ({})",
            ),
            (
                "verdicts",
                M4ProjectionArtifactKind.VERDICT,
                "verdict_id",
                "verdict_json",
                "document_sha256",
                Verdict,
                "case_id IN ({})",
            ),
            (
                "procedural_reviews",
                M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
                "review_id",
                "review_json",
                "document_sha256",
                ProceduralReview,
                "case_id IN ({})",
            ),
        )
        for table, kind, identity_sql, json_column, hash_column, model, where in specifications:
            sql = (
                f'SELECT *, {identity_sql} AS projection_identity FROM "{table}" '
                f"WHERE run_id = ? AND {where.format(placeholders)} "
                "ORDER BY projection_identity"
            )
            for row in connection.execute(sql, parameters).fetchall():
                loaded = _load_base_row(row, kind, json_column, hash_column, model, failures)
                if loaded is not None:
                    result[kind][loaded.artifact_id] = loaded

        backlog_rows = connection.execute(
            "SELECT version.*, "
            "version.item_id || '-version-' || printf('%06d', version.version) "
            "AS projection_identity "
            "FROM backlog_item_versions AS version "
            "JOIN backlog_items AS initial "
            "ON initial.run_id = version.run_id AND initial.item_id = version.item_id "
            f"WHERE version.run_id = ? AND initial.case_id IN ({placeholders}) "
            "ORDER BY projection_identity",
            parameters,
        ).fetchall()
        for row in backlog_rows:
            loaded = _load_base_row(
                row,
                M4ProjectionArtifactKind.BACKLOG_ITEM_VERSION,
                "item_json",
                "document_sha256",
                BacklogItem,
                failures,
            )
            if loaded is not None:
                result[M4ProjectionArtifactKind.BACKLOG_ITEM_VERSION][loaded.artifact_id] = loaded

        backlog_items = connection.execute(
            "SELECT *, item_id AS projection_identity FROM backlog_items "
            f"WHERE run_id = ? AND case_id IN ({placeholders}) ORDER BY item_id",
            parameters,
        ).fetchall()
        for row in backlog_items:
            loaded = _load_base_row(
                row,
                M4ProjectionArtifactKind.BACKLOG_ITEM,
                "initial_json",
                "initial_document_sha256",
                BacklogItem,
                failures,
            )
            if loaded is not None:
                result[M4ProjectionArtifactKind.BACKLOG_ITEM][loaded.artifact_id] = loaded

        # Only frames and detections that participate in the case packs are part
        # of this projection closure.  Their IDs are derived after packs parse.
        packs = result[M4ProjectionArtifactKind.EVIDENCE_PACK]
        frame_ids: set[str] = set()
        detection_ids: set[str] = set()
        for item in packs.values():
            pack = cast(EvidencePack, item.document)
            frame_ids.update(pack.key_frame_ids)
            for crop in pack.crops:
                frame_ids.add(crop.frame_id)
                detection_ids.update(
                    ref.artifact_id
                    for ref in crop.source_refs
                    if ref.kind == ArtifactKind.DETECTION
                )
            for tool in pack.tool_results:
                frame_ids.update(
                    ref.artifact_id for ref in tool.output_refs if ref.kind == ArtifactKind.FRAME
                )
                detection_ids.update(
                    ref.artifact_id
                    for ref in tool.output_refs
                    if ref.kind == ArtifactKind.DETECTION
                )
        self._load_id_set(
            connection,
            run_id,
            "frames",
            "frame_id",
            "document_json",
            FrameRef,
            M4ProjectionArtifactKind.FRAME,
            frame_ids,
            result,
            failures,
        )
        self._load_id_set(
            connection,
            run_id,
            "detections",
            "detection_id",
            "document_json",
            Detection,
            M4ProjectionArtifactKind.DETECTION,
            detection_ids,
            result,
            failures,
        )

        rows = connection.execute(
            "SELECT *, printf('%012d', sequence) AS projection_identity "
            "FROM audit_entries WHERE run_id = ? ORDER BY sequence",
            (run_id,),
        ).fetchall()
        for row in rows:
            loaded = _load_base_row(
                row,
                M4ProjectionArtifactKind.AUDIT_ENTRY,
                "entry_json",
                "document_sha256",
                AuditEntry,
                failures,
            )
            if loaded is not None:
                result[M4ProjectionArtifactKind.AUDIT_ENTRY][loaded.artifact_id] = loaded
        run = connection.execute(
            "SELECT manifest_id, audit_head_sequence, audit_head_hash FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        audits = tuple(
            item.document
            for item in result[M4ProjectionArtifactKind.AUDIT_ENTRY].values()
            if isinstance(item.document, AuditEntry)
        )
        if run is None:
            _base_failure(
                failures,
                M4ProjectionArtifactKind.AUDIT_ENTRY,
                run_id,
                "RUN_AUTHORITY_MISSING",
            )
        elif len(audits) == len(rows):
            report = verify_audit_chain(
                audits,
                expected_run_id=run_id,
                expected_manifest_id=str(run["manifest_id"]),
                expected_head_sequence=int(run["audit_head_sequence"]),
                expected_head_hash=str(run["audit_head_hash"]),
            )
            if not report.passed:
                _base_failure(
                    failures,
                    M4ProjectionArtifactKind.AUDIT_ENTRY,
                    run_id,
                    "AUDIT_CHAIN_INVALID",
                )
        return result

    @staticmethod
    def _load_id_set(
        connection: sqlite3.Connection,
        run_id: str,
        table: str,
        id_column: str,
        json_column: str,
        model: type[BaseModel],
        kind: M4ProjectionArtifactKind,
        identities: set[str],
        result: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        if not identities:
            return
        placeholders = ", ".join("?" for _ in identities)
        rows = connection.execute(
            f'SELECT *, "{id_column}" AS projection_identity FROM "{table}" '
            f'WHERE run_id = ? AND "{id_column}" IN ({placeholders}) ORDER BY "{id_column}"',
            (run_id, *sorted(identities)),
        ).fetchall()
        for row in rows:
            loaded = _load_base_row(
                row,
                kind,
                json_column,
                "document_sha256",
                model,
                failures,
            )
            if loaded is not None:
                result[kind][loaded.artifact_id] = loaded
        observed = set(result[kind])
        for missing in sorted(identities - observed):
            _base_failure(failures, kind, missing, "BASE_REFERENCE_MISSING")

    @staticmethod
    def _validate_current_case_heads(
        connection: sqlite3.Connection,
        run_id: str,
        case_ids: set[str],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        if not case_ids:
            return
        versions = _case_versions(base)
        audits = _base_documents(base, M4ProjectionArtifactKind.AUDIT_ENTRY, AuditEntry)
        audit_by_sequence = {item.sequence: item for item in audits.values()}
        placeholders = ", ".join("?" for _ in case_ids)
        rows = connection.execute(
            "SELECT * FROM cases WHERE run_id = ? "
            f"AND case_id IN ({placeholders}) ORDER BY case_id",
            (run_id, *sorted(case_ids)),
        ).fetchall()
        observed_case_ids: set[str] = set()
        for row in rows:
            case_id = row["case_id"]
            if not isinstance(case_id, str):
                continue
            observed_case_ids.add(case_id)
            candidates = sorted(
                (
                    (revision, case)
                    for (candidate_id, revision), case in versions.items()
                    if candidate_id == case_id
                ),
                key=lambda item: item[0],
            )
            if not candidates or tuple(item[0] for item in candidates) != tuple(
                range(1, len(candidates) + 1)
            ):
                _base_failure(
                    failures,
                    M4ProjectionArtifactKind.CASE_VERSION,
                    case_id,
                    "CASE_VERSION_SEQUENCE_INCOMPLETE",
                )
                continue
            prior: Case | None = None
            prior_document_sha256: str | None = None
            for revision, case in candidates:
                record = base[M4ProjectionArtifactKind.CASE_VERSION][
                    f"{case_id}-revision-{revision:06d}"
                ]
                audit_sequence = record.row["audit_sequence"]
                audit = (
                    audit_by_sequence.get(audit_sequence)
                    if isinstance(audit_sequence, int) and not isinstance(audit_sequence, bool)
                    else None
                )
                prefix_invalid = prior is not None and any(
                    previous != current[: len(previous)]
                    for previous, current in (
                        (prior.evidence_packs, case.evidence_packs),
                        (prior.screening_results, case.screening_results),
                        (prior.verdicts, case.verdicts),
                        (prior.procedural_reviews, case.procedural_reviews),
                        (prior.timeline, case.timeline),
                    )
                )
                if (
                    audit is None
                    or audit.after_sha256 != record.row["document_sha256"]
                    or audit.before_sha256 != prior_document_sha256
                    or audit.manifest_id != case.manifest_id
                    or case.case_id != case_id
                    or case.run_id != run_id
                    or prefix_invalid
                ):
                    _base_failure(
                        failures,
                        M4ProjectionArtifactKind.CASE_VERSION,
                        f"{case_id}-revision-{revision:06d}",
                        "CASE_VERSION_AUDIT_OR_PREFIX_MISMATCH",
                    )
                prior = case
                prior_document_sha256 = cast(str, record.row["document_sha256"])
            current_revision, current = candidates[-1]
            event_raw = row["event_json"]
            event_sha256 = row["event_sha256"]
            latest_pack = current.evidence_packs[-1] if current.evidence_packs else None
            if (
                row["current_revision"] != current_revision
                or row["status"] != current.status.value
                or row["manifest_id"] != current.manifest_id
                or not isinstance(event_raw, str)
                or event_raw != canonical_json(current.event.model_dump(mode="json"))
                or not isinstance(event_sha256, str)
                or hashlib.sha256(event_raw.encode("utf-8")).hexdigest() != event_sha256
                or row["latest_pack_id"]
                != (latest_pack.pack_id if latest_pack is not None else None)
                or row["latest_pack_version"]
                != (latest_pack.version if latest_pack is not None else None)
            ):
                _base_failure(
                    failures,
                    M4ProjectionArtifactKind.CASE_VERSION,
                    case_id,
                    "CURRENT_CASE_HEAD_MISMATCH",
                )
        for case_id in sorted(case_ids - observed_case_ids):
            _base_failure(
                failures,
                M4ProjectionArtifactKind.CASE_VERSION,
                case_id,
                "CURRENT_CASE_HEAD_MISSING",
            )

    @staticmethod
    def _validate_session_roots(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        sessions: dict[str, HearingSession],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        packs = _base_documents(base, M4ProjectionArtifactKind.EVIDENCE_PACK, EvidencePack)
        screenings = _base_documents(
            base,
            M4ProjectionArtifactKind.SCREENING_RESULT,
            ScreeningResult,
        )
        reviews = _base_documents(
            base,
            M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
            ProceduralReview,
        )
        cases = _case_versions(base)
        audits = _base_documents(base, M4ProjectionArtifactKind.AUDIT_ENTRY, AuditEntry)
        audit_by_sequence = {item.sequence: item for item in audits.values()}
        session_records = {
            item.artifact_id: item for item in records[M4ProjectionArtifactKind.HEARING_SESSION]
        }
        for session_id, session in sessions.items():
            session_record = session_records[session_id]
            current_entry = _current_case(cases, session.case_id)
            current = current_entry[1] if current_entry is not None else None
            pack = packs.get(session.initial_evidence_pack_id)
            screening = screenings.get(session.screening_id)
            screening_record = base[M4ProjectionArtifactKind.SCREENING_RESULT].get(
                session.screening_id
            )
            trigger_review = (
                reviews.get(session.initial_trigger_review_ref.artifact_id)
                if session.initial_trigger_review_ref is not None
                else None
            )
            trigger_invalid = session.initial_trigger_review_ref is not None and (
                trigger_review is None
                or trigger_review.passed
                or trigger_review.case_id != session.case_id
                or trigger_review.evidence_pack_id != session.initial_evidence_pack_id
                or trigger_review.evidence_pack_version != session.initial_evidence_pack_version
                or tuple(defect.code for defect in trigger_review.defects)
                != session.initial_defect_codes
            )
            if (
                current is None
                or pack is None
                or screening is None
                or pack.case_id != session.case_id
                or pack.version != session.initial_evidence_pack_version
                or screening.case_id != session.case_id
                or screening.evidence_pack_id != pack.pack_id
                or screening.evidence_pack_version != pack.version
                or session.manifest_id != pack.manifest_id
                or current.manifest_id != session.manifest_id
                or trigger_invalid
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_SESSION,
                    session_id,
                    "SESSION_ENTRY_CLOSURE_MISMATCH",
                )

            created_audit_sequence = session_record.row["created_audit_sequence"]
            screening_audit_sequence = (
                screening_record.row["audit_sequence"] if screening_record is not None else None
            )
            screening_audit = (
                audit_by_sequence.get(created_audit_sequence)
                if isinstance(created_audit_sequence, int)
                and not isinstance(created_audit_sequence, bool)
                else None
            )
            if (
                screening_record is None
                or created_audit_sequence != screening_audit_sequence
                or screening_audit is None
                or screening_audit.action != AuditAction.CASE_STATE_CHANGED
                or screening_audit.actor != AuditActorRole.SYSTEM.value
                or screening_audit.object_ref.kind != ArtifactKind.SCREENING_RESULT
                or screening_audit.object_ref.artifact_id != session.screening_id
            ):
                _record_failure(failures, session_record, "SESSION_CREATED_AUDIT_MISMATCH")

            history = sorted(
                (
                    (revision, case)
                    for (candidate_id, revision), case in cases.items()
                    if candidate_id == session.case_id
                ),
                key=lambda item: item[0],
            )
            transition_matches: list[tuple[int, Case, Case]] = []
            invalid_transition_candidate = False
            for (prior_revision, prior), (revision, after) in pairwise(history):
                if (
                    revision != prior_revision + 1
                    or prior.status.value != session.entry_status.value
                    or prior.current_backlog_item_id is not None
                    or after.status != CaseStatus.DELIBERATING
                ):
                    continue
                try:
                    expected = prior.model_copy(
                        update={
                            "status": CaseStatus.DELIBERATING,
                            "current_backlog_item_id": None,
                            "timeline": (
                                *prior.timeline,
                                TimelineEntry(
                                    sequence=len(prior.timeline),
                                    action=AuditAction.CASE_STATE_CHANGED.value,
                                    stage="HEARING",
                                    object_ref=session.session_id,
                                    details={"status": CaseStatus.DELIBERATING.value},
                                ),
                            ),
                        }
                    )
                except (ValidationError, TypeError, ValueError):
                    invalid_transition_candidate = True
                    continue
                if revision == prior_revision + 1 and after == expected:
                    transition_matches.append((revision, prior, after))
            if len(transition_matches) != 1:
                _record_failure(
                    failures,
                    session_record,
                    (
                        "SESSION_CASE_TRANSITION_INVALID"
                        if invalid_transition_candidate
                        else "SESSION_CASE_TRANSITION_MISSING"
                    ),
                )
                continue
            revision, entry_case, _ = transition_matches[0]
            transition_record = base[M4ProjectionArtifactKind.CASE_VERSION].get(
                f"{session.case_id}-revision-{revision:06d}"
            )
            transition_audit_sequence = (
                transition_record.row["audit_sequence"] if transition_record is not None else None
            )
            transition_audit = (
                audit_by_sequence.get(transition_audit_sequence)
                if isinstance(transition_audit_sequence, int)
                and not isinstance(transition_audit_sequence, bool)
                else None
            )
            latest_pack = entry_case.evidence_packs[-1] if entry_case.evidence_packs else None
            latest_screening = (
                entry_case.screening_results[-1] if entry_case.screening_results else None
            )
            latest_review = (
                entry_case.procedural_reviews[-1] if entry_case.procedural_reviews else None
            )
            trigger_invalid_at_entry = session.initial_trigger_review_ref is not None and (
                latest_review is None
                or latest_review.review_id != session.initial_trigger_review_ref.artifact_id
                or latest_review.passed
                or tuple(defect.code for defect in latest_review.defects)
                != session.initial_defect_codes
            )
            if (
                transition_record is None
                or transition_audit is None
                or transition_audit.action != AuditAction.CASE_STATE_CHANGED
                or transition_audit.actor != AuditActorRole.SYSTEM.value
                or transition_audit.object_ref.kind != ArtifactKind.CASE
                or transition_audit.object_ref.artifact_id != session.case_id
                or entry_case.status.value != session.entry_status.value
                or latest_pack is None
                or latest_pack.pack_id != session.initial_evidence_pack_id
                or latest_pack.version != session.initial_evidence_pack_version
                or latest_screening is None
                or latest_screening.screening_id != session.screening_id
                or trigger_invalid_at_entry
            ):
                _record_failure(failures, session_record, "SESSION_CASE_TRANSITION_MISMATCH")

    @staticmethod
    def _validate_session_scope(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        sessions: dict[str, HearingSession],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        for values in records.values():
            for record in values:
                if record.kind == M4ProjectionArtifactKind.HEARING_SESSION:
                    continue
                row = record.row
                if "hearing_id" not in tuple(row.keys()):
                    continue
                hearing_id = row["hearing_id"]
                case_id = dict(row).get("case_id")
                session = sessions.get(hearing_id) if isinstance(hearing_id, str) else None
                if session is None or (case_id is not None and case_id != session.case_id):
                    _record_failure(failures, record, "SESSION_SCOPE_ORPHAN")

    @staticmethod
    def _validate_cycles(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        sessions: dict[str, HearingSession],
        cycles: dict[str, HearingCycleScope],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        packs = _base_documents(base, M4ProjectionArtifactKind.EVIDENCE_PACK, EvidencePack)
        session_records = {
            item.artifact_id: item for item in records[M4ProjectionArtifactKind.HEARING_SESSION]
        }
        cycle_records = {
            item.artifact_id: item for item in records[M4ProjectionArtifactKind.HEARING_CYCLE]
        }
        by_hearing: dict[str, list[HearingCycleScope]] = defaultdict(list)
        for cycle_id, cycle in cycles.items():
            by_hearing[cycle.hearing_session_id].append(cycle)
            pack = packs.get(cycle.cycle_evidence_pack_id)
            session = sessions.get(cycle.hearing_session_id)
            cycle_record = cycle_records[cycle_id]
            session_record = session_records.get(cycle.hearing_session_id)
            if (
                session is None
                or pack is None
                or pack.case_id != cycle.case_id
                or pack.version != cycle.cycle_evidence_pack_version
                or cycle.manifest_id != session.manifest_id
                or (
                    cycle.cycle_index == 1
                    and (
                        cycle.initial_trigger_review_ref != session.initial_trigger_review_ref
                        or cycle.initial_defect_codes != session.initial_defect_codes
                        or cycle.cycle_evidence_pack_id != session.initial_evidence_pack_id
                        or cycle.cycle_evidence_pack_version
                        != session.initial_evidence_pack_version
                    )
                )
                or session_record is None
                or cycle_record.row["created_audit_sequence"]
                != session_record.row["created_audit_sequence"]
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_CYCLE,
                    cycle_id,
                    "CYCLE_PACK_SCOPE_MISMATCH",
                )
        for session_id in sessions:
            ordered = sorted(by_hearing.get(session_id, []), key=lambda item: item.cycle_index)
            if not ordered or tuple(item.cycle_index for item in ordered) != tuple(
                range(1, len(ordered) + 1)
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_SESSION,
                    session_id,
                    "CYCLE_SEQUENCE_INCOMPLETE",
                )

    @staticmethod
    def _validate_checkpoints(
        sessions: dict[str, HearingSession],
        cycles: dict[str, HearingCycleScope],
        checkpoints: dict[str, HearingCheckpoint],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        cases = _case_versions(base)
        by_hearing: dict[str, list[HearingCheckpoint]] = defaultdict(list)
        for checkpoint_id, checkpoint in checkpoints.items():
            by_hearing[checkpoint.hearing_session_id].append(checkpoint)
            session = sessions.get(checkpoint.hearing_session_id)
            cycle = cycles.get(checkpoint.cycle_scope_id)
            try:
                if session is None or cycle is None:
                    raise ValueError
                validate_hearing_cycle_scope_binding(cycle, checkpoint)
                if checkpoint.hearing_session_sha256 != session.session_sha256:
                    raise ValueError
            except (TypeError, ValueError):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_CHECKPOINT,
                    checkpoint_id,
                    "CHECKPOINT_SCOPE_MISMATCH",
                )
        for session_id, session in sessions.items():
            ordered = sorted(by_hearing.get(session_id, []), key=lambda item: item.version)
            if not ordered or tuple(item.version for item in ordered) != tuple(
                range(1, len(ordered) + 1)
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_SESSION,
                    session_id,
                    "CHECKPOINT_SEQUENCE_INCOMPLETE",
                )
                continue
            for previous, current in pairwise(ordered):
                if (
                    current.previous_checkpoint_id != previous.checkpoint_id
                    or current.previous_checkpoint_sha256 != previous.checkpoint_sha256
                    or current.previous_phase != previous.phase
                ):
                    _reference_failure(
                        failures,
                        M4ProjectionArtifactKind.HEARING_CHECKPOINT,
                        current.checkpoint_id,
                        "CHECKPOINT_PREDECESSOR_MISMATCH",
                    )
            current_entry = _current_case(cases, session.case_id)
            current_case = current_entry[1] if current_entry is not None else None
            head = ordered[-1]
            if current_case is not None and (
                not current_case.evidence_packs
                or current_case.evidence_packs[-1].pack_id != head.current_evidence_pack_id
                or current_case.evidence_packs[-1].version != head.current_evidence_pack_version
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_CHECKPOINT,
                    head.checkpoint_id,
                    "CHECKPOINT_CURRENT_PACK_MISMATCH",
                )

    @staticmethod
    def _validate_model_calls(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        sessions: dict[str, HearingSession],
        cycles: dict[str, HearingCycleScope],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        requests = _typed_map(records, M4ProjectionArtifactKind.MODEL_REQUEST, HearingModelRequest)
        responses = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_RESPONSE,
            HearingModelResponse,
        )
        caches = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_CACHE_ENTRY,
            HearingModelCacheEntry,
        )
        usages = _typed_map(records, M4ProjectionArtifactKind.USAGE_RECEIPT, HearingUsageReceipt)
        parses = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
            HearingModelParseReceipt,
        )
        outputs = _typed_map(records, M4ProjectionArtifactKind.ROLE_OUTPUT, HearingRoleOutput)
        retrievals = _typed_map(
            records,
            M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL,
            HearingPrecedentRetrievalReceipt,
        )
        response_by_request = {item.request_id: item for item in responses.values()}
        cache_by_request = {item.request_id: item for item in caches.values()}
        usage_by_request = {item.request_ref.artifact_id: item for item in usages.values()}
        output_by_parse = {item.parse_receipt_ref.artifact_id: item for item in outputs.values()}
        response_records = {
            record.artifact_id: record
            for record in records[M4ProjectionArtifactKind.MODEL_RESPONSE]
        }
        usage_records = {
            record.artifact_id: record for record in records[M4ProjectionArtifactKind.USAGE_RECEIPT]
        }
        claims = {
            record.artifact_id: record for record in records[M4ProjectionArtifactKind.MODEL_REQUEST]
        }
        for request_id, request in requests.items():
            record = claims[request_id]
            cycle = cycles.get(request.cycle_scope_id)
            session = sessions.get(request.hearing_session_id)
            if cycle is None or session is None:
                _record_failure(failures, record, "MODEL_REQUEST_SCOPE_ORPHAN")
                continue
            try:
                validate_hearing_cycle_scope_binding(cycle, request)
            except (TypeError, ValueError):
                _record_failure(failures, record, "MODEL_REQUEST_CYCLE_MISMATCH")
            expected_model = {
                VlmRole.PROSECUTOR: session.prosecutor_model_manifest_id,
                VlmRole.DEFENDER: session.defender_model_manifest_id,
                VlmRole.JUDGE: session.judge_model_manifest_id,
            }[request.role]
            if (
                request.model_manifest_id != expected_model
                or request.hearing_prompt_bundle_sha256 != session.hearing_prompt_bundle_sha256
            ):
                _record_failure(failures, record, "MODEL_REQUEST_SESSION_MANIFEST_MISMATCH")
            status = record.row["status"]
            response = response_by_request.get(request_id)
            cache = cache_by_request.get(request_id)
            usage = usage_by_request.get(request_id)
            if status == "COMPLETED":
                if (
                    response is None
                    or cache is None
                    or usage is None
                    or record.row["response_id"]
                    != (response.response_id if response is not None else None)
                    or not isinstance(record.row["completed_at"], str)
                ):
                    _record_failure(failures, record, "COMPLETED_CALL_CLOSURE_MISSING")
                elif not _call_closure_matches(request, response, cache, usage):
                    _record_failure(failures, record, "COMPLETED_CALL_CLOSURE_MISMATCH")
                elif not _usage_row_matches_claim(
                    usage_records[usage.usage_receipt_id],
                    record,
                    request,
                    usage,
                ):
                    _record_failure(
                        failures,
                        record,
                        "COMPLETED_CALL_USAGE_CLAIM_MISMATCH",
                    )
                elif not _response_row_matches_request(
                    response_records[response.response_id],
                    request,
                ):
                    _record_failure(failures, record, "RESPONSE_SCOPE_INDEX_MISMATCH")
            elif status == "ACTIVE":
                if (
                    response is not None
                    or cache is not None
                    or usage is not None
                    or record.row["response_id"] is not None
                    or record.row["completed_at"] is not None
                ):
                    _record_failure(failures, record, "ACTIVE_CALL_HAS_COMPLETION")
            else:
                _record_failure(failures, record, "MODEL_CALL_STATUS_INVALID")
        for response in responses.values():
            if response.request_id not in requests:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.MODEL_RESPONSE,
                    response.response_id,
                    "RESPONSE_CLAIM_ORPHAN",
                )
        for cache_record in records[M4ProjectionArtifactKind.MODEL_CACHE_ENTRY]:
            cache = cast(HearingModelCacheEntry, cache_record.document)
            claim = requests.get(cache.request_id)
            raw_request = cache_record.row["request_json"]
            raw_hash = cache_record.row["request_document_sha256"]
            if not isinstance(raw_request, str) or not isinstance(raw_hash, str) or claim is None:
                _record_failure(failures, cache_record, "CACHE_REQUEST_CLOSURE_MISSING")
                continue
            try:
                duplicate = HearingModelRequest.model_validate_json(raw_request)
            except (ValidationError, TypeError, ValueError):
                _record_failure(failures, cache_record, "CACHE_REQUEST_DOCUMENT_INVALID")
                continue
            if (
                canonical_json(duplicate.model_dump(mode="json")) != raw_request
                or hashlib.sha256(raw_request.encode("utf-8")).hexdigest() != raw_hash
                or duplicate != claim
            ):
                _record_failure(failures, cache_record, "CACHE_REQUEST_BINDING_MISMATCH")
        for usage_id, usage in usages.items():
            request = requests.get(usage.request_ref.artifact_id)
            response = responses.get(usage.response_ref.artifact_id)
            if (
                request is None
                or response is None
                or not _usage_matches_call(usage, request, response)
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.USAGE_RECEIPT,
                    usage_id,
                    "USAGE_CALL_CLOSURE_MISMATCH",
                )
        for parse_id, receipt in parses.items():
            request = requests.get(receipt.request_id)
            response = responses.get(receipt.response_id)
            output = output_by_parse.get(parse_id)
            if (
                request is None
                or response is None
                or not _parse_matches(receipt, request, response)
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
                    parse_id,
                    "PARSE_CALL_CLOSURE_MISMATCH",
                )
                continue
            if receipt.status.value == "PARSED":
                if output is None or output.payload.payload_sha256 != receipt.parsed_payload_sha256:
                    _reference_failure(
                        failures,
                        M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
                        parse_id,
                        "PARSED_OUTPUT_CLOSURE_MISSING",
                    )
            elif output is not None:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
                    parse_id,
                    "FAILED_PARSE_HAS_OUTPUT",
                )
        # A role commit intentionally precedes its checkpoint.  Its reverse
        # authority is therefore the exact parsed request/response closure,
        # not eventual checkpoint reachability.
        for output_id, output in outputs.items():
            request = requests.get(output.request_ref.artifact_id)
            response = responses.get(output.response_ref.artifact_id)
            parse = parses.get(output.parse_receipt_ref.artifact_id)
            retrieval = retrievals.get(output.precedent_retrieval_receipt_id)
            if (
                request is None
                or response is None
                or parse is None
                or retrieval is None
                or not _role_output_matches_call(
                    output,
                    request,
                    response,
                    parse,
                    retrieval,
                )
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.ROLE_OUTPUT,
                    output_id,
                    "ROLE_OUTPUT_CALL_CLOSURE_MISMATCH",
                )

    @staticmethod
    def _validate_checkpoint_closure(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        checkpoints: dict[str, HearingCheckpoint],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        retrievals = _typed_map(
            records,
            M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL,
            HearingPrecedentRetrievalReceipt,
        )
        outputs = _typed_map(records, M4ProjectionArtifactKind.ROLE_OUTPUT, HearingRoleOutput)
        acquisitions = _typed_map(
            records,
            M4ProjectionArtifactKind.ACQUISITION_REQUEST,
            AcquisitionRequest,
        )
        tool_receipts = _typed_map(
            records,
            M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
            ToolExecutionReceipt,
        )
        requests = _typed_map(records, M4ProjectionArtifactKind.MODEL_REQUEST, HearingModelRequest)
        responses = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_RESPONSE,
            HearingModelResponse,
        )
        parses = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
            HearingModelParseReceipt,
        )
        usage = _typed_map(records, M4ProjectionArtifactKind.USAGE_RECEIPT, HearingUsageReceipt)
        authorities = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY,
            HearingModelCallFailureAuthority,
        )
        reviews = _base_documents(
            base,
            M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
            ProceduralReview,
        )
        response_by_request = {item.request_id: item for item in responses.values()}
        parse_by_request = {item.request_id: item for item in parses.values()}
        usage_by_request = {item.request_ref.artifact_id: item for item in usage.values()}
        request_records = {
            item.artifact_id: item for item in records[M4ProjectionArtifactKind.MODEL_REQUEST]
        }
        by_hearing_version = {
            (item.hearing_session_id, item.version): item for item in checkpoints.values()
        }
        for checkpoint_id, checkpoint in checkpoints.items():
            embedded = (
                (checkpoint.precedent_retrieval_receipt, retrievals, "retrieval"),
                (checkpoint.prosecutor_output, outputs, "prosecutor output"),
                (checkpoint.defender_output, outputs, "defender output"),
                (checkpoint.judge_output, outputs, "judge output"),
                (checkpoint.acquisition_request, acquisitions, "acquisition request"),
                (checkpoint.tool_execution_receipt, tool_receipts, "tool receipt"),
            )
            closure_invalid = False
            for document, index, _label in embedded:
                if document is None:
                    continue
                identity = _document_identity(document)
                if identity is None or index.get(identity) != document:
                    closure_invalid = True
            for ref in checkpoint.model_request_refs:
                if requests.get(ref.artifact_id) is None:
                    closure_invalid = True
            for ref in checkpoint.model_response_refs:
                if responses.get(ref.artifact_id) is None:
                    closure_invalid = True
            for ref in checkpoint.parse_receipt_refs:
                if parses.get(ref.artifact_id) is None:
                    closure_invalid = True
            if any(
                usage.get(item.usage_receipt_id) != item for item in checkpoint.usage_receipts
            ) or any(
                authorities.get(item.authority_id) != item
                for item in checkpoint.failure_authorities
            ):
                closure_invalid = True
            if (
                checkpoint.procedural_review_ref is not None
                and checkpoint.procedural_review_ref.artifact_id not in reviews
            ):
                closure_invalid = True
            request_ids = {item.artifact_id for item in checkpoint.model_request_refs}
            response_ids = {item.artifact_id for item in checkpoint.model_response_refs}
            parse_ids = {item.artifact_id for item in checkpoint.parse_receipt_refs}
            usage_ids = {item.usage_receipt_id for item in checkpoint.usage_receipts}
            if not (len(request_ids) == len(response_ids) == len(parse_ids) == len(usage_ids)):
                closure_invalid = True
            for request_id in request_ids:
                request = requests.get(request_id)
                response = response_by_request.get(request_id)
                parse = parse_by_request.get(request_id)
                call_usage = usage_by_request.get(request_id)
                request_record = request_records.get(request_id)
                if (
                    request is None
                    or response is None
                    or parse is None
                    or call_usage is None
                    or request_record is None
                    or request_record.row["status"] != "COMPLETED"
                    or request.hearing_session_id != checkpoint.hearing_session_id
                    or request.case_id != checkpoint.case_id
                    or request.cycle_scope_id != checkpoint.cycle_scope_id
                    or request.cycle_scope_sha256 != checkpoint.cycle_scope_sha256
                    or response.response_id not in response_ids
                    or parse.parse_receipt_id not in parse_ids
                    or call_usage.usage_receipt_id not in usage_ids
                    or not _parse_matches(parse, request, response)
                    or not _usage_matches_call(call_usage, request, response)
                ):
                    closure_invalid = True
            for authority in checkpoint.failure_authorities:
                if (
                    authority.hearing_session_id != checkpoint.hearing_session_id
                    or authority.case_id != checkpoint.case_id
                    or authority.request.cycle_scope_id != checkpoint.cycle_scope_id
                    or authority.request.cycle_scope_sha256 != checkpoint.cycle_scope_sha256
                    or authority.manifest_id != checkpoint.manifest_id
                ):
                    closure_invalid = True
            if checkpoint.phase == HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING:
                if request_ids or checkpoint.failure_authorities:
                    closure_invalid = True
            elif checkpoint.version > 1:
                previous = by_hearing_version.get(
                    (checkpoint.hearing_session_id, checkpoint.version - 1)
                )
                if previous is None or any(
                    not old.issubset(current)
                    for old, current in (
                        (
                            {item.artifact_id for item in previous.model_request_refs},
                            request_ids,
                        ),
                        (
                            {item.artifact_id for item in previous.model_response_refs},
                            response_ids,
                        ),
                        (
                            {item.artifact_id for item in previous.parse_receipt_refs},
                            parse_ids,
                        ),
                        (
                            {item.usage_receipt_id for item in previous.usage_receipts},
                            usage_ids,
                        ),
                        (
                            {item.authority_id for item in previous.failure_authorities},
                            {item.authority_id for item in checkpoint.failure_authorities},
                        ),
                    )
                ):
                    closure_invalid = True
            if closure_invalid:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_CHECKPOINT,
                    checkpoint_id,
                    "CHECKPOINT_EMBEDDED_CLOSURE_MISMATCH",
                )

    @staticmethod
    def _validate_rounds_and_acquisition(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        cycles: dict[str, HearingCycleScope],
        checkpoints: dict[str, HearingCheckpoint],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        retrievals = _typed_map(
            records,
            M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL,
            HearingPrecedentRetrievalReceipt,
        )
        outputs = _typed_map(records, M4ProjectionArtifactKind.ROLE_OUTPUT, HearingRoleOutput)
        rounds = _typed_map(records, M4ProjectionArtifactKind.HEARING_ROUND, HearingRound)
        requests = _typed_map(
            records,
            M4ProjectionArtifactKind.ACQUISITION_REQUEST,
            AcquisitionRequest,
        )
        claims = _typed_map(
            records,
            M4ProjectionArtifactKind.ACQUISITION_EXECUTION_CLAIM,
            AcquisitionExecutionClaimAuthority,
        )
        publications = _typed_map(
            records,
            M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION,
            AcquisitionExecutionPublication,
        )
        manifests = _typed_map(
            records,
            M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST,
            ToolExecutionManifest,
        )
        receipts = _typed_map(
            records,
            M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
            ToolExecutionReceipt,
        )
        derivations = _typed_map(
            records,
            M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION,
            EvidencePackDerivation,
        )
        derivation_by_receipt = {
            item.tool_execution_receipt_id: item for item in derivations.values()
        }
        packs = _base_documents(base, M4ProjectionArtifactKind.EVIDENCE_PACK, EvidencePack)
        cases = _case_versions(base)
        audits = _base_documents(base, M4ProjectionArtifactKind.AUDIT_ENTRY, AuditEntry)
        audits_by_sequence = {item.sequence: item for item in audits.values()}
        acquired_crops = _typed_map(records, M4ProjectionArtifactKind.ACQUIRED_CROP, Crop)
        request_records = {
            item.artifact_id: item for item in records[M4ProjectionArtifactKind.ACQUISITION_REQUEST]
        }
        claim_records = {
            item.artifact_id: item
            for item in records[M4ProjectionArtifactKind.ACQUISITION_EXECUTION_CLAIM]
        }
        publication_records = {
            item.artifact_id: item
            for item in records[M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION]
        }
        receipt_records = {
            item.artifact_id: item
            for item in records[M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT]
        }
        checkpoint_request_ids = {
            item.acquisition_request.request_id
            for item in checkpoints.values()
            if item.acquisition_request is not None
        }
        checkpoint_receipt_ids = {
            item.tool_execution_receipt.receipt_id
            for item in checkpoints.values()
            if item.tool_execution_receipt is not None
        }
        used_requests: set[str] = set()
        used_receipts: set[str] = set()
        rounds_by_hearing_and_index = {
            (item.hearing_session_id, item.round_index): item for item in rounds.values()
        }
        for cycle_id, cycle in cycles.items():
            if cycle.cycle_index == 1:
                continue
            previous = rounds_by_hearing_and_index.get(
                (cycle.hearing_session_id, cycle.cycle_index - 1)
            )
            followed_acquisition = previous is not None and previous.acquisition_request is not None
            if (
                previous is None
                or cycle.cycle_evidence_pack_id != previous.resulting_evidence_pack_id
                or cycle.cycle_evidence_pack_version != previous.resulting_evidence_pack_version
                or cycle.prior_acquisition_rounds
                != previous.prior_acquisition_rounds + int(followed_acquisition)
                or cycle.prior_rework_rounds
                != previous.prior_rework_rounds + int(not followed_acquisition)
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_CYCLE,
                    cycle_id,
                    "CYCLE_PREDECESSOR_ROUND_MISMATCH",
                )
        for round_id, hearing_round in rounds.items():
            scoped_cycle = cycles.get(hearing_round.cycle_scope_id)
            try:
                if scoped_cycle is None:
                    raise ValueError
                validate_hearing_cycle_scope_binding(scoped_cycle, hearing_round)
            except (TypeError, ValueError):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_ROUND,
                    round_id,
                    "ROUND_CYCLE_MISMATCH",
                )
            if retrievals.get(hearing_round.precedent_retrieval_receipt.receipt_id) != (
                hearing_round.precedent_retrieval_receipt
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_ROUND,
                    round_id,
                    "ROUND_RETRIEVAL_MISMATCH",
                )
            for output in (
                hearing_round.prosecutor_output,
                hearing_round.defender_output,
                hearing_round.judge_output,
            ):
                if outputs.get(output.output_id) != output:
                    _reference_failure(
                        failures,
                        M4ProjectionArtifactKind.HEARING_ROUND,
                        round_id,
                        "ROUND_ROLE_OUTPUT_MISMATCH",
                    )
            if hearing_round.acquisition_request is None:
                continue
            request = hearing_round.acquisition_request
            receipt = hearing_round.tool_execution_receipt
            assert receipt is not None
            used_requests.add(request.request_id)
            used_receipts.add(receipt.receipt_id)
            if (
                requests.get(request.request_id) != request
                or manifests.get(receipt.execution_manifest.execution_manifest_id)
                != receipt.execution_manifest
                or receipts.get(receipt.receipt_id) != receipt
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_ROUND,
                    round_id,
                    "ROUND_ACQUISITION_CLOSURE_MISMATCH",
                )

        for request_id, request in requests.items():
            record = request_records[request_id]
            cycle_id = record.row["cycle_scope_id"]
            acquisition_cycle = cycles.get(cycle_id) if isinstance(cycle_id, str) else None
            judge = outputs.get(request.source_judge_output_id)
            if (
                acquisition_cycle is None
                or record.row["cycle_scope_sha256"] != acquisition_cycle.cycle_sha256
                or acquisition_cycle.hearing_session_id != request.hearing_session_id
                or acquisition_cycle.case_id != request.case_id
                or acquisition_cycle.cycle_index != request.round_index
                or acquisition_cycle.prior_acquisition_rounds != request.prior_acquisition_rounds
                or acquisition_cycle.prior_rework_rounds != request.prior_rework_rounds
                or acquisition_cycle.cycle_evidence_pack_id != request.current_evidence_pack_id
                or acquisition_cycle.cycle_evidence_pack_version
                != request.current_evidence_pack_version
                or acquisition_cycle.manifest_id != request.manifest_id
                or judge is None
                or judge.role != VlmRole.JUDGE
                or judge.request_ref != request.source_model_request_ref
                or judge.response_ref != request.source_model_response_ref
                or judge.hearing_session_id != request.hearing_session_id
                or judge.case_id != request.case_id
                or judge.round_index != request.round_index
                or getattr(cast(Any, judge.payload), "outcome", None) is None
                or getattr(cast(Any, judge.payload).outcome, "request", None)
                != request.request_payload
                or request_id not in checkpoint_request_ids
            ):
                _record_failure(failures, record, "ACQUISITION_REQUEST_CLOSURE_MISMATCH")

        receipt_by_request = {item.request.request_id: item for item in receipts.values()}
        publication_by_request = {item.request.request_id: item for item in publications.values()}
        for request_id, claim_authority in claims.items():
            record = claim_records[request_id]
            publication_id = record.row["execution_publication_id"]
            publication = (
                publications.get(publication_id) if isinstance(publication_id, str) else None
            )
            completed = record.row["status"] == "COMPLETED"
            if (
                requests.get(request_id) != claim_authority.request
                or completed != (publication is not None)
                or (
                    publication is not None
                    and (
                        publication.request != claim_authority.request
                        or publication.execution_mode != claim_authority.execution_mode
                        or publication.idempotency_key != claim_authority.idempotency_key
                        or publication.claim_owner_sha256 != claim_authority.owner_token_sha256
                        or publication.claim_fence != claim_authority.owner_fence
                    )
                )
            ):
                _record_failure(
                    failures,
                    record,
                    "ACQUISITION_EXECUTION_CLAIM_CLOSURE_MISMATCH",
                )

        for publication_id, publication in publications.items():
            record = publication_records[publication_id]
            claim = claim_records.get(publication.request.request_id)
            if (
                requests.get(publication.request.request_id) != publication.request
                or manifests.get(publication.execution_manifest.execution_manifest_id)
                != publication.execution_manifest
                or claim is None
                or claim.row["status"] != "COMPLETED"
                or claim.row["execution_publication_id"] != publication_id
            ):
                _record_failure(
                    failures,
                    record,
                    "ACQUISITION_EXECUTION_PUBLICATION_CLOSURE_MISMATCH",
                )

        for manifest_id, manifest in manifests.items():
            request = requests.get(manifest.acquisition_request_id)
            receipt = receipt_by_request.get(manifest.acquisition_request_id)
            execution_publication = publication_by_request.get(manifest.acquisition_request_id)
            if (
                request is None
                or (receipt is None and execution_publication is None)
                or (receipt is not None and receipt.execution_manifest != manifest)
                or (
                    execution_publication is not None
                    and execution_publication.execution_manifest != manifest
                )
                or manifest.run_id != request.run_id
                or manifest.case_id != request.case_id
                or manifest.hearing_session_id != request.hearing_session_id
                or manifest.action != request.action
                or manifest.manifest_id != request.manifest_id
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST,
                    manifest_id,
                    "TOOL_MANIFEST_CLOSURE_MISMATCH",
                )

        for receipt_id, receipt in receipts.items():
            request = requests.get(receipt.request.request_id)
            manifest = manifests.get(receipt.execution_manifest.execution_manifest_id)
            derivation = derivation_by_receipt.get(receipt_id)
            predecessor = packs.get(receipt.request.current_evidence_pack_id)
            successor = packs.get(receipt.resulting_evidence_pack_id)
            record = receipt_records[receipt_id]
            request_record = request_records.get(receipt.request.request_id)
            current_case_transition = next(
                (
                    (case_revision, case)
                    for (case_id, case_revision), case in cases.items()
                    if case_id == receipt.request.case_id
                    and case.evidence_packs
                    and case.evidence_packs[-1] == successor
                    and case.timeline
                    and case.timeline[-1].object_ref == receipt_id
                ),
                None,
            )
            transition_record = (
                base[M4ProjectionArtifactKind.CASE_VERSION].get(
                    f"{request.case_id}-revision-{current_case_transition[0]:06d}"
                )
                if request is not None and current_case_transition is not None
                else None
            )
            transition_audit_sequence = (
                transition_record.row["audit_sequence"] if transition_record is not None else None
            )
            transition_audit = (
                audits_by_sequence.get(transition_audit_sequence)
                if isinstance(transition_audit_sequence, int)
                and not isinstance(transition_audit_sequence, bool)
                else None
            )
            successor_record = base[M4ProjectionArtifactKind.EVIDENCE_PACK].get(
                receipt.resulting_evidence_pack_id
            )
            output_ids = {
                ArtifactKind.FRAME: set(base[M4ProjectionArtifactKind.FRAME]),
                ArtifactKind.DETECTION: set(base[M4ProjectionArtifactKind.DETECTION]),
                ArtifactKind.CROP: {
                    *(crop.crop_id for pack in packs.values() for crop in pack.crops),
                    *acquired_crops,
                },
                ArtifactKind.OBJECTIVE_FACT: {
                    fact.fact_id for pack in packs.values() for fact in pack.objective_facts
                },
            }
            output_refs_exist = all(
                ref.kind in output_ids and ref.artifact_id in output_ids[ref.kind]
                for ref in receipt.tool_result.output_refs
            )
            if (
                request != receipt.request
                or manifest != receipt.execution_manifest
                or derivation is None
                or predecessor is None
                or successor is None
                or request_record is None
                or successor_record is None
                or record.row["cycle_scope_id"] != request_record.row["cycle_scope_id"]
                or record.row["cycle_scope_sha256"] != request_record.row["cycle_scope_sha256"]
                or current_case_transition is None
                or transition_record is None
                or transition_audit is None
                or current_case_transition[1].status != CaseStatus.DELIBERATING
                or current_case_transition[1].timeline[-1].action != "CASE_STATE_CHANGED"
                or current_case_transition[1].timeline[-1].stage != "HEARING"
                or current_case_transition[1].timeline[-1].details
                != {
                    "action": request.action.value,
                    "evidence_pack_id": successor.pack_id,
                    "evidence_pack_version": successor.version,
                    "tool_receipt_id": receipt.receipt_id,
                }
                or transition_audit.action.value != "EVIDENCE_PACK_PUBLISHED"
                or transition_audit.object_ref.kind != ArtifactKind.CASE
                or transition_audit.object_ref.artifact_id != request.case_id
                or transition_audit.after_sha256 != transition_record.row["document_sha256"]
                or successor_record.row["created_audit_sequence"] != transition_audit.sequence
                or not output_refs_exist
                or (
                    receipt_id not in checkpoint_receipt_ids
                    and receipt_id not in used_receipts
                    and not any(
                        case.timeline and case.timeline[-1].object_ref == receipt_id
                        for case in cases.values()
                    )
                )
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
                    receipt_id,
                    "ACQUISITION_PACK_CLOSURE_MISSING",
                )
                continue
            try:
                validate_evidence_pack_successor(predecessor, successor, receipt)
            except EvidencePackSuccessorError:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
                    receipt_id,
                    "ACQUISITION_PACK_SUCCESSOR_INVALID",
                )
            if (
                derivation.hearing_session_id != request.hearing_session_id
                or derivation.case_id != request.case_id
                or derivation.source_cycle_scope_id != request_record.row["cycle_scope_id"]
                or derivation.source_cycle_scope_sha256 != request_record.row["cycle_scope_sha256"]
                or derivation.previous_evidence_pack_id != predecessor.pack_id
                or derivation.previous_evidence_pack_version != predecessor.version
                or derivation.new_evidence_pack_id != successor.pack_id
                or derivation.new_evidence_pack_version != successor.version
                or derivation.manifest_id != request.manifest_id
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION,
                    derivation.derivation_id,
                    "PACK_DERIVATION_CLOSURE_MISMATCH",
                )
        for derivation_id, derivation in derivations.items():
            if derivation.tool_execution_receipt_id not in receipts:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION,
                    derivation_id,
                    "PACK_DERIVATION_REVERSE_ORPHAN",
                )

        crop_output_ids = {
            ref.artifact_id
            for result in (
                *(receipt.tool_result for receipt in receipts.values()),
                *(publication.tool_result for publication in publications.values()),
            )
            for ref in result.output_refs
            if ref.kind == ArtifactKind.CROP
        }
        for crop_id in acquired_crops:
            if crop_id not in crop_output_ids:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.ACQUIRED_CROP,
                    crop_id,
                    "ACQUIRED_CROP_REVERSE_ORPHAN",
                )
        # A request is durable before the tool boundary, but must be rooted in
        # the acquisition-pending checkpoint.  Manifests and outputs publish
        # atomically with their receipt.
        for request_id in set(requests) - checkpoint_request_ids:
            if request_id not in used_requests:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.ACQUISITION_REQUEST,
                    request_id,
                    "ACQUISITION_REQUEST_REVERSE_ORPHAN",
                )

    @staticmethod
    def _rebuild_hearing_records(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        sessions: dict[str, HearingSession],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> dict[tuple[str, int], HearingRecord]:
        """Rebuild every complete-round prefix without consulting mutable state."""

        rounds = _typed_map(records, M4ProjectionArtifactKind.HEARING_ROUND, HearingRound)
        usage = _typed_map(records, M4ProjectionArtifactKind.USAGE_RECEIPT, HearingUsageReceipt)
        failure_authorities = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY,
            HearingModelCallFailureAuthority,
        )
        by_hearing: dict[str, list[HearingRound]] = defaultdict(list)
        for hearing_round in rounds.values():
            by_hearing[hearing_round.hearing_session_id].append(hearing_round)
        rebuilt: dict[tuple[str, int], HearingRecord] = {}
        for session_id, session in sessions.items():
            ordered = sorted(by_hearing.get(session_id, ()), key=lambda item: item.round_index)
            if not ordered:
                continue
            if tuple(item.round_index for item in ordered) != tuple(range(1, len(ordered) + 1)):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_SESSION,
                    session_id,
                    "ROUND_SEQUENCE_INCOMPLETE",
                )
                continue
            for version in range(1, len(ordered) + 1):
                prefix = tuple(ordered[:version])
                request_refs = tuple(
                    sorted(
                        (
                            output.request_ref
                            for hearing_round in prefix
                            for output in (
                                hearing_round.prosecutor_output,
                                hearing_round.defender_output,
                                hearing_round.judge_output,
                            )
                        ),
                        key=lambda ref: ref.sort_key,
                    )
                )
                response_refs = tuple(
                    sorted(
                        (
                            output.response_ref
                            for hearing_round in prefix
                            for output in (
                                hearing_round.prosecutor_output,
                                hearing_round.defender_output,
                                hearing_round.judge_output,
                            )
                        ),
                        key=lambda ref: ref.sort_key,
                    )
                )
                parse_refs = tuple(
                    sorted(
                        (
                            output.parse_receipt_ref
                            for hearing_round in prefix
                            for output in (
                                hearing_round.prosecutor_output,
                                hearing_round.defender_output,
                                hearing_round.judge_output,
                            )
                        ),
                        key=lambda ref: ref.sort_key,
                    )
                )
                prefix_usage = tuple(
                    sorted(
                        (
                            item
                            for item in usage.values()
                            if item.hearing_session_id == session_id
                            and item.round_index <= version
                            and item.request_ref.artifact_id
                            in {ref.artifact_id for ref in request_refs}
                        ),
                        key=lambda item: (
                            item.round_index,
                            item.role.value,
                            item.request_ref.artifact_id,
                        ),
                    )
                )
                prefix_failures = tuple(
                    sorted(
                        (
                            item
                            for item in failure_authorities.values()
                            if item.hearing_session_id == session_id
                            and item.request.round_index <= version
                        ),
                        key=lambda item: (
                            item.request.round_index,
                            item.role.value,
                            item.request.request_id,
                            item.authority_id,
                        ),
                    )
                )
                try:
                    record = HearingRecord(
                        run_id=session.run_id,
                        case_id=session.case_id,
                        version=version,
                        session=session,
                        screening_id=session.screening_id,
                        initial_evidence_pack_id=session.initial_evidence_pack_id,
                        initial_evidence_pack_version=session.initial_evidence_pack_version,
                        acquisition_round_limit=session.acquisition_round_limit,
                        rework_round_limit=session.rework_round_limit,
                        rounds=prefix,
                        model_request_refs=request_refs,
                        model_response_refs=response_refs,
                        parse_receipt_refs=parse_refs,
                        usage_receipts=prefix_usage,
                        failure_authorities=prefix_failures,
                        manifest_id=session.manifest_id,
                    )
                except (ValidationError, TypeError, ValueError):
                    _reference_failure(
                        failures,
                        M4ProjectionArtifactKind.HEARING_SESSION,
                        session_id,
                        f"HEARING_RECORD_V{version}_RECONSTRUCTION_INVALID",
                    )
                    continue
                rebuilt[(session_id, version)] = record
        return rebuilt

    @staticmethod
    def _validate_verdicts_and_reviews(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        checkpoints: dict[str, HearingCheckpoint],
        hearing_records: dict[tuple[str, int], HearingRecord],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        bindings = _typed_map(
            records,
            M4ProjectionArtifactKind.VERDICT_BINDING,
            HearingVerdictBinding,
        )
        rounds = _typed_map(records, M4ProjectionArtifactKind.HEARING_ROUND, HearingRound)
        verdicts = _base_documents(base, M4ProjectionArtifactKind.VERDICT, Verdict)
        reviews = _base_documents(
            base,
            M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
            ProceduralReview,
        )
        binding_ids_by_round: dict[str, list[str]] = defaultdict(list)
        binding_ids_by_verdict: dict[str, list[str]] = defaultdict(list)
        reviews_by_verdict: dict[str, list[ProceduralReview]] = defaultdict(list)
        checkpoints_by_review: dict[str, list[HearingCheckpoint]] = defaultdict(list)
        case_versions = _case_versions(base)
        audits = _base_documents(base, M4ProjectionArtifactKind.AUDIT_ENTRY, AuditEntry)
        audit_by_sequence = {item.sequence: item for item in audits.values()}
        for review in reviews.values():
            reviews_by_verdict[review.reviewed_verdict_id].append(review)
        for candidate_checkpoint in checkpoints.values():
            if candidate_checkpoint.procedural_review_ref is not None:
                checkpoints_by_review[
                    candidate_checkpoint.procedural_review_ref.artifact_id
                ].append(candidate_checkpoint)
        for binding_id, binding in bindings.items():
            binding_ids_by_round[binding.judge_round_id].append(binding_id)
            binding_ids_by_verdict[binding.verdict_id].append(binding_id)
            hearing_round = rounds.get(binding.judge_round_id)
            record = hearing_records.get(
                (binding.hearing_session_id, binding.hearing_record_version)
            )
            verdict = verdicts.get(binding.verdict_id)
            matching_reviews = [
                item
                for item in reviews_by_verdict.get(binding.verdict_id, ())
                if item.reviewed_verdict_version == binding.verdict_version
            ]
            review = matching_reviews[0] if len(matching_reviews) == 1 else None
            matching_checkpoints = (
                checkpoints_by_review.get(review.review_id, ()) if review is not None else ()
            )
            terminal_checkpoint = (
                matching_checkpoints[0] if len(matching_checkpoints) == 1 else None
            )
            verdict_record = base[M4ProjectionArtifactKind.VERDICT].get(binding.verdict_id)
            review_record = (
                base[M4ProjectionArtifactKind.PROCEDURAL_REVIEW].get(review.review_id)
                if review is not None
                else None
            )
            audit_sequence = (
                review_record.row["audit_sequence"] if review_record is not None else None
            )
            audit = (
                audit_by_sequence.get(audit_sequence)
                if isinstance(audit_sequence, int) and not isinstance(audit_sequence, bool)
                else None
            )
            transition = next(
                (
                    case
                    for (case_id, _), case in case_versions.items()
                    if case_id == binding.case_id
                    and case.verdicts
                    and case.verdicts[-1] == verdict
                    and case.procedural_reviews
                    and case.procedural_reviews[-1] == review
                    and base[M4ProjectionArtifactKind.CASE_VERSION][
                        f"{case_id}-revision-{_:06d}"
                    ].row["audit_sequence"]
                    == audit_sequence
                ),
                None,
            )
            final_payload = None
            if hearing_round is not None and isinstance(
                hearing_round.judge_output.payload,
                JudgeModelPayload,
            ):
                candidate = hearing_round.judge_output.payload.outcome
                if isinstance(candidate, JudgeFinalDecisionPayload):
                    final_payload = candidate
            expected_phase = (
                HearingCheckpointPhase.COMPLETE
                if review is not None and review.passed
                else HearingCheckpointPhase.REWORK_READY
            )
            if (
                hearing_round is None
                or record is None
                or verdict is None
                or review is None
                or terminal_checkpoint is None
                or verdict_record is None
                or review_record is None
                or audit is None
                or transition is None
                or final_payload is None
                or record.rounds[-1].round_id != hearing_round.round_id
                or binding.hearing_record_id != record.record_id
                or binding.hearing_record_sha256 != record.record_sha256
                or binding.model_request_refs != record.model_request_refs
                or binding.model_response_refs != record.model_response_refs
                or binding.parse_receipt_refs != record.parse_receipt_refs
                or binding.judge_round_index != hearing_round.round_index
                or binding.run_id != hearing_round.run_id
                or binding.case_id != hearing_round.case_id
                or binding.hearing_session_id != hearing_round.hearing_session_id
                or binding.manifest_id != hearing_round.manifest_id
                or binding.evidence_pack_id != verdict.evidence_pack_id
                or binding.evidence_pack_version != verdict.evidence_pack_version
                or binding.evidence_pack_id != hearing_round.current_evidence_pack_id
                or binding.evidence_pack_version != hearing_round.current_evidence_pack_version
                or binding.verdict_version != verdict.version
                or binding.verdict_input_sha256 != verdict.verdict_input_sha256
                or binding.verdict_sha256 != verdict.verdict_sha256
                or binding.prosecutor_output_id != hearing_round.prosecutor_output.output_id
                or binding.defender_output_id != hearing_round.defender_output.output_id
                or binding.judge_output_id != hearing_round.judge_output.output_id
                or verdict.run_id != binding.run_id
                or verdict.case_id != binding.case_id
                or verdict.screening_id != record.screening_id
                or verdict.model_response_refs != record.model_response_refs
                or verdict.decision != final_payload.decision
                or verdict.confidence != final_payload.confidence
                or verdict.recommended_alert_level != final_payload.recommended_alert_level
                or verdict.rationale_summary != final_payload.rationale_summary
                or verdict.evidence_citations != final_payload.evidence_citations
                or verdict.objective_claims != final_payload.objective_claims
                or verdict.observation_sufficiency != final_payload.observation_sufficiency
                or verdict.manifest_id != binding.manifest_id
                or review.run_id != verdict.run_id
                or review.case_id != verdict.case_id
                or review.reviewed_verdict_sha256 != verdict.verdict_sha256
                or review.evidence_pack_id != verdict.evidence_pack_id
                or review.evidence_pack_version != verdict.evidence_pack_version
                or review.manifest_id != verdict.manifest_id
                or verdict_record.row["audit_sequence"] != audit_sequence
                or terminal_checkpoint.hearing_session_id != binding.hearing_session_id
                or terminal_checkpoint.case_id != binding.case_id
                or terminal_checkpoint.current_evidence_pack_id != binding.evidence_pack_id
                or terminal_checkpoint.current_evidence_pack_version
                != binding.evidence_pack_version
                or terminal_checkpoint.phase != expected_phase
                or terminal_checkpoint.manifest_id != binding.manifest_id
                or audit.action.value != "CASE_STATE_CHANGED"
                or audit.object_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
                or audit.object_ref.artifact_id != review.review_id
                or not transition.timeline
                or transition.timeline[-1].action != "CASE_STATE_CHANGED"
                or transition.timeline[-1].stage != "PROCEDURAL_GATE"
                or transition.timeline[-1].object_ref != review.review_id
                or transition.timeline[-1].details
                != {"passed": review.passed, "verdict_id": verdict.verdict_id}
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.VERDICT_BINDING,
                    binding_id,
                    "VERDICT_BINDING_CLOSURE_MISMATCH",
                )

        for round_id, hearing_round in rounds.items():
            payload = hearing_round.judge_output.payload
            is_terminal = isinstance(payload, JudgeModelPayload) and isinstance(
                payload.outcome,
                JudgeFinalDecisionPayload,
            )
            binding_count = len(binding_ids_by_round.get(round_id, ()))
            if binding_count > 1 or (not is_terminal and binding_count != 0):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_ROUND,
                    round_id,
                    "TERMINAL_ROUND_VERDICT_BINDING_CARDINALITY_MISMATCH",
                )
        m4_response_ids = set(
            _typed_map(
                records,
                M4ProjectionArtifactKind.MODEL_RESPONSE,
                HearingModelResponse,
            )
        )
        for verdict_id, verdict in verdicts.items():
            hearing_origin = any(
                ref.artifact_id in m4_response_ids for ref in verdict.model_response_refs
            )
            if hearing_origin and len(binding_ids_by_verdict.get(verdict_id, ())) != 1:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.VERDICT,
                    verdict_id,
                    "HEARING_VERDICT_BINDING_MISSING",
                )
        for verdict_id, binding_ids in binding_ids_by_verdict.items():
            if len(binding_ids) != 1:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.VERDICT,
                    verdict_id,
                    "VERDICT_BINDING_REVERSE_CARDINALITY_MISMATCH",
                )

    @staticmethod
    def _validate_backlog_retry_graph(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        checkpoints: dict[str, HearingCheckpoint],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        requests = _typed_map(records, M4ProjectionArtifactKind.MODEL_REQUEST, HearingModelRequest)
        responses = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_RESPONSE,
            HearingModelResponse,
        )
        parses = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
            HearingModelParseReceipt,
        )
        outputs = _typed_map(records, M4ProjectionArtifactKind.ROLE_OUTPUT, HearingRoleOutput)
        human = _typed_map(
            records,
            M4ProjectionArtifactKind.HUMAN_REVIEW_RECEIPT,
            HearingHumanReviewReceipt,
        )
        attempts = _typed_map(
            records,
            M4ProjectionArtifactKind.STRICT_PARSE_FAILURE_ATTEMPT,
            HearingStrictParseFailureAttempt,
        )
        proofs = {
            item.artifact_id: item.document
            for item in records[M4ProjectionArtifactKind.STRICT_PARSE_FAILURE_PROOF]
            if isinstance(
                item.document,
                (HearingInitialStrictParseFailureProof, HearingStrictParseFailureProof),
            )
        }
        outcomes = {
            item.artifact_id: item.document
            for item in records[M4ProjectionArtifactKind.BACKLOG_RETRY_OUTCOME]
            if isinstance(item.document, (HearingBacklogRetrySuccess, HearingBacklogRetryFailure))
        }
        completions = _typed_map(
            records,
            M4ProjectionArtifactKind.HEARING_BACKLOG_COMPLETION,
            HearingBacklogCompletionReceipt,
        )
        authorities = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY,
            HearingModelCallFailureAuthority,
        )
        backlog_items = _base_documents(
            base,
            M4ProjectionArtifactKind.BACKLOG_ITEM,
            BacklogItem,
        )
        backlog_versions = _base_documents(
            base,
            M4ProjectionArtifactKind.BACKLOG_ITEM_VERSION,
            BacklogItem,
        )
        case_versions = _case_versions(base)
        audits = _base_documents(base, M4ProjectionArtifactKind.AUDIT_ENTRY, AuditEntry)
        audit_by_sequence = {item.sequence: item for item in audits.values()}
        claim_records = {
            item.artifact_id: item for item in records[M4ProjectionArtifactKind.MODEL_REQUEST]
        }
        completion_by_outcome = {item.outcome.outcome_id: item for item in completions.values()}
        referenced_attempts: set[str] = set()

        for proof_id, proof in proofs.items():
            primary, repair = proof.attempts
            source = checkpoints.get(proof.source_checkpoint_id)
            if isinstance(proof, HearingInitialStrictParseFailureProof):
                initial = True
                backlog_item_id = proof.backlog_item_id
                retry_proof: HearingStrictParseFailureProof | None = None
            else:
                initial = False
                retry_proof = proof
                backlog_item_id = retry_proof.lease.item_id
            backlog = backlog_items.get(backlog_item_id)
            closure_invalid = (
                attempts.get(primary.attempt_id) != primary
                or attempts.get(repair.attempt_id) != repair
                or source is None
                or source.checkpoint_sha256 != proof.source_checkpoint_sha256
                or source.version != proof.source_checkpoint_version
                or source.hearing_session_id != primary.request.hearing_session_id
                or source.case_id != primary.request.case_id
                or backlog is None
                or backlog.case_id != primary.request.case_id
                or backlog.stage.value != "HEARING"
                or backlog.role != proof.role
                or backlog.manifest_id != primary.request.manifest_id
            )
            if initial:
                closure_invalid = closure_invalid or any(
                    item.request.backlog_retry_context is not None for item in proof.attempts
                )

            else:
                assert retry_proof is not None
                leased = next(
                    (
                        item
                        for item in backlog_versions.values()
                        if item.item_id == retry_proof.lease.item_id
                        and item.status.value == "LEASED"
                        and item.lease_id == retry_proof.lease.lease_id
                        and item.attempt_count == retry_proof.lease.attempt_count
                        and item.retry_generation == retry_proof.lease.retry_generation
                    ),
                    None,
                )
                closure_invalid = closure_invalid or leased is None
            if closure_invalid:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.STRICT_PARSE_FAILURE_PROOF,
                    proof_id,
                    "STRICT_PARSE_PROOF_CLOSURE_MISMATCH",
                )
            referenced_attempts.update((primary.attempt_id, repair.attempt_id))

        for attempt_id, attempt in attempts.items():
            request = requests.get(attempt.request.request_id)
            response = responses.get(attempt.response.response_id)
            parse = parses.get(attempt.parse_receipt.parse_receipt_id)
            if (
                request != attempt.request
                or response != attempt.response
                or parse != attempt.parse_receipt
                or attempt_id not in referenced_attempts
                or not _parse_matches(attempt.parse_receipt, attempt.request, attempt.response)
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.STRICT_PARSE_FAILURE_ATTEMPT,
                    attempt_id,
                    "STRICT_PARSE_ATTEMPT_REVERSE_ORPHAN",
                )

        for outcome_id, outcome in outcomes.items():
            source = checkpoints.get(outcome.source_checkpoint_id)
            backlog = backlog_items.get(outcome.lease.item_id)
            leased = next(
                (
                    item
                    for item in backlog_versions.values()
                    if item.item_id == outcome.lease.item_id
                    and item.status.value == "LEASED"
                    and item.lease_id == outcome.lease.lease_id
                    and item.attempt_count == outcome.lease.attempt_count
                    and item.retry_generation == outcome.lease.retry_generation
                ),
                None,
            )
            closure_invalid = (
                source is None
                or source.checkpoint_sha256 != outcome.source_checkpoint_sha256
                or source.version != outcome.source_checkpoint_version
                or source.hearing_session_id != outcome.request.hearing_session_id
                or source.case_id != outcome.request.case_id
                or requests.get(outcome.request.request_id) != outcome.request
                or backlog is None
                or backlog.case_id != outcome.request.case_id
                or backlog.stage.value != "HEARING"
                or backlog.role != outcome.request.role
                or leased is None
                or outcome_id not in completion_by_outcome
            )
            if isinstance(outcome, HearingBacklogRetrySuccess):
                closure_invalid = closure_invalid or (
                    responses.get(outcome.response.response_id) != outcome.response
                    or parses.get(outcome.parse_receipt.parse_receipt_id) != outcome.parse_receipt
                    or outputs.get(outcome.parsed_role_output.output_id)
                    != outcome.parsed_role_output
                    or checkpoints.get(outcome.next_checkpoint.checkpoint_id)
                    != outcome.next_checkpoint
                    or (
                        outcome.human_review_receipt is not None
                        and human.get(outcome.human_review_receipt.receipt_id)
                        != outcome.human_review_receipt
                    )
                )
            else:
                closure_invalid = (
                    closure_invalid
                    or (
                        outcome.strict_parse_failure is not None
                        and proofs.get(outcome.strict_parse_failure.proof_id)
                        != outcome.strict_parse_failure
                    )
                    or (
                        outcome.human_review_receipt is not None
                        and human.get(outcome.human_review_receipt.receipt_id)
                        != outcome.human_review_receipt
                    )
                )
            if closure_invalid:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.BACKLOG_RETRY_OUTCOME,
                    outcome_id,
                    "BACKLOG_RETRY_OUTCOME_CLOSURE_MISMATCH",
                )

        for authority_id, authority in authorities.items():
            claim_record = claim_records.get(authority.request.request_id)
            source = checkpoints.get(authority.source_checkpoint_id)
            backlog = backlog_versions.get(
                f"{authority.backlog_item_id}-version-{authority.backlog_version:06d}"
            )
            completion = (
                completions.get(authority.completion_receipt_id)
                if authority.completion_receipt_id is not None
                else None
            )
            case = case_versions.get((authority.case_id, authority.closure_case_revision))
            case_record = base[M4ProjectionArtifactKind.CASE_VERSION].get(
                f"{authority.case_id}-revision-{authority.closure_case_revision:06d}"
            )
            audit = audit_by_sequence.get(authority.closure_audit_sequence)
            current_takeover_count = (
                claim_record.row["takeover_count"] if claim_record is not None else None
            )
            claim_epoch_invalid = (
                claim_record is None
                or not isinstance(current_takeover_count, int)
                or isinstance(current_takeover_count, bool)
                or authority.claim_takeover_count > current_takeover_count
                or (
                    authority.claim_takeover_count == current_takeover_count
                    and (
                        claim_record.row["status"] != "ACTIVE"
                        or claim_record.row["response_id"] is not None
                        or claim_record.row["completed_at"] is not None
                        or claim_record.row["owner_token_sha256"] != authority.claim_owner_sha256
                        or claim_record.row["lease_expires_at"]
                        != authority.claim_lease_expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    )
                )
            )
            expected_case_status = (
                CaseStatus.HUMAN_REVIEW
                if authority.backlog_status == BacklogStatus.EXHAUSTED
                else CaseStatus.BACKLOGGED
            )
            expected_current_backlog = (
                authority.backlog_item_id
                if authority.backlog_status == BacklogStatus.PENDING
                else None
            )
            completion_invalid = authority.completion_receipt_id is not None and (
                completion is None
                or completion.outcome.request != authority.request
                or completion.outcome.lease != authority.lease
                or completion.backlog_status != authority.backlog_status
                or completion.completion_case_revision != authority.closure_case_revision
                or completion.completion_audit_sequence != authority.closure_audit_sequence
                or completion.completion_audit_entry_hash != authority.closure_audit_entry_hash
            )
            if (
                requests.get(authority.request.request_id) != authority.request
                or claim_epoch_invalid
                or source is None
                or source.checkpoint_sha256 != authority.source_checkpoint_sha256
                or source.version != authority.source_checkpoint_version
                or source.case_id != authority.case_id
                or source.hearing_session_id != authority.hearing_session_id
                or source.cycle_scope_id != authority.request.cycle_scope_id
                or source.cycle_scope_sha256 != authority.request.cycle_scope_sha256
                or source.current_evidence_pack_id != authority.request.current_evidence_pack_id
                or source.current_evidence_pack_version
                != authority.request.current_evidence_pack_version
                or backlog is None
                or backlog.status != authority.backlog_status
                or backlog.attempt_count != authority.backlog_attempt_count
                or backlog.retry_generation != authority.retry_generation
                or case is None
                or case_record is None
                or case.status != expected_case_status
                or case.current_backlog_item_id != expected_current_backlog
                or audit is None
                or case_record.row["audit_sequence"] != authority.closure_audit_sequence
                or audit.entry_hash != authority.closure_audit_entry_hash
                or audit.action != AuditAction.CASE_STATE_CHANGED
                or audit.actor != AuditActorRole.SYSTEM.value
                or audit.object_ref.kind != ArtifactKind.BACKLOG_ITEM
                or audit.object_ref.artifact_id != authority.backlog_item_id
                or audit.after_sha256 != case_record.row["document_sha256"]
                or completion_invalid
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY,
                    authority_id,
                    "MODEL_FAILURE_AUTHORITY_CLOSURE_MISMATCH",
                )

        for completion_id, completion in completions.items():
            if outcomes.get(completion.outcome.outcome_id) != completion.outcome:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_BACKLOG_COMPLETION,
                    completion_id,
                    "BACKLOG_COMPLETION_OUTCOME_MISMATCH",
                )

    @staticmethod
    def _validate_backlog_history(
        connection: sqlite3.Connection,
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        """Rebuild every HEARING queue history and close each lease exit once."""

        requests = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_REQUEST,
            HearingModelRequest,
        )
        completions_by_exit: dict[tuple[str, int], list[M4Record]] = defaultdict(list)
        for completion_record in records[M4ProjectionArtifactKind.HEARING_BACKLOG_COMPLETION]:
            if not isinstance(completion_record.document, HearingBacklogCompletionReceipt):
                continue
            backlog_version = completion_record.row["backlog_version"]
            item_id = completion_record.row["item_id"]
            if (
                isinstance(backlog_version, int)
                and not isinstance(backlog_version, bool)
                and isinstance(item_id, str)
            ):
                completions_by_exit[(item_id, backlog_version)].append(completion_record)

        initial_items = _base_documents(
            base,
            M4ProjectionArtifactKind.BACKLOG_ITEM,
            BacklogItem,
        )
        version_records_by_item: dict[str, list[_BaseRecord]] = defaultdict(list)
        for version_record in base[M4ProjectionArtifactKind.BACKLOG_ITEM_VERSION].values():
            if isinstance(version_record.document, BacklogItem):
                version_records_by_item[version_record.document.item_id].append(version_record)

        hearing_item_ids = {
            item_id for item_id, item in initial_items.items() if item.stage.value == "HEARING"
        }
        heads: dict[str, int] = {}
        for run_id in sorted({initial_items[item_id].run_id for item_id in hearing_item_ids}):
            run_item_ids = sorted(
                item_id for item_id in hearing_item_ids if initial_items[item_id].run_id == run_id
            )
            placeholders = ", ".join("?" for _ in run_item_ids)
            rows = connection.execute(
                "SELECT item_id, current_version FROM backlog_heads "
                f"WHERE run_id = ? AND item_id IN ({placeholders})",
                (run_id, *run_item_ids),
            ).fetchall()
            for row in rows:
                item_id = row["item_id"]
                current_version = row["current_version"]
                if isinstance(item_id, str) and isinstance(current_version, int):
                    heads[item_id] = current_version

        for item_id in sorted(hearing_item_ids):
            initial = initial_items[item_id]
            version_records = sorted(
                version_records_by_item.get(item_id, ()),
                key=lambda item: int(item.row["version"]),
            )
            versions = [cast(BacklogItem, item.document) for item in version_records]
            observed_versions = [item.row["version"] for item in version_records]
            stage_request = requests.get(initial.stage_input_ref.artifact_id)
            stage_input_matches = (
                initial.stage_input_ref.kind == ArtifactKind.MODEL_REQUEST
                and stage_request is not None
                and stage_request.case_id == initial.case_id
                and stage_request.run_id == initial.run_id
                and stage_request.role == initial.role
                and stage_request.manifest_id == initial.manifest_id
                and initial.stage_input_sha256 == sha256_hex(stage_request.model_dump(mode="json"))
            )
            history_invalid = (
                observed_versions != list(range(1, len(version_records) + 1))
                or not versions
                or not _same_backlog_identity(initial, versions[0])
                or versions[0].status != BacklogStatus.PENDING
                or versions[0].attempt_count != 0
                or versions[0].lease_id is not None
                or heads.get(item_id) != len(version_records)
                or not stage_input_matches
                or any(not _same_backlog_identity(initial, item) for item in versions)
            )
            if history_invalid:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.BACKLOG_ITEM,
                    item_id,
                    "HEARING_BACKLOG_HISTORY_BINDING_MISMATCH",
                )
            for previous_record, current_record in pairwise(version_records):
                previous = cast(BacklogItem, previous_record.document)
                current = cast(BacklogItem, current_record.document)
                current_version = cast(int, current_record.row["version"])
                if not _legal_backlog_transition(previous, current):
                    _reference_failure(
                        failures,
                        M4ProjectionArtifactKind.BACKLOG_ITEM_VERSION,
                        current_record.artifact_id,
                        "HEARING_BACKLOG_HISTORY_TRANSITION_INVALID",
                    )
                if (
                    previous.status == BacklogStatus.LEASED
                    and current.status != BacklogStatus.LEASED
                ):
                    receipts = completions_by_exit.get((item_id, current_version), ())
                    if len(receipts) != 1:
                        _reference_failure(
                            failures,
                            M4ProjectionArtifactKind.BACKLOG_ITEM_VERSION,
                            current_record.artifact_id,
                            "HEARING_BACKLOG_LEASE_EXIT_COMPLETION_CARDINALITY_MISMATCH",
                        )

        for item_id, version_records in version_records_by_item.items():
            if item_id in initial_items:
                continue
            for orphan_record in version_records:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.BACKLOG_ITEM_VERSION,
                    orphan_record.artifact_id,
                    "BACKLOG_IDENTITY_REVERSE_ORPHAN",
                )

    @staticmethod
    def _validate_human_review(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        checkpoints: dict[str, HearingCheckpoint],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        receipts = _typed_map(
            records,
            M4ProjectionArtifactKind.HUMAN_REVIEW_RECEIPT,
            HearingHumanReviewReceipt,
        )
        cases = _case_versions(base)
        reviews = _base_documents(
            base,
            M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
            ProceduralReview,
        )
        backlog_items = _base_documents(
            base,
            M4ProjectionArtifactKind.BACKLOG_ITEM,
            BacklogItem,
        )
        requests = _typed_map(
            records,
            M4ProjectionArtifactKind.MODEL_REQUEST,
            HearingModelRequest,
        )
        outcomes = {
            item.artifact_id: item.document
            for item in records[M4ProjectionArtifactKind.BACKLOG_RETRY_OUTCOME]
            if isinstance(item.document, (HearingBacklogRetrySuccess, HearingBacklogRetryFailure))
        }
        completions = _typed_map(
            records,
            M4ProjectionArtifactKind.HEARING_BACKLOG_COMPLETION,
            HearingBacklogCompletionReceipt,
        )
        completion_by_outcome = {item.outcome.outcome_id: item for item in completions.values()}
        checkpoints_by_human: dict[str, list[HearingCheckpoint]] = defaultdict(list)
        for checkpoint in checkpoints.values():
            if checkpoint.human_review_receipt_id is not None:
                checkpoints_by_human[checkpoint.human_review_receipt_id].append(checkpoint)
        outcomes_by_human: dict[str, list[Any]] = defaultdict(list)
        for outcome in outcomes.values():
            if outcome.human_review_receipt is not None:
                outcomes_by_human[outcome.human_review_receipt.receipt_id].append(outcome)
        audits = _base_documents(base, M4ProjectionArtifactKind.AUDIT_ENTRY, AuditEntry)
        audits_by_sequence = {item.sequence: item for item in audits.values()}
        for receipt_id, receipt in receipts.items():
            source = checkpoints.get(receipt.source_checkpoint_id)
            matching_terminals = checkpoints_by_human.get(receipt_id, ())
            terminal = matching_terminals[0] if len(matching_terminals) == 1 else None
            embedded_outcomes = outcomes_by_human.get(receipt_id, ())
            embedded = embedded_outcomes[0] if len(embedded_outcomes) == 1 else None
            backlog_completion = (
                completion_by_outcome.get(embedded.outcome_id) if embedded is not None else None
            )
            current_entry = _current_case(cases, receipt.case_id)
            current_revision, current = current_entry if current_entry is not None else (-1, None)
            case_record = base[M4ProjectionArtifactKind.CASE_VERSION].get(
                f"{receipt.case_id}-revision-{current_revision:06d}"
            )
            audit_sequence = case_record.row["audit_sequence"] if case_record is not None else None
            audit = (
                audits_by_sequence.get(audit_sequence)
                if isinstance(audit_sequence, int) and not isinstance(audit_sequence, bool)
                else None
            )
            review = (
                reviews.get(receipt.procedural_review_ref.artifact_id)
                if receipt.procedural_review_ref is not None
                else None
            )
            backlog = (
                backlog_items.get(receipt.backlog_item_ref.artifact_id)
                if receipt.backlog_item_ref is not None
                else None
            )
            acquisition_call = (
                requests.get(receipt.acquisition_request_ref.artifact_id)
                if receipt.acquisition_request_ref is not None
                else None
            )
            direct_checkpoint_closure = terminal is not None and (
                source is not None
                and terminal.previous_checkpoint_id == source.checkpoint_id
                and terminal.previous_checkpoint_sha256 == source.checkpoint_sha256
                and terminal.previous_phase == source.phase
                and terminal.version == source.version + 1
                and terminal.phase == HearingCheckpointPhase.HUMAN_REVIEW
                and terminal.human_review_receipt_sha256 == receipt.receipt_sha256
                and terminal.human_review_reason == receipt.reason
                and terminal.current_evidence_pack_id == receipt.current_evidence_pack_id
                and terminal.current_evidence_pack_version == receipt.current_evidence_pack_version
                and terminal.judge_cycle == receipt.judge_cycle
                and terminal.run_id == receipt.run_id
                and terminal.case_id == receipt.case_id
                and terminal.hearing_session_id == receipt.hearing_session_id
                and terminal.manifest_id == receipt.manifest_id
            )
            backlog_closure = (
                terminal is None
                and isinstance(embedded, HearingBacklogRetryFailure)
                and backlog_completion is not None
                and embedded.human_review_receipt == receipt
                and backlog_completion.completion_case_revision == current_revision
                and backlog_completion.completion_case_status == CaseStatus.HUMAN_REVIEW
                and backlog_completion.resulting_checkpoint_id == receipt.source_checkpoint_id
                and backlog_completion.resulting_checkpoint_sha256
                == receipt.source_checkpoint_sha256
                and backlog_completion.resulting_checkpoint_version
                == receipt.source_checkpoint_version
            )
            expected_audit_ref = (
                (ArtifactKind.BACKLOG_ITEM, embedded.lease.item_id)
                if backlog_completion is not None and embedded is not None
                else (ArtifactKind.BACKLOG_ITEM, receipt.backlog_item_ref.artifact_id)
                if receipt.backlog_item_ref is not None
                else (ArtifactKind.CASE, receipt.case_id)
            )
            direct_timeline_closure = (
                current is not None
                and direct_checkpoint_closure
                and bool(current.timeline)
                and current.timeline[-1].object_ref == receipt.receipt_id
                and current.timeline[-1].action == "CASE_STATE_CHANGED"
                and current.timeline[-1].stage == "HEARING"
                and current.timeline[-1].details
                == {
                    "reason": receipt.reason.value,
                    "hearing_session_id": receipt.hearing_session_id,
                    "judge_cycle": receipt.judge_cycle,
                }
            )
            backlog_timeline_closure = (
                current is not None
                and backlog_closure
                and isinstance(embedded, HearingBacklogRetryFailure)
                and backlog_completion is not None
                and bool(current.timeline)
                and current.timeline[-1].object_ref == embedded.lease.item_id
                and current.timeline[-1].action == "CASE_STATE_CHANGED"
                and current.timeline[-1].stage == "BACKLOG"
                and current.timeline[-1].details
                == {
                    "outcome": "FAILURE",
                    "reason_code": embedded.reason_code.value,
                    "status": backlog_completion.backlog_status.value,
                    "retry_generation": embedded.next_retry_generation,
                }
            )
            if (
                source is None
                or current is None
                or receipt.source_checkpoint_sha256 != source.checkpoint_sha256
                or receipt.source_checkpoint_version != source.version
                or source.run_id != receipt.run_id
                or source.case_id != receipt.case_id
                or source.hearing_session_id != receipt.hearing_session_id
                or source.current_evidence_pack_id != receipt.current_evidence_pack_id
                or source.current_evidence_pack_version != receipt.current_evidence_pack_version
                or source.judge_cycle != receipt.judge_cycle
                or not (direct_checkpoint_closure or backlog_closure)
                or (receipt.procedural_review_ref is not None and review is None)
                or (receipt.backlog_item_ref is not None and backlog is None)
                or (receipt.acquisition_request_ref is not None and acquisition_call is None)
                or (review is not None and review.case_id != receipt.case_id)
                or (backlog is not None and backlog.case_id != receipt.case_id)
                or (
                    acquisition_call is not None
                    and (
                        acquisition_call.case_id != receipt.case_id
                        or acquisition_call.hearing_session_id != receipt.hearing_session_id
                        or acquisition_call.round_index != receipt.judge_cycle
                    )
                )
                or current.status != CaseStatus.HUMAN_REVIEW
                or current.current_backlog_item_id is not None
                or not current.evidence_packs
                or current.evidence_packs[-1].pack_id != receipt.current_evidence_pack_id
                or current.evidence_packs[-1].version != receipt.current_evidence_pack_version
                or not (direct_timeline_closure or backlog_timeline_closure)
                or case_record is None
                or audit is None
                or audit.after_sha256 != case_record.row["document_sha256"]
                or audit.action.value != "CASE_STATE_CHANGED"
                or audit.object_ref.kind != expected_audit_ref[0]
                or audit.object_ref.artifact_id != expected_audit_ref[1]
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HUMAN_REVIEW_RECEIPT,
                    receipt_id,
                    "HUMAN_REVIEW_BIDIRECTIONAL_CLOSURE_MISMATCH",
                )
        for receipt_id in set(checkpoints_by_human) - set(receipts):
            _reference_failure(
                failures,
                M4ProjectionArtifactKind.HEARING_CHECKPOINT,
                checkpoints_by_human[receipt_id][0].checkpoint_id,
                "HUMAN_REVIEW_RECEIPT_MISSING",
            )

    @staticmethod
    def _validate_reworks(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        cycles: dict[str, HearingCycleScope],
        checkpoints: dict[str, HearingCheckpoint],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        receipts = _typed_map(
            records,
            M4ProjectionArtifactKind.REWORK_RECEIPT,
            HearingReworkReceipt,
        )
        rounds = _typed_map(records, M4ProjectionArtifactKind.HEARING_ROUND, HearingRound)
        reviews = _base_documents(
            base,
            M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
            ProceduralReview,
        )
        cases = _case_versions(base)
        audits = _base_documents(base, M4ProjectionArtifactKind.AUDIT_ENTRY, AuditEntry)
        audits_by_sequence = {item.sequence: item for item in audits.values()}
        checkpoints_by_cycle: dict[str, list[HearingCheckpoint]] = defaultdict(list)
        for checkpoint in checkpoints.values():
            checkpoints_by_cycle[checkpoint.cycle_scope_id].append(checkpoint)
        receipt_by_cycle = {item.next_cycle_scope_id: item for item in receipts.values()}
        for receipt_id, receipt in receipts.items():
            review = reviews.get(receipt.failed_review_id)
            prior_round = rounds.get(receipt.prior_round_id)
            next_cycle = cycles.get(receipt.next_cycle_scope_id)
            opening_candidates = [
                item
                for item in checkpoints_by_cycle.get(receipt.next_cycle_scope_id, ())
                if item.phase == HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING
            ]
            opening = opening_candidates[0] if len(opening_candidates) == 1 else None
            previous = (
                checkpoints.get(opening.previous_checkpoint_id)
                if opening is not None and opening.previous_checkpoint_id is not None
                else None
            )
            transition_match: tuple[int, Case, _BaseRecord, AuditEntry] | None = None
            for (case_id, revision), case in cases.items():
                if (
                    case_id != receipt.case_id
                    or not case.timeline
                    or case.timeline[-1].object_ref != receipt.receipt_id
                ):
                    continue
                case_record = base[M4ProjectionArtifactKind.CASE_VERSION].get(
                    f"{case_id}-revision-{revision:06d}"
                )
                if case_record is None:
                    continue
                audit_sequence = case_record.row["audit_sequence"]
                audit = (
                    audits_by_sequence.get(audit_sequence)
                    if isinstance(audit_sequence, int) and not isinstance(audit_sequence, bool)
                    else None
                )
                if audit is not None:
                    transition_match = (revision, case, case_record, audit)
                    break
            review_codes = (
                tuple(defect.code for defect in review.defects) if review is not None else ()
            )
            if (
                review is None
                or review.passed
                or prior_round is None
                or next_cycle is None
                or opening is None
                or previous is None
                or transition_match is None
                or receipt.next_cycle_scope_sha256 != next_cycle.cycle_sha256
                or receipt.hearing_session_id != next_cycle.hearing_session_id
                or receipt.case_id != next_cycle.case_id
                or prior_round.hearing_session_id != receipt.hearing_session_id
                or prior_round.case_id != receipt.case_id
                or prior_round.round_index + 1 != next_cycle.cycle_index
                or receipt.rework_index != next_cycle.prior_rework_rounds
                or next_cycle.rework_review_ref is None
                or next_cycle.rework_review_ref.artifact_id != review.review_id
                or receipt.defect_codes != next_cycle.rework_defect_codes
                or receipt.defect_codes != review_codes
                or receipt.manifest_id != next_cycle.manifest_id
                or review.case_id != receipt.case_id
                or review.manifest_id != receipt.manifest_id
                or previous.phase != HearingCheckpointPhase.REWORK_READY
                or previous.procedural_review_ref is None
                or previous.procedural_review_ref.artifact_id != review.review_id
                or opening.previous_checkpoint_sha256 != previous.checkpoint_sha256
                or opening.previous_phase != previous.phase
                or opening.version != previous.version + 1
                or opening.hearing_session_id != receipt.hearing_session_id
                or opening.case_id != receipt.case_id
                or opening.current_evidence_pack_id != next_cycle.cycle_evidence_pack_id
                or opening.current_evidence_pack_version != next_cycle.cycle_evidence_pack_version
                or opening.manifest_id != receipt.manifest_id
                or transition_match[1].status != CaseStatus.DELIBERATING
                or not transition_match[1].procedural_reviews
                or transition_match[1].procedural_reviews[-1] != review
                or transition_match[1].timeline[-1].action != "CASE_STATE_CHANGED"
                or transition_match[1].timeline[-1].stage != "HEARING"
                or transition_match[1].timeline[-1].details
                != {
                    "rework_index": receipt.rework_index,
                    "status": CaseStatus.DELIBERATING.value,
                }
                or transition_match[3].action.value != "CASE_STATE_CHANGED"
                or transition_match[3].object_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
                or transition_match[3].object_ref.artifact_id != review.review_id
                or transition_match[3].after_sha256 != transition_match[2].row["document_sha256"]
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.REWORK_RECEIPT,
                    receipt_id,
                    "REWORK_BIDIRECTIONAL_CLOSURE_MISMATCH",
                )
        for cycle_id, cycle in cycles.items():
            if cycle.rework_review_ref is not None and cycle_id not in receipt_by_cycle:
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_CYCLE,
                    cycle_id,
                    "REWORK_RECEIPT_REVERSE_ORPHAN",
                )

    @staticmethod
    def _validate_unique_active_hearings(
        sessions: dict[str, HearingSession],
        checkpoints: dict[str, HearingCheckpoint],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        by_hearing: dict[str, list[HearingCheckpoint]] = defaultdict(list)
        for checkpoint in checkpoints.values():
            by_hearing[checkpoint.hearing_session_id].append(checkpoint)
        terminal = {
            HearingCheckpointPhase.COMPLETE,
            HearingCheckpointPhase.HUMAN_REVIEW,
        }
        active_by_case: dict[str, list[str]] = defaultdict(list)
        for session_id, session in sessions.items():
            ordered = sorted(by_hearing.get(session_id, ()), key=lambda item: item.version)
            if ordered and ordered[-1].phase not in terminal:
                active_by_case[session.case_id].append(session_id)
        for session_ids in active_by_case.values():
            if len(session_ids) <= 1:
                continue
            for session_id in sorted(session_ids):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_SESSION,
                    session_id,
                    "MULTIPLE_ACTIVE_HEARINGS_FOR_CASE",
                )

    @staticmethod
    def _validate_backlog_completion(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        checkpoints: dict[str, HearingCheckpoint],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        receipts = _typed_map(
            records,
            M4ProjectionArtifactKind.HEARING_BACKLOG_COMPLETION,
            HearingBacklogCompletionReceipt,
        )
        backlog_versions = _base_documents(
            base,
            M4ProjectionArtifactKind.BACKLOG_ITEM_VERSION,
            BacklogItem,
        )
        backlog_items = _base_documents(
            base,
            M4ProjectionArtifactKind.BACKLOG_ITEM,
            BacklogItem,
        )
        cases = _case_versions(base)
        audits = _base_documents(base, M4ProjectionArtifactKind.AUDIT_ENTRY, AuditEntry)
        audits_by_sequence = {item.sequence: item for item in audits.values()}
        receipt_records = {
            item.artifact_id: item
            for item in records[M4ProjectionArtifactKind.HEARING_BACKLOG_COMPLETION]
        }
        for receipt_id, receipt in receipts.items():
            outcome = receipt.outcome
            source = checkpoints.get(receipt.source_checkpoint_id)
            target = checkpoints.get(receipt.resulting_checkpoint_id)
            record = receipt_records[receipt_id]
            backlog_version = record.row["backlog_version"]
            version_is_valid = isinstance(backlog_version, int) and not isinstance(
                backlog_version,
                bool,
            )
            completed = (
                backlog_versions.get(f"{outcome.lease.item_id}-version-{backlog_version:06d}")
                if version_is_valid
                else None
            )
            leased = (
                backlog_versions.get(f"{outcome.lease.item_id}-version-{backlog_version - 1:06d}")
                if version_is_valid and backlog_version > 1
                else None
            )
            initial = backlog_items.get(outcome.lease.item_id)
            case = cases.get((outcome.request.case_id, receipt.completion_case_revision))
            case_record = base[M4ProjectionArtifactKind.CASE_VERSION].get(
                f"{outcome.request.case_id}-revision-{receipt.completion_case_revision:06d}"
            )
            audit = audits_by_sequence.get(receipt.completion_audit_sequence)
            expected_retry_generation = (
                outcome.next_retry_generation
                if isinstance(outcome, HearingBacklogRetryFailure)
                else outcome.lease.retry_generation
            )
            expected_current_backlog = (
                outcome.lease.item_id
                if receipt.completion_case_status == CaseStatus.BACKLOGGED
                else None
            )
            if (
                source is None
                or target is None
                or completed is None
                or leased is None
                or initial is None
                or case is None
                or case_record is None
                or audit is None
                or source.checkpoint_sha256 != receipt.source_checkpoint_sha256
                or source.version != receipt.source_checkpoint_version
                or target.checkpoint_sha256 != receipt.resulting_checkpoint_sha256
                or target.version != receipt.resulting_checkpoint_version
                or source.case_id != outcome.request.case_id
                or source.hearing_session_id != outcome.request.hearing_session_id
                or target.case_id != outcome.request.case_id
                or target.hearing_session_id != outcome.request.hearing_session_id
                or initial.case_id != outcome.request.case_id
                or initial.role != outcome.request.role
                or initial.manifest_id != receipt.manifest_id
                or not _same_backlog_identity(initial, completed)
                or not _same_backlog_identity(initial, leased)
                or completed.status != receipt.backlog_status
                or completed.attempt_count != outcome.lease.attempt_count
                or completed.retry_generation != expected_retry_generation
                or completed.lease_id is not None
                or completed.lease_owner_sha256 is not None
                or completed.lease_expires_at is not None
                or leased.status != BacklogStatus.LEASED
                or leased.lease_id != outcome.lease.lease_id
                or leased.attempt_count != outcome.lease.attempt_count
                or leased.retry_generation != outcome.lease.retry_generation
                or case.status != receipt.completion_case_status
                or case.current_backlog_item_id != expected_current_backlog
                or not case.evidence_packs
                or case.evidence_packs[-1].pack_id != target.current_evidence_pack_id
                or case.evidence_packs[-1].version != target.current_evidence_pack_version
                or case.manifest_id != receipt.manifest_id
                or case_record.row["audit_sequence"] != receipt.completion_audit_sequence
                or audit.entry_hash != receipt.completion_audit_entry_hash
                or audit.after_sha256 != case_record.row["document_sha256"]
                or audit.action.value != "CASE_STATE_CHANGED"
                or audit.object_ref.kind != ArtifactKind.BACKLOG_ITEM
                or audit.object_ref.artifact_id != outcome.lease.item_id
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.HEARING_BACKLOG_COMPLETION,
                    receipt_id,
                    "BACKLOG_COMPLETION_BIDIRECTIONAL_CLOSURE_MISMATCH",
                )

    @staticmethod
    def _validate_foreign_camera_boundary(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> None:
        packs = _base_documents(base, M4ProjectionArtifactKind.EVIDENCE_PACK, EvidencePack)
        requests = _typed_map(records, M4ProjectionArtifactKind.MODEL_REQUEST, HearingModelRequest)
        acquired_crops = _typed_map(records, M4ProjectionArtifactKind.ACQUIRED_CROP, Crop)
        foreign_frame_ids: set[str] = set()
        for pack in packs.values():
            for result in pack.tool_results:
                parameters = result.validated_parameters
                if isinstance(parameters, OtherCameraSameTimeParameters):
                    foreign_frame_ids.update(
                        ref.artifact_id
                        for ref in result.output_refs
                        if ref.kind == ArtifactKind.FRAME
                    )
        if not foreign_frame_ids:
            return
        crop_by_id = {crop.crop_id: crop for pack in packs.values() for crop in pack.crops}
        crop_by_id.update(acquired_crops)
        for pack_id, pack in packs.items():
            if foreign_frame_ids.intersection(pack.key_frame_ids) or any(
                crop.frame_id in foreign_frame_ids for crop in pack.crops
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.EVIDENCE_PACK,
                    pack_id,
                    "FOREIGN_CAMERA_FRAME_ESCAPED_TOOL_RESULT",
                )
        for request_id, request in requests.items():
            if any(
                crop_by_id.get(media.crop_id) is not None
                and cast(Crop, crop_by_id[media.crop_id]).frame_id in foreign_frame_ids
                for media in request.media
            ):
                _reference_failure(
                    failures,
                    M4ProjectionArtifactKind.MODEL_REQUEST,
                    request_id,
                    "FOREIGN_CAMERA_MEDIA_DISCLOSURE",
                )

    @staticmethod
    def _build_roots(
        records: dict[M4ProjectionArtifactKind, list[M4Record]],
        sessions: dict[str, HearingSession],
        checkpoints: dict[str, HearingCheckpoint],
        hearing_records: dict[tuple[str, int], HearingRecord],
        base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
        failures: list[M4ArtifactAuthorityFailure],
    ) -> tuple[M4HearingAuthorityRoot, ...]:
        rounds = _typed_map(records, M4ProjectionArtifactKind.HEARING_ROUND, HearingRound)
        bindings = _typed_map(
            records,
            M4ProjectionArtifactKind.VERDICT_BINDING,
            HearingVerdictBinding,
        )
        human = _typed_map(
            records,
            M4ProjectionArtifactKind.HUMAN_REVIEW_RECEIPT,
            HearingHumanReviewReceipt,
        )
        reviews = _base_documents(
            base,
            M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
            ProceduralReview,
        )
        cases = _case_versions(base)
        result: list[M4HearingAuthorityRoot] = []
        for session_id, session in sessions.items():
            session_checkpoints = sorted(
                (item for item in checkpoints.values() if item.hearing_session_id == session_id),
                key=lambda item: item.version,
            )
            current_entry = _current_case(cases, session.case_id)
            if not session_checkpoints or current_entry is None:
                continue
            current_revision, current = current_entry
            head = session_checkpoints[-1]
            session_rounds = sorted(
                (item for item in rounds.values() if item.hearing_session_id == session_id),
                key=lambda item: item.round_index,
            )
            session_bindings = sorted(
                (item for item in bindings.values() if item.hearing_session_id == session_id),
                key=lambda item: item.judge_round_index,
            )
            latest_binding = session_bindings[-1] if session_bindings else None
            session_records = sorted(
                (
                    item
                    for (hearing_id, _), item in hearing_records.items()
                    if hearing_id == session_id
                ),
                key=lambda item: item.version,
            )
            latest_record = session_records[-1] if session_records else None
            latest_review = None
            if latest_binding is not None:
                latest_review = next(
                    (
                        item
                        for item in reviews.values()
                        if item.reviewed_verdict_id == latest_binding.verdict_id
                        and item.reviewed_verdict_version == latest_binding.verdict_version
                    ),
                    None,
                )
            human_id = head.human_review_receipt_id
            if human_id is not None and human_id not in human:
                human_id = None
            root_projection = [
                "m4-hearing-authority-root",
                1,
                session.session_sha256,
                [item.checkpoint_sha256 for item in session_checkpoints],
                [item.round_id for item in session_rounds],
                (
                    [latest_record.record_id, latest_record.record_sha256]
                    if latest_record is not None
                    else None
                ),
                [item.binding_id for item in session_bindings],
                current.semantic_case_hash,
                head.current_evidence_pack_id,
                head.current_evidence_pack_version,
                latest_review.review_id if latest_review is not None else None,
                human_id,
            ]
            result.append(
                M4HearingAuthorityRoot(
                    hearing_session_id=session_id,
                    case_id=session.case_id,
                    current_case_revision=current_revision,
                    current_evidence_pack_id=head.current_evidence_pack_id,
                    current_evidence_pack_version=head.current_evidence_pack_version,
                    latest_checkpoint_id=head.checkpoint_id,
                    latest_checkpoint_version=head.version,
                    latest_round_id=session_rounds[-1].round_id if session_rounds else None,
                    latest_record_id=(latest_record.record_id if latest_record else None),
                    latest_record_version=(latest_record.version if latest_record else None),
                    latest_record_sha256=(latest_record.record_sha256 if latest_record else None),
                    latest_verdict_id=(latest_binding.verdict_id if latest_binding else None),
                    latest_review_id=(latest_review.review_id if latest_review else None),
                    human_review_receipt_id=human_id,
                    root_sha256=hashlib.sha256(
                        canonical_json(root_projection).encode("utf-8")
                    ).hexdigest(),
                )
            )
        return tuple(sorted(result, key=lambda item: item.hearing_session_id))


def _typed_map(
    records: dict[M4ProjectionArtifactKind, list[M4Record]],
    kind: M4ProjectionArtifactKind,
    expected: type[Any],
) -> dict[str, Any]:
    return {
        item.artifact_id: item.document
        for item in records[kind]
        if isinstance(item.document, expected)
    }


def _base_documents(
    base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
    kind: M4ProjectionArtifactKind,
    expected: type[Any],
) -> dict[str, Any]:
    return {
        identity: item.document
        for identity, item in base[kind].items()
        if isinstance(item.document, expected)
    }


def _case_versions(
    base: dict[M4ProjectionArtifactKind, dict[str, _BaseRecord]],
) -> dict[tuple[str, int], Case]:
    return {
        (case.case_id, int(item.row["revision"])): case
        for item in base[M4ProjectionArtifactKind.CASE_VERSION].values()
        if isinstance((case := item.document), Case)
    }


def _current_case(
    cases: dict[tuple[str, int], Case],
    case_id: str,
) -> tuple[int, Case] | None:
    matches = [
        (revision, case)
        for (candidate_id, revision), case in cases.items()
        if candidate_id == case_id
    ]
    return max(matches, key=lambda item: item[0]) if matches else None


def _load_base_row(
    row: sqlite3.Row,
    kind: M4ProjectionArtifactKind,
    json_column: str,
    hash_column: str,
    model: type[BaseModel],
    failures: list[M4ArtifactAuthorityFailure],
) -> _BaseRecord | None:
    identity = row["projection_identity"]
    raw = row[json_column]
    expected_hash = row[hash_column]
    if (
        not isinstance(identity, str)
        or not isinstance(raw, str)
        or not isinstance(expected_hash, str)
    ):
        _base_failure(
            failures,
            kind,
            identity if isinstance(identity, str) else None,
            "BASE_DOCUMENT_COLUMN_INVALID",
        )
        return None
    try:
        document = model.model_validate_json(raw)
    except (ValidationError, TypeError, ValueError, UnicodeError):
        _base_failure(failures, kind, identity, "BASE_DOCUMENT_CONTRACT_INVALID")
        return None
    canonical = canonical_json(document.model_dump(mode="json"))
    if canonical != raw or hashlib.sha256(raw.encode("utf-8")).hexdigest() != expected_hash:
        _base_failure(failures, kind, identity, "BASE_DOCUMENT_INTEGRITY_INVALID")
        return None
    if not _base_index_matches(row, kind, identity, document):
        _base_failure(failures, kind, identity, "BASE_INDEX_BINDING_MISMATCH")
        return None
    return _BaseRecord(kind, identity, document, canonical, row)


def _base_index_matches(
    row: sqlite3.Row,
    kind: M4ProjectionArtifactKind,
    identity: str,
    document: BaseModel,
) -> bool:
    values = dict(row)
    if isinstance(document, Case):
        return (
            values.get("run_id") == document.run_id
            and values.get("case_id") == document.case_id
            and values.get("status") == document.status.value
            and identity == f"{document.case_id}-revision-{int(values.get('revision', -1)):06d}"
        )
    if isinstance(document, EvidencePack):
        return (
            identity == document.pack_id == values.get("pack_id")
            and values.get("run_id") == document.run_id
            and values.get("case_id") == document.case_id
            and values.get("version") == document.version
            and values.get("complete") == int(document.complete)
            and values.get("pack_input_sha256") == document.pack_input_sha256
            and values.get("closure_input_sha256") == document.closure_input_sha256
            and values.get("manifest_id") == document.manifest_id
        )
    if isinstance(document, ScreeningResult):
        return (
            identity == document.screening_id == values.get("screening_id")
            and values.get("run_id") == document.run_id
            and values.get("case_id") == document.case_id
            and values.get("version") == document.version
            and values.get("evidence_pack_id") == document.evidence_pack_id
            and values.get("evidence_pack_version") == document.evidence_pack_version
            and values.get("manifest_id") == document.manifest_id
        )
    if isinstance(document, Verdict):
        return (
            identity == document.verdict_id == values.get("verdict_id")
            and values.get("run_id") == document.run_id
            and values.get("case_id") == document.case_id
            and values.get("version") == document.version
            and values.get("evidence_pack_id") == document.evidence_pack_id
            and values.get("evidence_pack_version") == document.evidence_pack_version
            and values.get("manifest_id") == document.manifest_id
        )
    if isinstance(document, ProceduralReview):
        return (
            identity == document.review_id == values.get("review_id")
            and values.get("run_id") == document.run_id
            and values.get("case_id") == document.case_id
            and values.get("version") == document.version
            and values.get("reviewed_verdict_id") == document.reviewed_verdict_id
            and values.get("reviewed_verdict_version") == document.reviewed_verdict_version
            and values.get("manifest_id") == document.manifest_id
        )
    if isinstance(document, BacklogItem):
        if kind == M4ProjectionArtifactKind.BACKLOG_ITEM:
            return (
                identity == document.item_id == values.get("item_id")
                and values.get("run_id") == document.run_id
                and values.get("case_id") == document.case_id
                and values.get("stage") == document.stage.value
                and values.get("role")
                == (document.role.value if document.role is not None else None)
                and values.get("reason_code") == document.reason_code.value
                and values.get("stage_input_kind") == document.stage_input_ref.kind.value
                and values.get("stage_input_id") == document.stage_input_ref.artifact_id
                and values.get("stage_input_sha256") == document.stage_input_sha256
                and values.get("max_attempts") == document.max_attempts
                and values.get("manifest_id") == document.manifest_id
            )
        version = values.get("version")
        return (
            values.get("run_id") == document.run_id
            and values.get("item_id") == document.item_id
            and isinstance(version, int)
            and not isinstance(version, bool)
            and version > 0
            and values.get("status") == document.status.value
            and values.get("attempt_count") == document.attempt_count
            and values.get("retry_generation") == document.retry_generation
            and values.get("lease_id") == document.lease_id
            and values.get("lease_owner_sha256") == document.lease_owner_sha256
            and values.get("lease_expires_at")
            == (
                document.lease_expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                if document.lease_expires_at is not None
                else None
            )
            and identity == f"{document.item_id}-version-{version:06d}"
        )
    if isinstance(document, FrameRef):
        return (
            identity == document.frame_id == values.get("frame_id")
            and values.get("camera_id") == document.camera_id
            and values.get("stream_id") == document.stream_id
            and values.get("frame_index") == document.frame_index
            and values.get("fps_num") == document.fps_num
            and values.get("fps_den") == document.fps_den
            and values.get("width") == document.width
            and values.get("height") == document.height
            and values.get("content_sha256") == document.content_sha256
        )
    if isinstance(document, Detection):
        return (
            identity == document.detection_id == values.get("detection_id")
            and values.get("frame_id") == document.frame_id
            and values.get("label") == document.label
            and values.get("detector_manifest_id") == document.model_manifest_id
        )
    if isinstance(document, AuditEntry):
        return (
            values.get("run_id") == document.run_id
            and values.get("sequence") == document.sequence
            and values.get("manifest_id") == document.manifest_id
            and values.get("actor") == document.actor
            and values.get("action") == document.action.value
            and values.get("object_kind") == document.object_ref.kind.value
            and values.get("object_id") == document.object_ref.artifact_id
            and values.get("before_sha256") == document.before_sha256
            and values.get("after_sha256") == document.after_sha256
            and values.get("recorded_at") == document.recorded_at
            and values.get("prev_entry_hash") == document.prev_entry_hash
            and values.get("entry_hash") == document.entry_hash
            and identity == f"{document.sequence:012d}"
        )
    return False


def _call_closure_matches(
    request: HearingModelRequest,
    response: HearingModelResponse,
    cache: HearingModelCacheEntry,
    usage: HearingUsageReceipt,
) -> bool:
    return (
        response.run_id == request.run_id
        and response.case_id == request.case_id
        and response.hearing_session_id == request.hearing_session_id
        and response.round_index == request.round_index
        and response.prior_acquisition_rounds == request.prior_acquisition_rounds
        and response.prior_rework_rounds == request.prior_rework_rounds
        and response.current_evidence_pack_id == request.current_evidence_pack_id
        and response.current_evidence_pack_version == request.current_evidence_pack_version
        and response.request_id == request.request_id
        and response.request_sha256 == request.request_sha256
        and response.cache_key == request.cache_key
        and response.role == request.role
        and response.attempt_index == request.attempt_index
        and response.model_manifest_id == request.model_manifest_id
        and response.manifest_id == request.manifest_id
        and cache.request_id == request.request_id
        and cache.response_id == response.response_id
        and cache.response_content_sha256 == response.content_sha256
        and usage.request_ref.artifact_id == request.request_id
        and usage.response_ref.artifact_id == response.response_id
        and usage.role == request.role
        and usage.run_id == request.run_id
        and usage.case_id == request.case_id
        and usage.hearing_session_id == request.hearing_session_id
        and usage.round_index == request.round_index
        and usage.manifest_id == request.manifest_id
        and usage.input_images == len(request.media)
        and usage.input_pixels == sum(item.width * item.height for item in request.media)
        and usage.input_tokens == response.input_tokens
        and usage.output_tokens == response.output_tokens
        and usage.latency_ms == response.latency_ms
        and usage.estimated_cost
        == request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
        and response.size_bytes <= request.budget.max_response_bytes
        and response.input_tokens <= request.budget.max_input_tokens
        and response.output_tokens <= request.budget.max_output_tokens
        and request.budget.allows_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
    )


def _usage_matches_call(
    usage: HearingUsageReceipt,
    request: HearingModelRequest,
    response: HearingModelResponse,
) -> bool:
    return (
        usage.request_ref.artifact_id == request.request_id
        and usage.response_ref.artifact_id == response.response_id
        and response.request_id == request.request_id
        and usage.run_id == request.run_id == response.run_id
        and usage.case_id == request.case_id == response.case_id
        and usage.hearing_session_id == request.hearing_session_id == response.hearing_session_id
        and usage.round_index == request.round_index == response.round_index
        and usage.role == request.role == response.role
        and usage.input_images == len(request.media)
        and usage.input_pixels == sum(item.width * item.height for item in request.media)
        and usage.input_tokens == response.input_tokens
        and usage.output_tokens == response.output_tokens
        and usage.latency_ms == response.latency_ms
        and usage.estimated_cost
        == request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
        and usage.manifest_id == request.manifest_id == response.manifest_id
    )


def _usage_row_matches_claim(
    usage_record: M4Record,
    claim_record: M4Record,
    request: HearingModelRequest,
    usage: HearingUsageReceipt,
) -> bool:
    """Bind usage-only SQLite metadata to the exact durable call claim."""

    cycle_scope_id = usage_record.row["cycle_scope_id"]
    cycle_scope_sha256 = usage_record.row["cycle_scope_sha256"]
    accounted_at = usage_record.row["accounted_at"]
    completed_at = claim_record.row["completed_at"]
    retries = usage_record.row["retries"]
    takeover_count = claim_record.row["takeover_count"]
    if (
        not isinstance(cycle_scope_id, str)
        or not isinstance(cycle_scope_sha256, str)
        or not isinstance(accounted_at, str)
        or not isinstance(completed_at, str)
        or not isinstance(retries, int)
        or isinstance(retries, bool)
        or not isinstance(takeover_count, int)
        or isinstance(takeover_count, bool)
    ):
        return False
    return (
        cycle_scope_id == request.cycle_scope_id
        and cycle_scope_sha256 == request.cycle_scope_sha256
        and accounted_at == completed_at
        and retries == takeover_count
        and usage.retry_count == takeover_count
    )


def _role_output_matches_call(
    output: HearingRoleOutput,
    request: HearingModelRequest,
    response: HearingModelResponse,
    parse: HearingModelParseReceipt,
    retrieval: HearingPrecedentRetrievalReceipt,
) -> bool:
    return (
        output.request_ref.artifact_id == request.request_id
        and output.response_ref.artifact_id == response.response_id
        and output.parse_receipt_ref.artifact_id == parse.parse_receipt_id
        and _parse_matches(parse, request, response)
        and parse.status.value == "PARSED"
        and parse.parsed_payload_sha256 == output.payload.payload_sha256
        and output.run_id == request.run_id == retrieval.run_id
        and output.case_id == request.case_id == retrieval.case_id
        and output.hearing_session_id == request.hearing_session_id == retrieval.hearing_session_id
        and output.round_index == request.round_index == retrieval.round_index
        and output.prior_acquisition_rounds
        == request.prior_acquisition_rounds
        == retrieval.prior_acquisition_rounds
        and output.prior_rework_rounds
        == request.prior_rework_rounds
        == retrieval.prior_rework_rounds
        and output.current_evidence_pack_id
        == request.current_evidence_pack_id
        == retrieval.current_evidence_pack_id
        and output.current_evidence_pack_version
        == request.current_evidence_pack_version
        == retrieval.current_evidence_pack_version
        and output.role == request.role == response.role == parse.role
        and output.prompt_manifest == request.prompt_manifest
        and output.model_manifest_id == request.model_manifest_id
        and output.prosecutor_output_id == _optional_artifact_id(request.prosecutor_output_ref)
        and output.defender_output_id == _optional_artifact_id(request.defender_output_ref)
        and output.precedent_retrieval_degraded == request.precedent_retrieval_degraded
        and output.precedent_retrieval_degraded == (retrieval.status.value == "DEGRADED")
        and output.precedent_retrieval_receipt_id == retrieval.receipt_id
        and output.precedent_retrieval_receipt_sha256 == retrieval.receipt_sha256
        and request.precedent_retrieval_receipt_id == retrieval.receipt_id
        and request.precedent_retrieval_receipt_sha256 == retrieval.receipt_sha256
        and output.initial_trigger_review_ref == request.initial_trigger_review_ref
        and output.initial_defect_codes == request.initial_defect_codes
        and output.rework_review_ref == request.rework_review_ref
        and output.rework_defect_codes == request.rework_defect_codes
        and output.manifest_id
        == request.manifest_id
        == response.manifest_id
        == parse.manifest_id
        == retrieval.manifest_id
    )


def _optional_artifact_id(reference: Any) -> str | None:
    return reference.artifact_id if reference is not None else None


def _same_backlog_identity(left: BacklogItem, right: BacklogItem) -> bool:
    return (
        left.item_id == right.item_id
        and left.run_id == right.run_id
        and left.case_id == right.case_id
        and left.stage == right.stage
        and left.role == right.role
        and left.reason_code == right.reason_code
        and left.stage_input_ref == right.stage_input_ref
        and left.stage_input_sha256 == right.stage_input_sha256
        and left.max_attempts == right.max_attempts
        and left.manifest_id == right.manifest_id
    )


def _legal_backlog_transition(previous: BacklogItem, current: BacklogItem) -> bool:
    if previous.status == BacklogStatus.PENDING:
        return (
            current.status == BacklogStatus.LEASED
            and current.attempt_count == previous.attempt_count + 1
            and current.retry_generation == previous.retry_generation
        )
    if previous.status != BacklogStatus.LEASED:
        return False
    if current.status not in {
        BacklogStatus.PENDING,
        BacklogStatus.COMPLETED,
        BacklogStatus.EXHAUSTED,
    }:
        return False
    if current.attempt_count != previous.attempt_count:
        return False
    return current.retry_generation == previous.retry_generation or (
        current.status == BacklogStatus.PENDING
        and current.retry_generation == previous.retry_generation + 1
    )


def _response_row_matches_request(
    record: M4Record,
    request: HearingModelRequest,
) -> bool:
    retry_generation = (
        request.backlog_retry_context.retry_generation
        if request.backlog_retry_context is not None
        else 0
    )
    row = record.row
    return bool(
        row["cycle_scope_id"] == request.cycle_scope_id
        and row["cycle_scope_sha256"] == request.cycle_scope_sha256
        and row["purpose"] == ("ROLE_CALL" if request.attempt_index == 0 else "STRUCTURE_REPAIR")
        and row["retry_generation"] == retry_generation
    )


def _parse_matches(
    receipt: HearingModelParseReceipt,
    request: HearingModelRequest,
    response: HearingModelResponse,
) -> bool:
    return (
        receipt.run_id == request.run_id == response.run_id
        and receipt.case_id == request.case_id == response.case_id
        and receipt.hearing_session_id == request.hearing_session_id == response.hearing_session_id
        and receipt.round_index == request.round_index == response.round_index
        and receipt.role == request.role == response.role
        and receipt.attempt_index == request.attempt_index == response.attempt_index
        and receipt.request_id == request.request_id == response.request_id
        and receipt.request_sha256 == request.request_sha256 == response.request_sha256
        and receipt.response_id == response.response_id
        and receipt.response_content_sha256 == response.content_sha256
        and receipt.output_schema_sha256 == request.prompt_manifest.output_schema_sha256
        and receipt.manifest_id == request.manifest_id == response.manifest_id
    )


def _document_identity(document: object) -> str | None:
    for attribute in (
        "receipt_id",
        "output_id",
        "request_id",
        "authority_id",
        "binding_id",
    ):
        value = getattr(document, attribute, None)
        if isinstance(value, str):
            return value
    return None


def _record_failure(
    failures: list[M4ArtifactAuthorityFailure],
    record: M4Record,
    reason_code: str,
) -> None:
    failure = M4ArtifactAuthorityFailure(
        failure_type=M4AuthorityFailureType.REFERENCE_INVALID,
        inventory_kind=record.kind,
        record_identity_sha256=record.identity,
        artifact_id=record.artifact_id,
        reason_code=reason_code,
    )
    if failure not in failures:
        failures.append(failure)


def _reference_failure(
    failures: list[M4ArtifactAuthorityFailure],
    kind: M4ProjectionArtifactKind,
    artifact_id: str,
    reason_code: str,
) -> None:
    identity = hashlib.sha256(
        canonical_json(["m4-reference-failure", 1, kind.value, artifact_id]).encode("utf-8")
    ).hexdigest()
    failure = M4ArtifactAuthorityFailure(
        failure_type=M4AuthorityFailureType.REFERENCE_INVALID,
        inventory_kind=kind,
        record_identity_sha256=identity,
        artifact_id=artifact_id,
        reason_code=reason_code,
    )
    if failure not in failures:
        failures.append(failure)


def _base_failure(
    failures: list[M4ArtifactAuthorityFailure],
    kind: M4ProjectionArtifactKind,
    artifact_id: str | None,
    reason_code: str,
) -> None:
    controlled = artifact_id or "unknown"
    _reference_failure(failures, kind, controlled, reason_code)


__all__ = ["M4ArtifactReferenceValidator", "M4RelationValidation"]
