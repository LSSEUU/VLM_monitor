"""Bounded same-snapshot M4 Verdict/Gate authority for the first terminal route.

The first opened route is deliberately narrow: one successful hearing cycle,
one Verdict, and one passing ProceduralReview.  All row identities and byte
budgets are frozen before any JSON body is admitted.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import cast

from pydantic import BaseModel, ValidationError

from labcourt.application.hearing_record import (
    HearingRecordBuildError,
    build_hearing_record,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind, CaseStatus
from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingCycleScope,
    HearingPrecedentRetrievalReceipt,
    HearingRecord,
    HearingRound,
    HearingSession,
    HearingVerdictBinding,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument
from labcourt.ports.m6_model_calls import M6M4ModelCallAuthoritySnapshot
from labcourt.ports.m6_procedural_gate_authority import M6ProceduralGateHistorySnapshot

from ._readonly_m4_artifact_codec import (
    M4_TYPED_TABLES,
    M4DocumentFailure,
    M4IndexFailure,
    M4TableSpec,
    load_m4_record,
)
from ._sqlite_m6_live_read_cut import M6LiveDocumentColumn, M6LiveReader
from ._sqlite_m6_upgrade_m4_model_bodies import (
    _canonical_bytes,
    _fresh_plan,
    _load_support,
)
from ._sqlite_m6_upgrade_m4_model_documents import M6SQLiteM4ModelDocumentError
from ._sqlite_m6_upgrade_m4_model_plan import (
    MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES,
    MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4ModelDocumentsPlan,
    M6SQLiteM4SupportDocumentRoute,
    M6SQLiteM4SupportDocumentSlot,
    M6SQLiteM4SupportRoute,
    _M6SQLiteM4MetadataFailure,
    _plan_is_consistent,
)
from ._sqlite_m6_upgrade_m4_model_primitives import (
    _active,
    _fail,
    _integer,
    _optional_text,
    _row_identity,
    _sha256,
    _support_pair,
    _text,
)
from ._sqlite_m6_upgrade_m4_model_rows import (
    _rows,
    _size_projection,
    read_hearing_support_rows,
)


class M6SQLiteM4GateDocumentRoute(StrEnum):
    VERDICT_BINDING = "m4_hearing_verdict_bindings.binding_json"
    VERDICT = "verdicts.verdict_json"
    PROCEDURAL_REVIEW = "procedural_reviews.review_json"


_GATE_ROUTE_RANK = {value: index for index, value in enumerate(M6SQLiteM4GateDocumentRoute)}
_LIVE_GATE_ROUTE = {
    M6SQLiteM4GateDocumentRoute.VERDICT_BINDING: (
        M6LiveDocumentColumn.M4_HEARING_VERDICT_BINDING_DOCUMENT
    ),
    M6SQLiteM4GateDocumentRoute.VERDICT: M6LiveDocumentColumn.M4_VERDICT_DOCUMENT,
    M6SQLiteM4GateDocumentRoute.PROCEDURAL_REVIEW: (
        M6LiveDocumentColumn.M4_PROCEDURAL_REVIEW_DOCUMENT
    ),
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and not any(character not in "0123456789abcdef" for character in value)
    )


def _require_sha256(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return cast(str, value)


def _document_sha256(value: BaseModel) -> str:
    return hashlib.sha256(canonical_json(value.model_dump(mode="json")).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class M6SQLiteM4GateDocumentSlot:
    route: M6SQLiteM4GateDocumentRoute
    rowid: int
    artifact_id: str
    document_sha256: str
    document_bytes: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        if type(self.route) is not M6SQLiteM4GateDocumentRoute:
            raise TypeError("Gate document route must be exact")
        if type(self.rowid) is not int or self.rowid <= 0:
            raise ValueError("Gate document rowid must be positive")
        _require_sha256(self.artifact_id, "Gate artifact_id")
        _require_sha256(self.document_sha256, "Gate document_sha256")
        if (
            type(self.document_bytes) is not int
            or self.document_bytes <= 0
            or self.document_bytes > MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES
        ):
            raise ValueError("Gate document byte length is invalid")
        _require_sha256(self.index_identity_sha256, "Gate index identity")

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return _GATE_ROUTE_RANK[self.route], self.artifact_id, self.rowid


@dataclass(frozen=True, slots=True)
class M6SQLiteM4GateBindingPlan:
    hearing_id: str
    hearing_record_id: str
    hearing_record_version: int
    hearing_record_sha256: str
    cycle_scope_id: str
    round_id: str
    judge_round_index: int
    evidence_pack_id: str
    evidence_pack_version: int
    verdict_id: str
    verdict_version: int
    review_id: str
    review_version: int
    prosecutor_output_id: str
    defender_output_id: str
    judge_output_id: str

    def __post_init__(self) -> None:
        for label, sha_value in (
            ("hearing_id", self.hearing_id),
            ("hearing_record_id", self.hearing_record_id),
            ("hearing_record_sha256", self.hearing_record_sha256),
            ("cycle_scope_id", self.cycle_scope_id),
            ("round_id", self.round_id),
            ("evidence_pack_id", self.evidence_pack_id),
            ("verdict_id", self.verdict_id),
            ("review_id", self.review_id),
            ("prosecutor_output_id", self.prosecutor_output_id),
            ("defender_output_id", self.defender_output_id),
            ("judge_output_id", self.judge_output_id),
        ):
            _require_sha256(sha_value, f"Gate binding {label}")
        for label, positive_value in (
            ("hearing_record_version", self.hearing_record_version),
            ("judge_round_index", self.judge_round_index),
            ("evidence_pack_version", self.evidence_pack_version),
            ("verdict_version", self.verdict_version),
            ("review_version", self.review_version),
        ):
            if type(positive_value) is not int or positive_value <= 0:
                raise ValueError(f"Gate binding {label} must be positive")


def _support_projection(slot: M6SQLiteM4SupportDocumentSlot) -> list[object]:
    return [
        slot.route,
        slot.rowid,
        slot.artifact_id,
        slot.commitment_kind,
        slot.body_commitment_sha256,
        slot.document_bytes,
        slot.index_identity_sha256,
    ]


def _gate_projection(slot: M6SQLiteM4GateDocumentSlot) -> list[object]:
    return [
        slot.route,
        slot.rowid,
        slot.artifact_id,
        slot.document_sha256,
        slot.document_bytes,
        slot.index_identity_sha256,
    ]


def _binding_projection(value: M6SQLiteM4GateBindingPlan) -> list[object]:
    return [
        value.hearing_id,
        value.hearing_record_id,
        value.hearing_record_version,
        value.hearing_record_sha256,
        value.cycle_scope_id,
        value.round_id,
        value.judge_round_index,
        value.evidence_pack_id,
        value.evidence_pack_version,
        value.verdict_id,
        value.verdict_version,
        value.review_id,
        value.review_version,
        value.prosecutor_output_id,
        value.defender_output_id,
        value.judge_output_id,
    ]


@dataclass(frozen=True, slots=True)
class M6SQLiteM4GateDocumentsPlan:
    """Body-free commitment to one first-slice successful M4/Gate graph."""

    upstream_m4_model_plan: M6SQLiteM4ModelDocumentsPlan
    support_document_slots: tuple[M6SQLiteM4SupportDocumentSlot, ...]
    gate_document_slots: tuple[M6SQLiteM4GateDocumentSlot, ...]
    binding: M6SQLiteM4GateBindingPlan
    planned_document_bytes: int = field(init=False)
    plan_identity_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        upstream = self.upstream_m4_model_plan
        if type(upstream) is not M6SQLiteM4ModelDocumentsPlan or not _plan_is_consistent(upstream):
            raise TypeError("Gate plan requires an exact upstream M4 model plan")
        if type(self.support_document_slots) is not tuple or any(
            type(item) is not M6SQLiteM4SupportDocumentSlot for item in self.support_document_slots
        ):
            raise TypeError("Gate support slots must be an exact typed tuple")
        if type(self.gate_document_slots) is not tuple or any(
            type(item) is not M6SQLiteM4GateDocumentSlot for item in self.gate_document_slots
        ):
            raise TypeError("Gate canonical slots must be an exact typed tuple")
        if type(self.binding) is not M6SQLiteM4GateBindingPlan:
            raise TypeError("Gate binding plan must be exact")
        support = tuple(
            M6SQLiteM4SupportDocumentSlot(
                route=item.route,
                rowid=item.rowid,
                artifact_id=item.artifact_id,
                body_commitment_sha256=item.body_commitment_sha256,
                document_bytes=item.document_bytes,
                index_identity_sha256=item.index_identity_sha256,
            )
            for item in self.support_document_slots
        )
        gate = tuple(
            M6SQLiteM4GateDocumentSlot(
                route=item.route,
                rowid=item.rowid,
                artifact_id=item.artifact_id,
                document_sha256=item.document_sha256,
                document_bytes=item.document_bytes,
                index_identity_sha256=item.index_identity_sha256,
            )
            for item in self.gate_document_slots
        )
        binding = replace(self.binding)
        object.__setattr__(self, "support_document_slots", support)
        object.__setattr__(self, "gate_document_slots", gate)
        object.__setattr__(self, "binding", binding)
        if support != tuple(sorted(support, key=lambda item: item.sort_key)) or gate != tuple(
            sorted(gate, key=lambda item: item.sort_key)
        ):
            raise ValueError("Gate document slots must use stable order")
        row_routes = tuple((item.route.value, item.rowid) for item in support) + tuple(
            (item.route.value, item.rowid) for item in gate
        )
        if len(set(row_routes)) != len(row_routes):
            raise ValueError("Gate document row routes must be unique")
        expected_support_routes = {
            M6SQLiteM4SupportDocumentRoute.HEARING_SESSION,
            M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE,
            M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL,
            M6SQLiteM4SupportDocumentRoute.HEARING_ROUND,
            M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT,
        }
        if (
            {item.route for item in support} != expected_support_routes
            or len(support) != len(expected_support_routes) + 1
            or sum(
                item.route == M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT for item in support
            )
            != 2
            or any(
                sum(item.route == route for item in support) != 1
                for route in expected_support_routes
                if route != M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT
            )
            or {item.route for item in gate} != set(M6SQLiteM4GateDocumentRoute)
            or len(gate) != len(M6SQLiteM4GateDocumentRoute)
        ):
            raise ValueError("Gate plan requires exactly one document on every first-slice route")
        support_by_route = {
            item.route: item
            for item in support
            if item.route != M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT
        }
        gate_by_route = {item.route: item for item in gate}
        if (
            support_by_route[M6SQLiteM4SupportDocumentRoute.HEARING_SESSION].artifact_id
            != binding.hearing_id
            or support_by_route[M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE].artifact_id
            != binding.cycle_scope_id
            or support_by_route[M6SQLiteM4SupportDocumentRoute.HEARING_ROUND].artifact_id
            != binding.round_id
            or gate_by_route[M6SQLiteM4GateDocumentRoute.VERDICT].artifact_id != binding.verdict_id
            or gate_by_route[M6SQLiteM4GateDocumentRoute.PROCEDURAL_REVIEW].artifact_id
            != binding.review_id
        ):
            raise ValueError("Gate plan slots cross their relational binding")
        embedded = upstream.selected_case
        verdicts = {item.verdict_id: item for item in embedded.verdicts}
        reviews = {item.review_id: item for item in embedded.procedural_reviews}
        verdict = verdicts.get(binding.verdict_id)
        review = reviews.get(binding.review_id)
        if (
            len(verdicts) != 1
            or len(reviews) != 1
            or verdict is None
            or review is None
            or verdict.version != binding.verdict_version
            or review.version != binding.review_version
            or review.reviewed_verdict_id != verdict.verdict_id
            or review.reviewed_verdict_version != verdict.version
            or review.evidence_pack_id != binding.evidence_pack_id
            or review.evidence_pack_version != binding.evidence_pack_version
            or not review.passed
        ):
            raise ValueError("Gate plan does not close the selected Case Verdict/Review")
        document_bytes = sum(item.document_bytes for item in support) + sum(
            item.document_bytes for item in gate
        )
        if document_bytes > MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES:
            raise ValueError("Gate plan exceeds the document byte budget")
        projection = [
            "m6-sqlite-m4-gate-documents-plan",
            1,
            upstream.plan_identity_sha256,
            [_support_projection(item) for item in support],
            [_gate_projection(item) for item in gate],
            _binding_projection(binding),
            document_bytes,
        ]
        identity = hashlib.sha256(canonical_json(projection).encode("utf-8")).hexdigest()
        object.__setattr__(self, "planned_document_bytes", document_bytes)
        object.__setattr__(self, "plan_identity_sha256", identity)


def _plan_is_consistent_gate(value: object) -> bool:
    if type(value) is not M6SQLiteM4GateDocumentsPlan:
        return False
    try:
        controlled = M6SQLiteM4GateDocumentsPlan(
            upstream_m4_model_plan=value.upstream_m4_model_plan,
            support_document_slots=value.support_document_slots,
            gate_document_slots=value.gate_document_slots,
            binding=value.binding,
        )
    except (AttributeError, TypeError, ValueError, ValidationError, UnicodeError):
        return False
    return controlled == value and controlled.plan_identity_sha256 == value.plan_identity_sha256


@dataclass(frozen=True, slots=True)
class M6SQLiteM4GateAuthoritySnapshot:
    source_identity_sha256: str
    upstream_m4_model_plan_identity_sha256: str
    run_id: str
    case_id: str
    manifest_id: str
    hearing_sessions: tuple[HearingSession, ...]
    hearing_cycles: tuple[HearingCycleScope, ...]
    retrieval_receipts: tuple[HearingPrecedentRetrievalReceipt, ...]
    hearing_rounds: tuple[HearingRound, ...]
    completed_checkpoints: tuple[HearingCheckpoint, ...]
    hearing_records: tuple[HearingRecord, ...]
    verdict_bindings: tuple[HearingVerdictBinding, ...]
    verdicts: tuple[Verdict, ...]
    procedural_reviews: tuple[ProceduralReview, ...]
    documents: tuple[M6HistoricalAuthorityDocument, ...]

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "Gate snapshot identity")
        _require_sha256(
            self.upstream_m4_model_plan_identity_sha256,
            "Gate upstream M4 plan identity",
        )
        if type(self.run_id) is not str or not self.run_id or type(self.case_id) is not str:
            raise TypeError("Gate snapshot scope must use non-empty strings")
        _require_sha256(self.manifest_id, "Gate snapshot manifest_id")
        groups: tuple[tuple[tuple[object, ...], type[object]], ...] = (
            (self.hearing_sessions, HearingSession),
            (self.hearing_cycles, HearingCycleScope),
            (self.retrieval_receipts, HearingPrecedentRetrievalReceipt),
            (self.hearing_rounds, HearingRound),
            (self.completed_checkpoints, HearingCheckpoint),
            (self.hearing_records, HearingRecord),
            (self.verdict_bindings, HearingVerdictBinding),
            (self.verdicts, Verdict),
            (self.procedural_reviews, ProceduralReview),
            (self.documents, M6HistoricalAuthorityDocument),
        )
        if any(
            type(values) is not tuple or any(type(item) is not expected for item in values)
            for values, expected in groups
        ):
            raise TypeError("Gate snapshot inventories must be exact typed tuples")
        if any(len(values) != 1 for values, _expected in groups[:-1]):
            raise ValueError("Gate snapshot first slice requires one authority per semantic route")
        if self.documents != tuple(sorted(self.documents, key=lambda item: item.sort_key)):
            raise ValueError("Gate snapshot documents must use stable order")


def _gate_document_bytes(
    connection: M6LiveReader,
    row: sqlite3.Row,
    route: M6SQLiteM4GateDocumentRoute,
) -> int:
    if row["gate_document_type"] != "text":
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    rowid = row["gate_rowid"]
    if type(rowid) is not int or rowid <= 0:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    value = row["gate_document_bytes"]
    if value is None:
        value = connection.document_octet_length(_LIVE_GATE_ROUTE[route], rowid)
    if type(value) is not int or value <= 0:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    if value > MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return value


def _gate_slot(
    connection: M6LiveReader,
    row: sqlite3.Row,
    *,
    route: M6SQLiteM4GateDocumentRoute,
    artifact_id: str,
    document_sha256: str,
) -> M6SQLiteM4GateDocumentSlot:
    try:
        return M6SQLiteM4GateDocumentSlot(
            route=route,
            rowid=_integer(row, "gate_rowid", minimum=1),
            artifact_id=artifact_id,
            document_sha256=document_sha256,
            document_bytes=_gate_document_bytes(connection, row, route),
            index_identity_sha256=_row_identity(row, route.value),
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)


def _read_gate_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
    binding_size = _size_projection("binding_json", "gate_document_bytes")
    verdict_size = _size_projection("verdict_json", "gate_document_bytes")
    review_size = _size_projection("review_json", "gate_document_bytes")
    scope = (run_id, case_id)
    bindings = _rows(
        connection,
        f"""
        SELECT rowid AS gate_rowid, run_id, binding_id, hearing_id,
               hearing_record_id, hearing_record_version,
               hearing_record_sha256, cycle_scope_id, cycle_scope_sha256,
               round_id, judge_round_index, case_id, evidence_pack_id,
               evidence_pack_version, verdict_id, verdict_version,
               verdict_input_sha256, verdict_sha256, prosecutor_output_id,
               defender_output_id, judge_output_id, manifest_id,
               document_sha256, typeof(binding_json) AS gate_document_type,
               {binding_size}
        FROM m4_hearing_verdict_bindings
        WHERE run_id = ? AND case_id = ?
        ORDER BY verdict_version, binding_id
        LIMIT 2
        """,
        scope,
        limit=1,
    )
    verdicts = _rows(
        connection,
        f"""
        SELECT rowid AS gate_rowid, run_id, verdict_id, case_id, version,
               screening_id, evidence_pack_id, evidence_pack_version,
               verdict_input_sha256, verdict_sha256, manifest_id,
               audit_sequence, document_sha256,
               typeof(verdict_json) AS gate_document_type, {verdict_size}
        FROM verdicts
        WHERE run_id = ? AND case_id = ?
        ORDER BY version, verdict_id
        LIMIT 2
        """,
        scope,
        limit=1,
    )
    reviews = _rows(
        connection,
        f"""
        SELECT rowid AS gate_rowid, run_id, review_id, case_id, version,
               evidence_pack_id, evidence_pack_version, reviewed_verdict_id,
               reviewed_verdict_version, reviewed_verdict_sha256, passed,
               manifest_id, audit_sequence, document_sha256,
               typeof(review_json) AS gate_document_type, {review_size}
        FROM procedural_reviews
        WHERE run_id = ? AND case_id = ?
        ORDER BY version, review_id
        LIMIT 2
        """,
        scope,
        limit=1,
    )
    if len(bindings) != 1 or len(verdicts) != 1 or len(reviews) != 1:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return bindings[0], verdicts[0], reviews[0]


def _build_gate_plan(
    connection: M6LiveReader,
    upstream: M6SQLiteM4ModelDocumentsPlan,
) -> M6SQLiteM4GateDocumentsPlan:
    if not _plan_is_consistent(upstream):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT)
    case = upstream.selected_case
    if (
        case.status != CaseStatus.READY_FOR_ALERT_POLICY
        or len(case.screening_results) != 1
        or len(case.evidence_packs) != 1
        or len(case.verdicts) != 1
        or len(case.procedural_reviews) != 1
        or case.alerts
        or case.appeals
        or case.evidence_packs[0].version != 1
        or case.evidence_packs[0].tool_results
        or len(upstream.call_graphs) != 3
        or upstream.historical_failures
        or any(
            graph.observation.result_kind != M6LockedModelCallResultKind.RESPONSE
            or graph.observation.attempt_index != 0
            or graph.failure is not None
            for graph in upstream.call_graphs
        )
        or {graph.observation.role for graph in upstream.call_graphs}
        != {
            M6LockedModelRole.PROSECUTOR,
            M6LockedModelRole.DEFENDER,
            M6LockedModelRole.JUDGE,
        }
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    run_id = upstream.run_id
    case_id = upstream.case_id
    manifest_id = upstream.manifest_id
    rows = read_hearing_support_rows(connection, run_id=run_id, case_id=case_id)
    completed = tuple(row for row in rows.checkpoints if row["phase"] == "ROUND_COMPLETE")
    terminal = tuple(row for row in rows.checkpoints if row["phase"] == "COMPLETE")
    if (
        len(rows.sessions) != 1
        or len(rows.cycles) != 1
        or len(rows.retrievals) != 1
        or len(rows.rounds) != 1
        or len(completed) != 1
        or len(terminal) != 1
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    session_row = rows.sessions[0]
    cycle_row = rows.cycles[0]
    retrieval_row = rows.retrievals[0]
    round_row = rows.rounds[0]
    checkpoint_row = completed[0]
    terminal_checkpoint_row = terminal[0]
    support_pairs = (
        _support_pair(
            connection,
            session_row,
            row_route=M6SQLiteM4SupportRoute.HEARING_SESSION,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_SESSION,
            artifact_id=_sha256(session_row, "hearing_id"),
        ),
        _support_pair(
            connection,
            cycle_row,
            row_route=M6SQLiteM4SupportRoute.HEARING_CYCLE,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE,
            artifact_id=_sha256(cycle_row, "cycle_id"),
        ),
        _support_pair(
            connection,
            retrieval_row,
            row_route=M6SQLiteM4SupportRoute.PRECEDENT_RETRIEVAL,
            document_route=M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL,
            artifact_id=_sha256(retrieval_row, "retrieval_receipt_id"),
        ),
        _support_pair(
            connection,
            round_row,
            row_route=M6SQLiteM4SupportRoute.HEARING_ROUND,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_ROUND,
            artifact_id=_sha256(round_row, "round_id"),
        ),
        _support_pair(
            connection,
            checkpoint_row,
            row_route=M6SQLiteM4SupportRoute.HEARING_CHECKPOINT,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT,
            artifact_id=_sha256(checkpoint_row, "checkpoint_id"),
        ),
        _support_pair(
            connection,
            terminal_checkpoint_row,
            row_route=M6SQLiteM4SupportRoute.HEARING_CHECKPOINT,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT,
            artifact_id=_sha256(terminal_checkpoint_row, "checkpoint_id"),
        ),
    )
    support = tuple(sorted((pair[1] for pair in support_pairs), key=lambda item: item.sort_key))
    upstream_core = tuple(
        item
        for item in upstream.support_document_slots
        if item.route
        in {
            M6SQLiteM4SupportDocumentRoute.HEARING_SESSION,
            M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE,
            M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL,
        }
    )
    if tuple(item for item in support if item.route in {slot.route for slot in upstream_core}) != (
        upstream_core
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

    binding_row, verdict_row, review_row = _read_gate_rows(
        connection,
        run_id=run_id,
        case_id=case_id,
    )
    verdict = case.verdicts[0]
    review = case.procedural_reviews[0]
    role_outputs = {
        graph.observation.role: (
            graph.role_output.artifact_id if graph.role_output is not None else None
        )
        for graph in upstream.call_graphs
    }
    hearing_id = _sha256(session_row, "hearing_id")
    cycle_id = _sha256(cycle_row, "cycle_id")
    retrieval_id = _sha256(retrieval_row, "retrieval_receipt_id")
    round_id = _sha256(round_row, "round_id")
    pack = case.evidence_packs[0]
    if any(
        _text(row, "run_id") != run_id
        or _text(row, "case_id") != case_id
        or _sha256(row, "manifest_id") != manifest_id
        for row in (
            session_row,
            cycle_row,
            retrieval_row,
            round_row,
            checkpoint_row,
            terminal_checkpoint_row,
            binding_row,
            verdict_row,
            review_row,
        )
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
    if (
        _sha256(cycle_row, "hearing_id") != hearing_id
        or _sha256(retrieval_row, "hearing_id") != hearing_id
        or _sha256(retrieval_row, "cycle_scope_id") != cycle_id
        or _sha256(round_row, "hearing_id") != hearing_id
        or _sha256(round_row, "cycle_scope_id") != cycle_id
        or _sha256(round_row, "retrieval_receipt_id") != retrieval_id
        or _sha256(checkpoint_row, "hearing_id") != hearing_id
        or _sha256(checkpoint_row, "cycle_scope_id") != cycle_id
        or _sha256(checkpoint_row, "retrieval_receipt_id") != retrieval_id
        or _sha256(terminal_checkpoint_row, "hearing_id") != hearing_id
        or _sha256(terminal_checkpoint_row, "cycle_scope_id") != cycle_id
        or _sha256(terminal_checkpoint_row, "retrieval_receipt_id") != retrieval_id
        or _integer(round_row, "round_index", minimum=1) != 1
        or _integer(checkpoint_row, "judge_cycle", minimum=1) != 1
        or _integer(terminal_checkpoint_row, "judge_cycle", minimum=1) != 1
        or _integer(terminal_checkpoint_row, "version", minimum=1)
        != _integer(checkpoint_row, "version", minimum=1) + 1
        or _text(terminal_checkpoint_row, "phase") != "COMPLETE"
        or _sha256(terminal_checkpoint_row, "previous_checkpoint_id")
        != _sha256(checkpoint_row, "checkpoint_id")
        or _sha256(terminal_checkpoint_row, "previous_checkpoint_sha256")
        != _sha256(checkpoint_row, "checkpoint_sha256")
        or _text(terminal_checkpoint_row, "previous_phase") != "ROUND_COMPLETE"
        or _sha256(terminal_checkpoint_row, "procedural_review_id") != review.review_id
        or _sha256(round_row, "current_pack_id") != pack.pack_id
        or _integer(round_row, "current_pack_version", minimum=1) != pack.version
        or _sha256(round_row, "resulting_pack_id") != pack.pack_id
        or _integer(round_row, "resulting_pack_version", minimum=1) != pack.version
        or _optional_text(round_row, "acquisition_request_id") is not None
        or _optional_text(round_row, "tool_receipt_id") is not None
        or _sha256(round_row, "prosecutor_output_id") != role_outputs[M6LockedModelRole.PROSECUTOR]
        or _sha256(round_row, "defender_output_id") != role_outputs[M6LockedModelRole.DEFENDER]
        or _sha256(round_row, "judge_output_id") != role_outputs[M6LockedModelRole.JUDGE]
        or _sha256(checkpoint_row, "prosecutor_output_id")
        != role_outputs[M6LockedModelRole.PROSECUTOR]
        or _sha256(checkpoint_row, "defender_output_id") != role_outputs[M6LockedModelRole.DEFENDER]
        or _sha256(checkpoint_row, "judge_output_id") != role_outputs[M6LockedModelRole.JUDGE]
        or _sha256(terminal_checkpoint_row, "current_pack_id") != pack.pack_id
        or _integer(terminal_checkpoint_row, "current_pack_version", minimum=1) != pack.version
        or _sha256(terminal_checkpoint_row, "prosecutor_output_id")
        != role_outputs[M6LockedModelRole.PROSECUTOR]
        or _sha256(terminal_checkpoint_row, "defender_output_id")
        != role_outputs[M6LockedModelRole.DEFENDER]
        or _sha256(terminal_checkpoint_row, "judge_output_id")
        != role_outputs[M6LockedModelRole.JUDGE]
        or _sha256(binding_row, "hearing_id") != hearing_id
        or _sha256(binding_row, "cycle_scope_id") != cycle_id
        or _sha256(binding_row, "round_id") != round_id
        or _integer(binding_row, "judge_round_index", minimum=1) != 1
        or _sha256(binding_row, "evidence_pack_id") != pack.pack_id
        or _integer(binding_row, "evidence_pack_version", minimum=1) != pack.version
        or _sha256(binding_row, "verdict_id") != verdict.verdict_id
        or _integer(binding_row, "verdict_version", minimum=1) != verdict.version
        or _sha256(binding_row, "verdict_input_sha256") != verdict.verdict_input_sha256
        or _sha256(binding_row, "verdict_sha256") != verdict.verdict_sha256
        or _sha256(binding_row, "prosecutor_output_id")
        != role_outputs[M6LockedModelRole.PROSECUTOR]
        or _sha256(binding_row, "defender_output_id") != role_outputs[M6LockedModelRole.DEFENDER]
        or _sha256(binding_row, "judge_output_id") != role_outputs[M6LockedModelRole.JUDGE]
        or _sha256(verdict_row, "verdict_id") != verdict.verdict_id
        or _integer(verdict_row, "version", minimum=1) != verdict.version
        or _sha256(verdict_row, "document_sha256") != _document_sha256(verdict)
        or _sha256(review_row, "review_id") != review.review_id
        or _integer(review_row, "version", minimum=1) != review.version
        or _sha256(review_row, "reviewed_verdict_id") != verdict.verdict_id
        or _integer(review_row, "reviewed_verdict_version", minimum=1) != verdict.version
        or _sha256(review_row, "reviewed_verdict_sha256") != verdict.verdict_sha256
        or _integer(review_row, "passed") != 1
        or _sha256(review_row, "document_sha256") != _document_sha256(review)
        or _integer(verdict_row, "audit_sequence")
        > upstream.selected_case_binding.case_audit_sequence
        or _integer(review_row, "audit_sequence")
        > upstream.selected_case_binding.case_audit_sequence
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

    gate_slots = tuple(
        sorted(
            (
                _gate_slot(
                    connection,
                    binding_row,
                    route=M6SQLiteM4GateDocumentRoute.VERDICT_BINDING,
                    artifact_id=_sha256(binding_row, "binding_id"),
                    document_sha256=_sha256(binding_row, "document_sha256"),
                ),
                _gate_slot(
                    connection,
                    verdict_row,
                    route=M6SQLiteM4GateDocumentRoute.VERDICT,
                    artifact_id=verdict.verdict_id,
                    document_sha256=_sha256(verdict_row, "document_sha256"),
                ),
                _gate_slot(
                    connection,
                    review_row,
                    route=M6SQLiteM4GateDocumentRoute.PROCEDURAL_REVIEW,
                    artifact_id=review.review_id,
                    document_sha256=_sha256(review_row, "document_sha256"),
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    binding = M6SQLiteM4GateBindingPlan(
        hearing_id=hearing_id,
        hearing_record_id=_sha256(binding_row, "hearing_record_id"),
        hearing_record_version=_integer(binding_row, "hearing_record_version", minimum=1),
        hearing_record_sha256=_sha256(binding_row, "hearing_record_sha256"),
        cycle_scope_id=cycle_id,
        round_id=round_id,
        judge_round_index=1,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        verdict_id=verdict.verdict_id,
        verdict_version=verdict.version,
        review_id=review.review_id,
        review_version=review.version,
        prosecutor_output_id=cast(str, role_outputs[M6LockedModelRole.PROSECUTOR]),
        defender_output_id=cast(str, role_outputs[M6LockedModelRole.DEFENDER]),
        judge_output_id=cast(str, role_outputs[M6LockedModelRole.JUDGE]),
    )
    try:
        plan = M6SQLiteM4GateDocumentsPlan(
            upstream_m4_model_plan=upstream,
            support_document_slots=support,
            gate_document_slots=gate_slots,
            binding=binding,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    _active(connection)
    return plan


def plan_m6_sqlite_m4_gate_documents(
    *,
    connection: object,
    upstream_m4_model_plan: object,
) -> M6SQLiteM4GateDocumentsPlan:
    """Freeze the first successful Verdict/Gate graph without reading bodies."""

    if (
        type(connection) is not M6LiveReader
        or type(upstream_m4_model_plan) is not M6SQLiteM4ModelDocumentsPlan
    ):
        raise M6SQLiteM4ModelDocumentError(
            M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT
        ) from None
    try:
        return _build_gate_plan(connection, upstream_m4_model_plan)
    except _M6SQLiteM4MetadataFailure as error:
        raise M6SQLiteM4ModelDocumentError(error.reason_code) from None
    except (sqlite3.Error, UnicodeError):
        raise M6SQLiteM4ModelDocumentError(
            M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED
        ) from None


def _gate_body_row(
    connection: M6LiveReader,
    slot: M6SQLiteM4GateDocumentSlot,
) -> sqlite3.Row:
    table, id_column = {
        M6SQLiteM4GateDocumentRoute.VERDICT_BINDING: (
            "m4_hearing_verdict_bindings",
            "binding_id",
        ),
        M6SQLiteM4GateDocumentRoute.VERDICT: ("verdicts", "verdict_id"),
        M6SQLiteM4GateDocumentRoute.PROCEDURAL_REVIEW: (
            "procedural_reviews",
            "review_id",
        ),
    }[slot.route]
    cursor = connection.execute(
        f"SELECT rowid AS gate_rowid, * FROM {table} WHERE rowid = ? AND {id_column} = ? LIMIT 2",
        (slot.rowid, slot.artifact_id),
    )
    try:
        rows = tuple(cursor.fetchmany(2))
    finally:
        cursor.close()
    if len(rows) != 1 or rows[0]["gate_rowid"] != slot.rowid:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return rows[0]


def _typed_gate_body(
    connection: M6LiveReader,
    slot: M6SQLiteM4GateDocumentSlot,
) -> tuple[BaseModel, str]:
    row = _gate_body_row(connection, slot)
    column, raw_model = {
        M6SQLiteM4GateDocumentRoute.VERDICT_BINDING: (
            "binding_json",
            HearingVerdictBinding,
        ),
        M6SQLiteM4GateDocumentRoute.VERDICT: ("verdict_json", Verdict),
        M6SQLiteM4GateDocumentRoute.PROCEDURAL_REVIEW: (
            "review_json",
            ProceduralReview,
        ),
    }[slot.route]
    model = cast(type[BaseModel], raw_model)
    encoded = _canonical_bytes(row[column], slot.document_bytes)
    if hashlib.sha256(encoded).hexdigest() != slot.document_sha256:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    raw = row[column]
    assert isinstance(raw, str)
    try:
        document = model.model_validate_json(raw)
        canonical = canonical_json(document.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    if canonical != raw:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    identity = {
        M6SQLiteM4GateDocumentRoute.VERDICT_BINDING: "binding_id",
        M6SQLiteM4GateDocumentRoute.VERDICT: "verdict_id",
        M6SQLiteM4GateDocumentRoute.PROCEDURAL_REVIEW: "review_id",
    }[slot.route]
    if getattr(document, identity, None) != slot.artifact_id:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    if slot.route == M6SQLiteM4GateDocumentRoute.VERDICT_BINDING:
        specs = tuple(
            spec for spec in M4_TYPED_TABLES if spec.table == "m4_hearing_verdict_bindings"
        )
        if len(specs) != 1:
            _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
        try:
            record = load_m4_record(row, cast(M4TableSpec[BaseModel], specs[0]))
        except M4DocumentFailure:
            _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
        except M4IndexFailure:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        if record.document != document:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return document, canonical


def _authority_document(
    kind: M4ProjectionArtifactKind,
    artifact_id: str,
    value: BaseModel,
) -> M6HistoricalAuthorityDocument:
    return M6HistoricalAuthorityDocument(
        kind=kind,
        artifact_id=artifact_id,
        canonical_document=canonical_json(value.model_dump(mode="json")),
    )


def _checked_authority_document(
    kind: M4ProjectionArtifactKind,
    artifact_id: str,
    value: BaseModel,
    claimed_document_sha256: str,
) -> M6HistoricalAuthorityDocument:
    document = _authority_document(kind, artifact_id, value)
    if document.document_sha256 != claimed_document_sha256:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    return document


def _m4_model_authority_documents(
    snapshot: M6M4ModelCallAuthoritySnapshot,
) -> tuple[M6HistoricalAuthorityDocument, ...]:
    documents = (
        *(
            _checked_authority_document(
                M4ProjectionArtifactKind.MODEL_REQUEST,
                item.request.request_id,
                item.request,
                item.document_sha256,
            )
            for item in snapshot.requests
        ),
        *(
            _checked_authority_document(
                M4ProjectionArtifactKind.MODEL_RESPONSE,
                item.response.response_id,
                item.response,
                item.document_sha256,
            )
            for item in snapshot.responses
        ),
        *(
            _checked_authority_document(
                M4ProjectionArtifactKind.MODEL_CACHE_ENTRY,
                item.entry.cache_entry_id,
                item.entry,
                item.document_sha256,
            )
            for item in snapshot.caches
        ),
        *(
            _checked_authority_document(
                M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
                item.receipt.parse_receipt_id,
                item.receipt,
                item.document_sha256,
            )
            for item in snapshot.parse_receipts
        ),
        *(
            _checked_authority_document(
                M4ProjectionArtifactKind.ROLE_OUTPUT,
                item.output.output_id,
                item.output,
                item.document_sha256,
            )
            for item in snapshot.role_outputs
        ),
        *(
            _checked_authority_document(
                M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY,
                item.authority.authority_id,
                item.authority,
                item.document_sha256,
            )
            for item in snapshot.failures
        ),
        *(
            _checked_authority_document(
                M4ProjectionArtifactKind.USAGE_RECEIPT,
                item.receipt.usage_receipt_id,
                item.receipt,
                item.document_sha256,
            )
            for item in snapshot.usages
        ),
    )
    return tuple(sorted(documents, key=lambda item: item.sort_key))


def _resolve_gate_documents(
    connection: M6LiveReader,
    plan: M6SQLiteM4GateDocumentsPlan,
    upstream_snapshot: M6M4ModelCallAuthoritySnapshot,
) -> M6SQLiteM4GateAuthoritySnapshot:
    if not _plan_is_consistent_gate(plan):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT)
    upstream = _fresh_plan(connection, plan.upstream_m4_model_plan)
    fresh = _build_gate_plan(connection, upstream)
    if fresh != plan:
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    if (
        type(upstream_snapshot) is not M6M4ModelCallAuthoritySnapshot
        or upstream_snapshot.source_identity_sha256 != upstream.plan_identity_sha256
        or upstream_snapshot.run_id != upstream.run_id
        or upstream_snapshot.case_id != upstream.case_id
        or upstream_snapshot.manifest_id != upstream.manifest_id
        or upstream_snapshot.authority_failure_count
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    support_records: dict[M6SQLiteM4SupportDocumentRoute, list[BaseModel]] = {}
    for slot in plan.support_document_slots:
        record, _body = _load_support(connection, slot)
        document = getattr(record, "document", None)
        canonical = getattr(record, "canonical_document", None)
        if not isinstance(document, BaseModel) or not isinstance(canonical, str):
            _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
        support_records.setdefault(slot.route, []).append(document)
    if any(
        len(support_records.get(route, ())) != expected_count
        for route, expected_count in (
            (M6SQLiteM4SupportDocumentRoute.HEARING_SESSION, 1),
            (M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE, 1),
            (M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL, 1),
            (M6SQLiteM4SupportDocumentRoute.HEARING_ROUND, 1),
            (M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT, 2),
        )
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    session = support_records[M6SQLiteM4SupportDocumentRoute.HEARING_SESSION][0]
    cycle = support_records[M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE][0]
    retrieval = support_records[M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL][0]
    hearing_round = support_records[M6SQLiteM4SupportDocumentRoute.HEARING_ROUND][0]
    checkpoints = support_records[M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT]
    round_checkpoints = tuple(
        item
        for item in checkpoints
        if type(item) is HearingCheckpoint and item.phase == HearingCheckpointPhase.ROUND_COMPLETE
    )
    terminal_checkpoints = tuple(
        item
        for item in checkpoints
        if type(item) is HearingCheckpoint and item.phase == HearingCheckpointPhase.COMPLETE
    )
    if len(round_checkpoints) != 1 or len(terminal_checkpoints) != 1:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    checkpoint = round_checkpoints[0]
    terminal_checkpoint = terminal_checkpoints[0]
    if (
        type(session) is not HearingSession
        or type(cycle) is not HearingCycleScope
        or type(retrieval) is not HearingPrecedentRetrievalReceipt
        or type(hearing_round) is not HearingRound
        or type(checkpoint) is not HearingCheckpoint
        or type(terminal_checkpoint) is not HearingCheckpoint
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)

    gate_values = {
        slot.route: _typed_gate_body(connection, slot)[0] for slot in plan.gate_document_slots
    }
    binding = gate_values[M6SQLiteM4GateDocumentRoute.VERDICT_BINDING]
    verdict = gate_values[M6SQLiteM4GateDocumentRoute.VERDICT]
    review = gate_values[M6SQLiteM4GateDocumentRoute.PROCEDURAL_REVIEW]
    if (
        type(binding) is not HearingVerdictBinding
        or type(verdict) is not Verdict
        or type(review) is not ProceduralReview
        or verdict != upstream.selected_case.verdicts[0]
        or review != upstream.selected_case.procedural_reviews[0]
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    try:
        built_record = build_hearing_record(session, (checkpoint,))
    except HearingRecordBuildError:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    expected = plan.binding
    if (
        built_record.rounds != (hearing_round,)
        or binding.hearing_session_id != session.session_id
        or binding.hearing_record_id != built_record.record_id
        or binding.hearing_record_version != built_record.version
        or binding.hearing_record_sha256 != built_record.record_sha256
        or binding.judge_round_id != hearing_round.round_id
        or binding.judge_round_index != hearing_round.round_index
        or binding.verdict_id != verdict.verdict_id
        or binding.verdict_version != verdict.version
        or binding.evidence_pack_id != expected.evidence_pack_id
        or binding.evidence_pack_version != expected.evidence_pack_version
        or review.reviewed_verdict_id != verdict.verdict_id
        or not review.passed
        or built_record.record_id != expected.hearing_record_id
        or built_record.version != expected.hearing_record_version
        or built_record.record_sha256 != expected.hearing_record_sha256
        or cycle.cycle_id != expected.cycle_scope_id
        or retrieval.cycle_scope_id != cycle.cycle_id
        or hearing_round.cycle_scope_id != cycle.cycle_id
        or terminal_checkpoint.version != checkpoint.version + 1
        or terminal_checkpoint.hearing_session_id != checkpoint.hearing_session_id
        or terminal_checkpoint.hearing_session_sha256 != checkpoint.hearing_session_sha256
        or terminal_checkpoint.cycle_scope_id != checkpoint.cycle_scope_id
        or terminal_checkpoint.cycle_scope_sha256 != checkpoint.cycle_scope_sha256
        or terminal_checkpoint.current_evidence_pack_id != checkpoint.current_evidence_pack_id
        or terminal_checkpoint.current_evidence_pack_version
        != checkpoint.current_evidence_pack_version
        or terminal_checkpoint.previous_checkpoint_id != checkpoint.checkpoint_id
        or terminal_checkpoint.previous_checkpoint_sha256 != checkpoint.checkpoint_sha256
        or terminal_checkpoint.previous_phase != HearingCheckpointPhase.ROUND_COMPLETE
        or terminal_checkpoint.procedural_review_ref is None
        or terminal_checkpoint.procedural_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
        or terminal_checkpoint.procedural_review_ref.artifact_id != review.review_id
        or terminal_checkpoint.precedent_retrieval_receipt != checkpoint.precedent_retrieval_receipt
        or terminal_checkpoint.prosecutor_output != checkpoint.prosecutor_output
        or terminal_checkpoint.defender_output != checkpoint.defender_output
        or terminal_checkpoint.judge_output != checkpoint.judge_output
        or terminal_checkpoint.acquisition_request is not None
        or terminal_checkpoint.tool_execution_receipt is not None
        or terminal_checkpoint.model_request_refs != checkpoint.model_request_refs
        or terminal_checkpoint.model_response_refs != checkpoint.model_response_refs
        or terminal_checkpoint.parse_receipt_refs != checkpoint.parse_receipt_refs
        or terminal_checkpoint.usage_receipts != checkpoint.usage_receipts
        or terminal_checkpoint.failure_authorities != checkpoint.failure_authorities
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

    documents = [
        _authority_document(
            M4ProjectionArtifactKind.EVIDENCE_PACK,
            upstream.selected_case.evidence_packs[0].pack_id,
            upstream.selected_case.evidence_packs[0],
        ),
        _authority_document(
            M4ProjectionArtifactKind.HEARING_SESSION,
            session.session_id,
            session,
        ),
        _authority_document(M4ProjectionArtifactKind.HEARING_CYCLE, cycle.cycle_id, cycle),
        _authority_document(
            M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL,
            retrieval.receipt_id,
            retrieval,
        ),
        _authority_document(
            M4ProjectionArtifactKind.HEARING_CHECKPOINT,
            checkpoint.checkpoint_id,
            checkpoint,
        ),
        _authority_document(
            M4ProjectionArtifactKind.HEARING_CHECKPOINT,
            terminal_checkpoint.checkpoint_id,
            terminal_checkpoint,
        ),
        _authority_document(
            M4ProjectionArtifactKind.HEARING_ROUND,
            hearing_round.round_id,
            hearing_round,
        ),
        _authority_document(
            M4ProjectionArtifactKind.HEARING_RECORD,
            built_record.record_id,
            built_record,
        ),
        _authority_document(
            M4ProjectionArtifactKind.VERDICT_BINDING,
            binding.binding_id,
            binding,
        ),
        _authority_document(M4ProjectionArtifactKind.VERDICT, verdict.verdict_id, verdict),
        _authority_document(
            M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
            review.review_id,
            review,
        ),
    ]
    try:
        snapshot = M6SQLiteM4GateAuthoritySnapshot(
            source_identity_sha256=plan.plan_identity_sha256,
            upstream_m4_model_plan_identity_sha256=upstream.plan_identity_sha256,
            run_id=upstream.run_id,
            case_id=upstream.case_id,
            manifest_id=upstream.manifest_id,
            hearing_sessions=(session,),
            hearing_cycles=(cycle,),
            retrieval_receipts=(retrieval,),
            hearing_rounds=(hearing_round,),
            completed_checkpoints=(checkpoint,),
            hearing_records=(built_record,),
            verdict_bindings=(binding,),
            verdicts=(verdict,),
            procedural_reviews=(review,),
            documents=tuple(sorted(documents, key=lambda item: item.sort_key)),
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    _active(connection)
    return snapshot


def resolve_m6_sqlite_m4_gate_documents(
    *,
    connection: object,
    metadata_plan: object,
    upstream_m4_model_snapshot: object,
) -> M6SQLiteM4GateAuthoritySnapshot:
    """Read and independently rebuild the frozen first-slice M4/Gate graph."""

    if (
        type(connection) is not M6LiveReader
        or type(metadata_plan) is not M6SQLiteM4GateDocumentsPlan
        or type(upstream_m4_model_snapshot) is not M6M4ModelCallAuthoritySnapshot
    ):
        raise M6SQLiteM4ModelDocumentError(
            M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT
        ) from None
    try:
        return _resolve_gate_documents(
            connection,
            metadata_plan,
            upstream_m4_model_snapshot,
        )
    except _M6SQLiteM4MetadataFailure as error:
        raise M6SQLiteM4ModelDocumentError(error.reason_code) from None
    except (sqlite3.Error, UnicodeError):
        raise M6SQLiteM4ModelDocumentError(
            M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED
        ) from None


def _assemble_gate_history_snapshot(
    gate_snapshot: M6SQLiteM4GateAuthoritySnapshot,
    upstream_snapshot: M6M4ModelCallAuthoritySnapshot,
    source_m4_authority_root_sha256: str,
) -> M6ProceduralGateHistorySnapshot:
    if (
        gate_snapshot.upstream_m4_model_plan_identity_sha256
        != upstream_snapshot.source_identity_sha256
        or gate_snapshot.run_id != upstream_snapshot.run_id
        or gate_snapshot.case_id != upstream_snapshot.case_id
        or gate_snapshot.manifest_id != upstream_snapshot.manifest_id
        or upstream_snapshot.authority_failure_count
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    try:
        root = _require_sha256(source_m4_authority_root_sha256, "source M4 authority root")
    except ValueError:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT)
    documents = tuple(
        sorted(
            (*gate_snapshot.documents, *_m4_model_authority_documents(upstream_snapshot)),
            key=lambda item: item.sort_key,
        )
    )
    keys = tuple(item.sort_key for item in documents)
    if len(keys) != len(set(keys)):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    identity = hashlib.sha256(
        canonical_json(
            [
                "m6-sqlite-m4-gate-history",
                1,
                gate_snapshot.source_identity_sha256,
                upstream_snapshot.source_identity_sha256,
                upstream_snapshot.m4_replay_authority_root_sha256,
                upstream_snapshot.model_call_authority_root_sha256,
                root,
                [[item.kind.value, item.artifact_id, item.document_sha256] for item in documents],
            ]
        ).encode("utf-8")
    ).hexdigest()
    try:
        return M6ProceduralGateHistorySnapshot(
            source_identity_sha256=identity,
            run_id=gate_snapshot.run_id,
            source_m4_authority_root_sha256=root,
            documents=documents,
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)


def assemble_m6_sqlite_m4_gate_history_snapshot(
    *,
    gate_snapshot: object,
    upstream_m4_model_snapshot: object,
    source_m4_authority_root_sha256: object,
) -> M6ProceduralGateHistorySnapshot:
    """Combine independently rebuilt Gate semantics and the full M4 call history."""

    if (
        type(gate_snapshot) is not M6SQLiteM4GateAuthoritySnapshot
        or type(upstream_m4_model_snapshot) is not M6M4ModelCallAuthoritySnapshot
        or type(source_m4_authority_root_sha256) is not str
    ):
        raise M6SQLiteM4ModelDocumentError(
            M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT
        ) from None
    try:
        return _assemble_gate_history_snapshot(
            gate_snapshot,
            upstream_m4_model_snapshot,
            source_m4_authority_root_sha256,
        )
    except _M6SQLiteM4MetadataFailure as error:
        raise M6SQLiteM4ModelDocumentError(error.reason_code) from None


__all__ = [
    "M6SQLiteM4GateAuthoritySnapshot",
    "M6SQLiteM4GateBindingPlan",
    "M6SQLiteM4GateDocumentRoute",
    "M6SQLiteM4GateDocumentSlot",
    "M6SQLiteM4GateDocumentsPlan",
    "assemble_m6_sqlite_m4_gate_history_snapshot",
    "plan_m6_sqlite_m4_gate_documents",
    "resolve_m6_sqlite_m4_gate_documents",
]
