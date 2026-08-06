"""Bind body-free M4 support rows to the exact observed call closure."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked import M6LockedModelRole

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m4_model_graph import _CycleContext
from ._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4FailureClosureKind,
    M6SQLiteM4HearingModelManifestBinding,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4RoleModelManifestBinding,
    M6SQLiteM4SelectedPackBinding,
    M6SQLiteM4SupportDocumentRoute,
    M6SQLiteM4SupportDocumentSlot,
    M6SQLiteM4SupportRoute,
    M6SQLiteM4SupportSlot,
)
from ._sqlite_m6_upgrade_m4_model_primitives import (
    _Claim,
    _fail,
    _Failure,
    _integer,
    _optional_text,
    _row_identity,
    _sha256,
    _single,
    _support_pair,
    _support_slot,
    _text,
)
from ._sqlite_m6_upgrade_m4_model_rows import (
    _M4BacklogSupportRows,
    _M4BaseSupportRows,
    _M4HearingSupportRows,
)


@dataclass(frozen=True, slots=True)
class _ResolvedSupport:
    hearing_bindings: tuple[M6SQLiteM4HearingModelManifestBinding, ...]
    selected_packs: tuple[M6SQLiteM4SelectedPackBinding, ...]
    contexts: dict[str, _CycleContext]
    slots: tuple[M6SQLiteM4SupportSlot, ...]
    document_slots: tuple[M6SQLiteM4SupportDocumentSlot, ...]


def _merge_slots(
    base: tuple[M6SQLiteM4SupportSlot, ...],
    added: list[M6SQLiteM4SupportSlot],
) -> tuple[M6SQLiteM4SupportSlot, ...]:
    merged = {(slot.route, slot.rowid): slot for slot in base}
    for slot in added:
        key = (slot.route, slot.rowid)
        previous = merged.get(key)
        if previous is not None and previous != slot:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        merged[key] = slot
    return tuple(sorted(merged.values(), key=lambda value: value.sort_key))


def _merge_documents(
    base: tuple[M6SQLiteM4SupportDocumentSlot, ...],
    added: list[M6SQLiteM4SupportDocumentSlot],
) -> tuple[M6SQLiteM4SupportDocumentSlot, ...]:
    merged = {(slot.route, slot.rowid): slot for slot in base}
    for slot in added:
        key = (slot.route, slot.rowid)
        previous = merged.get(key)
        if previous is not None and previous != slot:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        merged[key] = slot
    return tuple(sorted(merged.values(), key=lambda value: value.sort_key))


def _scoped_rows_by_sha(
    rows: tuple[sqlite3.Row, ...],
    *,
    id_column: str,
    run_id: str,
    case_id: str,
    manifest_id: str,
) -> dict[str, sqlite3.Row]:
    indexed: dict[str, sqlite3.Row] = {}
    for row in rows:
        if (
            _text(row, "run_id") != run_id
            or _text(row, "case_id") != case_id
            or _sha256(row, "manifest_id") != manifest_id
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
        identity = _sha256(row, id_column)
        if identity in indexed:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        indexed[identity] = row
    return indexed


def _append_pair(
    connection: M6LiveReader,
    row: sqlite3.Row,
    *,
    row_route: M6SQLiteM4SupportRoute,
    document_route: M6SQLiteM4SupportDocumentRoute,
    artifact_id: str,
    slots: list[M6SQLiteM4SupportSlot],
    documents: list[M6SQLiteM4SupportDocumentSlot],
) -> None:
    slot, document = _support_pair(
        connection,
        row,
        row_route=row_route,
        document_route=document_route,
        artifact_id=artifact_id,
    )
    slots.append(slot)
    documents.append(document)


def _bind_base_authority(
    rows: _M4BaseSupportRows,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    authority: M6SQLiteCaseAuthorityDocument,
    claims: dict[str, _Claim],
    referenced_screenings: set[str],
    referenced_reviews: set[str],
    slots: list[M6SQLiteM4SupportSlot],
) -> tuple[M6SQLiteM4SelectedPackBinding, ...]:
    run_row = _single(
        rows.run,
        missing=M6SQLiteM4ModelDocumentFailureCode.SCOPE_NOT_FOUND,
    )
    if _text(run_row, "run_id") != run_id or _sha256(run_row, "manifest_id") != manifest_id:
        _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
    slots.append(_support_slot(run_row, M6SQLiteM4SupportRoute.RUN, run_id))

    case_row = _single(rows.case_version)
    audit_row = _single(rows.audit)
    binding = authority.candidate_case_binding
    audit = authority.audit_entry
    if (
        _text(case_row, "run_id") != run_id
        or _text(case_row, "case_id") != case_id
        or _integer(case_row, "revision", minimum=1) != binding.case_revision
        or _sha256(case_row, "document_sha256") != binding.case_document_sha256
        or _integer(case_row, "audit_sequence") != binding.case_audit_sequence
        or _text(audit_row, "run_id") != run_id
        or _integer(audit_row, "sequence") != binding.case_audit_sequence
        or _sha256(audit_row, "manifest_id") != manifest_id
        or _sha256(audit_row, "entry_hash") != binding.case_audit_entry_hash
        or _sha256(audit_row, "after_sha256") != binding.case_document_sha256
        or _text(audit_row, "action") != audit.action.value
        or _text(audit_row, "object_kind") != audit.object_ref.kind.value
        or _text(audit_row, "object_id") != audit.object_ref.artifact_id
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.CASE_BINDING_MISMATCH)
    slots.append(
        _support_slot(
            case_row,
            M6SQLiteM4SupportRoute.CASE_VERSION,
            f"{case_id}:{binding.case_revision}",
        )
    )
    slots.append(
        _support_slot(
            audit_row,
            M6SQLiteM4SupportRoute.AUDIT_ENTRY,
            str(binding.case_audit_sequence),
        )
    )

    requested_pack_keys = {claim.pack_key for claim in claims.values()}
    pack_rows: dict[tuple[str, int], sqlite3.Row] = {}
    for row in rows.packs:
        if (
            _text(row, "run_id") != run_id
            or _text(row, "case_id") != case_id
            or _sha256(row, "manifest_id") != manifest_id
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
        key = (_sha256(row, "pack_id"), _integer(row, "version", minimum=1))
        if key in pack_rows:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        pack_rows[key] = row
    embedded_packs = {(pack.pack_id, pack.version): pack for pack in authority.case.evidence_packs}
    selected: list[M6SQLiteM4SelectedPackBinding] = []
    for key in sorted(requested_pack_keys):
        selected_row = pack_rows.get(key)
        embedded = embedded_packs.get(key)
        if selected_row is None or embedded is None:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        document_sha256 = _sha256(selected_row, "document_sha256")
        embedded_sha256 = hashlib.sha256(
            canonical_json(embedded.model_dump(mode="json")).encode("utf-8")
        ).hexdigest()
        if document_sha256 != embedded_sha256:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        try:
            binding_row = M6SQLiteM4SelectedPackBinding(
                rowid=_integer(selected_row, "support_rowid", minimum=1),
                pack_id=key[0],
                version=key[1],
                document_sha256=document_sha256,
                created_audit_sequence=_integer(selected_row, "created_audit_sequence"),
                index_identity_sha256=_row_identity(
                    selected_row,
                    M6SQLiteM4SupportRoute.EVIDENCE_PACK.value,
                ),
            )
        except (AttributeError, TypeError, ValueError):
            _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
        selected.append(binding_row)
        slots.append(
            M6SQLiteM4SupportSlot(
                route=M6SQLiteM4SupportRoute.EVIDENCE_PACK,
                rowid=binding_row.rowid,
                identity=f"{binding_row.pack_id}:{binding_row.version}",
                index_identity_sha256=binding_row.index_identity_sha256,
            )
        )

    screening_rows = _scoped_rows_by_sha(
        rows.screenings,
        id_column="screening_id",
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    for screening_id in sorted(referenced_screenings):
        screening_row = screening_rows.get(screening_id)
        if screening_row is None:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        slots.append(
            _support_slot(
                screening_row,
                M6SQLiteM4SupportRoute.SCREENING_RESULT,
                screening_id,
            )
        )

    review_rows = _scoped_rows_by_sha(
        rows.reviews,
        id_column="review_id",
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    for review_id in sorted(referenced_reviews):
        review_row = review_rows.get(review_id)
        if review_row is None:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        slots.append(
            _support_slot(
                review_row,
                M6SQLiteM4SupportRoute.PROCEDURAL_REVIEW,
                review_id,
            )
        )
    return tuple(sorted(selected, key=lambda value: value.sort_key))


def resolve_response_support(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    authority: M6SQLiteCaseAuthorityDocument,
    role_bindings: tuple[M6SQLiteM4RoleModelManifestBinding, ...],
    claims: dict[str, _Claim],
    base_rows: _M4BaseSupportRows,
    hearing_rows: _M4HearingSupportRows,
) -> _ResolvedSupport:
    """Select only the core support closure reachable from response calls."""

    expected_hearings = {claim.hearing_id for claim in claims.values()}
    expected_cycles = {claim.cycle_scope_id for claim in claims.values()}
    model_by_role = {item.role: item.model_manifest_id for item in role_bindings}
    sessions = _scoped_rows_by_sha(
        hearing_rows.sessions,
        id_column="hearing_id",
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    cycles = _scoped_rows_by_sha(
        hearing_rows.cycles,
        id_column="cycle_id",
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    retrievals = _scoped_rows_by_sha(
        hearing_rows.retrievals,
        id_column="retrieval_receipt_id",
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    retrieval_by_cycle: dict[str, sqlite3.Row] = {}
    for row in retrievals.values():
        cycle_id = _sha256(row, "cycle_scope_id")
        if cycle_id in retrieval_by_cycle:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        retrieval_by_cycle[cycle_id] = row

    slots: list[M6SQLiteM4SupportSlot] = []
    documents: list[M6SQLiteM4SupportDocumentSlot] = []
    hearing_bindings: list[M6SQLiteM4HearingModelManifestBinding] = []
    referenced_screenings: set[str] = set()
    referenced_reviews: set[str] = set()
    for hearing_id in sorted(expected_hearings):
        session_row = sessions.get(hearing_id)
        if session_row is None:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        stored_models = {
            M6LockedModelRole.PROSECUTOR: _sha256(
                session_row,
                "prosecutor_model_manifest_id",
            ),
            M6LockedModelRole.DEFENDER: _sha256(
                session_row,
                "defender_model_manifest_id",
            ),
            M6LockedModelRole.JUDGE: _sha256(
                session_row,
                "judge_model_manifest_id",
            ),
        }
        if stored_models != model_by_role:
            _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
        hearing_bindings.append(
            M6SQLiteM4HearingModelManifestBinding(
                hearing_id=hearing_id,
                hearing_prompt_bundle_sha256=_sha256(
                    session_row,
                    "hearing_prompt_bundle_sha256",
                ),
                role_bindings=role_bindings,
            )
        )
        _append_pair(
            connection,
            session_row,
            row_route=M6SQLiteM4SupportRoute.HEARING_SESSION,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_SESSION,
            artifact_id=hearing_id,
            slots=slots,
            documents=documents,
        )
        referenced_screenings.add(_sha256(session_row, "screening_id"))
        trigger_review = _optional_text(session_row, "trigger_review_id")
        if trigger_review is not None:
            referenced_reviews.add(trigger_review)

    contexts: dict[str, _CycleContext] = {}
    for cycle_id in sorted(expected_cycles):
        cycle_row = cycles.get(cycle_id)
        retrieval = retrieval_by_cycle.get(cycle_id)
        if cycle_row is None or retrieval is None:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        hearing_id = _sha256(cycle_row, "hearing_id")
        cycle_sha256 = _sha256(cycle_row, "cycle_sha256")
        pack_key = (
            _sha256(cycle_row, "cycle_pack_id"),
            _integer(cycle_row, "cycle_pack_version", minimum=1),
        )
        cycle_index = _integer(cycle_row, "cycle_index", minimum=1)
        prior_acquisition = _integer(cycle_row, "prior_acquisition_rounds")
        prior_rework = _integer(cycle_row, "prior_rework_rounds")
        related_claims = tuple(
            claim for claim in claims.values() if claim.cycle_scope_id == cycle_id
        )
        if (
            hearing_id not in expected_hearings
            or not related_claims
            or any(
                claim.hearing_id != hearing_id
                or claim.cycle_scope_sha256 != cycle_sha256
                or claim.pack_key != pack_key
                for claim in related_claims
            )
            or _sha256(retrieval, "hearing_id") != hearing_id
            or _sha256(retrieval, "cycle_scope_sha256") != cycle_sha256
            or (
                _sha256(retrieval, "current_pack_id"),
                _integer(retrieval, "current_pack_version", minimum=1),
            )
            != pack_key
            or _integer(retrieval, "prior_acquisition_rounds") != prior_acquisition
            or _integer(retrieval, "prior_rework_rounds") != prior_rework
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _append_pair(
            connection,
            cycle_row,
            row_route=M6SQLiteM4SupportRoute.HEARING_CYCLE,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE,
            artifact_id=cycle_id,
            slots=slots,
            documents=documents,
        )
        retrieval_id = _sha256(retrieval, "retrieval_receipt_id")
        _append_pair(
            connection,
            retrieval,
            row_route=M6SQLiteM4SupportRoute.PRECEDENT_RETRIEVAL,
            document_route=M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL,
            artifact_id=retrieval_id,
            slots=slots,
            documents=documents,
        )
        contexts[cycle_id] = _CycleContext(
            hearing_id=hearing_id,
            cycle_scope_id=cycle_id,
            cycle_scope_sha256=cycle_sha256,
            cycle_index=cycle_index,
            prior_acquisition_rounds=prior_acquisition,
            prior_rework_rounds=prior_rework,
            pack_key=pack_key,
            retrieval_receipt_id=retrieval_id,
            retrieval_commitment_sha256=_sha256(
                retrieval,
                "body_commitment_sha256",
            ),
        )
        for column in (
            "initial_trigger_review_id",
            "rework_review_id",
        ):
            review_id = _optional_text(retrieval, column)
            if review_id is not None:
                referenced_reviews.add(review_id)

    selected_packs = _bind_base_authority(
        base_rows,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        authority=authority,
        claims=claims,
        referenced_screenings=referenced_screenings,
        referenced_reviews=referenced_reviews,
        slots=slots,
    )
    return _ResolvedSupport(
        hearing_bindings=tuple(sorted(hearing_bindings, key=lambda value: value.sort_key)),
        selected_packs=selected_packs,
        contexts=contexts,
        slots=tuple(sorted(slots, key=lambda value: value.sort_key)),
        document_slots=tuple(sorted(documents, key=lambda value: value.sort_key)),
    )


def _optional_sha256(row: sqlite3.Row, column: str) -> str | None:
    value = _optional_text(row, column)
    if value is None:
        return None
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _case_closure_rows(
    rows: _M4BaseSupportRows,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
) -> tuple[dict[int, sqlite3.Row], dict[int, sqlite3.Row]]:
    cases: dict[int, sqlite3.Row] = {}
    for row in rows.case_history:
        if _text(row, "run_id") != run_id or _text(row, "case_id") != case_id:
            _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
        revision = _integer(row, "revision", minimum=1)
        if revision in cases:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        cases[revision] = row
    audits: dict[int, sqlite3.Row] = {}
    for row in rows.audit_history:
        if _text(row, "run_id") != run_id or _sha256(row, "manifest_id") != manifest_id:
            _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
        sequence = _integer(row, "sequence")
        if sequence in audits:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        audits[sequence] = row
    return cases, audits


def _bind_case_closure(
    *,
    revision: int,
    sequence: int,
    audit_hash: str,
    backlog_item_id: str,
    case_status: str,
    case_rows: dict[int, sqlite3.Row],
    audit_rows: dict[int, sqlite3.Row],
    slots: list[M6SQLiteM4SupportSlot],
) -> None:
    case_row = case_rows.get(revision)
    audit_row = audit_rows.get(sequence)
    if (
        case_row is None
        or audit_row is None
        or _integer(case_row, "audit_sequence") != sequence
        or _text(case_row, "status") != case_status
        or _sha256(audit_row, "entry_hash") != audit_hash
        or _text(audit_row, "actor") != "SYSTEM"
        or _text(audit_row, "action") != "CASE_STATE_CHANGED"
        or _text(audit_row, "object_kind") != "BACKLOG_ITEM"
        or _text(audit_row, "object_id") != backlog_item_id
        or _sha256(audit_row, "after_sha256") != _sha256(case_row, "document_sha256")
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    slots.append(
        _support_slot(
            case_row,
            M6SQLiteM4SupportRoute.CASE_VERSION,
            f"{_text(case_row, 'case_id')}:{revision}",
        )
    )
    slots.append(_support_slot(audit_row, M6SQLiteM4SupportRoute.AUDIT_ENTRY, str(sequence)))


def _backlog_indexes(
    rows: _M4BacklogSupportRows,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
) -> tuple[
    dict[str, sqlite3.Row],
    dict[str, list[sqlite3.Row]],
    dict[str, sqlite3.Row],
    dict[str, sqlite3.Row],
    dict[str, sqlite3.Row],
    dict[str, sqlite3.Row],
    dict[str, sqlite3.Row],
    dict[str, sqlite3.Row],
]:
    items = _scoped_rows_by_sha(
        rows.items,
        id_column="item_id",
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    versions: dict[str, list[sqlite3.Row]] = {}
    for row in rows.versions:
        if _text(row, "run_id") != run_id:
            _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
        item_id = _sha256(row, "item_id")
        if item_id not in items:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        versions.setdefault(item_id, []).append(row)
    heads: dict[str, sqlite3.Row] = {}
    for row in rows.heads:
        if _text(row, "run_id") != run_id:
            _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
        item_id = _sha256(row, "item_id")
        if item_id not in items or item_id in heads:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        heads[item_id] = row
    scoped_groups = (
        (rows.retry_outcomes, "outcome_id"),
        (rows.completions, "receipt_id"),
        (rows.strict_attempts, "attempt_id"),
        (rows.strict_proofs, "proof_id"),
        (rows.human_reviews, "receipt_id"),
    )
    indexed_groups: list[dict[str, sqlite3.Row]] = []
    for values, column in scoped_groups:
        indexed_groups.append(
            _scoped_rows_by_sha(
                values,
                id_column=column,
                run_id=run_id,
                case_id=case_id,
                manifest_id=manifest_id,
            )
        )
    return (
        items,
        versions,
        heads,
        indexed_groups[0],
        indexed_groups[1],
        indexed_groups[2],
        indexed_groups[3],
        indexed_groups[4],
    )


def _append_backlog_version(
    connection: M6LiveReader,
    row: sqlite3.Row,
    *,
    slots: list[M6SQLiteM4SupportSlot],
    documents: list[M6SQLiteM4SupportDocumentSlot],
) -> None:
    _append_pair(
        connection,
        row,
        row_route=M6SQLiteM4SupportRoute.BACKLOG_ITEM_VERSION,
        document_route=M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM_VERSION,
        artifact_id=_sha256(row, "document_sha256"),
        slots=slots,
        documents=documents,
    )


def _bind_checkpoint_support(
    connection: M6LiveReader,
    *,
    failure_rows: tuple[_Failure, ...],
    hearing_rows: _M4HearingSupportRows,
    run_id: str,
    case_id: str,
    manifest_id: str,
    slots: list[M6SQLiteM4SupportSlot],
    documents: list[M6SQLiteM4SupportDocumentSlot],
) -> None:
    checkpoints = _scoped_rows_by_sha(
        hearing_rows.checkpoints,
        id_column="checkpoint_id",
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    expected_hearings = {_sha256(value.row, "hearing_id") for value in failure_rows}
    for failure in failure_rows:
        row = checkpoints.get(_sha256(failure.row, "source_checkpoint_id"))
        if (
            row is None
            or _sha256(row, "checkpoint_sha256") != _sha256(failure.row, "source_checkpoint_sha256")
            or _integer(row, "version", minimum=1)
            != _integer(failure.row, "source_checkpoint_version", minimum=1)
            or _sha256(row, "hearing_id") != _sha256(failure.row, "hearing_id")
            or _sha256(row, "cycle_scope_id") != _sha256(failure.row, "cycle_scope_id")
            or _sha256(row, "cycle_scope_sha256") != _sha256(failure.row, "cycle_scope_sha256")
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _append_pair(
            connection,
            row,
            row_route=M6SQLiteM4SupportRoute.HEARING_CHECKPOINT,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT,
            artifact_id=_sha256(row, "checkpoint_id"),
            slots=slots,
            documents=documents,
        )
    for row in hearing_rows.rounds:
        if (
            _text(row, "run_id") != run_id
            or _text(row, "case_id") != case_id
            or _sha256(row, "manifest_id") != manifest_id
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH)
        if _sha256(row, "hearing_id") not in expected_hearings:
            continue
        _append_pair(
            connection,
            row,
            row_route=M6SQLiteM4SupportRoute.HEARING_ROUND,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_ROUND,
            artifact_id=_sha256(row, "round_id"),
            slots=slots,
            documents=documents,
        )


def _bind_auxiliary_backlog_documents(
    connection: M6LiveReader,
    *,
    item_ids: set[str],
    outcomes: dict[str, sqlite3.Row],
    attempts: dict[str, sqlite3.Row],
    proofs: dict[str, sqlite3.Row],
    human_reviews: dict[str, sqlite3.Row],
    slots: list[M6SQLiteM4SupportSlot],
    documents: list[M6SQLiteM4SupportDocumentSlot],
) -> None:
    selected_proofs = {
        proof_id: row
        for proof_id, row in proofs.items()
        if _sha256(row, "backlog_item_id") in item_ids
    }
    referenced_attempt_ids: set[str] = set()
    for proof_id, row in selected_proofs.items():
        closure_kind = _text(row, "closure_kind")
        lease_identity = _optional_sha256(row, "lease_identity_sha256")
        lease_id = _optional_sha256(row, "lease_id")
        if closure_kind == M6SQLiteM4FailureClosureKind.INITIAL_BACKLOG.value:
            if lease_identity is not None or lease_id is not None:
                _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        elif (
            closure_kind != M6SQLiteM4FailureClosureKind.RETRY_FAILURE.value
            or lease_identity is None
            or lease_id is None
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        referenced_attempt_ids.update(
            (
                _sha256(row, "primary_attempt_id"),
                _sha256(row, "repair_attempt_id"),
            )
        )
        _append_pair(
            connection,
            row,
            row_route=M6SQLiteM4SupportRoute.STRICT_PARSE_FAILURE_PROOF,
            document_route=M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_PROOF,
            artifact_id=proof_id,
            slots=slots,
            documents=documents,
        )
    for attempt_id in sorted(referenced_attempt_ids):
        attempt_row = attempts.get(attempt_id)
        if attempt_row is None or _sha256(attempt_row, "backlog_item_id") not in item_ids:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _append_pair(
            connection,
            attempt_row,
            row_route=M6SQLiteM4SupportRoute.STRICT_PARSE_FAILURE_ATTEMPT,
            document_route=M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_ATTEMPT,
            artifact_id=attempt_id,
            slots=slots,
            documents=documents,
        )
    referenced_human_ids = {
        human_id
        for row in outcomes.values()
        if _sha256(row, "backlog_item_id") in item_ids
        for human_id in (_optional_sha256(row, "human_review_receipt_id"),)
        if human_id is not None
    }
    for human_id in sorted(referenced_human_ids):
        human_row = human_reviews.get(human_id)
        if human_row is None or _optional_sha256(human_row, "backlog_item_id") not in item_ids:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _append_pair(
            connection,
            human_row,
            row_route=M6SQLiteM4SupportRoute.HEARING_HUMAN_REVIEW_RECEIPT,
            document_route=M6SQLiteM4SupportDocumentRoute.HEARING_HUMAN_REVIEW_RECEIPT,
            artifact_id=human_id,
            slots=slots,
            documents=documents,
        )


def resolve_failure_support(
    connection: M6LiveReader,
    *,
    base: _ResolvedSupport,
    run_id: str,
    case_id: str,
    manifest_id: str,
    claims: dict[str, _Claim],
    failures: tuple[_Failure, ...],
    terminal_request_ids: set[str],
    base_rows: _M4BaseSupportRows,
    hearing_rows: _M4HearingSupportRows,
    backlog_rows: _M4BacklogSupportRows,
) -> _ResolvedSupport:
    """Close provider-failure epochs to typed hearing/backlog support rows."""

    if not failures:
        return base
    case_rows, audit_rows = _case_closure_rows(
        base_rows,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    (
        items,
        versions,
        heads,
        outcomes,
        completions,
        attempts,
        proofs,
        human_reviews,
    ) = _backlog_indexes(
        backlog_rows,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    slots: list[M6SQLiteM4SupportSlot] = []
    documents: list[M6SQLiteM4SupportDocumentSlot] = []
    _bind_checkpoint_support(
        connection,
        failure_rows=failures,
        hearing_rows=hearing_rows,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        slots=slots,
        documents=documents,
    )
    failure_by_completion: dict[str, _Failure] = {}
    item_ids = {_sha256(value.row, "backlog_item_id") for value in failures}
    failures_by_item: dict[str, list[_Failure]] = {}
    for failure in failures:
        item_id = _sha256(failure.row, "backlog_item_id")
        failures_by_item.setdefault(item_id, []).append(failure)
        completion_id = _optional_sha256(failure.row, "completion_receipt_id")
        if completion_id is not None:
            if completion_id in failure_by_completion:
                _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            failure_by_completion[completion_id] = failure

    completion_by_item_version: dict[tuple[str, int], sqlite3.Row] = {}
    selected_outcome_ids: set[str] = set()
    for receipt_id, row in completions.items():
        item_id = _sha256(row, "item_id")
        if item_id not in item_ids:
            continue
        version = _integer(row, "backlog_version", minimum=1)
        key = (item_id, version)
        if key in completion_by_item_version:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        completion_by_item_version[key] = row
        outcome_id = _sha256(row, "outcome_id")
        outcome = outcomes.get(outcome_id)
        if (
            outcome is None
            or _text(row, "outcome_kind") != _text(outcome, "outcome_kind")
            or _sha256(outcome, "backlog_item_id") != item_id
            or _sha256(row, "hearing_id") != _sha256(outcome, "hearing_id")
            or _text(row, "role") != _text(outcome, "role")
            or _sha256(row, "lease_identity_sha256") != _sha256(outcome, "lease_identity_sha256")
            or _sha256(row, "lease_id") != _sha256(outcome, "lease_id")
            or _integer(row, "attempt_count") != _integer(outcome, "lease_attempt_count")
            or _integer(row, "retry_generation") != _integer(outcome, "retry_generation")
            or _sha256(row, "source_checkpoint_id") != _sha256(outcome, "source_checkpoint_id")
            or _sha256(row, "source_checkpoint_sha256")
            != _sha256(outcome, "source_checkpoint_sha256")
            or _integer(row, "source_checkpoint_version", minimum=1)
            != _integer(outcome, "source_checkpoint_version", minimum=1)
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        selected_outcome_ids.add(outcome_id)
        _append_pair(
            connection,
            row,
            row_route=M6SQLiteM4SupportRoute.BACKLOG_COMPLETION_RECEIPT,
            document_route=M6SQLiteM4SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT,
            artifact_id=receipt_id,
            slots=slots,
            documents=documents,
        )
        _append_pair(
            connection,
            outcome,
            row_route=M6SQLiteM4SupportRoute.BACKLOG_RETRY_OUTCOME,
            document_route=M6SQLiteM4SupportDocumentRoute.BACKLOG_RETRY_OUTCOME,
            artifact_id=outcome_id,
            slots=slots,
            documents=documents,
        )
        _bind_case_closure(
            revision=_integer(row, "completion_case_revision", minimum=1),
            sequence=_integer(row, "completion_audit_sequence"),
            audit_hash=_sha256(row, "completion_audit_entry_hash"),
            backlog_item_id=item_id,
            case_status=_text(row, "completion_case_status"),
            case_rows=case_rows,
            audit_rows=audit_rows,
            slots=slots,
        )

    for item_id in sorted(item_ids):
        item = items.get(item_id)
        head = heads.get(item_id)
        item_versions = sorted(
            versions.get(item_id, ()), key=lambda row: _integer(row, "version", minimum=1)
        )
        if item is None or head is None or not item_versions:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        current_version = _integer(head, "current_version", minimum=1)
        if tuple(_integer(row, "version", minimum=1) for row in item_versions) != tuple(
            range(1, current_version + 1)
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        related = failures_by_item[item_id]
        if (
            _text(item, "stage") != "HEARING"
            or _text(item, "stage_input_kind") != "MODEL_REQUEST"
            or _text(item, "role") != _text(related[0].row, "role")
            or _text(item, "reason_code")
            != _text(
                min(related, key=lambda value: value.takeover_count).row, "backlog_reason_code"
            )
            or any(
                _text(value.row, "role") != _text(item, "role")
                or _sha256(value.row, "manifest_id") != _sha256(item, "manifest_id")
                for value in related
            )
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        stage_request_id = _sha256(item, "stage_input_id")
        stage_claim = claims.get(stage_request_id)
        if (
            stage_claim is None
            or _sha256(item, "stage_input_sha256") != stage_claim.request_slot.document_sha256
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _append_pair(
            connection,
            item,
            row_route=M6SQLiteM4SupportRoute.BACKLOG_ITEM,
            document_route=M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM,
            artifact_id=item_id,
            slots=slots,
            documents=documents,
        )
        slots.append(_support_slot(head, M6SQLiteM4SupportRoute.BACKLOG_HEAD, item_id))
        for index, version_row in enumerate(item_versions):
            _append_backlog_version(
                connection,
                version_row,
                slots=slots,
                documents=documents,
            )
            if index == 0:
                if (
                    _text(version_row, "status") != "PENDING"
                    or _integer(version_row, "attempt_count") != 0
                    or _integer(version_row, "retry_generation") != 0
                ):
                    _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
                continue
            previous = item_versions[index - 1]
            if (
                _text(previous, "status") == "LEASED"
                and _text(version_row, "status") != "LEASED"
                and (item_id, _integer(version_row, "version", minimum=1))
                not in completion_by_item_version
            ):
                _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        for failure in related:
            version_number = _integer(failure.row, "backlog_version", minimum=1)
            if version_number > current_version:
                _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            version_row = item_versions[version_number - 1]
            if (
                _text(version_row, "status") != _text(failure.row, "backlog_status")
                or _integer(version_row, "attempt_count")
                != _integer(failure.row, "backlog_attempt_count")
                or _integer(version_row, "retry_generation")
                != _integer(failure.row, "retry_generation")
                or any(
                    _optional_text(version_row, column) is not None
                    for column in ("lease_id", "lease_owner_sha256", "lease_expires_at")
                )
            ):
                _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            if failure.request_id in terminal_request_ids and version_number != current_version:
                _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            closure_kind = M6SQLiteM4FailureClosureKind(_text(failure.row, "closure_kind"))
            completion_id = _optional_sha256(failure.row, "completion_receipt_id")
            if closure_kind == M6SQLiteM4FailureClosureKind.INITIAL_BACKLOG:
                if version_number != 1 or completion_id is not None:
                    _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            else:
                completion = completions.get(completion_id or "")
                outcome = (
                    outcomes.get(_sha256(completion, "outcome_id"))
                    if completion is not None
                    else None
                )
                if (
                    completion is None
                    or outcome is None
                    or _text(completion, "outcome_kind") != "FAILURE"
                    or _text(outcome, "outcome_kind") != "FAILURE"
                    or _sha256(outcome, "request_id") != failure.request_id
                    or _sha256(outcome, "request_sha256") != _sha256(failure.row, "request_sha256")
                    or _text(outcome, "reason_code") != _text(failure.row, "backlog_reason_code")
                    or _text(outcome, "next_status") != _text(failure.row, "backlog_status")
                    or _sha256(completion, "completion_audit_entry_hash")
                    != _sha256(failure.row, "closure_audit_entry_hash")
                    or _integer(completion, "completion_case_revision", minimum=1)
                    != _integer(failure.row, "closure_case_revision", minimum=1)
                    or _integer(completion, "completion_audit_sequence")
                    != _integer(failure.row, "closure_audit_sequence")
                ):
                    _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            _bind_case_closure(
                revision=_integer(failure.row, "closure_case_revision", minimum=1),
                sequence=_integer(failure.row, "closure_audit_sequence"),
                audit_hash=_sha256(failure.row, "closure_audit_entry_hash"),
                backlog_item_id=item_id,
                case_status=(
                    "HUMAN_REVIEW"
                    if _text(failure.row, "backlog_status") == "EXHAUSTED"
                    else "BACKLOGGED"
                ),
                case_rows=case_rows,
                audit_rows=audit_rows,
                slots=slots,
            )

    if set(failure_by_completion) - set(completions):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    _bind_auxiliary_backlog_documents(
        connection,
        item_ids=item_ids,
        outcomes={key: outcomes[key] for key in selected_outcome_ids},
        attempts=attempts,
        proofs=proofs,
        human_reviews=human_reviews,
        slots=slots,
        documents=documents,
    )
    return _ResolvedSupport(
        hearing_bindings=base.hearing_bindings,
        selected_packs=base.selected_packs,
        contexts=base.contexts,
        slots=_merge_slots(base.slots, slots),
        document_slots=_merge_documents(base.document_slots, documents),
    )
