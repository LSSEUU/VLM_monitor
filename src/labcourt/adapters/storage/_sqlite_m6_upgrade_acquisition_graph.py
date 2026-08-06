"""Fail-closed metadata graph for persisted M4 acquisition closures.

The graph consumes rows that were already enumerated by Case scope.  It never
uses an executor Observation as a SQL whitelist and never materializes a JSON
body.  Complete authorities after the selected Case audit cut are normalized
and ignored; an incomplete authority has no trustworthy cut anchor and fails
closed.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import NoReturn

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    ArtifactKind,
    AuditAction,
)
from labcourt.contracts.evidence import EvidencePack, ToolResult
from labcourt.contracts.m6_replay_locked import M6LockedModelRole
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_acquisition_plan import (
    M6SQLiteAcquisitionClaimState,
    M6SQLiteAcquisitionClosurePlan,
    M6SQLiteAcquisitionCompletedClaimSlot,
    M6SQLiteAcquisitionManifestSlot,
    M6SQLiteAcquisitionPackTransitionBinding,
    M6SQLiteAcquisitionPlanFailureCode,
    M6SQLiteAcquisitionSelectedPackBinding,
    M6SQLiteAcquisitionSupportDocumentRoute,
    M6SQLiteAcquisitionSupportDocumentSlot,
    M6SQLiteAcquisitionSupportRoute,
    M6SQLiteAcquisitionSupportSlot,
    M6SQLiteAcquisitionToolResultBinding,
    M6SQLiteAcquisitionUpstreamM4Binding,
    _M6SQLiteAcquisitionMetadataFailure,
)
from ._sqlite_m6_upgrade_acquisition_rows import (
    M6SQLiteAcquisitionHearingSupportRows,
    M6SQLiteAcquisitionOutputSupportRows,
    M6SQLiteAcquisitionPrimaryRows,
    M6SQLiteAcquisitionRowDocumentRoute,
    M6SQLiteAcquisitionTransitionSupportRows,
    document_bytes,
)
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4ModelDocumentsPlan,
    M6SQLiteM4SupportRoute,
)
from ._sqlite_m6_upgrade_m4_model_plan import (
    _plan_is_consistent as _m4_plan_is_consistent,
)
from ._sqlite_m6_upgrade_m4_model_primitives import _case_authority_is_consistent


def _fail(reason_code: M6SQLiteAcquisitionPlanFailureCode) -> NoReturn:
    raise _M6SQLiteAcquisitionMetadataFailure(reason_code)


def _value(row: sqlite3.Row, column: str) -> object:
    try:
        return row[column]
    except (IndexError, KeyError, TypeError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)


def _text(row: sqlite3.Row, column: str) -> str:
    value = _value(row, column)
    if type(value) is not str or not value:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _optional_text(row: sqlite3.Row, column: str) -> str | None:
    value = _value(row, column)
    if value is not None and (type(value) is not str or not value):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _integer(row: sqlite3.Row, column: str, *, minimum: int = 0) -> int:
    value = _value(row, column)
    if type(value) is not int or value < minimum:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _sha256(row: sqlite3.Row, column: str) -> str:
    value = _text(row, column)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _optional_sha256(row: sqlite3.Row, column: str) -> str | None:
    value = _optional_text(row, column)
    if value is not None and (
        len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _scope(
    row: sqlite3.Row,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str | None = None,
) -> None:
    if _text(row, "run_id") != run_id or _text(row, "case_id") != case_id:
        _fail(M6SQLiteAcquisitionPlanFailureCode.SCOPE_MISMATCH)
    if manifest_id is not None and _sha256(row, "manifest_id") != manifest_id:
        _fail(M6SQLiteAcquisitionPlanFailureCode.SCOPE_MISMATCH)


def _index_identity(row: sqlite3.Row, domain: str, columns: tuple[str, ...]) -> str:
    """Hash one explicit, versioned relational projection (never JSON bytes)."""

    values: list[list[object]] = []
    for column in columns:
        value = _value(row, column)
        if value is not None and type(value) not in (str, int, float):
            _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
        values.append([column, value])
    try:
        encoded = canonical_json(["m6-sqlite-acquisition-index", 1, domain, values]).encode("utf-8")
    except (TypeError, UnicodeError, ValueError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    return hashlib.sha256(encoded).hexdigest()


_REQUEST_COLUMNS = (
    "document_rowid",
    "run_id",
    "acquisition_request_id",
    "hearing_id",
    "cycle_scope_id",
    "cycle_scope_sha256",
    "case_id",
    "round_index",
    "prior_acquisition_rounds",
    "prior_rework_rounds",
    "evidence_pack_id",
    "evidence_pack_version",
    "judge_output_id",
    "source_model_request_id",
    "source_model_response_id",
    "action",
    "validated_parameters_sha256",
    "manifest_id",
    "document_sha256",
)
_CLAIM_COLUMNS = (
    "document_rowid",
    "run_id",
    "acquisition_request_id",
    "request_document_sha256",
    "case_id",
    "hearing_id",
    "execution_mode",
    "idempotency_key",
    "status",
    "owner_token_sha256",
    "owner_fence",
    "lease_expires_at",
    "execution_publication_id",
    "created_at",
    "updated_at",
    "document_sha256",
)
_MANIFEST_COLUMNS = (
    "document_rowid",
    "run_id",
    "execution_manifest_id",
    "case_id",
    "hearing_id",
    "acquisition_request_id",
    "action",
    "tool_id",
    "tool_revision",
    "parameters_schema_sha256",
    "component_manifest_id",
    "model_manifest_id",
    "manifest_id",
    "document_sha256",
)
_PUBLICATION_COLUMNS = (
    "document_rowid",
    "run_id",
    "execution_publication_id",
    "acquisition_request_id",
    "request_document_sha256",
    "case_id",
    "hearing_id",
    "execution_manifest_id",
    "tool_result_id",
    "execution_mode",
    "idempotency_key",
    "claim_owner_sha256",
    "claim_fence",
    "document_sha256",
)
_RECEIPT_COLUMNS = (
    "document_rowid",
    "run_id",
    "receipt_id",
    "acquisition_request_id",
    "hearing_id",
    "cycle_scope_id",
    "cycle_scope_sha256",
    "case_id",
    "action",
    "execution_manifest_id",
    "tool_result_id",
    "resulting_pack_id",
    "resulting_pack_version",
    "document_sha256",
)
_DERIVATION_COLUMNS = (
    "document_rowid",
    "run_id",
    "derivation_id",
    "hearing_id",
    "source_cycle_scope_id",
    "source_cycle_scope_sha256",
    "case_id",
    "previous_pack_id",
    "previous_pack_version",
    "new_pack_id",
    "new_pack_version",
    "tool_receipt_id",
    "manifest_id",
    "document_sha256",
)
_PACK_COLUMNS = (
    "document_rowid",
    "run_id",
    "pack_id",
    "case_id",
    "manifest_id",
    "version",
    "complete",
    "pack_input_sha256",
    "closure_input_sha256",
    "document_sha256",
    "created_audit_sequence",
)
_CHECKPOINT_COLUMNS = (
    "support_rowid",
    "run_id",
    "checkpoint_id",
    "checkpoint_sha256",
    "hearing_id",
    "hearing_sha256",
    "cycle_scope_id",
    "cycle_scope_sha256",
    "case_id",
    "version",
    "phase",
    "judge_cycle",
    "prior_acquisition_rounds",
    "prior_rework_rounds",
    "cycle_pack_id",
    "cycle_pack_version",
    "current_pack_id",
    "current_pack_version",
    "previous_checkpoint_id",
    "previous_checkpoint_sha256",
    "previous_phase",
    "initial_trigger_review_id",
    "cycle_trigger_review_id",
    "retrieval_receipt_id",
    "retrieval_receipt_sha256",
    "prosecutor_output_id",
    "defender_output_id",
    "judge_output_id",
    "acquisition_request_id",
    "tool_receipt_id",
    "procedural_review_id",
    "human_review_receipt_id",
    "human_review_receipt_sha256",
    "human_review_reason",
    "manifest_id",
    "body_commitment_sha256",
)
_ROUND_COLUMNS = (
    "support_rowid",
    "run_id",
    "round_id",
    "hearing_id",
    "cycle_scope_id",
    "cycle_scope_sha256",
    "case_id",
    "round_index",
    "prior_acquisition_rounds",
    "prior_rework_rounds",
    "current_pack_id",
    "current_pack_version",
    "precedent_retrieval_degraded",
    "retrieval_receipt_id",
    "retrieval_receipt_sha256",
    "initial_trigger_review_id",
    "rework_review_id",
    "prosecutor_output_id",
    "defender_output_id",
    "judge_output_id",
    "acquisition_request_id",
    "tool_receipt_id",
    "resulting_pack_id",
    "resulting_pack_version",
    "manifest_id",
    "body_commitment_sha256",
)
_CASE_COLUMNS = (
    "support_rowid",
    "run_id",
    "case_id",
    "revision",
    "status",
    "document_sha256",
    "audit_sequence",
    "body_commitment_sha256",
)
_AUDIT_COLUMNS = (
    "support_rowid",
    "run_id",
    "sequence",
    "manifest_id",
    "actor",
    "action",
    "object_kind",
    "object_id",
    "before_sha256",
    "after_sha256",
    "recorded_at",
    "prev_entry_hash",
    "entry_hash",
    "document_sha256",
    "body_commitment_sha256",
)
_FRAME_COLUMNS = (
    "support_rowid",
    "run_id",
    "frame_id",
    "manifest_id",
    "camera_id",
    "stream_id",
    "frame_index",
    "fps_num",
    "fps_den",
    "width",
    "height",
    "content_sha256",
    "document_sha256",
)
_DETECTION_COLUMNS = (
    "support_rowid",
    "run_id",
    "detection_id",
    "frame_id",
    "manifest_id",
    "detector_manifest_id",
    "label",
    "document_sha256",
    "registered_at",
)
_CROP_COLUMNS = (
    "support_rowid",
    "run_id",
    "crop_id",
    "case_id",
    "hearing_id",
    "acquisition_request_id",
    "execution_manifest_id",
    "frame_id",
    "media_sha256",
    "source_media_sha256",
    "pixel_sha256",
    "source_pack_id",
    "source_pack_version",
    "manifest_id",
    "document_sha256",
)


@dataclass(frozen=True, slots=True)
class _NormalizedAcquisition:
    request: sqlite3.Row
    claim: sqlite3.Row
    manifest: sqlite3.Row
    publication: sqlite3.Row
    receipt: sqlite3.Row
    derivation: sqlite3.Row
    previous_pack: sqlite3.Row
    resulting_pack: sqlite3.Row
    request_id: str
    hearing_id: str
    cycle_scope_id: str
    cycle_scope_sha256: str
    action: AcquisitionAction
    execution_manifest_id: str
    publication_id: str
    tool_result_id: str
    receipt_id: str
    derivation_id: str
    is_post_cut: bool


def _unique_by(
    rows: tuple[sqlite3.Row, ...],
    column: str,
) -> dict[str, sqlite3.Row]:
    result: dict[str, sqlite3.Row] = {}
    for row in rows:
        identity = _text(row, column)
        if identity in result:
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        result[identity] = row
    return result


def _rows_by_request(
    rows: tuple[sqlite3.Row, ...],
) -> dict[str, sqlite3.Row]:
    return _unique_by(rows, "acquisition_request_id")


def _classify_primary_cut(
    primary_rows: M6SQLiteAcquisitionPrimaryRows,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    selected_audit_sequence: int,
) -> tuple[_NormalizedAcquisition, ...]:
    """Normalize all six tables before classifying by successor-pack audit cut."""

    requests = _unique_by(primary_rows.requests, "acquisition_request_id")
    claims = _rows_by_request(primary_rows.claims)
    manifests = _rows_by_request(primary_rows.manifests)
    publications = _rows_by_request(primary_rows.publications)
    receipts = _rows_by_request(primary_rows.receipts)
    derivations_by_receipt = _unique_by(primary_rows.derivations, "tool_receipt_id")
    # ACTIVE/ABANDONED is a typed unsupported boundary even though those
    # states correctly have no publication-side closure yet.
    for claim in claims.values():
        if _text(claim, "status") in {
            M6SQLiteAcquisitionClaimState.ACTIVE.value,
            M6SQLiteAcquisitionClaimState.ABANDONED.value,
        }:
            _fail(M6SQLiteAcquisitionPlanFailureCode.UNSUPPORTED_ACQUISITION_STATE)
    if not (set(requests) == set(claims) == set(manifests) == set(publications) == set(receipts)):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    if len(derivations_by_receipt) != len(receipts):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)

    packs_by_key: dict[tuple[str, int], sqlite3.Row] = {}
    pack_ids: set[str] = set()
    for row in primary_rows.packs:
        _scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        key = (_sha256(row, "pack_id"), _integer(row, "version", minimum=1))
        if key in packs_by_key or key[0] in pack_ids:
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        if _integer(row, "complete") not in (0, 1):
            _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
        _sha256(row, "pack_input_sha256")
        _sha256(row, "closure_input_sha256")
        _sha256(row, "document_sha256")
        _integer(row, "created_audit_sequence")
        packs_by_key[key] = row
        pack_ids.add(key[0])

    normalized: list[_NormalizedAcquisition] = []
    seen_derivations: set[str] = set()
    for request_id in sorted(requests):
        request = requests[request_id]
        claim = claims[request_id]
        manifest = manifests[request_id]
        publication = publications[request_id]
        receipt = receipts[request_id]
        for row in (request, claim, manifest, publication, receipt):
            _scope(row, run_id=run_id, case_id=case_id)
        _scope(request, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        _scope(manifest, run_id=run_id, case_id=case_id, manifest_id=manifest_id)

        status = _text(claim, "status")
        if status != M6SQLiteAcquisitionClaimState.COMPLETED.value:
            if status in {
                M6SQLiteAcquisitionClaimState.ACTIVE.value,
                M6SQLiteAcquisitionClaimState.ABANDONED.value,
            }:
                _fail(M6SQLiteAcquisitionPlanFailureCode.UNSUPPORTED_ACQUISITION_STATE)
            _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
        publication_id = _sha256(publication, "execution_publication_id")
        if (
            _optional_text(claim, "lease_expires_at") is not None
            or _optional_text(claim, "execution_publication_id") != publication_id
            or _sha256(claim, "idempotency_key") != request_id
            or _sha256(publication, "idempotency_key") != request_id
            or _sha256(claim, "request_document_sha256") != _sha256(request, "document_sha256")
            or _sha256(publication, "request_document_sha256")
            != _sha256(request, "document_sha256")
            or _sha256(claim, "owner_token_sha256") != _sha256(publication, "claim_owner_sha256")
            or _integer(claim, "owner_fence", minimum=1)
            != _integer(publication, "claim_fence", minimum=1)
            or _text(claim, "hearing_id") != _sha256(request, "hearing_id")
            or _text(publication, "hearing_id") != _sha256(request, "hearing_id")
        ):
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        try:
            claim_mode = AcquisitionExecutionMode(_text(claim, "execution_mode"))
            publication_mode = AcquisitionExecutionMode(_text(publication, "execution_mode"))
            action = AcquisitionAction(_text(request, "action"))
        except ValueError:
            _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
        if claim_mode != publication_mode:
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)

        hearing_id = _sha256(request, "hearing_id")
        cycle_scope_id = _sha256(request, "cycle_scope_id")
        cycle_scope_sha256 = _sha256(request, "cycle_scope_sha256")
        round_index = _integer(request, "round_index", minimum=1)
        prior_acquisition = _integer(request, "prior_acquisition_rounds")
        prior_rework = _integer(request, "prior_rework_rounds")
        if round_index != 1 + prior_acquisition + prior_rework:
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        execution_manifest_id = _sha256(manifest, "execution_manifest_id")
        tool_result_id = _sha256(publication, "tool_result_id")
        receipt_id = _sha256(receipt, "receipt_id")
        derivation = derivations_by_receipt.get(receipt_id)
        if derivation is None:
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        seen_derivations.add(receipt_id)
        _scope(derivation, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        derivation_id = _sha256(derivation, "derivation_id")
        previous_key = (
            _sha256(derivation, "previous_pack_id"),
            _integer(derivation, "previous_pack_version", minimum=1),
        )
        resulting_key = (
            _sha256(derivation, "new_pack_id"),
            _integer(derivation, "new_pack_version", minimum=1),
        )
        previous_pack = packs_by_key.get(previous_key)
        resulting_pack = packs_by_key.get(resulting_key)
        if previous_pack is None or resulting_pack is None:
            _fail(M6SQLiteAcquisitionPlanFailureCode.POST_CUT_AUTHORITY)

        joined = (
            _sha256(manifest, "acquisition_request_id") == request_id
            and _sha256(publication, "acquisition_request_id") == request_id
            and _text(receipt, "acquisition_request_id") == request_id
            and _sha256(manifest, "hearing_id") == hearing_id
            and _sha256(receipt, "hearing_id") == hearing_id
            and _sha256(derivation, "hearing_id") == hearing_id
            and _sha256(receipt, "cycle_scope_id") == cycle_scope_id
            and _sha256(receipt, "cycle_scope_sha256") == cycle_scope_sha256
            and _sha256(derivation, "source_cycle_scope_id") == cycle_scope_id
            and _sha256(derivation, "source_cycle_scope_sha256") == cycle_scope_sha256
            and _text(manifest, "action") == action.value
            and _text(receipt, "action") == action.value
            and _sha256(publication, "execution_manifest_id") == execution_manifest_id
            and _sha256(receipt, "execution_manifest_id") == execution_manifest_id
            and _sha256(receipt, "tool_result_id") == tool_result_id
            and _sha256(receipt, "resulting_pack_id") == resulting_key[0]
            and _integer(receipt, "resulting_pack_version", minimum=1) == resulting_key[1]
            and _sha256(derivation, "tool_receipt_id") == receipt_id
            and previous_key
            == (
                _sha256(request, "evidence_pack_id"),
                _integer(request, "evidence_pack_version", minimum=1),
            )
            and resulting_key[1] == previous_key[1] + 1
            and resulting_key[0] != previous_key[0]
        )
        if not joined:
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        for row in (request, claim, manifest, publication, receipt, derivation):
            _sha256(row, "document_sha256")
        is_post_cut = _integer(resulting_pack, "created_audit_sequence") > selected_audit_sequence
        normalized.append(
            _NormalizedAcquisition(
                request=request,
                claim=claim,
                manifest=manifest,
                publication=publication,
                receipt=receipt,
                derivation=derivation,
                previous_pack=previous_pack,
                resulting_pack=resulting_pack,
                request_id=request_id,
                hearing_id=hearing_id,
                cycle_scope_id=cycle_scope_id,
                cycle_scope_sha256=cycle_scope_sha256,
                action=action,
                execution_manifest_id=execution_manifest_id,
                publication_id=publication_id,
                tool_result_id=tool_result_id,
                receipt_id=receipt_id,
                derivation_id=derivation_id,
                is_post_cut=is_post_cut,
            )
        )
    if set(derivations_by_receipt) != seen_derivations:
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    return tuple(normalized)


def _require_upstream_m4_membership(
    plan: M6SQLiteM4ModelDocumentsPlan,
    closure: _NormalizedAcquisition,
) -> M6SQLiteAcquisitionUpstreamM4Binding:
    """Bind request source IDs to exact M4 plan slots without rereading bodies."""

    matching = tuple(
        graph
        for graph in plan.call_graphs
        if graph.role_output is not None
        and graph.role_output.artifact_id == _sha256(closure.request, "judge_output_id")
    )
    if len(matching) != 1:
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    graph = matching[0]
    response = graph.response
    role_output = graph.role_output
    assert role_output is not None
    if (
        graph.observation.role != M6LockedModelRole.JUDGE
        or graph.hearing_id != closure.hearing_id
        or graph.cycle_scope_id != closure.cycle_scope_id
        or graph.cycle_scope_sha256 != closure.cycle_scope_sha256
        or graph.cycle_index != _integer(closure.request, "round_index", minimum=1)
        or graph.prior_acquisition_rounds != _integer(closure.request, "prior_acquisition_rounds")
        or graph.prior_rework_rounds != _integer(closure.request, "prior_rework_rounds")
        or graph.evidence_pack_id != _sha256(closure.request, "evidence_pack_id")
        or graph.evidence_pack_version
        != _integer(closure.request, "evidence_pack_version", minimum=1)
        or graph.request.artifact_id != _sha256(closure.request, "source_model_request_id")
        or response is None
        or response.artifact_id != _sha256(closure.request, "source_model_response_id")
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    hearing_slots = tuple(
        slot
        for slot in plan.support_slots
        if slot.route == M6SQLiteM4SupportRoute.HEARING_SESSION
        and slot.identity == closure.hearing_id
    )
    cycle_slots = tuple(
        slot
        for slot in plan.support_slots
        if slot.route == M6SQLiteM4SupportRoute.HEARING_CYCLE
        and slot.identity == closure.cycle_scope_id
    )
    if len(hearing_slots) != 1 or len(cycle_slots) != 1:
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    hearing_slot = hearing_slots[0]
    cycle_slot = cycle_slots[0]
    try:
        return M6SQLiteAcquisitionUpstreamM4Binding(
            upstream_m4_model_plan_identity_sha256=plan.plan_identity_sha256,
            run_id=plan.run_id,
            case_id=plan.case_id,
            hearing_id=closure.hearing_id,
            hearing_rowid=hearing_slot.rowid,
            hearing_support_index_identity_sha256=hearing_slot.index_identity_sha256,
            cycle_scope_id=closure.cycle_scope_id,
            cycle_scope_sha256=closure.cycle_scope_sha256,
            cycle_rowid=cycle_slot.rowid,
            cycle_support_index_identity_sha256=cycle_slot.index_identity_sha256,
            judge_output_id=role_output.artifact_id,
            judge_output_document_sha256=role_output.document_sha256,
            judge_output_rowid=role_output.rowid,
            judge_output_index_identity_sha256=role_output.index_identity_sha256,
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)


def _pending_checkpoints(
    rows: M6SQLiteAcquisitionHearingSupportRows,
    closures: tuple[_NormalizedAcquisition, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
) -> dict[str, sqlite3.Row]:
    requests = {value.request_id: value for value in closures}
    pending: dict[str, sqlite3.Row] = {}
    for row in rows.checkpoints:
        _scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        if _text(row, "phase") != "ACQUISITION_PENDING":
            continue
        request_id = _optional_text(row, "acquisition_request_id")
        if request_id is None or request_id not in requests or request_id in pending:
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        closure = requests[request_id]
        if (
            _optional_text(row, "tool_receipt_id") is not None
            or _sha256(row, "hearing_id") != closure.hearing_id
            or _sha256(row, "cycle_scope_id") != closure.cycle_scope_id
            or _sha256(row, "cycle_scope_sha256") != closure.cycle_scope_sha256
            or _integer(row, "judge_cycle", minimum=1)
            != _integer(closure.request, "round_index", minimum=1)
            or _integer(row, "prior_acquisition_rounds")
            != _integer(closure.request, "prior_acquisition_rounds")
            or _integer(row, "prior_rework_rounds")
            != _integer(closure.request, "prior_rework_rounds")
            or _sha256(row, "cycle_pack_id") != _sha256(closure.request, "evidence_pack_id")
            or _integer(row, "cycle_pack_version", minimum=1)
            != _integer(closure.request, "evidence_pack_version", minimum=1)
            or _sha256(row, "current_pack_id") != _sha256(closure.request, "evidence_pack_id")
            or _integer(row, "current_pack_version", minimum=1)
            != _integer(closure.request, "evidence_pack_version", minimum=1)
            or _sha256(row, "judge_output_id") != _sha256(closure.request, "judge_output_id")
            or _sha256(row, "checkpoint_sha256") != _sha256(row, "body_commitment_sha256")
        ):
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        pending[request_id] = row
    if set(pending) != set(requests):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    return pending


def _optional_rounds(
    rows: M6SQLiteAcquisitionHearingSupportRows,
    closures: tuple[_NormalizedAcquisition, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
) -> dict[str, sqlite3.Row]:
    requests = {value.request_id: value for value in closures}
    rounds: dict[str, sqlite3.Row] = {}
    for row in rows.rounds:
        _scope(row, run_id=run_id, case_id=case_id, manifest_id=manifest_id)
        request_id = _optional_text(row, "acquisition_request_id")
        receipt_id = _optional_text(row, "tool_receipt_id")
        if request_id is None:
            if receipt_id is not None:
                _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
            continue
        closure = requests.get(request_id)
        if closure is None or request_id in rounds or receipt_id != closure.receipt_id:
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        if (
            _sha256(row, "hearing_id") != closure.hearing_id
            or _sha256(row, "cycle_scope_id") != closure.cycle_scope_id
            or _sha256(row, "cycle_scope_sha256") != closure.cycle_scope_sha256
            or _integer(row, "round_index", minimum=1)
            != _integer(closure.request, "round_index", minimum=1)
            or _integer(row, "prior_acquisition_rounds")
            != _integer(closure.request, "prior_acquisition_rounds")
            or _integer(row, "prior_rework_rounds")
            != _integer(closure.request, "prior_rework_rounds")
            or _sha256(row, "current_pack_id") != _sha256(closure.request, "evidence_pack_id")
            or _integer(row, "current_pack_version", minimum=1)
            != _integer(closure.request, "evidence_pack_version", minimum=1)
            or _sha256(row, "judge_output_id") != _sha256(closure.request, "judge_output_id")
            or _sha256(row, "resulting_pack_id") != _sha256(closure.resulting_pack, "pack_id")
            or _integer(row, "resulting_pack_version", minimum=1)
            != _integer(closure.resulting_pack, "version", minimum=1)
            or _sha256(row, "round_id") != _sha256(row, "body_commitment_sha256")
        ):
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        rounds[request_id] = row
    return rounds


def _canonical_pack_sha256(pack: EvidencePack) -> tuple[str, int]:
    encoded = canonical_json(pack.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _selected_results(
    authority: M6SQLiteCaseAuthorityDocument,
) -> tuple[dict[str, tuple[EvidencePack, ToolResult]], dict[tuple[str, int], EvidencePack]]:
    packs = {(pack.pack_id, pack.version): pack for pack in authority.case.evidence_packs}
    results: dict[str, tuple[EvidencePack, ToolResult]] = {}
    for pack in authority.case.evidence_packs:
        for result in pack.tool_results:
            existing = results.get(result.tool_result_id)
            if existing is None:
                results[result.tool_result_id] = (pack, result)
            elif existing[1] != result:
                _fail(M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH)
    return results, packs


def _pack_binding(
    connection: M6LiveReader,
    row: sqlite3.Row,
    pack: EvidencePack,
    cache: dict[tuple[M6SQLiteAcquisitionRowDocumentRoute, int], int],
) -> M6SQLiteAcquisitionSelectedPackBinding:
    digest, canonical_bytes = _canonical_pack_sha256(pack)
    rowid = _integer(row, "document_rowid", minimum=1)
    if (
        _sha256(row, "pack_id") != pack.pack_id
        or _integer(row, "version", minimum=1) != pack.version
        or _integer(row, "complete") != int(pack.complete)
        or _sha256(row, "manifest_id") != pack.manifest_id
        or _sha256(row, "pack_input_sha256") != pack.pack_input_sha256
        or _sha256(row, "closure_input_sha256") != pack.closure_input_sha256
        or _sha256(row, "document_sha256") != digest
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    size = _document_length(
        connection,
        row,
        M6SQLiteAcquisitionRowDocumentRoute.SELECTED_EVIDENCE_PACK,
        cache,
    )
    if size != canonical_bytes:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    try:
        return M6SQLiteAcquisitionSelectedPackBinding(
            rowid=rowid,
            pack_id=pack.pack_id,
            version=pack.version,
            document_sha256=digest,
            document_bytes=size,
            created_audit_sequence=_integer(row, "created_audit_sequence"),
            index_identity_sha256=_index_identity(row, "evidence_packs", _PACK_COLUMNS),
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)


def _transition_rows(
    transition_rows: M6SQLiteAcquisitionTransitionSupportRows,
    closure: _NormalizedAcquisition,
    authority: M6SQLiteCaseAuthorityDocument,
) -> tuple[sqlite3.Row, sqlite3.Row, int, str]:
    sequence = _integer(closure.resulting_pack, "created_audit_sequence", minimum=1)
    cases = tuple(
        row for row in transition_rows.case_versions if _integer(row, "audit_sequence") == sequence
    )
    audits = tuple(row for row in transition_rows.audits if _integer(row, "sequence") == sequence)
    if len(cases) != 1 or len(audits) != 1:
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    case_row, audit_row = cases[0], audits[0]
    revision = _integer(case_row, "revision", minimum=2)
    previous_cases = tuple(
        row
        for row in transition_rows.case_versions
        if _integer(row, "revision", minimum=1) == revision - 1
    )
    if len(previous_cases) != 1:
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    case_digest = _sha256(case_row, "document_sha256")
    if (
        _text(case_row, "status") != "DELIBERATING"
        or _text(audit_row, "action") != AuditAction.EVIDENCE_PACK_PUBLISHED.value
        or _text(audit_row, "object_kind") != ArtifactKind.CASE.value
        or _text(audit_row, "object_id") != closure.request["case_id"]
        or _sha256(audit_row, "before_sha256") != _sha256(previous_cases[0], "document_sha256")
        or _sha256(audit_row, "after_sha256") != case_digest
        or _sha256(case_row, "body_commitment_sha256") != case_digest
        or _sha256(audit_row, "body_commitment_sha256") != _sha256(audit_row, "document_sha256")
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    timeline = tuple(
        entry
        for entry in authority.case.timeline
        if entry.object_ref == closure.receipt_id
        and entry.action == AuditAction.CASE_STATE_CHANGED.value
        and entry.stage == "HEARING"
    )
    expected_details = {
        "action": closure.action.value,
        "evidence_pack_id": _sha256(closure.resulting_pack, "pack_id"),
        "evidence_pack_version": _integer(closure.resulting_pack, "version", minimum=1),
        "tool_receipt_id": closure.receipt_id,
    }
    if len(timeline) != 1 or timeline[0].details != expected_details:
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    return case_row, audit_row, revision, _sha256(audit_row, "entry_hash")


def _document_length(
    connection: M6LiveReader,
    row: sqlite3.Row,
    route: M6SQLiteAcquisitionRowDocumentRoute,
    cache: dict[tuple[M6SQLiteAcquisitionRowDocumentRoute, int], int],
) -> int:
    rowid_column = (
        "support_rowid"
        if route
        in {
            M6SQLiteAcquisitionRowDocumentRoute.HEARING_CHECKPOINT,
            M6SQLiteAcquisitionRowDocumentRoute.HEARING_ROUND,
            M6SQLiteAcquisitionRowDocumentRoute.CASE_VERSION,
            M6SQLiteAcquisitionRowDocumentRoute.AUDIT_ENTRY,
        }
        else "document_rowid"
    )
    key = (route, _integer(row, rowid_column, minimum=1))
    value = cache.get(key)
    if value is None:
        value = document_bytes(connection, row, route)
        cache[key] = value
    return value


def _support_pair(
    connection: M6LiveReader,
    row: sqlite3.Row,
    *,
    row_route: M6SQLiteAcquisitionSupportRoute,
    document_route: M6SQLiteAcquisitionSupportDocumentRoute,
    body_route: M6SQLiteAcquisitionRowDocumentRoute,
    run_id: str,
    case_id: str,
    hearing_id: str,
    artifact_id: str,
    body_commitment_sha256: str,
    columns: tuple[str, ...],
    cache: dict[tuple[M6SQLiteAcquisitionRowDocumentRoute, int], int],
) -> tuple[M6SQLiteAcquisitionSupportSlot, M6SQLiteAcquisitionSupportDocumentSlot]:
    rowid = _integer(
        row, "support_rowid" if "support_rowid" in columns else "document_rowid", minimum=1
    )
    identity = _index_identity(row, row_route.value, columns)
    try:
        return (
            M6SQLiteAcquisitionSupportSlot(
                route=row_route,
                run_id=run_id,
                case_id=case_id,
                hearing_id=hearing_id,
                rowid=rowid,
                artifact_id=artifact_id,
                index_identity_sha256=identity,
            ),
            M6SQLiteAcquisitionSupportDocumentSlot(
                route=document_route,
                run_id=run_id,
                case_id=case_id,
                hearing_id=hearing_id,
                rowid=rowid,
                artifact_id=artifact_id,
                body_commitment_sha256=body_commitment_sha256,
                document_bytes=_document_length(connection, row, body_route, cache),
                index_identity_sha256=identity,
            ),
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)


def _output_maps(
    rows: M6SQLiteAcquisitionOutputSupportRows,
    results: tuple[ToolResult, ...],
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
) -> dict[ArtifactKind, dict[str, sqlite3.Row]]:
    expected: dict[ArtifactKind, set[str]] = {
        ArtifactKind.FRAME: set(),
        ArtifactKind.DETECTION: set(),
        ArtifactKind.CROP: set(),
    }
    for result in results:
        for ref in result.output_refs:
            if ref.kind == ArtifactKind.OBJECTIVE_FACT:
                continue
            if ref.kind not in expected:
                _fail(M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH)
            expected[ref.kind].add(ref.artifact_id)
    groups = (
        (ArtifactKind.FRAME, rows.frames, "frame_id"),
        (ArtifactKind.DETECTION, rows.detections, "detection_id"),
        (ArtifactKind.CROP, rows.crops, "crop_id"),
    )
    mapped: dict[ArtifactKind, dict[str, sqlite3.Row]] = {}
    for kind, values, column in groups:
        by_id = _unique_by(values, column)
        if set(by_id) != expected[kind]:
            _fail(M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH)
        for row in values:
            if _text(row, "run_id") != run_id or _sha256(row, "manifest_id") != manifest_id:
                _fail(M6SQLiteAcquisitionPlanFailureCode.SCOPE_MISMATCH)
            if kind == ArtifactKind.CROP and _text(row, "case_id") != case_id:
                _fail(M6SQLiteAcquisitionPlanFailureCode.SCOPE_MISMATCH)
            _sha256(row, "document_sha256")
        mapped[kind] = by_id
    return mapped


def _output_support_slot(
    row: sqlite3.Row,
    *,
    kind: ArtifactKind,
    run_id: str,
    case_id: str,
    hearing_id: str,
) -> M6SQLiteAcquisitionSupportSlot:
    route, columns, identity_column = {
        ArtifactKind.FRAME: (
            M6SQLiteAcquisitionSupportRoute.OUTPUT_FRAME,
            _FRAME_COLUMNS,
            "frame_id",
        ),
        ArtifactKind.DETECTION: (
            M6SQLiteAcquisitionSupportRoute.OUTPUT_DETECTION,
            _DETECTION_COLUMNS,
            "detection_id",
        ),
        ArtifactKind.CROP: (
            M6SQLiteAcquisitionSupportRoute.OUTPUT_CROP,
            _CROP_COLUMNS,
            "crop_id",
        ),
    }[kind]
    try:
        return M6SQLiteAcquisitionSupportSlot(
            route=route,
            run_id=run_id,
            case_id=case_id,
            hearing_id=hearing_id,
            rowid=_integer(row, "support_rowid", minimum=1),
            artifact_id=_text(row, identity_column),
            index_identity_sha256=_index_identity(row, route.value, columns),
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)


def _build_closure(
    connection: M6LiveReader,
    normalized: _NormalizedAcquisition,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    authority: M6SQLiteCaseAuthorityDocument,
    upstream_plan: M6SQLiteM4ModelDocumentsPlan,
    first_pack: EvidencePack,
    result: ToolResult,
    selected_packs: dict[tuple[str, int], EvidencePack],
    checkpoint: sqlite3.Row,
    round_row: sqlite3.Row | None,
    transition_rows: M6SQLiteAcquisitionTransitionSupportRows,
    outputs: dict[ArtifactKind, dict[str, sqlite3.Row]],
    byte_cache: dict[tuple[M6SQLiteAcquisitionRowDocumentRoute, int], int],
) -> M6SQLiteAcquisitionClosurePlan:
    previous_key = (
        _sha256(normalized.previous_pack, "pack_id"),
        _integer(normalized.previous_pack, "version", minimum=1),
    )
    previous_pack = selected_packs.get(previous_key)
    if previous_pack is None or first_pack.version != previous_pack.version + 1:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH)
    parameters = canonical_json(result.validated_parameters.model_dump(mode="json")).encode("utf-8")
    if (
        result.tool_result_id != normalized.tool_result_id
        or result.action != normalized.action
        or result.execution_manifest_id != normalized.execution_manifest_id
        or hashlib.sha256(parameters).hexdigest()
        != _sha256(normalized.request, "validated_parameters_sha256")
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    objective_ids = {
        ref.artifact_id for ref in result.output_refs if ref.kind == ArtifactKind.OBJECTIVE_FACT
    }
    if objective_ids - {fact.fact_id for fact in first_pack.objective_facts}:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH)

    case_row, audit_row, revision, audit_hash = _transition_rows(
        transition_rows,
        normalized,
        authority,
    )
    previous_binding = _pack_binding(
        connection, normalized.previous_pack, previous_pack, byte_cache
    )
    resulting_binding = _pack_binding(connection, normalized.resulting_pack, first_pack, byte_cache)
    transition = M6SQLiteAcquisitionPackTransitionBinding(
        previous_pack=previous_binding,
        resulting_pack=resulting_binding,
        added_tool_result_id=result.tool_result_id,
        first_occurrence_pack_id=first_pack.pack_id,
        first_occurrence_pack_version=first_pack.version,
        transition_case_revision=revision,
        transition_case_version_id=f"{case_id}-revision-{revision:06d}",
        transition_audit_sequence=_integer(audit_row, "sequence", minimum=1),
        transition_audit_entry_hash=audit_hash,
    )
    upstream = _require_upstream_m4_membership(upstream_plan, normalized)

    request_size = _document_length(
        connection,
        normalized.request,
        M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_REQUEST,
        byte_cache,
    )
    claim_request_size = _document_length(
        connection,
        normalized.claim,
        M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM_REQUEST,
        byte_cache,
    )
    if request_size != claim_request_size:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    claim = M6SQLiteAcquisitionCompletedClaimSlot(
        run_id=run_id,
        case_id=case_id,
        hearing_id=normalized.hearing_id,
        rowid=_integer(normalized.claim, "document_rowid", minimum=1),
        acquisition_request_id=normalized.request_id,
        execution_publication_id=normalized.publication_id,
        execution_mode=AcquisitionExecutionMode(_text(normalized.claim, "execution_mode")),
        idempotency_key=_sha256(normalized.claim, "idempotency_key"),
        owner_token_sha256=_sha256(normalized.claim, "owner_token_sha256"),
        owner_fence=_integer(normalized.claim, "owner_fence", minimum=1),
        status=M6SQLiteAcquisitionClaimState.COMPLETED,
        request_document_sha256=_sha256(normalized.claim, "request_document_sha256"),
        request_document_bytes=claim_request_size,
        claim_document_sha256=_sha256(normalized.claim, "document_sha256"),
        claim_document_bytes=_document_length(
            connection,
            normalized.claim,
            M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM,
            byte_cache,
        ),
        index_identity_sha256=_index_identity(
            normalized.claim, "m4_acquisition_execution_claims", _CLAIM_COLUMNS
        ),
    )
    manifest = M6SQLiteAcquisitionManifestSlot(
        run_id=run_id,
        case_id=case_id,
        hearing_id=normalized.hearing_id,
        rowid=_integer(normalized.manifest, "document_rowid", minimum=1),
        execution_manifest_id=normalized.execution_manifest_id,
        acquisition_request_id=normalized.request_id,
        action=normalized.action,
        component_manifest_id=_sha256(normalized.manifest, "component_manifest_id"),
        model_manifest_id=_optional_sha256(normalized.manifest, "model_manifest_id"),
        manifest_id=manifest_id,
        document_sha256=_sha256(normalized.manifest, "document_sha256"),
        document_bytes=_document_length(
            connection,
            normalized.manifest,
            M6SQLiteAcquisitionRowDocumentRoute.TOOL_EXECUTION_MANIFEST,
            byte_cache,
        ),
        index_identity_sha256=_index_identity(
            normalized.manifest, "m4_tool_execution_manifests", _MANIFEST_COLUMNS
        ),
    )
    result_binding = M6SQLiteAcquisitionToolResultBinding(
        tool_result=result,
        origin_pack_id=first_pack.pack_id,
        origin_pack_version=first_pack.version,
    )

    support: list[M6SQLiteAcquisitionSupportSlot] = []
    documents: list[M6SQLiteAcquisitionSupportDocumentSlot] = []

    def add_pair(
        row: sqlite3.Row,
        *,
        row_route: M6SQLiteAcquisitionSupportRoute,
        document_route: M6SQLiteAcquisitionSupportDocumentRoute,
        body_route: M6SQLiteAcquisitionRowDocumentRoute,
        artifact_id: str,
        commitment: str,
        columns: tuple[str, ...],
    ) -> None:
        row_slot, document_slot = _support_pair(
            connection,
            row,
            row_route=row_route,
            document_route=document_route,
            body_route=body_route,
            run_id=run_id,
            case_id=case_id,
            hearing_id=normalized.hearing_id,
            artifact_id=artifact_id,
            body_commitment_sha256=commitment,
            columns=columns,
            cache=byte_cache,
        )
        support.append(row_slot)
        documents.append(document_slot)

    add_pair(
        normalized.request,
        row_route=M6SQLiteAcquisitionSupportRoute.ACQUISITION_REQUEST,
        document_route=M6SQLiteAcquisitionSupportDocumentRoute.ACQUISITION_REQUEST,
        body_route=M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_REQUEST,
        artifact_id=normalized.request_id,
        commitment=_sha256(normalized.request, "document_sha256"),
        columns=_REQUEST_COLUMNS,
    )
    add_pair(
        normalized.publication,
        row_route=M6SQLiteAcquisitionSupportRoute.EXECUTION_PUBLICATION,
        document_route=M6SQLiteAcquisitionSupportDocumentRoute.EXECUTION_PUBLICATION,
        body_route=M6SQLiteAcquisitionRowDocumentRoute.EXECUTION_PUBLICATION,
        artifact_id=normalized.publication_id,
        commitment=_sha256(normalized.publication, "document_sha256"),
        columns=_PUBLICATION_COLUMNS,
    )
    add_pair(
        normalized.receipt,
        row_route=M6SQLiteAcquisitionSupportRoute.TOOL_EXECUTION_RECEIPT,
        document_route=M6SQLiteAcquisitionSupportDocumentRoute.TOOL_EXECUTION_RECEIPT,
        body_route=M6SQLiteAcquisitionRowDocumentRoute.TOOL_EXECUTION_RECEIPT,
        artifact_id=normalized.receipt_id,
        commitment=_sha256(normalized.receipt, "document_sha256"),
        columns=_RECEIPT_COLUMNS,
    )
    add_pair(
        normalized.derivation,
        row_route=M6SQLiteAcquisitionSupportRoute.EVIDENCE_PACK_DERIVATION,
        document_route=M6SQLiteAcquisitionSupportDocumentRoute.EVIDENCE_PACK_DERIVATION,
        body_route=M6SQLiteAcquisitionRowDocumentRoute.EVIDENCE_PACK_DERIVATION,
        artifact_id=normalized.derivation_id,
        commitment=_sha256(normalized.derivation, "document_sha256"),
        columns=_DERIVATION_COLUMNS,
    )
    checkpoint_id = _sha256(checkpoint, "checkpoint_id")
    add_pair(
        checkpoint,
        row_route=M6SQLiteAcquisitionSupportRoute.HEARING_CHECKPOINT,
        document_route=M6SQLiteAcquisitionSupportDocumentRoute.HEARING_CHECKPOINT,
        body_route=M6SQLiteAcquisitionRowDocumentRoute.HEARING_CHECKPOINT,
        artifact_id=checkpoint_id,
        commitment=_sha256(checkpoint, "checkpoint_sha256"),
        columns=_CHECKPOINT_COLUMNS,
    )
    round_id: str | None = None
    if round_row is not None:
        round_id = _sha256(round_row, "round_id")
        add_pair(
            round_row,
            row_route=M6SQLiteAcquisitionSupportRoute.HEARING_ROUND,
            document_route=M6SQLiteAcquisitionSupportDocumentRoute.HEARING_ROUND,
            body_route=M6SQLiteAcquisitionRowDocumentRoute.HEARING_ROUND,
            artifact_id=round_id,
            commitment=round_id,
            columns=_ROUND_COLUMNS,
        )
    case_version_id = f"{case_id}-revision-{revision:06d}"
    add_pair(
        case_row,
        row_route=M6SQLiteAcquisitionSupportRoute.CASE_VERSION,
        document_route=M6SQLiteAcquisitionSupportDocumentRoute.CASE_VERSION,
        body_route=M6SQLiteAcquisitionRowDocumentRoute.CASE_VERSION,
        artifact_id=case_version_id,
        commitment=_sha256(case_row, "document_sha256"),
        columns=_CASE_COLUMNS,
    )
    add_pair(
        audit_row,
        row_route=M6SQLiteAcquisitionSupportRoute.AUDIT_ENTRY,
        document_route=M6SQLiteAcquisitionSupportDocumentRoute.AUDIT_ENTRY,
        body_route=M6SQLiteAcquisitionRowDocumentRoute.AUDIT_ENTRY,
        artifact_id=audit_hash,
        commitment=_sha256(audit_row, "document_sha256"),
        columns=_AUDIT_COLUMNS,
    )
    for ref in result.output_refs:
        if ref.kind == ArtifactKind.OBJECTIVE_FACT:
            continue
        row = outputs[ref.kind][ref.artifact_id]
        if ref.kind == ArtifactKind.CROP and (
            _sha256(row, "hearing_id") != normalized.hearing_id
            or _sha256(row, "acquisition_request_id") != normalized.request_id
            or _sha256(row, "execution_manifest_id") != normalized.execution_manifest_id
            or _sha256(row, "source_pack_id") != previous_pack.pack_id
            or _integer(row, "source_pack_version", minimum=1) != previous_pack.version
        ):
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
        support.append(
            _output_support_slot(
                row,
                kind=ref.kind,
                run_id=run_id,
                case_id=case_id,
                hearing_id=normalized.hearing_id,
            )
        )
    try:
        return M6SQLiteAcquisitionClosurePlan(
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
            acquisition_request_id=normalized.request_id,
            execution_publication_id=normalized.publication_id,
            tool_receipt_id=normalized.receipt_id,
            derivation_id=normalized.derivation_id,
            checkpoint_id=checkpoint_id,
            round_id=round_id,
            upstream_m4=upstream,
            manifest=manifest,
            claim=claim,
            tool_result=result_binding,
            pack_transition=transition,
            support_slots=tuple(sorted(support, key=lambda value: value.sort_key)),
            support_document_slots=tuple(sorted(documents, key=lambda value: value.sort_key)),
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)


def build_acquisition_closures(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    selected_case_authority: M6SQLiteCaseAuthorityDocument,
    observed_acquisition_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...],
    upstream_m4_model_plan: M6SQLiteM4ModelDocumentsPlan,
    primary_rows: M6SQLiteAcquisitionPrimaryRows,
    hearing_rows: M6SQLiteAcquisitionHearingSupportRows,
    transition_rows: M6SQLiteAcquisitionTransitionSupportRows,
    output_rows: M6SQLiteAcquisitionOutputSupportRows,
) -> tuple[M6SQLiteAcquisitionClosurePlan, ...]:
    """Build only selected-cut acquisition closures from body-free row inventories."""

    if (
        type(connection) is not M6LiveReader
        or type(run_id) is not str
        or not run_id
        or type(case_id) is not str
        or not case_id
        or type(manifest_id) is not str
        or len(manifest_id) != 64
        or type(selected_case_authority) is not M6SQLiteCaseAuthorityDocument
        or type(observed_acquisition_artifacts) is not tuple
        or type(upstream_m4_model_plan) is not M6SQLiteM4ModelDocumentsPlan
        or type(primary_rows) is not M6SQLiteAcquisitionPrimaryRows
        or type(hearing_rows) is not M6SQLiteAcquisitionHearingSupportRows
        or type(transition_rows) is not M6SQLiteAcquisitionTransitionSupportRows
        or type(output_rows) is not M6SQLiteAcquisitionOutputSupportRows
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    if not _case_authority_is_consistent(selected_case_authority):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CASE_BINDING_MISMATCH)
    if not _m4_plan_is_consistent(upstream_m4_model_plan):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CASE_BINDING_MISMATCH)
    authority = selected_case_authority
    binding = authority.candidate_case_binding
    if (
        authority.case.run_id != run_id
        or authority.case.case_id != case_id
        or authority.case.manifest_id != manifest_id
        or upstream_m4_model_plan.run_id != run_id
        or upstream_m4_model_plan.case_id != case_id
        or upstream_m4_model_plan.manifest_id != manifest_id
        or upstream_m4_model_plan.selected_case_binding != binding
        or upstream_m4_model_plan.selected_case != authority.case
        or upstream_m4_model_plan.selected_case_audit != authority.audit_entry
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.SCOPE_MISMATCH)

    normalized = _classify_primary_cut(
        primary_rows,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
        selected_audit_sequence=binding.case_audit_sequence,
    )
    checkpoints = _pending_checkpoints(
        hearing_rows,
        normalized,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    rounds = _optional_rounds(
        hearing_rows,
        normalized,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    pre_cut = tuple(value for value in normalized if not value.is_post_cut)
    selected_results, selected_packs = _selected_results(authority)
    if {value.tool_result_id for value in pre_cut} != set(selected_results):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH)

    if any(
        type(item) is not M6UpgradeObservedArtifactIdentity
        for item in observed_acquisition_artifacts
    ) or observed_acquisition_artifacts != tuple(
        sorted(observed_acquisition_artifacts, key=lambda item: item.sort_key)
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    expected_observations = {
        (
            M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
            value.execution_manifest_id,
        )
        for value in pre_cut
    } | {
        (
            M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            M6UpgradePhysicalArtifactKind.TOOL_RESULT,
            value.tool_result_id,
        )
        for value in pre_cut
    }
    actual_observations = {item.identity_key for item in observed_acquisition_artifacts}
    if (
        len(actual_observations) != len(observed_acquisition_artifacts)
        or actual_observations != expected_observations
        or any(
            item.usage != M6UpgradeArtifactUsage.PRODUCED for item in observed_acquisition_artifacts
        )
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH)

    typed_results = tuple(selected_results[value.tool_result_id][1] for value in pre_cut)
    outputs = _output_maps(
        output_rows,
        typed_results,
        run_id=run_id,
        case_id=case_id,
        manifest_id=manifest_id,
    )
    byte_cache: dict[tuple[M6SQLiteAcquisitionRowDocumentRoute, int], int] = {}
    closures = tuple(
        _build_closure(
            connection,
            value,
            run_id=run_id,
            case_id=case_id,
            manifest_id=manifest_id,
            authority=authority,
            upstream_plan=upstream_m4_model_plan,
            first_pack=selected_results[value.tool_result_id][0],
            result=selected_results[value.tool_result_id][1],
            selected_packs=selected_packs,
            checkpoint=checkpoints[value.request_id],
            round_row=rounds.get(value.request_id),
            transition_rows=transition_rows,
            outputs=outputs,
            byte_cache=byte_cache,
        )
        for value in pre_cut
    )
    return tuple(sorted(closures, key=lambda value: value.sort_key))


__all__ = ["build_acquisition_closures"]
