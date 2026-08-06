"""Strict same-snapshot body recovery for one frozen M6 M5-precedent plan.

The metadata plan is deliberately body-free.  This module is the only late
read seam for its M5 closure: it first replays the complete metadata plan on
the caller's still-active reader, then opens only the exact planned rows.
M4 retrieval receipts and historical precedent revisions are verification
support; they never become sample physical references.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import NoReturn, TypeVar, cast

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_upgrade_physical_resolution import (
    M6UpgradePhysicalResolutionError,
    derive_m6_upgrade_embedding_physical_ref,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.hearing_state import HearingPrecedentRetrievalReceipt
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5EmbeddingVector,
    M5PrecedentAuthority,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedEmbeddingChannel,
    M6LockedEmbeddingScope,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.m6_embedding_authority import M6ResolvedEmbeddingAuthority

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m4_model_plan import M6SQLiteM4ModelDocumentsPlan
from ._sqlite_m6_upgrade_m4_model_plan import (
    _plan_is_consistent as _m4_plan_is_consistent,
)
from ._sqlite_m6_upgrade_m5_precedent_plan import (
    M6SQLiteM5PrecedentDocumentsPlan,
    M6SQLiteM5PrecedentDurableEmbeddingSlot,
    M6SQLiteM5PrecedentExposureSlot,
    M6SQLiteM5PrecedentPlanFailureCode,
    M6SQLiteM5PrecedentRetrievalSlot,
    M6SQLiteM5PrecedentRevisionSlot,
    _M6SQLiteM5PrecedentMetadataFailure,
    _plan_is_consistent,
)
from ._sqlite_m6_upgrade_m5_precedent_query import (
    M6SQLiteM5CycleQueryMetadata,
    M6SQLiteM5ExposureQueryMetadata,
    M6SQLiteM5HearingQueryMetadata,
    M6SQLiteM5PrecedentQueryError,
    M6SQLiteM5ReconstructedPrecedentQuery,
    M6SQLiteM5RetrievalQueryMetadata,
    reconstruct_m6_sqlite_m5_precedent_query,
)

_DocumentT = TypeVar("_DocumentT", bound=BaseModel)
_ContractT = TypeVar("_ContractT", AppConfig, Case, RunManifest)


def _fail(reason: M6SQLiteM5PrecedentPlanFailureCode) -> NoReturn:
    raise _M6SQLiteM5PrecedentMetadataFailure(reason)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _controlled_contract(value: object, expected: type[_ContractT]) -> _ContractT:
    if type(value) is not expected:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    return controlled


def _active(connection: M6LiveReader) -> None:
    try:
        active = connection.in_transaction
    except (RuntimeError, sqlite3.Error):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED)
    if type(active) is not bool or not active:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.TRANSACTION_REQUIRED)


def _exact_row(
    connection: M6LiveReader,
    sql: str,
    parameters: tuple[object, ...],
    *,
    rowid: int,
) -> sqlite3.Row:
    try:
        cursor = connection.execute(sql, parameters)
        try:
            rows = tuple(cursor.fetchmany(2))
        finally:
            cursor.close()
    except (RuntimeError, sqlite3.Error):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED)
    if len(rows) != 1:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    try:
        observed_rowid = rows[0]["document_rowid"]
    except (IndexError, KeyError, TypeError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    if observed_rowid != rowid:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return rows[0]


def _decode(
    row: sqlite3.Row,
    column: str,
    model: type[_DocumentT],
    *,
    expected_bytes: int,
    expected_canonical_sha256: str | None,
) -> tuple[_DocumentT, str]:
    try:
        raw = row[column]
    except (IndexError, KeyError, TypeError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    if type(raw) is not str:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_INVALID)
    try:
        encoded = raw.encode("utf-8")
        document = model.model_validate_json(raw)
        canonical = canonical_json(document.model_dump(mode="json"))
    except (TypeError, UnicodeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_INVALID)
    if (
        len(encoded) != expected_bytes
        or canonical != raw
        or (
            expected_canonical_sha256 is not None
            and hashlib.sha256(encoded).hexdigest() != expected_canonical_sha256
        )
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_INVALID)
    return document, canonical


_RETRIEVAL_BODY_SQL = """
SELECT rowid AS document_rowid, receipt_json
FROM m4_precedent_retrieval_receipts
WHERE rowid = ? AND run_id = ? AND retrieval_receipt_id = ?
LIMIT 2
"""

_EXPOSURE_BODY_SQL = """
SELECT rowid AS document_rowid, exposure_json
FROM m5_precedent_exposures
WHERE rowid = ? AND run_id = ? AND exposure_id = ?
LIMIT 2
"""

_EMBEDDING_BODY_SQL = """
SELECT rowid AS document_rowid, embedding_json
FROM precedent_embeddings
WHERE rowid = ? AND run_id = ? AND embedding_id = ?
LIMIT 2
"""

_AUTHORITY_BODY_SQL = """
SELECT rowid AS document_rowid, authority_json
FROM precedents
WHERE rowid = ? AND run_id = ? AND precedent_id = ? AND revision = ?
      AND authority_id = ?
LIMIT 2
"""


def _json_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _review_id(value: ArtifactRef | None) -> str | None:
    if value is None:
        return None
    try:
        return value.artifact_id
    except AttributeError:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _retrieval_index_matches(
    slot: M6SQLiteM5PrecedentRetrievalSlot,
    receipt: HearingPrecedentRetrievalReceipt,
) -> bool:
    candidate_refs = [value.model_dump(mode="json") for value in receipt.candidate_precedent_refs]
    visible_refs = [value.model_dump(mode="json") for value in receipt.visible_precedent_refs]
    scored = [value.model_dump(mode="json") for value in receipt.scored_precedents]
    return (
        receipt.run_id == slot.run_id
        and receipt.case_id == slot.case_id
        and receipt.receipt_id == slot.retrieval_receipt_id
        and receipt.hearing_session_id == slot.hearing_id
        and receipt.cycle_scope_id == slot.cycle_scope_id
        and receipt.cycle_scope_sha256 == slot.cycle_scope_sha256
        and receipt.prior_acquisition_rounds == slot.prior_acquisition_rounds
        and receipt.prior_rework_rounds == slot.prior_rework_rounds
        and receipt.current_evidence_pack_id == slot.current_pack_id
        and receipt.current_evidence_pack_version == slot.current_pack_version
        and receipt.evidence_class == slot.evidence_class
        and receipt.violation_type == slot.violation_type
        and receipt.rule_version == slot.rule_version
        and receipt.top_k == slot.top_k
        and _review_id(receipt.initial_trigger_review_ref) == slot.initial_trigger_review_id
        and receipt.initial_defect_codes == slot.initial_defect_codes
        and _json_sha256([value.value for value in receipt.initial_defect_codes])
        == slot.initial_defect_codes_sha256
        and _review_id(receipt.rework_review_ref) == slot.rework_review_id
        and receipt.rework_defect_codes == slot.rework_defect_codes
        and _json_sha256([value.value for value in receipt.rework_defect_codes])
        == slot.rework_defect_codes_sha256
        and tuple(value.artifact_id for value in receipt.candidate_precedent_refs)
        == slot.candidate_precedent_ids
        and _json_sha256(candidate_refs) == slot.candidate_refs_sha256
        and receipt.candidate_snapshot_sha256 == slot.candidate_snapshot_sha256
        and tuple(value.artifact_id for value in receipt.visible_precedent_refs)
        == slot.visible_precedent_ids
        and _json_sha256(visible_refs) == slot.visible_refs_sha256
        and receipt.visible_snapshot_sha256 == slot.visible_snapshot_sha256
        and _json_sha256(scored) == slot.scored_precedents_sha256
        and receipt.status == slot.retrieval_status
        and receipt.degraded_reason == slot.degraded_reason
        and (receipt.status.value == "DEGRADED") == slot.precedent_retrieval_degraded
        and receipt.retriever_version == slot.retriever_version
        and receipt.retriever_manifest_id == slot.retriever_manifest_id
        and receipt.query_sha256 == slot.query_sha256
        and receipt.embedding_model_manifest_id == slot.embedding_model_manifest_id
        and receipt.manifest_id == slot.manifest_id
        and receipt.receipt_sha256 == slot.document_sha256
    )


def _retrieval_body(
    connection: M6LiveReader,
    slot: M6SQLiteM5PrecedentRetrievalSlot,
) -> tuple[HearingPrecedentRetrievalReceipt, str]:
    row = _exact_row(
        connection,
        _RETRIEVAL_BODY_SQL,
        (slot.rowid, slot.run_id, slot.retrieval_receipt_id),
        rowid=slot.rowid,
    )
    receipt, canonical = _decode(
        row,
        "receipt_json",
        HearingPrecedentRetrievalReceipt,
        expected_bytes=slot.document_bytes,
        expected_canonical_sha256=None,
    )
    if not _retrieval_index_matches(slot, receipt):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return receipt, canonical


def _exposure_index_matches(
    slot: M6SQLiteM5PrecedentExposureSlot,
    exposure: M5PrecedentExposureBatchAuthority,
) -> bool:
    outcome = exposure.m4_retrieval_outcome
    result = exposure.m5_retrieval_result
    return (
        exposure.run_id == slot.run_id
        and exposure.case_id == slot.case_id
        and exposure.exposure_id == slot.exposure_id
        and exposure.exposure_sha256 == slot.exposure_sha256
        and exposure.hearing_session_id == slot.hearing_id
        and exposure.cycle_index == slot.cycle_index
        and exposure.cycle_scope_id == slot.cycle_scope_id
        and exposure.cycle_scope_sha256 == slot.cycle_scope_sha256
        and outcome.receipt.receipt_id == slot.retrieval_receipt_id
        and outcome.query.query_id == slot.m4_query_id
        and result.query.query_id == slot.m5_query_id
        and result.result_id == slot.m5_result_id
        and result.candidate_count == slot.candidate_count
        and len(exposure.exposed_precedents) == slot.exposed_count
        and exposure.policy_id == slot.policy_id
        and exposure.bridge_manifest_id == slot.bridge_manifest_id
        and exposure.manifest_id == slot.manifest_id
    )


def _exposure_body(
    connection: M6LiveReader,
    slot: M6SQLiteM5PrecedentExposureSlot,
) -> tuple[M5PrecedentExposureBatchAuthority, str]:
    row = _exact_row(
        connection,
        _EXPOSURE_BODY_SQL,
        (slot.rowid, slot.run_id, slot.exposure_id),
        rowid=slot.rowid,
    )
    exposure, canonical = _decode(
        row,
        "exposure_json",
        M5PrecedentExposureBatchAuthority,
        expected_bytes=slot.document_bytes,
        expected_canonical_sha256=slot.document_sha256,
    )
    if not _exposure_index_matches(slot, exposure):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return exposure, canonical


def _embedding_index_matches(
    slot: M6SQLiteM5PrecedentDurableEmbeddingSlot,
    embedding: M5EmbeddingVector,
    *,
    manifest_id: str,
) -> bool:
    request = embedding.request
    return (
        slot.manifest_id == manifest_id
        and embedding.embedding_id == slot.embedding_id
        and request.request_id == slot.request_id
        and request.channel == slot.channel
        and request.input_ref == slot.input_ref
        and request.input_sha256 == slot.input_sha256
        and request.model_manifest_id == slot.model_manifest_id
        and request.dimensions == slot.dimensions
        and request.algorithm == slot.algorithm
    )


def _embedding_body(
    connection: M6LiveReader,
    slot: M6SQLiteM5PrecedentDurableEmbeddingSlot,
    *,
    manifest_id: str,
) -> tuple[M5EmbeddingVector, str]:
    row = _exact_row(
        connection,
        _EMBEDDING_BODY_SQL,
        (slot.rowid, slot.run_id, slot.embedding_id),
        rowid=slot.rowid,
    )
    embedding, canonical = _decode(
        row,
        "embedding_json",
        M5EmbeddingVector,
        expected_bytes=slot.document_bytes,
        expected_canonical_sha256=slot.document_sha256,
    )
    if not _embedding_index_matches(slot, embedding, manifest_id=manifest_id):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return embedding, canonical


def _authority_index_matches(
    slot: M6SQLiteM5PrecedentRevisionSlot,
    authority: M5PrecedentAuthority,
    *,
    config_sha256: str,
    manifest_id: str,
) -> bool:
    precedent = authority.precedent
    dump = authority.model_dump(mode="json")
    visual_ids = tuple(value.embedding_id for value in authority.visual_embeddings)
    return (
        authority.run_id == slot.run_id
        and authority.config_sha256 == config_sha256
        and slot.manifest_id == manifest_id
        and precedent.precedent_id == slot.precedent_id
        and authority.revision == slot.revision
        and authority.authority_id == slot.authority_id
        and precedent.status == slot.status
        and precedent.source == slot.source
        and precedent.evidence_class == slot.evidence_class
        and precedent.violation_type == slot.violation_type
        and precedent.decision_direction == slot.decision_direction
        and precedent.rule_version == slot.rule_version
        and precedent.source_case_id == slot.source_case_id
        and precedent.citation_count == slot.citation_count
        and (
            authority.text_embedding.embedding_id if authority.text_embedding is not None else None
        )
        == slot.text_embedding_id
        and visual_ids == slot.visual_embedding_ids
        and _json_sha256(list(visual_ids)) == slot.visual_embedding_ids_sha256
        and dump["created_at"] == slot.created_at
        and dump["activation_not_before"] == slot.activation_not_before
        and dump["activated_at"] == slot.activated_at
    )


def _authority_body(
    connection: M6LiveReader,
    slot: M6SQLiteM5PrecedentRevisionSlot,
    *,
    config_sha256: str,
    manifest_id: str,
) -> tuple[M5PrecedentAuthority, str]:
    row = _exact_row(
        connection,
        _AUTHORITY_BODY_SQL,
        (slot.rowid, slot.run_id, slot.precedent_id, slot.revision, slot.authority_id),
        rowid=slot.rowid,
    )
    authority, canonical = _decode(
        row,
        "authority_json",
        M5PrecedentAuthority,
        expected_bytes=slot.document_bytes,
        expected_canonical_sha256=slot.document_sha256,
    )
    if not _authority_index_matches(
        slot,
        authority,
        config_sha256=config_sha256,
        manifest_id=manifest_id,
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return authority, canonical


def _fresh_plan(
    connection: M6LiveReader,
    plan: M6SQLiteM5PrecedentDocumentsPlan,
    *,
    selected_case: Case,
    config: AppConfig,
    manifest: RunManifest,
    upstream: M6SQLiteM4ModelDocumentsPlan,
) -> M6SQLiteM5PrecedentDocumentsPlan:
    """Re-run all metadata reads before the first canonical body is opened."""

    if (
        not _plan_is_consistent(plan)
        or not _m4_plan_is_consistent(upstream)
        or selected_case != upstream.selected_case
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    if (
        plan.upstream_m4_plan_identity_sha256 != upstream.plan_identity_sha256
        or plan.run_id != upstream.run_id
        or plan.case_id != upstream.case_id
        or plan.manifest_id != upstream.manifest_id
        or selected_case.run_id != plan.run_id
        or selected_case.case_id != plan.case_id
        or selected_case.manifest_id != plan.manifest_id
        or manifest.manifest_id != plan.manifest_id
        or manifest.config_sha256 != config.config_sha256
        or manifest.rule_version != config.rule_version
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.SCOPE_MISMATCH)
    try:
        authority = M6SQLiteCaseAuthorityDocument(
            candidate_case_binding=upstream.selected_case_binding,
            case=selected_case,
            canonical_case_document=canonical_json(selected_case.model_dump(mode="json")),
            audit_entry=upstream.selected_case_audit,
            canonical_audit_document=canonical_json(
                upstream.selected_case_audit.model_dump(mode="json")
            ),
        )
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)

    # Local import avoids a module cycle: the public metadata facade imports
    # this resolver only for its late-read ``resolve_*`` wrapper.
    from ._sqlite_m6_upgrade_m5_precedent_metadata import (
        build_m6_sqlite_m5_precedent_documents_plan,
    )

    fresh = build_m6_sqlite_m5_precedent_documents_plan(
        connection=connection,
        manifest=manifest,
        config=config,
        selected_case_authority=authority,
        upstream_m4_model_plan=upstream,
        observed_precedent_artifacts=plan.observed_artifacts,
    )
    if fresh != plan:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
    return fresh


def _reconstructed_query(
    *,
    plan: M6SQLiteM5PrecedentDocumentsPlan,
    retrieval: M6SQLiteM5PrecedentRetrievalSlot,
    exposure: M6SQLiteM5PrecedentExposureSlot,
    selected_case: Case,
    config: AppConfig,
    manifest: RunManifest,
) -> M6SQLiteM5ReconstructedPrecedentQuery:
    hearing_matches = tuple(
        value for value in plan.hearings if value.hearing_id == retrieval.hearing_id
    )
    cycle_matches = tuple(
        value for value in plan.cycles if value.cycle_id == retrieval.cycle_scope_id
    )
    if len(hearing_matches) != 1 or len(cycle_matches) != 1:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
    hearing = hearing_matches[0]
    cycle = cycle_matches[0]
    try:
        return reconstruct_m6_sqlite_m5_precedent_query(
            manifest=manifest,
            config=config,
            selected_case=selected_case,
            hearing_metadata=M6SQLiteM5HearingQueryMetadata(
                run_id=hearing.run_id,
                case_id=hearing.case_id,
                hearing_id=hearing.hearing_id,
                screening_id=hearing.screening_id,
                entry_status=hearing.entry_status,
                trigger_review_id=hearing.trigger_review_id,
                initial_defect_codes_sha256=hearing.initial_defect_codes_sha256,
                initial_pack_id=hearing.initial_pack_id,
                initial_pack_version=hearing.initial_pack_version,
                max_acquisition_rounds=hearing.max_acquisition_rounds,
                max_rework_rounds=hearing.max_rework_rounds,
                max_total_images=hearing.max_total_images,
                max_total_output_tokens=hearing.max_total_output_tokens,
                max_judge_cycles=hearing.max_judge_cycles,
                hearing_prompt_bundle_sha256=hearing.hearing_prompt_bundle_sha256,
                prosecutor_model_manifest_id=hearing.prosecutor_model_manifest_id,
                defender_model_manifest_id=hearing.defender_model_manifest_id,
                judge_model_manifest_id=hearing.judge_model_manifest_id,
                manifest_id=hearing.manifest_id,
                document_sha256=hearing.document_sha256,
            ),
            cycle_metadata=M6SQLiteM5CycleQueryMetadata(
                run_id=cycle.run_id,
                case_id=cycle.case_id,
                hearing_id=cycle.hearing_id,
                cycle_id=cycle.cycle_id,
                cycle_sha256=cycle.cycle_sha256,
                cycle_index=cycle.cycle_index,
                prior_acquisition_rounds=cycle.prior_acquisition_rounds,
                prior_rework_rounds=cycle.prior_rework_rounds,
                cycle_pack_id=cycle.cycle_pack_id,
                cycle_pack_version=cycle.cycle_pack_version,
                initial_trigger_review_id=cycle.initial_trigger_review_id,
                initial_defect_codes_sha256=cycle.initial_defect_codes_sha256,
                rework_review_id=cycle.rework_review_id,
                rework_defect_codes_sha256=cycle.rework_defect_codes_sha256,
                manifest_id=cycle.manifest_id,
            ),
            retrieval_metadata=M6SQLiteM5RetrievalQueryMetadata(
                run_id=retrieval.run_id,
                retrieval_receipt_id=retrieval.retrieval_receipt_id,
                hearing_id=retrieval.hearing_id,
                cycle_scope_id=retrieval.cycle_scope_id,
                cycle_scope_sha256=retrieval.cycle_scope_sha256,
                case_id=retrieval.case_id,
                prior_acquisition_rounds=retrieval.prior_acquisition_rounds,
                prior_rework_rounds=retrieval.prior_rework_rounds,
                current_pack_id=retrieval.current_pack_id,
                current_pack_version=retrieval.current_pack_version,
                evidence_class=retrieval.evidence_class,
                violation_type=retrieval.violation_type,
                rule_version=retrieval.rule_version,
                top_k=retrieval.top_k,
                initial_trigger_review_id=retrieval.initial_trigger_review_id,
                initial_defect_codes_sha256=retrieval.initial_defect_codes_sha256,
                rework_review_id=retrieval.rework_review_id,
                rework_defect_codes_sha256=retrieval.rework_defect_codes_sha256,
                retrieval_status=retrieval.retrieval_status,
                degraded_reason=retrieval.degraded_reason,
                precedent_retrieval_degraded=retrieval.precedent_retrieval_degraded,
                retriever_version=retrieval.retriever_version,
                retriever_manifest_id=retrieval.retriever_manifest_id,
                query_sha256=retrieval.query_sha256,
                embedding_model_manifest_id=retrieval.embedding_model_manifest_id,
                manifest_id=retrieval.manifest_id,
            ),
            exposure_metadata=M6SQLiteM5ExposureQueryMetadata(
                run_id=exposure.run_id,
                exposure_id=exposure.exposure_id,
                case_id=exposure.case_id,
                hearing_id=exposure.hearing_id,
                cycle_index=exposure.cycle_index,
                cycle_scope_id=exposure.cycle_scope_id,
                cycle_scope_sha256=exposure.cycle_scope_sha256,
                retrieval_receipt_id=exposure.retrieval_receipt_id,
                m4_query_id=exposure.m4_query_id,
                m5_query_id=exposure.m5_query_id,
                policy_id=exposure.policy_id,
                bridge_manifest_id=exposure.bridge_manifest_id,
                manifest_id=exposure.manifest_id,
            ),
        )
    except M6SQLiteM5PrecedentQueryError:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)


def _locked_channel(channel: M5EmbeddingChannel) -> M6LockedEmbeddingChannel:
    return {
        M5EmbeddingChannel.TEXT: M6LockedEmbeddingChannel.TEXT,
        M5EmbeddingChannel.VISUAL: M6LockedEmbeddingChannel.VISUAL,
    }[channel]


def _resolved_embedding(
    vector: M5EmbeddingVector,
    *,
    scope: M6LockedEmbeddingScope,
) -> M6ResolvedEmbeddingAuthority:
    canonical = canonical_json(vector.model_dump(mode="json"))
    try:
        return M6ResolvedEmbeddingAuthority(
            scope=scope,
            channel=_locked_channel(vector.request.channel),
            vector=vector,
            document_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_INVALID)


def _authority_root(
    plan: M6SQLiteM5PrecedentDocumentsPlan,
    *,
    receipts: tuple[HearingPrecedentRetrievalReceipt, ...],
    exposures: tuple[M5PrecedentExposureBatchAuthority, ...],
    authorities: tuple[M5PrecedentAuthority, ...],
    embeddings: tuple[M6ResolvedEmbeddingAuthority, ...],
) -> str:
    projection = [
        "m6-sqlite-m5-precedent-authority",
        1,
        plan.plan_identity_sha256,
        [value.receipt_id for value in receipts],
        [value.exposure_id for value in exposures],
        [value.authority_id for value in authorities],
        [
            [value.scope.value, value.channel.value, value.embedding_id, value.document_sha256]
            for value in embeddings
        ],
    ]
    return hashlib.sha256(canonical_json(projection).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentAuthoritySnapshot:
    """Canonical M5 replay authority proven inside one immutable SQLite cut."""

    source_identity_sha256: str
    upstream_m4_model_plan_identity_sha256: str
    precedent_authority_root_sha256: str
    run_id: str
    case_id: str
    manifest_id: str
    retrieval_receipts: tuple[HearingPrecedentRetrievalReceipt, ...]
    exposures: tuple[M5PrecedentExposureBatchAuthority, ...]
    historical_precedent_authorities: tuple[M5PrecedentAuthority, ...]
    reconstructed_queries: tuple[M6SQLiteM5ReconstructedPrecedentQuery, ...]
    resolved_embeddings: tuple[M6ResolvedEmbeddingAuthority, ...]
    observed_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...]
    planned_artifact_refs: tuple[M6UpgradePhysicalArtifactRef, ...]

    def __post_init__(self) -> None:
        for value in (
            self.source_identity_sha256,
            self.upstream_m4_model_plan_identity_sha256,
            self.precedent_authority_root_sha256,
            self.manifest_id,
        ):
            if not _is_sha256(value):
                raise ValueError("M5 snapshot identities must be lowercase SHA-256 values")
        if type(self.run_id) is not str or not self.run_id or type(self.case_id) is not str:
            raise TypeError("M5 snapshot scope must use non-empty strings")
        typed_groups: tuple[tuple[tuple[object, ...], type[object]], ...] = (
            (self.retrieval_receipts, HearingPrecedentRetrievalReceipt),
            (self.exposures, M5PrecedentExposureBatchAuthority),
            (self.historical_precedent_authorities, M5PrecedentAuthority),
            (self.reconstructed_queries, M6SQLiteM5ReconstructedPrecedentQuery),
            (self.resolved_embeddings, M6ResolvedEmbeddingAuthority),
            (self.observed_artifacts, M6UpgradeObservedArtifactIdentity),
            (self.planned_artifact_refs, M6UpgradePhysicalArtifactRef),
        )
        if any(
            type(values) is not tuple or any(type(value) is not expected for value in values)
            for values, expected in typed_groups
        ):
            raise TypeError("M5 snapshot inventories must be exact typed tuples")
        if self.retrieval_receipts != tuple(
            sorted(self.retrieval_receipts, key=lambda value: value.receipt_id)
        ) or self.exposures != tuple(sorted(self.exposures, key=lambda value: value.exposure_id)):
            raise ValueError("M5 snapshot retrieval inventories must use stable order")
        if self.historical_precedent_authorities != tuple(
            sorted(
                self.historical_precedent_authorities,
                key=lambda value: (value.precedent.precedent_id, value.revision),
            )
        ):
            raise ValueError("M5 snapshot authority history must use stable order")
        if self.reconstructed_queries != tuple(
            sorted(self.reconstructed_queries, key=lambda value: value.exposure_id)
        ) or self.resolved_embeddings != tuple(
            sorted(self.resolved_embeddings, key=lambda value: value.sort_key)
        ):
            raise ValueError("M5 snapshot resolved authorities must use stable order")
        if self.observed_artifacts != tuple(
            sorted(self.observed_artifacts, key=lambda value: value.sort_key)
        ) or self.planned_artifact_refs != tuple(
            sorted(self.planned_artifact_refs, key=lambda value: value.sort_key)
        ):
            raise ValueError("M5 snapshot physical inventories must use stable order")
        expected_usage = {
            (
                M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
                value.exposure_id,
            ): M6UpgradeArtifactUsage.PRODUCED
            for value in self.exposures
        }
        for resolved_embedding in self.resolved_embeddings:
            expected_usage[
                (
                    M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                    M6UpgradePhysicalArtifactKind.EMBEDDING,
                    resolved_embedding.embedding_id,
                )
            ] = (
                M6UpgradeArtifactUsage.PRODUCED
                if resolved_embedding.scope == M6LockedEmbeddingScope.QUERY
                else M6UpgradeArtifactUsage.CONSUMED
            )
        actual_usage = {value.identity_key: value.usage for value in self.observed_artifacts}
        if len(actual_usage) != len(self.observed_artifacts) or actual_usage != expected_usage:
            raise ValueError("M5 snapshot observation usage does not close exactly")
        ref_identities = {
            (value.source, value.kind, value.artifact_id) for value in self.planned_artifact_refs
        }
        if len(ref_identities) != len(self.planned_artifact_refs) or ref_identities != set(
            expected_usage
        ):
            raise ValueError("M5 snapshot physical refs do not close exactly")


def build_m6_sqlite_m5_precedent_authority_snapshot(
    *,
    connection: object,
    metadata_plan: object,
    selected_case: object,
    config: object,
    manifest: object,
    upstream_m4_model_plan: object,
) -> M6SQLiteM5PrecedentAuthoritySnapshot:
    """Open and verify only bodies frozen by an already-compared Pending plan."""

    if (
        type(connection) is not M6LiveReader
        or not _plan_is_consistent(metadata_plan)
        or not _m4_plan_is_consistent(upstream_m4_model_plan)
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    controlled_case = _controlled_contract(selected_case, Case)
    controlled_config = _controlled_contract(config, AppConfig)
    controlled_manifest = _controlled_contract(manifest, RunManifest)
    plan = cast(M6SQLiteM5PrecedentDocumentsPlan, metadata_plan)
    upstream = cast(M6SQLiteM4ModelDocumentsPlan, upstream_m4_model_plan)
    if (
        plan.upstream_m4_plan_identity_sha256 != upstream.plan_identity_sha256
        or plan.run_id != upstream.run_id
        or plan.case_id != upstream.case_id
        or plan.manifest_id != upstream.manifest_id
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.UPSTREAM_M4_MISMATCH)

    _active(connection)
    plan = _fresh_plan(
        connection,
        plan,
        selected_case=controlled_case,
        config=controlled_config,
        manifest=controlled_manifest,
        upstream=upstream,
    )

    receipt_pairs = tuple(_retrieval_body(connection, value) for value in plan.retrievals)
    authority_pairs = tuple(
        _authority_body(
            connection,
            value,
            config_sha256=controlled_config.config_sha256,
            manifest_id=controlled_manifest.manifest_id,
        )
        for value in plan.precedent_revisions
    )
    durable_pairs = tuple(
        _embedding_body(
            connection,
            value,
            manifest_id=controlled_manifest.manifest_id,
        )
        for value in plan.durable_embeddings
    )
    exposure_pairs = tuple(_exposure_body(connection, value) for value in plan.exposures)
    receipts = tuple(
        sorted((value[0] for value in receipt_pairs), key=lambda value: value.receipt_id)
    )
    authorities = tuple(
        sorted(
            (value[0] for value in authority_pairs),
            key=lambda value: (value.precedent.precedent_id, value.revision),
        )
    )
    durable_vectors = tuple(value[0] for value in durable_pairs)
    exposures = tuple(
        sorted((value[0] for value in exposure_pairs), key=lambda value: value.exposure_id)
    )

    receipt_by_id = {value.receipt_id: value for value in receipts}
    authority_by_key = {
        (value.precedent.precedent_id, value.revision): value for value in authorities
    }
    durable_by_id = {value.embedding_id: value for value in durable_vectors}
    if (
        len(receipt_by_id) != len(receipts)
        or len(authority_by_key) != len(authorities)
        or len(durable_by_id) != len(durable_vectors)
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)

    # Every embedding nested in every historical revision must equal its one
    # durable row, including revisions that are verification support only.
    for authority in authorities:
        nested = (
            () if authority.text_embedding is None else (authority.text_embedding,)
        ) + authority.visual_embeddings
        if any(durable_by_id.get(value.embedding_id) != value for value in nested):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)

    retrieval_by_receipt = {value.retrieval_receipt_id: value for value in plan.retrievals}
    exposure_slot_by_id = {value.exposure_id: value for value in plan.exposures}
    derived_by_receipt = {
        value.retrieval_receipt_id: value for value in plan.derived_query_embeddings
    }
    resolved_by_key: dict[tuple[M6LockedEmbeddingScope, str], M6ResolvedEmbeddingAuthority] = {}
    reconstructed: list[M6SQLiteM5ReconstructedPrecedentQuery] = []
    candidate_embedding_ids: set[str] = set()
    for exposure in exposures:
        slot = exposure_slot_by_id.get(exposure.exposure_id)
        if slot is None:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
        retrieval = retrieval_by_receipt.get(slot.retrieval_receipt_id)
        receipt = receipt_by_id.get(slot.retrieval_receipt_id)
        derived = derived_by_receipt.get(slot.retrieval_receipt_id)
        if retrieval is None or receipt is None or derived is None:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
        rebuilt = _reconstructed_query(
            plan=plan,
            retrieval=retrieval,
            exposure=slot,
            selected_case=controlled_case,
            config=controlled_config,
            manifest=controlled_manifest,
        )
        if (
            exposure.m4_retrieval_outcome.receipt != receipt
            or exposure.m4_retrieval_outcome.query != rebuilt.m4_query
            or exposure.m5_retrieval_result.query != rebuilt.m5_query
            or tuple(
                value.authority.precedent.precedent_id
                for value in exposure.m5_retrieval_result.candidate_evaluations
            )
            != retrieval.candidate_precedent_ids
        ):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
        vector = rebuilt.query_embedding_authority.vector
        if (
            derived.physical_ref != rebuilt.query_embedding_ref
            or derived.channel != vector.request.channel
            or derived.channel_index != 0
            or derived.request_id != vector.request.request_id
            or derived.input_ref != vector.request.input_ref
            or derived.input_sha256 != vector.request.input_sha256
            or derived.model_manifest_id != vector.request.model_manifest_id
            or derived.dimensions != vector.request.dimensions
            or derived.algorithm != vector.request.algorithm
        ):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_PLAN_INVALID)
        query_key = (M6LockedEmbeddingScope.QUERY, vector.embedding_id)
        previous_query = resolved_by_key.setdefault(query_key, rebuilt.query_embedding_authority)
        if previous_query != rebuilt.query_embedding_authority:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
        reconstructed.append(rebuilt)

        for evaluation in exposure.m5_retrieval_result.candidate_evaluations:
            nested_authority = evaluation.authority
            key = (nested_authority.precedent.precedent_id, nested_authority.revision)
            if authority_by_key.get(key) != nested_authority:
                _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
            vectors = (
                ()
                if nested_authority.text_embedding is None
                else (nested_authority.text_embedding,)
            ) + nested_authority.visual_embeddings
            for candidate_vector in vectors:
                if durable_by_id.get(candidate_vector.embedding_id) != candidate_vector:
                    _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
                resolved = _resolved_embedding(
                    candidate_vector,
                    scope=M6LockedEmbeddingScope.PRECEDENT,
                )
                resolved_key = (resolved.scope, resolved.embedding_id)
                previous = resolved_by_key.setdefault(resolved_key, resolved)
                if previous != resolved:
                    _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
                candidate_embedding_ids.add(resolved.embedding_id)

    resolved_embeddings = tuple(sorted(resolved_by_key.values(), key=lambda value: value.sort_key))
    durable_slot_by_id = {value.embedding_id: value for value in plan.durable_embeddings}
    if any(value not in durable_slot_by_id for value in candidate_embedding_ids):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
    try:
        embedding_refs = tuple(
            derive_m6_upgrade_embedding_physical_ref(
                expected_embedding_id=value.embedding_id,
                authority=value,
            )
            for value in resolved_embeddings
        )
    except M6UpgradePhysicalResolutionError:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_PLAN_INVALID)
    for value in resolved_embeddings:
        if value.scope == M6LockedEmbeddingScope.PRECEDENT:
            durable_slot = durable_slot_by_id.get(value.embedding_id)
            if durable_slot is None or durable_slot.physical_ref not in embedding_refs:
                _fail(M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_PLAN_INVALID)
    actual_refs = tuple(
        sorted(
            (
                *(value.physical_ref for value in plan.exposures),
                *embedding_refs,
            ),
            key=lambda value: value.sort_key,
        )
    )
    if actual_refs != plan.planned_artifact_refs:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_PLAN_INVALID)

    try:
        snapshot = M6SQLiteM5PrecedentAuthoritySnapshot(
            source_identity_sha256=plan.plan_identity_sha256,
            upstream_m4_model_plan_identity_sha256=upstream.plan_identity_sha256,
            precedent_authority_root_sha256=_authority_root(
                plan,
                receipts=receipts,
                exposures=exposures,
                authorities=authorities,
                embeddings=resolved_embeddings,
            ),
            run_id=plan.run_id,
            case_id=plan.case_id,
            manifest_id=plan.manifest_id,
            retrieval_receipts=receipts,
            exposures=exposures,
            historical_precedent_authorities=authorities,
            reconstructed_queries=tuple(sorted(reconstructed, key=lambda value: value.exposure_id)),
            resolved_embeddings=resolved_embeddings,
            observed_artifacts=plan.observed_artifacts,
            planned_artifact_refs=actual_refs,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
    _active(connection)
    return snapshot


__all__ = [
    "M6SQLiteM5PrecedentAuthoritySnapshot",
    "build_m6_sqlite_m5_precedent_authority_snapshot",
]
