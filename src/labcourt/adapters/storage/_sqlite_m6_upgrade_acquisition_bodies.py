"""Same-snapshot canonical-body resolver for a frozen acquisition plan."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import NoReturn, TypeVar, cast

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_acquisition_projection import (
    M6AcquisitionProjectionError,
    resolve_m6_locked_acquisitions,
)
from labcourt.application.m6_upgrade_physical_resolution import (
    M6UpgradePhysicalResolutionError,
    derive_m6_upgrade_tool_result_physical_ref,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing import HearingCheckpoint, HearingCheckpointPhase, HearingRound
from labcourt.contracts.hearing_acquisition import (
    AcquisitionExecutionClaimAuthority,
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    ToolExecutionManifest,
    ToolExecutionReceipt,
)
from labcourt.contracts.hearing_persistence import EvidencePackDerivation
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_replay_locked import (
    M6LockedToolResultInput,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.domain.m6_semantic_projection import M6ResolvedAcquisition
from labcourt.ports.m6_acquisition_authority import (
    M6ValidatedM4ReplayAuthoritySnapshot,
)
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_acquisition_metadata import (
    build_m6_sqlite_acquisition_documents_plan,
)
from ._sqlite_m6_upgrade_acquisition_plan import (
    M6SQLiteAcquisitionClosurePlan,
    M6SQLiteAcquisitionDocumentsPlan,
    M6SQLiteAcquisitionPlanFailureCode,
    M6SQLiteAcquisitionSelectedPackBinding,
    M6SQLiteAcquisitionSupportDocumentRoute,
    M6SQLiteAcquisitionSupportDocumentSlot,
    _M6SQLiteAcquisitionMetadataFailure,
    _plan_is_consistent,
)
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4ModelDocumentsPlan,
)
from ._sqlite_m6_upgrade_m4_model_plan import (
    _plan_is_consistent as _m4_plan_is_consistent,
)

_DocumentT = TypeVar("_DocumentT", bound=BaseModel)


def _fail(reason: M6SQLiteAcquisitionPlanFailureCode) -> NoReturn:
    raise _M6SQLiteAcquisitionMetadataFailure(reason)


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionAuthoritySnapshot:
    """Fully decoded acquisition authority from one frozen live-read cut."""

    source_identity_sha256: str
    upstream_m4_model_plan_identity_sha256: str
    run_id: str
    case_id: str
    manifest_id: str
    replay_authority_snapshot: M6ValidatedM4ReplayAuthoritySnapshot
    locked_tool_results: tuple[M6LockedToolResultInput, ...]
    resolved_acquisitions: tuple[M6ResolvedAcquisition, ...]
    planned_artifact_refs: tuple[M6UpgradePhysicalArtifactRef, ...]

    def __post_init__(self) -> None:
        for value in (
            self.source_identity_sha256,
            self.upstream_m4_model_plan_identity_sha256,
            self.manifest_id,
        ):
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError("snapshot identities must be lowercase SHA-256 values")
        if type(self.run_id) is not str or not self.run_id or type(self.case_id) is not str:
            raise TypeError("snapshot scope must use non-empty strings")
        if type(self.replay_authority_snapshot) is not M6ValidatedM4ReplayAuthoritySnapshot:
            raise TypeError("snapshot replay authority must be exact")
        if type(self.locked_tool_results) is not tuple or any(
            type(value) is not M6LockedToolResultInput for value in self.locked_tool_results
        ):
            raise TypeError("snapshot locked ToolResults must be an exact typed tuple")
        if type(self.resolved_acquisitions) is not tuple or any(
            type(value) is not M6ResolvedAcquisition for value in self.resolved_acquisitions
        ):
            raise TypeError("snapshot acquisitions must be an exact typed tuple")
        if type(self.planned_artifact_refs) is not tuple or any(
            type(value) is not M6UpgradePhysicalArtifactRef for value in self.planned_artifact_refs
        ):
            raise TypeError("snapshot inventories must be exact typed tuples")
        if (
            self.replay_authority_snapshot.source_identity_sha256 != self.source_identity_sha256
            or self.replay_authority_snapshot.run_id != self.run_id
        ):
            raise ValueError("snapshot replay authority crosses its source identity")
        locked_ids = tuple(value.tool_result_id for value in self.locked_tool_results)
        resolved_ids = tuple(
            value.locked_input.tool_result_id for value in self.resolved_acquisitions
        )
        if (
            len(locked_ids) != len(set(locked_ids))
            or resolved_ids != locked_ids
            or self.resolved_acquisitions
            != tuple(sorted(self.resolved_acquisitions, key=lambda value: value.sort_key))
        ):
            raise ValueError("snapshot ToolResult inventories do not close exactly")
        if self.planned_artifact_refs != tuple(
            sorted(self.planned_artifact_refs, key=lambda value: value.sort_key)
        ):
            raise ValueError("snapshot physical refs must use stable order")


def _active(connection: M6LiveReader) -> None:
    try:
        active = connection.in_transaction
    except (RuntimeError, sqlite3.Error):
        _fail(M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED)
    if type(active) is not bool or not active:
        _fail(M6SQLiteAcquisitionPlanFailureCode.TRANSACTION_REQUIRED)


def _exact_row(
    connection: M6LiveReader,
    sql: str,
    *,
    rowid: int,
    artifact_id: str,
    rowid_column: str,
) -> sqlite3.Row:
    try:
        cursor = connection.execute(sql, (rowid, artifact_id))
        try:
            rows = tuple(cursor.fetchmany(2))
        finally:
            cursor.close()
    except (RuntimeError, sqlite3.Error):
        _fail(M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED)
    if len(rows) != 1 or rows[0][rowid_column] != rowid:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    return rows[0]


def _decode(
    raw: object,
    model: type[_DocumentT],
    *,
    expected_bytes: int,
    expected_canonical_sha256: str | None,
) -> tuple[_DocumentT, str]:
    if type(raw) is not str:
        _fail(M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID)
    try:
        encoded = raw.encode("utf-8")
        document = model.model_validate_json(raw)
        canonical = canonical_json(document.model_dump(mode="json"))
    except (TypeError, UnicodeError, ValueError, ValidationError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID)
    canonical_sha256 = hashlib.sha256(encoded).hexdigest()
    if (
        len(encoded) != expected_bytes
        or canonical != raw
        or (expected_canonical_sha256 is not None and canonical_sha256 != expected_canonical_sha256)
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID)
    return document, canonical


def _slot(
    closure: M6SQLiteAcquisitionClosurePlan,
    route: M6SQLiteAcquisitionSupportDocumentRoute,
) -> M6SQLiteAcquisitionSupportDocumentSlot:
    values = tuple(value for value in closure.support_document_slots if value.route == route)
    if len(values) != 1:
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)
    return values[0]


_SUPPORT_BODY_SQL = {
    M6SQLiteAcquisitionSupportDocumentRoute.ACQUISITION_REQUEST: (
        "SELECT rowid AS document_rowid, request_json FROM m4_acquisition_requests "
        "WHERE rowid = ? AND acquisition_request_id = ? LIMIT 2",
        "document_rowid",
        "request_json",
        AcquisitionRequest,
    ),
    M6SQLiteAcquisitionSupportDocumentRoute.EXECUTION_PUBLICATION: (
        "SELECT rowid AS document_rowid, publication_json "
        "FROM m4_acquisition_execution_publications "
        "WHERE rowid = ? AND execution_publication_id = ? LIMIT 2",
        "document_rowid",
        "publication_json",
        AcquisitionExecutionPublication,
    ),
    M6SQLiteAcquisitionSupportDocumentRoute.TOOL_EXECUTION_RECEIPT: (
        "SELECT rowid AS document_rowid, receipt_json FROM m4_tool_execution_receipts "
        "WHERE rowid = ? AND receipt_id = ? LIMIT 2",
        "document_rowid",
        "receipt_json",
        ToolExecutionReceipt,
    ),
    M6SQLiteAcquisitionSupportDocumentRoute.EVIDENCE_PACK_DERIVATION: (
        "SELECT rowid AS document_rowid, derivation_json FROM m4_evidence_pack_derivations "
        "WHERE rowid = ? AND derivation_id = ? LIMIT 2",
        "document_rowid",
        "derivation_json",
        EvidencePackDerivation,
    ),
    M6SQLiteAcquisitionSupportDocumentRoute.HEARING_CHECKPOINT: (
        "SELECT rowid AS support_rowid, checkpoint_json FROM m4_hearing_checkpoints "
        "WHERE rowid = ? AND checkpoint_id = ? LIMIT 2",
        "support_rowid",
        "checkpoint_json",
        HearingCheckpoint,
    ),
    M6SQLiteAcquisitionSupportDocumentRoute.HEARING_ROUND: (
        "SELECT rowid AS support_rowid, round_json FROM m4_hearing_rounds "
        "WHERE rowid = ? AND round_id = ? LIMIT 2",
        "support_rowid",
        "round_json",
        HearingRound,
    ),
    M6SQLiteAcquisitionSupportDocumentRoute.CASE_VERSION: (
        "SELECT rowid AS support_rowid, case_json FROM case_versions "
        "WHERE rowid = ? AND case_id = ? LIMIT 2",
        "support_rowid",
        "case_json",
        Case,
    ),
    M6SQLiteAcquisitionSupportDocumentRoute.AUDIT_ENTRY: (
        "SELECT rowid AS support_rowid, entry_json FROM audit_entries "
        "WHERE rowid = ? AND entry_hash = ? LIMIT 2",
        "support_rowid",
        "entry_json",
        AuditEntry,
    ),
}


def _support_body(
    connection: M6LiveReader,
    slot: M6SQLiteAcquisitionSupportDocumentSlot,
) -> tuple[BaseModel, str]:
    sql, rowid_column, json_column, model = _SUPPORT_BODY_SQL[slot.route]
    lookup_id = slot.artifact_id
    if slot.route == M6SQLiteAcquisitionSupportDocumentRoute.CASE_VERSION:
        marker = "-revision-"
        case_id, separator, revision = slot.artifact_id.rpartition(marker)
        if separator != marker or not case_id or len(revision) != 6 or not revision.isdecimal():
            _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)
        lookup_id = case_id
    row = _exact_row(
        connection,
        sql,
        rowid=slot.rowid,
        artifact_id=lookup_id,
        rowid_column=rowid_column,
    )
    expected_sha = (
        slot.body_commitment_sha256 if slot.commitment_kind.value == "CANONICAL_DOCUMENT" else None
    )
    document: BaseModel
    document, canonical = _decode(
        row[json_column],
        cast(type[BaseModel], model),
        expected_bytes=slot.document_bytes,
        expected_canonical_sha256=expected_sha,
    )
    semantic = None
    if isinstance(document, HearingCheckpoint):
        semantic = document.checkpoint_sha256
    elif isinstance(document, HearingRound):
        semantic = document.round_id
    if semantic is not None and semantic != slot.body_commitment_sha256:
        _fail(M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID)
    return document, canonical


def _authority_ref(
    kind: M6ReplayAuthorityKind,
    artifact_id: str,
    canonical_document: str,
) -> M6ReplayAuthorityRef:
    return M6ReplayAuthorityRef(
        kind=kind,
        artifact_id=artifact_id,
        document_sha256=hashlib.sha256(canonical_document.encode("utf-8")).hexdigest(),
    )


def _fresh_plan(
    connection: M6LiveReader,
    plan: M6SQLiteAcquisitionDocumentsPlan,
    upstream: M6SQLiteM4ModelDocumentsPlan,
) -> None:
    authority = M6SQLiteCaseAuthorityDocument(
        candidate_case_binding=plan.selected_case_binding,
        case=plan.selected_case,
        canonical_case_document=canonical_json(plan.selected_case.model_dump(mode="json")),
        audit_entry=plan.selected_case_audit,
        canonical_audit_document=canonical_json(plan.selected_case_audit.model_dump(mode="json")),
    )
    rebuilt = build_m6_sqlite_acquisition_documents_plan(
        connection=connection,
        expected_run_id=plan.run_id,
        expected_manifest_id=plan.manifest_id,
        upstream_m4_model_plan=upstream,
        selected_case_authority=authority,
        observed_acquisition_artifacts=plan.observed_artifacts,
    )
    if rebuilt != plan or rebuilt.plan_identity_sha256 != plan.plan_identity_sha256:
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)


def _manifest_body(
    connection: M6LiveReader,
    closure: M6SQLiteAcquisitionClosurePlan,
) -> tuple[ToolExecutionManifest, str]:
    slot = closure.manifest
    row = _exact_row(
        connection,
        "SELECT rowid AS document_rowid, manifest_json FROM m4_tool_execution_manifests "
        "WHERE rowid = ? AND execution_manifest_id = ? LIMIT 2",
        rowid=slot.rowid,
        artifact_id=slot.execution_manifest_id,
        rowid_column="document_rowid",
    )
    manifest, canonical = _decode(
        row["manifest_json"],
        ToolExecutionManifest,
        expected_bytes=slot.document_bytes,
        expected_canonical_sha256=slot.document_sha256,
    )
    if (
        manifest.execution_manifest_id != slot.execution_manifest_id
        or manifest.acquisition_request_id != slot.acquisition_request_id
        or manifest.run_id != slot.run_id
        or manifest.case_id != slot.case_id
        or manifest.hearing_session_id != slot.hearing_id
        or manifest.action != slot.action
        or manifest.component_manifest_id != slot.component_manifest_id
        or manifest.model_manifest_id != slot.model_manifest_id
        or manifest.manifest_id != slot.manifest_id
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    return manifest, canonical


def _claim_bodies(
    connection: M6LiveReader,
    closure: M6SQLiteAcquisitionClosurePlan,
) -> tuple[AcquisitionRequest, AcquisitionExecutionClaimAuthority]:
    slot = closure.claim
    row = _exact_row(
        connection,
        "SELECT rowid AS document_rowid, request_json, claim_json "
        "FROM m4_acquisition_execution_claims "
        "WHERE rowid = ? AND acquisition_request_id = ? LIMIT 2",
        rowid=slot.rowid,
        artifact_id=slot.acquisition_request_id,
        rowid_column="document_rowid",
    )
    request, _canonical_request = _decode(
        row["request_json"],
        AcquisitionRequest,
        expected_bytes=slot.request_document_bytes,
        expected_canonical_sha256=slot.request_document_sha256,
    )
    claim, _canonical_claim = _decode(
        row["claim_json"],
        AcquisitionExecutionClaimAuthority,
        expected_bytes=slot.claim_document_bytes,
        expected_canonical_sha256=slot.claim_document_sha256,
    )
    return request, claim


def _pack_body(
    connection: M6LiveReader,
    *,
    rowid: int,
    pack_id: str,
    document_bytes: int,
    document_sha256: str,
) -> tuple[EvidencePack, str]:
    row = _exact_row(
        connection,
        "SELECT rowid AS document_rowid, pack_json FROM evidence_packs "
        "WHERE rowid = ? AND pack_id = ? LIMIT 2",
        rowid=rowid,
        artifact_id=pack_id,
        rowid_column="document_rowid",
    )
    return _decode(
        row["pack_json"],
        EvidencePack,
        expected_bytes=document_bytes,
        expected_canonical_sha256=document_sha256,
    )


_PackBodyCache = dict[
    tuple[int, str],
    tuple[M6SQLiteAcquisitionSelectedPackBinding, EvidencePack, str],
]


def _cached_pack_body(
    connection: M6LiveReader,
    binding: M6SQLiteAcquisitionSelectedPackBinding,
    cache: _PackBodyCache,
) -> tuple[EvidencePack, str]:
    key = (binding.rowid, binding.pack_id)
    cached = cache.get(key)
    if cached is not None:
        cached_binding, document, canonical = cached
        if cached_binding != binding:
            _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)
        return document, canonical
    document, canonical = _pack_body(
        connection,
        rowid=binding.rowid,
        pack_id=binding.pack_id,
        document_bytes=binding.document_bytes,
        document_sha256=binding.document_sha256,
    )
    cache[key] = (binding, document, canonical)
    return document, canonical


@dataclass(frozen=True, slots=True)
class _ResolvedClosureBodies:
    documents: tuple[M6HistoricalAuthorityDocument, ...]
    locked: M6LockedToolResultInput
    manifest: ToolExecutionManifest


def _resolve_closure_bodies(
    connection: M6LiveReader,
    plan: M6SQLiteAcquisitionDocumentsPlan,
    closure: M6SQLiteAcquisitionClosurePlan,
    pack_cache: _PackBodyCache,
) -> _ResolvedClosureBodies:
    decoded_support: dict[M6SQLiteAcquisitionSupportDocumentRoute, tuple[BaseModel, str]] = {}
    for support_slot in closure.support_document_slots:
        decoded_support[support_slot.route] = _support_body(connection, support_slot)
    if len(decoded_support) != len(closure.support_document_slots):
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)

    request = cast(
        AcquisitionRequest,
        decoded_support[M6SQLiteAcquisitionSupportDocumentRoute.ACQUISITION_REQUEST][0],
    )
    publication = cast(
        AcquisitionExecutionPublication,
        decoded_support[M6SQLiteAcquisitionSupportDocumentRoute.EXECUTION_PUBLICATION][0],
    )
    receipt = cast(
        ToolExecutionReceipt,
        decoded_support[M6SQLiteAcquisitionSupportDocumentRoute.TOOL_EXECUTION_RECEIPT][0],
    )
    derivation = cast(
        EvidencePackDerivation,
        decoded_support[M6SQLiteAcquisitionSupportDocumentRoute.EVIDENCE_PACK_DERIVATION][0],
    )
    checkpoint = cast(
        HearingCheckpoint,
        decoded_support[M6SQLiteAcquisitionSupportDocumentRoute.HEARING_CHECKPOINT][0],
    )
    transition_case = cast(
        Case,
        decoded_support[M6SQLiteAcquisitionSupportDocumentRoute.CASE_VERSION][0],
    )
    transition_audit = cast(
        AuditEntry,
        decoded_support[M6SQLiteAcquisitionSupportDocumentRoute.AUDIT_ENTRY][0],
    )
    claim_request, claim = _claim_bodies(connection, closure)
    manifest, canonical_manifest = _manifest_body(connection, closure)
    previous, _canonical_previous = _cached_pack_body(
        connection,
        closure.pack_transition.previous_pack,
        pack_cache,
    )
    resulting, canonical_resulting = _cached_pack_body(
        connection,
        closure.pack_transition.resulting_pack,
        pack_cache,
    )
    try:
        parameters_schema_sha256 = sha256_hex(
            [
                "m4-acquisition-parameters-schema",
                1,
                request.action.value,
                type(request.validated_parameters).model_json_schema(mode="validation"),
            ]
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID)
    embedded_packs = {
        (value.pack_id, value.version): value for value in plan.selected_case.evidence_packs
    }
    if (
        claim_request != request
        or claim.request != request
        or claim.execution_mode != closure.claim.execution_mode
        or claim.idempotency_key != closure.claim.idempotency_key
        or claim.owner_token_sha256 != closure.claim.owner_token_sha256
        or claim.owner_fence != closure.claim.owner_fence
        or claim.status.value != closure.claim.status.value
        or claim.execution_publication_id != closure.claim.execution_publication_id
        or claim.execution_publication_id != publication.publication_id
        or claim.owner_token_sha256 != publication.claim_owner_sha256
        or claim.owner_fence != publication.claim_fence
        or claim.execution_mode != publication.execution_mode
        or manifest != publication.execution_manifest
        or publication.request != request
        or receipt.request != request
        or receipt.execution_manifest != manifest
        or receipt.tool_result != publication.tool_result
        or derivation.tool_execution_receipt_id != receipt.receipt_id
        or derivation.previous_evidence_pack_id != previous.pack_id
        or derivation.new_evidence_pack_id != resulting.pack_id
        or embedded_packs.get((previous.pack_id, previous.version)) != previous
        or embedded_packs.get((resulting.pack_id, resulting.version)) != resulting
        or transition_audit.after_sha256
        != hashlib.sha256(
            canonical_json(transition_case.model_dump(mode="json")).encode("utf-8")
        ).hexdigest()
        or transition_audit.sequence != closure.pack_transition.transition_audit_sequence
        or transition_audit.entry_hash != closure.pack_transition.transition_audit_entry_hash
        or not transition_case.evidence_packs
        or transition_case.evidence_packs[-1] != resulting
        or request.run_id != plan.run_id
        or request.case_id != plan.case_id
        or request.manifest_id != plan.manifest_id
        or request.request_id != closure.acquisition_request_id
        or request.hearing_session_id != closure.upstream_m4.hearing_id
        or publication.publication_id != closure.execution_publication_id
        or receipt.receipt_id != closure.tool_receipt_id
        or derivation.derivation_id != closure.derivation_id
        or checkpoint.checkpoint_id != closure.checkpoint_id
        or checkpoint.phase != HearingCheckpointPhase.ACQUISITION_PENDING
        or checkpoint.hearing_session_id != request.hearing_session_id
        or checkpoint.current_evidence_pack_id != previous.pack_id
        or checkpoint.current_evidence_pack_version != previous.version
        or manifest.component_manifest_id != closure.manifest.component_manifest_id
        or manifest.model_manifest_id != closure.manifest.model_manifest_id
        or manifest.parameters_schema_sha256 != parameters_schema_sha256
        or checkpoint.acquisition_request != request
        or checkpoint.tool_execution_receipt is not None
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    if closure.round_id is None:
        if M6SQLiteAcquisitionSupportDocumentRoute.HEARING_ROUND in decoded_support:
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    else:
        hearing_round = cast(
            HearingRound,
            decoded_support[M6SQLiteAcquisitionSupportDocumentRoute.HEARING_ROUND][0],
        )
        if (
            hearing_round.round_id != closure.round_id
            or hearing_round.run_id != plan.run_id
            or hearing_round.case_id != plan.case_id
            or hearing_round.manifest_id != plan.manifest_id
            or hearing_round.hearing_session_id != request.hearing_session_id
            or hearing_round.current_evidence_pack_id != previous.pack_id
            or hearing_round.current_evidence_pack_version != previous.version
            or hearing_round.acquisition_request != request
            or hearing_round.tool_execution_receipt != receipt
            or hearing_round.resulting_evidence_pack_id != resulting.pack_id
        ):
            _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)

    canonical_request = decoded_support[
        M6SQLiteAcquisitionSupportDocumentRoute.ACQUISITION_REQUEST
    ][1]
    canonical_publication = decoded_support[
        M6SQLiteAcquisitionSupportDocumentRoute.EXECUTION_PUBLICATION
    ][1]
    canonical_receipt = decoded_support[
        M6SQLiteAcquisitionSupportDocumentRoute.TOOL_EXECUTION_RECEIPT
    ][1]
    canonical_derivation = decoded_support[
        M6SQLiteAcquisitionSupportDocumentRoute.EVIDENCE_PACK_DERIVATION
    ][1]
    historical = tuple(
        sorted(
            (
                M6HistoricalAuthorityDocument(
                    kind=M4ProjectionArtifactKind.ACQUISITION_REQUEST,
                    artifact_id=request.request_id,
                    canonical_document=canonical_request,
                ),
                M6HistoricalAuthorityDocument(
                    kind=M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST,
                    artifact_id=manifest.execution_manifest_id,
                    canonical_document=canonical_manifest,
                ),
                M6HistoricalAuthorityDocument(
                    kind=M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION,
                    artifact_id=publication.publication_id,
                    canonical_document=canonical_publication,
                ),
                M6HistoricalAuthorityDocument(
                    kind=M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
                    artifact_id=receipt.receipt_id,
                    canonical_document=canonical_receipt,
                ),
                M6HistoricalAuthorityDocument(
                    kind=M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION,
                    artifact_id=derivation.derivation_id,
                    canonical_document=canonical_derivation,
                ),
            ),
            key=lambda value: value.sort_key,
        )
    )
    tool_result_document = canonical_json(publication.tool_result.model_dump(mode="json"))
    locked = M6LockedToolResultInput(
        tool_result_id=publication.tool_result.tool_result_id,
        tool_result_document_sha256=hashlib.sha256(
            tool_result_document.encode("utf-8")
        ).hexdigest(),
        acquisition_request_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_ACQUISITION_REQUEST,
            request.request_id,
            canonical_request,
        ),
        execution_manifest_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_TOOL_EXECUTION_MANIFEST,
            manifest.execution_manifest_id,
            canonical_manifest,
        ),
        execution_publication_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_ACQUISITION_PUBLICATION,
            publication.publication_id,
            canonical_publication,
        ),
        tool_receipt_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_TOOL_EXECUTION_RECEIPT,
            receipt.receipt_id,
            canonical_receipt,
        ),
        evidence_pack_derivation_ref=_authority_ref(
            M6ReplayAuthorityKind.M4_EVIDENCE_PACK_DERIVATION,
            derivation.derivation_id,
            canonical_derivation,
        ),
        resulting_evidence_pack_ref=_authority_ref(
            M6ReplayAuthorityKind.EVIDENCE_PACK,
            resulting.pack_id,
            canonical_resulting,
        ),
    )
    return _ResolvedClosureBodies(documents=historical, locked=locked, manifest=manifest)


def build_m6_sqlite_acquisition_authority_snapshot(
    *,
    connection: object,
    metadata_plan: object,
    upstream_m4_model_plan: object,
) -> M6SQLiteAcquisitionAuthoritySnapshot:
    """Resolve exactly the acquisition bodies frozen by one same-snapshot plan."""

    if (
        type(connection) is not M6LiveReader
        or not _plan_is_consistent(metadata_plan)
        or not _m4_plan_is_consistent(upstream_m4_model_plan)
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    plan = cast(M6SQLiteAcquisitionDocumentsPlan, metadata_plan)
    upstream = cast(M6SQLiteM4ModelDocumentsPlan, upstream_m4_model_plan)
    if (
        plan.upstream_m4_model_plan_identity_sha256 != upstream.plan_identity_sha256
        or plan.run_id != upstream.run_id
        or plan.case_id != upstream.case_id
        or plan.manifest_id != upstream.manifest_id
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.SCOPE_MISMATCH)

    _active(connection)
    # Replay every metadata/index query before opening the first canonical body.
    # Exact plan equality makes drift, added rows, and altered commitments fatal.
    _fresh_plan(connection, plan, upstream)

    pack_cache: _PackBodyCache = {}
    closure_bodies = tuple(
        _resolve_closure_bodies(connection, plan, closure, pack_cache) for closure in plan.closures
    )
    if set(pack_cache) != {
        (binding.rowid, binding.pack_id) for binding in plan.selected_pack_bindings
    }:
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)
    documents = tuple(
        sorted(
            (document for item in closure_bodies for document in item.documents),
            key=lambda value: value.sort_key,
        )
    )
    document_keys = tuple(value.sort_key for value in documents)
    if len(document_keys) != len(set(document_keys)):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    locked = tuple(item.locked for item in closure_bodies)
    if len(locked) != len(plan.closures) or len({item.tool_result_id for item in locked}) != len(
        locked
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)

    try:
        replay_snapshot = M6ValidatedM4ReplayAuthoritySnapshot(
            source_identity_sha256=plan.plan_identity_sha256,
            run_id=plan.run_id,
            documents=documents,
        )
        resolved = resolve_m6_locked_acquisitions(
            source_case=plan.selected_case,
            snapshot=replay_snapshot,
            locked_tool_results=locked,
        )
    except M6AcquisitionProjectionError:
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID)

    try:
        derived_tool_refs = tuple(
            derive_m6_upgrade_tool_result_physical_ref(
                expected_run_id=plan.run_id,
                expected_tool_result_id=item.locked_input.tool_result_id,
                authority=item,
            )
            for item in resolved
        )
    except M6UpgradePhysicalResolutionError:
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)
    actual_refs = tuple(
        sorted(
            (
                *(item.manifest.physical_ref for item in plan.closures),
                *derived_tool_refs,
            ),
            key=lambda value: value.sort_key,
        )
    )
    if actual_refs != plan.planned_artifact_refs:
        _fail(M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_PLAN_INVALID)

    try:
        snapshot = M6SQLiteAcquisitionAuthoritySnapshot(
            source_identity_sha256=plan.plan_identity_sha256,
            upstream_m4_model_plan_identity_sha256=upstream.plan_identity_sha256,
            run_id=plan.run_id,
            case_id=plan.case_id,
            manifest_id=plan.manifest_id,
            replay_authority_snapshot=replay_snapshot,
            locked_tool_results=locked,
            resolved_acquisitions=resolved,
            planned_artifact_refs=actual_refs,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.CLOSURE_MISMATCH)
    _active(connection)
    return snapshot


__all__ = [
    "M6SQLiteAcquisitionAuthoritySnapshot",
    "build_m6_sqlite_acquisition_authority_snapshot",
]
