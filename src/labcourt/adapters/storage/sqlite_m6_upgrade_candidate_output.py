"""SQLite terminal Inventory V3 builder for opened base and M3 routes."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from labcourt.application.m6_source_authority_sealing import M6SealedGateSource
from labcourt.application.m6_upgrade_candidate_output import (
    build_m6_upgrade_candidate_output_inventory,
)
from labcourt.application.m6_upgrade_candidate_projection import (
    build_m6_upgrade_base_candidate_case_snapshot,
    build_m6_upgrade_hearing_candidate_case_snapshot,
    build_m6_upgrade_screening_candidate_case_snapshot,
)
from labcourt.application.m6_upgrade_m3_model_physical import (
    M6M3ModelPhysicalPlan,
    M6M3ModelPhysicalResolutionError,
    M6M3ModelPhysicalResolutionErrorCode,
    plan_m6_m3_observed_model_call_closures,
    resolve_m6_m3_observed_model_call_physical_plan,
)
from labcourt.application.m6_upgrade_m4_model_physical import (
    M6M4ModelPhysicalPlan,
    M6M4ModelPhysicalResolutionError,
    M6M4ModelPhysicalResolutionErrorCode,
    plan_m6_m4_observed_model_call_closures,
    resolve_m6_m4_observed_model_call_physical_plan,
)
from labcourt.application.m6_upgrade_physical_resolution import (
    M6UpgradePhysicalResolutionError,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import Detection
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6ReplayExecutionOutcome,
)
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
    M6UpgradeCandidateRunCutAuthority,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import parse_frame_id, require_reference_token
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.ports.evidence_repository import EvidenceVerifier
from labcourt.ports.hearing_vlm import HearingRawModelResponseVerifier
from labcourt.ports.m6_historical_retrieval import M6ValidatedHistoricalRetrievalSnapshots
from labcourt.ports.m6_model_calls import (
    M6M3ModelCallAuthoritySnapshot,
    M6M4ModelCallAuthoritySnapshot,
)
from labcourt.ports.m6_procedural_gate_authority import M6ProceduralGateHistorySnapshot
from labcourt.ports.m6_upgrade_candidate_output import (
    M6UpgradeCandidateOutputError,
    M6UpgradeCandidateOutputFailureCode,
)
from labcourt.ports.m6_upgrade_candidate_run_cut import (
    M6UpgradeCandidateRunCutError,
    M6UpgradeCandidateRunCutFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
)
from labcourt.ports.m6_upgrade_model_physical import (
    M6ObservedModelCallPhysicalClosure,
    M6PlannedModelCallPhysicalClosure,
)
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from labcourt.ports.pixels import PixelFrameProvider
from labcourt.ports.vlm import RawModelResponseVerifier

from ._sqlite_m6_live_read_cut import (
    M6LivePendingSelector,
    M6LiveReadCutError,
    M6LiveReader,
    m6_live_committed_read_cut,
)
from ._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseAuthorityDocument,
    M6SQLiteCaseDocumentError,
    M6SQLiteCaseDocumentFailureCode,
    read_m6_sqlite_case_authority_v3,
)
from ._sqlite_m6_upgrade_evidence_pack_document import (
    M6SQLiteEvidencePackDocumentError,
    M6SQLiteEvidencePackDocumentFailureCode,
    M6SQLiteEvidencePackPhysicalPlan,
    resolve_m6_sqlite_evidence_pack_physical_plan,
)
from ._sqlite_m6_upgrade_frame_document import (
    M6SQLiteFrameDocumentError,
    M6SQLiteFrameDocumentFailureCode,
    M6SQLiteFramePhysicalPlan,
)
from ._sqlite_m6_upgrade_gate_current_source import (
    M6SQLiteGateCurrentSourceError,
    M6SQLiteGateCurrentSourceFailureCode,
    seal_m6_sqlite_gate_current_source,
)
from ._sqlite_m6_upgrade_m3_model_documents import (
    M6SQLiteM3ModelDocumentError,
    M6SQLiteM3ModelDocumentFailureCode,
    M6SQLiteM3ModelDocumentsPlan,
    resolve_m6_sqlite_m3_model_documents,
)
from ._sqlite_m6_upgrade_m4_gate_documents import (
    M6SQLiteM4GateAuthoritySnapshot,
    M6SQLiteM4GateDocumentsPlan,
    assemble_m6_sqlite_m4_gate_history_snapshot,
    plan_m6_sqlite_m4_gate_documents,
    resolve_m6_sqlite_m4_gate_documents,
)
from ._sqlite_m6_upgrade_m4_model_documents import (
    M6SQLiteM4ModelDocumentError,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4ModelDocumentsPlan,
    resolve_m6_sqlite_m4_model_documents,
)
from ._sqlite_m6_upgrade_m5_precedent_bodies import (
    M6SQLiteM5PrecedentAuthoritySnapshot,
)
from ._sqlite_m6_upgrade_m5_precedent_metadata import (
    M6SQLiteM5PrecedentDocumentError,
    assemble_m6_sqlite_historical_retrieval_snapshots,
    resolve_m6_sqlite_m5_precedent_documents,
)
from ._sqlite_m6_upgrade_m5_precedent_plan import (
    M6SQLiteM5PrecedentDocumentsPlan,
    M6SQLiteM5PrecedentPlanFailureCode,
)
from ._sqlite_m6_upgrade_physical_documents import (
    M6SQLiteCanonicalPhysicalDocument,
    M6SQLitePhysicalDocumentError,
    M6SQLitePhysicalDocumentFailureCode,
    resolve_m6_sqlite_canonical_physical_identity,
)
from .sqlite_m6_upgrade_candidate_run_cut import (
    load_m6_upgrade_candidate_run_cut_from_connection,
)
from .sqlite_m6_upgrade_execution_ledger_v3 import (
    M6SQLiteUpgradeV3State,
    load_m6_upgrade_v3_state_from_connection,
)
from .sqlite_m6_upgrade_whole_sample_record_builder import (
    SQLiteM6UpgradeWholeSampleRecordBuilderV3,
)

_FailureCode = M6UpgradeCandidateOutputFailureCode
_BASE_KINDS = {
    M6UpgradePhysicalArtifactKind.FRAME,
    M6UpgradePhysicalArtifactKind.DETECTION,
}
_BASE_ROUTES = {
    (
        M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        M6UpgradePhysicalArtifactKind.FRAME,
    ),
    (
        M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        M6UpgradePhysicalArtifactKind.DETECTION,
    ),
}
_SCREENING_ROUTES = _BASE_ROUTES | {
    (
        M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
        M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
    )
}


def _error(code: _FailureCode) -> M6UpgradeCandidateOutputError:
    return M6UpgradeCandidateOutputError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _public_identity(
    candidate_run_id: object,
    execution_scope_authority_id: object,
) -> tuple[str, str]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(candidate_run_id, "M6 terminal candidate run_id")
    except (TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if (
        not isinstance(execution_scope_authority_id, str)
        or len(execution_scope_authority_id) != 64
        or any(character not in "0123456789abcdef" for character in execution_scope_authority_id)
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    return run_id, execution_scope_authority_id


def _select_terminal_v3(
    selector: M6LivePendingSelector,
    run_id: str,
    scope_id: str,
) -> None:
    row = selector.execute(
        """
        SELECT protocol.protocol_version, seal.seal_schema_version
        FROM m6_upgrade_execution_scopes AS scope
        JOIN m6_upgrade_execution_ledger_protocols AS protocol
          ON protocol.run_id = scope.run_id
         AND protocol.execution_scope_authority_id = scope.execution_scope_authority_id
        LEFT JOIN m6_upgrade_execution_ledger_seals AS seal
          ON seal.run_id = scope.run_id
         AND seal.execution_scope_authority_id = scope.execution_scope_authority_id
        WHERE scope.run_id = ? AND scope.execution_scope_authority_id = ?
        """,
        (run_id, scope_id),
    ).fetchone()
    if row is None:
        _fail(_FailureCode.SCOPE_NOT_FOUND)
    try:
        protocol_version = row["protocol_version"]
        seal_version = row["seal_schema_version"]
    except (IndexError, KeyError, TypeError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    if protocol_version != "v3":
        _fail(_FailureCode.LEDGER_VERSION_UNSUPPORTED)
    if seal_version is None:
        _fail(_FailureCode.LEDGER_NOT_SEALED)
    if seal_version != "v2":
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


def _run_cut_failure(code: M6UpgradeCandidateRunCutFailureCode) -> _FailureCode:
    direct = {
        M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6UpgradeCandidateRunCutFailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6UpgradeCandidateRunCutFailureCode.LEDGER_VERSION_UNSUPPORTED: (
            _FailureCode.LEDGER_VERSION_UNSUPPORTED
        ),
        M6UpgradeCandidateRunCutFailureCode.LEDGER_NOT_SEALED: (_FailureCode.LEDGER_NOT_SEALED),
        M6UpgradeCandidateRunCutFailureCode.RUN_CUT_NOT_FOUND: (_FailureCode.RUN_CUT_NOT_FOUND),
        M6UpgradeCandidateRunCutFailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeCandidateRunCutFailureCode.SNAPSHOT_REJECTED: (_FailureCode.SNAPSHOT_REJECTED),
        M6UpgradeCandidateRunCutFailureCode.STORAGE_REJECTED: (_FailureCode.STORAGE_REJECTED),
    }
    return direct.get(code, _FailureCode.RUN_CUT_MISMATCH)


def _state_failure(code: M6UpgradeExecutionLedgerV3FailureCode) -> _FailureCode:
    direct = {
        M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6UpgradeExecutionLedgerV3FailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            _FailureCode.LEDGER_VERSION_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_VERSION_UNSUPPORTED: (
            _FailureCode.LEDGER_VERSION_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
    }
    return direct.get(code, _FailureCode.SNAPSHOT_REJECTED)


def _record_builder_failure(
    code: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> _FailureCode:
    if code == M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH:
        return _FailureCode.CASE_BINDING_MISMATCH
    if code == M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH:
        return _FailureCode.MODEL_CALL_CLOSURE_MISMATCH
    if code in {
        M6UpgradeWholeSampleRecordBuilderFailureCode.LINK_LIMIT_EXCEEDED,
        M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED,
        M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE,
        M6UpgradeWholeSampleRecordBuilderFailureCode.RECORD_TOO_LARGE,
    }:
        return _FailureCode.DOCUMENT_TOO_LARGE
    if code == M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID:
        return _FailureCode.STORED_AUTHORITY_INVALID
    if code in {
        M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED,
        M6UpgradeWholeSampleRecordBuilderFailureCode.RAW_RESPONSE_REJECTED,
        M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT,
    }:
        return _FailureCode.PHYSICAL_ARTIFACT_REJECTED
    return _FailureCode.INVENTORY_CLOSURE_MISMATCH


def _frame_document_failure(code: M6SQLiteFrameDocumentFailureCode) -> _FailureCode:
    if code == M6SQLiteFrameDocumentFailureCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    if code in {
        M6SQLiteFrameDocumentFailureCode.SCOPE_NOT_FOUND,
        M6SQLiteFrameDocumentFailureCode.DOCUMENT_NOT_FOUND,
    }:
        return _FailureCode.OBSERVATION_CLOSURE_MISMATCH
    if code in {
        M6SQLiteFrameDocumentFailureCode.TRANSACTION_REQUIRED,
        M6SQLiteFrameDocumentFailureCode.DATABASE_REJECTED,
    }:
        return _FailureCode.SNAPSHOT_REJECTED
    return _FailureCode.STORED_AUTHORITY_INVALID


def _physical_document_failure(
    code: M6SQLitePhysicalDocumentFailureCode,
) -> _FailureCode:
    if code == M6SQLitePhysicalDocumentFailureCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    if code in {
        M6SQLitePhysicalDocumentFailureCode.SCOPE_NOT_FOUND,
        M6SQLitePhysicalDocumentFailureCode.DOCUMENT_NOT_FOUND,
    }:
        return _FailureCode.OBSERVATION_CLOSURE_MISMATCH
    if code in {
        M6SQLitePhysicalDocumentFailureCode.TRANSACTION_REQUIRED,
        M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED,
    }:
        return _FailureCode.SNAPSHOT_REJECTED
    return _FailureCode.STORED_AUTHORITY_INVALID


def _case_document_failure(code: M6SQLiteCaseDocumentFailureCode) -> _FailureCode:
    if code == M6SQLiteCaseDocumentFailureCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    if code in {
        M6SQLiteCaseDocumentFailureCode.SCOPE_NOT_FOUND,
        M6SQLiteCaseDocumentFailureCode.DOCUMENT_NOT_FOUND,
        M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH,
        M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        M6SQLiteCaseDocumentFailureCode.SELECTED_AUDIT_ANCHOR_MISMATCH,
    }:
        return _FailureCode.CASE_BINDING_MISMATCH
    if code in {
        M6SQLiteCaseDocumentFailureCode.TRANSACTION_REQUIRED,
        M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED,
    }:
        return _FailureCode.SNAPSHOT_REJECTED
    return _FailureCode.STORED_AUTHORITY_INVALID


def _evidence_pack_document_failure(
    code: M6SQLiteEvidencePackDocumentFailureCode,
) -> _FailureCode:
    if code == M6SQLiteEvidencePackDocumentFailureCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code in {
        M6SQLiteEvidencePackDocumentFailureCode.ROW_LIMIT_EXCEEDED,
        M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_TOO_LARGE,
    }:
        return _FailureCode.DOCUMENT_TOO_LARGE
    if code in {
        M6SQLiteEvidencePackDocumentFailureCode.SCOPE_NOT_FOUND,
        M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_NOT_FOUND,
        M6SQLiteEvidencePackDocumentFailureCode.SELECTED_CASE_MEMBERSHIP_MISMATCH,
    }:
        return _FailureCode.OBSERVATION_CLOSURE_MISMATCH
    if code in {
        M6SQLiteEvidencePackDocumentFailureCode.TRANSACTION_REQUIRED,
        M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED,
    }:
        return _FailureCode.SNAPSHOT_REJECTED
    return _FailureCode.STORED_AUTHORITY_INVALID


def _m3_document_failure(code: M6SQLiteM3ModelDocumentFailureCode) -> _FailureCode:
    direct = {
        M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6SQLiteM3ModelDocumentFailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6SQLiteM3ModelDocumentFailureCode.CASE_BINDING_MISMATCH: (
            _FailureCode.CASE_BINDING_MISMATCH
        ),
        M6SQLiteM3ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH: (
            _FailureCode.MODEL_CALL_CLOSURE_MISMATCH
        ),
        M6SQLiteM3ModelDocumentFailureCode.ROW_LIMIT_EXCEEDED: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6SQLiteM3ModelDocumentFailureCode.TRANSACTION_REQUIRED: (_FailureCode.SNAPSHOT_REJECTED),
        M6SQLiteM3ModelDocumentFailureCode.DATABASE_REJECTED: (_FailureCode.SNAPSHOT_REJECTED),
    }
    return direct.get(code, _FailureCode.STORED_AUTHORITY_INVALID)


def _m3_physical_failure(code: M6M3ModelPhysicalResolutionErrorCode) -> _FailureCode:
    if code == M6M3ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code in {
        M6M3ModelPhysicalResolutionErrorCode.AUTHORITY_ASSEMBLY_FAILED,
        M6M3ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID,
        M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_REF_INVALID,
    }:
        return _FailureCode.STORED_AUTHORITY_INVALID
    if code in {
        M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH,
        M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID,
        M6M3ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID,
    }:
        return _FailureCode.MODEL_CALL_CLOSURE_MISMATCH
    if code == M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_BUDGET_EXCEEDED:
        return _FailureCode.DOCUMENT_TOO_LARGE
    return _FailureCode.PHYSICAL_ARTIFACT_REJECTED


def _m4_document_failure(code: M6SQLiteM4ModelDocumentFailureCode) -> _FailureCode:
    direct = {
        M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6SQLiteM4ModelDocumentFailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6SQLiteM4ModelDocumentFailureCode.CASE_BINDING_MISMATCH: (
            _FailureCode.CASE_BINDING_MISMATCH
        ),
        M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH: (
            _FailureCode.MODEL_CALL_CLOSURE_MISMATCH
        ),
        M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6SQLiteM4ModelDocumentFailureCode.TRANSACTION_REQUIRED: (_FailureCode.SNAPSHOT_REJECTED),
        M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED: (_FailureCode.SNAPSHOT_REJECTED),
    }
    return direct.get(code, _FailureCode.STORED_AUTHORITY_INVALID)


def _m4_physical_failure(code: M6M4ModelPhysicalResolutionErrorCode) -> _FailureCode:
    if code == M6M4ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code in {
        M6M4ModelPhysicalResolutionErrorCode.AUTHORITY_ASSEMBLY_FAILED,
        M6M4ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID,
        M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_REF_INVALID,
    }:
        return _FailureCode.STORED_AUTHORITY_INVALID
    if code in {
        M6M4ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH,
        M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID,
        M6M4ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID,
    }:
        return _FailureCode.MODEL_CALL_CLOSURE_MISMATCH
    if code == M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_BUDGET_EXCEEDED:
        return _FailureCode.DOCUMENT_TOO_LARGE
    return _FailureCode.PHYSICAL_ARTIFACT_REJECTED


def _m5_document_failure(code: M6SQLiteM5PrecedentPlanFailureCode) -> _FailureCode:
    direct = {
        M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6SQLiteM5PrecedentPlanFailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH: (
            _FailureCode.OBSERVATION_CLOSURE_MISMATCH
        ),
        M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_BUDGET_EXCEEDED: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_BUDGET_EXCEEDED: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6SQLiteM5PrecedentPlanFailureCode.TRANSACTION_REQUIRED: (_FailureCode.SNAPSHOT_REJECTED),
        M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED: (_FailureCode.SNAPSHOT_REJECTED),
    }
    return direct.get(code, _FailureCode.STORED_AUTHORITY_INVALID)


def _gate_current_source_failure(code: M6SQLiteGateCurrentSourceFailureCode) -> _FailureCode:
    direct = {
        M6SQLiteGateCurrentSourceFailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6SQLiteGateCurrentSourceFailureCode.TRANSACTION_REQUIRED: (_FailureCode.SNAPSHOT_REJECTED),
        M6SQLiteGateCurrentSourceFailureCode.SCOPE_MISMATCH: (_FailureCode.CASE_BINDING_MISMATCH),
        M6SQLiteGateCurrentSourceFailureCode.AUDIT_HEAD_MISMATCH: (_FailureCode.RUN_CUT_MISMATCH),
        M6SQLiteGateCurrentSourceFailureCode.REVIEW_PACK_COVERAGE_MISMATCH: (
            _FailureCode.INVENTORY_CLOSURE_MISMATCH
        ),
        M6SQLiteGateCurrentSourceFailureCode.PACK_AUTHORITY_MISMATCH: (
            _FailureCode.INVENTORY_CLOSURE_MISMATCH
        ),
        M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH: (
            _FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_INVALID: (
            _FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6SQLiteGateCurrentSourceFailureCode.CURRENT_MEDIA_VERIFICATION_FAILED: (
            _FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6SQLiteGateCurrentSourceFailureCode.SEALING_REJECTED: (
            _FailureCode.INVENTORY_CLOSURE_MISMATCH
        ),
        M6SQLiteGateCurrentSourceFailureCode.DATABASE_REJECTED: (_FailureCode.SNAPSHOT_REJECTED),
    }
    return direct.get(code, _FailureCode.STORED_AUTHORITY_INVALID)


def _model_closure_projection(
    value: M6PlannedModelCallPhysicalClosure | M6ObservedModelCallPhysicalClosure,
) -> tuple[object, ...]:
    return (
        value.source_identity_sha256,
        value.run_id,
        value.case_id,
        value.manifest_id,
        value.layer,
        value.role,
        value.attempt_index,
        value.timeout_ms,
        value.execution_model_manifest_id,
        value.request_ref,
        value.result_kind,
        value.response_ref,
        value.cache_ref,
        value.parse_receipt_ref,
        value.parsed_output_ref,
        value.failure_ref,
        value.usage_receipt_ref,
    )


def _require_exact_model_closures(
    plan: M6M3ModelPhysicalPlan | M6M4ModelPhysicalPlan,
    observed: tuple[M6ObservedModelCallPhysicalClosure, ...],
) -> None:
    if type(observed) is not tuple or any(
        type(item) is not M6ObservedModelCallPhysicalClosure for item in observed
    ):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    if tuple(_model_closure_projection(item) for item in observed) != tuple(
        _model_closure_projection(item) for item in plan.planned_calls
    ):
        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)


@dataclass(frozen=True, slots=True)
class _TerminalMetadataPlan:
    observation: M6UpgradeSampleExecutionObservationAuthorityV2
    record: M6UpgradeSampleExecutionRecordV2
    selected_case: M6SQLiteCaseAuthorityDocument | None
    planned_refs: tuple[M6UpgradePhysicalArtifactRef, ...]
    frame_plans: tuple[M6SQLiteFramePhysicalPlan, ...]
    evidence_pack_plans: tuple[M6SQLiteEvidencePackPhysicalPlan, ...]
    m3_documents_plan: M6SQLiteM3ModelDocumentsPlan | None
    m4_documents_plan: M6SQLiteM4ModelDocumentsPlan | None
    m5_precedent_documents_plan: M6SQLiteM5PrecedentDocumentsPlan | None
    m4_gate_documents_plan: M6SQLiteM4GateDocumentsPlan | None


@dataclass(frozen=True, slots=True)
class _TerminalResolvedPlan:
    metadata: _TerminalMetadataPlan
    perception: M6ResolvedPerception
    snapshot: M6CaseReplaySnapshot | None
    m3_snapshot: M6M3ModelCallAuthoritySnapshot | None
    m3_physical_plan: M6M3ModelPhysicalPlan | None
    m4_snapshot: M6M4ModelCallAuthoritySnapshot | None
    m4_physical_plan: M6M4ModelPhysicalPlan | None
    m5_precedent_snapshot: M6SQLiteM5PrecedentAuthoritySnapshot | None
    m4_gate_snapshot: M6SQLiteM4GateAuthoritySnapshot | None
    gate_history_snapshot: M6ProceduralGateHistorySnapshot | None
    historical_snapshots: M6ValidatedHistoricalRetrievalSnapshots | None
    resolved_evidence_packs: tuple[M6SQLiteCanonicalPhysicalDocument, ...]
    verified_evidence_pack_refs: tuple[M6UpgradePhysicalArtifactRef, ...]


class SQLiteM6UpgradeCandidateOutputBuilderV3(SQLiteM6UpgradeWholeSampleRecordBuilderV3):
    """Build one terminal V3 inventory through the first atomic M4/Gate slice."""

    __slots__ = ("_current_crop_verifier",)

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        *,
        pixel_provider: PixelFrameProvider,
        m3_raw_response_verifier: RawModelResponseVerifier,
        m4_raw_response_verifier: HearingRawModelResponseVerifier,
        current_crop_verifier: EvidenceVerifier | None = None,
    ) -> None:
        super().__init__(
            database_path,
            busy_timeout_ms,
            pixel_provider=pixel_provider,
            m3_raw_response_verifier=m3_raw_response_verifier,
            m4_raw_response_verifier=m4_raw_response_verifier,
        )
        if current_crop_verifier is not None and not callable(
            getattr(current_crop_verifier, "verify_crop", None)
        ):
            raise TypeError("current_crop_verifier must provide verify_crop")
        self._current_crop_verifier = current_crop_verifier

    @staticmethod
    def _require_open_state(state: M6SQLiteUpgradeV3State) -> None:
        if state.seal is None:
            _fail(_FailureCode.LEDGER_NOT_SEALED)
        for observation, record in zip(
            state.observations,
            state.records,
            strict=True,
        ):
            authority = observation.authority
            if authority.outcome not in {
                M6ReplayExecutionOutcome.NO_CASE,
                M6ReplayExecutionOutcome.CASE_REPLAYED,
            }:
                _fail(_FailureCode.CASE_BINDING_MISMATCH)
            if (
                record.outcome != authority.outcome
                or record.candidate_case != authority.candidate_case
                or (authority.candidate_case is None)
                != (authority.selected_case_audit_anchor is None)
            ):
                _fail(_FailureCode.CASE_BINDING_MISMATCH)
            screening_calls = tuple(
                item
                for item in authority.model_calls
                if item.layer == M6LockedModelCallLayer.SCREENING
            )
            hearing_calls = tuple(
                item
                for item in authority.model_calls
                if item.layer == M6LockedModelCallLayer.HEARING
            )
            if tuple(
                sorted((*screening_calls, *hearing_calls), key=lambda item: item.sort_key)
            ) != (authority.model_calls) or any(
                item.role != M6LockedModelRole.SCREENING for item in screening_calls
            ):
                _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
            if hearing_calls and (
                len(screening_calls) != 1
                or len(hearing_calls) != 3
                or {(item.layer, item.role) for item in authority.model_calls}
                != {
                    (M6LockedModelCallLayer.SCREENING, M6LockedModelRole.SCREENING),
                    (M6LockedModelCallLayer.HEARING, M6LockedModelRole.PROSECUTOR),
                    (M6LockedModelCallLayer.HEARING, M6LockedModelRole.DEFENDER),
                    (M6LockedModelCallLayer.HEARING, M6LockedModelRole.JUDGE),
                }
                or any(
                    item.attempt_index != 0
                    or item.result_kind != M6LockedModelCallResultKind.RESPONSE
                    for item in authority.model_calls
                )
            ):
                _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
            if authority.outcome == M6ReplayExecutionOutcome.NO_CASE and authority.model_calls:
                _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
            if any(
                (item.source, item.kind) not in _SCREENING_ROUTES for item in authority.artifacts
            ):
                _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
            if authority.outcome == M6ReplayExecutionOutcome.NO_CASE and any(
                (item.source, item.kind) not in _BASE_ROUTES for item in authority.artifacts
            ):
                _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)

    @staticmethod
    def _selected_case_authority(
        reader: M6LiveReader,
        state: M6SQLiteUpgradeV3State,
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    ) -> M6SQLiteCaseAuthorityDocument | None:
        if observation.outcome == M6ReplayExecutionOutcome.NO_CASE:
            return None
        binding = observation.candidate_case
        anchor = observation.selected_case_audit_anchor
        if binding is None or anchor is None:
            _fail(_FailureCode.CASE_BINDING_MISMATCH)
        scope = state.stored_scope.authority
        return read_m6_sqlite_case_authority_v3(
            connection=reader,
            expected_run_id=scope.candidate_run_id,
            expected_manifest_id=scope.candidate_manifest.manifest_id,
            expected_manifest_rule_version=scope.candidate_manifest.rule_version,
            candidate_case_binding=binding,
            selected_case_audit_anchor=anchor,
        )

    @staticmethod
    def _resolved_perception(
        reader: M6LiveReader,
        state: M6SQLiteUpgradeV3State,
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
        frame_plans: tuple[M6SQLiteFramePhysicalPlan, ...],
    ) -> M6ResolvedPerception:
        frames: list[FrameRef] = []
        for plan in frame_plans:
            try:
                frame = FrameRef.model_validate_json(plan.frame_authority.canonical_document)
            except (TypeError, ValueError):
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            if (
                frame.frame_id != plan.frame_authority.frame_id
                or canonical_json(frame.model_dump(mode="json"))
                != plan.frame_authority.canonical_document
            ):
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            frames.append(frame)
        scope = state.stored_scope.authority
        detections: list[Detection] = []
        for identity in observation.artifacts:
            if identity.kind != M6UpgradePhysicalArtifactKind.DETECTION:
                continue
            resolved = resolve_m6_sqlite_canonical_physical_identity(
                connection=reader,
                source=identity.source,
                kind=identity.kind,
                artifact_id=identity.artifact_id,
                expected_run_id=scope.candidate_run_id,
                expected_manifest_id=scope.candidate_manifest.manifest_id,
            )
            if type(resolved.document) is not Detection:
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            detections.append(resolved.document)
        try:
            return M6ResolvedPerception(
                frames=tuple(sorted(frames, key=lambda item: parse_frame_id(item.frame_id))),
                detections=tuple(
                    sorted(
                        detections,
                        key=lambda item: (
                            parse_frame_id(item.frame_id),
                            item.detection_id,
                        ),
                    )
                ),
            )
        except (TypeError, ValueError):
            _fail(_FailureCode.OBSERVATION_CLOSURE_MISMATCH)

    @staticmethod
    def _resolved_evidence_packs(
        reader: M6LiveReader,
        plans: tuple[M6SQLiteEvidencePackPhysicalPlan, ...],
    ) -> tuple[M6SQLiteCanonicalPhysicalDocument, ...]:
        resolved: list[M6SQLiteCanonicalPhysicalDocument] = []
        for plan in sorted(plans, key=lambda item: item.planned_artifact_ref.physical_key):
            document = resolve_m6_sqlite_evidence_pack_physical_plan(
                connection=reader,
                physical_plan=plan,
            )
            if document.artifact_ref != plan.planned_artifact_ref:
                _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)
            resolved.append(document)
        return tuple(resolved)

    def _seal_current_gate_source(
        self,
        *,
        reader: M6LiveReader,
        selected_case: M6SQLiteCaseAuthorityDocument,
        evidence_pack_plans: tuple[M6SQLiteEvidencePackPhysicalPlan, ...],
        resolved_evidence_packs: tuple[M6SQLiteCanonicalPhysicalDocument, ...],
        run_cut: M6UpgradeCandidateRunCutAuthority,
    ) -> M6SealedGateSource:
        verifier = self._current_crop_verifier
        if verifier is None:
            _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)
        return seal_m6_sqlite_gate_current_source(
            connection=reader,
            selected_case_authority=selected_case,
            evidence_pack_plans=evidence_pack_plans,
            resolved_evidence_packs=resolved_evidence_packs,
            expected_audit_head_sequence=run_cut.audit_head_sequence,
            expected_audit_head_hash=run_cut.audit_head_hash,
            crop_verifier=verifier,
        )

    def _build_from_terminal_cut(
        self,
        run_id: str,
        scope_id: str,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        inventory: M6UpgradeCandidateOutputInventoryAuthorityV3 | None = None
        with m6_live_committed_read_cut(
            self._database,
            self._busy_timeout_ms,
        ) as cut:
            with cut.selector() as selector:
                _select_terminal_v3(selector, run_id, scope_id)
            with cut.reader() as reader:
                state = load_m6_upgrade_v3_state_from_connection(
                    self._state_repository_v3,
                    reader,
                    run_id,
                    scope_id,
                )
                self._require_open_state(state)
                seal = state.seal
                if seal is None:
                    _fail(_FailureCode.LEDGER_NOT_SEALED)
                run_cut = load_m6_upgrade_candidate_run_cut_from_connection(
                    connection=reader,
                    state=state,
                )

                # Phase 1: freeze every sample's metadata and exact Record
                # closure before reading any independent canonical body, Raw
                # response, or Pixel bytes.
                metadata_plans: list[_TerminalMetadataPlan] = []
                for observation, record in zip(
                    state.observations,
                    state.records,
                    strict=True,
                ):
                    selected_case = self._selected_case_authority(
                        reader,
                        state,
                        observation.authority,
                    )
                    planned_refs, frame_plans, evidence_pack_plans = self._plan_v3_artifacts(
                        reader,
                        state,
                        observation.authority,
                        selected_case,
                    )
                    m3_observations = tuple(
                        item
                        for item in observation.authority.model_calls
                        if item.layer == M6LockedModelCallLayer.SCREENING
                    )
                    m4_observations = tuple(
                        item
                        for item in observation.authority.model_calls
                        if item.layer == M6LockedModelCallLayer.HEARING
                    )
                    m3_documents_plan = (
                        self._plan_v3_m3_documents(
                            reader,
                            state,
                            m3_observations,
                            selected_case,
                        )
                        if m3_observations and selected_case is not None
                        else None
                    )
                    m4_documents_plan = (
                        self._plan_v3_m4_documents(
                            reader,
                            state,
                            m4_observations,
                            selected_case,
                        )
                        if m4_observations and selected_case is not None
                        else None
                    )
                    if (m3_observations and m3_documents_plan is None) or (
                        m4_observations and m4_documents_plan is None
                    ):
                        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
                    if (
                        m3_documents_plan is not None
                        and m3_documents_plan.observed_model_calls != m3_observations
                    ):
                        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
                    if (
                        m4_documents_plan is not None
                        and m4_documents_plan.observed_model_calls != m4_observations
                    ):
                        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
                    m5_precedent_documents_plan = (
                        self._plan_v3_m5_precedent_documents(
                            reader,
                            state,
                            (),
                            selected_case,
                            m4_documents_plan,
                        )
                        if m4_documents_plan is not None and selected_case is not None
                        else None
                    )
                    m4_gate_documents_plan = (
                        plan_m6_sqlite_m4_gate_documents(
                            connection=reader,
                            upstream_m4_model_plan=m4_documents_plan,
                        )
                        if m4_documents_plan is not None
                        else None
                    )
                    if m4_documents_plan is not None and (
                        m5_precedent_documents_plan is None
                        or m4_gate_documents_plan is None
                        or self._current_crop_verifier is None
                    ):
                        _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)
                    self._require_v3_combined_preflight(
                        planned_refs,
                        m3_documents_plan,
                        m4_documents_plan,
                        None,
                        m5_precedent_documents_plan,
                    )
                    ordered_planned_refs = tuple(
                        sorted(
                            (
                                *planned_refs,
                                *(
                                    m3_documents_plan.planned_artifact_refs
                                    if m3_documents_plan is not None
                                    else ()
                                ),
                                *(
                                    m4_documents_plan.planned_artifact_refs
                                    if m4_documents_plan is not None
                                    else ()
                                ),
                                *(
                                    m5_precedent_documents_plan.planned_artifact_refs
                                    if m5_precedent_documents_plan is not None
                                    else ()
                                ),
                            ),
                            key=lambda item: item.physical_key,
                        )
                    )
                    record_refs = tuple(link.artifact for link in record.artifact_links)
                    if ordered_planned_refs != record_refs:
                        _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)
                    metadata_plans.append(
                        _TerminalMetadataPlan(
                            observation=observation.authority,
                            record=record,
                            selected_case=selected_case,
                            planned_refs=ordered_planned_refs,
                            frame_plans=frame_plans,
                            evidence_pack_plans=evidence_pack_plans,
                            m3_documents_plan=m3_documents_plan,
                            m4_documents_plan=m4_documents_plan,
                            m5_precedent_documents_plan=m5_precedent_documents_plan,
                            m4_gate_documents_plan=m4_gate_documents_plan,
                        )
                    )

                # Phase 2: resolve every same-snapshot canonical body and build
                # semantic snapshots. No external Raw or Pixel provider is
                # admitted until every sample completes this phase.
                resolved_plans: list[_TerminalResolvedPlan] = []
                for metadata in metadata_plans:
                    perception = self._resolved_perception(
                        reader,
                        state,
                        metadata.observation,
                        metadata.frame_plans,
                    )
                    resolved_evidence_packs = self._resolved_evidence_packs(
                        reader,
                        metadata.evidence_pack_plans,
                    )
                    verified_evidence_pack_refs = tuple(
                        item.artifact_ref for item in resolved_evidence_packs
                    )
                    m3_snapshot: M6M3ModelCallAuthoritySnapshot | None = None
                    m3_physical_plan: M6M3ModelPhysicalPlan | None = None
                    if metadata.m3_documents_plan is not None:
                        if metadata.selected_case is None:
                            _fail(_FailureCode.CASE_BINDING_MISMATCH)
                        m3_snapshot = resolve_m6_sqlite_m3_model_documents(
                            connection=reader,
                            metadata_plan=metadata.m3_documents_plan,
                        )
                        m3_physical_plan = plan_m6_m3_observed_model_call_closures(
                            source_case=metadata.selected_case.case,
                            snapshot=m3_snapshot,
                        )
                        if (
                            m3_physical_plan.source_identity_sha256
                            != metadata.m3_documents_plan.plan_identity_sha256
                            or m3_physical_plan.planned_refs
                            != metadata.m3_documents_plan.planned_artifact_refs
                        ):
                            _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)

                    m4_snapshot: M6M4ModelCallAuthoritySnapshot | None = None
                    m4_physical_plan: M6M4ModelPhysicalPlan | None = None
                    if metadata.m4_documents_plan is not None:
                        if metadata.selected_case is None:
                            _fail(_FailureCode.CASE_BINDING_MISMATCH)
                        m4_snapshot = resolve_m6_sqlite_m4_model_documents(
                            connection=reader,
                            metadata_plan=metadata.m4_documents_plan,
                        )
                        m4_physical_plan = plan_m6_m4_observed_model_call_closures(
                            source_case=metadata.selected_case.case,
                            snapshot=m4_snapshot,
                        )
                        if (
                            m4_physical_plan.source_identity_sha256
                            != metadata.m4_documents_plan.plan_identity_sha256
                            or m4_physical_plan.planned_refs
                            != metadata.m4_documents_plan.planned_artifact_refs
                        ):
                            _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)

                    m5_precedent_snapshot: M6SQLiteM5PrecedentAuthoritySnapshot | None = None
                    m4_gate_snapshot: M6SQLiteM4GateAuthoritySnapshot | None = None
                    gate_history_snapshot: M6ProceduralGateHistorySnapshot | None = None
                    historical_snapshots: M6ValidatedHistoricalRetrievalSnapshots | None = None
                    if metadata.m4_documents_plan is not None:
                        if (
                            metadata.selected_case is None
                            or m4_snapshot is None
                            or metadata.m5_precedent_documents_plan is None
                            or metadata.m4_gate_documents_plan is None
                        ):
                            _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
                        m5_precedent_snapshot = resolve_m6_sqlite_m5_precedent_documents(
                            connection=reader,
                            metadata_plan=metadata.m5_precedent_documents_plan,
                            selected_case=metadata.selected_case.case,
                            config=state.stored_scope.authority.candidate_config,
                            manifest=state.stored_scope.authority.candidate_manifest,
                            upstream_m4_model_plan=metadata.m4_documents_plan,
                        )
                        m4_gate_snapshot = resolve_m6_sqlite_m4_gate_documents(
                            connection=reader,
                            metadata_plan=metadata.m4_gate_documents_plan,
                            upstream_m4_model_snapshot=m4_snapshot,
                        )
                        m4_report = run_cut.validation_report.predecessor_report
                        if (
                            not isinstance(m4_report, M4ArtifactValidationReport)
                            or m4_report.authority_root_sha256 is None
                        ):
                            _fail(_FailureCode.RUN_CUT_MISMATCH)
                        gate_history_snapshot = assemble_m6_sqlite_m4_gate_history_snapshot(
                            gate_snapshot=m4_gate_snapshot,
                            upstream_m4_model_snapshot=m4_snapshot,
                            source_m4_authority_root_sha256=m4_report.authority_root_sha256,
                        )
                        historical_snapshots = assemble_m6_sqlite_historical_retrieval_snapshots(
                            gate_history_snapshot=gate_history_snapshot,
                            m5_precedent_snapshot=m5_precedent_snapshot,
                            expected_upstream_m4_plan_identity_sha256=(
                                metadata.m4_documents_plan.plan_identity_sha256
                            ),
                        )

                    if metadata.selected_case is None or m4_snapshot is not None:
                        snapshot = None
                    elif m3_snapshot is not None and m3_physical_plan is not None:
                        snapshot = build_m6_upgrade_screening_candidate_case_snapshot(
                            execution_ledger=seal,
                            run_cut=run_cut,
                            observation=metadata.observation,
                            sample_record=metadata.record,
                            selected_case=metadata.selected_case.case,
                            perception=perception,
                            m3_snapshot=m3_snapshot,
                            m3_physical_plan=m3_physical_plan,
                        )
                    else:
                        snapshot = build_m6_upgrade_base_candidate_case_snapshot(
                            execution_ledger=seal,
                            run_cut=run_cut,
                            observation=metadata.observation,
                            sample_record=metadata.record,
                            selected_case=metadata.selected_case.case,
                            perception=perception,
                        )
                    resolved_plans.append(
                        _TerminalResolvedPlan(
                            metadata=metadata,
                            perception=perception,
                            snapshot=snapshot,
                            m3_snapshot=m3_snapshot,
                            m3_physical_plan=m3_physical_plan,
                            m4_snapshot=m4_snapshot,
                            m4_physical_plan=m4_physical_plan,
                            m5_precedent_snapshot=m5_precedent_snapshot,
                            m4_gate_snapshot=m4_gate_snapshot,
                            gate_history_snapshot=gate_history_snapshot,
                            historical_snapshots=historical_snapshots,
                            resolved_evidence_packs=resolved_evidence_packs,
                            verified_evidence_pack_refs=verified_evidence_pack_refs,
                        )
                    )

                # Phase 3: verify every M3 Raw response before any Pixel read.
                m3_model_call_closures: list[tuple[M6ObservedModelCallPhysicalClosure, ...]] = []
                for resolved in resolved_plans:
                    if resolved.m3_physical_plan is None:
                        m3_model_call_closures.append(())
                        continue
                    if resolved.m3_snapshot is None or resolved.metadata.selected_case is None:
                        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
                    observed_calls = resolve_m6_m3_observed_model_call_physical_plan(
                        source_case=resolved.metadata.selected_case.case,
                        snapshot=resolved.m3_snapshot,
                        plan=resolved.m3_physical_plan,
                        raw_response_verifier=self._m3_raw_response_verifier,
                    )
                    _require_exact_model_closures(
                        resolved.m3_physical_plan,
                        observed_calls,
                    )
                    m3_model_call_closures.append(observed_calls)

                # Phase 4: every M4 Raw response follows the complete global
                # M3 Raw phase and still precedes current Crop verification.
                m4_model_call_closures: list[tuple[M6ObservedModelCallPhysicalClosure, ...]] = []
                for resolved in resolved_plans:
                    if resolved.m4_physical_plan is None:
                        m4_model_call_closures.append(())
                        continue
                    if resolved.m4_snapshot is None or resolved.metadata.selected_case is None:
                        _fail(_FailureCode.MODEL_CALL_CLOSURE_MISMATCH)
                    observed_calls = resolve_m6_m4_observed_model_call_physical_plan(
                        source_case=resolved.metadata.selected_case.case,
                        snapshot=resolved.m4_snapshot,
                        plan=resolved.m4_physical_plan,
                        raw_response_verifier=self._m4_raw_response_verifier,
                    )
                    _require_exact_model_closures(
                        resolved.m4_physical_plan,
                        observed_calls,
                    )
                    m4_model_call_closures.append(observed_calls)

                model_call_closures = [
                    tuple(sorted((*m3_calls, *m4_calls), key=lambda item: item.sort_key))
                    for m3_calls, m4_calls in zip(
                        m3_model_call_closures,
                        m4_model_call_closures,
                        strict=True,
                    )
                ]

                # Phase 5: terminal Gate receipts reverify the current Crop
                # media only after every model Raw response has closed.
                candidate_snapshots: list[M6CaseReplaySnapshot | None] = [
                    item.snapshot for item in resolved_plans
                ]
                for index, resolved in enumerate(resolved_plans):
                    if resolved.m4_physical_plan is None:
                        continue
                    metadata = resolved.metadata
                    if (
                        metadata.selected_case is None
                        or resolved.m3_snapshot is None
                        or resolved.m3_physical_plan is None
                        or resolved.m4_snapshot is None
                        or resolved.gate_history_snapshot is None
                        or resolved.historical_snapshots is None
                        or self._current_crop_verifier is None
                    ):
                        _fail(_FailureCode.INVENTORY_CLOSURE_MISMATCH)
                    gate_source = self._seal_current_gate_source(
                        reader=reader,
                        selected_case=metadata.selected_case,
                        evidence_pack_plans=metadata.evidence_pack_plans,
                        resolved_evidence_packs=resolved.resolved_evidence_packs,
                        run_cut=run_cut,
                    )
                    candidate_snapshots[index] = build_m6_upgrade_hearing_candidate_case_snapshot(
                        execution_ledger=seal,
                        run_cut=run_cut,
                        observation=metadata.observation,
                        sample_record=metadata.record,
                        selected_case=metadata.selected_case.case,
                        perception=resolved.perception,
                        m3_snapshot=resolved.m3_snapshot,
                        m3_physical_plan=resolved.m3_physical_plan,
                        m4_snapshot=resolved.m4_snapshot,
                        m4_physical_plan=resolved.m4_physical_plan,
                        gate_source=gate_source,
                        gate_history_snapshot=resolved.gate_history_snapshot,
                        historical_snapshots=resolved.historical_snapshots,
                    )

                # Phase 6: Pixel is the final external authority read. Every
                # metadata/body/Raw/Crop failure above therefore leaks no Pixel.
                for resolved, closures in zip(
                    resolved_plans,
                    model_call_closures,
                    strict=True,
                ):
                    metadata = resolved.metadata
                    verified_frames = self._verify_frame_plans(run_id, metadata.frame_plans)
                    verified_by_identity = {
                        (item.source, item.kind, item.artifact_id): item
                        for item in (
                            *verified_frames,
                            *resolved.verified_evidence_pack_refs,
                            *(ref for closure in closures for ref in closure.artifact_refs),
                        )
                    }
                    verified_refs = tuple(
                        verified_by_identity.get(
                            (item.source, item.kind, item.artifact_id),
                            item,
                        )
                        for item in metadata.planned_refs
                    )
                    record_refs = tuple(link.artifact for link in metadata.record.artifact_links)
                    if verified_refs != record_refs:
                        _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)

                inventory = build_m6_upgrade_candidate_output_inventory(
                    execution_scope=state.stored_scope.authority,
                    execution_ledger=seal,
                    run_cut=run_cut,
                    observations=tuple(item.authority for item in state.observations),
                    candidate_snapshots=tuple(candidate_snapshots),
                    model_call_closures=tuple(model_call_closures),
                )
            with cut.writer():
                pass
        if inventory is None:
            _fail(_FailureCode.SNAPSHOT_REJECTED)
        return inventory

    def _attempt_build_terminal_inventory(
        self,
        candidate_run_id: object,
        execution_scope_authority_id: object,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        run_id, scope_id = _public_identity(
            candidate_run_id,
            execution_scope_authority_id,
        )
        try:
            return self._build_from_terminal_cut(run_id, scope_id)
        except M6UpgradeCandidateOutputError:
            raise
        except M6UpgradeCandidateRunCutError as exc:
            _fail(_run_cut_failure(exc.reason_code))
        except M6UpgradeExecutionLedgerV3Error as exc:
            _fail(_state_failure(exc.reason_code))
        except M6UpgradeWholeSampleRecordBuilderError as exc:
            _fail(_record_builder_failure(exc.reason_code))
        except M6SQLiteCaseDocumentError as exc:
            _fail(_case_document_failure(exc.reason_code))
        except M6SQLiteFrameDocumentError as exc:
            _fail(_frame_document_failure(exc.reason_code))
        except M6SQLiteEvidencePackDocumentError as exc:
            _fail(_evidence_pack_document_failure(exc.reason_code))
        except M6SQLiteM3ModelDocumentError as exc:
            _fail(_m3_document_failure(exc.reason_code))
        except M6SQLiteM4ModelDocumentError as exc:
            _fail(_m4_document_failure(exc.reason_code))
        except M6SQLiteM5PrecedentDocumentError as exc:
            _fail(_m5_document_failure(exc.reason_code))
        except M6SQLiteGateCurrentSourceError as exc:
            _fail(_gate_current_source_failure(exc.reason_code))
        except M6SQLitePhysicalDocumentError as exc:
            _fail(_physical_document_failure(exc.reason_code))
        except M6M3ModelPhysicalResolutionError as exc:
            _fail(_m3_physical_failure(exc.code))
        except M6M4ModelPhysicalResolutionError as exc:
            _fail(_m4_physical_failure(exc.code))
        except M6UpgradePhysicalResolutionError:
            _fail(_FailureCode.PHYSICAL_ARTIFACT_REJECTED)
        except M6LiveReadCutError:
            _fail(_FailureCode.SNAPSHOT_REJECTED)
        except sqlite3.DatabaseError:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        except OSError:
            _fail(_FailureCode.STORAGE_REJECTED)

    def build_terminal_inventory(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        """Build through a fresh payload-free public failure boundary."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_build_terminal_inventory(
                candidate_run_id,
                execution_scope_authority_id,
            )
        except M6UpgradeCandidateOutputError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, candidate_run_id, execution_scope_authority_id
        raise _error(failure) from None


__all__ = ["SQLiteM6UpgradeCandidateOutputBuilderV3"]
