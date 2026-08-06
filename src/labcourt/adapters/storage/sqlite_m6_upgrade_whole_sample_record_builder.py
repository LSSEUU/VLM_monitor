"""SQLite implementations of the exact M6 V2/V3 whole-sample builders.

V3 opens Frame, Detection, EvidencePack, M3 screening calls, M4 hearing calls,
completed M4 acquisition closures, and M5 precedent exposure/embedding
closures through one metadata-first pending comparison.  Later
execution/output joins remain closed until their authority families are
implemented in milestone order.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

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
    resolve_m6_upgrade_frame_physical_ref,
)
from labcourt.application.m6_upgrade_whole_sample_record import (
    M6MetadataModelCallArtifactPlan,
    build_m6_upgrade_case_replayed_acquisition_record_v3,
    build_m6_upgrade_case_replayed_base_record,
    build_m6_upgrade_case_replayed_base_record_v3,
    build_m6_upgrade_case_replayed_evidence_pack_record_v3,
    build_m6_upgrade_case_replayed_metadata_acquisition_record_v3,
    build_m6_upgrade_case_replayed_metadata_model_record_v3,
    build_m6_upgrade_case_replayed_metadata_precedent_record_v3,
    build_m6_upgrade_case_replayed_model_record_v3,
    build_m6_upgrade_case_replayed_precedent_record_v3,
    build_m6_upgrade_no_case_record,
    build_m6_upgrade_no_case_record_v3,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    M6UpgradeCandidateCaseBinding,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeObservedModelCall,
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token
from labcourt.ports.hearing_vlm import HearingRawModelResponseVerifier
from labcourt.ports.m6_model_calls import (
    M6M3ModelCallAuthoritySnapshot,
    M6M4ModelCallAuthoritySnapshot,
)
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
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
    M6LiveReadCutError,
    M6LiveReader,
    m6_live_committed_read_cut,
)
from ._sqlite_m6_upgrade_acquisition_documents import (
    M6SQLiteAcquisitionDocumentError,
    M6SQLiteAcquisitionDocumentsPlan,
    M6SQLiteAcquisitionPlanFailureCode,
    plan_m6_sqlite_acquisition_documents,
    resolve_m6_sqlite_acquisition_documents,
)
from ._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseAuthorityDocument,
    M6SQLiteCaseDocumentError,
    M6SQLiteCaseDocumentFailureCode,
    read_m6_sqlite_case_authority,
    read_m6_sqlite_case_authority_v3,
)
from ._sqlite_m6_upgrade_evidence_pack_document import (
    M6SQLiteEvidencePackDocumentError,
    M6SQLiteEvidencePackDocumentFailureCode,
    M6SQLiteEvidencePackPhysicalPlan,
    plan_m6_sqlite_evidence_pack_physical_identity,
    resolve_m6_sqlite_evidence_pack_physical_plan,
)
from ._sqlite_m6_upgrade_frame_document import (
    M6SQLiteFrameDocumentError,
    M6SQLiteFrameDocumentFailureCode,
    M6SQLiteFramePhysicalPlan,
    plan_m6_sqlite_frame_physical_identity,
)
from ._sqlite_m6_upgrade_m3_model_documents import (
    M6SQLiteM3ModelDocumentError,
    M6SQLiteM3ModelDocumentFailureCode,
    M6SQLiteM3ModelDocumentsPlan,
    plan_m6_sqlite_m3_model_documents,
    resolve_m6_sqlite_m3_model_documents,
)
from ._sqlite_m6_upgrade_m4_model_documents import (
    M6SQLiteM4ModelDocumentError,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4ModelDocumentsPlan,
    M6SQLiteM4RoleModelManifestBinding,
    plan_m6_sqlite_m4_model_documents,
    resolve_m6_sqlite_m4_model_documents,
)
from ._sqlite_m6_upgrade_m5_precedent_metadata import (
    M6SQLiteM5PrecedentDocumentError,
    plan_m6_sqlite_m5_precedent_documents,
    resolve_m6_sqlite_m5_precedent_documents,
)
from ._sqlite_m6_upgrade_m5_precedent_plan import (
    M6SQLiteM5PrecedentDocumentsPlan,
    M6SQLiteM5PrecedentPlanFailureCode,
)
from ._sqlite_m6_upgrade_physical_documents import (
    M6SQLitePhysicalDocumentError,
    M6SQLitePhysicalDocumentFailureCode,
    resolve_m6_sqlite_canonical_physical_identity,
)
from ._sqlite_m6_upgrade_v2_pending_selection import (
    M6UpgradeV2PendingSelection,
    M6UpgradeV2PendingSelectionError,
    M6UpgradeV2PendingSelectionFailureCode,
    select_m6_upgrade_v2_pending,
    select_m6_upgrade_v3_pending,
)
from .sqlite_m6_upgrade_execution_ledger_v2 import (
    M6SQLiteUpgradeV2State,
    SQLiteM6UpgradeExecutionLedgerV2Repository,
    load_m6_upgrade_v2_state_from_connection,
)
from .sqlite_m6_upgrade_execution_ledger_v3 import (
    M6SQLiteUpgradeV3State,
    SQLiteM6UpgradeExecutionLedgerV3Repository,
    load_m6_upgrade_v3_state_from_connection,
)

_V3_ACQUISITION_ROUTES = frozenset(
    {
        (
            M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        ),
        (
            M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
            M6UpgradePhysicalArtifactKind.TOOL_RESULT,
        ),
    }
)
_V3_PRECEDENT_ROUTES = frozenset(
    {
        (
            M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            M6UpgradePhysicalArtifactKind.EMBEDDING,
        ),
        (
            M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
        ),
    }
)
_V3_DEFERRED_ARTIFACT_ROUTES = _V3_ACQUISITION_ROUTES | _V3_PRECEDENT_ROUTES
_V3_ORDINARY_ROUTES = frozenset(
    {
        (
            M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            M6UpgradePhysicalArtifactKind.FRAME,
        ),
        (
            M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            M6UpgradePhysicalArtifactKind.DETECTION,
        ),
        (
            M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
            M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
        ),
    }
)


def _fail(code: M6UpgradeWholeSampleRecordBuilderFailureCode) -> NoReturn:
    # This is a public trust boundary.  Lower adapters may carry database text,
    # provider payloads, or host paths in their exception chains, so the typed
    # public failure must suppress that diagnostic context as well as its message.
    raise M6UpgradeWholeSampleRecordBuilderError(code) from None


def _require_sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT)
    return value


def _public_identity(candidate_run_id: object, scope_id: object) -> tuple[str, str]:
    if not isinstance(candidate_run_id, str):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT)
    try:
        run_id = require_reference_token(candidate_run_id, "M6 builder candidate run_id")
    except (TypeError, ValueError, ValidationError):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT)
    return run_id, _require_sha256(scope_id)


def _selection_failure_code(
    error: M6UpgradeV2PendingSelectionError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    mapping = {
        M6UpgradeV2PendingSelectionFailureCode.INVALID_ARGUMENT: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeV2PendingSelectionFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeV2PendingSelectionFailureCode.SCOPE_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeV2PendingSelectionFailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.LEDGER_VERSION_UNSUPPORTED
        ),
        M6UpgradeV2PendingSelectionFailureCode.NO_PENDING_SAMPLE: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_NOT_FOUND
        ),
        M6UpgradeV2PendingSelectionFailureCode.STORED_AUTHORITY_INVALID: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeV2PendingSelectionFailureCode.CAPABILITY_REJECTED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
        M6UpgradeV2PendingSelectionFailureCode.STORAGE_REJECTED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
    }
    return mapping[error.reason_code]


def _translate_selection(error: M6UpgradeV2PendingSelectionError) -> NoReturn:
    _fail(_selection_failure_code(error))


def _state_failure_code(
    error: M6UpgradeExecutionLedgerV2Error,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    if error.reason_code == M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
    if error.reason_code == M6UpgradeExecutionLedgerV2FailureCode.SCOPE_NOT_FOUND:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND
    if error.reason_code == M6UpgradeExecutionLedgerV2FailureCode.SCOPE_MISMATCH:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
    if error.reason_code in {
        M6UpgradeExecutionLedgerV2FailureCode.LEGACY_LEDGER_UNSUPPORTED,
        M6UpgradeExecutionLedgerV2FailureCode.LEDGER_VERSION_UNSUPPORTED,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.LEDGER_VERSION_UNSUPPORTED
    if error.reason_code == M6UpgradeExecutionLedgerV2FailureCode.OBSERVATION_NOT_FOUND:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_NOT_FOUND
    if error.reason_code == M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
    if error.reason_code == M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
    return M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID


def _translate_state(error: M6UpgradeExecutionLedgerV2Error) -> NoReturn:
    _fail(_state_failure_code(error))


def _state_v3_failure_code(
    error: M6UpgradeExecutionLedgerV3Error,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    if error.reason_code == M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
    if error.reason_code == M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND
    if error.reason_code == M6UpgradeExecutionLedgerV3FailureCode.SCOPE_MISMATCH:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
    if error.reason_code in {
        M6UpgradeExecutionLedgerV3FailureCode.LEGACY_LEDGER_UNSUPPORTED,
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_VERSION_UNSUPPORTED,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.LEDGER_VERSION_UNSUPPORTED
    if error.reason_code == M6UpgradeExecutionLedgerV3FailureCode.OBSERVATION_NOT_FOUND:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_NOT_FOUND
    if error.reason_code == M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
    if error.reason_code == M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
    return M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID


def _frame_document_failure_code(
    error: M6SQLiteFrameDocumentError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    if error.reason_code == M6SQLiteFrameDocumentFailureCode.DOCUMENT_TOO_LARGE:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
    if error.reason_code == M6SQLiteFrameDocumentFailureCode.DOCUMENT_NOT_FOUND:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    if error.reason_code == M6SQLiteFrameDocumentFailureCode.TRANSACTION_REQUIRED:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
    if error.reason_code == M6SQLiteFrameDocumentFailureCode.DATABASE_REJECTED:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
    return M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID


def _translate_frame_document(error: M6SQLiteFrameDocumentError) -> NoReturn:
    _fail(_frame_document_failure_code(error))


def _case_document_failure_code(
    error: M6SQLiteCaseDocumentError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    if error.reason_code == M6SQLiteCaseDocumentFailureCode.DOCUMENT_TOO_LARGE:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
    if error.reason_code == M6SQLiteCaseDocumentFailureCode.SCOPE_NOT_FOUND:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND
    if error.reason_code == M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
    if error.reason_code in {
        M6SQLiteCaseDocumentFailureCode.TRANSACTION_REQUIRED,
        M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
    if error.reason_code in {
        M6SQLiteCaseDocumentFailureCode.DOCUMENT_NOT_FOUND,
        M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH,
        M6SQLiteCaseDocumentFailureCode.SELECTED_AUDIT_ANCHOR_MISMATCH,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
    return M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID


def _translate_case_document(error: M6SQLiteCaseDocumentError) -> NoReturn:
    _fail(_case_document_failure_code(error))


def _evidence_pack_document_failure_code(
    error: M6SQLiteEvidencePackDocumentError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    if error.reason_code == M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_TOO_LARGE:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
    if error.reason_code == M6SQLiteEvidencePackDocumentFailureCode.SCOPE_NOT_FOUND:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND
    if error.reason_code == M6SQLiteEvidencePackDocumentFailureCode.SCOPE_MISMATCH:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
    if error.reason_code in {
        M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_NOT_FOUND,
        M6SQLiteEvidencePackDocumentFailureCode.SELECTED_CASE_MEMBERSHIP_MISMATCH,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    if error.reason_code in {
        M6SQLiteEvidencePackDocumentFailureCode.TRANSACTION_REQUIRED,
        M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
    if error.reason_code == M6SQLiteEvidencePackDocumentFailureCode.INVALID_ARGUMENT:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
    return M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID


def _translate_evidence_pack_document(
    error: M6SQLiteEvidencePackDocumentError,
) -> NoReturn:
    _fail(_evidence_pack_document_failure_code(error))


def _m3_model_document_failure_code(
    error: M6SQLiteM3ModelDocumentError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    mapping = {
        M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
        ),
        M6SQLiteM3ModelDocumentFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND
        ),
        M6SQLiteM3ModelDocumentFailureCode.SCOPE_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
        ),
        M6SQLiteM3ModelDocumentFailureCode.CASE_BINDING_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
        ),
        M6SQLiteM3ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
        ),
        M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
        ),
        M6SQLiteM3ModelDocumentFailureCode.TRANSACTION_REQUIRED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
        M6SQLiteM3ModelDocumentFailureCode.DATABASE_REJECTED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
    }
    return mapping.get(
        error.reason_code,
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID,
    )


def _m3_physical_failure_code(
    error: M6M3ModelPhysicalResolutionError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    if error.code == M6M3ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
    if error.code in {
        M6M3ModelPhysicalResolutionErrorCode.AUTHORITY_ASSEMBLY_FAILED,
        M6M3ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID,
        M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_REF_INVALID,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    if error.code in {
        M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH,
        M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID,
        M6M3ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    if error.code == M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_BUDGET_EXCEEDED:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED
    return M6UpgradeWholeSampleRecordBuilderFailureCode.RAW_RESPONSE_REJECTED


def _m4_model_document_failure_code(
    error: M6SQLiteM4ModelDocumentError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    mapping = {
        M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
        ),
        M6SQLiteM4ModelDocumentFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND
        ),
        M6SQLiteM4ModelDocumentFailureCode.SCOPE_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
        ),
        M6SQLiteM4ModelDocumentFailureCode.CASE_BINDING_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
        ),
        M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
        ),
        M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
        ),
        M6SQLiteM4ModelDocumentFailureCode.TRANSACTION_REQUIRED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
        M6SQLiteM4ModelDocumentFailureCode.DATABASE_REJECTED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
    }
    return mapping.get(
        error.reason_code,
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID,
    )


def _m4_physical_failure_code(
    error: M6M4ModelPhysicalResolutionError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    if error.code == M6M4ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
    if error.code in {
        M6M4ModelPhysicalResolutionErrorCode.AUTHORITY_ASSEMBLY_FAILED,
        M6M4ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID,
        M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_REF_INVALID,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    if error.code in {
        M6M4ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH,
        M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID,
        M6M4ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID,
    }:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    if error.code == M6M4ModelPhysicalResolutionErrorCode.PHYSICAL_BUDGET_EXCEEDED:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED
    return M6UpgradeWholeSampleRecordBuilderFailureCode.RAW_RESPONSE_REJECTED


def _acquisition_document_failure_code(
    error: M6SQLiteAcquisitionDocumentError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    mapping = {
        M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
        ),
        M6SQLiteAcquisitionPlanFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND
        ),
        M6SQLiteAcquisitionPlanFailureCode.SCOPE_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
        ),
        M6SQLiteAcquisitionPlanFailureCode.CASE_BINDING_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
        ),
        M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
        ),
        M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
        ),
        M6SQLiteAcquisitionPlanFailureCode.SUPPORT_BUDGET_EXCEEDED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
        ),
        M6SQLiteAcquisitionPlanFailureCode.ROW_LIMIT_EXCEEDED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.LINK_LIMIT_EXCEEDED
        ),
        M6SQLiteAcquisitionPlanFailureCode.PHYSICAL_BUDGET_EXCEEDED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED
        ),
        M6SQLiteAcquisitionPlanFailureCode.TRANSACTION_REQUIRED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
        M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
    }
    return mapping.get(
        error.reason_code,
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID,
    )


def _m5_precedent_document_failure_code(
    error: M6SQLiteM5PrecedentDocumentError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    mapping = {
        M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
        ),
        M6SQLiteM5PrecedentPlanFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND
        ),
        M6SQLiteM5PrecedentPlanFailureCode.SCOPE_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
        ),
        M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
        ),
        M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.LINK_LIMIT_EXCEEDED
        ),
        M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
        ),
        M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_BUDGET_EXCEEDED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
        ),
        M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_BUDGET_EXCEEDED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED
        ),
        M6SQLiteM5PrecedentPlanFailureCode.TRANSACTION_REQUIRED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
        M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED: (
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        ),
    }
    return mapping.get(
        error.reason_code,
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID,
    )


def _canonical_document_failure_code(
    error: M6SQLitePhysicalDocumentError,
) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    if error.reason_code == M6SQLitePhysicalDocumentFailureCode.DOCUMENT_TOO_LARGE:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE
    if error.reason_code == M6SQLitePhysicalDocumentFailureCode.DOCUMENT_NOT_FOUND:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
    if error.reason_code == M6SQLitePhysicalDocumentFailureCode.UNSUPPORTED:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    if error.reason_code == M6SQLitePhysicalDocumentFailureCode.TRANSACTION_REQUIRED:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
    if error.reason_code == M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED:
        return M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
    return M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID


def _translate_canonical_document(error: M6SQLitePhysicalDocumentError) -> NoReturn:
    _fail(_canonical_document_failure_code(error))


def _public_failure_code(error: Exception) -> M6UpgradeWholeSampleRecordBuilderFailureCode:
    if isinstance(error, M6UpgradeWholeSampleRecordBuilderError):
        return error.reason_code
    if isinstance(error, M6UpgradeV2PendingSelectionError):
        return _selection_failure_code(error)
    if isinstance(error, M6UpgradeExecutionLedgerV2Error):
        return _state_failure_code(error)
    if isinstance(error, M6UpgradeExecutionLedgerV3Error):
        return _state_v3_failure_code(error)
    if isinstance(error, M6SQLiteCaseDocumentError):
        return _case_document_failure_code(error)
    if isinstance(error, M6SQLiteFrameDocumentError):
        return _frame_document_failure_code(error)
    if isinstance(error, M6SQLiteEvidencePackDocumentError):
        return _evidence_pack_document_failure_code(error)
    if isinstance(error, M6SQLiteM3ModelDocumentError):
        return _m3_model_document_failure_code(error)
    if isinstance(error, M6SQLiteM4ModelDocumentError):
        return _m4_model_document_failure_code(error)
    if isinstance(error, M6SQLiteAcquisitionDocumentError):
        return _acquisition_document_failure_code(error)
    if isinstance(error, M6SQLiteM5PrecedentDocumentError):
        return _m5_precedent_document_failure_code(error)
    if isinstance(error, M6SQLitePhysicalDocumentError):
        return _canonical_document_failure_code(error)
    if isinstance(error, M6M3ModelPhysicalResolutionError):
        return _m3_physical_failure_code(error)
    if isinstance(error, M6M4ModelPhysicalResolutionError):
        return _m4_physical_failure_code(error)
    if isinstance(error, M6UpgradePhysicalResolutionError):
        return M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED
    return M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED


def _pending_observation(
    state: M6SQLiteUpgradeV2State,
    selection: M6UpgradeV2PendingSelection,
) -> tuple[
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradePendingSampleCommitmentAuthority | None,
]:
    sequence = len(state.records)
    if state.seal is not None or len(state.observations) != sequence + 1:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_NOT_FOUND)
    observation = state.observations[sequence].authority
    pending_commitment = (
        state.commitments[sequence].authority if len(state.commitments) == sequence + 1 else None
    )
    commitment_id = (
        pending_commitment.pending_sample_commitment_authority_id
        if pending_commitment is not None
        else None
    )
    if (
        selection.sequence != sequence
        or selection.observation_authority_id != observation.observation_authority_id
        or selection.pending_sample_commitment_authority_id != commitment_id
        or selection.previous_ledger_entry_hash != state.ledger_head_hash
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED)
    return observation, pending_commitment


def _pending_observation_v3(
    state: M6SQLiteUpgradeV3State,
    selection: M6UpgradeV2PendingSelection,
) -> tuple[
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradePendingSampleCommitmentAuthority | None,
]:
    sequence = len(state.records)
    if state.seal is not None or len(state.observations) != sequence + 1:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_NOT_FOUND)
    observation = state.observations[sequence].authority
    if type(observation) is not M6UpgradeSampleExecutionObservationAuthorityV2:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
    pending_commitment = (
        state.commitments[sequence].authority if len(state.commitments) == sequence + 1 else None
    )
    commitment_id = (
        pending_commitment.pending_sample_commitment_authority_id
        if pending_commitment is not None
        else None
    )
    if (
        selection.sequence != sequence
        or selection.observation_authority_id != observation.observation_authority_id
        or selection.pending_sample_commitment_authority_id != commitment_id
        or selection.previous_ledger_entry_hash != state.ledger_head_hash
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED)
    return observation, pending_commitment


def _compose_base_record(
    *,
    state: M6SQLiteUpgradeV2State,
    observation: M6UpgradeSampleExecutionObservationAuthority,
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding | None,
) -> M6UpgradeSampleExecutionRecordV2:
    if candidate_case is None:
        return build_m6_upgrade_no_case_record(
            scope=state.stored_scope.authority,
            observation=observation,
            prior_records=state.records,
            artifacts=artifacts,
        )
    return build_m6_upgrade_case_replayed_base_record(
        scope=state.stored_scope.authority,
        observation=observation,
        prior_records=state.records,
        artifacts=artifacts,
        candidate_case=candidate_case,
    )


def _compose_base_record_v3(
    *,
    state: M6SQLiteUpgradeV3State,
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    artifacts: tuple[M6UpgradePhysicalArtifactRef, ...],
    candidate_case: M6UpgradeCandidateCaseBinding | None,
    planned_model_calls: tuple[M6PlannedModelCallPhysicalClosure, ...] = (),
    acquisition_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...] = (),
    precedent_artifacts: tuple[M6UpgradePhysicalArtifactRef, ...] = (),
) -> M6UpgradeSampleExecutionRecordV2:
    if precedent_artifacts:
        if candidate_case is None or not observation.model_calls or not planned_model_calls:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
        return build_m6_upgrade_case_replayed_precedent_record_v3(
            scope=state.stored_scope.authority,
            observation=observation,
            prior_records=state.records,
            artifacts=artifacts,
            planned_calls=planned_model_calls,
            acquisition_artifacts=acquisition_artifacts,
            precedent_artifacts=precedent_artifacts,
            candidate_case=candidate_case,
        )
    if acquisition_artifacts:
        if candidate_case is None or not observation.model_calls or not planned_model_calls:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
        return build_m6_upgrade_case_replayed_acquisition_record_v3(
            scope=state.stored_scope.authority,
            observation=observation,
            prior_records=state.records,
            artifacts=artifacts,
            planned_calls=planned_model_calls,
            acquisition_artifacts=acquisition_artifacts,
            candidate_case=candidate_case,
        )
    if observation.model_calls:
        if candidate_case is None or not planned_model_calls:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
        return build_m6_upgrade_case_replayed_model_record_v3(
            scope=state.stored_scope.authority,
            observation=observation,
            prior_records=state.records,
            artifacts=artifacts,
            planned_calls=planned_model_calls,
            candidate_case=candidate_case,
        )
    if planned_model_calls:
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    if any(artifact.kind == M6UpgradePhysicalArtifactKind.EVIDENCE_PACK for artifact in artifacts):
        if candidate_case is None:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
        return build_m6_upgrade_case_replayed_evidence_pack_record_v3(
            scope=state.stored_scope.authority,
            observation=observation,
            prior_records=state.records,
            artifacts=artifacts,
            candidate_case=candidate_case,
        )
    if candidate_case is None:
        return build_m6_upgrade_no_case_record_v3(
            scope=state.stored_scope.authority,
            observation=observation,
            prior_records=state.records,
            artifacts=artifacts,
        )
    return build_m6_upgrade_case_replayed_base_record_v3(
        scope=state.stored_scope.authority,
        observation=observation,
        prior_records=state.records,
        artifacts=artifacts,
        candidate_case=candidate_case,
    )


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


def _require_exact_model_observed_closures(
    plan: M6M3ModelPhysicalPlan | M6M4ModelPhysicalPlan,
    observed: tuple[M6ObservedModelCallPhysicalClosure, ...],
) -> None:
    if type(observed) is not tuple or any(
        type(item) is not M6ObservedModelCallPhysicalClosure for item in observed
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)
    if tuple(_model_closure_projection(item) for item in observed) != tuple(
        _model_closure_projection(item) for item in plan.planned_calls
    ):
        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH)


class SQLiteM6UpgradeWholeSampleRecordBuilder:
    """Build one trusted V2 base-route record from two public scope identities."""

    __slots__ = (
        "_busy_timeout_ms",
        "_database",
        "_m3_raw_response_verifier",
        "_m4_raw_response_verifier",
        "_pixel_provider",
        "_state_repository",
    )

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        *,
        pixel_provider: PixelFrameProvider,
        m3_raw_response_verifier: RawModelResponseVerifier,
        m4_raw_response_verifier: HearingRawModelResponseVerifier,
    ) -> None:
        if (
            not isinstance(database_path, (str, Path))
            or not isinstance(busy_timeout_ms, int)
            or isinstance(busy_timeout_ms, bool)
            or busy_timeout_ms < 0
            or not callable(getattr(pixel_provider, "read_rgb8", None))
            or not callable(getattr(m3_raw_response_verifier, "verify_raw_response", None))
            or not callable(getattr(m4_raw_response_verifier, "verify_raw_response", None))
        ):
            raise TypeError("invalid M6 whole-sample builder dependency")
        self._database = Path(database_path).absolute()
        self._busy_timeout_ms = busy_timeout_ms
        self._pixel_provider = pixel_provider
        self._m3_raw_response_verifier = m3_raw_response_verifier
        self._m4_raw_response_verifier = m4_raw_response_verifier
        self._state_repository = SQLiteM6UpgradeExecutionLedgerV2Repository(
            self._database,
            busy_timeout_ms,
        )

    def _plan_base_artifacts(
        self,
        connection: M6LiveReader,
        state: M6SQLiteUpgradeV2State | M6SQLiteUpgradeV3State,
        observation: M6UpgradeSampleExecutionObservationAuthority,
    ) -> tuple[
        tuple[M6UpgradePhysicalArtifactRef, ...],
        tuple[M6SQLiteFramePhysicalPlan, ...],
    ]:
        scope = state.stored_scope.authority
        planned: list[M6UpgradePhysicalArtifactRef] = []
        frame_plans: list[M6SQLiteFramePhysicalPlan] = []
        total_bytes = 0
        for identity in observation.artifacts:
            if identity.kind == M6UpgradePhysicalArtifactKind.FRAME:
                frame_plan = plan_m6_sqlite_frame_physical_identity(
                    connection=connection,
                    expected_run_id=scope.candidate_run_id,
                    expected_manifest_id=scope.candidate_manifest.manifest_id,
                    frame_id=identity.artifact_id,
                )
                artifact = frame_plan.planned_artifact_ref
                frame_plans.append(frame_plan)
            elif identity.kind == M6UpgradePhysicalArtifactKind.DETECTION:
                resolved = resolve_m6_sqlite_canonical_physical_identity(
                    connection=connection,
                    source=identity.source,
                    kind=identity.kind,
                    artifact_id=identity.artifact_id,
                    expected_run_id=scope.candidate_run_id,
                    expected_manifest_id=scope.candidate_manifest.manifest_id,
                )
                artifact = resolved.artifact_ref
            else:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
            planned.append(artifact)
            total_bytes += artifact.size_bytes
            if total_bytes > MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED)
        return tuple(planned), tuple(frame_plans)

    def _verify_frame_plans(
        self,
        run_id: str,
        frame_plans: tuple[M6SQLiteFramePhysicalPlan, ...],
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        verified: list[M6UpgradePhysicalArtifactRef] = []
        for plan in sorted(
            frame_plans,
            key=lambda item: item.planned_artifact_ref.physical_key,
        ):
            resolved = resolve_m6_upgrade_frame_physical_ref(
                expected_run_id=run_id,
                expected_frame_id=plan.frame_authority.frame_id,
                authority=plan.frame_authority,
                provider=self._pixel_provider,
            )
            if resolved != plan.planned_artifact_ref:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED)
            verified.append(resolved)
        return tuple(verified)

    def _attempt_build_m6_upgrade_sample_record(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionRecordV2:
        run_id, scope_id = _public_identity(candidate_run_id, execution_scope_authority_id)
        record: M6UpgradeSampleExecutionRecordV2 | None = None
        try:
            with m6_live_committed_read_cut(
                self._database,
                self._busy_timeout_ms,
            ) as cut:
                with cut.selector() as selector:
                    selection = select_m6_upgrade_v2_pending(selector, run_id, scope_id)
                with cut.reader() as reader:
                    state = load_m6_upgrade_v2_state_from_connection(
                        self._state_repository,
                        reader,
                        run_id,
                        scope_id,
                    )
                    observation, pending_commitment = _pending_observation(state, selection)
                    candidate_case: M6UpgradeCandidateCaseBinding | None = None
                    if observation.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED:
                        if observation.candidate_case is None:
                            _fail(
                                M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
                            )
                        case_authority = read_m6_sqlite_case_authority(
                            connection=reader,
                            expected_run_id=state.stored_scope.authority.candidate_run_id,
                            expected_manifest_id=(
                                state.stored_scope.authority.candidate_manifest.manifest_id
                            ),
                            expected_manifest_rule_version=(
                                state.stored_scope.authority.candidate_manifest.rule_version
                            ),
                            candidate_case_binding=observation.candidate_case,
                        )
                        # ADR-0021 makes fixed executor instrumentation the identity
                        # authority for this whole-sample physical set.  This reader
                        # proves the Case binding/history; candidate-output and
                        # executor/terminal cross-joins remain later M6 gates.
                        candidate_case = case_authority.candidate_case_binding
                    planned_refs, frame_plans = self._plan_base_artifacts(
                        reader,
                        state,
                        observation,
                    )
                    planned_record = _compose_base_record(
                        state=state,
                        observation=observation,
                        artifacts=planned_refs,
                        candidate_case=candidate_case,
                    )
                    if (
                        pending_commitment is not None
                        and pending_commitment.sample_execution_record != planned_record
                    ):
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)

                    verified_frames = self._verify_frame_plans(run_id, frame_plans)
                    verified_by_identity = {
                        (item.source, item.kind, item.artifact_id): item for item in verified_frames
                    }
                    verified_refs = tuple(
                        verified_by_identity.get(
                            (item.source, item.kind, item.artifact_id),
                            item,
                        )
                        for item in planned_refs
                    )
                    record = _compose_base_record(
                        state=state,
                        observation=observation,
                        artifacts=verified_refs,
                        candidate_case=candidate_case,
                    )
                    if record != planned_record or (
                        pending_commitment is not None
                        and pending_commitment.sample_execution_record != record
                    ):
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
                with cut.writer():
                    pass
        except M6UpgradeWholeSampleRecordBuilderError:
            raise
        except M6UpgradeV2PendingSelectionError as exc:
            _translate_selection(exc)
        except M6UpgradeExecutionLedgerV2Error as exc:
            _translate_state(exc)
        except M6SQLiteCaseDocumentError as exc:
            _translate_case_document(exc)
        except M6SQLiteFrameDocumentError as exc:
            _translate_frame_document(exc)
        except M6SQLitePhysicalDocumentError as exc:
            _translate_canonical_document(exc)
        except M6UpgradePhysicalResolutionError:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED)
        except M6LiveReadCutError:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED)
        except (sqlite3.Error, OSError):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED)
        if record is None:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED)
        return record

    def build_m6_upgrade_sample_record(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionRecordV2:
        """Build one record and publish only a fresh payload-free typed failure."""

        failure_code = M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
        try:
            return self._attempt_build_m6_upgrade_sample_record(
                candidate_run_id,
                execution_scope_authority_id,
            )
        except Exception as error:
            failure_code = _public_failure_code(error)
        del self, candidate_run_id, execution_scope_authority_id
        _fail(failure_code)


class SQLiteM6UpgradeWholeSampleRecordBuilderV3(SQLiteM6UpgradeWholeSampleRecordBuilder):
    """Build one trusted V3 opened-route record from an Observation V2 cut."""

    __slots__ = ("_state_repository_v3",)

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        *,
        pixel_provider: PixelFrameProvider,
        m3_raw_response_verifier: RawModelResponseVerifier,
        m4_raw_response_verifier: HearingRawModelResponseVerifier,
    ) -> None:
        if (
            not isinstance(database_path, (str, Path))
            or not isinstance(busy_timeout_ms, int)
            or isinstance(busy_timeout_ms, bool)
            or busy_timeout_ms < 0
            or not callable(getattr(pixel_provider, "read_rgb8", None))
            or not callable(getattr(m3_raw_response_verifier, "verify_raw_response", None))
            or not callable(getattr(m4_raw_response_verifier, "verify_raw_response", None))
        ):
            raise TypeError("invalid M6 whole-sample builder dependency")
        self._database = Path(database_path).absolute()
        self._busy_timeout_ms = busy_timeout_ms
        self._pixel_provider = pixel_provider
        self._m3_raw_response_verifier = m3_raw_response_verifier
        self._m4_raw_response_verifier = m4_raw_response_verifier
        self._state_repository_v3 = SQLiteM6UpgradeExecutionLedgerV3Repository(
            self._database,
            busy_timeout_ms,
        )

    @staticmethod
    def _plan_v3_artifacts(
        connection: M6LiveReader,
        state: M6SQLiteUpgradeV3State,
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
        selected_case_authority: M6SQLiteCaseAuthorityDocument | None,
    ) -> tuple[
        tuple[M6UpgradePhysicalArtifactRef, ...],
        tuple[M6SQLiteFramePhysicalPlan, ...],
        tuple[M6SQLiteEvidencePackPhysicalPlan, ...],
    ]:
        """Plan all metadata before admitting bytes or reading any physical body."""

        scope = state.stored_scope.authority
        planned_by_identity: dict[
            tuple[object, object, str],
            M6UpgradePhysicalArtifactRef,
        ] = {}
        frame_plans: list[M6SQLiteFramePhysicalPlan] = []
        evidence_pack_plans: list[M6SQLiteEvidencePackPhysicalPlan] = []

        # Case membership is the authority for this route, so all targeted pack
        # metadata is fixed before any other physical plan is considered.
        for identity in observation.artifacts:
            route = (identity.source, identity.kind)
            if route in _V3_DEFERRED_ARTIFACT_ROUTES:
                continue
            if identity.kind != M6UpgradePhysicalArtifactKind.EVIDENCE_PACK:
                continue
            if route not in _V3_ORDINARY_ROUTES:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
            if selected_case_authority is None:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
            plan = plan_m6_sqlite_evidence_pack_physical_identity(
                connection=connection,
                expected_run_id=scope.candidate_run_id,
                expected_manifest_id=scope.candidate_manifest.manifest_id,
                selected_case_authority=selected_case_authority,
                pack_id=identity.artifact_id,
            )
            pack_key: tuple[object, object, str] = (
                identity.source,
                identity.kind,
                identity.artifact_id,
            )
            if pack_key in planned_by_identity:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
            planned_by_identity[pack_key] = plan.planned_artifact_ref
            evidence_pack_plans.append(plan)

        for identity in observation.artifacts:
            route = (identity.source, identity.kind)
            if route in _V3_DEFERRED_ARTIFACT_ROUTES:
                continue
            if identity.kind == M6UpgradePhysicalArtifactKind.EVIDENCE_PACK:
                continue
            if route == (
                M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                M6UpgradePhysicalArtifactKind.FRAME,
            ):
                frame_plan = plan_m6_sqlite_frame_physical_identity(
                    connection=connection,
                    expected_run_id=scope.candidate_run_id,
                    expected_manifest_id=scope.candidate_manifest.manifest_id,
                    frame_id=identity.artifact_id,
                )
                artifact = frame_plan.planned_artifact_ref
                frame_plans.append(frame_plan)
            elif route == (
                M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                M6UpgradePhysicalArtifactKind.DETECTION,
            ):
                artifact = resolve_m6_sqlite_canonical_physical_identity(
                    connection=connection,
                    source=identity.source,
                    kind=identity.kind,
                    artifact_id=identity.artifact_id,
                    expected_run_id=scope.candidate_run_id,
                    expected_manifest_id=scope.candidate_manifest.manifest_id,
                ).artifact_ref
            else:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
            artifact_key: tuple[object, object, str] = (
                identity.source,
                identity.kind,
                identity.artifact_id,
            )
            if artifact_key in planned_by_identity:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
            planned_by_identity[artifact_key] = artifact

        try:
            planned = tuple(
                planned_by_identity[(identity.source, identity.kind, identity.artifact_id)]
                for identity in observation.artifacts
                if (identity.source, identity.kind) not in _V3_DEFERRED_ARTIFACT_ROUTES
            )
        except KeyError:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
        return planned, tuple(frame_plans), tuple(evidence_pack_plans)

    @staticmethod
    def _plan_v3_m3_documents(
        connection: M6LiveReader,
        state: M6SQLiteUpgradeV3State,
        observed_model_calls: tuple[M6UpgradeObservedModelCall, ...],
        selected_case_authority: M6SQLiteCaseAuthorityDocument,
    ) -> M6SQLiteM3ModelDocumentsPlan:
        scope = state.stored_scope.authority
        screening_manifest = scope.candidate_manifest.models.get("screening")
        if screening_manifest is None:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
        return plan_m6_sqlite_m3_model_documents(
            connection=connection,
            expected_run_id=scope.candidate_run_id,
            expected_manifest_id=scope.candidate_manifest.manifest_id,
            expected_model_manifest_id=screening_manifest.model_manifest_id,
            selected_case_authority=selected_case_authority,
            observed_model_calls=observed_model_calls,
        )

    @staticmethod
    def _plan_v3_m4_documents(
        connection: M6LiveReader,
        state: M6SQLiteUpgradeV3State,
        observed_model_calls: tuple[M6UpgradeObservedModelCall, ...],
        selected_case_authority: M6SQLiteCaseAuthorityDocument,
    ) -> M6SQLiteM4ModelDocumentsPlan:
        scope = state.stored_scope.authority
        role_components = (
            (M6LockedModelRole.PROSECUTOR, "prosecutor"),
            (M6LockedModelRole.DEFENDER, "defender"),
            (M6LockedModelRole.JUDGE, "judge"),
        )
        role_bindings: list[M6SQLiteM4RoleModelManifestBinding] = []
        for role, component in role_components:
            model_manifest = scope.candidate_manifest.models.get(component)
            if model_manifest is None:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)
            role_bindings.append(
                M6SQLiteM4RoleModelManifestBinding(
                    role=role,
                    model_manifest_id=model_manifest.model_manifest_id,
                )
            )
        return plan_m6_sqlite_m4_model_documents(
            connection=connection,
            expected_run_id=scope.candidate_run_id,
            expected_manifest_id=scope.candidate_manifest.manifest_id,
            expected_role_model_manifests=tuple(role_bindings),
            selected_case_authority=selected_case_authority,
            observed_model_calls=observed_model_calls,
        )

    @staticmethod
    def _plan_v3_acquisition_documents(
        connection: M6LiveReader,
        state: M6SQLiteUpgradeV3State,
        observed_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...],
        selected_case_authority: M6SQLiteCaseAuthorityDocument,
        upstream_m4_model_plan: M6SQLiteM4ModelDocumentsPlan,
    ) -> M6SQLiteAcquisitionDocumentsPlan:
        scope = state.stored_scope.authority
        return plan_m6_sqlite_acquisition_documents(
            connection=connection,
            expected_run_id=scope.candidate_run_id,
            expected_manifest_id=scope.candidate_manifest.manifest_id,
            upstream_m4_model_plan=upstream_m4_model_plan,
            selected_case_authority=selected_case_authority,
            observed_acquisition_artifacts=observed_artifacts,
        )

    @staticmethod
    def _plan_v3_m5_precedent_documents(
        connection: M6LiveReader,
        state: M6SQLiteUpgradeV3State,
        observed_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...],
        selected_case_authority: M6SQLiteCaseAuthorityDocument,
        upstream_m4_model_plan: M6SQLiteM4ModelDocumentsPlan,
    ) -> M6SQLiteM5PrecedentDocumentsPlan:
        scope = state.stored_scope.authority
        return plan_m6_sqlite_m5_precedent_documents(
            connection=connection,
            manifest=scope.candidate_manifest,
            config=scope.candidate_config,
            selected_case_authority=selected_case_authority,
            upstream_m4_model_plan=upstream_m4_model_plan,
            observed_precedent_artifacts=observed_artifacts,
        )

    @staticmethod
    def _require_v3_acquisition_manifest_pins(
        state: M6SQLiteUpgradeV3State,
        acquisition_plan: M6SQLiteAcquisitionDocumentsPlan,
    ) -> None:
        manifest = state.stored_scope.authority.candidate_manifest
        component_manifest_ids = {
            hashlib.sha256(
                canonical_json(component.model_dump(mode="json")).encode("utf-8")
            ).hexdigest()
            for component in manifest.software_components.values()
        }
        model_manifest_ids = {model.model_manifest_id for model in manifest.models.values()}
        if any(
            closure.manifest.component_manifest_id not in component_manifest_ids
            or (
                closure.manifest.model_manifest_id is not None
                and closure.manifest.model_manifest_id not in model_manifest_ids
            )
            for closure in acquisition_plan.closures
        ):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID)

    @staticmethod
    def _require_v3_combined_preflight(
        ordinary_refs: tuple[M6UpgradePhysicalArtifactRef, ...],
        m3_documents_plan: M6SQLiteM3ModelDocumentsPlan | None,
        m4_documents_plan: M6SQLiteM4ModelDocumentsPlan | None,
        acquisition_documents_plan: M6SQLiteAcquisitionDocumentsPlan | None,
        m5_precedent_documents_plan: M6SQLiteM5PrecedentDocumentsPlan | None,
    ) -> None:
        m3_refs = m3_documents_plan.planned_artifact_refs if m3_documents_plan is not None else ()
        m4_refs = m4_documents_plan.planned_artifact_refs if m4_documents_plan is not None else ()
        acquisition_refs = (
            acquisition_documents_plan.planned_artifact_refs
            if acquisition_documents_plan is not None
            else ()
        )
        m5_refs = (
            m5_precedent_documents_plan.planned_artifact_refs
            if m5_precedent_documents_plan is not None
            else ()
        )
        combined = ordinary_refs + m3_refs + m4_refs + acquisition_refs + m5_refs
        if len(combined) > MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.LINK_LIMIT_EXCEEDED)
        identities = tuple((item.source, item.kind, item.artifact_id) for item in combined)
        physical_keys = tuple(item.physical_key for item in combined)
        ref_ids = tuple(item.artifact_ref_id for item in combined)
        if (
            len(identities) != len(set(identities))
            or len(physical_keys) != len(set(physical_keys))
            or len(ref_ids) != len(set(ref_ids))
        ):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
        if sum(item.size_bytes for item in combined) > MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED)

    @staticmethod
    def _resolve_evidence_pack_plans(
        connection: M6LiveReader,
        plans: tuple[M6SQLiteEvidencePackPhysicalPlan, ...],
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        verified: list[M6UpgradePhysicalArtifactRef] = []
        for plan in sorted(
            plans,
            key=lambda item: item.planned_artifact_ref.physical_key,
        ):
            resolved = resolve_m6_sqlite_evidence_pack_physical_plan(
                connection=connection,
                physical_plan=plan,
            ).artifact_ref
            if resolved != plan.planned_artifact_ref:
                _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
            verified.append(resolved)
        return tuple(verified)

    def _attempt_build_m6_upgrade_sample_record(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionRecordV2:
        run_id, scope_id = _public_identity(candidate_run_id, execution_scope_authority_id)
        record: M6UpgradeSampleExecutionRecordV2 | None = None
        try:
            with m6_live_committed_read_cut(
                self._database,
                self._busy_timeout_ms,
            ) as cut:
                with cut.selector() as selector:
                    selection = select_m6_upgrade_v3_pending(selector, run_id, scope_id)
                with cut.reader() as reader:
                    state = load_m6_upgrade_v3_state_from_connection(
                        self._state_repository_v3,
                        reader,
                        run_id,
                        scope_id,
                    )
                    observation, pending_commitment = _pending_observation_v3(
                        state,
                        selection,
                    )
                    candidate_case: M6UpgradeCandidateCaseBinding | None = None
                    selected_case_authority: M6SQLiteCaseAuthorityDocument | None = None
                    if observation.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED:
                        anchor = observation.selected_case_audit_anchor
                        if observation.candidate_case is None or anchor is None:
                            _fail(
                                M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
                            )
                        selected_case_authority = read_m6_sqlite_case_authority_v3(
                            connection=reader,
                            expected_run_id=state.stored_scope.authority.candidate_run_id,
                            expected_manifest_id=(
                                state.stored_scope.authority.candidate_manifest.manifest_id
                            ),
                            expected_manifest_rule_version=(
                                state.stored_scope.authority.candidate_manifest.rule_version
                            ),
                            candidate_case_binding=observation.candidate_case,
                            selected_case_audit_anchor=anchor,
                        )
                        candidate_case = selected_case_authority.candidate_case_binding
                    elif observation.outcome != M6ReplayExecutionOutcome.NO_CASE:
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)

                    m3_observations = tuple(
                        item
                        for item in observation.model_calls
                        if item.layer == M6LockedModelCallLayer.SCREENING
                    )
                    m4_observations = tuple(
                        item
                        for item in observation.model_calls
                        if item.layer == M6LockedModelCallLayer.HEARING
                    )
                    acquisition_observations = tuple(
                        item
                        for item in observation.artifacts
                        if (item.source, item.kind) in _V3_ACQUISITION_ROUTES
                    )
                    precedent_observations = tuple(
                        item
                        for item in observation.artifacts
                        if (item.source, item.kind) in _V3_PRECEDENT_ROUTES
                    )
                    if (
                        tuple(
                            sorted(
                                m3_observations + m4_observations,
                                key=lambda item: item.sort_key,
                            )
                        )
                        != observation.model_calls
                        or any(item.role != M6LockedModelRole.SCREENING for item in m3_observations)
                        or any(
                            item.role
                            not in {
                                M6LockedModelRole.PROSECUTOR,
                                M6LockedModelRole.DEFENDER,
                                M6LockedModelRole.JUDGE,
                            }
                            for item in m4_observations
                        )
                    ):
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
                    if observation.model_calls and selected_case_authority is None:
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
                    if acquisition_observations and selected_case_authority is None:
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
                    if precedent_observations and selected_case_authority is None:
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)

                    planned_refs, frame_plans, evidence_pack_plans = self._plan_v3_artifacts(
                        reader,
                        state,
                        observation,
                        selected_case_authority,
                    )
                    m3_documents_plan = (
                        self._plan_v3_m3_documents(
                            reader,
                            state,
                            m3_observations,
                            selected_case_authority,
                        )
                        if selected_case_authority is not None
                        else None
                    )
                    m4_documents_plan = (
                        self._plan_v3_m4_documents(
                            reader,
                            state,
                            m4_observations,
                            selected_case_authority,
                        )
                        if selected_case_authority is not None
                        else None
                    )
                    acquisition_documents_plan: M6SQLiteAcquisitionDocumentsPlan | None = None
                    m5_precedent_documents_plan: M6SQLiteM5PrecedentDocumentsPlan | None = None
                    if selected_case_authority is not None:
                        if m4_documents_plan is None:
                            _fail(
                                M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
                            )
                        acquisition_documents_plan = self._plan_v3_acquisition_documents(
                            reader,
                            state,
                            acquisition_observations,
                            selected_case_authority,
                            m4_documents_plan,
                        )
                        self._require_v3_acquisition_manifest_pins(
                            state,
                            acquisition_documents_plan,
                        )
                        m5_precedent_documents_plan = self._plan_v3_m5_precedent_documents(
                            reader,
                            state,
                            precedent_observations,
                            selected_case_authority,
                            m4_documents_plan,
                        )
                    self._require_v3_combined_preflight(
                        planned_refs,
                        m3_documents_plan,
                        m4_documents_plan,
                        acquisition_documents_plan,
                        m5_precedent_documents_plan,
                    )
                    acquisition_refs = (
                        acquisition_documents_plan.planned_artifact_refs
                        if acquisition_documents_plan is not None
                        else ()
                    )
                    precedent_refs = (
                        m5_precedent_documents_plan.planned_artifact_refs
                        if m5_precedent_documents_plan is not None
                        else ()
                    )

                    metadata_model_calls = tuple(
                        sorted(
                            (
                                *(
                                    M6MetadataModelCallArtifactPlan(
                                        observation=graph.observation,
                                        artifact_refs=graph.artifact_refs,
                                    )
                                    for graph in (
                                        m3_documents_plan.call_graphs
                                        if m3_documents_plan is not None
                                        else ()
                                    )
                                ),
                                *(
                                    M6MetadataModelCallArtifactPlan(
                                        observation=graph.observation,
                                        artifact_refs=graph.artifact_refs,
                                    )
                                    for graph in (
                                        m4_documents_plan.call_graphs
                                        if m4_documents_plan is not None
                                        else ()
                                    )
                                ),
                            ),
                            key=lambda item: item.sort_key,
                        )
                    )
                    if len(metadata_model_calls) != len(observation.model_calls):
                        _fail(
                            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
                        )
                    if precedent_refs:
                        if candidate_case is None:
                            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
                        metadata_record = (
                            build_m6_upgrade_case_replayed_metadata_precedent_record_v3(
                                scope=state.stored_scope.authority,
                                observation=observation,
                                prior_records=state.records,
                                artifacts=planned_refs,
                                model_calls=metadata_model_calls,
                                acquisition_artifacts=acquisition_refs,
                                precedent_artifacts=precedent_refs,
                                candidate_case=candidate_case,
                            )
                        )
                    elif acquisition_refs:
                        if candidate_case is None:
                            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED)
                        metadata_record = (
                            build_m6_upgrade_case_replayed_metadata_acquisition_record_v3(
                                scope=state.stored_scope.authority,
                                observation=observation,
                                prior_records=state.records,
                                artifacts=planned_refs,
                                model_calls=metadata_model_calls,
                                acquisition_artifacts=acquisition_refs,
                                candidate_case=candidate_case,
                            )
                        )
                    elif observation.model_calls and candidate_case is not None:
                        metadata_record = build_m6_upgrade_case_replayed_metadata_model_record_v3(
                            scope=state.stored_scope.authority,
                            observation=observation,
                            prior_records=state.records,
                            artifacts=planned_refs,
                            model_calls=metadata_model_calls,
                            candidate_case=candidate_case,
                        )
                    else:
                        metadata_record = _compose_base_record_v3(
                            state=state,
                            observation=observation,
                            artifacts=planned_refs,
                            candidate_case=candidate_case,
                        )
                    if (
                        pending_commitment is not None
                        and pending_commitment.sample_execution_record != metadata_record
                    ):
                        # This exact comparison deliberately precedes the first
                        # M3/M4/M5 canonical body, Raw response, or Pixel read.
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)

                    m3_plan: M6M3ModelPhysicalPlan | None = None
                    m3_snapshot: M6M3ModelCallAuthoritySnapshot | None = None
                    if m3_observations:
                        if m3_documents_plan is None:
                            _fail(
                                M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
                            )
                        m3_snapshot = resolve_m6_sqlite_m3_model_documents(
                            connection=reader,
                            metadata_plan=m3_documents_plan,
                        )
                        m3_plan = plan_m6_m3_observed_model_call_closures(
                            source_case=m3_documents_plan.selected_case,
                            snapshot=m3_snapshot,
                        )
                        if (
                            m3_plan.source_identity_sha256 != m3_documents_plan.plan_identity_sha256
                            or m3_plan.planned_refs != m3_documents_plan.planned_artifact_refs
                        ):
                            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
                    elif m3_documents_plan is not None and (
                        m3_documents_plan.call_graphs or m3_documents_plan.planned_artifact_refs
                    ):
                        _fail(
                            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
                        )

                    m4_plan: M6M4ModelPhysicalPlan | None = None
                    m4_snapshot: M6M4ModelCallAuthoritySnapshot | None = None
                    if m4_observations:
                        if m4_documents_plan is None:
                            _fail(
                                M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
                            )
                        m4_snapshot = resolve_m6_sqlite_m4_model_documents(
                            connection=reader,
                            metadata_plan=m4_documents_plan,
                        )
                        m4_plan = plan_m6_m4_observed_model_call_closures(
                            source_case=m4_documents_plan.selected_case,
                            snapshot=m4_snapshot,
                        )
                        if (
                            m4_plan.source_identity_sha256 != m4_documents_plan.plan_identity_sha256
                            or m4_plan.planned_refs != m4_documents_plan.planned_artifact_refs
                        ):
                            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
                    elif m4_documents_plan is not None and (
                        m4_documents_plan.call_graphs or m4_documents_plan.planned_artifact_refs
                    ):
                        _fail(
                            M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
                        )

                    verified_acquisition_refs: tuple[M6UpgradePhysicalArtifactRef, ...] = ()
                    if acquisition_refs:
                        if acquisition_documents_plan is None or m4_documents_plan is None:
                            _fail(
                                M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
                            )
                        acquisition_snapshot = resolve_m6_sqlite_acquisition_documents(
                            connection=reader,
                            metadata_plan=acquisition_documents_plan,
                            upstream_m4_model_plan=m4_documents_plan,
                        )
                        if (
                            acquisition_snapshot.source_identity_sha256
                            != acquisition_documents_plan.plan_identity_sha256
                            or acquisition_snapshot.upstream_m4_model_plan_identity_sha256
                            != m4_documents_plan.plan_identity_sha256
                            or acquisition_snapshot.run_id != acquisition_documents_plan.run_id
                            or acquisition_snapshot.case_id != acquisition_documents_plan.case_id
                            or acquisition_snapshot.manifest_id
                            != acquisition_documents_plan.manifest_id
                            or acquisition_snapshot.planned_artifact_refs != acquisition_refs
                        ):
                            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
                        verified_acquisition_refs = acquisition_snapshot.planned_artifact_refs
                    elif acquisition_documents_plan is not None and (
                        acquisition_documents_plan.closures
                        or acquisition_documents_plan.planned_artifact_refs
                    ):
                        _fail(
                            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
                        )

                    verified_precedent_refs: tuple[M6UpgradePhysicalArtifactRef, ...] = ()
                    if m5_precedent_documents_plan is not None:
                        if selected_case_authority is None or m4_documents_plan is None:
                            _fail(
                                M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
                            )
                        precedent_snapshot = resolve_m6_sqlite_m5_precedent_documents(
                            connection=reader,
                            metadata_plan=m5_precedent_documents_plan,
                            selected_case=selected_case_authority.case,
                            config=state.stored_scope.authority.candidate_config,
                            manifest=state.stored_scope.authority.candidate_manifest,
                            upstream_m4_model_plan=m4_documents_plan,
                        )
                        if (
                            precedent_snapshot.source_identity_sha256
                            != m5_precedent_documents_plan.plan_identity_sha256
                            or precedent_snapshot.upstream_m4_model_plan_identity_sha256
                            != m4_documents_plan.plan_identity_sha256
                            or precedent_snapshot.run_id != m5_precedent_documents_plan.run_id
                            or precedent_snapshot.case_id != m5_precedent_documents_plan.case_id
                            or precedent_snapshot.manifest_id
                            != m5_precedent_documents_plan.manifest_id
                            or precedent_snapshot.observed_artifacts
                            != m5_precedent_documents_plan.observed_artifacts
                            or precedent_snapshot.planned_artifact_refs != precedent_refs
                        ):
                            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
                        verified_precedent_refs = precedent_snapshot.planned_artifact_refs
                    elif precedent_refs:
                        _fail(
                            M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
                        )

                    planned_model_calls = tuple(
                        sorted(
                            (
                                *(m3_plan.planned_calls if m3_plan is not None else ()),
                                *(m4_plan.planned_calls if m4_plan is not None else ()),
                            ),
                            key=lambda item: item.sort_key,
                        )
                    )
                    planned_record = _compose_base_record_v3(
                        state=state,
                        observation=observation,
                        artifacts=planned_refs,
                        candidate_case=candidate_case,
                        planned_model_calls=planned_model_calls,
                        acquisition_artifacts=verified_acquisition_refs,
                        precedent_artifacts=verified_precedent_refs,
                    )
                    if planned_record != metadata_record or (
                        pending_commitment is not None
                        and pending_commitment.sample_execution_record != planned_record
                    ):
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)

                    verified_evidence_packs = self._resolve_evidence_pack_plans(
                        reader,
                        evidence_pack_plans,
                    )
                    if m3_plan is not None:
                        if m3_snapshot is None or m3_documents_plan is None:
                            _fail(
                                M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
                            )
                        observed_m3_calls = resolve_m6_m3_observed_model_call_physical_plan(
                            source_case=m3_documents_plan.selected_case,
                            snapshot=m3_snapshot,
                            plan=m3_plan,
                            raw_response_verifier=self._m3_raw_response_verifier,
                        )
                        _require_exact_model_observed_closures(m3_plan, observed_m3_calls)
                    if m4_plan is not None:
                        if m4_snapshot is None or m4_documents_plan is None:
                            _fail(
                                M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
                            )
                        observed_m4_calls = resolve_m6_m4_observed_model_call_physical_plan(
                            source_case=m4_documents_plan.selected_case,
                            snapshot=m4_snapshot,
                            plan=m4_plan,
                            raw_response_verifier=self._m4_raw_response_verifier,
                        )
                        _require_exact_model_observed_closures(m4_plan, observed_m4_calls)
                    verified_frames = self._verify_frame_plans(run_id, frame_plans)
                    verified_by_identity = {
                        (item.source, item.kind, item.artifact_id): item
                        for item in (*verified_evidence_packs, *verified_frames)
                    }
                    verified_refs = tuple(
                        verified_by_identity.get(
                            (item.source, item.kind, item.artifact_id),
                            item,
                        )
                        for item in planned_refs
                    )
                    record = _compose_base_record_v3(
                        state=state,
                        observation=observation,
                        artifacts=verified_refs,
                        candidate_case=candidate_case,
                        planned_model_calls=planned_model_calls,
                        acquisition_artifacts=verified_acquisition_refs,
                        precedent_artifacts=verified_precedent_refs,
                    )
                    if record != planned_record or (
                        pending_commitment is not None
                        and pending_commitment.sample_execution_record != record
                    ):
                        _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT)
                with cut.writer():
                    pass
        except M6UpgradeWholeSampleRecordBuilderError:
            raise
        except M6UpgradeV2PendingSelectionError as exc:
            _translate_selection(exc)
        except M6UpgradeExecutionLedgerV3Error as exc:
            _fail(_state_v3_failure_code(exc))
        except M6SQLiteCaseDocumentError as exc:
            _translate_case_document(exc)
        except M6SQLiteFrameDocumentError as exc:
            _translate_frame_document(exc)
        except M6SQLiteEvidencePackDocumentError as exc:
            _translate_evidence_pack_document(exc)
        except M6SQLiteM3ModelDocumentError as exc:
            _fail(_m3_model_document_failure_code(exc))
        except M6SQLiteM4ModelDocumentError as exc:
            _fail(_m4_model_document_failure_code(exc))
        except M6SQLiteAcquisitionDocumentError as exc:
            _fail(_acquisition_document_failure_code(exc))
        except M6SQLiteM5PrecedentDocumentError as exc:
            _fail(_m5_precedent_document_failure_code(exc))
        except M6SQLitePhysicalDocumentError as exc:
            _translate_canonical_document(exc)
        except M6M3ModelPhysicalResolutionError as exc:
            _fail(_m3_physical_failure_code(exc))
        except M6M4ModelPhysicalResolutionError as exc:
            _fail(_m4_physical_failure_code(exc))
        except M6UpgradePhysicalResolutionError:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED)
        except M6LiveReadCutError:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED)
        except (sqlite3.Error, OSError):
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED)
        if record is None:
            _fail(M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED)
        return record


__all__ = [
    "SQLiteM6UpgradeWholeSampleRecordBuilder",
    "SQLiteM6UpgradeWholeSampleRecordBuilderV3",
]
