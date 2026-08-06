"""Pure contracts for bounded M6 acquisition metadata planning.

This module deliberately performs no SQLite access and reads no canonical
authority body.  It freezes the identities, byte commitments, upstream M4
dependencies, and selected-Case pack transitions needed by the later
metadata/body readers.  Only the execution manifest and the deduplicated
``ToolResult`` become M6 physical artifacts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import ValidationError

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    ArtifactKind,
)
from labcourt.contracts.evidence import EvidencePack, ToolResult
from labcourt.contracts.m6_replay_locked import MAX_M6_LOCKED_TOOL_RESULTS_PER_CASE
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef

MAX_M6_SQLITE_ACQUISITION_ITEMS = MAX_M6_LOCKED_TOOL_RESULTS_PER_CASE
MAX_M6_SQLITE_ACQUISITION_SELECTED_PACKS = MAX_M6_SQLITE_ACQUISITION_ITEMS + 1
MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_SQLITE_ACQUISITION_SUPPORT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_M6_SQLITE_ACQUISITION_DOCUMENT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_M6_SQLITE_ACQUISITION_PHYSICAL_TOTAL_BYTES = MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES
MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS = MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE
MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE = MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE

if (
    MAX_M6_SQLITE_ACQUISITION_ITEMS != 64
    or MAX_M6_SQLITE_ACQUISITION_PHYSICAL_TOTAL_BYTES != 256 * 1024 * 1024
    or MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS != 20_000
):
    raise RuntimeError("M6 acquisition plan budgets must match the frozen replay/ledger limits")


class M6SQLiteAcquisitionPlanFailureCode(StrEnum):
    """Closed, payload-free failures for the future acquisition planner."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TRANSACTION_REQUIRED = "TRANSACTION_REQUIRED"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    CASE_BINDING_MISMATCH = "CASE_BINDING_MISMATCH"
    INVENTORY_MISMATCH = "INVENTORY_MISMATCH"
    UNSUPPORTED_ACQUISITION_STATE = "UNSUPPORTED_ACQUISITION_STATE"
    POST_CUT_AUTHORITY = "POST_CUT_AUTHORITY"
    ROW_LIMIT_EXCEEDED = "ROW_LIMIT_EXCEEDED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    SUPPORT_BUDGET_EXCEEDED = "SUPPORT_BUDGET_EXCEEDED"
    PHYSICAL_BUDGET_EXCEEDED = "PHYSICAL_BUDGET_EXCEEDED"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_BINDING_MISMATCH = "INDEX_BINDING_MISMATCH"
    CLOSURE_MISMATCH = "CLOSURE_MISMATCH"
    PHYSICAL_PLAN_INVALID = "PHYSICAL_PLAN_INVALID"
    DATABASE_REJECTED = "DATABASE_REJECTED"


class _M6SQLiteAcquisitionMetadataFailure(Exception):
    """Private control-flow failure retaining only one closed reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: M6SQLiteAcquisitionPlanFailureCode) -> None:
        if type(reason_code) is not M6SQLiteAcquisitionPlanFailureCode:
            raise TypeError("reason_code must be an exact acquisition failure code")
        self.reason_code = reason_code
        super().__init__(reason_code.value)


class M6SQLiteAcquisitionPhysicalRoute(StrEnum):
    TOOL_EXECUTION_MANIFEST = "m4_tool_execution_manifests.manifest_json"
    TOOL_RESULT = "selected_case.evidence_packs.tool_results"


class M6SQLiteAcquisitionSupportRoute(StrEnum):
    """Body-free relational rows supporting an acquisition closure."""

    ACQUISITION_REQUEST = "m4_acquisition_requests"
    EXECUTION_PUBLICATION = "m4_acquisition_execution_publications"
    TOOL_EXECUTION_RECEIPT = "m4_tool_execution_receipts"
    EVIDENCE_PACK_DERIVATION = "m4_evidence_pack_derivations"
    HEARING_CHECKPOINT = "m4_hearing_checkpoints"
    HEARING_ROUND = "m4_hearing_rounds"
    CASE_VERSION = "case_versions"
    AUDIT_ENTRY = "audit_entries"
    OUTPUT_FRAME = "frames"
    OUTPUT_DETECTION = "detections"
    OUTPUT_CROP = "m4_acquired_crops"


class M6SQLiteAcquisitionSupportDocumentRoute(StrEnum):
    """Exact acquisition body columns already opened by the live reader."""

    ACQUISITION_REQUEST = "m4_acquisition_requests.request_json"
    EXECUTION_PUBLICATION = "m4_acquisition_execution_publications.publication_json"
    TOOL_EXECUTION_RECEIPT = "m4_tool_execution_receipts.receipt_json"
    EVIDENCE_PACK_DERIVATION = "m4_evidence_pack_derivations.derivation_json"
    HEARING_CHECKPOINT = "m4_hearing_checkpoints.checkpoint_json"
    HEARING_ROUND = "m4_hearing_rounds.round_json"
    CASE_VERSION = "case_versions.case_json"
    AUDIT_ENTRY = "audit_entries.entry_json"


class M6SQLiteAcquisitionDocumentCommitmentKind(StrEnum):
    CANONICAL_DOCUMENT = "CANONICAL_DOCUMENT"
    SEMANTIC_DOCUMENT = "SEMANTIC_DOCUMENT"


class M6SQLiteAcquisitionClaimState(StrEnum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ABANDONED = "ABANDONED"


_SUPPORT_ROUTE_RANK = {route: index for index, route in enumerate(M6SQLiteAcquisitionSupportRoute)}
_SUPPORT_DOCUMENT_ROUTE_RANK = {
    route: index for index, route in enumerate(M6SQLiteAcquisitionSupportDocumentRoute)
}
_SUPPORT_DOCUMENT_TO_ROW_ROUTE = {
    document_route: M6SQLiteAcquisitionSupportRoute[document_route.name]
    for document_route in M6SQLiteAcquisitionSupportDocumentRoute
}
_SUPPORT_COMMITMENT_KIND = {
    route: (
        M6SQLiteAcquisitionDocumentCommitmentKind.SEMANTIC_DOCUMENT
        if route
        in {
            M6SQLiteAcquisitionSupportDocumentRoute.HEARING_CHECKPOINT,
            M6SQLiteAcquisitionSupportDocumentRoute.HEARING_ROUND,
        }
        else M6SQLiteAcquisitionDocumentCommitmentKind.CANONICAL_DOCUMENT
    )
    for route in M6SQLiteAcquisitionSupportDocumentRoute
}
_OUTPUT_ROUTE_BY_KIND = {
    # These are bounded, selected-ToolResult-driven targeted existence checks.
    # They deliberately have no document route, body commitment, or physical ref.
    ArtifactKind.FRAME: M6SQLiteAcquisitionSupportRoute.OUTPUT_FRAME,
    ArtifactKind.DETECTION: M6SQLiteAcquisitionSupportRoute.OUTPUT_DETECTION,
    ArtifactKind.CROP: M6SQLiteAcquisitionSupportRoute.OUTPUT_CROP,
}
_OUTPUT_KIND_BY_ROUTE = {route: kind for kind, route in _OUTPUT_ROUTE_BY_KIND.items()}
_MANDATORY_SUPPORT_ROUTES = frozenset(
    {
        M6SQLiteAcquisitionSupportRoute.ACQUISITION_REQUEST,
        M6SQLiteAcquisitionSupportRoute.EXECUTION_PUBLICATION,
        M6SQLiteAcquisitionSupportRoute.TOOL_EXECUTION_RECEIPT,
        M6SQLiteAcquisitionSupportRoute.EVIDENCE_PACK_DERIVATION,
        M6SQLiteAcquisitionSupportRoute.HEARING_CHECKPOINT,
        M6SQLiteAcquisitionSupportRoute.CASE_VERSION,
        M6SQLiteAcquisitionSupportRoute.AUDIT_ENTRY,
    }
)
_ACQUISITION_KINDS = frozenset(
    {
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
    }
)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_sha256(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    assert isinstance(value, str)
    return value


def _require_scope_token(value: object, label: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{label} must be a string")
    return require_reference_token(value, label)


def _require_positive_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _require_non_negative_integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _require_document_bytes(value: object, label: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES:
        raise ValueError(f"{label} is outside the acquisition document budget")
    return value


def _canonical_document(value: object) -> tuple[str, str, int]:
    if not hasattr(value, "model_dump"):
        raise TypeError("canonical authority must be a typed contract")
    try:
        document = canonical_json(value.model_dump(mode="json"))
    except (AttributeError, TypeError, UnicodeError, ValueError):
        raise ValueError("canonical authority cannot be serialized") from None
    encoded = document.encode("utf-8")
    _require_document_bytes(len(encoded), "canonical authority document")
    return document, hashlib.sha256(encoded).hexdigest(), len(encoded)


def _controlled_case(value: object) -> Case:
    if type(value) is not Case:
        raise TypeError("selected Case must be exact")
    try:
        controlled = Case.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        raise ValueError("selected Case must be canonical") from None
    if controlled != value:
        raise ValueError("selected Case must be canonical")
    return controlled


def _controlled_audit(value: object) -> AuditEntry:
    if type(value) is not AuditEntry:
        raise TypeError("selected Case audit must be exact")
    try:
        controlled = AuditEntry.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        raise ValueError("selected Case audit must be canonical") from None
    if controlled != value:
        raise ValueError("selected Case audit must be canonical")
    return controlled


def _controlled_case_binding(value: object) -> M6UpgradeCandidateCaseBinding:
    if type(value) is not M6UpgradeCandidateCaseBinding:
        raise TypeError("selected Case binding must be exact")
    try:
        controlled = M6UpgradeCandidateCaseBinding.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        raise ValueError("selected Case binding must be canonical") from None
    if controlled != value:
        raise ValueError("selected Case binding must be canonical")
    return controlled


def _controlled_observation(value: object) -> M6UpgradeObservedArtifactIdentity:
    if type(value) is not M6UpgradeObservedArtifactIdentity:
        raise TypeError("acquisition observation must be exact")
    try:
        controlled = M6UpgradeObservedArtifactIdentity.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        raise ValueError("acquisition observation must be canonical") from None
    if controlled != value:
        raise ValueError("acquisition observation must be canonical")
    return controlled


def _controlled_tool_result(value: object) -> ToolResult:
    if type(value) is not ToolResult:
        raise TypeError("ToolResult must be exact")
    try:
        controlled = ToolResult.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        raise ValueError("ToolResult must be canonical") from None
    if controlled != value:
        raise ValueError("ToolResult must be canonical")
    return controlled


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionSupportSlot:
    """One body-free commitment to a supporting relational row."""

    route: M6SQLiteAcquisitionSupportRoute
    run_id: str
    case_id: str
    hearing_id: str
    rowid: int
    artifact_id: str
    index_identity_sha256: str

    def __post_init__(self) -> None:
        if type(self.route) is not M6SQLiteAcquisitionSupportRoute:
            raise TypeError("support route must be exact")
        _require_scope_token(self.run_id, "support run_id")
        _require_scope_token(self.case_id, "support case_id")
        _require_sha256(self.hearing_id, "support hearing_id")
        _require_positive_integer(self.rowid, "support rowid")
        if self.route in _OUTPUT_KIND_BY_ROUTE:
            try:
                ArtifactRef(
                    kind=_OUTPUT_KIND_BY_ROUTE[self.route],
                    artifact_id=self.artifact_id,
                )
            except (TypeError, ValueError, ValidationError):
                raise ValueError("output support artifact identity is invalid") from None
        else:
            _require_scope_token(self.artifact_id, "support artifact_id")
        _require_sha256(self.index_identity_sha256, "support index identity")

    @property
    def identity_key(self) -> tuple[M6SQLiteAcquisitionSupportRoute, str]:
        return self.route, self.artifact_id

    @property
    def row_key(self) -> tuple[M6SQLiteAcquisitionSupportRoute, int]:
        return self.route, self.rowid

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return _SUPPORT_ROUTE_RANK[self.route], self.artifact_id, self.rowid


def _controlled_support_slot(value: object) -> M6SQLiteAcquisitionSupportSlot:
    if type(value) is not M6SQLiteAcquisitionSupportSlot:
        raise TypeError("support slot must be exact")
    return M6SQLiteAcquisitionSupportSlot(
        route=value.route,
        run_id=value.run_id,
        case_id=value.case_id,
        hearing_id=value.hearing_id,
        rowid=value.rowid,
        artifact_id=value.artifact_id,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionSupportDocumentSlot:
    """One pre-body commitment to an exact live-reader document column."""

    route: M6SQLiteAcquisitionSupportDocumentRoute
    run_id: str
    case_id: str
    hearing_id: str
    rowid: int
    artifact_id: str
    body_commitment_sha256: str
    document_bytes: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        if type(self.route) is not M6SQLiteAcquisitionSupportDocumentRoute:
            raise TypeError("support document route must be exact")
        _require_scope_token(self.run_id, "support document run_id")
        _require_scope_token(self.case_id, "support document case_id")
        _require_sha256(self.hearing_id, "support document hearing_id")
        _require_positive_integer(self.rowid, "support document rowid")
        _require_scope_token(self.artifact_id, "support document artifact_id")
        _require_sha256(self.body_commitment_sha256, "support body commitment")
        _require_document_bytes(self.document_bytes, "support document length")
        _require_sha256(self.index_identity_sha256, "support document index identity")

    @property
    def row_route(self) -> M6SQLiteAcquisitionSupportRoute:
        return _SUPPORT_DOCUMENT_TO_ROW_ROUTE[self.route]

    @property
    def commitment_kind(self) -> M6SQLiteAcquisitionDocumentCommitmentKind:
        return _SUPPORT_COMMITMENT_KIND[self.route]

    @property
    def identity_key(self) -> tuple[M6SQLiteAcquisitionSupportDocumentRoute, str]:
        return self.route, self.artifact_id

    @property
    def row_key(self) -> tuple[M6SQLiteAcquisitionSupportDocumentRoute, int]:
        return self.route, self.rowid

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return _SUPPORT_DOCUMENT_ROUTE_RANK[self.route], self.artifact_id, self.rowid


def _controlled_support_document_slot(
    value: object,
) -> M6SQLiteAcquisitionSupportDocumentSlot:
    if type(value) is not M6SQLiteAcquisitionSupportDocumentSlot:
        raise TypeError("support document slot must be exact")
    return M6SQLiteAcquisitionSupportDocumentSlot(
        route=value.route,
        run_id=value.run_id,
        case_id=value.case_id,
        hearing_id=value.hearing_id,
        rowid=value.rowid,
        artifact_id=value.artifact_id,
        body_commitment_sha256=value.body_commitment_sha256,
        document_bytes=value.document_bytes,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionCompletedClaimSlot:
    """Completed claim metadata, including both stored request copies."""

    run_id: str
    case_id: str
    hearing_id: str
    rowid: int
    acquisition_request_id: str
    execution_publication_id: str
    execution_mode: AcquisitionExecutionMode
    idempotency_key: str
    owner_token_sha256: str
    owner_fence: int
    status: M6SQLiteAcquisitionClaimState
    request_document_sha256: str
    request_document_bytes: int
    claim_document_sha256: str
    claim_document_bytes: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        _require_scope_token(self.run_id, "claim run_id")
        _require_scope_token(self.case_id, "claim case_id")
        for value, label in (
            (self.hearing_id, "claim hearing_id"),
            (self.acquisition_request_id, "claim request_id"),
            (self.execution_publication_id, "claim publication_id"),
            (self.idempotency_key, "claim idempotency key"),
            (self.owner_token_sha256, "claim owner token digest"),
            (self.request_document_sha256, "claim request document digest"),
            (self.claim_document_sha256, "claim document digest"),
            (self.index_identity_sha256, "claim index identity"),
        ):
            _require_sha256(value, label)
        _require_positive_integer(self.rowid, "claim rowid")
        _require_positive_integer(self.owner_fence, "claim owner fence")
        _require_document_bytes(self.request_document_bytes, "claim request document length")
        _require_document_bytes(self.claim_document_bytes, "claim document length")
        if type(self.execution_mode) is not AcquisitionExecutionMode:
            raise TypeError("claim execution mode must be exact")
        if (
            type(self.status) is not M6SQLiteAcquisitionClaimState
            or self.status != M6SQLiteAcquisitionClaimState.COMPLETED
        ):
            raise ValueError("acquisition plan requires a completed execution claim")
        if self.idempotency_key != self.acquisition_request_id:
            raise ValueError("claim idempotency key must equal the acquisition request")

    @property
    def sort_key(self) -> tuple[str, int]:
        return self.acquisition_request_id, self.rowid


def _controlled_claim_slot(value: object) -> M6SQLiteAcquisitionCompletedClaimSlot:
    if type(value) is not M6SQLiteAcquisitionCompletedClaimSlot:
        raise TypeError("completed claim slot must be exact")
    return M6SQLiteAcquisitionCompletedClaimSlot(
        run_id=value.run_id,
        case_id=value.case_id,
        hearing_id=value.hearing_id,
        rowid=value.rowid,
        acquisition_request_id=value.acquisition_request_id,
        execution_publication_id=value.execution_publication_id,
        execution_mode=value.execution_mode,
        idempotency_key=value.idempotency_key,
        owner_token_sha256=value.owner_token_sha256,
        owner_fence=value.owner_fence,
        status=value.status,
        request_document_sha256=value.request_document_sha256,
        request_document_bytes=value.request_document_bytes,
        claim_document_sha256=value.claim_document_sha256,
        claim_document_bytes=value.claim_document_bytes,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionManifestSlot:
    """Manifest metadata that deterministically creates its only physical ref."""

    run_id: str
    case_id: str
    hearing_id: str
    rowid: int
    execution_manifest_id: str
    acquisition_request_id: str
    action: AcquisitionAction
    component_manifest_id: str
    model_manifest_id: str | None
    manifest_id: str
    document_sha256: str
    document_bytes: int
    index_identity_sha256: str
    physical_ref: M6UpgradePhysicalArtifactRef = field(init=False)

    def __post_init__(self) -> None:
        _require_scope_token(self.run_id, "manifest slot run_id")
        _require_scope_token(self.case_id, "manifest slot case_id")
        for value, label in (
            (self.hearing_id, "manifest slot hearing_id"),
            (self.execution_manifest_id, "execution_manifest_id"),
            (self.acquisition_request_id, "manifest acquisition request_id"),
            (self.component_manifest_id, "component manifest_id"),
            (self.manifest_id, "manifest slot manifest_id"),
            (self.document_sha256, "manifest document_sha256"),
            (self.index_identity_sha256, "manifest index identity"),
        ):
            _require_sha256(value, label)
        _require_positive_integer(self.rowid, "manifest rowid")
        _require_document_bytes(self.document_bytes, "manifest document length")
        if self.model_manifest_id is not None:
            _require_sha256(self.model_manifest_id, "model manifest_id")
        if type(self.action) is not AcquisitionAction:
            raise TypeError("manifest action must be exact")
        try:
            physical_ref = M6UpgradePhysicalArtifactRef(
                source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                kind=M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
                artifact_id=self.execution_manifest_id,
                document_sha256=self.document_sha256,
                content_sha256=self.document_sha256,
                size_bytes=self.document_bytes,
            )
        except (TypeError, ValueError, ValidationError):
            raise ValueError("manifest metadata cannot create its physical ref") from None
        object.__setattr__(self, "physical_ref", physical_ref)

    @property
    def route(self) -> M6SQLiteAcquisitionPhysicalRoute:
        return M6SQLiteAcquisitionPhysicalRoute.TOOL_EXECUTION_MANIFEST

    @property
    def sort_key(self) -> tuple[str, int]:
        return self.execution_manifest_id, self.rowid


def _controlled_manifest_slot(value: object) -> M6SQLiteAcquisitionManifestSlot:
    if type(value) is not M6SQLiteAcquisitionManifestSlot:
        raise TypeError("manifest slot must be exact")
    controlled = M6SQLiteAcquisitionManifestSlot(
        run_id=value.run_id,
        case_id=value.case_id,
        hearing_id=value.hearing_id,
        rowid=value.rowid,
        execution_manifest_id=value.execution_manifest_id,
        acquisition_request_id=value.acquisition_request_id,
        action=value.action,
        component_manifest_id=value.component_manifest_id,
        model_manifest_id=value.model_manifest_id,
        manifest_id=value.manifest_id,
        document_sha256=value.document_sha256,
        document_bytes=value.document_bytes,
        index_identity_sha256=value.index_identity_sha256,
    )
    if controlled != value:
        raise ValueError("manifest slot contains inconsistent derived state")
    return controlled


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionToolResultBinding:
    """One selected-Case ToolResult and its derived canonical physical ref."""

    tool_result: ToolResult
    origin_pack_id: str
    origin_pack_version: int
    document_sha256: str = field(init=False)
    document_bytes: int = field(init=False)
    physical_ref: M6UpgradePhysicalArtifactRef = field(init=False)

    def __post_init__(self) -> None:
        result = _controlled_tool_result(self.tool_result)
        _require_sha256(self.origin_pack_id, "ToolResult origin pack_id")
        _require_positive_integer(self.origin_pack_version, "ToolResult origin pack version")
        _document, digest, size = _canonical_document(result)
        try:
            physical_ref = M6UpgradePhysicalArtifactRef(
                source=M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                kind=M6UpgradePhysicalArtifactKind.TOOL_RESULT,
                artifact_id=result.tool_result_id,
                document_sha256=digest,
                content_sha256=digest,
                size_bytes=size,
            )
        except (TypeError, ValueError, ValidationError):
            raise ValueError("ToolResult cannot create its derived physical ref") from None
        object.__setattr__(self, "tool_result", result)
        object.__setattr__(self, "document_sha256", digest)
        object.__setattr__(self, "document_bytes", size)
        object.__setattr__(self, "physical_ref", physical_ref)

    @property
    def route(self) -> M6SQLiteAcquisitionPhysicalRoute:
        return M6SQLiteAcquisitionPhysicalRoute.TOOL_RESULT

    @property
    def sort_key(self) -> tuple[int, str]:
        return self.origin_pack_version, self.tool_result.tool_result_id


def _controlled_tool_result_binding(value: object) -> M6SQLiteAcquisitionToolResultBinding:
    if type(value) is not M6SQLiteAcquisitionToolResultBinding:
        raise TypeError("ToolResult binding must be exact")
    controlled = M6SQLiteAcquisitionToolResultBinding(
        tool_result=_controlled_tool_result(value.tool_result),
        origin_pack_id=value.origin_pack_id,
        origin_pack_version=value.origin_pack_version,
    )
    if controlled != value:
        raise ValueError("ToolResult binding contains inconsistent derived state")
    return controlled


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionSelectedPackBinding:
    """Canonical selected-Case EvidencePack metadata used by one transition."""

    rowid: int
    pack_id: str
    version: int
    document_sha256: str
    document_bytes: int
    created_audit_sequence: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        _require_positive_integer(self.rowid, "pack rowid")
        _require_sha256(self.pack_id, "pack_id")
        _require_positive_integer(self.version, "pack version")
        _require_sha256(self.document_sha256, "pack document_sha256")
        _require_document_bytes(self.document_bytes, "pack document length")
        _require_non_negative_integer(self.created_audit_sequence, "pack audit sequence")
        _require_sha256(self.index_identity_sha256, "pack index identity")

    @property
    def sort_key(self) -> tuple[int, str]:
        return self.version, self.pack_id


def _controlled_pack_binding(value: object) -> M6SQLiteAcquisitionSelectedPackBinding:
    if type(value) is not M6SQLiteAcquisitionSelectedPackBinding:
        raise TypeError("selected pack binding must be exact")
    return M6SQLiteAcquisitionSelectedPackBinding(
        rowid=value.rowid,
        pack_id=value.pack_id,
        version=value.version,
        document_sha256=value.document_sha256,
        document_bytes=value.document_bytes,
        created_audit_sequence=value.created_audit_sequence,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionPackTransitionBinding:
    """Body-free predecessor/successor and historical Case/audit anchor."""

    previous_pack: M6SQLiteAcquisitionSelectedPackBinding
    resulting_pack: M6SQLiteAcquisitionSelectedPackBinding
    added_tool_result_id: str
    first_occurrence_pack_id: str
    first_occurrence_pack_version: int
    transition_case_revision: int
    transition_case_version_id: str
    transition_audit_sequence: int
    transition_audit_entry_hash: str

    def __post_init__(self) -> None:
        previous = _controlled_pack_binding(self.previous_pack)
        resulting = _controlled_pack_binding(self.resulting_pack)
        object.__setattr__(self, "previous_pack", previous)
        object.__setattr__(self, "resulting_pack", resulting)
        for value, label in (
            (self.added_tool_result_id, "transition ToolResult ID"),
            (self.first_occurrence_pack_id, "first occurrence pack_id"),
            (self.transition_audit_entry_hash, "transition audit entry hash"),
        ):
            _require_sha256(value, label)
        _require_scope_token(self.transition_case_version_id, "transition Case-version ID")
        _require_positive_integer(
            self.first_occurrence_pack_version,
            "first occurrence pack version",
        )
        _require_positive_integer(self.transition_case_revision, "transition Case revision")
        _require_positive_integer(
            self.transition_audit_sequence,
            "transition audit sequence",
        )
        if resulting.version != previous.version + 1 or resulting.pack_id == previous.pack_id:
            raise ValueError("acquisition pack transition must advance exactly one version")
        if (
            self.first_occurrence_pack_id != resulting.pack_id
            or self.first_occurrence_pack_version != resulting.version
        ):
            raise ValueError("ToolResult first occurrence must be the transition successor")
        if resulting.created_audit_sequence != self.transition_audit_sequence:
            raise ValueError("successor pack audit sequence differs from transition authority")

    @property
    def sort_key(self) -> tuple[int, str]:
        return self.resulting_pack.version, self.added_tool_result_id


def _controlled_transition(value: object) -> M6SQLiteAcquisitionPackTransitionBinding:
    if type(value) is not M6SQLiteAcquisitionPackTransitionBinding:
        raise TypeError("pack transition binding must be exact")
    return M6SQLiteAcquisitionPackTransitionBinding(
        previous_pack=_controlled_pack_binding(value.previous_pack),
        resulting_pack=_controlled_pack_binding(value.resulting_pack),
        added_tool_result_id=value.added_tool_result_id,
        first_occurrence_pack_id=value.first_occurrence_pack_id,
        first_occurrence_pack_version=value.first_occurrence_pack_version,
        transition_case_revision=value.transition_case_revision,
        transition_case_version_id=value.transition_case_version_id,
        transition_audit_sequence=value.transition_audit_sequence,
        transition_audit_entry_hash=value.transition_audit_entry_hash,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionUpstreamM4Binding:
    """Identity-only dependency on bodies already budgeted by the M4 plan."""

    upstream_m4_model_plan_identity_sha256: str
    run_id: str
    case_id: str
    hearing_id: str
    hearing_rowid: int
    hearing_support_index_identity_sha256: str
    cycle_scope_id: str
    cycle_scope_sha256: str
    cycle_rowid: int
    cycle_support_index_identity_sha256: str
    judge_output_id: str
    judge_output_document_sha256: str
    judge_output_rowid: int
    judge_output_index_identity_sha256: str

    def __post_init__(self) -> None:
        _require_scope_token(self.run_id, "upstream run_id")
        _require_scope_token(self.case_id, "upstream case_id")
        _require_positive_integer(self.hearing_rowid, "upstream hearing rowid")
        _require_positive_integer(self.cycle_rowid, "upstream cycle rowid")
        _require_positive_integer(self.judge_output_rowid, "upstream Judge output rowid")
        for value, label in (
            (self.upstream_m4_model_plan_identity_sha256, "upstream M4 plan identity"),
            (self.hearing_id, "upstream hearing_id"),
            (self.hearing_support_index_identity_sha256, "hearing support identity"),
            (self.cycle_scope_id, "upstream cycle scope ID"),
            (self.cycle_scope_sha256, "upstream cycle scope digest"),
            (self.cycle_support_index_identity_sha256, "cycle support identity"),
            (self.judge_output_id, "upstream Judge output ID"),
            (self.judge_output_document_sha256, "Judge output document digest"),
            (self.judge_output_index_identity_sha256, "Judge output index identity"),
        ):
            _require_sha256(value, label)

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return self.hearing_id, self.cycle_scope_id, self.judge_output_id


def _controlled_upstream_binding(value: object) -> M6SQLiteAcquisitionUpstreamM4Binding:
    if type(value) is not M6SQLiteAcquisitionUpstreamM4Binding:
        raise TypeError("upstream M4 binding must be exact")
    return M6SQLiteAcquisitionUpstreamM4Binding(
        upstream_m4_model_plan_identity_sha256=(value.upstream_m4_model_plan_identity_sha256),
        run_id=value.run_id,
        case_id=value.case_id,
        hearing_id=value.hearing_id,
        hearing_rowid=value.hearing_rowid,
        hearing_support_index_identity_sha256=(value.hearing_support_index_identity_sha256),
        cycle_scope_id=value.cycle_scope_id,
        cycle_scope_sha256=value.cycle_scope_sha256,
        cycle_rowid=value.cycle_rowid,
        cycle_support_index_identity_sha256=value.cycle_support_index_identity_sha256,
        judge_output_id=value.judge_output_id,
        judge_output_document_sha256=value.judge_output_document_sha256,
        judge_output_rowid=value.judge_output_rowid,
        judge_output_index_identity_sha256=value.judge_output_index_identity_sha256,
    )


def _support_slot_by_route(
    slots: tuple[M6SQLiteAcquisitionSupportSlot, ...],
    route: M6SQLiteAcquisitionSupportRoute,
) -> M6SQLiteAcquisitionSupportSlot | None:
    matches = tuple(slot for slot in slots if slot.route == route)
    if len(matches) > 1:
        raise ValueError("acquisition closure contains a duplicate singleton support route")
    return matches[0] if matches else None


def _support_document_slot_by_route(
    slots: tuple[M6SQLiteAcquisitionSupportDocumentSlot, ...],
    route: M6SQLiteAcquisitionSupportDocumentRoute,
) -> M6SQLiteAcquisitionSupportDocumentSlot | None:
    matches = tuple(slot for slot in slots if slot.route == route)
    if len(matches) > 1:
        raise ValueError("acquisition closure contains a duplicate singleton document route")
    return matches[0] if matches else None


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionClosurePlan:
    """One distinct ToolResult and its complete metadata-only acquisition closure."""

    run_id: str
    case_id: str
    manifest_id: str
    acquisition_request_id: str
    execution_publication_id: str
    tool_receipt_id: str
    derivation_id: str
    checkpoint_id: str
    round_id: str | None
    upstream_m4: M6SQLiteAcquisitionUpstreamM4Binding
    manifest: M6SQLiteAcquisitionManifestSlot
    claim: M6SQLiteAcquisitionCompletedClaimSlot
    tool_result: M6SQLiteAcquisitionToolResultBinding
    pack_transition: M6SQLiteAcquisitionPackTransitionBinding
    support_slots: tuple[M6SQLiteAcquisitionSupportSlot, ...]
    support_document_slots: tuple[M6SQLiteAcquisitionSupportDocumentSlot, ...]

    def __post_init__(self) -> None:
        _require_scope_token(self.run_id, "closure run_id")
        _require_scope_token(self.case_id, "closure case_id")
        for value, label in (
            (self.manifest_id, "closure manifest_id"),
            (self.acquisition_request_id, "closure acquisition request_id"),
            (self.execution_publication_id, "closure publication_id"),
            (self.tool_receipt_id, "closure receipt_id"),
            (self.derivation_id, "closure derivation_id"),
            (self.checkpoint_id, "closure checkpoint_id"),
        ):
            _require_sha256(value, label)
        if self.round_id is not None:
            _require_sha256(self.round_id, "closure round_id")

        upstream = _controlled_upstream_binding(self.upstream_m4)
        manifest = _controlled_manifest_slot(self.manifest)
        claim = _controlled_claim_slot(self.claim)
        result = _controlled_tool_result_binding(self.tool_result)
        transition = _controlled_transition(self.pack_transition)
        if type(self.support_slots) is not tuple or any(
            type(value) is not M6SQLiteAcquisitionSupportSlot for value in self.support_slots
        ):
            raise TypeError("closure support slots must be an exact tuple")
        if type(self.support_document_slots) is not tuple or any(
            type(value) is not M6SQLiteAcquisitionSupportDocumentSlot
            for value in self.support_document_slots
        ):
            raise TypeError("closure support document slots must be an exact tuple")
        support = tuple(_controlled_support_slot(value) for value in self.support_slots)
        support_documents = tuple(
            _controlled_support_document_slot(value) for value in self.support_document_slots
        )
        if support != tuple(sorted(support, key=lambda value: value.sort_key)):
            raise ValueError("closure support slots must use stable order")
        if support_documents != tuple(sorted(support_documents, key=lambda value: value.sort_key)):
            raise ValueError("closure support document slots must use stable order")
        if (
            len({slot.identity_key for slot in support}) != len(support)
            or len({slot.row_key for slot in support}) != len(support)
            or len({slot.index_identity_sha256 for slot in support}) != len(support)
        ):
            raise ValueError("closure support slots must be unique")
        if (
            len({slot.identity_key for slot in support_documents}) != len(support_documents)
            or len({slot.row_key for slot in support_documents}) != len(support_documents)
            or len({slot.index_identity_sha256 for slot in support_documents})
            != len(support_documents)
        ):
            raise ValueError("closure support document slots must be unique")
        object.__setattr__(self, "upstream_m4", upstream)
        object.__setattr__(self, "manifest", manifest)
        object.__setattr__(self, "claim", claim)
        object.__setattr__(self, "tool_result", result)
        object.__setattr__(self, "pack_transition", transition)
        object.__setattr__(self, "support_slots", support)
        object.__setattr__(self, "support_document_slots", support_documents)

        scopes = (
            (upstream.run_id, upstream.case_id),
            (manifest.run_id, manifest.case_id),
            (claim.run_id, claim.case_id),
            *((slot.run_id, slot.case_id) for slot in support),
            *((slot.run_id, slot.case_id) for slot in support_documents),
        )
        if any(scope != (self.run_id, self.case_id) for scope in scopes):
            raise ValueError("acquisition closure crosses its run or Case scope")
        if (
            manifest.manifest_id != self.manifest_id
            or manifest.hearing_id != upstream.hearing_id
            or claim.hearing_id != upstream.hearing_id
            or any(slot.hearing_id != upstream.hearing_id for slot in support)
            or any(slot.hearing_id != upstream.hearing_id for slot in support_documents)
        ):
            raise ValueError("acquisition closure crosses its hearing or manifest scope")
        if (
            manifest.acquisition_request_id != self.acquisition_request_id
            or claim.acquisition_request_id != self.acquisition_request_id
            or claim.execution_publication_id != self.execution_publication_id
            or result.tool_result.execution_manifest_id != manifest.execution_manifest_id
            or result.tool_result.action != manifest.action
            or transition.added_tool_result_id != result.tool_result.tool_result_id
            or transition.first_occurrence_pack_id != result.origin_pack_id
            or transition.first_occurrence_pack_version != result.origin_pack_version
        ):
            raise ValueError("acquisition closure identities do not join exactly")

        required_ids = {
            M6SQLiteAcquisitionSupportRoute.ACQUISITION_REQUEST: (self.acquisition_request_id),
            M6SQLiteAcquisitionSupportRoute.EXECUTION_PUBLICATION: (self.execution_publication_id),
            M6SQLiteAcquisitionSupportRoute.TOOL_EXECUTION_RECEIPT: self.tool_receipt_id,
            M6SQLiteAcquisitionSupportRoute.EVIDENCE_PACK_DERIVATION: self.derivation_id,
            M6SQLiteAcquisitionSupportRoute.HEARING_CHECKPOINT: self.checkpoint_id,
            M6SQLiteAcquisitionSupportRoute.CASE_VERSION: (transition.transition_case_version_id),
            M6SQLiteAcquisitionSupportRoute.AUDIT_ENTRY: (transition.transition_audit_entry_hash),
        }
        for route, artifact_id in required_ids.items():
            slot = _support_slot_by_route(support, route)
            if slot is None or slot.artifact_id != artifact_id:
                raise ValueError("acquisition closure is missing an exact mandatory support")
        round_slot = _support_slot_by_route(
            support,
            M6SQLiteAcquisitionSupportRoute.HEARING_ROUND,
        )
        if (self.round_id is None) != (round_slot is None) or (
            round_slot is not None and round_slot.artifact_id != self.round_id
        ):
            raise ValueError("optional hearing round support differs from closure metadata")

        expected_outputs = {
            (_OUTPUT_ROUTE_BY_KIND[ref.kind], ref.artifact_id)
            for ref in result.tool_result.output_refs
            if ref.kind in _OUTPUT_ROUTE_BY_KIND
        }
        actual_outputs = {
            slot.identity_key
            for slot in support
            if slot.route in set(_OUTPUT_ROUTE_BY_KIND.values())
        }
        if actual_outputs != expected_outputs:
            raise ValueError("output authority support differs from ToolResult output refs")
        allowed_routes = _MANDATORY_SUPPORT_ROUTES | frozenset(
            {
                M6SQLiteAcquisitionSupportRoute.HEARING_ROUND,
                *set(_OUTPUT_ROUTE_BY_KIND.values()),
            }
        )
        if any(slot.route not in allowed_routes for slot in support):
            raise ValueError("acquisition closure contains an unsupported support route")
        document_rows = {
            (slot.route, slot.rowid, slot.artifact_id, slot.index_identity_sha256)
            for slot in support
            if slot.route not in set(_OUTPUT_ROUTE_BY_KIND.values())
        }
        document_bodies = {
            (
                slot.row_route,
                slot.rowid,
                slot.artifact_id,
                slot.index_identity_sha256,
            )
            for slot in support_documents
        }
        if document_rows != document_bodies:
            raise ValueError("document-bearing support rows and bodies must close exactly")
        request_document = _support_document_slot_by_route(
            support_documents,
            M6SQLiteAcquisitionSupportDocumentRoute.ACQUISITION_REQUEST,
        )
        assert request_document is not None
        if (
            request_document.body_commitment_sha256 != claim.request_document_sha256
            or request_document.document_bytes != claim.request_document_bytes
        ):
            raise ValueError("claim request copy differs from acquisition request metadata")

        predecessor_ref = ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=transition.previous_pack.pack_id,
        )
        predecessor_refs = tuple(
            ref for ref in result.tool_result.input_refs if ref.kind == ArtifactKind.EVIDENCE_PACK
        )
        if predecessor_refs != (predecessor_ref,):
            raise ValueError("ToolResult does not bind the transition predecessor pack")

    @property
    def artifact_refs(self) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        return tuple(
            sorted(
                (self.manifest.physical_ref, self.tool_result.physical_ref),
                key=lambda value: value.sort_key,
            )
        )

    @property
    def sort_key(self) -> tuple[int, str]:
        return self.tool_result.sort_key


def _controlled_closure(value: object) -> M6SQLiteAcquisitionClosurePlan:
    if type(value) is not M6SQLiteAcquisitionClosurePlan:
        raise TypeError("acquisition closure must be exact")
    return M6SQLiteAcquisitionClosurePlan(
        run_id=value.run_id,
        case_id=value.case_id,
        manifest_id=value.manifest_id,
        acquisition_request_id=value.acquisition_request_id,
        execution_publication_id=value.execution_publication_id,
        tool_receipt_id=value.tool_receipt_id,
        derivation_id=value.derivation_id,
        checkpoint_id=value.checkpoint_id,
        round_id=value.round_id,
        upstream_m4=_controlled_upstream_binding(value.upstream_m4),
        manifest=_controlled_manifest_slot(value.manifest),
        claim=_controlled_claim_slot(value.claim),
        tool_result=_controlled_tool_result_binding(value.tool_result),
        pack_transition=_controlled_transition(value.pack_transition),
        support_slots=tuple(_controlled_support_slot(slot) for slot in value.support_slots),
        support_document_slots=tuple(
            _controlled_support_document_slot(slot) for slot in value.support_document_slots
        ),
    )


def _pack_document(pack: EvidencePack) -> tuple[str, int]:
    _document, digest, size = _canonical_document(pack)
    return digest, size


def _unique_pack_bindings(
    closures: tuple[M6SQLiteAcquisitionClosurePlan, ...],
) -> tuple[M6SQLiteAcquisitionSelectedPackBinding, ...]:
    by_id: dict[str, M6SQLiteAcquisitionSelectedPackBinding] = {}
    for closure in closures:
        for binding in (
            closure.pack_transition.previous_pack,
            closure.pack_transition.resulting_pack,
        ):
            existing = by_id.get(binding.pack_id)
            if existing is not None and existing != binding:
                raise ValueError("the same selected pack has conflicting metadata bindings")
            by_id[binding.pack_id] = binding
    values = tuple(sorted(by_id.values(), key=lambda value: value.sort_key))
    if (
        len({value.rowid for value in values}) != len(values)
        or len({value.version for value in values}) != len(values)
        or len({value.index_identity_sha256 for value in values}) != len(values)
    ):
        raise ValueError("selected pack metadata bindings must be globally unique")
    return values


def _unique_support_slots(
    closures: tuple[M6SQLiteAcquisitionClosurePlan, ...],
) -> tuple[M6SQLiteAcquisitionSupportSlot, ...]:
    by_identity: dict[
        tuple[M6SQLiteAcquisitionSupportRoute, str],
        M6SQLiteAcquisitionSupportSlot,
    ] = {}
    row_owners: dict[
        tuple[M6SQLiteAcquisitionSupportRoute, int],
        tuple[M6SQLiteAcquisitionSupportRoute, str],
    ] = {}
    index_owners: dict[str, tuple[M6SQLiteAcquisitionSupportRoute, str]] = {}
    for closure in closures:
        for slot in closure.support_slots:
            key = slot.identity_key
            existing = by_identity.get(key)
            if existing is not None and existing != slot:
                raise ValueError("shared support identity has conflicting metadata")
            row_owner = row_owners.setdefault(slot.row_key, key)
            index_owner = index_owners.setdefault(slot.index_identity_sha256, key)
            if row_owner != key or index_owner != key:
                raise ValueError("support rows or index identities cross acquisition documents")
            by_identity[key] = slot
    return tuple(sorted(by_identity.values(), key=lambda value: value.sort_key))


def _unique_support_document_slots(
    closures: tuple[M6SQLiteAcquisitionClosurePlan, ...],
) -> tuple[M6SQLiteAcquisitionSupportDocumentSlot, ...]:
    by_identity: dict[
        tuple[M6SQLiteAcquisitionSupportDocumentRoute, str],
        M6SQLiteAcquisitionSupportDocumentSlot,
    ] = {}
    row_owners: dict[
        tuple[M6SQLiteAcquisitionSupportDocumentRoute, int],
        tuple[M6SQLiteAcquisitionSupportDocumentRoute, str],
    ] = {}
    index_owners: dict[str, tuple[M6SQLiteAcquisitionSupportDocumentRoute, str]] = {}
    for closure in closures:
        for slot in closure.support_document_slots:
            key = slot.identity_key
            existing = by_identity.get(key)
            if existing is not None and existing != slot:
                raise ValueError("shared support document has conflicting metadata")
            row_owner = row_owners.setdefault(slot.row_key, key)
            index_owner = index_owners.setdefault(slot.index_identity_sha256, key)
            if row_owner != key or index_owner != key:
                raise ValueError("support document rows or indexes cross authority bodies")
            by_identity[key] = slot
    return tuple(sorted(by_identity.values(), key=lambda value: value.sort_key))


def _validate_upstream_m4_bindings(
    closures: tuple[M6SQLiteAcquisitionClosurePlan, ...],
) -> None:
    hearing_by_id: dict[str, tuple[int, str]] = {}
    cycle_by_id: dict[str, tuple[str, int, str]] = {}
    judge_by_id: dict[str, tuple[str, int, str]] = {}
    hearing_row_owners: dict[int, str] = {}
    cycle_row_owners: dict[int, str] = {}
    judge_row_owners: dict[int, str] = {}
    hearing_index_owners: dict[str, str] = {}
    cycle_index_owners: dict[str, str] = {}
    judge_index_owners: dict[str, str] = {}
    for closure in closures:
        binding = closure.upstream_m4
        hearing_metadata = (
            binding.hearing_rowid,
            binding.hearing_support_index_identity_sha256,
        )
        cycle_metadata = (
            binding.cycle_scope_sha256,
            binding.cycle_rowid,
            binding.cycle_support_index_identity_sha256,
        )
        judge_metadata = (
            binding.judge_output_document_sha256,
            binding.judge_output_rowid,
            binding.judge_output_index_identity_sha256,
        )
        if (
            hearing_by_id.setdefault(binding.hearing_id, hearing_metadata) != hearing_metadata
            or cycle_by_id.setdefault(binding.cycle_scope_id, cycle_metadata) != cycle_metadata
            or judge_by_id.setdefault(binding.judge_output_id, judge_metadata) != judge_metadata
        ):
            raise ValueError("shared upstream M4 identity has conflicting metadata")
        if (
            hearing_row_owners.setdefault(binding.hearing_rowid, binding.hearing_id)
            != binding.hearing_id
            or cycle_row_owners.setdefault(binding.cycle_rowid, binding.cycle_scope_id)
            != binding.cycle_scope_id
            or judge_row_owners.setdefault(
                binding.judge_output_rowid,
                binding.judge_output_id,
            )
            != binding.judge_output_id
            or hearing_index_owners.setdefault(
                binding.hearing_support_index_identity_sha256,
                binding.hearing_id,
            )
            != binding.hearing_id
            or cycle_index_owners.setdefault(
                binding.cycle_support_index_identity_sha256,
                binding.cycle_scope_id,
            )
            != binding.cycle_scope_id
            or judge_index_owners.setdefault(
                binding.judge_output_index_identity_sha256,
                binding.judge_output_id,
            )
            != binding.judge_output_id
        ):
            raise ValueError("upstream M4 rows or indexes cross authority identities")


def _plan_projection(plan: M6SQLiteAcquisitionDocumentsPlan) -> list[object]:
    return [
        "m6-sqlite-acquisition-documents-plan",
        1,
        plan.run_id,
        plan.case_id,
        plan.manifest_id,
        plan.upstream_m4_model_plan_identity_sha256,
        plan.selected_case_binding.model_dump(mode="json"),
        plan.selected_case.model_dump(mode="json"),
        plan.selected_case_revision,
        plan.selected_case_audit.model_dump(mode="json"),
        [item.model_dump(mode="json") for item in plan.observed_artifacts],
        [
            [
                closure.run_id,
                closure.case_id,
                closure.manifest_id,
                closure.acquisition_request_id,
                closure.execution_publication_id,
                closure.tool_receipt_id,
                closure.derivation_id,
                closure.checkpoint_id,
                closure.round_id,
                [
                    closure.upstream_m4.upstream_m4_model_plan_identity_sha256,
                    closure.upstream_m4.run_id,
                    closure.upstream_m4.case_id,
                    closure.upstream_m4.hearing_id,
                    closure.upstream_m4.hearing_rowid,
                    closure.upstream_m4.hearing_support_index_identity_sha256,
                    closure.upstream_m4.cycle_scope_id,
                    closure.upstream_m4.cycle_scope_sha256,
                    closure.upstream_m4.cycle_rowid,
                    closure.upstream_m4.cycle_support_index_identity_sha256,
                    closure.upstream_m4.judge_output_id,
                    closure.upstream_m4.judge_output_document_sha256,
                    closure.upstream_m4.judge_output_rowid,
                    closure.upstream_m4.judge_output_index_identity_sha256,
                ],
                [
                    closure.manifest.run_id,
                    closure.manifest.case_id,
                    closure.manifest.hearing_id,
                    closure.manifest.rowid,
                    closure.manifest.execution_manifest_id,
                    closure.manifest.acquisition_request_id,
                    closure.manifest.action,
                    closure.manifest.component_manifest_id,
                    closure.manifest.model_manifest_id,
                    closure.manifest.manifest_id,
                    closure.manifest.document_sha256,
                    closure.manifest.document_bytes,
                    closure.manifest.index_identity_sha256,
                    closure.manifest.physical_ref.model_dump(mode="json"),
                ],
                [
                    closure.claim.run_id,
                    closure.claim.case_id,
                    closure.claim.hearing_id,
                    closure.claim.rowid,
                    closure.claim.acquisition_request_id,
                    closure.claim.execution_publication_id,
                    closure.claim.execution_mode,
                    closure.claim.idempotency_key,
                    closure.claim.owner_token_sha256,
                    closure.claim.owner_fence,
                    closure.claim.status,
                    closure.claim.request_document_sha256,
                    closure.claim.request_document_bytes,
                    closure.claim.claim_document_sha256,
                    closure.claim.claim_document_bytes,
                    closure.claim.index_identity_sha256,
                ],
                [
                    closure.tool_result.tool_result.model_dump(mode="json"),
                    closure.tool_result.origin_pack_id,
                    closure.tool_result.origin_pack_version,
                    closure.tool_result.document_sha256,
                    closure.tool_result.document_bytes,
                    closure.tool_result.physical_ref.model_dump(mode="json"),
                ],
                [
                    [
                        closure.pack_transition.previous_pack.rowid,
                        closure.pack_transition.previous_pack.pack_id,
                        closure.pack_transition.previous_pack.version,
                        closure.pack_transition.previous_pack.document_sha256,
                        closure.pack_transition.previous_pack.document_bytes,
                        closure.pack_transition.previous_pack.created_audit_sequence,
                        closure.pack_transition.previous_pack.index_identity_sha256,
                    ],
                    [
                        closure.pack_transition.resulting_pack.rowid,
                        closure.pack_transition.resulting_pack.pack_id,
                        closure.pack_transition.resulting_pack.version,
                        closure.pack_transition.resulting_pack.document_sha256,
                        closure.pack_transition.resulting_pack.document_bytes,
                        closure.pack_transition.resulting_pack.created_audit_sequence,
                        closure.pack_transition.resulting_pack.index_identity_sha256,
                    ],
                    closure.pack_transition.added_tool_result_id,
                    closure.pack_transition.first_occurrence_pack_id,
                    closure.pack_transition.first_occurrence_pack_version,
                    closure.pack_transition.transition_case_revision,
                    closure.pack_transition.transition_case_version_id,
                    closure.pack_transition.transition_audit_sequence,
                    closure.pack_transition.transition_audit_entry_hash,
                ],
                [
                    [
                        slot.route,
                        slot.run_id,
                        slot.case_id,
                        slot.hearing_id,
                        slot.rowid,
                        slot.artifact_id,
                        slot.index_identity_sha256,
                    ]
                    for slot in closure.support_slots
                ],
                [
                    [
                        slot.route,
                        slot.row_route,
                        slot.run_id,
                        slot.case_id,
                        slot.hearing_id,
                        slot.rowid,
                        slot.artifact_id,
                        slot.commitment_kind,
                        slot.body_commitment_sha256,
                        slot.document_bytes,
                        slot.index_identity_sha256,
                    ]
                    for slot in closure.support_document_slots
                ],
            ]
            for closure in plan.closures
        ],
        plan.planned_support_bytes,
        plan.planned_document_bytes,
        plan.planned_physical_bytes,
    ]


def _plan_digest(plan: M6SQLiteAcquisitionDocumentsPlan) -> str:
    return hashlib.sha256(canonical_json(_plan_projection(plan)).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionDocumentsPlan:
    """Complete, bounded, metadata-only acquisition closure for one selected Case."""

    run_id: str
    case_id: str
    manifest_id: str
    upstream_m4_model_plan_identity_sha256: str
    selected_case_binding: M6UpgradeCandidateCaseBinding
    selected_case: Case
    selected_case_revision: int
    selected_case_audit: AuditEntry
    observed_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...]
    closures: tuple[M6SQLiteAcquisitionClosurePlan, ...]
    support_slots: tuple[M6SQLiteAcquisitionSupportSlot, ...] = field(init=False)
    support_document_slots: tuple[M6SQLiteAcquisitionSupportDocumentSlot, ...] = field(init=False)
    selected_pack_bindings: tuple[M6SQLiteAcquisitionSelectedPackBinding, ...] = field(init=False)
    planned_artifact_refs: tuple[M6UpgradePhysicalArtifactRef, ...] = field(init=False)
    planned_support_bytes: int = field(init=False)
    planned_document_bytes: int = field(init=False)
    planned_physical_bytes: int = field(init=False)
    plan_identity_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_scope_token(self.run_id, "plan run_id")
        _require_scope_token(self.case_id, "plan case_id")
        _require_sha256(self.manifest_id, "plan manifest_id")
        _require_sha256(
            self.upstream_m4_model_plan_identity_sha256,
            "upstream M4 model plan identity",
        )
        binding = _controlled_case_binding(self.selected_case_binding)
        selected_case = _controlled_case(self.selected_case)
        audit = _controlled_audit(self.selected_case_audit)
        _require_positive_integer(self.selected_case_revision, "selected Case revision")
        _case_document, case_sha256, _case_bytes = _canonical_document(selected_case)
        if (
            selected_case.run_id != self.run_id
            or selected_case.case_id != self.case_id
            or selected_case.manifest_id != self.manifest_id
            or binding.case_id != self.case_id
            or binding.case_revision != self.selected_case_revision
            or binding.case_document_sha256 != case_sha256
            or audit.run_id != self.run_id
            or audit.manifest_id != self.manifest_id
            or audit.sequence != binding.case_audit_sequence
            or audit.entry_hash != binding.case_audit_entry_hash
            or audit.after_sha256 != case_sha256
        ):
            raise ValueError("plan binding does not identify the selected Case document")
        object.__setattr__(self, "selected_case_binding", binding)
        object.__setattr__(self, "selected_case", selected_case)
        object.__setattr__(self, "selected_case_audit", audit)

        if type(self.observed_artifacts) is not tuple or any(
            type(value) is not M6UpgradeObservedArtifactIdentity
            for value in self.observed_artifacts
        ):
            raise TypeError("observed acquisition artifacts must be an exact tuple")
        if type(self.closures) is not tuple or any(
            type(value) is not M6SQLiteAcquisitionClosurePlan for value in self.closures
        ):
            raise TypeError("acquisition closures must be an exact tuple")
        observations = tuple(_controlled_observation(value) for value in self.observed_artifacts)
        closures = tuple(_controlled_closure(value) for value in self.closures)
        if observations != tuple(sorted(observations, key=lambda value: value.sort_key)):
            raise ValueError("acquisition observations must use stable physical order")
        if closures != tuple(sorted(closures, key=lambda value: value.sort_key)):
            raise ValueError("acquisition closures must use first-occurrence order")
        if len(closures) > MAX_M6_SQLITE_ACQUISITION_ITEMS:
            raise ValueError("acquisition closure count exceeds the frozen replay limit")
        if any(
            observation.source != M6UpgradePhysicalArtifactSource.M4_ACQUISITION
            or observation.kind not in _ACQUISITION_KINDS
            or observation.usage != M6UpgradeArtifactUsage.PRODUCED
            for observation in observations
        ):
            raise ValueError("acquisition observations contain an illegal route or usage")
        observation_keys = tuple(value.identity_key for value in observations)
        if len(observation_keys) != len(set(observation_keys)):
            raise ValueError("acquisition observations must be unique")
        object.__setattr__(self, "observed_artifacts", observations)
        object.__setattr__(self, "closures", closures)

        identities = (
            tuple(closure.acquisition_request_id for closure in closures),
            tuple(closure.execution_publication_id for closure in closures),
            tuple(closure.tool_receipt_id for closure in closures),
            tuple(closure.derivation_id for closure in closures),
            tuple(closure.manifest.execution_manifest_id for closure in closures),
            tuple(closure.tool_result.tool_result.tool_result_id for closure in closures),
        )
        if any(len(values) != len(set(values)) for values in identities):
            raise ValueError("acquisition closure identities must be globally unique")
        if any(
            closure.run_id != self.run_id
            or closure.case_id != self.case_id
            or closure.manifest_id != self.manifest_id
            or closure.upstream_m4.upstream_m4_model_plan_identity_sha256
            != self.upstream_m4_model_plan_identity_sha256
            for closure in closures
        ):
            raise ValueError("acquisition closure crosses its plan or upstream M4 scope")
        _validate_upstream_m4_bindings(closures)

        packs_by_id = {pack.pack_id: pack for pack in selected_case.evidence_packs}
        packs_by_version = {pack.version: pack for pack in selected_case.evidence_packs}
        if len(packs_by_id) != len(selected_case.evidence_packs) or len(packs_by_version) != len(
            selected_case.evidence_packs
        ):
            raise ValueError("selected Case packs must have unique identities and versions")
        result_occurrences: dict[str, list[tuple[EvidencePack, ToolResult]]] = {}
        for pack in selected_case.evidence_packs:
            for result in pack.tool_results:
                result_occurrences.setdefault(result.tool_result_id, []).append((pack, result))
        expected_results: dict[str, tuple[EvidencePack, ToolResult]] = {}
        for result_id, occurrences in result_occurrences.items():
            first_pack, first_result = min(occurrences, key=lambda value: value[0].version)
            if any(result != first_result for _pack, result in occurrences):
                raise ValueError("selected Case rewrites a historical ToolResult")
            expected_versions = tuple(
                pack.version
                for pack in selected_case.evidence_packs
                if pack.version >= first_pack.version
            )
            actual_versions = tuple(pack.version for pack, _result in occurrences)
            if actual_versions != expected_versions:
                raise ValueError("selected Case ToolResult history is not cumulative")
            expected_results[result_id] = (first_pack, first_result)
        closure_results = {
            closure.tool_result.tool_result.tool_result_id: closure for closure in closures
        }
        if set(closure_results) != set(expected_results):
            raise ValueError("acquisition closures do not exactly cover selected Case ToolResults")

        for result_id, closure in closure_results.items():
            first_pack, selected_result = expected_results[result_id]
            transition = closure.pack_transition
            predecessor = packs_by_version.get(first_pack.version - 1)
            if predecessor is None:
                raise ValueError("acquisition ToolResult has no selected-Case predecessor pack")
            if (
                closure.tool_result.tool_result != selected_result
                or closure.tool_result.origin_pack_id != first_pack.pack_id
                or closure.tool_result.origin_pack_version != first_pack.version
                or transition.previous_pack.pack_id != predecessor.pack_id
                or transition.previous_pack.version != predecessor.version
                or transition.resulting_pack.pack_id != first_pack.pack_id
                or transition.resulting_pack.version != first_pack.version
                or result_id in {item.tool_result_id for item in predecessor.tool_results}
                or {item.tool_result_id for item in first_pack.tool_results}
                != {item.tool_result_id for item in predecessor.tool_results} | {result_id}
            ):
                raise ValueError("pack transition differs from ToolResult first occurrence")
            previous_results = {item.tool_result_id: item for item in predecessor.tool_results}
            if any(
                {item.tool_result_id: item for item in first_pack.tool_results}.get(item_id) != item
                for item_id, item in previous_results.items()
            ):
                raise ValueError("acquisition transition rewrites an earlier ToolResult")
            objective_output_ids = {
                ref.artifact_id
                for ref in selected_result.output_refs
                if ref.kind == ArtifactKind.OBJECTIVE_FACT
            }
            if objective_output_ids - {fact.fact_id for fact in first_pack.objective_facts}:
                raise ValueError("ToolResult objective outputs are absent from the result pack")
            for pack_binding in (transition.previous_pack, transition.resulting_pack):
                embedded = packs_by_id.get(pack_binding.pack_id)
                if embedded is None:
                    raise ValueError("pack transition references a pack outside selected Case")
                digest, size = _pack_document(embedded)
                if (
                    embedded.version != pack_binding.version
                    or digest != pack_binding.document_sha256
                    or size != pack_binding.document_bytes
                    or pack_binding.created_audit_sequence > audit.sequence
                ):
                    raise ValueError("pack metadata binding differs from selected Case authority")
            if (
                transition.transition_case_revision > self.selected_case_revision
                or transition.transition_audit_sequence > audit.sequence
            ):
                raise ValueError("pack transition occurs after the selected Case cut")

        support = _unique_support_slots(closures)
        support_documents = _unique_support_document_slots(closures)
        if len(support) > MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS:
            raise ValueError("acquisition relational support exceeds its total row limit")
        for route in M6SQLiteAcquisitionSupportRoute:
            if (
                sum(slot.route == route for slot in support)
                > MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE
            ):
                raise ValueError("acquisition relational support exceeds its per-route limit")
        pack_bindings = _unique_pack_bindings(closures)
        if len(pack_bindings) > MAX_M6_SQLITE_ACQUISITION_SELECTED_PACKS:
            raise ValueError("acquisition selected-pack inventory exceeds its bounded maximum")
        refs = tuple(
            sorted(
                (ref for closure in closures for ref in closure.artifact_refs),
                key=lambda value: value.sort_key,
            )
        )
        if len({ref.physical_key for ref in refs}) != len(refs) or len(
            {ref.artifact_ref_id for ref in refs}
        ) != len(refs):
            raise ValueError("acquisition physical refs must be globally unique")
        expected_observations = tuple(
            sorted(
                (
                    M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                    ref.kind,
                    ref.artifact_id,
                )
                for ref in refs
            )
        )
        if tuple(sorted(observation_keys)) != expected_observations:
            raise ValueError("planned acquisition refs and observations are not an exact set")

        claim_slots = tuple(closure.claim for closure in closures)
        manifest_slots = tuple(closure.manifest for closure in closures)
        if (
            len({slot.rowid for slot in claim_slots}) != len(claim_slots)
            or len({slot.index_identity_sha256 for slot in claim_slots}) != len(claim_slots)
            or len({slot.rowid for slot in manifest_slots}) != len(manifest_slots)
            or len({slot.index_identity_sha256 for slot in manifest_slots}) != len(manifest_slots)
        ):
            raise ValueError("claim or manifest metadata slots must be globally unique")

        support_bytes = (
            sum(slot.document_bytes for slot in support_documents)
            + sum(slot.request_document_bytes + slot.claim_document_bytes for slot in claim_slots)
            + sum(slot.document_bytes for slot in pack_bindings)
        )
        document_bytes = support_bytes + sum(slot.document_bytes for slot in manifest_slots)
        physical_bytes = sum(ref.size_bytes for ref in refs)
        if support_bytes > MAX_M6_SQLITE_ACQUISITION_SUPPORT_TOTAL_BYTES:
            raise ValueError("acquisition support documents exceed their total budget")
        if document_bytes > MAX_M6_SQLITE_ACQUISITION_DOCUMENT_TOTAL_BYTES:
            raise ValueError("acquisition planned documents exceed their total budget")
        if physical_bytes > MAX_M6_SQLITE_ACQUISITION_PHYSICAL_TOTAL_BYTES:
            raise ValueError("acquisition physical refs exceed the sample budget")

        object.__setattr__(self, "support_slots", support)
        object.__setattr__(self, "support_document_slots", support_documents)
        object.__setattr__(self, "selected_pack_bindings", pack_bindings)
        object.__setattr__(self, "planned_artifact_refs", refs)
        object.__setattr__(self, "planned_support_bytes", support_bytes)
        object.__setattr__(self, "planned_document_bytes", document_bytes)
        object.__setattr__(self, "planned_physical_bytes", physical_bytes)
        object.__setattr__(self, "plan_identity_sha256", _plan_digest(self))


def _plan_is_consistent(value: object) -> bool:
    if type(value) is not M6SQLiteAcquisitionDocumentsPlan:
        return False
    try:
        controlled = M6SQLiteAcquisitionDocumentsPlan(
            run_id=value.run_id,
            case_id=value.case_id,
            manifest_id=value.manifest_id,
            upstream_m4_model_plan_identity_sha256=(value.upstream_m4_model_plan_identity_sha256),
            selected_case_binding=value.selected_case_binding,
            selected_case=value.selected_case,
            selected_case_revision=value.selected_case_revision,
            selected_case_audit=value.selected_case_audit,
            observed_artifacts=value.observed_artifacts,
            closures=value.closures,
        )
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        return False
    return controlled == value and value.plan_identity_sha256 == _plan_digest(value)


__all__ = [
    "MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_ACQUISITION_DOCUMENT_TOTAL_BYTES",
    "MAX_M6_SQLITE_ACQUISITION_ITEMS",
    "MAX_M6_SQLITE_ACQUISITION_PHYSICAL_TOTAL_BYTES",
    "MAX_M6_SQLITE_ACQUISITION_SELECTED_PACKS",
    "MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS",
    "MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE",
    "MAX_M6_SQLITE_ACQUISITION_SUPPORT_TOTAL_BYTES",
    "M6SQLiteAcquisitionClaimState",
    "M6SQLiteAcquisitionClosurePlan",
    "M6SQLiteAcquisitionCompletedClaimSlot",
    "M6SQLiteAcquisitionDocumentCommitmentKind",
    "M6SQLiteAcquisitionDocumentsPlan",
    "M6SQLiteAcquisitionManifestSlot",
    "M6SQLiteAcquisitionPackTransitionBinding",
    "M6SQLiteAcquisitionPhysicalRoute",
    "M6SQLiteAcquisitionPlanFailureCode",
    "M6SQLiteAcquisitionSelectedPackBinding",
    "M6SQLiteAcquisitionSupportDocumentRoute",
    "M6SQLiteAcquisitionSupportDocumentSlot",
    "M6SQLiteAcquisitionSupportRoute",
    "M6SQLiteAcquisitionSupportSlot",
    "M6SQLiteAcquisitionToolResultBinding",
    "M6SQLiteAcquisitionUpstreamM4Binding",
]
