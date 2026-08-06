"""Pure contracts for bounded same-snapshot M4 model metadata plans.

This first contract slice deliberately contains no SQLite access.  It freezes
the row, column, hash, length, and physical-reference identities that a later
metadata reader may emit before any canonical document or raw response body is
read.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import ValidationError

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ModelParseStatus
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_execution_observation import M6UpgradeObservedModelCall
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token

MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP = 256
MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_M6_SQLITE_M4_MODEL_PHYSICAL_TOTAL_BYTES = 256 * 1024 * 1024


class M6SQLiteM4ModelDocumentFailureCode(StrEnum):
    """Closed, payload-free failures for M4 metadata planning."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TRANSACTION_REQUIRED = "TRANSACTION_REQUIRED"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    CASE_BINDING_MISMATCH = "CASE_BINDING_MISMATCH"
    OBSERVATION_CLOSURE_MISMATCH = "OBSERVATION_CLOSURE_MISMATCH"
    ROW_LIMIT_EXCEEDED = "ROW_LIMIT_EXCEEDED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_BINDING_MISMATCH = "INDEX_BINDING_MISMATCH"
    PHYSICAL_PLAN_INVALID = "PHYSICAL_PLAN_INVALID"
    DATABASE_REJECTED = "DATABASE_REJECTED"


class _M6SQLiteM4MetadataFailure(Exception):
    """Private control-flow failure caught before a public traceback."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: M6SQLiteM4ModelDocumentFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code.value)


class M6SQLiteM4DocumentRoute(StrEnum):
    """Canonical M4 call bodies; exactly seven routes are physical."""

    MODEL_REQUEST = "m4_model_call_claims.request_json"
    MODEL_RESPONSE = "m4_model_responses.response_json"
    MODEL_CACHE_REQUEST = "m4_model_cache.request_json"
    MODEL_CACHE_ENTRY = "m4_model_cache.entry_json"
    MODEL_PARSE_RECEIPT = "m4_model_parse_receipts.receipt_json"
    ROLE_OUTPUT = "m4_parsed_hearing_outputs.output_json"
    MODEL_CALL_FAILURE = "m4_model_call_failure_authorities.authority_json"
    MODEL_USAGE = "m4_hearing_usage_receipts.usage_json"


class M6SQLiteM4SupportRoute(StrEnum):
    """Body-free commitments to relational rows used by the call graph."""

    RUN = "runs"
    CASE_VERSION = "case_versions"
    AUDIT_ENTRY = "audit_entries"
    EVIDENCE_PACK = "evidence_packs"
    SCREENING_RESULT = "screening_results"
    PROCEDURAL_REVIEW = "procedural_reviews"
    BACKLOG_ITEM = "backlog_items"
    BACKLOG_ITEM_VERSION = "backlog_item_versions"
    BACKLOG_HEAD = "backlog_heads"
    HEARING_SESSION = "m4_hearings"
    HEARING_CYCLE = "m4_hearing_cycles"
    PRECEDENT_RETRIEVAL = "m4_precedent_retrieval_receipts"
    HEARING_ROUND = "m4_hearing_rounds"
    HEARING_CHECKPOINT = "m4_hearing_checkpoints"
    BACKLOG_RETRY_OUTCOME = "m4_hearing_backlog_retry_outcomes"
    BACKLOG_COMPLETION_RECEIPT = "m4_backlog_completion_receipts"
    STRICT_PARSE_FAILURE_ATTEMPT = "m4_hearing_strict_parse_failure_attempts"
    STRICT_PARSE_FAILURE_PROOF = "m4_hearing_strict_parse_failure_proofs"
    HEARING_HUMAN_REVIEW_RECEIPT = "m4_hearing_human_review_receipts"


class M6SQLiteM4SupportDocumentRoute(StrEnum):
    """Canonical causal support bodies that never become physical artifacts."""

    HEARING_SESSION = "m4_hearings.hearing_json"
    HEARING_CYCLE = "m4_hearing_cycles.cycle_json"
    PRECEDENT_RETRIEVAL = "m4_precedent_retrieval_receipts.receipt_json"
    HEARING_ROUND = "m4_hearing_rounds.round_json"
    HEARING_CHECKPOINT = "m4_hearing_checkpoints.checkpoint_json"
    BACKLOG_ITEM = "backlog_items.initial_json"
    BACKLOG_ITEM_VERSION = "backlog_item_versions.item_json"
    BACKLOG_RETRY_OUTCOME = "m4_hearing_backlog_retry_outcomes.outcome_json"
    BACKLOG_COMPLETION_RECEIPT = "m4_backlog_completion_receipts.receipt_json"
    STRICT_PARSE_FAILURE_ATTEMPT = "m4_hearing_strict_parse_failure_attempts.attempt_json"
    STRICT_PARSE_FAILURE_PROOF = "m4_hearing_strict_parse_failure_proofs.proof_json"
    HEARING_HUMAN_REVIEW_RECEIPT = "m4_hearing_human_review_receipts.receipt_json"


class M6SQLiteM4SupportDocumentCommitmentKind(StrEnum):
    """Meaning of the pre-body SHA commitment stored for a support route."""

    CANONICAL_DOCUMENT = "CANONICAL_DOCUMENT"
    SEMANTIC_DOCUMENT = "SEMANTIC_DOCUMENT"


class M6SQLiteM4FailureClosureKind(StrEnum):
    INITIAL_BACKLOG = "INITIAL_BACKLOG"
    RETRY_FAILURE = "RETRY_FAILURE"


class M6SQLiteM4CallGeneration(StrEnum):
    INITIAL = "INITIAL"
    BACKLOG = "BACKLOG"


class M6SQLiteM4ClaimStatus(StrEnum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"


_DOCUMENT_ROUTE_RANK = {value: index for index, value in enumerate(M6SQLiteM4DocumentRoute)}
_SUPPORT_ROUTE_RANK = {value: index for index, value in enumerate(M6SQLiteM4SupportRoute)}
_SUPPORT_DOCUMENT_ROUTE_RANK = {
    value: index for index, value in enumerate(M6SQLiteM4SupportDocumentRoute)
}
_SUPPORT_DOCUMENT_TO_ROW_ROUTE = {
    M6SQLiteM4SupportDocumentRoute.HEARING_SESSION: M6SQLiteM4SupportRoute.HEARING_SESSION,
    M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE: M6SQLiteM4SupportRoute.HEARING_CYCLE,
    M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL: (
        M6SQLiteM4SupportRoute.PRECEDENT_RETRIEVAL
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_ROUND: M6SQLiteM4SupportRoute.HEARING_ROUND,
    M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT: (M6SQLiteM4SupportRoute.HEARING_CHECKPOINT),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM: M6SQLiteM4SupportRoute.BACKLOG_ITEM,
    M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM_VERSION: (
        M6SQLiteM4SupportRoute.BACKLOG_ITEM_VERSION
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_RETRY_OUTCOME: (
        M6SQLiteM4SupportRoute.BACKLOG_RETRY_OUTCOME
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT: (
        M6SQLiteM4SupportRoute.BACKLOG_COMPLETION_RECEIPT
    ),
    M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_ATTEMPT: (
        M6SQLiteM4SupportRoute.STRICT_PARSE_FAILURE_ATTEMPT
    ),
    M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_PROOF: (
        M6SQLiteM4SupportRoute.STRICT_PARSE_FAILURE_PROOF
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_HUMAN_REVIEW_RECEIPT: (
        M6SQLiteM4SupportRoute.HEARING_HUMAN_REVIEW_RECEIPT
    ),
}
_SUPPORT_DOCUMENT_COMMITMENT_KIND = {
    M6SQLiteM4SupportDocumentRoute.HEARING_SESSION: (
        M6SQLiteM4SupportDocumentCommitmentKind.SEMANTIC_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE: (
        M6SQLiteM4SupportDocumentCommitmentKind.SEMANTIC_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL: (
        M6SQLiteM4SupportDocumentCommitmentKind.SEMANTIC_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_ROUND: (
        M6SQLiteM4SupportDocumentCommitmentKind.SEMANTIC_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT: (
        M6SQLiteM4SupportDocumentCommitmentKind.SEMANTIC_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM: (
        M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM_VERSION: (
        M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_RETRY_OUTCOME: (
        M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT: (
        M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_ATTEMPT: (
        M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_PROOF: (
        M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_HUMAN_REVIEW_RECEIPT: (
        M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT
    ),
}
if set(_SUPPORT_DOCUMENT_COMMITMENT_KIND) != set(M6SQLiteM4SupportDocumentRoute):
    raise RuntimeError("M4 support document commitment meanings must be exhaustive")
_ROLE_RANK = {
    M6LockedModelRole.PROSECUTOR: 0,
    M6LockedModelRole.DEFENDER: 1,
    M6LockedModelRole.JUDGE: 2,
}
_PHYSICAL_KIND_BY_ROUTE = {
    M6SQLiteM4DocumentRoute.MODEL_REQUEST: M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
    M6SQLiteM4DocumentRoute.MODEL_RESPONSE: M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
    M6SQLiteM4DocumentRoute.MODEL_CACHE_ENTRY: M6UpgradePhysicalArtifactKind.MODEL_CACHE,
    M6SQLiteM4DocumentRoute.MODEL_PARSE_RECEIPT: (
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT
    ),
    M6SQLiteM4DocumentRoute.ROLE_OUTPUT: M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
    M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE: (M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE),
    M6SQLiteM4DocumentRoute.MODEL_USAGE: M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
}


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


def _require_positive_rowid(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _require_document_bytes(value: object, label: str) -> int:
    if type(value) is not int or not 0 < value <= MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES:
        raise ValueError(f"{label} is outside the M4 document budget")
    return value


def _controlled_ref(value: object) -> M6UpgradePhysicalArtifactRef:
    if type(value) is not M6UpgradePhysicalArtifactRef:
        raise TypeError("physical_ref must be an exact M6 physical artifact ref")
    try:
        controlled = M6UpgradePhysicalArtifactRef.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("physical_ref must be canonical") from None
    if controlled != value:
        raise ValueError("physical_ref must be canonical")
    return controlled


def _controlled_observation(value: object) -> M6UpgradeObservedModelCall:
    if type(value) is not M6UpgradeObservedModelCall:
        raise TypeError("observation must be exact")
    try:
        controlled = M6UpgradeObservedModelCall.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("observation must be canonical") from None
    if controlled != value:
        raise ValueError("observation must be canonical")
    return controlled


def _controlled_binding(value: object) -> M6UpgradeCandidateCaseBinding:
    if type(value) is not M6UpgradeCandidateCaseBinding:
        raise TypeError("selected Case binding must be exact")
    try:
        controlled = M6UpgradeCandidateCaseBinding.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("selected Case binding must be canonical") from None
    if controlled != value:
        raise ValueError("selected Case binding must be canonical")
    return controlled


def _controlled_case(value: object) -> Case:
    if type(value) is not Case:
        raise TypeError("selected Case must be exact")
    try:
        controlled = Case.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
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
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("selected Case audit must be canonical") from None
    if controlled != value:
        raise ValueError("selected Case audit must be canonical")
    return controlled


@dataclass(frozen=True, slots=True)
class M6SQLiteM4RoleModelManifestBinding:
    """One exact hearing-role to execution-model binding."""

    role: M6LockedModelRole
    model_manifest_id: str

    def __post_init__(self) -> None:
        if type(self.role) is not M6LockedModelRole or self.role not in _ROLE_RANK:
            raise ValueError("M4 model binding requires a prosecutor, defender, or judge role")
        _require_sha256(self.model_manifest_id, "model_manifest_id")

    @property
    def sort_key(self) -> tuple[int, str]:
        return _ROLE_RANK[self.role], self.model_manifest_id


def _controlled_role_binding(value: object) -> M6SQLiteM4RoleModelManifestBinding:
    if type(value) is not M6SQLiteM4RoleModelManifestBinding:
        raise TypeError("role model binding must be exact")
    return M6SQLiteM4RoleModelManifestBinding(
        role=value.role,
        model_manifest_id=value.model_manifest_id,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM4HearingModelManifestBinding:
    """The exact three-role execution-model matrix for one hearing."""

    hearing_id: str
    hearing_prompt_bundle_sha256: str
    role_bindings: tuple[M6SQLiteM4RoleModelManifestBinding, ...]

    def __post_init__(self) -> None:
        _require_sha256(self.hearing_id, "hearing binding hearing_id")
        _require_sha256(
            self.hearing_prompt_bundle_sha256,
            "hearing prompt bundle sha256",
        )
        if type(self.role_bindings) is not tuple or any(
            type(value) is not M6SQLiteM4RoleModelManifestBinding for value in self.role_bindings
        ):
            raise TypeError("hearing role bindings must be an exact tuple")
        bindings = tuple(_controlled_role_binding(value) for value in self.role_bindings)
        if bindings != tuple(sorted(bindings, key=lambda value: value.sort_key)):
            raise ValueError("hearing role bindings must be ordered")
        if tuple(value.role for value in bindings) != tuple(_ROLE_RANK):
            raise ValueError("hearing model matrix requires exactly prosecutor, defender, judge")
        object.__setattr__(self, "role_bindings", bindings)

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.hearing_id, self.hearing_prompt_bundle_sha256

    def model_manifest_id_for(self, role: M6LockedModelRole) -> str:
        if type(role) is not M6LockedModelRole or role not in _ROLE_RANK:
            raise ValueError("M4 model lookup requires a hearing role")
        return next(value.model_manifest_id for value in self.role_bindings if value.role == role)


def _controlled_hearing_binding(
    value: object,
) -> M6SQLiteM4HearingModelManifestBinding:
    if type(value) is not M6SQLiteM4HearingModelManifestBinding:
        raise TypeError("hearing model binding must be exact")
    return M6SQLiteM4HearingModelManifestBinding(
        hearing_id=value.hearing_id,
        hearing_prompt_bundle_sha256=value.hearing_prompt_bundle_sha256,
        role_bindings=tuple(_controlled_role_binding(item) for item in value.role_bindings),
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM4DocumentSlot:
    """One rowid-bound M4 call document length and index commitment."""

    route: M6SQLiteM4DocumentRoute
    rowid: int
    artifact_id: str
    document_sha256: str
    document_bytes: int
    index_identity_sha256: str
    physical_ref: M6UpgradePhysicalArtifactRef | None = None

    def __post_init__(self) -> None:
        if type(self.route) is not M6SQLiteM4DocumentRoute:
            raise TypeError("document route must be exact")
        _require_positive_rowid(self.rowid, "document rowid")
        _require_sha256(self.artifact_id, "document artifact_id")
        _require_sha256(self.document_sha256, "document_sha256")
        _require_document_bytes(self.document_bytes, "document byte length")
        _require_sha256(self.index_identity_sha256, "index_identity_sha256")

        expected_kind = _PHYSICAL_KIND_BY_ROUTE.get(self.route)
        if expected_kind is None:
            if self.physical_ref is not None:
                raise ValueError("cache request body is not a physical artifact")
            return
        controlled = _controlled_ref(self.physical_ref)
        if (
            controlled.source != M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
            or controlled.kind != expected_kind
            or controlled.artifact_id != self.artifact_id
            or controlled.document_sha256 != self.document_sha256
        ):
            raise ValueError("document slot and physical ref differ")
        if (
            self.route != M6SQLiteM4DocumentRoute.MODEL_RESPONSE
            and controlled.size_bytes != self.document_bytes
        ):
            raise ValueError("canonical document and physical sizes differ")
        object.__setattr__(self, "physical_ref", controlled)

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return _DOCUMENT_ROUTE_RANK[self.route], self.artifact_id, self.rowid


def _controlled_document_slot(value: object) -> M6SQLiteM4DocumentSlot:
    if type(value) is not M6SQLiteM4DocumentSlot:
        raise TypeError("document slot must be exact")
    return M6SQLiteM4DocumentSlot(
        route=value.route,
        rowid=value.rowid,
        artifact_id=value.artifact_id,
        document_sha256=value.document_sha256,
        document_bytes=value.document_bytes,
        index_identity_sha256=value.index_identity_sha256,
        physical_ref=(
            _controlled_ref(value.physical_ref) if value.physical_ref is not None else None
        ),
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM4SupportSlot:
    """A body-free commitment to one supporting relational row."""

    route: M6SQLiteM4SupportRoute
    rowid: int
    identity: str
    index_identity_sha256: str

    def __post_init__(self) -> None:
        if type(self.route) is not M6SQLiteM4SupportRoute:
            raise TypeError("support route must be exact")
        _require_positive_rowid(self.rowid, "support rowid")
        if type(self.identity) is not str or not self.identity:
            raise TypeError("support identity must be a non-empty string")
        _require_sha256(self.index_identity_sha256, "support index identity")

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return _SUPPORT_ROUTE_RANK[self.route], self.identity, self.rowid


def _controlled_support_slot(value: object) -> M6SQLiteM4SupportSlot:
    if type(value) is not M6SQLiteM4SupportSlot:
        raise TypeError("support slot must be exact")
    return M6SQLiteM4SupportSlot(
        route=value.route,
        rowid=value.rowid,
        identity=value.identity,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM4SupportDocumentSlot:
    """A causal support body committed before its bytes are materialized.

    Some legacy M4 tables persist only a typed semantic hash rather than a
    SHA-256 of the canonical JSON bytes.  ``body_commitment_sha256`` therefore
    has the exact route-defined meaning exposed by ``commitment_kind``.
    """

    route: M6SQLiteM4SupportDocumentRoute
    rowid: int
    artifact_id: str
    body_commitment_sha256: str
    document_bytes: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        if type(self.route) is not M6SQLiteM4SupportDocumentRoute:
            raise TypeError("support document route must be exact")
        _require_positive_rowid(self.rowid, "support document rowid")
        _require_sha256(self.artifact_id, "support document artifact_id")
        _require_sha256(self.body_commitment_sha256, "support body commitment")
        _require_document_bytes(self.document_bytes, "support document byte length")
        _require_sha256(self.index_identity_sha256, "support document index identity")

    @property
    def commitment_kind(self) -> M6SQLiteM4SupportDocumentCommitmentKind:
        return _SUPPORT_DOCUMENT_COMMITMENT_KIND[self.route]

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return _SUPPORT_DOCUMENT_ROUTE_RANK[self.route], self.artifact_id, self.rowid


def _controlled_support_document_slot(value: object) -> M6SQLiteM4SupportDocumentSlot:
    if type(value) is not M6SQLiteM4SupportDocumentSlot:
        raise TypeError("support document slot must be exact")
    return M6SQLiteM4SupportDocumentSlot(
        route=value.route,
        rowid=value.rowid,
        artifact_id=value.artifact_id,
        body_commitment_sha256=value.body_commitment_sha256,
        document_bytes=value.document_bytes,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM4SelectedPackBinding:
    """One selected-Case EvidencePack row used by an M4 request."""

    rowid: int
    pack_id: str
    version: int
    document_sha256: str
    created_audit_sequence: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        _require_positive_rowid(self.rowid, "pack rowid")
        _require_sha256(self.pack_id, "pack_id")
        _require_sha256(self.document_sha256, "pack document_sha256")
        _require_sha256(self.index_identity_sha256, "pack index identity")
        if type(self.version) is not int or self.version <= 0:
            raise ValueError("pack version must be positive")
        if type(self.created_audit_sequence) is not int or self.created_audit_sequence < 0:
            raise ValueError("pack audit sequence must be non-negative")

    @property
    def sort_key(self) -> tuple[int, str]:
        return self.version, self.pack_id


def _controlled_pack(value: object) -> M6SQLiteM4SelectedPackBinding:
    if type(value) is not M6SQLiteM4SelectedPackBinding:
        raise TypeError("selected pack binding must be exact")
    return M6SQLiteM4SelectedPackBinding(
        rowid=value.rowid,
        pack_id=value.pack_id,
        version=value.version,
        document_sha256=value.document_sha256,
        created_audit_sequence=value.created_audit_sequence,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM4HistoricalFailureBinding:
    """One verified older claim epoch, never a current physical artifact."""

    request_id: str
    claim_takeover_count: int
    authority_id: str
    hearing_id: str
    cycle_scope_id: str
    cycle_scope_sha256: str
    case_id: str
    role: M6LockedModelRole
    source_checkpoint_id: str
    source_checkpoint_sha256: str
    source_checkpoint_version: int
    backlog_item_id: str
    backlog_version: int
    retry_generation: int
    closure_kind: M6SQLiteM4FailureClosureKind
    completion_receipt_id: str | None
    closure_case_revision: int
    closure_audit_sequence: int
    closure_audit_entry_hash: str
    rowid: int
    document_sha256: str
    document_bytes: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.request_id, "historical request_id"),
            (self.authority_id, "historical authority_id"),
            (self.hearing_id, "historical hearing_id"),
            (self.cycle_scope_id, "historical cycle_scope_id"),
            (self.cycle_scope_sha256, "historical cycle_scope_sha256"),
            (self.source_checkpoint_id, "historical source checkpoint_id"),
            (self.source_checkpoint_sha256, "historical source checkpoint_sha256"),
            (self.backlog_item_id, "historical backlog_item_id"),
            (self.closure_audit_entry_hash, "historical closure audit hash"),
            (self.document_sha256, "historical document_sha256"),
            (self.index_identity_sha256, "historical index identity"),
        ):
            _require_sha256(value, label)
        if type(self.case_id) is not str:
            raise TypeError("historical case_id must be a string")
        require_reference_token(self.case_id, "historical case_id")
        if type(self.role) is not M6LockedModelRole or self.role not in _ROLE_RANK:
            raise ValueError("historical failure requires a hearing role")
        if type(self.claim_takeover_count) is not int or self.claim_takeover_count < 0:
            raise ValueError("historical failure epoch must be non-negative")
        if type(self.backlog_version) is not int or self.backlog_version <= 0:
            raise ValueError("historical failure backlog version must be positive")
        if type(self.source_checkpoint_version) is not int or self.source_checkpoint_version <= 0:
            raise ValueError("historical source checkpoint version must be positive")
        if type(self.retry_generation) is not int or self.retry_generation < 0:
            raise ValueError("historical retry generation must be non-negative")
        if type(self.closure_kind) is not M6SQLiteM4FailureClosureKind:
            raise TypeError("historical failure closure kind must be exact")
        if self.closure_kind == M6SQLiteM4FailureClosureKind.INITIAL_BACKLOG:
            if self.completion_receipt_id is not None or self.backlog_version != 1:
                raise ValueError("initial historical failure cannot have completion authority")
        else:
            _require_sha256(self.completion_receipt_id, "historical completion receipt_id")
        if type(self.closure_case_revision) is not int or self.closure_case_revision <= 0:
            raise ValueError("historical failure Case revision must be positive")
        if type(self.closure_audit_sequence) is not int or self.closure_audit_sequence < 0:
            raise ValueError("historical closure audit sequence must be non-negative")
        _require_positive_rowid(self.rowid, "historical failure rowid")
        _require_document_bytes(self.document_bytes, "historical failure document length")

    @property
    def route(self) -> M6SQLiteM4DocumentRoute:
        return M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE

    @property
    def sort_key(self) -> tuple[str, int, str, int]:
        return self.request_id, self.claim_takeover_count, self.authority_id, self.rowid


def _controlled_historical_failure(value: object) -> M6SQLiteM4HistoricalFailureBinding:
    if type(value) is not M6SQLiteM4HistoricalFailureBinding:
        raise TypeError("historical failure binding must be exact")
    return M6SQLiteM4HistoricalFailureBinding(
        request_id=value.request_id,
        claim_takeover_count=value.claim_takeover_count,
        authority_id=value.authority_id,
        hearing_id=value.hearing_id,
        cycle_scope_id=value.cycle_scope_id,
        cycle_scope_sha256=value.cycle_scope_sha256,
        case_id=value.case_id,
        role=value.role,
        source_checkpoint_id=value.source_checkpoint_id,
        source_checkpoint_sha256=value.source_checkpoint_sha256,
        source_checkpoint_version=value.source_checkpoint_version,
        backlog_item_id=value.backlog_item_id,
        backlog_version=value.backlog_version,
        retry_generation=value.retry_generation,
        closure_kind=value.closure_kind,
        completion_receipt_id=value.completion_receipt_id,
        closure_case_revision=value.closure_case_revision,
        closure_audit_sequence=value.closure_audit_sequence,
        closure_audit_entry_hash=value.closure_audit_entry_hash,
        rowid=value.rowid,
        document_sha256=value.document_sha256,
        document_bytes=value.document_bytes,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM4CallGraphPlan:
    """One observed hearing call exactly joined to its current terminal graph."""

    observation: M6UpgradeObservedModelCall
    hearing_id: str
    cycle_scope_id: str
    cycle_scope_sha256: str
    cycle_index: int
    prior_acquisition_rounds: int
    prior_rework_rounds: int
    evidence_pack_id: str
    evidence_pack_version: int
    retrieval_receipt_id: str
    retrieval_commitment_sha256: str
    purpose: str
    call_generation: M6SQLiteM4CallGeneration
    backlog_item_id: str | None
    retry_generation: int
    model_manifest_id: str
    claim_status: M6SQLiteM4ClaimStatus
    claim_takeover_count: int
    request: M6SQLiteM4DocumentSlot
    response: M6SQLiteM4DocumentSlot | None = None
    cache_request: M6SQLiteM4DocumentSlot | None = None
    cache: M6SQLiteM4DocumentSlot | None = None
    parse_receipt: M6SQLiteM4DocumentSlot | None = None
    role_output: M6SQLiteM4DocumentSlot | None = None
    failure: M6SQLiteM4DocumentSlot | None = None
    usage: M6SQLiteM4DocumentSlot | None = None
    parse_status: ModelParseStatus | None = None
    repair_request_id: str | None = None

    def __post_init__(self) -> None:
        observation = _controlled_observation(self.observation)
        object.__setattr__(self, "observation", observation)
        if (
            observation.layer != M6LockedModelCallLayer.HEARING
            or observation.role not in _ROLE_RANK
        ):
            raise ValueError("M4 call graph requires a typed hearing observation")
        for value, label in (
            (self.hearing_id, "call graph hearing_id"),
            (self.cycle_scope_id, "call graph cycle_scope_id"),
            (self.cycle_scope_sha256, "call graph cycle_scope_sha256"),
            (self.evidence_pack_id, "call graph pack_id"),
            (self.retrieval_receipt_id, "call graph retrieval receipt_id"),
            (self.retrieval_commitment_sha256, "call graph retrieval commitment"),
            (self.model_manifest_id, "call graph model_manifest_id"),
        ):
            _require_sha256(value, label)
        if type(self.cycle_index) is not int or not 1 <= self.cycle_index <= 5:
            raise ValueError("call graph cycle index must be in [1, 5]")
        if (
            type(self.prior_acquisition_rounds) is not int
            or not 0 <= self.prior_acquisition_rounds <= 2
            or type(self.prior_rework_rounds) is not int
            or not 0 <= self.prior_rework_rounds <= 2
            or self.cycle_index != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds
        ):
            raise ValueError("call graph cycle counters are inconsistent")
        if type(self.evidence_pack_version) is not int or self.evidence_pack_version <= 0:
            raise ValueError("call graph pack version must be positive")
        expected_purpose = "ROLE_CALL" if observation.attempt_index == 0 else "STRUCTURE_REPAIR"
        if self.purpose != expected_purpose:
            raise ValueError("call graph purpose and attempt differ")
        if type(self.call_generation) is not M6SQLiteM4CallGeneration:
            raise TypeError("call generation must be exact")
        if type(self.retry_generation) is not int or self.retry_generation < 0:
            raise ValueError("call graph retry generation must be non-negative")
        if self.call_generation == M6SQLiteM4CallGeneration.INITIAL:
            if self.backlog_item_id is not None or self.retry_generation != 0:
                raise ValueError("initial call cannot carry backlog generation state")
        elif self.backlog_item_id is None or self.retry_generation <= 0:
            raise ValueError("backlog call requires an item and positive retry generation")
        else:
            _require_sha256(self.backlog_item_id, "call graph backlog item_id")
        if type(self.claim_status) is not M6SQLiteM4ClaimStatus:
            raise TypeError("claim status must be exact")
        if type(self.claim_takeover_count) is not int or self.claim_takeover_count < 0:
            raise ValueError("call graph claim epoch must be non-negative")
        if self.repair_request_id is not None:
            _require_sha256(self.repair_request_id, "repair request_id")

        request = _controlled_document_slot(self.request)
        object.__setattr__(self, "request", request)
        for field_name in (
            "response",
            "cache_request",
            "cache",
            "parse_receipt",
            "role_output",
            "failure",
            "usage",
        ):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _controlled_document_slot(value))
        if (
            request.route != M6SQLiteM4DocumentRoute.MODEL_REQUEST
            or request.artifact_id != observation.request_id
        ):
            raise ValueError("call graph request differs from observation")

        response_slots = (
            self.response,
            self.cache_request,
            self.cache,
            self.parse_receipt,
            self.usage,
        )
        if observation.result_kind == M6LockedModelCallResultKind.RESPONSE:
            if (
                self.claim_status != M6SQLiteM4ClaimStatus.COMPLETED
                or any(value is None for value in response_slots)
                or self.failure is not None
            ):
                raise ValueError("response call graph is incomplete")
            if type(self.parse_status) is not ModelParseStatus:
                raise ValueError("response call graph parse status is invalid")
            if (self.parse_status == ModelParseStatus.PARSED) != (self.role_output is not None):
                raise ValueError("role output presence differs from parse status")
            if (self.parse_status == ModelParseStatus.REPAIR_REQUIRED) != (
                self.repair_request_id is not None
            ):
                raise ValueError("repair pointer presence differs from parse status")
            if (
                observation.attempt_index == 0
                and self.parse_status == ModelParseStatus.INVALID_FINAL
            ):
                raise ValueError("primary response cannot be invalid-final")
            if (
                observation.attempt_index == 1
                and self.parse_status == ModelParseStatus.REPAIR_REQUIRED
            ):
                raise ValueError("repair response cannot request a third attempt")
        elif (
            self.claim_status != M6SQLiteM4ClaimStatus.ACTIVE
            or self.failure is None
            or any(value is not None for value in response_slots)
            or self.role_output is not None
            or self.parse_status is not None
            or self.repair_request_id is not None
        ):
            raise ValueError("failure call graph is incomplete")

        expected_routes = (
            (self.response, M6SQLiteM4DocumentRoute.MODEL_RESPONSE),
            (self.cache_request, M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST),
            (self.cache, M6SQLiteM4DocumentRoute.MODEL_CACHE_ENTRY),
            (self.parse_receipt, M6SQLiteM4DocumentRoute.MODEL_PARSE_RECEIPT),
            (self.role_output, M6SQLiteM4DocumentRoute.ROLE_OUTPUT),
            (self.failure, M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE),
            (self.usage, M6SQLiteM4DocumentRoute.MODEL_USAGE),
        )
        if any(slot is not None and slot.route != route for slot, route in expected_routes):
            raise ValueError("call graph contains a document in the wrong route")

    @property
    def document_slots(self) -> tuple[M6SQLiteM4DocumentSlot, ...]:
        return tuple(
            slot
            for slot in (
                self.request,
                self.response,
                self.cache_request,
                self.cache,
                self.parse_receipt,
                self.role_output,
                self.failure,
                self.usage,
            )
            if slot is not None
        )

    @property
    def artifact_refs(self) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        return tuple(
            slot.physical_ref for slot in self.document_slots if slot.physical_ref is not None
        )

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        return self.observation.sort_key


def _controlled_call_graph(value: object) -> M6SQLiteM4CallGraphPlan:
    if type(value) is not M6SQLiteM4CallGraphPlan:
        raise TypeError("call graph must be exact")
    return M6SQLiteM4CallGraphPlan(
        observation=_controlled_observation(value.observation),
        hearing_id=value.hearing_id,
        cycle_scope_id=value.cycle_scope_id,
        cycle_scope_sha256=value.cycle_scope_sha256,
        cycle_index=value.cycle_index,
        prior_acquisition_rounds=value.prior_acquisition_rounds,
        prior_rework_rounds=value.prior_rework_rounds,
        evidence_pack_id=value.evidence_pack_id,
        evidence_pack_version=value.evidence_pack_version,
        retrieval_receipt_id=value.retrieval_receipt_id,
        retrieval_commitment_sha256=value.retrieval_commitment_sha256,
        purpose=value.purpose,
        call_generation=value.call_generation,
        backlog_item_id=value.backlog_item_id,
        retry_generation=value.retry_generation,
        model_manifest_id=value.model_manifest_id,
        claim_status=value.claim_status,
        claim_takeover_count=value.claim_takeover_count,
        request=_controlled_document_slot(value.request),
        response=(
            _controlled_document_slot(value.response) if value.response is not None else None
        ),
        cache_request=(
            _controlled_document_slot(value.cache_request)
            if value.cache_request is not None
            else None
        ),
        cache=_controlled_document_slot(value.cache) if value.cache is not None else None,
        parse_receipt=(
            _controlled_document_slot(value.parse_receipt)
            if value.parse_receipt is not None
            else None
        ),
        role_output=(
            _controlled_document_slot(value.role_output) if value.role_output is not None else None
        ),
        failure=(_controlled_document_slot(value.failure) if value.failure is not None else None),
        usage=_controlled_document_slot(value.usage) if value.usage is not None else None,
        parse_status=value.parse_status,
        repair_request_id=value.repair_request_id,
    )


def _slot_projection(slot: M6SQLiteM4DocumentSlot) -> list[object]:
    ref = slot.physical_ref
    return [
        slot.route,
        slot.rowid,
        slot.artifact_id,
        slot.document_sha256,
        slot.document_bytes,
        slot.index_identity_sha256,
        ref.model_dump(mode="json") if ref is not None else None,
    ]


def _support_document_slot_projection(
    slot: M6SQLiteM4SupportDocumentSlot,
) -> list[object]:
    return [
        slot.route,
        slot.rowid,
        slot.artifact_id,
        slot.commitment_kind,
        slot.body_commitment_sha256,
        slot.document_bytes,
        slot.index_identity_sha256,
    ]


def _historical_failure_projection(
    value: M6SQLiteM4HistoricalFailureBinding,
) -> list[object]:
    return [
        value.route,
        value.request_id,
        value.claim_takeover_count,
        value.authority_id,
        value.hearing_id,
        value.cycle_scope_id,
        value.cycle_scope_sha256,
        value.case_id,
        value.role,
        value.source_checkpoint_id,
        value.source_checkpoint_sha256,
        value.source_checkpoint_version,
        value.backlog_item_id,
        value.backlog_version,
        value.retry_generation,
        value.closure_kind,
        value.completion_receipt_id,
        value.closure_case_revision,
        value.closure_audit_sequence,
        value.closure_audit_entry_hash,
        value.rowid,
        value.document_sha256,
        value.document_bytes,
        value.index_identity_sha256,
    ]


def _plan_projection(plan: M6SQLiteM4ModelDocumentsPlan) -> list[object]:
    return [
        "m6-sqlite-m4-model-documents-plan",
        2,
        plan.run_id,
        plan.case_id,
        plan.manifest_id,
        plan.selected_case_binding.model_dump(mode="json"),
        plan.selected_case.model_dump(mode="json"),
        plan.selected_case_revision,
        plan.selected_case_audit.model_dump(mode="json"),
        [
            [
                value.hearing_id,
                value.hearing_prompt_bundle_sha256,
                [[item.role, item.model_manifest_id] for item in value.role_bindings],
            ]
            for value in plan.hearing_model_bindings
        ],
        [
            [
                pack.pack_id,
                pack.rowid,
                pack.version,
                pack.document_sha256,
                pack.created_audit_sequence,
                pack.index_identity_sha256,
            ]
            for pack in plan.selected_packs
        ],
        [item.model_dump(mode="json") for item in plan.observed_model_calls],
        [
            [
                graph.observation.request_id,
                graph.hearing_id,
                graph.cycle_scope_id,
                graph.cycle_scope_sha256,
                graph.cycle_index,
                graph.prior_acquisition_rounds,
                graph.prior_rework_rounds,
                graph.evidence_pack_id,
                graph.evidence_pack_version,
                graph.retrieval_receipt_id,
                graph.retrieval_commitment_sha256,
                graph.purpose,
                graph.call_generation,
                graph.backlog_item_id,
                graph.retry_generation,
                graph.model_manifest_id,
                graph.claim_status,
                graph.claim_takeover_count,
                graph.parse_status,
                graph.repair_request_id,
                [_slot_projection(slot) for slot in graph.document_slots],
            ]
            for graph in plan.call_graphs
        ],
        [_historical_failure_projection(value) for value in plan.historical_failures],
        [
            [slot.route, slot.rowid, slot.identity, slot.index_identity_sha256]
            for slot in plan.support_slots
        ],
        [_support_document_slot_projection(slot) for slot in plan.support_document_slots],
        plan.planned_document_bytes,
        plan.planned_physical_bytes,
    ]


def _plan_digest(plan: M6SQLiteM4ModelDocumentsPlan) -> str:
    return hashlib.sha256(canonical_json(_plan_projection(plan)).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class M6SQLiteM4ModelDocumentsPlan:
    """Complete bounded M4 model metadata closure for one selected Case."""

    run_id: str
    case_id: str
    manifest_id: str
    selected_case_binding: M6UpgradeCandidateCaseBinding
    selected_case: Case
    selected_case_revision: int
    selected_case_audit: AuditEntry
    hearing_model_bindings: tuple[M6SQLiteM4HearingModelManifestBinding, ...]
    selected_packs: tuple[M6SQLiteM4SelectedPackBinding, ...]
    observed_model_calls: tuple[M6UpgradeObservedModelCall, ...]
    call_graphs: tuple[M6SQLiteM4CallGraphPlan, ...]
    support_slots: tuple[M6SQLiteM4SupportSlot, ...]
    support_document_slots: tuple[M6SQLiteM4SupportDocumentSlot, ...]
    historical_failures: tuple[M6SQLiteM4HistoricalFailureBinding, ...] = ()
    document_slots: tuple[M6SQLiteM4DocumentSlot, ...] = field(init=False)
    planned_artifact_refs: tuple[M6UpgradePhysicalArtifactRef, ...] = field(init=False)
    planned_document_bytes: int = field(init=False)
    planned_physical_bytes: int = field(init=False)
    plan_identity_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not all(type(value) is str and value for value in (self.run_id, self.case_id)):
            raise TypeError("plan scope identifiers must be non-empty strings")
        _require_sha256(self.manifest_id, "plan manifest_id")
        binding = _controlled_binding(self.selected_case_binding)
        selected_case = _controlled_case(self.selected_case)
        selected_audit = _controlled_audit(self.selected_case_audit)
        object.__setattr__(self, "selected_case_binding", binding)
        object.__setattr__(self, "selected_case", selected_case)
        object.__setattr__(self, "selected_case_audit", selected_audit)
        if type(self.selected_case_revision) is not int or self.selected_case_revision <= 0:
            raise ValueError("selected Case revision must be positive")
        canonical_case = canonical_json(selected_case.model_dump(mode="json"))
        case_document_sha256 = hashlib.sha256(canonical_case.encode("utf-8")).hexdigest()
        if (
            selected_case.run_id != self.run_id
            or selected_case.case_id != self.case_id
            or selected_case.manifest_id != self.manifest_id
            or binding.case_id != self.case_id
            or binding.case_revision != self.selected_case_revision
            or binding.case_document_sha256 != case_document_sha256
            or selected_audit.run_id != self.run_id
            or selected_audit.manifest_id != self.manifest_id
            or selected_audit.sequence != binding.case_audit_sequence
            or selected_audit.entry_hash != binding.case_audit_entry_hash
            or selected_audit.after_sha256 != case_document_sha256
        ):
            raise ValueError("plan binding does not identify the selected Case document")

        typed_groups = (
            (self.hearing_model_bindings, M6SQLiteM4HearingModelManifestBinding),
            (self.selected_packs, M6SQLiteM4SelectedPackBinding),
            (self.observed_model_calls, M6UpgradeObservedModelCall),
            (self.call_graphs, M6SQLiteM4CallGraphPlan),
            (self.historical_failures, M6SQLiteM4HistoricalFailureBinding),
            (self.support_slots, M6SQLiteM4SupportSlot),
            (self.support_document_slots, M6SQLiteM4SupportDocumentSlot),
        )
        if any(
            type(values) is not tuple or any(type(value) is not expected for value in values)
            for values, expected in typed_groups
        ):
            raise TypeError("plan groups must be exact typed tuples")
        hearings = tuple(
            _controlled_hearing_binding(value) for value in self.hearing_model_bindings
        )
        packs = tuple(_controlled_pack(value) for value in self.selected_packs)
        observations = tuple(_controlled_observation(value) for value in self.observed_model_calls)
        graphs = tuple(_controlled_call_graph(value) for value in self.call_graphs)
        history = tuple(_controlled_historical_failure(value) for value in self.historical_failures)
        support = tuple(_controlled_support_slot(value) for value in self.support_slots)
        support_documents = tuple(
            _controlled_support_document_slot(value) for value in self.support_document_slots
        )
        object.__setattr__(self, "hearing_model_bindings", hearings)
        object.__setattr__(self, "selected_packs", packs)
        object.__setattr__(self, "observed_model_calls", observations)
        object.__setattr__(self, "call_graphs", graphs)
        object.__setattr__(self, "historical_failures", history)
        object.__setattr__(self, "support_slots", support)
        object.__setattr__(self, "support_document_slots", support_documents)

        if any(
            len(values) > MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP
            for values in (hearings, packs, observations, graphs, history)
        ):
            raise ValueError("M4 plan group exceeds its row budget")
        ordered_groups = (
            (hearings, tuple(sorted(hearings, key=lambda value: value.sort_key))),
            (packs, tuple(sorted(packs, key=lambda value: value.sort_key))),
            (observations, tuple(sorted(observations, key=lambda value: value.sort_key))),
            (graphs, tuple(sorted(graphs, key=lambda value: value.sort_key))),
            (history, tuple(sorted(history, key=lambda value: value.sort_key))),
            (support, tuple(sorted(support, key=lambda value: value.sort_key))),
            (
                support_documents,
                tuple(sorted(support_documents, key=lambda value: value.sort_key)),
            ),
        )
        if any(values != ordered for values, ordered in ordered_groups):
            raise ValueError("M4 plan groups must use stable order")
        observation_ids = tuple(value.request_id for value in observations)
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("observed request identities must be unique")
        if tuple(graph.observation for graph in graphs) != observations:
            raise ValueError("call graphs and observations do not close bidirectionally")
        graph_ids = tuple(graph.observation.request_id for graph in graphs)
        if len(graph_ids) != len(set(graph_ids)):
            raise ValueError("call graph request identities must be unique")

        hearings_by_id = {value.hearing_id: value for value in hearings}
        if len(hearings_by_id) != len(hearings) or set(hearings_by_id) != {
            graph.hearing_id for graph in graphs
        }:
            raise ValueError("hearing bindings must be the exact call-graph hearing set")
        for graph in graphs:
            hearing = hearings_by_id[graph.hearing_id]
            if hearing.model_manifest_id_for(graph.observation.role) != graph.model_manifest_id:
                raise ValueError("call graph crosses its hearing role model manifest")

        pack_keys = tuple((pack.pack_id, pack.version) for pack in packs)
        if len(pack_keys) != len(set(pack_keys)):
            raise ValueError("selected pack keys must be unique")
        if len({pack.rowid for pack in packs}) != len(packs):
            raise ValueError("selected pack rowids must be unique")
        if len({pack.index_identity_sha256 for pack in packs}) != len(packs):
            raise ValueError("selected pack index identities must be unique")
        case_packs = {(pack.pack_id, pack.version): pack for pack in selected_case.evidence_packs}
        for pack_binding in packs:
            embedded = case_packs.get((pack_binding.pack_id, pack_binding.version))
            if embedded is None:
                raise ValueError("call graph pack is absent from the selected Case")
            canonical_pack = canonical_json(embedded.model_dump(mode="json"))
            if (
                hashlib.sha256(canonical_pack.encode("utf-8")).hexdigest()
                != pack_binding.document_sha256
                or pack_binding.created_audit_sequence > binding.case_audit_sequence
            ):
                raise ValueError("selected pack binding differs from the selected Case")
        if {(graph.evidence_pack_id, graph.evidence_pack_version) for graph in graphs} != set(
            pack_keys
        ):
            raise ValueError("selected packs must be the exact call-graph pack subset")

        graph_by_request = {graph.observation.request_id: graph for graph in graphs}
        historical_epochs = tuple(
            (value.request_id, value.claim_takeover_count) for value in history
        )
        if len(historical_epochs) != len(set(historical_epochs)):
            raise ValueError("historical failure claim epochs must be unique")
        if len({value.authority_id for value in history}) != len(history):
            raise ValueError("historical failure authorities must be unique")
        for value in history:
            terminal_graph = graph_by_request.get(value.request_id)
            if (
                terminal_graph is None
                or value.claim_takeover_count >= terminal_graph.claim_takeover_count
                or value.case_id != self.case_id
                or value.hearing_id != terminal_graph.hearing_id
                or value.cycle_scope_id != terminal_graph.cycle_scope_id
                or value.cycle_scope_sha256 != terminal_graph.cycle_scope_sha256
                or value.role != terminal_graph.observation.role
                or value.closure_case_revision > self.selected_case_revision
                or value.closure_audit_sequence > binding.case_audit_sequence
            ):
                raise ValueError("historical failure does not precede its exact terminal claim")

        repair_sources: dict[str, int] = {}
        for graph in graphs:
            if graph.repair_request_id is not None:
                repair_sources[graph.repair_request_id] = (
                    repair_sources.get(graph.repair_request_id, 0) + 1
                )
        for graph in graphs:
            if graph.observation.attempt_index == 0:
                if graph.parse_status == ModelParseStatus.REPAIR_REQUIRED:
                    target = graph_by_request.get(graph.repair_request_id or "")
                    if (
                        target is None
                        or target.observation.attempt_index != 1
                        or target.hearing_id != graph.hearing_id
                        or target.cycle_scope_id != graph.cycle_scope_id
                        or target.observation.role != graph.observation.role
                        or target.evidence_pack_id != graph.evidence_pack_id
                        or target.evidence_pack_version != graph.evidence_pack_version
                        or target.model_manifest_id != graph.model_manifest_id
                        or target.call_generation != graph.call_generation
                        or target.backlog_item_id != graph.backlog_item_id
                        or target.retry_generation != graph.retry_generation
                    ):
                        raise ValueError("primary repair pointer has no exact repair call")
                elif graph.repair_request_id is not None:
                    raise ValueError("non-repair primary call points to a repair")
            elif repair_sources.get(graph.observation.request_id) != 1:
                raise ValueError("repair call must have exactly one primary predecessor")

        slots = tuple(
            sorted(
                (slot for graph in graphs for slot in graph.document_slots),
                key=lambda value: value.sort_key,
            )
        )
        refs = tuple(
            sorted(
                (ref for graph in graphs for ref in graph.artifact_refs),
                key=lambda value: value.sort_key,
            )
        )
        if len({(slot.route, slot.rowid) for slot in slots}) != len(slots):
            raise ValueError("document slots must be globally unique")
        if len({(slot.route, slot.artifact_id) for slot in slots}) != len(slots):
            raise ValueError("document route identities must be globally unique")
        if len({slot.index_identity_sha256 for slot in slots}) != len(slots):
            raise ValueError("document index identities must be globally unique")
        terminal_failures = tuple(
            slot for slot in slots if slot.route == M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE
        )
        failure_rowids = tuple(slot.rowid for slot in terminal_failures) + tuple(
            value.rowid for value in history
        )
        failure_ids = tuple(slot.artifact_id for slot in terminal_failures) + tuple(
            value.authority_id for value in history
        )
        failure_indexes = tuple(slot.index_identity_sha256 for slot in terminal_failures) + tuple(
            value.index_identity_sha256 for value in history
        )
        if (
            len(failure_rowids) != len(set(failure_rowids))
            or len(failure_ids) != len(set(failure_ids))
            or len(failure_indexes) != len(set(failure_indexes))
        ):
            raise ValueError("terminal and historical failure commitments must be unique")
        if any(
            sum(slot.route == route for slot in slots) > MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP
            for route in M6SQLiteM4DocumentRoute
        ) or (len(terminal_failures) + len(history) > MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP):
            raise ValueError("M4 document route exceeds its row budget")

        if len({(slot.route, slot.rowid) for slot in support}) != len(support):
            raise ValueError("support route rowids must be globally unique")
        if len({(slot.route, slot.identity) for slot in support}) != len(support):
            raise ValueError("support route identities must be globally unique")
        if len({slot.index_identity_sha256 for slot in support}) != len(support):
            raise ValueError("support index identities must be globally unique")
        if any(
            sum(slot.route == route for slot in support) > MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP
            for route in M6SQLiteM4SupportRoute
        ):
            raise ValueError("support route exceeds its row budget")
        if len({(slot.route, slot.rowid) for slot in support_documents}) != len(
            support_documents
        ) or len({(slot.route, slot.artifact_id) for slot in support_documents}) != len(
            support_documents
        ):
            raise ValueError("support document commitments must be globally unique")
        if len({slot.index_identity_sha256 for slot in support_documents}) != len(
            support_documents
        ):
            raise ValueError("support document index identities must be globally unique")
        if any(
            sum(slot.route == route for slot in support_documents)
            > MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP
            for route in M6SQLiteM4SupportDocumentRoute
        ):
            raise ValueError("support document route exceeds its row budget")
        document_support_rows = {
            (slot.route, slot.rowid, slot.index_identity_sha256)
            for slot in support
            if slot.route in set(_SUPPORT_DOCUMENT_TO_ROW_ROUTE.values())
        }
        document_support_bodies = {
            (
                _SUPPORT_DOCUMENT_TO_ROW_ROUTE[slot.route],
                slot.rowid,
                slot.index_identity_sha256,
            )
            for slot in support_documents
        }
        if document_support_rows != document_support_bodies:
            raise ValueError("document-bearing support rows and bodies must close exactly")

        hearing_documents = {
            slot.artifact_id: slot
            for slot in support_documents
            if slot.route == M6SQLiteM4SupportDocumentRoute.HEARING_SESSION
        }
        if set(hearing_documents) != set(hearings_by_id):
            raise ValueError("hearing support documents must match the model matrices")
        cycle_documents = {
            (slot.artifact_id, slot.body_commitment_sha256)
            for slot in support_documents
            if slot.route == M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE
        }
        retrieval_documents = {
            (slot.artifact_id, slot.body_commitment_sha256)
            for slot in support_documents
            if slot.route == M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL
        }
        if {
            (graph.cycle_scope_id, graph.cycle_scope_sha256) for graph in graphs
        } != cycle_documents or {
            (graph.retrieval_receipt_id, graph.retrieval_commitment_sha256) for graph in graphs
        } != retrieval_documents:
            raise ValueError("cycle and retrieval support do not close the call graphs")
        completion_documents = {
            slot.artifact_id
            for slot in support_documents
            if slot.route == M6SQLiteM4SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT
        }
        if {
            value.completion_receipt_id
            for value in history
            if value.completion_receipt_id is not None
        } - completion_documents:
            raise ValueError("historical retry failure lacks completion support")

        ref_identities = tuple((ref.source, ref.kind, ref.artifact_id) for ref in refs)
        if (
            len({ref.physical_key for ref in refs}) != len(refs)
            or len(ref_identities) != len(set(ref_identities))
            or len({ref.artifact_ref_id for ref in refs}) != len(refs)
        ):
            raise ValueError("physical refs must be globally unique")
        document_bytes = (
            sum(slot.document_bytes for slot in slots)
            + sum(slot.document_bytes for slot in support_documents)
            + sum(value.document_bytes for value in history)
        )
        physical_bytes = sum(ref.size_bytes for ref in refs)
        if document_bytes > MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES:
            raise ValueError("planned M4 documents exceed the total budget")
        if physical_bytes > MAX_M6_SQLITE_M4_MODEL_PHYSICAL_TOTAL_BYTES:
            raise ValueError("planned M4 physical refs exceed the total budget")
        object.__setattr__(self, "document_slots", slots)
        object.__setattr__(self, "planned_artifact_refs", refs)
        object.__setattr__(self, "planned_document_bytes", document_bytes)
        object.__setattr__(self, "planned_physical_bytes", physical_bytes)
        object.__setattr__(self, "plan_identity_sha256", _plan_digest(self))


def _plan_is_consistent(value: object) -> bool:
    if type(value) is not M6SQLiteM4ModelDocumentsPlan:
        return False
    try:
        controlled = M6SQLiteM4ModelDocumentsPlan(
            run_id=value.run_id,
            case_id=value.case_id,
            manifest_id=value.manifest_id,
            selected_case_binding=value.selected_case_binding,
            selected_case=value.selected_case,
            selected_case_revision=value.selected_case_revision,
            selected_case_audit=value.selected_case_audit,
            hearing_model_bindings=value.hearing_model_bindings,
            selected_packs=value.selected_packs,
            observed_model_calls=value.observed_model_calls,
            call_graphs=value.call_graphs,
            historical_failures=value.historical_failures,
            support_slots=value.support_slots,
            support_document_slots=value.support_document_slots,
        )
    except (AttributeError, TypeError, ValueError, ValidationError, UnicodeError):
        return False
    return controlled == value and value.plan_identity_sha256 == _plan_digest(value)


__all__ = [
    "MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_M4_MODEL_DOCUMENT_TOTAL_BYTES",
    "MAX_M6_SQLITE_M4_MODEL_PHYSICAL_TOTAL_BYTES",
    "MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP",
    "M6SQLiteM4CallGeneration",
    "M6SQLiteM4CallGraphPlan",
    "M6SQLiteM4ClaimStatus",
    "M6SQLiteM4DocumentRoute",
    "M6SQLiteM4DocumentSlot",
    "M6SQLiteM4FailureClosureKind",
    "M6SQLiteM4HearingModelManifestBinding",
    "M6SQLiteM4HistoricalFailureBinding",
    "M6SQLiteM4ModelDocumentFailureCode",
    "M6SQLiteM4ModelDocumentsPlan",
    "M6SQLiteM4RoleModelManifestBinding",
    "M6SQLiteM4SelectedPackBinding",
    "M6SQLiteM4SupportDocumentCommitmentKind",
    "M6SQLiteM4SupportDocumentRoute",
    "M6SQLiteM4SupportDocumentSlot",
    "M6SQLiteM4SupportRoute",
    "M6SQLiteM4SupportSlot",
]
