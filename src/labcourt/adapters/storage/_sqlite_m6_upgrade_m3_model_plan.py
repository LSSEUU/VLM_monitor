"""Immutable metadata plans for same-snapshot M3 model documents.

This module is deliberately storage-free.  It owns the frozen identities that
the SQLite metadata reader emits before any canonical document or raw response
body is allowed to be read.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import ValidationError

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedModelCall,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
)

MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP = 256
MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES = 256 * 1024 * 1024


class M6SQLiteM3ModelDocumentFailureCode(StrEnum):
    """Closed, payload-free failures for M3 metadata planning."""

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


class _M6SQLiteM3MetadataFailure(Exception):
    """Private control-flow failure caught before the public traceback."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: M6SQLiteM3ModelDocumentFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code.value)


class M6SQLiteM3DocumentRoute(StrEnum):
    MODEL_REQUEST = "model_call_claims.request_json"
    MODEL_RESPONSE = "model_responses.response_json"
    MODEL_CACHE_REQUEST = "model_cache.request_json"
    MODEL_CACHE_ENTRY = "model_cache.entry_json"
    MODEL_PARSE_RECEIPT = "model_parse_receipts.receipt_json"
    PARSED_SCREENING_OUTPUT = "parsed_screening_outputs.output_json"
    MODEL_CALL_FAILURE = "model_call_failure_authorities.authority_json"
    MODEL_USAGE = "model_call_usage_accounting.usage_json"


class M6SQLiteM3SupportRoute(StrEnum):
    RUN = "runs"
    CASE_VERSION = "case_versions"
    AUDIT_ENTRY = "audit_entries"
    EVIDENCE_PACK = "evidence_packs"
    SCREENING_RESULT = "screening_results"
    BACKLOG_ITEM = "backlog_items"
    BACKLOG_ITEM_VERSION = "backlog_item_versions"
    BACKLOG_HEAD = "backlog_heads"
    BACKLOG_COMPLETION_RECEIPT = "backlog_completion_receipts"


class M6SQLiteM3SupportDocumentRoute(StrEnum):
    """Canonical support bodies needed by a later authority resolver."""

    BACKLOG_COMPLETION_RECEIPT = "backlog_completion_receipts.receipt_json"


_DOCUMENT_ROUTE_RANK = {value: index for index, value in enumerate(M6SQLiteM3DocumentRoute)}
_SUPPORT_ROUTE_RANK = {value: index for index, value in enumerate(M6SQLiteM3SupportRoute)}
_SUPPORT_DOCUMENT_ROUTE_RANK = {
    value: index for index, value in enumerate(M6SQLiteM3SupportDocumentRoute)
}
_PHYSICAL_KIND_BY_ROUTE = {
    M6SQLiteM3DocumentRoute.MODEL_REQUEST: M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
    M6SQLiteM3DocumentRoute.MODEL_RESPONSE: M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
    M6SQLiteM3DocumentRoute.MODEL_CACHE_ENTRY: M6UpgradePhysicalArtifactKind.MODEL_CACHE,
    M6SQLiteM3DocumentRoute.MODEL_PARSE_RECEIPT: (
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT
    ),
    M6SQLiteM3DocumentRoute.PARSED_SCREENING_OUTPUT: (
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT
    ),
    M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE: (M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE),
    M6SQLiteM3DocumentRoute.MODEL_USAGE: (M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT),
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
class M6SQLiteM3DocumentSlot:
    """One rowid-bound canonical document length and index commitment."""

    route: M6SQLiteM3DocumentRoute
    rowid: int
    artifact_id: str
    document_sha256: str
    document_bytes: int
    index_identity_sha256: str
    physical_ref: M6UpgradePhysicalArtifactRef | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.route, M6SQLiteM3DocumentRoute):
            raise TypeError("document route must be typed")
        if type(self.rowid) is not int or self.rowid <= 0:
            raise ValueError("document rowid must be positive")
        _require_sha256(self.artifact_id, "document artifact_id")
        _require_sha256(self.document_sha256, "document_sha256")
        _require_sha256(self.index_identity_sha256, "index_identity_sha256")
        if type(self.document_bytes) is not int or not (
            0 < self.document_bytes <= MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES
        ):
            raise ValueError("document byte length is outside the M3 plan budget")
        expected_kind = _PHYSICAL_KIND_BY_ROUTE.get(self.route)
        if expected_kind is None:
            if self.physical_ref is not None:
                raise ValueError("cache request body is not a physical artifact")
            return
        controlled = _controlled_ref(self.physical_ref)
        if (
            controlled.kind != expected_kind
            or controlled.artifact_id != self.artifact_id
            or controlled.document_sha256 != self.document_sha256
        ):
            raise ValueError("document slot and physical ref differ")
        if (
            self.route != M6SQLiteM3DocumentRoute.MODEL_RESPONSE
            and controlled.size_bytes != self.document_bytes
        ):
            raise ValueError("canonical document slot and physical size differ")
        object.__setattr__(self, "physical_ref", controlled)

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return _DOCUMENT_ROUTE_RANK[self.route], self.artifact_id, self.rowid


def _controlled_document_slot(value: object) -> M6SQLiteM3DocumentSlot:
    if type(value) is not M6SQLiteM3DocumentSlot:
        raise TypeError("document slot must be exact")
    return M6SQLiteM3DocumentSlot(
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
class M6SQLiteM3SupportSlot:
    """A body-free commitment to one supporting relational row."""

    route: M6SQLiteM3SupportRoute
    rowid: int
    identity: str
    index_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.route, M6SQLiteM3SupportRoute):
            raise TypeError("support route must be typed")
        if type(self.rowid) is not int or self.rowid <= 0:
            raise ValueError("support rowid must be positive")
        if not isinstance(self.identity, str) or not self.identity:
            raise TypeError("support identity must be non-empty")
        _require_sha256(self.index_identity_sha256, "support index identity")

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return _SUPPORT_ROUTE_RANK[self.route], self.identity, self.rowid


def _controlled_support_slot(value: object) -> M6SQLiteM3SupportSlot:
    if type(value) is not M6SQLiteM3SupportSlot:
        raise TypeError("support slot must be exact")
    return M6SQLiteM3SupportSlot(
        route=value.route,
        rowid=value.rowid,
        identity=value.identity,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM3SupportDocumentSlot:
    """A rowid-bound canonical support body with no physical-artifact claim."""

    route: M6SQLiteM3SupportDocumentRoute
    rowid: int
    artifact_id: str
    document_sha256: str
    document_bytes: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.route, M6SQLiteM3SupportDocumentRoute):
            raise TypeError("support document route must be typed")
        if type(self.rowid) is not int or self.rowid <= 0:
            raise ValueError("support document rowid must be positive")
        _require_sha256(self.artifact_id, "support document artifact_id")
        _require_sha256(self.document_sha256, "support document_sha256")
        _require_sha256(self.index_identity_sha256, "support document index identity")
        if type(self.document_bytes) is not int or not (
            0 < self.document_bytes <= MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES
        ):
            raise ValueError("support document byte length is outside the M3 plan budget")

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return _SUPPORT_DOCUMENT_ROUTE_RANK[self.route], self.artifact_id, self.rowid


def _controlled_support_document_slot(value: object) -> M6SQLiteM3SupportDocumentSlot:
    if type(value) is not M6SQLiteM3SupportDocumentSlot:
        raise TypeError("support document slot must be exact")
    return M6SQLiteM3SupportDocumentSlot(
        route=value.route,
        rowid=value.rowid,
        artifact_id=value.artifact_id,
        document_sha256=value.document_sha256,
        document_bytes=value.document_bytes,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM3SelectedPackBinding:
    rowid: int
    pack_id: str
    version: int
    document_sha256: str
    created_audit_sequence: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        if type(self.rowid) is not int or self.rowid <= 0:
            raise ValueError("pack rowid must be positive")
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


def _controlled_pack(value: object) -> M6SQLiteM3SelectedPackBinding:
    if type(value) is not M6SQLiteM3SelectedPackBinding:
        raise TypeError("selected pack binding must be exact")
    return M6SQLiteM3SelectedPackBinding(
        rowid=value.rowid,
        pack_id=value.pack_id,
        version=value.version,
        document_sha256=value.document_sha256,
        created_audit_sequence=value.created_audit_sequence,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM3HistoricalFailureBinding:
    """Canonical historical failure body retained outside the terminal graph.

    A prior claim epoch is part of the same-snapshot canonical closure, but it
    is neither the observed terminal result nor an M6 physical artifact.
    """

    request_id: str
    claim_takeover_count: int
    authority_id: str
    backlog_item_id: str
    backlog_version: int
    closure_kind: str
    closure_case_revision: int
    rowid: int
    document_sha256: str
    document_bytes: int
    index_identity_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.request_id, "historical failure request_id")
        _require_sha256(self.authority_id, "historical failure authority_id")
        _require_sha256(self.backlog_item_id, "historical failure backlog_item_id")
        _require_sha256(self.document_sha256, "historical failure document_sha256")
        _require_sha256(self.index_identity_sha256, "historical failure index identity")
        if type(self.claim_takeover_count) is not int or self.claim_takeover_count < 0:
            raise ValueError("historical failure claim epoch must be non-negative")
        if type(self.backlog_version) is not int or self.backlog_version <= 0:
            raise ValueError("historical failure backlog version must be positive")
        if self.closure_kind not in {"INITIAL_BACKLOG", "RETRY_FAILURE"}:
            raise ValueError("historical failure closure kind is invalid")
        if type(self.closure_case_revision) is not int or self.closure_case_revision <= 0:
            raise ValueError("historical failure Case revision must be positive")
        if type(self.rowid) is not int or self.rowid <= 0:
            raise ValueError("historical failure rowid must be positive")
        if type(self.document_bytes) is not int or not (
            0 < self.document_bytes <= MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES
        ):
            raise ValueError("historical failure document length is outside the M3 budget")

    @property
    def route(self) -> M6SQLiteM3DocumentRoute:
        return M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE

    @property
    def sort_key(self) -> tuple[str, int, str, int]:
        return self.request_id, self.claim_takeover_count, self.authority_id, self.rowid


def _controlled_historical_failure(
    value: object,
) -> M6SQLiteM3HistoricalFailureBinding:
    if type(value) is not M6SQLiteM3HistoricalFailureBinding:
        raise TypeError("historical failure binding must be exact")
    return M6SQLiteM3HistoricalFailureBinding(
        request_id=value.request_id,
        claim_takeover_count=value.claim_takeover_count,
        authority_id=value.authority_id,
        backlog_item_id=value.backlog_item_id,
        backlog_version=value.backlog_version,
        closure_kind=value.closure_kind,
        closure_case_revision=value.closure_case_revision,
        rowid=value.rowid,
        document_sha256=value.document_sha256,
        document_bytes=value.document_bytes,
        index_identity_sha256=value.index_identity_sha256,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM3CallGraphPlan:
    """One observation exactly joined to a response or failure row graph."""

    observation: M6UpgradeObservedModelCall
    evidence_pack_id: str
    evidence_pack_version: int
    purpose: str
    model_manifest_id: str
    request: M6SQLiteM3DocumentSlot
    claim_takeover_count: int = 0
    response: M6SQLiteM3DocumentSlot | None = None
    cache_request: M6SQLiteM3DocumentSlot | None = None
    cache: M6SQLiteM3DocumentSlot | None = None
    parse_receipt: M6SQLiteM3DocumentSlot | None = None
    parsed_output: M6SQLiteM3DocumentSlot | None = None
    failure: M6SQLiteM3DocumentSlot | None = None
    usage: M6SQLiteM3DocumentSlot | None = None
    parse_status: str | None = None
    repair_request_id: str | None = None

    def __post_init__(self) -> None:
        observation = _controlled_observation(self.observation)
        object.__setattr__(self, "observation", observation)
        if (
            observation.layer != M6LockedModelCallLayer.SCREENING
            or observation.role != M6LockedModelRole.SCREENING
        ):
            raise ValueError("M3 call graph requires a screening observation")
        _require_sha256(self.evidence_pack_id, "call graph pack_id")
        _require_sha256(self.model_manifest_id, "call graph model_manifest_id")
        if type(self.evidence_pack_version) is not int or self.evidence_pack_version <= 0:
            raise ValueError("call graph pack version must be positive")
        if type(self.claim_takeover_count) is not int or self.claim_takeover_count < 0:
            raise ValueError("call graph claim epoch must be non-negative")
        expected_purpose = "SCREENING" if observation.attempt_index == 0 else "STRUCTURE_REPAIR"
        if self.purpose != expected_purpose:
            raise ValueError("call graph purpose and attempt differ")
        if self.repair_request_id is not None:
            _require_sha256(self.repair_request_id, "repair request_id")
        request = _controlled_document_slot(self.request)
        object.__setattr__(self, "request", request)
        for field_name in (
            "response",
            "cache_request",
            "cache",
            "parse_receipt",
            "parsed_output",
            "failure",
            "usage",
        ):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _controlled_document_slot(value))
        if request.route != M6SQLiteM3DocumentRoute.MODEL_REQUEST:
            raise ValueError("call graph request route is invalid")
        if request.artifact_id != observation.request_id:
            raise ValueError("call graph request differs from observation")
        response_slots = (
            self.response,
            self.cache_request,
            self.cache,
            self.parse_receipt,
            self.usage,
        )
        if observation.result_kind == M6LockedModelCallResultKind.RESPONSE:
            if any(value is None for value in response_slots) or self.failure is not None:
                raise ValueError("response call graph is incomplete")
            if self.parse_status not in {"PARSED", "REPAIR_REQUIRED", "INVALID_FINAL"}:
                raise ValueError("response call graph parse status is invalid")
            if (self.parse_status == "PARSED") != (self.parsed_output is not None):
                raise ValueError("parsed output presence differs from parse status")
            if (self.parse_status == "REPAIR_REQUIRED") != (self.repair_request_id is not None):
                raise ValueError("repair pointer presence differs from parse status")
            if observation.attempt_index == 0 and self.parse_status == "INVALID_FINAL":
                raise ValueError("primary response cannot be an invalid-final repair")
            if observation.attempt_index == 1 and self.parse_status == "REPAIR_REQUIRED":
                raise ValueError("repair response cannot request a third attempt")
        elif (
            self.failure is None
            or any(value is not None for value in response_slots)
            or self.parsed_output is not None
            or self.parse_status is not None
            or self.repair_request_id is not None
        ):
            raise ValueError("failure call graph is incomplete")
        expected_routes = (
            (self.response, M6SQLiteM3DocumentRoute.MODEL_RESPONSE),
            (self.cache_request, M6SQLiteM3DocumentRoute.MODEL_CACHE_REQUEST),
            (self.cache, M6SQLiteM3DocumentRoute.MODEL_CACHE_ENTRY),
            (self.parse_receipt, M6SQLiteM3DocumentRoute.MODEL_PARSE_RECEIPT),
            (self.parsed_output, M6SQLiteM3DocumentRoute.PARSED_SCREENING_OUTPUT),
            (self.failure, M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE),
            (self.usage, M6SQLiteM3DocumentRoute.MODEL_USAGE),
        )
        if any(slot is not None and slot.route != route for slot, route in expected_routes):
            raise ValueError("call graph contains a document in the wrong route")

    @property
    def document_slots(self) -> tuple[M6SQLiteM3DocumentSlot, ...]:
        return tuple(
            slot
            for slot in (
                self.request,
                self.response,
                self.cache_request,
                self.cache,
                self.parse_receipt,
                self.parsed_output,
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


def _controlled_call_graph(value: object) -> M6SQLiteM3CallGraphPlan:
    if type(value) is not M6SQLiteM3CallGraphPlan:
        raise TypeError("call graph must be exact")
    return M6SQLiteM3CallGraphPlan(
        observation=_controlled_observation(value.observation),
        evidence_pack_id=value.evidence_pack_id,
        evidence_pack_version=value.evidence_pack_version,
        purpose=value.purpose,
        model_manifest_id=value.model_manifest_id,
        request=_controlled_document_slot(value.request),
        claim_takeover_count=value.claim_takeover_count,
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
        parsed_output=(
            _controlled_document_slot(value.parsed_output)
            if value.parsed_output is not None
            else None
        ),
        failure=(_controlled_document_slot(value.failure) if value.failure is not None else None),
        usage=_controlled_document_slot(value.usage) if value.usage is not None else None,
        parse_status=value.parse_status,
        repair_request_id=value.repair_request_id,
    )


def _slot_projection(slot: M6SQLiteM3DocumentSlot) -> list[object]:
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
    slot: M6SQLiteM3SupportDocumentSlot,
) -> list[object]:
    return [
        slot.route,
        slot.rowid,
        slot.artifact_id,
        slot.document_sha256,
        slot.document_bytes,
        slot.index_identity_sha256,
    ]


def _historical_failure_projection(
    binding: M6SQLiteM3HistoricalFailureBinding,
) -> list[object]:
    return [
        binding.route,
        binding.request_id,
        binding.claim_takeover_count,
        binding.authority_id,
        binding.backlog_item_id,
        binding.backlog_version,
        binding.closure_kind,
        binding.closure_case_revision,
        binding.rowid,
        binding.document_sha256,
        binding.document_bytes,
        binding.index_identity_sha256,
    ]


def _plan_projection(plan: M6SQLiteM3ModelDocumentsPlan) -> list[object]:
    return [
        "m6-sqlite-m3-model-documents-plan",
        3,
        plan.run_id,
        plan.case_id,
        plan.manifest_id,
        plan.model_manifest_id,
        plan.selected_case_binding.model_dump(mode="json"),
        plan.selected_case.model_dump(mode="json"),
        plan.selected_case_revision,
        plan.selected_case_audit.model_dump(mode="json"),
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
                graph.evidence_pack_id,
                graph.evidence_pack_version,
                graph.purpose,
                graph.model_manifest_id,
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


def _plan_digest(plan: M6SQLiteM3ModelDocumentsPlan) -> str:
    payload = canonical_json(_plan_projection(plan)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class M6SQLiteM3ModelDocumentsPlan:
    """Complete, bounded M3 metadata closure for one selected Case."""

    run_id: str
    case_id: str
    manifest_id: str
    model_manifest_id: str
    selected_case_binding: M6UpgradeCandidateCaseBinding
    selected_case: Case
    selected_case_revision: int
    selected_case_audit: AuditEntry
    selected_packs: tuple[M6SQLiteM3SelectedPackBinding, ...]
    observed_model_calls: tuple[M6UpgradeObservedModelCall, ...]
    call_graphs: tuple[M6SQLiteM3CallGraphPlan, ...]
    support_slots: tuple[M6SQLiteM3SupportSlot, ...]
    support_document_slots: tuple[M6SQLiteM3SupportDocumentSlot, ...]
    historical_failures: tuple[M6SQLiteM3HistoricalFailureBinding, ...] = ()
    document_slots: tuple[M6SQLiteM3DocumentSlot, ...] = field(init=False)
    planned_artifact_refs: tuple[M6UpgradePhysicalArtifactRef, ...] = field(init=False)
    planned_document_bytes: int = field(init=False)
    planned_physical_bytes: int = field(init=False)
    plan_identity_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value for value in (self.run_id, self.case_id)):
            raise TypeError("plan scope identifiers must be non-empty strings")
        _require_sha256(self.manifest_id, "plan manifest_id")
        _require_sha256(self.model_manifest_id, "plan model_manifest_id")
        binding = _controlled_binding(self.selected_case_binding)
        selected_case = _controlled_case(self.selected_case)
        selected_audit = _controlled_audit(self.selected_case_audit)
        object.__setattr__(self, "selected_case_binding", binding)
        object.__setattr__(self, "selected_case", selected_case)
        object.__setattr__(self, "selected_case_audit", selected_audit)
        if type(self.selected_case_revision) is not int or self.selected_case_revision <= 0:
            raise ValueError("selected Case revision must be positive")
        if (
            selected_case.run_id != self.run_id
            or selected_case.case_id != self.case_id
            or selected_case.manifest_id != self.manifest_id
            or binding.case_id != self.case_id
        ):
            raise ValueError("plan selected Case crosses scope")
        canonical_case = canonical_json(selected_case.model_dump(mode="json"))
        case_document_sha256 = hashlib.sha256(canonical_case.encode("utf-8")).hexdigest()
        if (
            case_document_sha256 != binding.case_document_sha256
            or self.selected_case_revision != binding.case_revision
            or selected_audit.run_id != self.run_id
            or selected_audit.manifest_id != self.manifest_id
            or selected_audit.sequence != binding.case_audit_sequence
            or selected_audit.entry_hash != binding.case_audit_entry_hash
            or selected_audit.after_sha256 != case_document_sha256
        ):
            raise ValueError("plan binding does not identify the selected Case document")
        typed_groups = (
            (self.selected_packs, M6SQLiteM3SelectedPackBinding),
            (self.observed_model_calls, M6UpgradeObservedModelCall),
            (self.call_graphs, M6SQLiteM3CallGraphPlan),
            (self.historical_failures, M6SQLiteM3HistoricalFailureBinding),
            (self.support_slots, M6SQLiteM3SupportSlot),
            (self.support_document_slots, M6SQLiteM3SupportDocumentSlot),
        )
        if any(
            type(values) is not tuple or any(type(value) is not expected for value in values)
            for values, expected in typed_groups
        ):
            raise TypeError("plan groups must be exact typed tuples")
        selected_packs = tuple(_controlled_pack(value) for value in self.selected_packs)
        observations = tuple(_controlled_observation(value) for value in self.observed_model_calls)
        call_graphs = tuple(_controlled_call_graph(value) for value in self.call_graphs)
        historical_failures = tuple(
            _controlled_historical_failure(value) for value in self.historical_failures
        )
        support_slots = tuple(_controlled_support_slot(value) for value in self.support_slots)
        support_document_slots = tuple(
            _controlled_support_document_slot(value) for value in self.support_document_slots
        )
        object.__setattr__(self, "selected_packs", selected_packs)
        object.__setattr__(self, "observed_model_calls", observations)
        object.__setattr__(self, "call_graphs", call_graphs)
        object.__setattr__(self, "historical_failures", historical_failures)
        object.__setattr__(self, "support_slots", support_slots)
        object.__setattr__(self, "support_document_slots", support_document_slots)
        if any(
            len(values) > MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
            for values in (selected_packs, observations, call_graphs, historical_failures)
        ):
            raise ValueError("M3 plan group exceeds its row budget")
        if selected_packs != tuple(sorted(selected_packs, key=lambda item: item.sort_key)):
            raise ValueError("selected packs must be ordered")
        ordered_observations = tuple(sorted(observations, key=lambda item: item.sort_key))
        if observations != ordered_observations:
            raise ValueError("observed calls must be ordered")
        if call_graphs != tuple(sorted(call_graphs, key=lambda item: item.sort_key)):
            raise ValueError("call graphs must be ordered")
        if historical_failures != tuple(
            sorted(historical_failures, key=lambda item: item.sort_key)
        ):
            raise ValueError("historical failures must be ordered")
        if support_slots != tuple(sorted(support_slots, key=lambda item: item.sort_key)):
            raise ValueError("support slots must be ordered")
        if support_document_slots != tuple(
            sorted(support_document_slots, key=lambda item: item.sort_key)
        ):
            raise ValueError("support document slots must be ordered")
        observation_ids = tuple(item.request_id for item in observations)
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("observed request identities must be unique")
        if tuple(graph.observation for graph in call_graphs) != observations:
            raise ValueError("call graphs and observations do not close bidirectionally")
        graph_ids = tuple(graph.observation.request_id for graph in call_graphs)
        if len(graph_ids) != len(set(graph_ids)):
            raise ValueError("call graph request identities must be unique")
        if any(graph.model_manifest_id != self.model_manifest_id for graph in call_graphs):
            raise ValueError("call graph crosses model manifest")
        graph_by_request = {graph.observation.request_id: graph for graph in call_graphs}
        historical_epoch_keys = tuple(
            (value.request_id, value.claim_takeover_count) for value in historical_failures
        )
        if len(historical_epoch_keys) != len(set(historical_epoch_keys)):
            raise ValueError("historical failure claim epochs must be unique")
        if len({value.authority_id for value in historical_failures}) != len(historical_failures):
            raise ValueError("historical failure authorities must be unique")
        for value in historical_failures:
            graph = graph_by_request.get(value.request_id)
            if graph is None or value.claim_takeover_count >= graph.claim_takeover_count:
                raise ValueError("historical failure is not older than its terminal claim")
        pack_keys = tuple((pack.pack_id, pack.version) for pack in selected_packs)
        if len(pack_keys) != len(set(pack_keys)):
            raise ValueError("selected pack keys must be unique")
        if len({pack.rowid for pack in selected_packs}) != len(selected_packs):
            raise ValueError("selected pack rowids must be unique")
        if len({pack.index_identity_sha256 for pack in selected_packs}) != len(selected_packs):
            raise ValueError("selected pack index identities must be unique")
        case_packs = {(pack.pack_id, pack.version): pack for pack in selected_case.evidence_packs}
        for pack_binding in selected_packs:
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
        graph_pack_keys = {
            (graph.evidence_pack_id, graph.evidence_pack_version) for graph in call_graphs
        }
        if graph_pack_keys != set(pack_keys):
            raise ValueError("selected packs must be the exact call-graph pack subset")
        repair_sources: dict[str, int] = {}
        for graph in call_graphs:
            if graph.repair_request_id is not None:
                repair_sources[graph.repair_request_id] = (
                    repair_sources.get(graph.repair_request_id, 0) + 1
                )
        by_request = {graph.observation.request_id: graph for graph in call_graphs}
        for graph in call_graphs:
            if graph.observation.attempt_index == 0:
                if graph.parse_status == "REPAIR_REQUIRED":
                    target = by_request.get(graph.repair_request_id or "")
                    if (
                        target is None
                        or target.observation.attempt_index != 1
                        or target.observation.layer != graph.observation.layer
                        or target.observation.role != graph.observation.role
                        or target.evidence_pack_id != graph.evidence_pack_id
                        or target.evidence_pack_version != graph.evidence_pack_version
                        or target.model_manifest_id != graph.model_manifest_id
                    ):
                        raise ValueError("primary repair pointer has no exact repair call")
                elif graph.repair_request_id is not None:
                    raise ValueError("non-repair primary call points to a repair")
            elif repair_sources.get(graph.observation.request_id) != 1:
                raise ValueError("repair call must have exactly one primary predecessor")
        slots = tuple(
            sorted(
                (slot for graph in call_graphs for slot in graph.document_slots),
                key=lambda item: item.sort_key,
            )
        )
        refs = tuple(
            sorted(
                (ref for graph in call_graphs for ref in graph.artifact_refs),
                key=lambda item: item.sort_key,
            )
        )
        if len({(slot.route, slot.rowid) for slot in slots}) != len(slots):
            raise ValueError("document slots must be globally unique")
        if len({(slot.route, slot.artifact_id) for slot in slots}) != len(slots):
            raise ValueError("document route identities must be globally unique")
        terminal_failure_slots = tuple(
            slot for slot in slots if slot.route == M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE
        )
        failure_row_keys = tuple(
            (slot.route, slot.rowid) for slot in terminal_failure_slots
        ) + tuple((value.route, value.rowid) for value in historical_failures)
        failure_artifact_keys = tuple(
            (slot.route, slot.artifact_id) for slot in terminal_failure_slots
        ) + tuple((value.route, value.authority_id) for value in historical_failures)
        failure_index_identities = tuple(
            slot.index_identity_sha256 for slot in terminal_failure_slots
        ) + tuple(value.index_identity_sha256 for value in historical_failures)
        if len(failure_row_keys) != len(set(failure_row_keys)):
            raise ValueError("terminal and historical failure rowids must be unique")
        if len(failure_artifact_keys) != len(set(failure_artifact_keys)):
            raise ValueError("terminal and historical failure identities must be unique")
        if len(failure_index_identities) != len(set(failure_index_identities)):
            raise ValueError("terminal and historical failure index identities must be unique")
        if any(
            sum(slot.route == route for slot in slots) > MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
            for route in M6SQLiteM3DocumentRoute
        ):
            raise ValueError("document route exceeds its row budget")
        if (
            len(terminal_failure_slots) + len(historical_failures)
            > MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
        ):
            raise ValueError("failure document route exceeds its row budget")
        if len({(slot.route, slot.rowid) for slot in support_slots}) != len(support_slots):
            raise ValueError("support route rowids must be globally unique")
        if len({(slot.route, slot.identity) for slot in support_slots}) != len(support_slots):
            raise ValueError("support route identities must be globally unique")
        if any(
            sum(slot.route == route for slot in support_slots)
            > MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
            for route in M6SQLiteM3SupportRoute
        ):
            raise ValueError("support route exceeds its row budget")
        if len({(slot.route, slot.rowid) for slot in support_document_slots}) != len(
            support_document_slots
        ):
            raise ValueError("support document route rowids must be globally unique")
        if len({(slot.route, slot.artifact_id) for slot in support_document_slots}) != len(
            support_document_slots
        ):
            raise ValueError("support document route identities must be globally unique")
        if len({slot.index_identity_sha256 for slot in support_document_slots}) != len(
            support_document_slots
        ):
            raise ValueError("support document index identities must be globally unique")
        if any(
            sum(slot.route == route for slot in support_document_slots)
            > MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP
            for route in M6SQLiteM3SupportDocumentRoute
        ):
            raise ValueError("support document route exceeds its row budget")
        receipt_support = {
            (slot.rowid, slot.identity)
            for slot in support_slots
            if slot.route == M6SQLiteM3SupportRoute.BACKLOG_COMPLETION_RECEIPT
        }
        receipt_documents = {
            (slot.rowid, slot.artifact_id)
            for slot in support_document_slots
            if slot.route == M6SQLiteM3SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT
        }
        if receipt_documents != receipt_support:
            raise ValueError("completion support rows and canonical bodies must close exactly")
        if len({ref.physical_key for ref in refs}) != len(refs):
            raise ValueError("physical refs must be globally unique")
        document_bytes = (
            sum(slot.document_bytes for slot in slots)
            + sum(slot.document_bytes for slot in support_document_slots)
            + sum(value.document_bytes for value in historical_failures)
        )
        physical_bytes = sum(ref.size_bytes for ref in refs)
        if document_bytes > MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES:
            raise ValueError("planned M3 documents exceed the total budget")
        if physical_bytes > MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES:
            raise ValueError("planned M3 physical refs exceed the total budget")
        object.__setattr__(self, "document_slots", slots)
        object.__setattr__(self, "planned_artifact_refs", refs)
        object.__setattr__(self, "planned_document_bytes", document_bytes)
        object.__setattr__(self, "planned_physical_bytes", physical_bytes)
        object.__setattr__(self, "plan_identity_sha256", _plan_digest(self))


def _plan_is_consistent(value: object) -> bool:
    if type(value) is not M6SQLiteM3ModelDocumentsPlan:
        return False
    try:
        controlled = M6SQLiteM3ModelDocumentsPlan(
            run_id=value.run_id,
            case_id=value.case_id,
            manifest_id=value.manifest_id,
            model_manifest_id=value.model_manifest_id,
            selected_case_binding=value.selected_case_binding,
            selected_case=value.selected_case,
            selected_case_revision=value.selected_case_revision,
            selected_case_audit=value.selected_case_audit,
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
    "MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_M3_MODEL_DOCUMENT_TOTAL_BYTES",
    "MAX_M6_SQLITE_M3_MODEL_PHYSICAL_TOTAL_BYTES",
    "MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP",
    "M6SQLiteM3CallGraphPlan",
    "M6SQLiteM3DocumentRoute",
    "M6SQLiteM3DocumentSlot",
    "M6SQLiteM3HistoricalFailureBinding",
    "M6SQLiteM3ModelDocumentFailureCode",
    "M6SQLiteM3ModelDocumentsPlan",
    "M6SQLiteM3SelectedPackBinding",
    "M6SQLiteM3SupportDocumentRoute",
    "M6SQLiteM3SupportDocumentSlot",
    "M6SQLiteM3SupportRoute",
    "M6SQLiteM3SupportSlot",
]
