"""Pure contracts for the body-free M6 M5-precedent metadata plan.

The plan has two deliberately separate inventories:

* physical M5 artifacts are limited to precedent exposures and embeddings;
* M4 hearing metadata, historical precedent revisions, and their durable
  embeddings are support authority only.

No SQLite access or canonical body decoding belongs in this module.  The
later graph builder supplies normalized, bounded rows and the later body
resolver proves that exposure-nested authorities equal this durable support
inventory before selecting any physical embedding references.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum, StrEnum
from typing import cast

from pydantic import BaseModel, ValidationError

from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    ProceduralDefectCode,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.hearing_state import (
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalStatus,
    HearingSessionEntryStatus,
)
from labcourt.contracts.m5_precedents import M5EmbeddingChannel
from labcourt.contracts.m6_replay_locked import MAX_M6_LOCKED_EMBEDDINGS_PER_CASE
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
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

MAX_M6_SQLITE_M5_PRECEDENT_CASE_ROWS = 256
MAX_M6_SQLITE_M5_PRECEDENT_EXPOSURES = 64
MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_EMBEDDINGS = MAX_M6_LOCKED_EMBEDDINGS_PER_CASE
MAX_M6_SQLITE_M5_PRECEDENT_SUPPORT_ROWS = MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE
MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_TOTAL_BYTES = MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES

if (
    MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_EMBEDDINGS != 4_096
    or MAX_M6_SQLITE_M5_PRECEDENT_SUPPORT_ROWS != 20_000
    or MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_TOTAL_BYTES != 256 * 1024 * 1024
):
    raise RuntimeError("M6 M5-precedent budgets must match the frozen M6 contracts")


class M6SQLiteM5PrecedentPlanFailureCode(StrEnum):
    """Closed, payload-free reasons for M5 precedent metadata rejection."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TRANSACTION_REQUIRED = "TRANSACTION_REQUIRED"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    UPSTREAM_M4_MISMATCH = "UPSTREAM_M4_MISMATCH"
    BRIDGE_PIN_MISMATCH = "BRIDGE_PIN_MISMATCH"
    INVENTORY_MISMATCH = "INVENTORY_MISMATCH"
    ROW_LIMIT_EXCEEDED = "ROW_LIMIT_EXCEEDED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_BUDGET_EXCEEDED = "DOCUMENT_BUDGET_EXCEEDED"
    PHYSICAL_BUDGET_EXCEEDED = "PHYSICAL_BUDGET_EXCEEDED"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_BINDING_MISMATCH = "INDEX_BINDING_MISMATCH"
    CLOSURE_MISMATCH = "CLOSURE_MISMATCH"
    PHYSICAL_PLAN_INVALID = "PHYSICAL_PLAN_INVALID"
    DATABASE_REJECTED = "DATABASE_REJECTED"


class _M6SQLiteM5PrecedentMetadataFailure(Exception):
    """Private control-flow failure retaining no database or document payload."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: M6SQLiteM5PrecedentPlanFailureCode) -> None:
        if type(reason_code) is not M6SQLiteM5PrecedentPlanFailureCode:
            raise TypeError("reason_code must be an exact M5 precedent failure code")
        self.reason_code = reason_code
        super().__init__(reason_code.value)


class M6SQLiteM5PrecedentPhysicalRoute(StrEnum):
    """The complete M5 physical route matrix admitted by V3."""

    PRECEDENT_EXPOSURE = "m5_precedent_exposures.exposure_json"
    EMBEDDING = "precedent_embeddings.embedding_json"


class M6SQLiteM5PrecedentSupportRoute(StrEnum):
    """Body-free durable authority supporting the M5 physical closure."""

    HEARING = "m4_hearings"
    CYCLE = "m4_hearing_cycles"
    RETRIEVAL = "m4_precedent_retrieval_receipts"
    PRECEDENT_REVISION = "precedents"


_PHYSICAL_KIND_BY_ROUTE = {
    M6SQLiteM5PrecedentPhysicalRoute.PRECEDENT_EXPOSURE: (
        M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE
    ),
    M6SQLiteM5PrecedentPhysicalRoute.EMBEDDING: M6UpgradePhysicalArtifactKind.EMBEDDING,
}
if set(_PHYSICAL_KIND_BY_ROUTE) != set(M6SQLiteM5PrecedentPhysicalRoute) or set(
    _PHYSICAL_KIND_BY_ROUTE.values()
) != {
    M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
    M6UpgradePhysicalArtifactKind.EMBEDDING,
}:
    raise RuntimeError("M6 M5-precedent physical routes must remain closed")


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_sha256(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return cast(str, value)


def _require_token(value: object, label: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{label} must be a string")
    return require_reference_token(value, label)


def _require_optional_sha256(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, label)


def _require_rowid(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive rowid")
    return value


def _require_positive(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be positive")
    return value


def _require_non_negative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be non-negative")
    return value


def _require_document_bytes(value: object, label: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_BYTES:
        raise ValueError(f"{label} is outside the per-document budget")
    return value


def _require_stable_unique(values: tuple[str, ...], label: str) -> None:
    if type(values) is not tuple or any(type(value) is not str for value in values):
        raise TypeError(f"{label} must be an exact string tuple")
    for value in values:
        _require_token(value, label)
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique and stably ordered")


def _require_defects(values: tuple[ProceduralDefectCode, ...], label: str) -> None:
    if type(values) is not tuple or any(
        type(value) is not ProceduralDefectCode for value in values
    ):
        raise TypeError(f"{label} must be an exact defect-code tuple")
    if len(values) > 14 or len(values) != len(set(values)):
        raise ValueError(f"{label} is not a bounded unique defect-code tuple")


def _stable_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, tuple):
        return [_stable_value(item) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _stable_value(getattr(value, item.name))
            for item in fields(value)
            if item.init
        }
    if value is None or type(value) in {str, int, bool, float}:
        return value
    raise TypeError("M5 precedent plan contains an unsupported projection value")


def _identity(label: str, value: object) -> str:
    return hashlib.sha256(
        canonical_json([label, 1, _stable_value(value)]).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentRetrievalKey:
    """One selected retrieval membership copied from the upstream M4 plan."""

    hearing_id: str
    cycle_scope_id: str
    retrieval_receipt_id: str

    def __post_init__(self) -> None:
        _require_sha256(self.hearing_id, "retrieval key hearing_id")
        _require_sha256(self.cycle_scope_id, "retrieval key cycle_scope_id")
        _require_sha256(self.retrieval_receipt_id, "retrieval key receipt_id")

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return self.hearing_id, self.cycle_scope_id, self.retrieval_receipt_id


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentHearingSlot:
    """Normalized hearing authority needed to reconstruct the M4 query."""

    run_id: str
    case_id: str
    rowid: int
    hearing_id: str
    screening_id: str
    entry_status: HearingSessionEntryStatus
    trigger_review_id: str | None
    initial_defect_codes: tuple[ProceduralDefectCode, ...]
    initial_defect_codes_sha256: str
    initial_pack_id: str
    initial_pack_version: int
    max_acquisition_rounds: int
    max_rework_rounds: int
    max_total_images: int
    max_total_output_tokens: int
    max_judge_cycles: int
    hearing_prompt_bundle_sha256: str
    prosecutor_model_manifest_id: str
    defender_model_manifest_id: str
    judge_model_manifest_id: str
    manifest_id: str
    created_audit_sequence: int
    document_sha256: str
    document_bytes: int

    def __post_init__(self) -> None:
        _require_token(self.run_id, "hearing run_id")
        _require_token(self.case_id, "hearing case_id")
        _require_rowid(self.rowid, "hearing")
        for value, label in (
            (self.hearing_id, "hearing_id"),
            (self.screening_id, "hearing screening_id"),
            (self.initial_pack_id, "hearing initial pack_id"),
            (self.hearing_prompt_bundle_sha256, "hearing prompt bundle"),
            (self.prosecutor_model_manifest_id, "hearing prosecutor manifest"),
            (self.defender_model_manifest_id, "hearing defender manifest"),
            (self.judge_model_manifest_id, "hearing judge manifest"),
            (self.manifest_id, "hearing manifest_id"),
            (self.document_sha256, "hearing document"),
            (self.initial_defect_codes_sha256, "hearing initial defects"),
        ):
            _require_sha256(value, label)
        if type(self.entry_status) is not HearingSessionEntryStatus:
            raise TypeError("hearing entry status must be exact")
        _require_optional_sha256(self.trigger_review_id, "hearing trigger review")
        _require_defects(self.initial_defect_codes, "hearing initial defects")
        _require_positive(self.initial_pack_version, "hearing initial pack version")
        for number, label in (
            (self.max_acquisition_rounds, "hearing acquisition budget"),
            (self.max_rework_rounds, "hearing rework budget"),
            (self.created_audit_sequence, "hearing audit sequence"),
        ):
            _require_non_negative(number, label)
        for number, label in (
            (self.max_total_images, "hearing image budget"),
            (self.max_total_output_tokens, "hearing token budget"),
            (self.max_judge_cycles, "hearing cycle budget"),
        ):
            _require_positive(number, label)
        if self.max_judge_cycles != 1 + self.max_acquisition_rounds + self.max_rework_rounds:
            raise ValueError("hearing cycle budget is inconsistent")
        if (self.entry_status == HearingSessionEntryStatus.REWORK_REQUIRED) != (
            self.trigger_review_id is not None and bool(self.initial_defect_codes)
        ):
            raise ValueError("hearing entry authority is inconsistent")
        _require_document_bytes(self.document_bytes, "hearing document")

    @property
    def sort_key(self) -> tuple[str, int]:
        return self.hearing_id, self.rowid

    @property
    def index_identity_sha256(self) -> str:
        return _identity("m6-m5-precedent-hearing-index", self)


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentCycleSlot:
    """Normalized hearing-cycle authority without opening ``cycle_json``."""

    run_id: str
    case_id: str
    rowid: int
    cycle_id: str
    cycle_sha256: str
    hearing_id: str
    cycle_index: int
    prior_acquisition_rounds: int
    prior_rework_rounds: int
    cycle_pack_id: str
    cycle_pack_version: int
    initial_trigger_review_id: str | None
    initial_defect_codes: tuple[ProceduralDefectCode, ...]
    initial_defect_codes_sha256: str
    rework_review_id: str | None
    rework_defect_codes: tuple[ProceduralDefectCode, ...]
    rework_defect_codes_sha256: str
    manifest_id: str
    created_audit_sequence: int
    document_sha256: str
    document_bytes: int

    def __post_init__(self) -> None:
        _require_token(self.run_id, "cycle run_id")
        _require_token(self.case_id, "cycle case_id")
        _require_rowid(self.rowid, "cycle")
        for value, label in (
            (self.cycle_id, "cycle_id"),
            (self.cycle_sha256, "cycle semantic digest"),
            (self.hearing_id, "cycle hearing_id"),
            (self.cycle_pack_id, "cycle pack_id"),
            (self.initial_defect_codes_sha256, "cycle initial defects"),
            (self.rework_defect_codes_sha256, "cycle rework defects"),
            (self.manifest_id, "cycle manifest_id"),
            (self.document_sha256, "cycle document"),
        ):
            _require_sha256(value, label)
        if type(self.cycle_index) is not int or not 1 <= self.cycle_index <= 5:
            raise ValueError("cycle index must be in [1, 5]")
        for number, label in (
            (self.prior_acquisition_rounds, "cycle prior acquisition rounds"),
            (self.prior_rework_rounds, "cycle prior rework rounds"),
            (self.created_audit_sequence, "cycle audit sequence"),
        ):
            _require_non_negative(number, label)
        if self.cycle_index != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds:
            raise ValueError("cycle counters are inconsistent")
        _require_positive(self.cycle_pack_version, "cycle pack version")
        _require_optional_sha256(self.initial_trigger_review_id, "cycle initial review")
        _require_optional_sha256(self.rework_review_id, "cycle rework review")
        _require_defects(self.initial_defect_codes, "cycle initial defects")
        _require_defects(self.rework_defect_codes, "cycle rework defects")
        if (self.initial_trigger_review_id is None) != (not self.initial_defect_codes):
            raise ValueError("cycle initial review and defects differ")
        if self.initial_trigger_review_id is not None and self.cycle_index != 1:
            raise ValueError("cycle initial review is only legal in cycle one")
        if self.prior_rework_rounds == 0:
            if self.rework_review_id is not None or self.rework_defect_codes:
                raise ValueError("initial cycle cannot claim rework authority")
        elif self.rework_review_id is None or not self.rework_defect_codes:
            raise ValueError("rework cycle requires review authority")
        _require_document_bytes(self.document_bytes, "cycle document")

    @property
    def sort_key(self) -> tuple[str, int, str]:
        return self.hearing_id, self.cycle_index, self.cycle_id

    @property
    def index_identity_sha256(self) -> str:
        return _identity("m6-m5-precedent-cycle-index", self)


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentRetrievalSlot:
    """Normalized M4 retrieval authority selected by the upstream M4 plan."""

    run_id: str
    case_id: str
    rowid: int
    retrieval_receipt_id: str
    hearing_id: str
    cycle_scope_id: str
    cycle_scope_sha256: str
    prior_acquisition_rounds: int
    prior_rework_rounds: int
    current_pack_id: str
    current_pack_version: int
    evidence_class: EvidenceClass
    violation_type: ViolationType
    rule_version: str
    top_k: int
    initial_trigger_review_id: str | None
    initial_defect_codes: tuple[ProceduralDefectCode, ...]
    initial_defect_codes_sha256: str
    rework_review_id: str | None
    rework_defect_codes: tuple[ProceduralDefectCode, ...]
    rework_defect_codes_sha256: str
    candidate_precedent_ids: tuple[str, ...]
    candidate_refs_sha256: str
    candidate_snapshot_sha256: str
    visible_precedent_ids: tuple[str, ...]
    visible_refs_sha256: str
    visible_snapshot_sha256: str
    scored_precedents_sha256: str
    retrieval_status: HearingPrecedentRetrievalStatus
    degraded_reason: HearingPrecedentDegradedReason | None
    precedent_retrieval_degraded: bool
    retriever_version: str
    retriever_manifest_id: str
    query_sha256: str
    embedding_model_manifest_id: str | None
    manifest_id: str
    document_sha256: str
    document_bytes: int

    def __post_init__(self) -> None:
        _require_token(self.run_id, "retrieval run_id")
        _require_token(self.case_id, "retrieval case_id")
        _require_rowid(self.rowid, "retrieval")
        for value, label in (
            (self.retrieval_receipt_id, "retrieval receipt_id"),
            (self.hearing_id, "retrieval hearing_id"),
            (self.cycle_scope_id, "retrieval cycle_scope_id"),
            (self.cycle_scope_sha256, "retrieval cycle digest"),
            (self.current_pack_id, "retrieval pack_id"),
            (self.initial_defect_codes_sha256, "retrieval initial defects"),
            (self.rework_defect_codes_sha256, "retrieval rework defects"),
            (self.candidate_refs_sha256, "retrieval candidate refs"),
            (self.candidate_snapshot_sha256, "retrieval candidate snapshot"),
            (self.visible_refs_sha256, "retrieval visible refs"),
            (self.visible_snapshot_sha256, "retrieval visible snapshot"),
            (self.scored_precedents_sha256, "retrieval scored precedents"),
            (self.retriever_manifest_id, "retrieval manifest"),
            (self.query_sha256, "retrieval query digest"),
            (self.manifest_id, "retrieval run manifest"),
            (self.document_sha256, "retrieval document"),
        ):
            _require_sha256(value, label)
        for number, label in (
            (self.prior_acquisition_rounds, "retrieval prior acquisition rounds"),
            (self.prior_rework_rounds, "retrieval prior rework rounds"),
        ):
            _require_non_negative(number, label)
        if 1 + self.prior_acquisition_rounds + self.prior_rework_rounds > 5:
            raise ValueError("retrieval cycle counters exceed the M4 bound")
        _require_positive(self.current_pack_version, "retrieval pack version")
        if type(self.evidence_class) is not EvidenceClass:
            raise TypeError("retrieval evidence class must be exact")
        if type(self.violation_type) is not ViolationType:
            raise TypeError("retrieval violation type must be exact")
        _require_token(self.rule_version, "retrieval rule version")
        if type(self.top_k) is not int or not 1 <= self.top_k <= 64:
            raise ValueError("retrieval top_k must be in [1, 64]")
        _require_optional_sha256(self.initial_trigger_review_id, "retrieval initial review")
        _require_optional_sha256(self.rework_review_id, "retrieval rework review")
        _require_defects(self.initial_defect_codes, "retrieval initial defects")
        _require_defects(self.rework_defect_codes, "retrieval rework defects")
        if (self.initial_trigger_review_id is None) != (not self.initial_defect_codes):
            raise ValueError("retrieval initial review and defects differ")
        if self.prior_rework_rounds == 0:
            if self.rework_review_id is not None or self.rework_defect_codes:
                raise ValueError("initial retrieval cannot claim rework authority")
        elif self.rework_review_id is None or not self.rework_defect_codes:
            raise ValueError("rework retrieval requires review authority")
        if self.initial_trigger_review_id is not None and (
            1 + self.prior_acquisition_rounds + self.prior_rework_rounds != 1
        ):
            raise ValueError("retrieval initial review is only legal in cycle one")
        _require_stable_unique(self.candidate_precedent_ids, "candidate precedent IDs")
        _require_stable_unique(self.visible_precedent_ids, "visible precedent IDs")
        if not set(self.visible_precedent_ids).issubset(self.candidate_precedent_ids):
            raise ValueError("visible precedents must be a candidate subset")
        if type(self.retrieval_status) is not HearingPrecedentRetrievalStatus:
            raise TypeError("retrieval status must be exact")
        if self.degraded_reason is not None and type(self.degraded_reason) is not (
            HearingPrecedentDegradedReason
        ):
            raise TypeError("retrieval degraded reason must be exact")
        if type(self.precedent_retrieval_degraded) is not bool:
            raise TypeError("retrieval degraded marker must be exact")
        degraded = self.retrieval_status == HearingPrecedentRetrievalStatus.DEGRADED
        if degraded != self.precedent_retrieval_degraded or degraded != (
            self.degraded_reason is not None
        ):
            raise ValueError("retrieval terminal status is inconsistent")
        if degraded and self.visible_precedent_ids:
            raise ValueError("degraded retrieval cannot expose visible precedents")
        _require_token(self.retriever_version, "retriever version")
        _require_optional_sha256(
            self.embedding_model_manifest_id,
            "retrieval embedding manifest",
        )
        if not degraded and self.embedding_model_manifest_id is None:
            raise ValueError("successful retrieval requires an embedding model manifest")
        _require_document_bytes(self.document_bytes, "retrieval document")

        version_matches = self.retriever_version == M5_HEARING_PRECEDENT_BRIDGE_VERSION
        manifest_matches = self.retriever_manifest_id == M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID
        if version_matches != manifest_matches:
            raise ValueError("M5 bridge version and manifest must be pinned together")

    @property
    def retrieval_key(self) -> M6SQLiteM5PrecedentRetrievalKey:
        return M6SQLiteM5PrecedentRetrievalKey(
            hearing_id=self.hearing_id,
            cycle_scope_id=self.cycle_scope_id,
            retrieval_receipt_id=self.retrieval_receipt_id,
        )

    @property
    def is_m5_bridge(self) -> bool:
        return (
            self.retriever_version == M5_HEARING_PRECEDENT_BRIDGE_VERSION
            and self.retriever_manifest_id == M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID
        )

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return self.retrieval_key.sort_key

    @property
    def index_identity_sha256(self) -> str:
        return _identity("m6-m5-precedent-retrieval-index", self)


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentExposureSlot:
    """One observed durable M5 exposure; its body remains unopened."""

    run_id: str
    case_id: str
    rowid: int
    exposure_id: str
    exposure_sha256: str
    hearing_id: str
    cycle_index: int
    cycle_scope_id: str
    cycle_scope_sha256: str
    retrieval_receipt_id: str
    m4_query_id: str
    m5_query_id: str
    m5_result_id: str
    candidate_count: int
    exposed_count: int
    policy_id: str
    bridge_manifest_id: str
    manifest_id: str
    document_sha256: str
    document_bytes: int

    def __post_init__(self) -> None:
        _require_token(self.run_id, "exposure run_id")
        _require_token(self.case_id, "exposure case_id")
        _require_rowid(self.rowid, "exposure")
        for value, label in (
            (self.exposure_id, "exposure_id"),
            (self.exposure_sha256, "exposure semantic digest"),
            (self.hearing_id, "exposure hearing_id"),
            (self.cycle_scope_id, "exposure cycle_scope_id"),
            (self.cycle_scope_sha256, "exposure cycle digest"),
            (self.retrieval_receipt_id, "exposure receipt_id"),
            (self.m4_query_id, "exposure M4 query_id"),
            (self.m5_query_id, "exposure M5 query_id"),
            (self.m5_result_id, "exposure M5 result_id"),
            (self.policy_id, "exposure policy_id"),
            (self.bridge_manifest_id, "exposure bridge manifest"),
            (self.manifest_id, "exposure run manifest"),
            (self.document_sha256, "exposure document"),
        ):
            _require_sha256(value, label)
        if type(self.cycle_index) is not int or not 1 <= self.cycle_index <= 5:
            raise ValueError("exposure cycle index must be in [1, 5]")
        if type(self.candidate_count) is not int or not 0 <= self.candidate_count <= 10_000:
            raise ValueError("exposure candidate count is invalid")
        if (
            type(self.exposed_count) is not int
            or not 0 <= self.exposed_count <= 64
            or self.exposed_count > self.candidate_count
        ):
            raise ValueError("exposure visible count is invalid")
        if self.bridge_manifest_id != M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID:
            raise ValueError("exposure is not pinned to the M5 hearing bridge")
        _require_document_bytes(self.document_bytes, "exposure document")

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.retrieval_receipt_id, self.exposure_id

    @property
    def index_identity_sha256(self) -> str:
        return _identity("m6-m5-precedent-exposure-index", self)

    @property
    def physical_ref(self) -> M6UpgradePhysicalArtifactRef:
        return M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            kind=M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
            artifact_id=self.exposure_id,
            document_sha256=self.document_sha256,
            content_sha256=self.document_sha256,
            size_bytes=self.document_bytes,
        )


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentDurableEmbeddingSlot:
    """One durable embedding row, observed or support-only."""

    run_id: str
    rowid: int
    embedding_id: str
    request_id: str
    channel: M5EmbeddingChannel
    input_ref: str
    input_sha256: str
    model_manifest_id: str
    dimensions: int
    algorithm: str
    manifest_id: str
    document_sha256: str
    document_bytes: int

    def __post_init__(self) -> None:
        _require_token(self.run_id, "embedding run_id")
        _require_rowid(self.rowid, "embedding")
        for value, label in (
            (self.embedding_id, "embedding_id"),
            (self.request_id, "embedding request_id"),
            (self.input_sha256, "embedding input digest"),
            (self.model_manifest_id, "embedding model manifest"),
            (self.manifest_id, "embedding run manifest"),
            (self.document_sha256, "embedding document"),
        ):
            _require_sha256(value, label)
        if type(self.channel) is not M5EmbeddingChannel:
            raise TypeError("embedding channel must be exact")
        _require_token(self.input_ref, "embedding input_ref")
        if type(self.dimensions) is not int or not 1 <= self.dimensions <= 4_096:
            raise ValueError("embedding dimensions are invalid")
        if self.algorithm != "FAKE_SHA256_SIGNED_PROJECTION_V1":
            raise ValueError("embedding algorithm is not frozen")
        _require_document_bytes(self.document_bytes, "embedding document")

    @property
    def sort_key(self) -> tuple[str, int]:
        return self.embedding_id, self.rowid

    @property
    def index_identity_sha256(self) -> str:
        return _identity("m6-m5-precedent-embedding-index", self)

    @property
    def physical_ref(self) -> M6UpgradePhysicalArtifactRef:
        return M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
            kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
            artifact_id=self.embedding_id,
            document_sha256=self.document_sha256,
            content_sha256=self.document_sha256,
            size_bytes=self.document_bytes,
        )


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot:
    """A query embedding derived pre-Pending and therefore absent from SQLite."""

    run_id: str
    case_id: str
    hearing_id: str
    cycle_scope_id: str
    retrieval_receipt_id: str
    m4_query_id: str
    m5_query_id: str
    channel: M5EmbeddingChannel
    channel_index: int
    request_id: str
    input_ref: str
    input_sha256: str
    model_manifest_id: str
    dimensions: int
    algorithm: str
    physical_ref: M6UpgradePhysicalArtifactRef

    def __post_init__(self) -> None:
        _require_token(self.run_id, "derived query run_id")
        _require_token(self.case_id, "derived query case_id")
        for value, label in (
            (self.hearing_id, "derived query hearing_id"),
            (self.cycle_scope_id, "derived query cycle_scope_id"),
            (self.retrieval_receipt_id, "derived query receipt_id"),
            (self.m4_query_id, "derived M4 query_id"),
            (self.m5_query_id, "derived M5 query_id"),
            (self.request_id, "derived embedding request_id"),
            (self.input_sha256, "derived embedding input digest"),
            (self.model_manifest_id, "derived embedding model manifest"),
        ):
            _require_sha256(value, label)
        if type(self.channel) is not M5EmbeddingChannel:
            raise TypeError("derived embedding channel must be exact")
        if type(self.channel_index) is not int or self.channel_index < 0:
            raise ValueError("derived embedding channel index must be non-negative")
        if self.channel == M5EmbeddingChannel.TEXT and self.channel_index != 0:
            raise ValueError("derived text embedding must use channel index zero")
        _require_token(self.input_ref, "derived embedding input_ref")
        if type(self.dimensions) is not int or not 1 <= self.dimensions <= 4_096:
            raise ValueError("derived embedding dimensions are invalid")
        if self.algorithm != "FAKE_SHA256_SIGNED_PROJECTION_V1":
            raise ValueError("derived embedding algorithm is not frozen")
        try:
            controlled = M6UpgradePhysicalArtifactRef.model_validate(
                self.physical_ref.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("derived embedding physical ref is invalid") from None
        if controlled != self.physical_ref:
            raise ValueError("derived embedding physical ref is not canonical")
        if (
            controlled.source != M6UpgradePhysicalArtifactSource.M5_PRECEDENT
            or controlled.kind != M6UpgradePhysicalArtifactKind.EMBEDDING
        ):
            raise ValueError("derived query physical ref uses an illegal M5 route")

    @property
    def sort_key(self) -> tuple[str, int, str]:
        return self.retrieval_receipt_id, self.channel_index, self.physical_ref.artifact_id


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentRevisionSlot:
    """One historical precedent revision available to exposure verification."""

    run_id: str
    rowid: int
    precedent_id: str
    revision: int
    authority_id: str
    status: PrecedentStatus
    source: PrecedentSource
    evidence_class: EvidenceClass
    violation_type: ViolationType
    decision_direction: VerdictDecision
    rule_version: str
    source_case_id: str | None
    citation_count: int
    text_embedding_id: str | None
    visual_embedding_ids: tuple[str, ...]
    visual_embedding_ids_sha256: str
    created_at: str
    activation_not_before: str | None
    activated_at: str | None
    manifest_id: str
    document_sha256: str
    document_bytes: int

    def __post_init__(self) -> None:
        _require_token(self.run_id, "precedent revision run_id")
        _require_rowid(self.rowid, "precedent revision")
        _require_token(self.precedent_id, "precedent_id")
        _require_positive(self.revision, "precedent revision")
        for value, label in (
            (self.authority_id, "precedent authority_id"),
            (self.visual_embedding_ids_sha256, "precedent visual embedding IDs"),
            (self.manifest_id, "precedent manifest_id"),
            (self.document_sha256, "precedent authority document"),
        ):
            _require_sha256(value, label)
        if type(self.status) is not PrecedentStatus:
            raise TypeError("precedent status must be exact")
        if type(self.source) is not PrecedentSource:
            raise TypeError("precedent source must be exact")
        if type(self.evidence_class) is not EvidenceClass:
            raise TypeError("precedent evidence class must be exact")
        if type(self.violation_type) is not ViolationType:
            raise TypeError("precedent violation type must be exact")
        if type(self.decision_direction) is not VerdictDecision:
            raise TypeError("precedent direction must be exact")
        _require_token(self.rule_version, "precedent rule version")
        if self.source_case_id is not None:
            _require_token(self.source_case_id, "precedent source Case")
        if self.citation_count != 0:
            raise ValueError("stored precedent revision citation count must remain zero")
        _require_optional_sha256(self.text_embedding_id, "precedent text embedding")
        _require_stable_unique(self.visual_embedding_ids, "precedent visual embeddings")
        for timestamp, label in (
            (self.created_at, "precedent created_at"),
            (self.activation_not_before, "precedent activation_not_before"),
            (self.activated_at, "precedent activated_at"),
        ):
            if timestamp is not None and (type(timestamp) is not str or not timestamp):
                raise ValueError(f"{label} must be a non-empty timestamp")
        _require_document_bytes(self.document_bytes, "precedent authority document")

    @property
    def embedding_ids(self) -> tuple[str, ...]:
        values = self.visual_embedding_ids
        if self.text_embedding_id is not None:
            values = (*values, self.text_embedding_id)
        return tuple(sorted(values))

    @property
    def sort_key(self) -> tuple[str, int, int]:
        return self.precedent_id, self.revision, self.rowid

    @property
    def index_identity_sha256(self) -> str:
        return _identity("m6-m5-precedent-revision-index", self)


def _controlled_observation(value: object) -> M6UpgradeObservedArtifactIdentity:
    if type(value) is not M6UpgradeObservedArtifactIdentity:
        raise TypeError("M5 observation must be exact")
    try:
        controlled = M6UpgradeObservedArtifactIdentity.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("M5 observation must be canonical") from None
    if controlled != value:
        raise ValueError("M5 observation must be canonical")
    return controlled


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentDocumentsPlan:
    """Complete body-free M5 closure for retrievals selected by one M4 plan."""

    run_id: str
    case_id: str
    manifest_id: str
    upstream_m4_plan_identity_sha256: str
    upstream_retrieval_keys: tuple[M6SQLiteM5PrecedentRetrievalKey, ...]
    observed_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...]
    hearings: tuple[M6SQLiteM5PrecedentHearingSlot, ...]
    cycles: tuple[M6SQLiteM5PrecedentCycleSlot, ...]
    retrievals: tuple[M6SQLiteM5PrecedentRetrievalSlot, ...]
    exposures: tuple[M6SQLiteM5PrecedentExposureSlot, ...]
    derived_query_embeddings: tuple[M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot, ...]
    durable_embeddings: tuple[M6SQLiteM5PrecedentDurableEmbeddingSlot, ...]
    precedent_revisions: tuple[M6SQLiteM5PrecedentRevisionSlot, ...]
    planned_artifact_refs: tuple[M6UpgradePhysicalArtifactRef, ...] = field(init=False)
    planned_document_bytes: int = field(init=False)
    planned_physical_bytes: int = field(init=False)
    plan_identity_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_token(self.run_id, "M5 plan run_id")
        _require_token(self.case_id, "M5 plan case_id")
        _require_sha256(self.manifest_id, "M5 plan manifest_id")
        _require_sha256(self.upstream_m4_plan_identity_sha256, "upstream M4 plan identity")
        typed_groups: tuple[tuple[tuple[object, ...], type[object]], ...] = (
            (self.upstream_retrieval_keys, M6SQLiteM5PrecedentRetrievalKey),
            (self.observed_artifacts, M6UpgradeObservedArtifactIdentity),
            (self.hearings, M6SQLiteM5PrecedentHearingSlot),
            (self.cycles, M6SQLiteM5PrecedentCycleSlot),
            (self.retrievals, M6SQLiteM5PrecedentRetrievalSlot),
            (self.exposures, M6SQLiteM5PrecedentExposureSlot),
            (
                self.derived_query_embeddings,
                M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot,
            ),
            (self.durable_embeddings, M6SQLiteM5PrecedentDurableEmbeddingSlot),
            (self.precedent_revisions, M6SQLiteM5PrecedentRevisionSlot),
        )
        if any(
            type(values) is not tuple or any(type(value) is not expected for value in values)
            for values, expected in typed_groups
        ):
            raise TypeError("M5 plan groups must be exact typed tuples")

        observations = tuple(_controlled_observation(value) for value in self.observed_artifacts)
        object.__setattr__(self, "observed_artifacts", observations)
        ordered_groups = (
            (self.upstream_retrieval_keys, lambda value: value.sort_key),
            (observations, lambda value: value.sort_key),
            (self.hearings, lambda value: value.sort_key),
            (self.cycles, lambda value: value.sort_key),
            (self.retrievals, lambda value: value.sort_key),
            (self.exposures, lambda value: value.sort_key),
            (self.derived_query_embeddings, lambda value: value.sort_key),
            (self.durable_embeddings, lambda value: value.sort_key),
            (self.precedent_revisions, lambda value: value.sort_key),
        )
        if any(values != tuple(sorted(values, key=key)) for values, key in ordered_groups):
            raise ValueError("M5 plan groups must use stable order")

        if any(
            value.source != M6UpgradePhysicalArtifactSource.M5_PRECEDENT
            or value.kind
            not in {
                M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
                M6UpgradePhysicalArtifactKind.EMBEDDING,
            }
            for value in observations
        ):
            raise ValueError("M5 plan observations use an illegal physical route")
        observation_keys = tuple(value.identity_key for value in observations)
        if len(observation_keys) != len(set(observation_keys)):
            raise ValueError("M5 observations must be unique")
        observed_exposures = {
            value.artifact_id
            for value in observations
            if value.kind == M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE
        }
        observed_embeddings = {
            value.artifact_id
            for value in observations
            if value.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
        }
        if (
            len(observed_exposures) > MAX_M6_SQLITE_M5_PRECEDENT_EXPOSURES
            or len(observed_embeddings) > MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_EMBEDDINGS
        ):
            raise ValueError("M5 physical observation inventory exceeds its budget")
        observation_by_identity = {(value.kind, value.artifact_id): value for value in observations}

        keys = tuple(value.sort_key for value in self.upstream_retrieval_keys)
        if len(keys) != len(set(keys)):
            raise ValueError("upstream retrieval membership must be unique")
        retrieval_keys = tuple(value.retrieval_key.sort_key for value in self.retrievals)
        if retrieval_keys != keys:
            raise ValueError("M5 retrievals must exactly match the upstream M4 plan membership")
        if len(self.retrievals) > MAX_M6_SQLITE_M5_PRECEDENT_CASE_ROWS:
            raise ValueError("selected retrieval inventory exceeds its budget")
        if (
            len(self.hearings) > MAX_M6_SQLITE_M5_PRECEDENT_CASE_ROWS
            or len(self.cycles) > MAX_M6_SQLITE_M5_PRECEDENT_CASE_ROWS
        ):
            raise ValueError("selected M4 support inventory exceeds its budget")
        if (
            len(self.durable_embeddings) > MAX_M6_SQLITE_M5_PRECEDENT_SUPPORT_ROWS
            or len(self.precedent_revisions) > MAX_M6_SQLITE_M5_PRECEDENT_SUPPORT_ROWS
        ):
            raise ValueError("M5 durable support inventory exceeds its budget")

        hearing_by_id = {value.hearing_id: value for value in self.hearings}
        cycle_by_id = {value.cycle_id: value for value in self.cycles}
        if len(hearing_by_id) != len(self.hearings) or len(cycle_by_id) != len(self.cycles):
            raise ValueError("M4 hearing support identities must be unique")
        if (
            len({value.rowid for value in self.hearings}) != len(self.hearings)
            or len({value.index_identity_sha256 for value in self.hearings}) != len(self.hearings)
            or len({value.rowid for value in self.cycles}) != len(self.cycles)
            or len({value.index_identity_sha256 for value in self.cycles}) != len(self.cycles)
            or len({value.rowid for value in self.retrievals}) != len(self.retrievals)
            or len({value.index_identity_sha256 for value in self.retrievals})
            != len(self.retrievals)
        ):
            raise ValueError("M4 retrieval support rowids and index identities must be unique")
        if set(hearing_by_id) != {value.hearing_id for value in self.retrievals}:
            raise ValueError("hearing support must be the exact selected retrieval set")
        if set(cycle_by_id) != {value.cycle_scope_id for value in self.retrievals}:
            raise ValueError("cycle support must be the exact selected retrieval set")
        for retrieval in self.retrievals:
            hearing = hearing_by_id[retrieval.hearing_id]
            cycle = cycle_by_id[retrieval.cycle_scope_id]
            if (
                hearing.run_id != self.run_id
                or hearing.case_id != self.case_id
                or cycle.run_id != self.run_id
                or cycle.case_id != self.case_id
                or cycle.hearing_id != hearing.hearing_id
                or cycle.cycle_sha256 != retrieval.cycle_scope_sha256
                or cycle.prior_acquisition_rounds != retrieval.prior_acquisition_rounds
                or cycle.prior_rework_rounds != retrieval.prior_rework_rounds
                or cycle.cycle_pack_id != retrieval.current_pack_id
                or cycle.cycle_pack_version != retrieval.current_pack_version
                or retrieval.manifest_id != self.manifest_id
            ):
                raise ValueError("selected retrieval crosses its normalized M4 authority")

        exposures_by_receipt: dict[str, list[M6SQLiteM5PrecedentExposureSlot]] = {}
        for exposure in self.exposures:
            exposures_by_receipt.setdefault(exposure.retrieval_receipt_id, []).append(exposure)
        derived_by_receipt: dict[str, list[M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot]] = {}
        for embedding in self.derived_query_embeddings:
            derived_by_receipt.setdefault(embedding.retrieval_receipt_id, []).append(embedding)
        for retrieval in self.retrievals:
            exposures = exposures_by_receipt.get(retrieval.retrieval_receipt_id, [])
            derived = derived_by_receipt.get(retrieval.retrieval_receipt_id, [])
            bridge_success = (
                retrieval.is_m5_bridge
                and retrieval.retrieval_status == HearingPrecedentRetrievalStatus.SUCCESS
            )
            if bridge_success:
                if len(exposures) != 1 or len(derived) != 1:
                    raise ValueError("successful M5 bridge retrieval lacks exposure/query closure")
                exposure = exposures[0]
                derived_embedding = derived[0]
                if (
                    exposure.run_id != self.run_id
                    or exposure.case_id != self.case_id
                    or exposure.hearing_id != retrieval.hearing_id
                    or exposure.cycle_scope_id != retrieval.cycle_scope_id
                    or exposure.cycle_scope_sha256 != retrieval.cycle_scope_sha256
                    or exposure.cycle_index
                    != 1 + retrieval.prior_acquisition_rounds + retrieval.prior_rework_rounds
                    or exposure.candidate_count != len(retrieval.candidate_precedent_ids)
                    or exposure.exposed_count != len(retrieval.visible_precedent_ids)
                ):
                    raise ValueError("M5 exposure crosses its M4 retrieval")
                if (
                    derived_embedding.run_id != self.run_id
                    or derived_embedding.case_id != self.case_id
                    or derived_embedding.hearing_id != retrieval.hearing_id
                    or derived_embedding.cycle_scope_id != retrieval.cycle_scope_id
                    or derived_embedding.m4_query_id != exposure.m4_query_id
                    or derived_embedding.m5_query_id != exposure.m5_query_id
                    or derived_embedding.channel != M5EmbeddingChannel.TEXT
                    or derived_embedding.channel_index != 0
                ):
                    raise ValueError("derived query embedding crosses its exposure")
            elif exposures or derived:
                raise ValueError("non-success or non-M5 retrieval cannot claim M5 artifacts")
        if set(exposures_by_receipt) - {
            value.retrieval_receipt_id for value in self.retrievals
        } or set(derived_by_receipt) - {value.retrieval_receipt_id for value in self.retrievals}:
            raise ValueError("M5 artifacts are not members of the upstream retrieval cut")

        exposure_ids = tuple(value.exposure_id for value in self.exposures)
        if len(exposure_ids) != len(set(exposure_ids)) or set(exposure_ids) != observed_exposures:
            raise ValueError("M5 exposure rows must exactly match the observation")
        if any(
            observation_by_identity[
                (M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE, exposure_id)
            ].usage
            != M6UpgradeArtifactUsage.PRODUCED
            for exposure_id in exposure_ids
        ):
            raise ValueError("M5 exposure observations must be produced")
        durable_ids = tuple(value.embedding_id for value in self.durable_embeddings)
        derived_ids = tuple(
            value.physical_ref.artifact_id for value in self.derived_query_embeddings
        )
        if len(durable_ids) != len(set(durable_ids)):
            raise ValueError("durable M5 embedding identities must be unique")
        derived_authority_by_id: dict[
            str,
            tuple[
                M5EmbeddingChannel,
                int,
                str,
                str,
                str,
                str,
                int,
                str,
                M6UpgradePhysicalArtifactRef,
            ],
        ] = {}
        for value in self.derived_query_embeddings:
            authority = (
                value.channel,
                value.channel_index,
                value.request_id,
                value.input_ref,
                value.input_sha256,
                value.model_manifest_id,
                value.dimensions,
                value.algorithm,
                value.physical_ref,
            )
            previous = derived_authority_by_id.setdefault(
                value.physical_ref.artifact_id,
                authority,
            )
            if previous != authority:
                raise ValueError("reused derived embedding ID rewrites its byte authority")
        if set(durable_ids).intersection(derived_ids):
            raise ValueError("derived query embeddings cannot masquerade as durable rows")
        if observed_embeddings != (set(durable_ids).intersection(observed_embeddings)) | set(
            derived_ids
        ):
            raise ValueError("observed embeddings are not covered by durable or derived authority")
        if not set(derived_ids).issubset(observed_embeddings):
            raise ValueError("derived query embeddings must be explicit observations")
        if any(
            observation_by_identity[(M6UpgradePhysicalArtifactKind.EMBEDDING, embedding_id)].usage
            != M6UpgradeArtifactUsage.PRODUCED
            for embedding_id in derived_ids
        ):
            raise ValueError("derived query embeddings must be produced")
        if any(
            observation_by_identity[(M6UpgradePhysicalArtifactKind.EMBEDDING, embedding_id)].usage
            != M6UpgradeArtifactUsage.CONSUMED
            for embedding_id in set(durable_ids).intersection(observed_embeddings)
        ):
            raise ValueError("observed durable historical embeddings must be consumed")

        revision_keys = tuple(
            (value.precedent_id, value.revision) for value in self.precedent_revisions
        )
        if len(revision_keys) != len(set(revision_keys)):
            raise ValueError("precedent revision inventory must be unique")
        required_precedents = {
            precedent_id
            for retrieval in self.retrievals
            if retrieval.is_m5_bridge
            and retrieval.retrieval_status == HearingPrecedentRetrievalStatus.SUCCESS
            for precedent_id in retrieval.candidate_precedent_ids
        }
        revisions_by_precedent: dict[str, list[int]] = {}
        for revision in self.precedent_revisions:
            revisions_by_precedent.setdefault(revision.precedent_id, []).append(revision.revision)
        if set(revisions_by_precedent) != required_precedents:
            raise ValueError("precedent revision support is not the exact bridge candidate set")
        if any(
            values != list(range(1, max(values) + 1)) for values in revisions_by_precedent.values()
        ):
            raise ValueError("precedent revision support must contain complete revision histories")
        required_support_embeddings = {
            embedding_id
            for revision in self.precedent_revisions
            for embedding_id in revision.embedding_ids
        }
        if not required_support_embeddings.issubset(durable_ids):
            raise ValueError("historical precedent embedding support is incomplete")
        expected_durable_embeddings = required_support_embeddings | (
            observed_embeddings - set(derived_ids)
        )
        if set(durable_ids) != expected_durable_embeddings:
            raise ValueError("durable embedding rows are not the exact observed/support inventory")

        if any(value.run_id != self.run_id for value in self.durable_embeddings) or any(
            value.run_id != self.run_id for value in self.precedent_revisions
        ):
            raise ValueError("M5 durable support crosses the selected run")
        if len({value.rowid for value in self.exposures}) != len(self.exposures):
            raise ValueError("M5 exposure rowids must be unique")
        if len({value.rowid for value in self.durable_embeddings}) != len(self.durable_embeddings):
            raise ValueError("M5 embedding rowids must be unique")
        if len({value.rowid for value in self.precedent_revisions}) != len(
            self.precedent_revisions
        ):
            raise ValueError("precedent revision rowids must be unique")
        if (
            len({value.index_identity_sha256 for value in self.exposures}) != len(self.exposures)
            or len({value.index_identity_sha256 for value in self.durable_embeddings})
            != len(self.durable_embeddings)
            or len({value.index_identity_sha256 for value in self.precedent_revisions})
            != len(self.precedent_revisions)
        ):
            raise ValueError("M5 durable index identities must be unique")

        observed_durable = (
            value.physical_ref
            for value in self.durable_embeddings
            if value.embedding_id in observed_embeddings
        )
        unique_derived_refs = tuple(
            value[-1]
            for _, value in sorted(derived_authority_by_id.items(), key=lambda item: item[0])
        )
        refs = tuple(
            sorted(
                (
                    *(value.physical_ref for value in self.exposures),
                    *unique_derived_refs,
                    *observed_durable,
                ),
                key=lambda value: value.sort_key,
            )
        )
        identities = tuple((value.source, value.kind, value.artifact_id) for value in refs)
        if len(identities) != len(set(identities)) or len(
            {value.artifact_ref_id for value in refs}
        ) != len(refs):
            raise ValueError("planned M5 physical refs must be globally unique")
        document_bytes = (
            sum(value.document_bytes for value in self.hearings)
            + sum(value.document_bytes for value in self.cycles)
            + sum(value.document_bytes for value in self.retrievals)
            + sum(value.document_bytes for value in self.exposures)
            + sum(value.document_bytes for value in self.durable_embeddings)
            + sum(value.document_bytes for value in self.precedent_revisions)
            + sum(value.size_bytes for value in unique_derived_refs)
        )
        physical_bytes = sum(value.size_bytes for value in refs)
        if document_bytes > MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_TOTAL_BYTES:
            raise ValueError("planned M5 documents exceed the total budget")
        if physical_bytes > MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_TOTAL_BYTES:
            raise ValueError("planned M5 physical refs exceed the total budget")
        object.__setattr__(self, "planned_artifact_refs", refs)
        object.__setattr__(self, "planned_document_bytes", document_bytes)
        object.__setattr__(self, "planned_physical_bytes", physical_bytes)
        object.__setattr__(self, "plan_identity_sha256", _identity("m6-m5-precedent-plan", self))


def _plan_is_consistent(value: object) -> bool:
    """Return whether a frozen plan still matches its stable projection."""

    return type(
        value
    ) is M6SQLiteM5PrecedentDocumentsPlan and value.plan_identity_sha256 == _identity(
        "m6-m5-precedent-plan", value
    )


__all__ = [
    "MAX_M6_SQLITE_M5_PRECEDENT_CASE_ROWS",
    "MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_TOTAL_BYTES",
    "MAX_M6_SQLITE_M5_PRECEDENT_EXPOSURES",
    "MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_EMBEDDINGS",
    "MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_TOTAL_BYTES",
    "MAX_M6_SQLITE_M5_PRECEDENT_SUPPORT_ROWS",
    "M6SQLiteM5PrecedentCycleSlot",
    "M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot",
    "M6SQLiteM5PrecedentDocumentsPlan",
    "M6SQLiteM5PrecedentDurableEmbeddingSlot",
    "M6SQLiteM5PrecedentExposureSlot",
    "M6SQLiteM5PrecedentHearingSlot",
    "M6SQLiteM5PrecedentPhysicalRoute",
    "M6SQLiteM5PrecedentPlanFailureCode",
    "M6SQLiteM5PrecedentRetrievalKey",
    "M6SQLiteM5PrecedentRetrievalSlot",
    "M6SQLiteM5PrecedentRevisionSlot",
    "M6SQLiteM5PrecedentSupportRoute",
]
