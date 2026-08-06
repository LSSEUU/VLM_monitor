"""Build the body-free M5 precedent plan from one frozen SQLite read cut."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar, cast

from pydantic import BaseModel, ValidationError

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
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
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m5_precedents import M5EmbeddingChannel
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ContractViolation
from labcourt.ports.m6_historical_retrieval import (
    M6HistoricalAuthorityDocument,
    M6ValidatedHistoricalRetrievalSnapshots,
)
from labcourt.ports.m6_procedural_gate_authority import M6ProceduralGateHistorySnapshot

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4ModelDocumentsPlan,
    M6SQLiteM4SupportDocumentRoute,
)
from ._sqlite_m6_upgrade_m4_model_plan import (
    _plan_is_consistent as _m4_plan_is_consistent,
)
from ._sqlite_m6_upgrade_m5_precedent_bodies import (
    M6SQLiteM5PrecedentAuthoritySnapshot,
    build_m6_sqlite_m5_precedent_authority_snapshot,
)
from ._sqlite_m6_upgrade_m5_precedent_plan import (
    MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_TOTAL_BYTES,
    MAX_M6_SQLITE_M5_PRECEDENT_EXPOSURES,
    MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_EMBEDDINGS,
    MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_TOTAL_BYTES,
    M6SQLiteM5PrecedentCycleSlot,
    M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot,
    M6SQLiteM5PrecedentDocumentsPlan,
    M6SQLiteM5PrecedentDurableEmbeddingSlot,
    M6SQLiteM5PrecedentExposureSlot,
    M6SQLiteM5PrecedentHearingSlot,
    M6SQLiteM5PrecedentPlanFailureCode,
    M6SQLiteM5PrecedentRetrievalKey,
    M6SQLiteM5PrecedentRetrievalSlot,
    M6SQLiteM5PrecedentRevisionSlot,
    _M6SQLiteM5PrecedentMetadataFailure,
)
from ._sqlite_m6_upgrade_m5_precedent_query import (
    M6SQLiteM5CycleQueryMetadata,
    M6SQLiteM5ExposureQueryMetadata,
    M6SQLiteM5HearingQueryMetadata,
    M6SQLiteM5PrecedentQueryError,
    M6SQLiteM5PrecedentQueryFailureCode,
    M6SQLiteM5RetrievalQueryMetadata,
    reconstruct_m6_sqlite_m5_precedent_query,
)
from ._sqlite_m6_upgrade_m5_precedent_rows import (
    M6SQLiteM5PrecedentCaseRows,
    M6SQLiteM5PrecedentRowDocumentRoute,
    candidate_precedent_ids,
    document_bytes,
    normalized_json_sha256,
    precedent_revision_embedding_ids,
    read_candidate_precedent_revision_rows,
    read_case_retrieval_rows,
    read_durable_embedding_rows,
    read_exposure_rows,
)


class M6SQLiteM5PrecedentDocumentError(ContractViolation):
    """One payload-free reason for rejecting an M5 precedent metadata plan."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: M6SQLiteM5PrecedentPlanFailureCode) -> None:
        if type(reason_code) is not M6SQLiteM5PrecedentPlanFailureCode:
            raise TypeError("reason_code must be an exact M5 precedent plan failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 SQLite M5 precedent planning failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class _PlanAttempt:
    value: M6SQLiteM5PrecedentDocumentsPlan | None
    failure_code: M6SQLiteM5PrecedentPlanFailureCode | None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.failure_code is None):
            raise RuntimeError("M5 precedent plan attempt must contain exactly one outcome")


@dataclass(frozen=True, slots=True)
class _ResolveAttempt:
    value: M6SQLiteM5PrecedentAuthoritySnapshot | None
    failure_code: M6SQLiteM5PrecedentPlanFailureCode | None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.failure_code is None):
            raise RuntimeError("M5 precedent resolve attempt must contain exactly one outcome")


def _fail(reason_code: M6SQLiteM5PrecedentPlanFailureCode) -> NoReturn:
    raise _M6SQLiteM5PrecedentMetadataFailure(reason_code)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _controlled_model(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    assert isinstance(value, BaseModel)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    return controlled


def _case_authority_is_consistent(value: object) -> bool:
    if type(value) is not M6SQLiteCaseAuthorityDocument:
        return False
    try:
        binding = _controlled_model(value.candidate_case_binding, M6UpgradeCandidateCaseBinding)
        selected_case = _controlled_model(value.case, Case)
        audit = _controlled_model(value.audit_entry, AuditEntry)
        controlled = M6SQLiteCaseAuthorityDocument(
            candidate_case_binding=binding,
            case=selected_case,
            canonical_case_document=value.canonical_case_document,
            audit_entry=audit,
            canonical_audit_document=value.canonical_audit_document,
        )
    except _M6SQLiteM5PrecedentMetadataFailure:
        return False
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return False
    return controlled == value


def _controlled_observations(
    value: object,
) -> tuple[M6UpgradeObservedArtifactIdentity, ...]:
    if type(value) is not tuple or any(
        type(item) is not M6UpgradeObservedArtifactIdentity for item in value
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    assert isinstance(value, tuple)
    try:
        controlled = tuple(
            M6UpgradeObservedArtifactIdentity.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in value
        )
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    if (
        controlled != value
        or controlled != tuple(sorted(controlled, key=lambda item: item.sort_key))
        or len({item.identity_key for item in controlled}) != len(controlled)
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    if any(
        item.source != M6UpgradePhysicalArtifactSource.M5_PRECEDENT
        or item.kind
        not in {
            M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
            M6UpgradePhysicalArtifactKind.EMBEDDING,
        }
        for item in controlled
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    exposure_count = sum(
        item.kind == M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE for item in controlled
    )
    embedding_count = len(controlled) - exposure_count
    if (
        exposure_count > MAX_M6_SQLITE_M5_PRECEDENT_EXPOSURES
        or embedding_count > MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_EMBEDDINGS
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED)
    return controlled


def _active(connection: M6LiveReader) -> None:
    active = connection.in_transaction
    if type(active) is not bool:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED)
    if not active:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.TRANSACTION_REQUIRED)


def _validated_arguments(
    connection: object,
    manifest: object,
    config: object,
    selected_case_authority: object,
    upstream_m4_model_plan: object,
    observed_precedent_artifacts: object,
) -> tuple[
    M6LiveReader,
    RunManifest,
    AppConfig,
    M6SQLiteCaseAuthorityDocument,
    M6SQLiteM4ModelDocumentsPlan,
    tuple[M6UpgradeObservedArtifactIdentity, ...],
]:
    if (
        type(connection) is not M6LiveReader
        or type(upstream_m4_model_plan) is not M6SQLiteM4ModelDocumentsPlan
        or not _case_authority_is_consistent(selected_case_authority)
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    assert isinstance(connection, M6LiveReader)
    assert isinstance(selected_case_authority, M6SQLiteCaseAuthorityDocument)
    assert isinstance(upstream_m4_model_plan, M6SQLiteM4ModelDocumentsPlan)
    controlled_manifest = _controlled_model(manifest, RunManifest)
    controlled_config = _controlled_model(config, AppConfig)
    observations = _controlled_observations(observed_precedent_artifacts)
    if not _m4_plan_is_consistent(upstream_m4_model_plan):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.UPSTREAM_M4_MISMATCH)
    authority = selected_case_authority
    selected_case = authority.case
    upstream = upstream_m4_model_plan
    if (
        controlled_manifest.config_sha256 != controlled_config.config_sha256
        or controlled_manifest.rule_version != controlled_config.rule_version
        or selected_case.manifest_id != controlled_manifest.manifest_id
        or upstream.manifest_id != controlled_manifest.manifest_id
        or upstream.run_id != selected_case.run_id
        or upstream.case_id != selected_case.case_id
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.SCOPE_MISMATCH)
    if (
        upstream.selected_case_binding != authority.candidate_case_binding
        or upstream.selected_case != selected_case
        or upstream.selected_case_revision != authority.candidate_case_binding.case_revision
        or upstream.selected_case_audit != authority.audit_entry
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.UPSTREAM_M4_MISMATCH)
    _active(connection)
    return (
        connection,
        controlled_manifest,
        controlled_config,
        authority,
        upstream,
        observations,
    )


def _value(row: sqlite3.Row, column: str) -> object:
    try:
        return row[column]
    except (IndexError, KeyError, TypeError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _text(row: sqlite3.Row, column: str) -> str:
    value = _value(row, column)
    if type(value) is not str or not value:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _token(row: sqlite3.Row, column: str) -> str:
    value = _text(row, column)
    try:
        return require_reference_token(value, f"M6 M5 precedent {column}")
    except (TypeError, ValueError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _sha256(row: sqlite3.Row, column: str) -> str:
    value = _value(row, column)
    if not _is_sha256(value):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return cast(str, value)


def _optional_sha256(row: sqlite3.Row, column: str) -> str | None:
    value = _value(row, column)
    if value is None:
        return None
    if not _is_sha256(value):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return cast(str, value)


def _optional_token(row: sqlite3.Row, column: str) -> str | None:
    value = _value(row, column)
    if value is None:
        return None
    if type(value) is not str:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    try:
        return require_reference_token(value, f"M6 M5 precedent {column}")
    except (TypeError, ValueError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _integer(
    row: sqlite3.Row,
    column: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    value = _value(row, column)
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _boolean(row: sqlite3.Row, column: str) -> bool:
    value = _integer(row, column, maximum=1)
    return bool(value)


_EnumT = TypeVar("_EnumT", bound=StrEnum)


def _enum(row: sqlite3.Row, column: str, expected: type[_EnumT]) -> _EnumT:
    value = _value(row, column)
    if type(value) is not str:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    try:
        return expected(value)
    except ValueError:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _optional_enum(
    row: sqlite3.Row,
    column: str,
    expected: type[_EnumT],
) -> _EnumT | None:
    value = _value(row, column)
    if value is None:
        return None
    if type(value) is not str:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    try:
        return expected(value)
    except ValueError:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _array(row: sqlite3.Row, column: str) -> list[object]:
    value = _value(row, column)
    if type(value) is not str:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    if type(decoded) is not list:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return decoded


def _defects(row: sqlite3.Row, column: str) -> tuple[ProceduralDefectCode, ...]:
    decoded = _array(row, column)
    if any(type(value) is not str for value in decoded):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    values = cast(list[str], decoded)
    try:
        controlled = tuple(ProceduralDefectCode(value) for value in values)
    except ValueError:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    if controlled != tuple(sorted(controlled, key=lambda value: value.value)) or len(
        controlled
    ) != len(set(controlled)):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return controlled


def _artifact_ids(row: sqlite3.Row, column: str) -> tuple[str, ...]:
    decoded = _array(row, column)
    try:
        refs = tuple(ArtifactRef.model_validate(value) for value in decoded)
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    if any(value.kind != ArtifactKind.PRECEDENT for value in refs):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    values = tuple(value.artifact_id for value in refs)
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return values


def _string_ids(row: sqlite3.Row, column: str) -> tuple[str, ...]:
    decoded = _array(row, column)
    if any(type(value) is not str for value in decoded):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    values = cast(tuple[str, ...], tuple(decoded))
    try:
        for value in values:
            require_reference_token(value, f"M6 M5 precedent {column}")
    except (TypeError, ValueError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return values


def _upstream_retrieval_keys(
    upstream: M6SQLiteM4ModelDocumentsPlan,
) -> tuple[M6SQLiteM5PrecedentRetrievalKey, ...]:
    by_key: dict[tuple[str, str, str], tuple[str, str, int, int, str, int]] = {}
    for graph in upstream.call_graphs:
        key = (graph.hearing_id, graph.cycle_scope_id, graph.retrieval_receipt_id)
        binding = (
            graph.cycle_scope_sha256,
            graph.retrieval_commitment_sha256,
            graph.prior_acquisition_rounds,
            graph.prior_rework_rounds,
            graph.evidence_pack_id,
            graph.evidence_pack_version,
        )
        existing = by_key.setdefault(key, binding)
        if existing != binding:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.UPSTREAM_M4_MISMATCH)
    try:
        return tuple(
            M6SQLiteM5PrecedentRetrievalKey(
                hearing_id=hearing_id,
                cycle_scope_id=cycle_scope_id,
                retrieval_receipt_id=receipt_id,
            )
            for hearing_id, cycle_scope_id, receipt_id in sorted(by_key)
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.UPSTREAM_M4_MISMATCH)


def _hearing_slot(
    connection: M6LiveReader,
    row: sqlite3.Row,
) -> M6SQLiteM5PrecedentHearingSlot:
    defects = _defects(row, "initial_defect_codes_json")
    try:
        return M6SQLiteM5PrecedentHearingSlot(
            run_id=_token(row, "run_id"),
            case_id=_token(row, "case_id"),
            rowid=_integer(row, "document_rowid", minimum=1),
            hearing_id=_sha256(row, "hearing_id"),
            screening_id=_sha256(row, "screening_id"),
            entry_status=_enum(row, "entry_status", HearingSessionEntryStatus),
            trigger_review_id=_optional_sha256(row, "trigger_review_id"),
            initial_defect_codes=defects,
            initial_defect_codes_sha256=normalized_json_sha256(row, "initial_defect_codes_json"),
            initial_pack_id=_sha256(row, "initial_pack_id"),
            initial_pack_version=_integer(row, "initial_pack_version", minimum=1),
            max_acquisition_rounds=_integer(row, "max_acquisition_rounds", maximum=2),
            max_rework_rounds=_integer(row, "max_rework_rounds", maximum=2),
            max_total_images=_integer(row, "max_total_images", minimum=1, maximum=320),
            max_total_output_tokens=_integer(
                row,
                "max_total_output_tokens",
                minimum=1,
                maximum=1_000_000,
            ),
            max_judge_cycles=_integer(row, "max_judge_cycles", minimum=1, maximum=5),
            hearing_prompt_bundle_sha256=_sha256(row, "hearing_prompt_bundle_sha256"),
            prosecutor_model_manifest_id=_sha256(row, "prosecutor_model_manifest_id"),
            defender_model_manifest_id=_sha256(row, "defender_model_manifest_id"),
            judge_model_manifest_id=_sha256(row, "judge_model_manifest_id"),
            manifest_id=_sha256(row, "manifest_id"),
            created_audit_sequence=_integer(row, "created_audit_sequence"),
            document_sha256=_sha256(row, "document_sha256"),
            document_bytes=document_bytes(
                connection,
                row,
                M6SQLiteM5PrecedentRowDocumentRoute.HEARING,
            ),
        )
    except _M6SQLiteM5PrecedentMetadataFailure:
        raise
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _cycle_slot(
    connection: M6LiveReader,
    row: sqlite3.Row,
) -> M6SQLiteM5PrecedentCycleSlot:
    initial = _defects(row, "initial_defect_codes_json")
    rework = _defects(row, "rework_defect_codes_json")
    try:
        return M6SQLiteM5PrecedentCycleSlot(
            run_id=_token(row, "run_id"),
            case_id=_token(row, "case_id"),
            rowid=_integer(row, "document_rowid", minimum=1),
            cycle_id=_sha256(row, "cycle_id"),
            cycle_sha256=_sha256(row, "cycle_sha256"),
            hearing_id=_sha256(row, "hearing_id"),
            cycle_index=_integer(row, "cycle_index", minimum=1, maximum=5),
            prior_acquisition_rounds=_integer(row, "prior_acquisition_rounds", maximum=2),
            prior_rework_rounds=_integer(row, "prior_rework_rounds", maximum=2),
            cycle_pack_id=_sha256(row, "cycle_pack_id"),
            cycle_pack_version=_integer(row, "cycle_pack_version", minimum=1),
            initial_trigger_review_id=_optional_sha256(row, "initial_trigger_review_id"),
            initial_defect_codes=initial,
            initial_defect_codes_sha256=normalized_json_sha256(row, "initial_defect_codes_json"),
            rework_review_id=_optional_sha256(row, "rework_review_id"),
            rework_defect_codes=rework,
            rework_defect_codes_sha256=normalized_json_sha256(row, "rework_defect_codes_json"),
            manifest_id=_sha256(row, "manifest_id"),
            created_audit_sequence=_integer(row, "created_audit_sequence"),
            document_sha256=_sha256(row, "cycle_sha256"),
            document_bytes=document_bytes(
                connection,
                row,
                M6SQLiteM5PrecedentRowDocumentRoute.CYCLE,
            ),
        )
    except _M6SQLiteM5PrecedentMetadataFailure:
        raise
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _retrieval_slot(
    connection: M6LiveReader,
    row: sqlite3.Row,
) -> M6SQLiteM5PrecedentRetrievalSlot:
    initial = _defects(row, "initial_defect_codes_json")
    rework = _defects(row, "rework_defect_codes_json")
    try:
        return M6SQLiteM5PrecedentRetrievalSlot(
            run_id=_token(row, "run_id"),
            case_id=_token(row, "case_id"),
            rowid=_integer(row, "document_rowid", minimum=1),
            retrieval_receipt_id=_sha256(row, "retrieval_receipt_id"),
            hearing_id=_sha256(row, "hearing_id"),
            cycle_scope_id=_sha256(row, "cycle_scope_id"),
            cycle_scope_sha256=_sha256(row, "cycle_scope_sha256"),
            prior_acquisition_rounds=_integer(row, "prior_acquisition_rounds", maximum=2),
            prior_rework_rounds=_integer(row, "prior_rework_rounds", maximum=2),
            current_pack_id=_sha256(row, "current_pack_id"),
            current_pack_version=_integer(row, "current_pack_version", minimum=1),
            evidence_class=_enum(row, "evidence_class", EvidenceClass),
            violation_type=_enum(row, "violation_type", ViolationType),
            rule_version=_token(row, "rule_version"),
            top_k=_integer(row, "top_k", maximum=64),
            initial_trigger_review_id=_optional_sha256(row, "initial_trigger_review_id"),
            initial_defect_codes=initial,
            initial_defect_codes_sha256=normalized_json_sha256(row, "initial_defect_codes_json"),
            rework_review_id=_optional_sha256(row, "rework_review_id"),
            rework_defect_codes=rework,
            rework_defect_codes_sha256=normalized_json_sha256(row, "rework_defect_codes_json"),
            candidate_precedent_ids=_artifact_ids(row, "candidate_precedent_refs_json"),
            candidate_refs_sha256=normalized_json_sha256(row, "candidate_precedent_refs_json"),
            candidate_snapshot_sha256=_sha256(row, "candidate_snapshot_sha256"),
            visible_precedent_ids=_artifact_ids(row, "visible_precedent_refs_json"),
            visible_refs_sha256=normalized_json_sha256(row, "visible_precedent_refs_json"),
            visible_snapshot_sha256=_sha256(row, "visible_snapshot_sha256"),
            scored_precedents_sha256=normalized_json_sha256(row, "scored_precedents_json"),
            retrieval_status=_enum(
                row,
                "retrieval_status",
                HearingPrecedentRetrievalStatus,
            ),
            degraded_reason=_optional_enum(
                row,
                "degraded_reason",
                HearingPrecedentDegradedReason,
            ),
            precedent_retrieval_degraded=_boolean(row, "precedent_retrieval_degraded"),
            retriever_version=_token(row, "retriever_version"),
            retriever_manifest_id=_sha256(row, "retriever_manifest_id"),
            query_sha256=_sha256(row, "query_sha256"),
            embedding_model_manifest_id=_optional_sha256(row, "embedding_model_manifest_id"),
            manifest_id=_sha256(row, "manifest_id"),
            document_sha256=_sha256(row, "document_sha256"),
            document_bytes=document_bytes(
                connection,
                row,
                M6SQLiteM5PrecedentRowDocumentRoute.RETRIEVAL,
            ),
        )
    except _M6SQLiteM5PrecedentMetadataFailure:
        raise
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _exposure_slot(
    connection: M6LiveReader,
    row: sqlite3.Row,
) -> M6SQLiteM5PrecedentExposureSlot:
    try:
        return M6SQLiteM5PrecedentExposureSlot(
            run_id=_token(row, "run_id"),
            case_id=_token(row, "case_id"),
            rowid=_integer(row, "document_rowid", minimum=1),
            exposure_id=_sha256(row, "exposure_id"),
            exposure_sha256=_sha256(row, "exposure_sha256"),
            hearing_id=_sha256(row, "hearing_id"),
            cycle_index=_integer(row, "cycle_index", minimum=1, maximum=5),
            cycle_scope_id=_sha256(row, "cycle_scope_id"),
            cycle_scope_sha256=_sha256(row, "cycle_scope_sha256"),
            retrieval_receipt_id=_sha256(row, "retrieval_receipt_id"),
            m4_query_id=_sha256(row, "m4_query_id"),
            m5_query_id=_sha256(row, "m5_query_id"),
            m5_result_id=_sha256(row, "m5_result_id"),
            candidate_count=_integer(row, "candidate_count", maximum=10_000),
            exposed_count=_integer(row, "exposed_count", maximum=64),
            policy_id=_sha256(row, "policy_id"),
            bridge_manifest_id=_sha256(row, "bridge_manifest_id"),
            manifest_id=_sha256(row, "manifest_id"),
            document_sha256=_sha256(row, "document_sha256"),
            document_bytes=document_bytes(
                connection,
                row,
                M6SQLiteM5PrecedentRowDocumentRoute.PRECEDENT_EXPOSURE,
            ),
        )
    except _M6SQLiteM5PrecedentMetadataFailure:
        raise
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _revision_slot(
    connection: M6LiveReader,
    row: sqlite3.Row,
) -> M6SQLiteM5PrecedentRevisionSlot:
    visual = _string_ids(row, "visual_embedding_ids_json")
    try:
        return M6SQLiteM5PrecedentRevisionSlot(
            run_id=_token(row, "run_id"),
            rowid=_integer(row, "document_rowid", minimum=1),
            precedent_id=_token(row, "precedent_id"),
            revision=_integer(row, "revision", minimum=1),
            authority_id=_sha256(row, "authority_id"),
            status=_enum(row, "status", PrecedentStatus),
            source=_enum(row, "source", PrecedentSource),
            evidence_class=_enum(row, "evidence_class", EvidenceClass),
            violation_type=_enum(row, "violation_type", ViolationType),
            decision_direction=_enum(row, "decision_direction", VerdictDecision),
            rule_version=_token(row, "rule_version"),
            source_case_id=_optional_token(row, "source_case_id"),
            citation_count=_integer(row, "citation_count"),
            text_embedding_id=_optional_sha256(row, "text_embedding_id"),
            visual_embedding_ids=visual,
            visual_embedding_ids_sha256=normalized_json_sha256(row, "visual_embedding_ids_json"),
            created_at=_text(row, "created_at"),
            activation_not_before=(
                None
                if _value(row, "activation_not_before") is None
                else _text(row, "activation_not_before")
            ),
            activated_at=(
                None if _value(row, "activated_at") is None else _text(row, "activated_at")
            ),
            manifest_id=_sha256(row, "manifest_id"),
            document_sha256=_sha256(row, "document_sha256"),
            document_bytes=document_bytes(
                connection,
                row,
                M6SQLiteM5PrecedentRowDocumentRoute.PRECEDENT_AUTHORITY,
            ),
        )
    except _M6SQLiteM5PrecedentMetadataFailure:
        raise
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _embedding_slot(
    connection: M6LiveReader,
    row: sqlite3.Row,
) -> M6SQLiteM5PrecedentDurableEmbeddingSlot:
    try:
        return M6SQLiteM5PrecedentDurableEmbeddingSlot(
            run_id=_token(row, "run_id"),
            rowid=_integer(row, "document_rowid", minimum=1),
            embedding_id=_sha256(row, "embedding_id"),
            request_id=_sha256(row, "request_id"),
            channel=_enum(row, "channel", M5EmbeddingChannel),
            input_ref=_token(row, "input_ref"),
            input_sha256=_sha256(row, "input_sha256"),
            model_manifest_id=_sha256(row, "model_manifest_id"),
            dimensions=_integer(row, "dimensions", minimum=1, maximum=4_096),
            algorithm=_text(row, "algorithm"),
            manifest_id=_sha256(row, "manifest_id"),
            document_sha256=_sha256(row, "document_sha256"),
            document_bytes=document_bytes(
                connection,
                row,
                M6SQLiteM5PrecedentRowDocumentRoute.EMBEDDING,
            ),
        )
    except _M6SQLiteM5PrecedentMetadataFailure:
        raise
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _selected_m4_slots(
    connection: M6LiveReader,
    rows: M6SQLiteM5PrecedentCaseRows,
    upstream: M6SQLiteM4ModelDocumentsPlan,
    keys: tuple[M6SQLiteM5PrecedentRetrievalKey, ...],
) -> tuple[
    tuple[M6SQLiteM5PrecedentHearingSlot, ...],
    tuple[M6SQLiteM5PrecedentCycleSlot, ...],
    tuple[M6SQLiteM5PrecedentRetrievalSlot, ...],
]:
    retrieval_by_key: dict[tuple[str, str, str], sqlite3.Row] = {}
    for row in rows.retrievals:
        key = (
            _sha256(row, "hearing_id"),
            _sha256(row, "cycle_scope_id"),
            _sha256(row, "retrieval_receipt_id"),
        )
        if key in retrieval_by_key:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
        retrieval_by_key[key] = row
    selected_rows: list[sqlite3.Row] = []
    for retrieval_key in keys:
        selected_row = retrieval_by_key.get(retrieval_key.sort_key)
        if selected_row is None:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.SCOPE_NOT_FOUND)
        selected_rows.append(selected_row)
    retrievals = tuple(
        sorted(
            (_retrieval_slot(connection, row) for row in selected_rows),
            key=lambda value: value.sort_key,
        )
    )

    hearing_by_id: dict[str, sqlite3.Row] = {}
    for row in rows.hearings:
        hearing_id = _sha256(row, "hearing_id")
        if hearing_id in hearing_by_id:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
        hearing_by_id[hearing_id] = row
    cycle_by_id: dict[str, sqlite3.Row] = {}
    for row in rows.cycles:
        cycle_id = _sha256(row, "cycle_id")
        if cycle_id in cycle_by_id:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
        cycle_by_id[cycle_id] = row
    hearing_ids = tuple(sorted({value.hearing_id for value in retrievals}))
    cycle_ids = tuple(sorted({value.cycle_scope_id for value in retrievals}))
    if any(value not in hearing_by_id for value in hearing_ids) or any(
        value not in cycle_by_id for value in cycle_ids
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.SCOPE_NOT_FOUND)
    hearings = tuple(
        sorted(
            (_hearing_slot(connection, hearing_by_id[value]) for value in hearing_ids),
            key=lambda value: value.sort_key,
        )
    )
    cycles = tuple(
        sorted(
            (_cycle_slot(connection, cycle_by_id[value]) for value in cycle_ids),
            key=lambda value: value.sort_key,
        )
    )
    _require_upstream_support(upstream, hearings, cycles, retrievals)
    return hearings, cycles, retrievals


def _require_upstream_support(
    upstream: M6SQLiteM4ModelDocumentsPlan,
    hearings: tuple[M6SQLiteM5PrecedentHearingSlot, ...],
    cycles: tuple[M6SQLiteM5PrecedentCycleSlot, ...],
    retrievals: tuple[M6SQLiteM5PrecedentRetrievalSlot, ...],
) -> None:
    by_route_and_id = {
        (value.route, value.artifact_id): value for value in upstream.support_document_slots
    }
    if len(by_route_and_id) != len(upstream.support_document_slots):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.UPSTREAM_M4_MISMATCH)
    expected = (
        *(
            (
                M6SQLiteM4SupportDocumentRoute.HEARING_SESSION,
                value.hearing_id,
                value.rowid,
                value.document_sha256,
                value.document_bytes,
            )
            for value in hearings
        ),
        *(
            (
                M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE,
                value.cycle_id,
                value.rowid,
                value.cycle_sha256,
                value.document_bytes,
            )
            for value in cycles
        ),
        *(
            (
                M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL,
                value.retrieval_receipt_id,
                value.rowid,
                value.document_sha256,
                value.document_bytes,
            )
            for value in retrievals
        ),
    )
    for route, artifact_id, rowid, commitment, size in expected:
        support = by_route_and_id.get((route, artifact_id))
        if (
            support is None
            or support.rowid != rowid
            or support.body_commitment_sha256 != commitment
            or support.document_bytes != size
        ):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.UPSTREAM_M4_MISMATCH)

    graph_by_key: dict[tuple[str, str, str], tuple[str, str, int, int, str, int]] = {}
    for graph in upstream.call_graphs:
        key = (graph.hearing_id, graph.cycle_scope_id, graph.retrieval_receipt_id)
        graph_by_key[key] = (
            graph.cycle_scope_sha256,
            graph.retrieval_commitment_sha256,
            graph.prior_acquisition_rounds,
            graph.prior_rework_rounds,
            graph.evidence_pack_id,
            graph.evidence_pack_version,
        )
    for value in retrievals:
        binding = graph_by_key.get(value.retrieval_key.sort_key)
        if binding != (
            value.cycle_scope_sha256,
            value.document_sha256,
            value.prior_acquisition_rounds,
            value.prior_rework_rounds,
            value.current_pack_id,
            value.current_pack_version,
        ):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.UPSTREAM_M4_MISMATCH)


def _query_failure_code(
    value: M6SQLiteM5PrecedentQueryFailureCode,
) -> M6SQLiteM5PrecedentPlanFailureCode:
    if value == M6SQLiteM5PrecedentQueryFailureCode.SCOPE_MISMATCH:
        return M6SQLiteM5PrecedentPlanFailureCode.SCOPE_MISMATCH
    if value == M6SQLiteM5PrecedentQueryFailureCode.BRIDGE_BINDING_MISMATCH:
        return M6SQLiteM5PrecedentPlanFailureCode.BRIDGE_PIN_MISMATCH
    if value == M6SQLiteM5PrecedentQueryFailureCode.PHYSICAL_PLAN_INVALID:
        return M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_PLAN_INVALID
    return M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH


def _derive_query_embedding(
    *,
    selected_case: Case,
    manifest: RunManifest,
    config: AppConfig,
    hearing: M6SQLiteM5PrecedentHearingSlot,
    cycle: M6SQLiteM5PrecedentCycleSlot,
    retrieval: M6SQLiteM5PrecedentRetrievalSlot,
    exposure: M6SQLiteM5PrecedentExposureSlot,
) -> M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot:
    try:
        reconstructed = reconstruct_m6_sqlite_m5_precedent_query(
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
    except M6SQLiteM5PrecedentQueryError as error:
        _fail(_query_failure_code(error.reason_code))
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
    if (
        reconstructed.hearing_session.initial_defect_codes != hearing.initial_defect_codes
        or reconstructed.cycle_scope.initial_defect_codes != cycle.initial_defect_codes
        or reconstructed.cycle_scope.rework_defect_codes != cycle.rework_defect_codes
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
    vector = reconstructed.query_embedding_authority.vector
    request = vector.request
    if request.channel != M5EmbeddingChannel.TEXT:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
    try:
        return M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot(
            run_id=retrieval.run_id,
            case_id=retrieval.case_id,
            hearing_id=retrieval.hearing_id,
            cycle_scope_id=retrieval.cycle_scope_id,
            retrieval_receipt_id=retrieval.retrieval_receipt_id,
            m4_query_id=exposure.m4_query_id,
            m5_query_id=exposure.m5_query_id,
            channel=request.channel,
            channel_index=0,
            request_id=request.request_id,
            input_ref=request.input_ref,
            input_sha256=request.input_sha256,
            model_manifest_id=request.model_manifest_id,
            dimensions=request.dimensions,
            algorithm=request.algorithm,
            physical_ref=reconstructed.query_embedding_ref,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_PLAN_INVALID)


def _bridge_artifacts(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    manifest: RunManifest,
    config: AppConfig,
    selected_case: Case,
    observations: tuple[M6UpgradeObservedArtifactIdentity, ...],
    hearings: tuple[M6SQLiteM5PrecedentHearingSlot, ...],
    cycles: tuple[M6SQLiteM5PrecedentCycleSlot, ...],
    retrievals: tuple[M6SQLiteM5PrecedentRetrievalSlot, ...],
) -> tuple[
    tuple[M6SQLiteM5PrecedentExposureSlot, ...],
    tuple[M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot, ...],
]:
    exposure_ids = tuple(
        value.artifact_id
        for value in observations
        if value.kind == M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE
    )
    exposure_rows = read_exposure_rows(
        connection,
        run_id=run_id,
        exposure_ids=exposure_ids,
    )
    exposures = tuple(
        sorted(
            (_exposure_slot(connection, row) for row in exposure_rows),
            key=lambda value: value.sort_key,
        )
    )
    if any(
        value.run_id != run_id
        or value.case_id != case_id
        or value.manifest_id != manifest.manifest_id
        for value in exposures
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.SCOPE_MISMATCH)
    by_receipt: dict[str, list[M6SQLiteM5PrecedentExposureSlot]] = {}
    for exposure in exposures:
        by_receipt.setdefault(exposure.retrieval_receipt_id, []).append(exposure)
    hearing_by_id = {value.hearing_id: value for value in hearings}
    cycle_by_id = {value.cycle_id: value for value in cycles}
    derived: list[M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot] = []
    selected_receipts = {value.retrieval_receipt_id for value in retrievals}
    if set(by_receipt) - selected_receipts:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)
    for retrieval in retrievals:
        matches = by_receipt.get(retrieval.retrieval_receipt_id, [])
        bridge_success = (
            retrieval.is_m5_bridge
            and retrieval.retrieval_status == HearingPrecedentRetrievalStatus.SUCCESS
        )
        if not bridge_success:
            if matches:
                _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)
            continue
        if len(matches) != 1:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)
        exposure = matches[0]
        if exposure.candidate_count != len(
            retrieval.candidate_precedent_ids
        ) or exposure.exposed_count != len(retrieval.visible_precedent_ids):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
        hearing = hearing_by_id.get(retrieval.hearing_id)
        cycle = cycle_by_id.get(retrieval.cycle_scope_id)
        if hearing is None or cycle is None:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)
        derived.append(
            _derive_query_embedding(
                selected_case=selected_case,
                manifest=manifest,
                config=config,
                hearing=hearing,
                cycle=cycle,
                retrieval=retrieval,
                exposure=exposure,
            )
        )
    return exposures, tuple(sorted(derived, key=lambda value: value.sort_key))


def _historical_support(
    connection: M6LiveReader,
    *,
    run_id: str,
    manifest: RunManifest,
    observations: tuple[M6UpgradeObservedArtifactIdentity, ...],
    bridge_success_rows: tuple[sqlite3.Row, ...],
    derived_query_embeddings: tuple[M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot, ...],
) -> tuple[
    tuple[M6SQLiteM5PrecedentRevisionSlot, ...],
    tuple[M6SQLiteM5PrecedentDurableEmbeddingSlot, ...],
]:
    candidate_ids = candidate_precedent_ids(bridge_success_rows)
    revision_rows = read_candidate_precedent_revision_rows(
        connection,
        run_id=run_id,
        precedent_ids=candidate_ids,
    )
    revisions = tuple(
        sorted(
            (_revision_slot(connection, row) for row in revision_rows),
            key=lambda value: value.sort_key,
        )
    )
    if any(
        value.run_id != run_id or value.manifest_id != manifest.manifest_id for value in revisions
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.SCOPE_MISMATCH)
    support_ids = set(precedent_revision_embedding_ids(revision_rows))
    derived_ids = {value.physical_ref.artifact_id for value in derived_query_embeddings}
    observed_embedding_ids = {
        value.artifact_id
        for value in observations
        if value.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
    }
    observed_durable_ids = observed_embedding_ids - derived_ids
    if not observed_durable_ids.issubset(support_ids):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)
    if derived_ids.intersection(support_ids):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)
    durable_ids = tuple(sorted(support_ids | observed_durable_ids))
    durable_rows = read_durable_embedding_rows(
        connection,
        run_id=run_id,
        embedding_ids=durable_ids,
    )
    durable = tuple(
        sorted(
            (_embedding_slot(connection, row) for row in durable_rows),
            key=lambda value: value.sort_key,
        )
    )
    expected_models = {
        M5EmbeddingChannel.TEXT: manifest.models["text_embedding"].model_manifest_id,
        M5EmbeddingChannel.VISUAL: manifest.models["visual_embedding"].model_manifest_id,
    }
    if any(
        value.run_id != run_id
        or value.manifest_id != manifest.manifest_id
        or value.model_manifest_id != expected_models[value.channel]
        for value in durable
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.SCOPE_MISMATCH)
    return revisions, durable


def _require_observation_exact_set(
    observations: tuple[M6UpgradeObservedArtifactIdentity, ...],
    exposures: tuple[M6SQLiteM5PrecedentExposureSlot, ...],
    derived: tuple[M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot, ...],
    durable: tuple[M6SQLiteM5PrecedentDurableEmbeddingSlot, ...],
) -> None:
    exposure_ids = {value.exposure_id for value in exposures}
    derived_ids = {value.physical_ref.artifact_id for value in derived}
    durable_ids = {value.embedding_id for value in durable}
    actual_exposure_ids: set[str] = set()
    actual_derived_ids: set[str] = set()
    actual_durable_ids: set[str] = set()
    for value in observations:
        if value.kind == M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE:
            if value.usage != M6UpgradeArtifactUsage.PRODUCED:
                _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)
            actual_exposure_ids.add(value.artifact_id)
        elif value.artifact_id in derived_ids:
            if value.usage != M6UpgradeArtifactUsage.PRODUCED:
                _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)
            actual_derived_ids.add(value.artifact_id)
        else:
            if (
                value.usage != M6UpgradeArtifactUsage.CONSUMED
                or value.artifact_id not in durable_ids
            ):
                _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)
            actual_durable_ids.add(value.artifact_id)
    if (
        actual_exposure_ids != exposure_ids
        or actual_derived_ids != derived_ids
        or not actual_durable_ids.issubset(durable_ids)
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)


def _preflight_totals(
    *,
    hearings: tuple[M6SQLiteM5PrecedentHearingSlot, ...],
    cycles: tuple[M6SQLiteM5PrecedentCycleSlot, ...],
    retrievals: tuple[M6SQLiteM5PrecedentRetrievalSlot, ...],
    exposures: tuple[M6SQLiteM5PrecedentExposureSlot, ...],
    derived: tuple[M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot, ...],
    durable: tuple[M6SQLiteM5PrecedentDurableEmbeddingSlot, ...],
    revisions: tuple[M6SQLiteM5PrecedentRevisionSlot, ...],
    observations: tuple[M6UpgradeObservedArtifactIdentity, ...],
) -> None:
    document_total = (
        sum(value.document_bytes for value in hearings)
        + sum(value.document_bytes for value in cycles)
        + sum(value.document_bytes for value in retrievals)
        + sum(value.document_bytes for value in exposures)
        + sum(value.document_bytes for value in durable)
        + sum(value.document_bytes for value in revisions)
        + sum(
            {
                value.physical_ref.artifact_id: value.physical_ref.size_bytes for value in derived
            }.values()
        )
    )
    if document_total > MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_TOTAL_BYTES:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_BUDGET_EXCEEDED)
    observed_ids = {value.identity_key for value in observations}
    physical_refs = (
        *(value.physical_ref for value in exposures),
        *(value.physical_ref for value in derived),
        *(
            value.physical_ref
            for value in durable
            if (
                M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                M6UpgradePhysicalArtifactKind.EMBEDDING,
                value.embedding_id,
            )
            in observed_ids
        ),
    )
    unique_refs = {value.physical_key: value for value in physical_refs}
    if any(unique_refs[value.physical_key] != value for value in physical_refs):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_PLAN_INVALID)
    if sum(value.size_bytes for value in unique_refs.values()) > (
        MAX_M6_SQLITE_M5_PRECEDENT_PHYSICAL_TOTAL_BYTES
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_BUDGET_EXCEEDED)


def build_m6_sqlite_m5_precedent_documents_plan(
    *,
    connection: object,
    manifest: object,
    config: object,
    selected_case_authority: object,
    upstream_m4_model_plan: object,
    observed_precedent_artifacts: object,
) -> M6SQLiteM5PrecedentDocumentsPlan:
    """Build the exact M5 plan without reading any M4 or M5 JSON body."""

    controlled, run_manifest, app_config, authority, upstream, observations = _validated_arguments(
        connection,
        manifest,
        config,
        selected_case_authority,
        upstream_m4_model_plan,
        observed_precedent_artifacts,
    )
    run_id = authority.case.run_id
    case_id = authority.case.case_id
    keys = _upstream_retrieval_keys(upstream)
    case_rows = read_case_retrieval_rows(controlled, run_id=run_id, case_id=case_id)
    hearings, cycles, retrievals = _selected_m4_slots(
        controlled,
        case_rows,
        upstream,
        keys,
    )
    exposures, derived = _bridge_artifacts(
        controlled,
        run_id=run_id,
        case_id=case_id,
        manifest=run_manifest,
        config=app_config,
        selected_case=authority.case,
        observations=observations,
        hearings=hearings,
        cycles=cycles,
        retrievals=retrievals,
    )
    # Select bridge-success rows from the already typed inventory.  The explicit
    # mapping avoids treating unrelated Case rows as M5 candidate authority.
    bridge_receipts = {
        value.retrieval_receipt_id
        for value in retrievals
        if value.is_m5_bridge and value.retrieval_status == HearingPrecedentRetrievalStatus.SUCCESS
    }
    bridge_success_rows = tuple(
        row
        for row in case_rows.retrievals
        if _sha256(row, "retrieval_receipt_id") in bridge_receipts
    )
    revisions, durable = _historical_support(
        controlled,
        run_id=run_id,
        manifest=run_manifest,
        observations=observations,
        bridge_success_rows=bridge_success_rows,
        derived_query_embeddings=derived,
    )
    _require_observation_exact_set(observations, exposures, derived, durable)
    _preflight_totals(
        hearings=hearings,
        cycles=cycles,
        retrievals=retrievals,
        exposures=exposures,
        derived=derived,
        durable=durable,
        revisions=revisions,
        observations=observations,
    )
    try:
        plan = M6SQLiteM5PrecedentDocumentsPlan(
            run_id=run_id,
            case_id=case_id,
            manifest_id=run_manifest.manifest_id,
            upstream_m4_plan_identity_sha256=upstream.plan_identity_sha256,
            upstream_retrieval_keys=keys,
            observed_artifacts=observations,
            hearings=hearings,
            cycles=cycles,
            retrievals=retrievals,
            exposures=exposures,
            derived_query_embeddings=derived,
            durable_embeddings=durable,
            precedent_revisions=revisions,
        )
    except (TypeError, UnicodeError, ValueError, ValidationError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.PHYSICAL_PLAN_INVALID)
    _active(controlled)
    return plan


def _capture_plan(
    *,
    connection: object,
    manifest: object,
    config: object,
    selected_case_authority: object,
    upstream_m4_model_plan: object,
    observed_precedent_artifacts: object,
) -> _PlanAttempt:
    try:
        value = build_m6_sqlite_m5_precedent_documents_plan(
            connection=connection,
            manifest=manifest,
            config=config,
            selected_case_authority=selected_case_authority,
            upstream_m4_model_plan=upstream_m4_model_plan,
            observed_precedent_artifacts=observed_precedent_artifacts,
        )
    except _M6SQLiteM5PrecedentMetadataFailure as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED
    else:
        return _PlanAttempt(value=value, failure_code=None)
    return _PlanAttempt(value=None, failure_code=failure_code)


def plan_m6_sqlite_m5_precedent_documents(
    *,
    connection: M6LiveReader,
    manifest: RunManifest,
    config: AppConfig,
    selected_case_authority: M6SQLiteCaseAuthorityDocument,
    upstream_m4_model_plan: M6SQLiteM4ModelDocumentsPlan,
    observed_precedent_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...],
) -> M6SQLiteM5PrecedentDocumentsPlan:
    """Public payload-free facade for one same-snapshot M5 metadata plan."""

    outcome = _capture_plan(
        connection=connection,
        manifest=manifest,
        config=config,
        selected_case_authority=selected_case_authority,
        upstream_m4_model_plan=upstream_m4_model_plan,
        observed_precedent_artifacts=observed_precedent_artifacts,
    )
    del (
        connection,
        manifest,
        config,
        selected_case_authority,
        upstream_m4_model_plan,
        observed_precedent_artifacts,
    )
    if outcome.value is not None:
        return outcome.value
    reason_code = outcome.failure_code
    del outcome
    if reason_code is None:
        reason_code = M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED
    raise M6SQLiteM5PrecedentDocumentError(reason_code) from None


def _capture_resolve(
    *,
    connection: object,
    metadata_plan: object,
    selected_case: object,
    config: object,
    manifest: object,
    upstream_m4_model_plan: object,
) -> _ResolveAttempt:
    try:
        value = build_m6_sqlite_m5_precedent_authority_snapshot(
            connection=connection,
            metadata_plan=metadata_plan,
            selected_case=selected_case,
            config=config,
            manifest=manifest,
            upstream_m4_model_plan=upstream_m4_model_plan,
        )
    except _M6SQLiteM5PrecedentMetadataFailure as error:
        failure_code = error.reason_code
    except Exception:
        failure_code = M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED
    else:
        return _ResolveAttempt(value=value, failure_code=None)
    return _ResolveAttempt(value=None, failure_code=failure_code)


def resolve_m6_sqlite_m5_precedent_documents(
    *,
    connection: M6LiveReader,
    metadata_plan: M6SQLiteM5PrecedentDocumentsPlan,
    selected_case: Case,
    config: AppConfig,
    manifest: RunManifest,
    upstream_m4_model_plan: M6SQLiteM4ModelDocumentsPlan,
) -> M6SQLiteM5PrecedentAuthoritySnapshot:
    """Public payload-free boundary for late, exact planned-body recovery."""

    outcome = _capture_resolve(
        connection=connection,
        metadata_plan=metadata_plan,
        selected_case=selected_case,
        config=config,
        manifest=manifest,
        upstream_m4_model_plan=upstream_m4_model_plan,
    )
    del (
        connection,
        metadata_plan,
        selected_case,
        config,
        manifest,
        upstream_m4_model_plan,
    )
    if outcome.value is not None:
        return outcome.value
    reason_code = outcome.failure_code
    del outcome
    if reason_code is None:
        reason_code = M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED
    raise M6SQLiteM5PrecedentDocumentError(reason_code) from None


def assemble_m6_sqlite_historical_retrieval_snapshots(
    *,
    gate_history_snapshot: object,
    m5_precedent_snapshot: object,
    expected_upstream_m4_plan_identity_sha256: object,
) -> M6ValidatedHistoricalRetrievalSnapshots:
    """Bind full M4 history and validated M5 exposures to one retrieval snapshot."""

    if (
        type(gate_history_snapshot) is not M6ProceduralGateHistorySnapshot
        or type(m5_precedent_snapshot) is not M6SQLiteM5PrecedentAuthoritySnapshot
        or not _is_sha256(expected_upstream_m4_plan_identity_sha256)
    ):
        raise M6SQLiteM5PrecedentDocumentError(
            M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT
        ) from None
    gate = gate_history_snapshot
    snapshot = m5_precedent_snapshot
    upstream_identity = cast(str, expected_upstream_m4_plan_identity_sha256)
    expected_receipts = {
        item.receipt_id: canonical_json(item.model_dump(mode="json"))
        for item in snapshot.retrieval_receipts
    }
    gate_receipts = {
        item.artifact_id: item.canonical_document
        for item in gate.documents
        if item.kind == M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL
    }
    if (
        snapshot.upstream_m4_model_plan_identity_sha256 != upstream_identity
        or gate.run_id != snapshot.run_id
        or snapshot.case_id == ""
        or expected_receipts != gate_receipts
    ):
        raise M6SQLiteM5PrecedentDocumentError(
            M6SQLiteM5PrecedentPlanFailureCode.UPSTREAM_M4_MISMATCH
        ) from None
    m5_documents = tuple(
        sorted(
            (
                M6HistoricalAuthorityDocument(
                    kind=M5AuthorityKind.PRECEDENT_EXPOSURE,
                    artifact_id=item.exposure_id,
                    canonical_document=canonical_json(item.model_dump(mode="json")),
                )
                for item in snapshot.exposures
            ),
            key=lambda item: item.sort_key,
        )
    )
    identity = hashlib.sha256(
        canonical_json(
            [
                "m6-sqlite-historical-retrieval-snapshots",
                1,
                gate.source_identity_sha256,
                snapshot.source_identity_sha256,
                snapshot.precedent_authority_root_sha256,
                [
                    [item.kind.value, item.artifact_id, item.document_sha256]
                    for item in gate.documents
                ],
                [
                    [item.kind.value, item.artifact_id, item.document_sha256]
                    for item in m5_documents
                ],
            ]
        ).encode("utf-8")
    ).hexdigest()
    try:
        return M6ValidatedHistoricalRetrievalSnapshots(
            source_identity_sha256=identity,
            run_id=snapshot.run_id,
            manifest_id=snapshot.manifest_id,
            m4_documents=gate.documents,
            m5_documents=m5_documents,
        )
    except (TypeError, ValueError):
        raise M6SQLiteM5PrecedentDocumentError(
            M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH
        ) from None


__all__ = [
    "M6SQLiteM5PrecedentAuthoritySnapshot",
    "M6SQLiteM5PrecedentDocumentError",
    "assemble_m6_sqlite_historical_retrieval_snapshots",
    "build_m6_sqlite_m5_precedent_documents_plan",
    "plan_m6_sqlite_m5_precedent_documents",
    "resolve_m6_sqlite_m5_precedent_documents",
]
