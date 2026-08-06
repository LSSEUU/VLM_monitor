"""Assemble one M6 semantic projection from exact same-snapshot authorities.

This boundary proves only the SQLite-backed *source* perception, model-call,
historical retrieval, acquisition, and embedding closure.  The input-authority
and source-validation-report references carried by the replay closure are
intentionally not dereferenced here, so this module cannot issue a complete
replay receipt or claim that candidate application/policy logic was rerun.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application.m6_acquisition_projection import (
    resolve_m6_locked_acquisitions,
)
from labcourt.application.m6_embedding_authority import (
    assemble_m6_resolved_embeddings,
)
from labcourt.application.m6_hearing_model_call_authority import (
    assemble_m6_locked_hearing_model_calls,
)
from labcourt.application.m6_historical_retrieval_cut import (
    assemble_m6_historical_retrieval_cut,
    resolve_m6_historical_retrieval_cycles,
)
from labcourt.application.m6_model_call_authority import (
    assemble_m6_locked_screening_model_calls,
)
from labcourt.application.m6_model_reference_authority import (
    M6ModelReferenceAuthorityError,
    assemble_m6_case_model_reference_authority,
)
from labcourt.application.m6_perception_authority import (
    assemble_m6_resolved_perception,
)
from labcourt.application.m6_procedural_gate_authority import (
    M6ProceduralGateAuthorityError,
    assemble_m6_case_procedural_gate_authority,
)
from labcourt.application.m6_source_authority import M6ValidatedSourceAuthority
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6ReplayInputClosureAuthority,
)
from labcourt.domain.m6_embedding_authority import M6ResolvedEmbeddingAuthority
from labcourt.domain.m6_model_reference_authority import M6CaseModelReferenceAuthority
from labcourt.domain.m6_procedural_gate_authority import M6CaseProceduralGateAuthority
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_acquisition_authority import (
    M6ValidatedM4ReplayAuthoritySnapshot,
)
from labcourt.ports.m6_embeddings import M6EmbeddingAuthoritySnapshot
from labcourt.ports.m6_historical_retrieval import (
    M6ValidatedHistoricalRetrievalSnapshots,
)
from labcourt.ports.m6_model_calls import (
    M6M3ModelCallAuthoritySnapshot,
    M6M4ModelCallAuthoritySnapshot,
)
from labcourt.ports.m6_perception import M6PerceptionAuthoritySnapshot
from labcourt.ports.m6_procedural_gate_authority import (
    M6ProceduralGateHistorySnapshot,
)


class M6SqliteProjectionAssemblyErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_CASE_REQUIRED = "SOURCE_CASE_REQUIRED"
    SOURCE_CASE_DOCUMENT_INVALID = "SOURCE_CASE_DOCUMENT_INVALID"
    SOURCE_SCOPE_MISMATCH = "SOURCE_SCOPE_MISMATCH"
    SNAPSHOT_IDENTITY_MISMATCH = "SNAPSHOT_IDENTITY_MISMATCH"
    SNAPSHOT_CHANGED = "SNAPSHOT_CHANGED"
    MODEL_CALL_CLOSURE_MISMATCH = "MODEL_CALL_CLOSURE_MISMATCH"
    MODEL_REFERENCE_AUTHORITY_INVALID = "MODEL_REFERENCE_AUTHORITY_INVALID"
    CURRENT_CLOSURE_AUTHORITY_MISSING = "CURRENT_CLOSURE_AUTHORITY_MISSING"
    PROCEDURAL_GATE_AUTHORITY_INVALID = "PROCEDURAL_GATE_AUTHORITY_INVALID"
    SOURCE_AUTHORITY_INVALID = "SOURCE_AUTHORITY_INVALID"
    HISTORICAL_CUT_MISMATCH = "HISTORICAL_CUT_MISMATCH"
    PROJECTION_CONTEXT_INVALID = "PROJECTION_CONTEXT_INVALID"
    CASE_REPLAY_SNAPSHOT_INVALID = "CASE_REPLAY_SNAPSHOT_INVALID"


class M6SqliteProjectionAssemblyError(LabCourtError):
    """One SQLite-backed semantic projection could not be proven exactly."""

    def __init__(self, code: M6SqliteProjectionAssemblyErrorCode) -> None:
        if not isinstance(code, M6SqliteProjectionAssemblyErrorCode):
            raise TypeError("code must be an M6SqliteProjectionAssemblyErrorCode")
        self.code = code
        super().__init__(f"M6 SQLite projection assembly failed: {code.value}")


def _fail(code: M6SqliteProjectionAssemblyErrorCode) -> NoReturn:
    raise M6SqliteProjectionAssemblyError(code)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True)
class M6SqliteProjectionAssembly:
    """Partial source projection authority proven from one SQLite snapshot.

    Deliberately absent are a ``verified`` flag, an execution receipt, and any
    dereferenced input-authority or source-validation-report document.  Alerts
    and appeals inside ``projection_context.case`` remain frozen source data;
    they are not evidence of candidate policy recomputation, and appeal truth
    remains evaluator-only.
    """

    source_identity_sha256: str
    closure: M6ReplayInputClosureAuthority
    model_calls: tuple[M6LockedModelCallInput, ...]
    embeddings: tuple[M6ResolvedEmbeddingAuthority, ...]
    projection_context: M6VerifiedProjectionContext
    case_replay_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if not _is_sha256(self.source_identity_sha256):
            raise ValueError("M6 SQLite projection source identity must be a SHA-256")
        if not isinstance(self.closure, M6ReplayInputClosureAuthority):
            raise TypeError("M6 SQLite projection closure must be typed")
        if not isinstance(self.model_calls, tuple) or any(
            not isinstance(item, M6LockedModelCallInput) for item in self.model_calls
        ):
            raise TypeError("M6 SQLite projection model_calls must be a typed tuple")
        if not isinstance(self.embeddings, tuple) or any(
            not isinstance(item, M6ResolvedEmbeddingAuthority) for item in self.embeddings
        ):
            raise TypeError("M6 SQLite projection embeddings must be a typed tuple")
        if not isinstance(self.projection_context, M6VerifiedProjectionContext):
            raise TypeError("M6 SQLite projection context must be typed")
        if not isinstance(self.case_replay_snapshot, M6CaseReplaySnapshot):
            raise TypeError("M6 SQLite projection snapshot must be typed")
        revision = self.closure.source_case_revision
        if revision is None or self.closure.source_case_id is None:
            raise ValueError("M6 SQLite projection assembly requires a source Case")
        try:
            derived = build_m6_case_replay_snapshot(
                context=self.projection_context,
                sample_id=self.closure.sample_id,
                source_case_revision=revision,
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 SQLite projection snapshot is not derivable") from None
        if (
            self.model_calls != self.closure.model_calls
            or derived != self.case_replay_snapshot
            or derived.source_run_id != self.closure.source_run_id
            or derived.source_case_id != self.closure.source_case_id
            or derived.source_case_revision != revision
            or derived.source_case_document_sha256 != self.closure.source_case_document_sha256
            or derived.manifest_id != self.closure.source_manifest_id
        ):
            raise ValueError("M6 SQLite projection assembly has a cross-grafted snapshot")


def _validated_arguments(
    closure: object,
    perception_snapshot: object,
    m3_snapshot: object,
    m4_snapshot: object,
    historical_snapshots: object,
    acquisition_snapshot: object,
    embedding_snapshot: object,
) -> tuple[
    M6ReplayInputClosureAuthority,
    M6PerceptionAuthoritySnapshot,
    M6M3ModelCallAuthoritySnapshot,
    M6M4ModelCallAuthoritySnapshot,
    M6ValidatedHistoricalRetrievalSnapshots,
    M6ValidatedM4ReplayAuthoritySnapshot,
    M6EmbeddingAuthoritySnapshot,
]:
    typed = (
        isinstance(closure, M6ReplayInputClosureAuthority),
        isinstance(perception_snapshot, M6PerceptionAuthoritySnapshot),
        isinstance(m3_snapshot, M6M3ModelCallAuthoritySnapshot),
        isinstance(m4_snapshot, M6M4ModelCallAuthoritySnapshot),
        isinstance(historical_snapshots, M6ValidatedHistoricalRetrievalSnapshots),
        isinstance(acquisition_snapshot, M6ValidatedM4ReplayAuthoritySnapshot),
        isinstance(embedding_snapshot, M6EmbeddingAuthoritySnapshot),
    )
    if not all(typed):
        _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
    assert isinstance(closure, M6ReplayInputClosureAuthority)
    assert isinstance(perception_snapshot, M6PerceptionAuthoritySnapshot)
    assert isinstance(m3_snapshot, M6M3ModelCallAuthoritySnapshot)
    assert isinstance(m4_snapshot, M6M4ModelCallAuthoritySnapshot)
    assert isinstance(historical_snapshots, M6ValidatedHistoricalRetrievalSnapshots)
    assert isinstance(acquisition_snapshot, M6ValidatedM4ReplayAuthoritySnapshot)
    assert isinstance(embedding_snapshot, M6EmbeddingAuthoritySnapshot)
    try:
        controlled_closure = M6ReplayInputClosureAuthority.model_validate(
            closure.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
    if controlled_closure != closure:
        _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
    return (
        controlled_closure,
        perception_snapshot,
        m3_snapshot,
        m4_snapshot,
        historical_snapshots,
        acquisition_snapshot,
        embedding_snapshot,
    )


def _require_common_identity(
    snapshots: tuple[
        M6PerceptionAuthoritySnapshot,
        M6M3ModelCallAuthoritySnapshot,
        M6M4ModelCallAuthoritySnapshot,
        M6ValidatedHistoricalRetrievalSnapshots,
        M6ValidatedM4ReplayAuthoritySnapshot,
        M6EmbeddingAuthoritySnapshot,
    ],
) -> str:
    identities = tuple(item.source_identity_sha256 for item in snapshots)
    if any(not _is_sha256(item) for item in identities) or len(set(identities)) != 1:
        _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
    return identities[0]


def _source_case(
    closure: M6ReplayInputClosureAuthority,
    snapshot: M6PerceptionAuthoritySnapshot,
) -> Case:
    if (
        closure.source_case_id is None
        or closure.source_case_revision is None
        or closure.source_case_document_sha256 is None
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_REQUIRED)
    if (
        snapshot.source_case_id is None
        or snapshot.source_case_revision is None
        or snapshot.source_case_canonical_document is None
        or snapshot.source_case_document_sha256 is None
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_REQUIRED)
    document = snapshot.source_case_canonical_document
    try:
        case = Case.model_validate_json(document)
    except (TypeError, ValueError, ValidationError):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_DOCUMENT_INVALID)
    observed_sha256 = hashlib.sha256(document.encode("utf-8")).hexdigest()
    if (
        canonical_json(case.model_dump(mode="json")) != document
        or observed_sha256 != snapshot.source_case_document_sha256
        or observed_sha256 != closure.source_case_document_sha256
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_DOCUMENT_INVALID)
    if (
        snapshot.source_case_id != closure.source_case_id
        or snapshot.source_case_revision != closure.source_case_revision
        or case.run_id != closure.source_run_id
        or case.case_id != closure.source_case_id
        or case.manifest_id != closure.source_manifest_id
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_SCOPE_MISMATCH)
    return case


def _require_source_scope(
    closure: M6ReplayInputClosureAuthority,
    case: Case,
    perception: M6PerceptionAuthoritySnapshot,
    m3: M6M3ModelCallAuthoritySnapshot,
    m4: M6M4ModelCallAuthoritySnapshot,
    historical: M6ValidatedHistoricalRetrievalSnapshots,
    acquisition: M6ValidatedM4ReplayAuthoritySnapshot,
    embedding: M6EmbeddingAuthoritySnapshot,
) -> None:
    case_id = closure.source_case_id
    if case_id is None:
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_REQUIRED)
    if (
        perception.run_id != closure.source_run_id
        or perception.manifest_id != closure.source_manifest_id
        or perception.source_case_id != case_id
        or m3.run_id != closure.source_run_id
        or m3.case_id != case_id
        or m3.manifest_id != closure.source_manifest_id
        or m4.run_id != closure.source_run_id
        or m4.case_id != case_id
        or m4.manifest_id != closure.source_manifest_id
        or historical.run_id != closure.source_run_id
        or historical.manifest_id != closure.source_manifest_id
        or acquisition.run_id != closure.source_run_id
        or embedding.run_id != closure.source_run_id
        or embedding.manifest_id != closure.source_manifest_id
        or case.run_id != closure.source_run_id
        or case.case_id != case_id
        or case.manifest_id != closure.source_manifest_id
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_SCOPE_MISMATCH)


def _require_model_reference_call_binding(
    *,
    authority: M6CaseModelReferenceAuthority,
    case: Case,
    model_calls: tuple[M6LockedModelCallInput, ...],
    source_identity_sha256: str,
) -> None:
    """Close semantic reference scopes over the independently validated calls."""

    if authority.source_identity_sha256 != source_identity_sha256:
        _fail(M6SqliteProjectionAssemblyErrorCode.MODEL_REFERENCE_AUTHORITY_INVALID)
    calls_by_request_id = {item.request_ref.artifact_id: item for item in model_calls}
    if len(calls_by_request_id) != len(model_calls):
        _fail(M6SqliteProjectionAssemblyErrorCode.MODEL_REFERENCE_AUTHORITY_INVALID)
    calls_by_response_id = {
        item.response_ref.artifact_id: item for item in model_calls if item.response_ref is not None
    }
    if len(calls_by_response_id) != sum(item.response_ref is not None for item in model_calls):
        _fail(M6SqliteProjectionAssemblyErrorCode.MODEL_REFERENCE_AUTHORITY_INVALID)

    screenings_by_id = {item.screening_id: item for item in case.screening_results}
    screening_bindings_by_id = {item.screening_id: item for item in authority.screening_bindings}
    for binding in authority.screening_bindings:
        screening = screenings_by_id.get(binding.screening_id)
        final_call = calls_by_request_id.get(binding.final_request_id)
        scope_call = calls_by_request_id.get(binding.scope.request_id)
        if (
            screening is None
            or final_call is None
            or scope_call is None
            or final_call.layer != M6LockedModelCallLayer.SCREENING
            or scope_call.layer != M6LockedModelCallLayer.SCREENING
            or final_call.role != M6LockedModelRole.SCREENING
            or scope_call.role != M6LockedModelRole.SCREENING
            or final_call.result_kind != M6LockedModelCallResultKind.RESPONSE
            or final_call.parsed_output_ref is None
            or final_call.parsed_output_ref.artifact_id != binding.parsed_output_id
            or final_call.response_ref is None
            or final_call.response_ref.artifact_id != screening.parsed_output.response_id
            or (
                binding.final_request_id == binding.scope.request_id
                and (final_call.attempt_index != 0 or scope_call.attempt_index != 0)
            )
            or (
                binding.final_request_id != binding.scope.request_id
                and (final_call.attempt_index != 1 or scope_call.attempt_index != 0)
            )
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.MODEL_REFERENCE_AUTHORITY_INVALID)

    verdicts_by_id = {item.verdict_id: item for item in case.verdicts}
    for fast_binding in authority.fast_verdict_bindings:
        verdict = verdicts_by_id.get(fast_binding.verdict_id)
        screening_binding = screening_bindings_by_id.get(fast_binding.screening_id)
        response_calls = tuple(
            calls_by_response_id.get(response_id) for response_id in fast_binding.response_ids
        )
        if (
            verdict is None
            or screening_binding is None
            or any(item is None for item in response_calls)
            or {item.request_ref.artifact_id for item in response_calls if item is not None}
            != {
                screening_binding.scope.request_id,
                screening_binding.final_request_id,
            }
            or {item.attempt_index for item in response_calls if item is not None}
            != (
                {0}
                if screening_binding.scope.request_id == screening_binding.final_request_id
                else {0, 1}
            )
            or any(
                item is None
                or item.layer != M6LockedModelCallLayer.SCREENING
                or item.role != M6LockedModelRole.SCREENING
                or item.result_kind != M6LockedModelCallResultKind.RESPONSE
                for item in response_calls
            )
        ):
            _fail(M6SqliteProjectionAssemblyErrorCode.MODEL_REFERENCE_AUTHORITY_INVALID)

    locked_role_by_model_role = {
        "PROSECUTOR": M6LockedModelRole.PROSECUTOR,
        "DEFENDER": M6LockedModelRole.DEFENDER,
        "JUDGE": M6LockedModelRole.JUDGE,
    }
    for verdict_binding in authority.verdict_bindings:
        for role_binding in verdict_binding.role_bindings:
            final_call = calls_by_request_id.get(role_binding.final_request_id)
            scope_call = calls_by_request_id.get(role_binding.scope.request_id)
            expected_role = locked_role_by_model_role[role_binding.role.value]
            if (
                final_call is None
                or scope_call is None
                or final_call.layer != M6LockedModelCallLayer.HEARING
                or scope_call.layer != M6LockedModelCallLayer.HEARING
                or final_call.role != expected_role
                or scope_call.role != expected_role
                or final_call.result_kind != M6LockedModelCallResultKind.RESPONSE
                or final_call.parsed_output_ref is None
                or final_call.parsed_output_ref.artifact_id != role_binding.output_id
                or final_call.response_ref is None
                or final_call.response_ref.artifact_id != role_binding.response_id
                or (
                    role_binding.final_request_id == role_binding.scope.request_id
                    and (final_call.attempt_index != 0 or scope_call.attempt_index != 0)
                )
                or (
                    role_binding.final_request_id != role_binding.scope.request_id
                    and (final_call.attempt_index != 1 or scope_call.attempt_index != 0)
                )
            ):
                _fail(M6SqliteProjectionAssemblyErrorCode.MODEL_REFERENCE_AUTHORITY_INVALID)


def _require_source_authority_binding(
    *,
    closure: M6ReplayInputClosureAuthority,
    case: Case,
    source_identity_sha256: str,
    source: M6ValidatedSourceAuthority,
    gate_history: M6ProceduralGateHistorySnapshot,
    config: AppConfig,
) -> None:
    authority = source.input_authority
    if (
        source.source_identity_sha256 != source_identity_sha256
        or gate_history.source_identity_sha256 != source_identity_sha256
        or source.source_case != case
        or source.source_manifest.manifest_id != case.manifest_id
        or source.source_manifest.config_sha256 != config.config_sha256
        or authority.sample_id != closure.sample_id
        or authority.source_run_id != closure.source_run_id
        or authority.source_case_id != closure.source_case_id
        or authority.source_case_revision != closure.source_case_revision
        or authority.source_case_document_sha256 != closure.source_case_document_sha256
        or authority.source_manifest_id != closure.source_manifest_id
        or authority.source_manifest_document_sha256 != closure.source_manifest_document_sha256
        or authority.input_authority_id != closure.input_authority_id
        or authority.input_authority_document_sha256 != closure.input_authority_document_sha256
        or authority.source_validation_report_id != closure.source_validation_report_id
        or authority.source_validation_report_document_sha256
        != closure.source_validation_report_document_sha256
        or gate_history.run_id != closure.source_run_id
        or gate_history.source_m4_authority_root_sha256 != authority.source_m4_authority_root_sha256
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_AUTHORITY_INVALID)


def assemble_m6_sqlite_projection_authority(
    *,
    closure: M6ReplayInputClosureAuthority,
    perception_snapshot: M6PerceptionAuthoritySnapshot,
    m3_snapshot: M6M3ModelCallAuthoritySnapshot,
    m4_snapshot: M6M4ModelCallAuthoritySnapshot,
    historical_snapshots: M6ValidatedHistoricalRetrievalSnapshots,
    acquisition_snapshot: M6ValidatedM4ReplayAuthoritySnapshot,
    embedding_snapshot: M6EmbeddingAuthoritySnapshot,
    source_authority: M6ValidatedSourceAuthority | None = None,
    gate_history_snapshot: M6ProceduralGateHistorySnapshot | None = None,
    config: AppConfig | None = None,
) -> M6SqliteProjectionAssembly:
    """Build the exact source projection provable from six SQLite readers.

    Despite carrying an ``M6CaseReplaySnapshot`` projection artifact, this
    result is not a candidate replay completion proof.
    """

    (
        controlled,
        perception_authority,
        m3_authority,
        m4_authority,
        historical_authority,
        acquisition_authority,
        embedding_authority,
    ) = _validated_arguments(
        closure,
        perception_snapshot,
        m3_snapshot,
        m4_snapshot,
        historical_snapshots,
        acquisition_snapshot,
        embedding_snapshot,
    )
    source_identity = _require_common_identity(
        (
            perception_authority,
            m3_authority,
            m4_authority,
            historical_authority,
            acquisition_authority,
            embedding_authority,
        )
    )
    supplied_gate_authorities = (
        source_authority is not None,
        gate_history_snapshot is not None,
        config is not None,
    )
    if any(supplied_gate_authorities) and not all(supplied_gate_authorities):
        _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
    if all(supplied_gate_authorities) and (
        not isinstance(source_authority, M6ValidatedSourceAuthority)
        or not isinstance(config, AppConfig)
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT)
    if gate_history_snapshot is not None and (
        not isinstance(gate_history_snapshot, M6ProceduralGateHistorySnapshot)
        or gate_history_snapshot.source_identity_sha256 != source_identity
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
    case = _source_case(controlled, perception_authority)
    _require_source_scope(
        controlled,
        case,
        perception_authority,
        m3_authority,
        m4_authority,
        historical_authority,
        acquisition_authority,
        embedding_authority,
    )

    perception = assemble_m6_resolved_perception(
        closure=controlled,
        snapshot=perception_authority,
    )
    screening_calls = assemble_m6_locked_screening_model_calls(
        source_case=case,
        snapshot=m3_authority,
    )
    hearing_calls = assemble_m6_locked_hearing_model_calls(
        source_case=case,
        snapshot=m4_authority,
    )
    model_calls = tuple(sorted((*screening_calls, *hearing_calls), key=lambda item: item.sort_key))
    if model_calls != controlled.model_calls:
        _fail(M6SqliteProjectionAssemblyErrorCode.MODEL_CALL_CLOSURE_MISMATCH)
    try:
        model_responses = resolve_m6_locked_model_responses(model_calls)
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SqliteProjectionAssemblyErrorCode.MODEL_CALL_CLOSURE_MISMATCH)
    try:
        model_reference_snapshot = acquisition_authority
        if gate_history_snapshot is not None:
            model_reference_snapshot = M6ValidatedM4ReplayAuthoritySnapshot(
                source_identity_sha256=gate_history_snapshot.source_identity_sha256,
                run_id=gate_history_snapshot.run_id,
                documents=gate_history_snapshot.documents,
            )
        model_reference_authority = assemble_m6_case_model_reference_authority(
            source_case=case,
            m3_snapshot=m3_authority,
            m4_snapshot=model_reference_snapshot,
        )
    except M6ModelReferenceAuthorityError:
        _fail(M6SqliteProjectionAssemblyErrorCode.MODEL_REFERENCE_AUTHORITY_INVALID)
    _require_model_reference_call_binding(
        authority=model_reference_authority,
        case=case,
        model_calls=model_calls,
        source_identity_sha256=source_identity,
    )

    expected_cut = assemble_m6_historical_retrieval_cut(
        source_case=case,
        snapshots=historical_authority,
    )
    if expected_cut != controlled.historical_cut:
        _fail(M6SqliteProjectionAssemblyErrorCode.HISTORICAL_CUT_MISMATCH)
    retrieval_cycles = resolve_m6_historical_retrieval_cycles(
        source_case=case,
        snapshots=historical_authority,
        historical_cut=controlled.historical_cut,
    )
    acquisitions = resolve_m6_locked_acquisitions(
        source_case=case,
        snapshot=acquisition_authority,
        locked_tool_results=controlled.tool_results,
    )
    embeddings = assemble_m6_resolved_embeddings(
        closure=controlled,
        snapshot=embedding_authority,
    )

    if source_authority is None or gate_history_snapshot is None or config is None:
        # The persisted pack carries only its creation closure.  A reviewed Case
        # therefore remains blocked unless its independently sealed source and
        # full M4 Gate history are supplied together.
        if case.procedural_reviews:
            _fail(M6SqliteProjectionAssemblyErrorCode.CURRENT_CLOSURE_AUTHORITY_MISSING)
        procedural_gate_authority = M6CaseProceduralGateAuthority(
            source_identity_sha256=source_identity,
            run_id=case.run_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
        )
    else:
        _require_source_authority_binding(
            closure=controlled,
            case=case,
            source_identity_sha256=source_identity,
            source=source_authority,
            gate_history=gate_history_snapshot,
            config=config,
        )
        try:
            procedural_gate_authority = assemble_m6_case_procedural_gate_authority(
                source=source_authority,
                snapshot=gate_history_snapshot,
                config=config,
            )
        except M6ProceduralGateAuthorityError:
            _fail(M6SqliteProjectionAssemblyErrorCode.PROCEDURAL_GATE_AUTHORITY_INVALID)

    try:
        context = M6VerifiedProjectionContext(
            case=case,
            perception=perception,
            historical_source_run_id=controlled.source_run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=controlled.source_manifest_id,
            model_reference_authority=model_reference_authority,
            procedural_gate_authority=procedural_gate_authority,
            model_responses=model_responses,
            retrieval_cycles=retrieval_cycles,
            acquisitions=acquisitions,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SqliteProjectionAssemblyErrorCode.PROJECTION_CONTEXT_INVALID)

    assert controlled.source_case_revision is not None
    try:
        replay_snapshot = build_m6_case_replay_snapshot(
            context=context,
            sample_id=controlled.sample_id,
            source_case_revision=controlled.source_case_revision,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SqliteProjectionAssemblyErrorCode.CASE_REPLAY_SNAPSHOT_INVALID)
    if (
        replay_snapshot.source_run_id != controlled.source_run_id
        or replay_snapshot.source_case_id != controlled.source_case_id
        or replay_snapshot.source_case_revision != controlled.source_case_revision
        or replay_snapshot.source_case_document_sha256 != controlled.source_case_document_sha256
        or replay_snapshot.manifest_id != controlled.source_manifest_id
        or context.case != case
    ):
        _fail(M6SqliteProjectionAssemblyErrorCode.SOURCE_SCOPE_MISMATCH)

    try:
        return M6SqliteProjectionAssembly(
            source_identity_sha256=source_identity,
            closure=controlled,
            model_calls=model_calls,
            embeddings=embeddings,
            projection_context=context,
            case_replay_snapshot=replay_snapshot,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6SqliteProjectionAssemblyErrorCode.CASE_REPLAY_SNAPSHOT_INVALID)


__all__ = [
    "M6SqliteProjectionAssembly",
    "M6SqliteProjectionAssemblyError",
    "M6SqliteProjectionAssemblyErrorCode",
    "assemble_m6_sqlite_projection_authority",
]
