"""Prove deterministic source projection without claiming candidate execution."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.frames import SHA256_PATTERN
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6RegressionExecutionEntry,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_replay_locked import (
    M6ReplayInputClosureAuthority,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_policy import (
    M6ReplayLockedAlertPolicyCausalCutAuthority,
)
from labcourt.contracts.references import require_reference_token
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
    M6ReplayLockedClosedPolicyM4PrePolicySource,
    M6ReplayLockedClosedPolicyPrePolicySource,
    M6ReplayLockedClosedPolicyPrePolicySourceProvider,
)
from labcourt.ports.m6_replay_locked_source import (
    M6ReplayLockedSourceProjection,
    M6ReplayLockedSourceProjectionProvider,
)

_SHA256 = re.compile(SHA256_PATTERN)
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedSourceDeterminismErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    MODE_NOT_REPLAY_LOCKED = "MODE_NOT_REPLAY_LOCKED"
    EXECUTION_ENTRY_CLOSURE_MISMATCH = "EXECUTION_ENTRY_CLOSURE_MISMATCH"
    COMMAND_CLOSURE_MANIFEST_MISMATCH = "COMMAND_CLOSURE_MANIFEST_MISMATCH"
    CANDIDATE_RUN_NOT_DISTINCT = "CANDIDATE_RUN_NOT_DISTINCT"
    SOURCE_READ_REJECTED = "SOURCE_READ_REJECTED"
    SOURCE_PROJECTION_MISMATCH = "SOURCE_PROJECTION_MISMATCH"
    POLICY_CAUSAL_CUT_MISMATCH = "POLICY_CAUSAL_CUT_MISMATCH"


class M6ReplayLockedSourceDeterminismError(LabCourtError):
    """Payload-free source determinism failure."""

    def __init__(self, code: M6ReplayLockedSourceDeterminismErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedSourceDeterminismErrorCode):
            raise TypeError("code must be an M6 locked source determinism error code")
        self.code = code
        super().__init__(f"M6 locked source determinism failed: {code.value}")


def _fail(code: M6ReplayLockedSourceDeterminismErrorCode) -> NoReturn:
    raise M6ReplayLockedSourceDeterminismError(code)


def _canonical_model(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedSourceDeterminismErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedSourceDeterminismErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_execution_identity(
    candidate_run_id: object,
    execution_component_manifest_id: object,
) -> tuple[str, str]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(candidate_run_id, "M6 locked candidate run_id")
    except (TypeError, ValueError):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.INVALID_ARGUMENT)
    if (
        not isinstance(execution_component_manifest_id, str)
        or _SHA256.fullmatch(execution_component_manifest_id) is None
    ):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.INVALID_ARGUMENT)
    return run_id, execution_component_manifest_id


def _load_projection(
    provider: M6ReplayLockedSourceProjectionProvider,
    closure: M6ReplayInputClosureAuthority,
) -> M6ReplayLockedSourceProjection:
    try:
        projection = provider.load_source_projection(closure)
    except Exception:
        raise M6ReplayLockedSourceDeterminismError(
            M6ReplayLockedSourceDeterminismErrorCode.SOURCE_READ_REJECTED
        ) from None
    if type(projection) is not M6ReplayLockedSourceProjection:
        _fail(M6ReplayLockedSourceDeterminismErrorCode.SOURCE_READ_REJECTED)
    return projection


def _load_closed_policy_projection(
    provider: M6ReplayLockedClosedPolicyPrePolicySourceProvider,
    closure: M6ReplayInputClosureAuthority,
    pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
) -> M6ReplayLockedClosedPolicyPrePolicySource:
    try:
        projection = provider.load_closed_policy_pre_policy_source(
            closure,
            pending.source_binding,
        )
    except Exception:
        raise M6ReplayLockedSourceDeterminismError(
            M6ReplayLockedSourceDeterminismErrorCode.SOURCE_READ_REJECTED
        ) from None
    if type(projection) not in {
        M6ReplayLockedClosedPolicyFastPrePolicySource,
        M6ReplayLockedClosedPolicyM4PrePolicySource,
    }:
        _fail(M6ReplayLockedSourceDeterminismErrorCode.SOURCE_READ_REJECTED)
    return projection


def _physical_identity(value: BaseModel) -> tuple[str, int]:
    payload = canonical_json(value.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _closed_snapshot(
    *,
    source: M6ReplayLockedClosedPolicyPrePolicySource,
    cut: M6ReplayLockedAlertPolicyCausalCutAuthority,
    closure: M6ReplayInputClosureAuthority,
) -> M6CaseReplaySnapshot:
    ready = source.projection_context
    try:
        context = M6VerifiedProjectionContext(
            case=cut.source_closed_case,
            perception=ready.perception,
            historical_source_run_id=ready.historical_source_run_id,
            historical_source_case_id=ready.historical_source_case_id,
            historical_source_manifest_id=ready.historical_source_manifest_id,
            model_reference_authority=ready.model_reference_authority,
            procedural_gate_authority=ready.procedural_gate_authority,
            model_responses=ready.model_responses,
            retrieval_cycles=ready.retrieval_cycles,
            acquisitions=ready.acquisitions,
        )
        return build_m6_case_replay_snapshot(
            context=context,
            sample_id=closure.sample_id,
            source_case_revision=cut.source_closed_case_revision,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.SOURCE_PROJECTION_MISMATCH)


def prove_m6_replay_locked_source_determinism(
    *,
    command: object,
    execution_entry: object,
    closure: object,
    candidate_run_id: object,
    execution_component_manifest_id: object,
    projection_provider: object,
) -> M6ReplayLockedSourceDeterminismAuthority:
    """Rebuild one immutable source projection twice and bind equal results."""

    controlled_command = _canonical_model(command, M6RegressionRunCommand)
    controlled_entry = _canonical_model(execution_entry, M6RegressionExecutionEntry)
    controlled_closure = _canonical_model(closure, M6ReplayInputClosureAuthority)
    run_id, component_id = _controlled_execution_identity(
        candidate_run_id,
        execution_component_manifest_id,
    )
    if not isinstance(projection_provider, M6ReplayLockedSourceProjectionProvider):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.INVALID_ARGUMENT)
    if controlled_command.mode != ReproducibilityMode.REPLAY_LOCKED:
        _fail(M6ReplayLockedSourceDeterminismErrorCode.MODE_NOT_REPLAY_LOCKED)
    if (
        controlled_command.baseline_manifest_id != controlled_closure.source_manifest_id
        or controlled_command.candidate_manifest_id != controlled_closure.source_manifest_id
    ):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.COMMAND_CLOSURE_MANIFEST_MISMATCH)
    if (
        controlled_entry.sample_id,
        controlled_entry.input_authority_id,
        controlled_entry.input_authority_document_sha256,
        controlled_entry.replay_input_closure_authority_id,
        controlled_entry.replay_input_closure_document_sha256,
    ) != (
        controlled_closure.sample_id,
        controlled_closure.input_authority_id,
        controlled_closure.input_authority_document_sha256,
        controlled_closure.replay_input_closure_authority_id,
        controlled_closure.replay_input_closure_document_sha256,
    ):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.EXECUTION_ENTRY_CLOSURE_MISMATCH)
    if run_id == controlled_closure.source_run_id:
        _fail(M6ReplayLockedSourceDeterminismErrorCode.CANDIDATE_RUN_NOT_DISTINCT)

    first = _load_projection(projection_provider, controlled_closure)
    second = _load_projection(projection_provider, controlled_closure)
    if (
        first.closure != controlled_closure
        or second.closure != controlled_closure
        or first != second
    ):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.SOURCE_PROJECTION_MISMATCH)
    snapshot = first.source_snapshot
    try:
        return M6ReplayLockedSourceDeterminismAuthority(
            command_id=controlled_command.command_id,
            execution_entry_id=controlled_entry.execution_entry_id,
            sample_id=controlled_entry.sample_id,
            source_run_id=controlled_closure.source_run_id,
            candidate_run_id=run_id,
            source_manifest_id=controlled_closure.source_manifest_id,
            execution_component_manifest_id=component_id,
            replay_input_closure_authority_id=(
                controlled_closure.replay_input_closure_authority_id
            ),
            replay_input_closure_document_sha256=(
                controlled_closure.replay_input_closure_document_sha256
            ),
            source_identity_sha256=first.source_identity_sha256,
            first_source_snapshot_id=snapshot.snapshot_id,
            second_source_snapshot_id=second.source_snapshot.snapshot_id,
            first_semantic_case_hash=snapshot.semantic_case_hash,
            second_semantic_case_hash=second.source_snapshot.semantic_case_hash,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.SOURCE_PROJECTION_MISMATCH)


def prove_m6_replay_locked_closed_policy_source_determinism(
    *,
    execution_scope: object,
    pending_commitment: object,
    closure: object,
    policy_causal_cut: object,
    projection_provider: object,
) -> M6ReplayLockedSourceDeterminismAuthority:
    """Read one safe predecessor twice and prove its exact CLOSED source semantics."""

    scope = _canonical_model(
        execution_scope,
        M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    )
    pending = _canonical_model(
        pending_commitment,
        M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    )
    controlled_closure = _canonical_model(closure, M6ReplayInputClosureAuthority)
    cut = _canonical_model(
        policy_causal_cut,
        M6ReplayLockedAlertPolicyCausalCutAuthority,
    )
    if not isinstance(
        projection_provider,
        M6ReplayLockedClosedPolicyPrePolicySourceProvider,
    ):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.INVALID_ARGUMENT)
    entry = pending.pre_policy_pending_commitment.execution_entry
    binding = pending.source_binding
    closure_identity = (
        controlled_closure.sample_id,
        controlled_closure.input_authority_id,
        controlled_closure.input_authority_document_sha256,
        controlled_closure.replay_input_closure_authority_id,
        controlled_closure.replay_input_closure_document_sha256,
    )
    entry_identity = (
        entry.sample_id,
        entry.input_authority_id,
        entry.input_authority_document_sha256,
        entry.replay_input_closure_authority_id,
        entry.replay_input_closure_document_sha256,
    )
    cut_sha256, cut_size = _physical_identity(cut)
    if (
        pending.execution_scope_authority_id != scope.execution_scope_authority_id
        or pending.execution_component_authority_id
        != scope.execution_component.component_authority_id
        or pending.pre_policy_execution_scope_authority_id
        != scope.pre_policy_execution_scope_authority_id
        or pending.locked_config_sha256 != scope.locked_config_sha256
        or entry_identity != closure_identity
        or scope.candidate_run_id == controlled_closure.source_run_id
        or binding.sample_id != controlled_closure.sample_id
        or binding.execution_entry_id != entry.execution_entry_id
        or binding.replay_input_closure_authority_id
        != controlled_closure.replay_input_closure_authority_id
        or binding.replay_input_closure_document_sha256
        != controlled_closure.replay_input_closure_document_sha256
    ):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.EXECUTION_ENTRY_CLOSURE_MISMATCH)
    if (
        binding.policy_causal_cut_authority_id != cut.policy_causal_cut_authority_id
        or binding.policy_causal_cut_content_sha256 != cut_sha256
        or binding.policy_causal_cut_size_bytes != cut_size
        or binding.source_config_sha256 != cut.source_config_sha256
        or binding.cooldown_causal_head != cut.cooldown_causal_head
        or binding.emergency_causal_basis != cut.emergency_causal_basis
        or cut.sample_id != controlled_closure.sample_id
        or cut.replay_input_closure_authority_id
        != controlled_closure.replay_input_closure_authority_id
        or cut.replay_input_closure_document_sha256
        != controlled_closure.replay_input_closure_document_sha256
        or controlled_closure.source_case_id != cut.source_closed_case.case_id
        or controlled_closure.source_case_revision != cut.source_closed_case_revision
        or controlled_closure.source_case_document_sha256 != cut.source_closed_case_content_sha256
        or controlled_closure.source_run_id != cut.source_closed_case.run_id
        or controlled_closure.source_manifest_id != cut.source_closed_case.manifest_id
    ):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.POLICY_CAUSAL_CUT_MISMATCH)

    first = _load_closed_policy_projection(
        projection_provider,
        controlled_closure,
        pending,
    )
    second = _load_closed_policy_projection(
        projection_provider,
        controlled_closure,
        pending,
    )
    if (
        first != second
        or first.catalog_closure != controlled_closure
        or second.catalog_closure != controlled_closure
        or first.source_binding != binding
        or second.source_binding != binding
        or first.source_identity_sha256 != cut.source_identity_sha256
        or second.source_identity_sha256 != cut.source_identity_sha256
        or first.projection_context.case != cut.source_ready_case
        or second.projection_context.case != cut.source_ready_case
        or first.source_ready_case_revision != cut.source_ready_case_revision
        or second.source_ready_case_revision != cut.source_ready_case_revision
    ):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.SOURCE_PROJECTION_MISMATCH)
    first_snapshot = _closed_snapshot(
        source=first,
        cut=cut,
        closure=controlled_closure,
    )
    second_snapshot = _closed_snapshot(
        source=second,
        cut=cut,
        closure=controlled_closure,
    )
    if (
        first_snapshot != second_snapshot
        or first_snapshot.source_case_document_sha256
        != controlled_closure.source_case_document_sha256
        or first_snapshot.source_case_revision != controlled_closure.source_case_revision
    ):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.SOURCE_PROJECTION_MISMATCH)
    try:
        return M6ReplayLockedSourceDeterminismAuthority(
            command_id=scope.command_id,
            execution_entry_id=entry.execution_entry_id,
            sample_id=entry.sample_id,
            source_run_id=controlled_closure.source_run_id,
            candidate_run_id=scope.candidate_run_id,
            source_manifest_id=controlled_closure.source_manifest_id,
            execution_component_manifest_id=(
                scope.pre_policy_execution_scope.execution_component.component_authority_id
            ),
            replay_input_closure_authority_id=(
                controlled_closure.replay_input_closure_authority_id
            ),
            replay_input_closure_document_sha256=(
                controlled_closure.replay_input_closure_document_sha256
            ),
            source_identity_sha256=first.source_identity_sha256,
            first_source_snapshot_id=first_snapshot.snapshot_id,
            second_source_snapshot_id=second_snapshot.snapshot_id,
            first_semantic_case_hash=first_snapshot.semantic_case_hash,
            second_semantic_case_hash=second_snapshot.semantic_case_hash,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedSourceDeterminismErrorCode.SOURCE_PROJECTION_MISMATCH)


__all__ = [
    "M6ReplayLockedSourceDeterminismError",
    "M6ReplayLockedSourceDeterminismErrorCode",
    "prove_m6_replay_locked_closed_policy_source_determinism",
    "prove_m6_replay_locked_source_determinism",
]
