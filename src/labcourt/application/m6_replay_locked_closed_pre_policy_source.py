"""Trusted rebase from one CLOSED causal cut to its sanitized READY source."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.hearing_state import HearingRecord, HearingVerdictBinding
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionRoute,
)
from labcourt.contracts.m6_replay_locked_policy import (
    M6ReplayLockedAlertPolicyCausalCutAuthority,
)
from labcourt.contracts.m6_source_authority import M6GateCurrentClosureReceipt
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
    M6ReplayLockedClosedPolicyM4PrePolicySource,
    M6ReplayLockedClosedPolicyPrePolicySource,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedClosedPrePolicySourceErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    CAUSAL_CUT_MISMATCH = "CAUSAL_CUT_MISMATCH"
    CLOSED_PROJECTION_MISMATCH = "CLOSED_PROJECTION_MISMATCH"
    READY_REBASE_REJECTED = "READY_REBASE_REJECTED"
    ROUTE_AUTHORITY_MISSING = "ROUTE_AUTHORITY_MISSING"


class M6ReplayLockedClosedPrePolicySourceError(LabCourtError):
    """Payload-free failure from the trusted CLOSED-to-READY rebase."""

    def __init__(
        self,
        code: M6ReplayLockedClosedPrePolicySourceErrorCode,
    ) -> None:
        if not isinstance(code, M6ReplayLockedClosedPrePolicySourceErrorCode):
            raise TypeError("code must be an M6 CLOSED pre-policy source error code")
        self.code = code
        super().__init__(f"M6 CLOSED pre-policy source rebase failed: {code.value}")


def _fail(code: M6ReplayLockedClosedPrePolicySourceErrorCode) -> NoReturn:
    raise M6ReplayLockedClosedPrePolicySourceError(code) from None


def _canonical(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_context(value: object) -> M6VerifiedProjectionContext:
    if type(value) is not M6VerifiedProjectionContext:
        _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.INVALID_ARGUMENT)
    try:
        return M6VerifiedProjectionContext(
            case=value.case,
            perception=value.perception,
            historical_source_run_id=value.historical_source_run_id,
            historical_source_case_id=value.historical_source_case_id,
            historical_source_manifest_id=value.historical_source_manifest_id,
            model_reference_authority=value.model_reference_authority,
            procedural_gate_authority=value.procedural_gate_authority,
            model_responses=value.model_responses,
            retrieval_cycles=value.retrieval_cycles,
            acquisitions=value.acquisitions,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.INVALID_ARGUMENT)


def _identity(value: BaseModel) -> tuple[str, int]:
    document = canonical_json(value.model_dump(mode="json"))
    payload = document.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _ready_context(
    closed_context: M6VerifiedProjectionContext,
    cut: M6ReplayLockedAlertPolicyCausalCutAuthority,
) -> M6VerifiedProjectionContext:
    try:
        return M6VerifiedProjectionContext(
            case=cut.source_ready_case,
            perception=closed_context.perception,
            historical_source_run_id=closed_context.historical_source_run_id,
            historical_source_case_id=closed_context.historical_source_case_id,
            historical_source_manifest_id=(closed_context.historical_source_manifest_id),
            model_reference_authority=(closed_context.model_reference_authority),
            procedural_gate_authority=(closed_context.procedural_gate_authority),
            model_responses=closed_context.model_responses,
            retrieval_cycles=closed_context.retrieval_cycles,
            acquisitions=closed_context.acquisitions,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.READY_REBASE_REJECTED)


def build_m6_replay_locked_closed_policy_pre_policy_source(
    *,
    source_binding: object,
    policy_causal_cut: object,
    catalog_closure: object,
    closed_projection_context: object,
    hearing_record: object | None = None,
    hearing_verdict_binding: object | None = None,
    gate_current_closure_receipt: object | None = None,
) -> M6ReplayLockedClosedPolicyPrePolicySource:
    """Remove evaluator-only policy/CLOSED truth after proving one exact cut."""

    binding = _canonical(
        source_binding,
        M6ReplayLockedClosedPolicySourceBindingAuthority,
    )
    cut = _canonical(
        policy_causal_cut,
        M6ReplayLockedAlertPolicyCausalCutAuthority,
    )
    closure = _canonical(catalog_closure, M6ReplayInputClosureAuthority)
    closed_context = _controlled_context(closed_projection_context)
    cut_sha256, cut_size = _identity(cut)
    if (
        binding.policy_causal_cut_authority_id != cut.policy_causal_cut_authority_id
        or binding.policy_causal_cut_content_sha256 != cut_sha256
        or binding.policy_causal_cut_size_bytes != cut_size
        or binding.source_config_sha256 != cut.source_config_sha256
        or binding.cooldown_causal_head != cut.cooldown_causal_head
        or binding.emergency_causal_basis != cut.emergency_causal_basis
        or binding.sample_id != closure.sample_id
        or binding.replay_input_closure_authority_id != closure.replay_input_closure_authority_id
        or binding.replay_input_closure_document_sha256
        != closure.replay_input_closure_document_sha256
        or cut.sample_id != closure.sample_id
        or cut.replay_input_closure_authority_id != closure.replay_input_closure_authority_id
        or cut.replay_input_closure_document_sha256 != closure.replay_input_closure_document_sha256
        or closure.source_case_id != cut.source_closed_case.case_id
        or closure.source_case_revision != cut.source_closed_case_revision
        or closure.source_case_document_sha256 != cut.source_closed_case_content_sha256
        or closure.source_run_id != cut.source_closed_case.run_id
        or closure.source_manifest_id != cut.source_closed_case.manifest_id
        or closure.source_validation_report_id != cut.source_validation_report_id
        or closure.source_validation_report_document_sha256
        != cut.source_validation_report_document_sha256
    ):
        _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.CAUSAL_CUT_MISMATCH)
    if (
        closed_context.case != cut.source_closed_case
        or closed_context.historical_source_run_id != closure.source_run_id
        or closed_context.historical_source_case_id != closure.source_case_id
        or closed_context.historical_source_manifest_id != closure.source_manifest_id
        or closed_context.model_reference_authority.source_identity_sha256
        != cut.source_identity_sha256
        or closed_context.procedural_gate_authority.source_identity_sha256
        != cut.source_identity_sha256
    ):
        _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.CLOSED_PROJECTION_MISMATCH)
    ready_context = _ready_context(closed_context, cut)
    try:
        ready_snapshot = build_m6_case_replay_snapshot(
            context=ready_context,
            sample_id=closure.sample_id,
            source_case_revision=cut.source_ready_case_revision,
        )
        if binding.pre_policy_route == (M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE):
            if any(
                value is not None
                for value in (
                    hearing_record,
                    hearing_verdict_binding,
                    gate_current_closure_receipt,
                )
            ):
                _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.INVALID_ARGUMENT)
            return M6ReplayLockedClosedPolicyFastPrePolicySource(
                source_identity_sha256=cut.source_identity_sha256,
                source_binding=binding,
                catalog_closure=closure,
                source_ready_case_revision=cut.source_ready_case_revision,
                projection_context=ready_context,
                source_snapshot=ready_snapshot,
            )
        if binding.pre_policy_route == (
            M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
        ):
            if (
                type(hearing_record) is not HearingRecord
                or type(hearing_verdict_binding) is not HearingVerdictBinding
                or type(gate_current_closure_receipt) is not M6GateCurrentClosureReceipt
            ):
                _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.ROUTE_AUTHORITY_MISSING)
            return M6ReplayLockedClosedPolicyM4PrePolicySource(
                source_identity_sha256=cut.source_identity_sha256,
                source_binding=binding,
                catalog_closure=closure,
                source_ready_case_revision=cut.source_ready_case_revision,
                projection_context=ready_context,
                hearing_record=hearing_record,
                hearing_verdict_binding=hearing_verdict_binding,
                gate_current_closure_receipt=gate_current_closure_receipt,
                source_snapshot=ready_snapshot,
            )
    except M6ReplayLockedClosedPrePolicySourceError:
        raise
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.READY_REBASE_REJECTED)
    _fail(M6ReplayLockedClosedPrePolicySourceErrorCode.INVALID_ARGUMENT)


__all__ = [
    "M6ReplayLockedClosedPrePolicySourceError",
    "M6ReplayLockedClosedPrePolicySourceErrorCode",
    "build_m6_replay_locked_closed_policy_pre_policy_source",
]
