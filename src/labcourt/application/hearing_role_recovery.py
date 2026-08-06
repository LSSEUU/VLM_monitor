"""Fail-closed recovery planning for one pending M4 role call.

The durable request claim is created before the provider boundary, while the
hearing checkpoint advances only after a complete parse trace exists.  A
process crash between those operations therefore leaves the aggregate budget
including the pending role's request.  Re-preparing against that aggregate
would change the request budget and its content-derived identity.

This module reconstructs the exact budget and evidence grant that existed
immediately before the pending primary request.  It performs no I/O and never
chooses a new generation; normal orchestration may only resume generation zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from labcourt.application.hearing_request import HearingBudgetUsage
from labcourt.contracts.enums import ArtifactKind, VlmRole
from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingModelCallFailureAuthority,
    HearingModelRequest,
    HearingUsageReceipt,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.evidence_authority import (
    EvidenceDisclosureError,
    HearingEvidenceGrant,
    RoleEvidenceDisclosure,
    extend_hearing_evidence_grant,
)
from labcourt.domain.procedural_gate import ArtifactBounds
from labcourt.exceptions import ContractViolation
from labcourt.ports.hearing_repository import (
    HearingBudgetUsage as PersistedHearingBudgetUsage,
)


class HearingRoleRecoveryFailureCode(StrEnum):
    """Stable recovery failures without provider-authored text."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    NOT_ROLE_PENDING = "NOT_ROLE_PENDING"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    HISTORY_ORDER_INVALID = "HISTORY_ORDER_INVALID"
    HISTORY_BINDING_INVALID = "HISTORY_BINDING_INVALID"
    BUDGET_RECONSTRUCTION_MISMATCH = "BUDGET_RECONSTRUCTION_MISMATCH"
    CURRENT_CALL_INVALID = "CURRENT_CALL_INVALID"
    EVIDENCE_GRANT_INVALID = "EVIDENCE_GRANT_INVALID"


class HearingRoleRecoveryError(ContractViolation):
    """Persisted M4 roots cannot authorize a deterministic role-call resume."""

    def __init__(self, reason_code: HearingRoleRecoveryFailureCode) -> None:
        if not isinstance(reason_code, HearingRoleRecoveryFailureCode):
            raise TypeError("reason_code must be a HearingRoleRecoveryFailureCode")
        self.reason_code = reason_code
        super().__init__(f"hearing role recovery failed: {reason_code.value}")


def _fail(code: HearingRoleRecoveryFailureCode) -> NoReturn:
    raise HearingRoleRecoveryError(code)


_PENDING_ROLE = {
    HearingCheckpointPhase.PROSECUTOR_PENDING: VlmRole.PROSECUTOR,
    HearingCheckpointPhase.DEFENDER_PENDING: VlmRole.DEFENDER,
    HearingCheckpointPhase.JUDGE_PENDING: VlmRole.JUDGE,
}
_ROLE_ORDER = {
    VlmRole.PROSECUTOR: 0,
    VlmRole.DEFENDER: 1,
    VlmRole.JUDGE: 2,
}
_REPAIR_SCOPE_FIELDS = (
    "run_id",
    "case_id",
    "hearing_session_id",
    "round_index",
    "prior_acquisition_rounds",
    "prior_rework_rounds",
    "current_evidence_pack_id",
    "current_evidence_pack_version",
    "screening_ref",
    "violation_type",
    "evidence_class",
    "role",
    "provider_profile",
    "provider",
    "model",
    "revision",
    "model_manifest_id",
    "execution_location",
    "prompt_manifest",
    "hearing_prompt_bundle_sha256",
    "allowed_evidence_refs",
    "allowed_precedent_refs",
    "prosecutor_output_ref",
    "defender_output_ref",
    "precedent_retrieval_degraded",
    "precedent_retrieval_receipt_id",
    "precedent_retrieval_receipt_sha256",
    "initial_trigger_review_ref",
    "initial_defect_codes",
    "rework_review_ref",
    "rework_defect_codes",
    "temperature",
    "seed",
    "backlog_retry_context",
    "manifest_id",
)


@dataclass(frozen=True, slots=True)
class PendingHearingRoleRecovery:
    """Authority reconstructed immediately before one pending primary call."""

    role: VlmRole
    budget_usage_before_primary: HearingBudgetUsage
    hearing_grant_before_primary: HearingEvidenceGrant | None
    existing_primary: HearingModelRequest | None
    current_requests: tuple[HearingModelRequest, ...]

    def __post_init__(self) -> None:
        if self.role not in _ROLE_ORDER:
            raise TypeError("role must be one exact hearing role")
        if not isinstance(self.budget_usage_before_primary, HearingBudgetUsage):
            raise TypeError("budget_usage_before_primary has the wrong type")
        if self.hearing_grant_before_primary is not None and not isinstance(
            self.hearing_grant_before_primary,
            HearingEvidenceGrant,
        ):
            raise TypeError("hearing_grant_before_primary has the wrong type")
        if self.existing_primary is not None and (
            not isinstance(self.existing_primary, HearingModelRequest)
            or self.existing_primary.attempt_index != 0
            or self.existing_primary.role != self.role
        ):
            raise TypeError("existing_primary has the wrong request identity")
        if (
            not isinstance(self.current_requests, tuple)
            or any(not isinstance(item, HearingModelRequest) for item in self.current_requests)
            or (self.current_requests and self.current_requests[0] != self.existing_primary)
        ):
            raise TypeError("current_requests do not start with existing_primary")


def _request_sort_key(
    request: HearingModelRequest,
) -> tuple[int, int, int, int, str]:
    retry = request.backlog_retry_context
    return (
        request.round_index,
        _ROLE_ORDER[request.role],
        retry.retry_generation if retry is not None else 0,
        request.attempt_index,
        request.request_id,
    )


def _validate_request_scope(
    checkpoint: HearingCheckpoint,
    requests: tuple[HearingModelRequest, ...],
) -> dict[str, HearingModelRequest]:
    if len({item.request_id for item in requests}) != len(requests):
        _fail(HearingRoleRecoveryFailureCode.HISTORY_BINDING_INVALID)
    if requests != tuple(sorted(requests, key=_request_sort_key)):
        _fail(HearingRoleRecoveryFailureCode.HISTORY_ORDER_INVALID)
    for request in requests:
        if (
            request.run_id != checkpoint.run_id
            or request.case_id != checkpoint.case_id
            or request.hearing_session_id != checkpoint.hearing_session_id
            or request.manifest_id != checkpoint.manifest_id
        ):
            _fail(HearingRoleRecoveryFailureCode.SCOPE_MISMATCH)
    return {item.request_id: item for item in requests}


def _validate_usage(
    checkpoint: HearingCheckpoint,
    requests: dict[str, HearingModelRequest],
    usage_receipts: tuple[HearingUsageReceipt, ...],
) -> dict[str, HearingUsageReceipt]:
    if len({item.usage_receipt_id for item in usage_receipts}) != len(usage_receipts):
        _fail(HearingRoleRecoveryFailureCode.HISTORY_BINDING_INVALID)
    try:
        keys = tuple(
            _request_sort_key(requests[item.request_ref.artifact_id]) for item in usage_receipts
        )
    except KeyError:
        _fail(HearingRoleRecoveryFailureCode.HISTORY_BINDING_INVALID)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        _fail(HearingRoleRecoveryFailureCode.HISTORY_ORDER_INVALID)

    by_request: dict[str, HearingUsageReceipt] = {}
    for usage in usage_receipts:
        request_id = usage.request_ref.artifact_id
        request = requests[request_id]
        expected_pixels = sum(item.width * item.height for item in request.media)
        if (
            request_id in by_request
            or usage.request_ref.kind != ArtifactKind.MODEL_REQUEST
            or usage.response_ref.kind != ArtifactKind.MODEL_RESPONSE
            or usage.run_id != checkpoint.run_id
            or usage.case_id != checkpoint.case_id
            or usage.hearing_session_id != checkpoint.hearing_session_id
            or usage.round_index != request.round_index
            or usage.role != request.role
            or usage.input_images != len(request.media)
            or usage.input_pixels != expected_pixels
            or usage.manifest_id != checkpoint.manifest_id
        ):
            _fail(HearingRoleRecoveryFailureCode.HISTORY_BINDING_INVALID)
        by_request[request_id] = usage
    return by_request


def _validate_failures(
    checkpoint: HearingCheckpoint,
    requests: dict[str, HearingModelRequest],
    authorities: tuple[HearingModelCallFailureAuthority, ...],
) -> dict[str, tuple[HearingModelCallFailureAuthority, ...]]:
    if len({item.authority_id for item in authorities}) != len(authorities):
        _fail(HearingRoleRecoveryFailureCode.HISTORY_BINDING_INVALID)
    grouped: dict[str, list[HearingModelCallFailureAuthority]] = {}
    for authority in authorities:
        request = requests.get(authority.request.request_id)
        if (
            request is None
            or authority.request != request
            or authority.run_id != checkpoint.run_id
            or authority.case_id != checkpoint.case_id
            or authority.hearing_session_id != checkpoint.hearing_session_id
            or authority.role != request.role
            or authority.reserved_images != len(request.media)
            or authority.reserved_pixels != sum(item.width * item.height for item in request.media)
            or authority.manifest_id != checkpoint.manifest_id
        ):
            _fail(HearingRoleRecoveryFailureCode.HISTORY_BINDING_INVALID)
        grouped.setdefault(request.request_id, []).append(authority)
    return {request_id: tuple(values) for request_id, values in grouped.items()}


def _current_requests(
    checkpoint: HearingCheckpoint,
    role: VlmRole,
    requests: tuple[HearingModelRequest, ...],
    failure_by_request: dict[
        str,
        tuple[HearingModelCallFailureAuthority, ...],
    ],
) -> tuple[HearingModelRequest, ...]:
    matching_scope = tuple(
        item
        for item in requests
        if item.cycle_scope_id == checkpoint.cycle_scope_id
        and item.cycle_scope_sha256 == checkpoint.cycle_scope_sha256
        and item.role == role
    )
    if any(item.backlog_retry_context is not None for item in matching_scope):
        _fail(HearingRoleRecoveryFailureCode.CURRENT_CALL_INVALID)
    if not matching_scope:
        return ()
    if (
        len(matching_scope) > 2
        or tuple(item.attempt_index for item in matching_scope) not in {(0,), (0, 1)}
        or any(item.request_id in failure_by_request for item in matching_scope)
    ):
        _fail(HearingRoleRecoveryFailureCode.CURRENT_CALL_INVALID)
    primary = matching_scope[0]
    if len(matching_scope) == 2:
        repair = matching_scope[1]
        if repair.original_request_id != primary.request_id or any(
            getattr(repair, field) != getattr(primary, field) for field in _REPAIR_SCOPE_FIELDS
        ):
            _fail(HearingRoleRecoveryFailureCode.CURRENT_CALL_INVALID)
    return matching_scope


def _disclosure_for(request: HearingModelRequest) -> RoleEvidenceDisclosure:
    bounds = tuple(
        sorted(
            (
                ArtifactBounds(
                    artifact_ref=ArtifactRef(
                        kind=ArtifactKind.CROP,
                        artifact_id=media.crop_id,
                    ),
                    width=media.width,
                    height=media.height,
                )
                for media in request.media
            ),
            key=lambda item: item.sort_key,
        )
    )
    return RoleEvidenceDisclosure(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.current_evidence_pack_id,
        evidence_pack_version=request.current_evidence_pack_version,
        media=request.media,
        allowed_evidence_refs=request.allowed_evidence_refs,
        artifact_bounds=bounds,
    )


def _grant_before_current(
    requests: tuple[HearingModelRequest, ...],
    usage_by_request: dict[str, HearingUsageReceipt],
    failure_by_request: dict[
        str,
        tuple[HearingModelCallFailureAuthority, ...],
    ],
    current_ids: set[str],
) -> HearingEvidenceGrant | None:
    grant: HearingEvidenceGrant | None = None
    try:
        for request in requests:
            if request.request_id in current_ids or not request.media:
                continue
            disclosed = request.request_id in usage_by_request or any(
                item.disclosed_images > 0 for item in failure_by_request.get(request.request_id, ())
            )
            if disclosed:
                grant = extend_hearing_evidence_grant(
                    grant,
                    _disclosure_for(request),
                )
    except (EvidenceDisclosureError, TypeError, ValueError):
        _fail(HearingRoleRecoveryFailureCode.EVIDENCE_GRANT_INVALID)
    return grant


def plan_pending_hearing_role_recovery(
    checkpoint: HearingCheckpoint,
    aggregate: PersistedHearingBudgetUsage,
    *,
    requests: tuple[HearingModelRequest, ...],
    usage_receipts: tuple[HearingUsageReceipt, ...],
    failure_authorities: tuple[HearingModelCallFailureAuthority, ...] = (),
) -> PendingHearingRoleRecovery:
    """Rebuild the pre-primary authorities for the checkpoint's pending role."""

    if (
        not isinstance(checkpoint, HearingCheckpoint)
        or not isinstance(aggregate, PersistedHearingBudgetUsage)
        or not isinstance(requests, tuple)
        or any(not isinstance(item, HearingModelRequest) for item in requests)
        or not isinstance(usage_receipts, tuple)
        or any(not isinstance(item, HearingUsageReceipt) for item in usage_receipts)
        or not isinstance(failure_authorities, tuple)
        or any(
            not isinstance(item, HearingModelCallFailureAuthority) for item in failure_authorities
        )
    ):
        _fail(HearingRoleRecoveryFailureCode.INVALID_ARGUMENT)
    role = _PENDING_ROLE.get(checkpoint.phase)
    if role is None:
        _fail(HearingRoleRecoveryFailureCode.NOT_ROLE_PENDING)
    if (
        aggregate.hearing_session_id != checkpoint.hearing_session_id
        or aggregate.manifest_id != checkpoint.manifest_id
    ):
        _fail(HearingRoleRecoveryFailureCode.SCOPE_MISMATCH)

    request_by_id = _validate_request_scope(checkpoint, requests)
    usage_by_request = _validate_usage(
        checkpoint,
        request_by_id,
        usage_receipts,
    )
    failure_by_request = _validate_failures(
        checkpoint,
        request_by_id,
        failure_authorities,
    )
    expected_images = sum(len(item.media) for item in requests)
    expected_pixels = sum(
        media.width * media.height for request in requests for media in request.media
    )
    expected_output_tokens = sum(item.output_tokens for item in usage_receipts) + sum(
        item.output_tokens for item in failure_authorities
    )
    if (
        aggregate.request_count != len(requests)
        or aggregate.reserved_images != expected_images
        or aggregate.reserved_pixels != expected_pixels
        or aggregate.output_tokens != expected_output_tokens
    ):
        _fail(HearingRoleRecoveryFailureCode.BUDGET_RECONSTRUCTION_MISMATCH)

    current = _current_requests(
        checkpoint,
        role,
        requests,
        failure_by_request,
    )
    current_ids = {item.request_id for item in current}
    for request in requests:
        if (
            request.request_id not in current_ids
            and request.request_id not in usage_by_request
            and request.request_id not in failure_by_request
        ):
            _fail(HearingRoleRecoveryFailureCode.HISTORY_BINDING_INVALID)

    current_output_tokens = sum(
        usage_by_request[item.request_id].output_tokens
        for item in current
        if item.request_id in usage_by_request
    )
    before_images = aggregate.reserved_images - sum(len(item.media) for item in current)
    before_tokens = aggregate.output_tokens - current_output_tokens
    if before_images < 0 or before_tokens < 0:
        _fail(HearingRoleRecoveryFailureCode.BUDGET_RECONSTRUCTION_MISMATCH)

    return PendingHearingRoleRecovery(
        role=role,
        budget_usage_before_primary=HearingBudgetUsage(
            reserved_images=before_images,
            accounted_output_tokens=before_tokens,
        ),
        hearing_grant_before_primary=_grant_before_current(
            requests,
            usage_by_request,
            failure_by_request,
            current_ids,
        ),
        existing_primary=current[0] if current else None,
        current_requests=current,
    )


__all__ = [
    "HearingRoleRecoveryError",
    "HearingRoleRecoveryFailureCode",
    "PendingHearingRoleRecovery",
    "plan_pending_hearing_role_recovery",
]
