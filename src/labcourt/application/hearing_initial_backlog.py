"""Pure bridge from one failed initial M4 role call to backlog authority.

The role-call service owns the secret claim token while the coordinator owns
the exact pending checkpoint and queue policy.  This module joins those two
authorities without giving an unclassified exception permission to advance a
Case or create retry work.
"""

from __future__ import annotations

from enum import StrEnum

from labcourt.application.hearing_role_call import (
    HearingRoleCallError,
    HearingRoleCallFailureCode,
)
from labcourt.contracts.backlog import BacklogItem
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
)
from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingInitialStrictParseFailureProof,
    HearingModelRequest,
    HearingStrictParseFailureAttempt,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ContractViolation
from labcourt.ports.hearing_backlog import (
    HearingBacklogEnqueueIntent,
    hearing_request_document_sha256,
)


class HearingInitialBacklogFailureCode(StrEnum):
    """Stable reasons an initial role failure cannot authorize queue work."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    FAILURE_AUTHORITY_INVALID = "FAILURE_AUTHORITY_INVALID"


class HearingInitialBacklogFailure(ContractViolation):
    """Controlled bridge failure containing no provider-authored content."""

    def __init__(
        self,
        reason_code: HearingInitialBacklogFailureCode,
        *,
        request_id: str,
    ) -> None:
        if not isinstance(reason_code, HearingInitialBacklogFailureCode):
            raise TypeError("reason_code must be a HearingInitialBacklogFailureCode")
        if not isinstance(request_id, str):
            raise TypeError("request_id must be a string")
        self.reason_code = reason_code
        self.request_id = request_id
        super().__init__(f"initial hearing backlog bridge failed: {reason_code.value}")


def build_initial_hearing_backlog_intent(
    error: HearingRoleCallError,
    checkpoint: HearingCheckpoint,
    *,
    max_attempts: int,
) -> HearingBacklogEnqueueIntent:
    """Build the sole legal initial HEARING enqueue from durable authority.

    Known, definitely-not-sent provider failures keep generation zero and the
    exact unfinished request.  Two persisted strict parse failures start
    generation one and bind both complete call closures.  Every other failure
    retains the role claim/checkpoint for recovery or a separate human-review
    decision; it cannot be converted to retry authority here.
    """

    if not isinstance(error, HearingRoleCallError) or not isinstance(checkpoint, HearingCheckpoint):
        request_id = (
            error.request_id if isinstance(error, HearingRoleCallError) else "invalid-request"
        )
        raise HearingInitialBacklogFailure(
            HearingInitialBacklogFailureCode.INVALID_ARGUMENT,
            request_id=request_id,
        )
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts <= 0:
        raise HearingInitialBacklogFailure(
            HearingInitialBacklogFailureCode.INVALID_ARGUMENT,
            request_id=error.request_id,
        )

    provider = error.model_call_failure
    if provider is not None:
        request = provider.request
        item = _initial_item(
            request=request,
            reason=provider.backlog_reason_code,
            retry_generation=0,
            max_attempts=max_attempts,
        )
        try:
            return HearingBacklogEnqueueIntent(
                item=item,
                checkpoint=checkpoint,
                stage_request=request,
                model_call_failure=provider,
            )
        except (TypeError, ValueError) as cause:
            raise HearingInitialBacklogFailure(
                HearingInitialBacklogFailureCode.FAILURE_AUTHORITY_INVALID,
                request_id=error.request_id,
            ) from cause

    if error.reason_code != HearingRoleCallFailureCode.STRICT_PARSE_FAILED:
        raise HearingInitialBacklogFailure(
            HearingInitialBacklogFailureCode.RECOVERY_REQUIRED,
            request_id=error.request_id,
        )
    if len(error.failed_calls) != 2:
        raise HearingInitialBacklogFailure(
            HearingInitialBacklogFailureCode.FAILURE_AUTHORITY_INVALID,
            request_id=error.request_id,
        )
    primary = error.failed_calls[0].request
    item = _initial_item(
        request=primary,
        reason=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        retry_generation=1,
        max_attempts=max_attempts,
    )
    try:
        proof = HearingInitialStrictParseFailureProof(
            backlog_item_id=item.item_id,
            source_checkpoint_id=checkpoint.checkpoint_id,
            source_checkpoint_sha256=checkpoint.checkpoint_sha256,
            source_checkpoint_version=checkpoint.version,
            role=primary.role,
            attempts=tuple(
                HearingStrictParseFailureAttempt(
                    request=call.request,
                    response=call.response,
                    parse_receipt=call.parse_receipt,
                )
                for call in error.failed_calls
            ),
        )
        return HearingBacklogEnqueueIntent(
            item=item,
            checkpoint=checkpoint,
            stage_request=primary,
            strict_parse_failure=proof,
        )
    except (TypeError, ValueError) as cause:
        raise HearingInitialBacklogFailure(
            HearingInitialBacklogFailureCode.FAILURE_AUTHORITY_INVALID,
            request_id=error.request_id,
        ) from cause


def _initial_item(
    *,
    request: HearingModelRequest,
    reason: BacklogReasonCode,
    retry_generation: int,
    max_attempts: int,
) -> BacklogItem:
    return BacklogItem(
        run_id=request.run_id,
        case_id=request.case_id,
        stage=BacklogStage.HEARING,
        role=request.role,
        reason_code=reason,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=request.request_id,
        ),
        stage_input_sha256=hearing_request_document_sha256(request),
        max_attempts=max_attempts,
        retry_generation=retry_generation,
        status=BacklogStatus.PENDING,
        manifest_id=request.manifest_id,
    )


__all__ = [
    "HearingInitialBacklogFailure",
    "HearingInitialBacklogFailureCode",
    "build_initial_hearing_backlog_intent",
]
