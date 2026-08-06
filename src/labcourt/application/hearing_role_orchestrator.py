"""Advance exactly one pending M4 advocate or Judge role."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.application._hearing_workflow_types import (
    HearingCoordinatorError,
    HearingCoordinatorErrorCode,
)
from labcourt.application.hearing_acquisition_request import (
    build_acquisition_request,
)
from labcourt.application.hearing_initial_backlog import (
    HearingInitialBacklogFailure,
    HearingInitialBacklogFailureCode,
    build_initial_hearing_backlog_intent,
)
from labcourt.application.hearing_request import (
    HearingRequestPreparationError,
    HearingRequestPreparationErrorCode,
    prepare_primary_hearing_request,
)
from labcourt.application.hearing_role_call import (
    HearingRoleCallContext,
    HearingRoleCallError,
    HearingRoleCallFailureCode,
    HearingRoleCallService,
)
from labcourt.application.hearing_role_recovery import (
    plan_pending_hearing_role_recovery,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import VlmRole
from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingHumanReviewReason,
    HearingSession,
    JudgeAcquisitionDecisionPayload,
    JudgeModelPayload,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.domain.evidence_authority import EvidenceAuthority
from labcourt.domain.hearing_fsm import (
    complete_defender,
    complete_judge,
    complete_prosecutor,
    transfer_to_human_review,
)
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.hearing_backlog import HearingBacklogRepository
from labcourt.ports.hearing_repository import HearingRepository
from labcourt.ports.prompts import PromptCatalog


@dataclass(frozen=True, slots=True)
class HearingRoleAdvance:
    """The next durable checkpoint or a bounded Case disposition."""

    checkpoint: HearingCheckpoint
    case: CaseSnapshot | None = None
    backlog_item_id: str | None = None
    cache_hit_count: int = 0
    recovered_response_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint, HearingCheckpoint):
            raise TypeError("checkpoint must be a HearingCheckpoint")
        if self.case is not None and not isinstance(self.case, CaseSnapshot):
            raise TypeError("case must be a CaseSnapshot or None")
        for name in ("cache_hit_count", "recovered_response_count"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TypeError(f"{name} must be a non-negative integer")
        if self.backlog_item_id is not None and (
            self.case is None or self.case.case.current_backlog_item_id != self.backlog_item_id
        ):
            raise ValueError("backlog identity conflicts with the returned Case")


_PENDING_ROLE = {
    HearingCheckpointPhase.PROSECUTOR_PENDING: VlmRole.PROSECUTOR,
    HearingCheckpointPhase.DEFENDER_PENDING: VlmRole.DEFENDER,
    HearingCheckpointPhase.JUDGE_PENDING: VlmRole.JUDGE,
}
_SESSION_BUDGET_FAILURES = {
    HearingRequestPreparationErrorCode.IMAGE_BUDGET_EXHAUSTED,
    HearingRequestPreparationErrorCode.OUTPUT_TOKEN_BUDGET_EXHAUSTED,
}


def _coordination_error(
    checkpoint: HearingCheckpoint,
    code: HearingCoordinatorErrorCode,
) -> HearingCoordinatorError:
    return HearingCoordinatorError(code, case_id=checkpoint.case_id)


def _commit_budget_exhaustion(
    *,
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    source_case: CaseSnapshot,
    audit_head: AuditHead,
    repository: HearingRepository,
) -> HearingRoleAdvance:
    transition = transfer_to_human_review(
        session,
        checkpoint,
        HearingHumanReviewReason.HEARING_BUDGET_EXHAUSTED,
    )
    assert transition.human_review_receipt is not None
    committed = repository.commit_hearing_human_review(
        checkpoint.run_id,
        source_case.revision,
        audit_head,
        transition.human_review_receipt,
        transition.checkpoint,
    )
    return HearingRoleAdvance(
        checkpoint=committed.checkpoint,
        case=committed.case,
    )


def _commit_role_failure(
    *,
    error: HearingRoleCallError,
    checkpoint: HearingCheckpoint,
    source_case: CaseSnapshot,
    audit_head: AuditHead,
    config: AppConfig,
    backlog_repository: HearingBacklogRepository,
) -> HearingRoleAdvance:
    try:
        intent = build_initial_hearing_backlog_intent(
            error,
            checkpoint,
            max_attempts=config.screening.backlog_max_attempts,
        )
    except HearingInitialBacklogFailure as failure:
        if failure.reason_code == HearingInitialBacklogFailureCode.RECOVERY_REQUIRED:
            raise _coordination_error(
                checkpoint,
                HearingCoordinatorErrorCode.ROLE_RECOVERY_REQUIRED,
            ) from failure
        raise _coordination_error(
            checkpoint,
            HearingCoordinatorErrorCode.AUTHORITY_MISMATCH,
        ) from failure
    committed = backlog_repository.commit_hearing_backlog(
        checkpoint.run_id,
        source_case.revision,
        audit_head,
        intent,
    )
    return HearingRoleAdvance(
        checkpoint=committed.checkpoint,
        case=committed.case,
        backlog_item_id=committed.item.item_id,
    )


def advance_pending_hearing_role(
    *,
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    source_case: CaseSnapshot,
    audit_head: AuditHead,
    evidence: EvidenceAuthority,
    run_manifest: RunManifest,
    config: AppConfig,
    catalog: PromptCatalog,
    repository: HearingRepository,
    backlog_repository: HearingBacklogRepository,
    role_calls: HearingRoleCallService,
) -> HearingRoleAdvance:
    """Prepare/recover, execute, and persist one exact pending role."""

    role = _PENDING_ROLE.get(checkpoint.phase)
    if role is None:
        raise _coordination_error(
            checkpoint,
            HearingCoordinatorErrorCode.AUTHORITY_MISMATCH,
        )
    retrieval = checkpoint.precedent_retrieval_receipt
    if retrieval is None:
        raise _coordination_error(
            checkpoint,
            HearingCoordinatorErrorCode.AUTHORITY_MISMATCH,
        )
    cycle_scope = repository.load_hearing_cycle(
        checkpoint.run_id,
        checkpoint.cycle_scope_id,
    )
    aggregate = repository.load_hearing_budget_usage(
        checkpoint.run_id,
        session.session_id,
    )
    recovery = plan_pending_hearing_role_recovery(
        checkpoint,
        aggregate,
        requests=repository.list_hearing_model_requests(
            checkpoint.run_id,
            session.session_id,
        ),
        usage_receipts=repository.list_hearing_usage_receipts(
            checkpoint.run_id,
            session.session_id,
        ),
        failure_authorities=repository.list_hearing_failure_authorities(
            checkpoint.run_id,
            session.session_id,
        ),
    )
    try:
        prepared = prepare_primary_hearing_request(
            role=role,
            session=session,
            cycle_scope=cycle_scope,
            retrieval=retrieval,
            evidence_pack=evidence.pack,
            evidence_authority=evidence,
            hearing_grant=recovery.hearing_grant_before_primary,
            budget_usage=recovery.budget_usage_before_primary,
            config=config,
            run_manifest=run_manifest,
            catalog=catalog,
            prosecutor_output=checkpoint.prosecutor_output,
            defender_output=checkpoint.defender_output,
        )
    except HearingRequestPreparationError as error:
        if error.reason_code in _SESSION_BUDGET_FAILURES:
            return _commit_budget_exhaustion(
                session=session,
                checkpoint=checkpoint,
                source_case=source_case,
                audit_head=audit_head,
                repository=repository,
            )
        raise _coordination_error(
            checkpoint,
            HearingCoordinatorErrorCode.AUTHORITY_MISMATCH,
        ) from error
    if recovery.existing_primary is not None and prepared.request != recovery.existing_primary:
        raise _coordination_error(
            checkpoint,
            HearingCoordinatorErrorCode.ROLE_RECOVERY_REQUIRED,
        )

    context = HearingRoleCallContext(
        session=session,
        cycle_scope=cycle_scope,
        budget_usage_before_primary=recovery.budget_usage_before_primary,
        config=config,
        run_manifest=run_manifest,
        catalog=catalog,
    )
    try:
        result = role_calls.execute(prepared, context)
    except HearingRoleCallError as error:
        if error.reason_code == HearingRoleCallFailureCode.HEARING_BUDGET_EXHAUSTED:
            return _commit_budget_exhaustion(
                session=session,
                checkpoint=checkpoint,
                source_case=source_case,
                audit_head=audit_head,
                repository=repository,
            )
        return _commit_role_failure(
            error=error,
            checkpoint=checkpoint,
            source_case=source_case,
            audit_head=audit_head,
            config=config,
            backlog_repository=backlog_repository,
        )

    if role == VlmRole.PROSECUTOR:
        successor = complete_prosecutor(
            session,
            checkpoint,
            result.output,
            result.trace,
        )
    elif role == VlmRole.DEFENDER:
        successor = complete_defender(
            session,
            checkpoint,
            result.output,
            result.trace,
        )
    else:
        acquisition = None
        payload = result.output.payload
        if (
            isinstance(payload, JudgeModelPayload)
            and isinstance(payload.outcome, JudgeAcquisitionDecisionPayload)
            and checkpoint.prior_acquisition_rounds < session.acquisition_round_limit
        ):
            acquisition = build_acquisition_request(
                session,
                checkpoint,
                result.output,
            )
        transition = complete_judge(
            session,
            checkpoint,
            result.output,
            result.trace,
            acquisition_request=acquisition,
        )
        successor = transition.checkpoint
        if transition.human_review_receipt is not None:
            committed = repository.commit_hearing_human_review(
                checkpoint.run_id,
                source_case.revision,
                audit_head,
                transition.human_review_receipt,
                successor,
            )
            return HearingRoleAdvance(
                checkpoint=committed.checkpoint,
                case=committed.case,
                cache_hit_count=result.cache_hit_count,
                recovered_response_count=result.recovered_response_count,
            )

    try:
        repository.append_hearing_checkpoint(checkpoint.run_id, successor)
    except ConcurrentModification as error:
        raise _coordination_error(
            checkpoint,
            HearingCoordinatorErrorCode.PERSISTENCE_CONFLICT,
        ) from error
    return HearingRoleAdvance(
        checkpoint=successor,
        cache_hit_count=result.cache_hit_count,
        recovered_response_count=result.recovered_response_count,
    )


__all__ = [
    "HearingRoleAdvance",
    "advance_pending_hearing_role",
]
