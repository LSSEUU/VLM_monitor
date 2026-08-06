"""Exact-role M4 backlog retry under lease, checkpoint, Case, and audit CAS."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from labcourt.application.hearing_acquisition_request import build_acquisition_request
from labcourt.application.hearing_request import PreparedHearingRequest
from labcourt.application.hearing_role_call import (
    HearingRoleCallContext,
    HearingRoleCallError,
    HearingRoleCallFailureCode,
    HearingRoleCallResult,
)
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStatus,
    VlmRole,
)
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    HearingBacklogRetryFailure,
    HearingBacklogRetryOutcome,
    HearingBacklogRetrySuccess,
    HearingHumanReviewReason,
    HearingHumanReviewReceipt,
    HearingStrictParseFailureAttempt,
    HearingStrictParseFailureProof,
    JudgeAcquisitionDecisionPayload,
    JudgeModelPayload,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import (
    HearingCallClosure,
    HearingTransition,
    complete_defender,
    complete_judge,
    complete_prosecutor,
)
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.hearing_backlog import (
    HearingBacklogRepository,
    HearingBacklogRetryAuthority,
    HearingBacklogRetryCommit,
    HearingModelCallFailureIntent,
)


class HearingBacklogRetryRecoveryCode(StrEnum):
    """Typed reasons that must leave the lease for provider-free recovery."""

    CLAIM_RECOVERY_REQUIRED = "CLAIM_RECOVERY_REQUIRED"
    RESPONSE_PUBLICATION_RECOVERY_REQUIRED = "RESPONSE_PUBLICATION_RECOVERY_REQUIRED"
    PERSISTENCE_RECOVERY_REQUIRED = "PERSISTENCE_RECOVERY_REQUIRED"


class HearingBacklogRetryRecoveryRequired(ContractViolation):
    """The exact call is not safely closable until maintenance converges it."""

    def __init__(
        self,
        code: HearingBacklogRetryRecoveryCode,
        *,
        request_id: str,
    ) -> None:
        if not isinstance(code, HearingBacklogRetryRecoveryCode):
            raise TypeError("code must be a HearingBacklogRetryRecoveryCode")
        if not isinstance(request_id, str):
            raise TypeError("request_id must be a string")
        self.code = code
        self.request_id = request_id
        super().__init__(f"hearing backlog call requires recovery: {code.value}")


@dataclass(frozen=True, slots=True)
class HearingBacklogCallPlan:
    """Prepared exact call; repair is present only for repair-only resume."""

    primary: PreparedHearingRequest
    context: HearingRoleCallContext
    repair: PreparedHearingRequest | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.primary, PreparedHearingRequest):
            raise TypeError("primary must be a PreparedHearingRequest")
        if not isinstance(self.context, HearingRoleCallContext):
            raise TypeError("context must be a HearingRoleCallContext")
        if self.repair is not None and not isinstance(self.repair, PreparedHearingRequest):
            raise TypeError("repair must be a PreparedHearingRequest or None")
        if self.primary.request.attempt_index != 0:
            raise ValueError("hearing backlog plan primary must have attempt index zero")
        if self.repair is not None and self.repair.request.attempt_index != 1:
            raise ValueError("hearing backlog repair plan must have attempt index one")


class HearingBacklogRoleCallExecutor(Protocol):
    """Only the two provider-boundary operations a retry may invoke."""

    def execute(
        self,
        prepared: PreparedHearingRequest,
        context: HearingRoleCallContext,
    ) -> HearingRoleCallResult: ...

    def resume_repair(
        self,
        original: PreparedHearingRequest,
        repair: PreparedHearingRequest,
        primary_failure: HearingCallClosure,
        context: HearingRoleCallContext,
    ) -> HearingRoleCallResult: ...


_REQUEST_SCOPE_FIELDS = (
    "run_id",
    "case_id",
    "hearing_session_id",
    "cycle_scope_id",
    "cycle_scope_sha256",
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
    "hearing_context_sha256",
    "media",
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
    "manifest_id",
)


class HearingBacklogRetryService:
    """Retry one already-leased HEARING item without driving another role."""

    __slots__ = ("_repository", "_role_calls")

    def __init__(
        self,
        *,
        repository: HearingBacklogRepository,
        role_calls: HearingBacklogRoleCallExecutor,
    ) -> None:
        for dependency, methods, name in (
            (
                repository,
                ("load_hearing_backlog_retry_authority", "commit_hearing_backlog_retry"),
                "repository",
            ),
            (role_calls, ("execute", "resume_repair"), "role_calls"),
        ):
            for method in methods:
                if not callable(getattr(dependency, method, None)):
                    raise TypeError(f"{name} does not implement {method}")
        self._repository = repository
        self._role_calls = role_calls

    def retry_leased_item(
        self,
        authority: HearingBacklogRetryAuthority,
        plan: HearingBacklogCallPlan,
    ) -> HearingBacklogRetryCommit:
        """Resolve one exact active lease or leave it untouched for recovery."""

        if not isinstance(authority, HearingBacklogRetryAuthority):
            raise TypeError("authority must be a HearingBacklogRetryAuthority")
        if not isinstance(plan, HearingBacklogCallPlan):
            raise TypeError("plan must be a HearingBacklogCallPlan")
        self._require_current_authority(authority)
        self._validate_plan(authority, plan)
        try:
            result = self._execute(authority, plan)
        except HearingRoleCallError as error:
            return self._resolve_call_failure(authority, error)
        self._validate_result(authority, plan, result)
        transition = self._advance_role(authority, result)
        successful = result.trace.successful_call
        outcome = HearingBacklogRetrySuccess(
            lease=authority.lease,
            session=authority.session,
            source_checkpoint_id=authority.checkpoint.checkpoint_id,
            source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
            source_checkpoint_version=authority.checkpoint.version,
            request=successful.request,
            response=successful.response,
            parse_receipt=successful.parse_receipt,
            parsed_role_output=result.output,
            next_checkpoint=transition.checkpoint,
            human_review_receipt=transition.human_review_receipt,
            manifest_id=authority.item.manifest_id,
        )
        return self._commit(authority, outcome)

    def _execute(
        self,
        authority: HearingBacklogRetryAuthority,
        plan: HearingBacklogCallPlan,
    ) -> HearingRoleCallResult:
        if plan.repair is None:
            return self._role_calls.execute(plan.primary, plan.context)
        primary_failure = authority.prior_primary_failure
        if primary_failure is None:
            raise AssertionError("validated repair resume lacks its primary closure")
        return self._role_calls.resume_repair(
            plan.primary,
            plan.repair,
            primary_failure,
            plan.context,
        )

    def _resolve_call_failure(
        self,
        authority: HearingBacklogRetryAuthority,
        error: HearingRoleCallError,
    ) -> HearingBacklogRetryCommit:
        recovery = {
            HearingRoleCallFailureCode.CLAIM_TIMEOUT: (
                HearingBacklogRetryRecoveryCode.CLAIM_RECOVERY_REQUIRED
            ),
            HearingRoleCallFailureCode.CLAIM_RECOVERY_REQUIRED: (
                HearingBacklogRetryRecoveryCode.CLAIM_RECOVERY_REQUIRED
            ),
            HearingRoleCallFailureCode.RESPONSE_PUBLICATION_RECOVERY_REQUIRED: (
                HearingBacklogRetryRecoveryCode.RESPONSE_PUBLICATION_RECOVERY_REQUIRED
            ),
            HearingRoleCallFailureCode.PERSISTENCE_FAILURE: (
                HearingBacklogRetryRecoveryCode.PERSISTENCE_RECOVERY_REQUIRED
            ),
        }.get(error.reason_code)
        if recovery is not None:
            raise HearingBacklogRetryRecoveryRequired(
                recovery,
                request_id=error.request_id,
            ) from error

        strict_proof: HearingStrictParseFailureProof | None = None
        response_refs: tuple[ArtifactRef, ...] = ()
        if error.reason_code == HearingRoleCallFailureCode.STRICT_PARSE_FAILED:
            if len(error.failed_calls) != 2:
                raise ContractViolation(
                    "strict hearing retry failure lacks primary-and-repair closure"
                ) from error
            role = authority.item.role
            assert role is not None
            strict_proof = HearingStrictParseFailureProof(
                lease=authority.lease,
                source_checkpoint_id=authority.checkpoint.checkpoint_id,
                source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
                source_checkpoint_version=authority.checkpoint.version,
                role=role,
                attempts=tuple(
                    HearingStrictParseFailureAttempt(
                        request=call.request,
                        response=call.response,
                        parse_receipt=call.parse_receipt,
                    )
                    for call in error.failed_calls
                ),
            )
            response_refs = tuple(
                sorted(
                    (
                        ArtifactRef(
                            kind=ArtifactKind.MODEL_RESPONSE,
                            artifact_id=call.response.response_id,
                        )
                        for call in error.failed_calls
                    ),
                    key=lambda ref: ref.sort_key,
                )
            )
            request = error.failed_calls[0].request
            reason = BacklogReasonCode.MODEL_OUTPUT_INVALID
        else:
            reason = self._backlog_reason(error)
            failed_request = error.request
            if failed_request is None:
                raise ContractViolation("hearing call failure omitted its exact request") from error
            request = failed_request
        role = authority.item.role
        assert role is not None
        if request.role != role:
            raise ContractViolation("hearing call failure changed the leased role") from error

        next_status = (
            BacklogStatus.EXHAUSTED
            if authority.item.attempt_count == authority.item.max_attempts
            else BacklogStatus.PENDING
        )
        human = (
            self._backlog_exhaustion_receipt(authority)
            if next_status == BacklogStatus.EXHAUSTED
            else None
        )
        failure = HearingBacklogRetryFailure(
            lease=authority.lease,
            source_checkpoint_id=authority.checkpoint.checkpoint_id,
            source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
            source_checkpoint_version=authority.checkpoint.version,
            request=request,
            role=role,
            reason_code=reason,
            next_status=next_status,
            response_refs=response_refs,
            strict_parse_failure=strict_proof,
            human_review_receipt=human,
            manifest_id=authority.item.manifest_id,
        )
        return self._commit(
            authority,
            failure,
            model_call_failure=error.model_call_failure,
        )

    @staticmethod
    def _backlog_reason(error: HearingRoleCallError) -> BacklogReasonCode:
        reason = {
            HearingRoleCallFailureCode.PROVIDER_FAILED: BacklogReasonCode.PROVIDER_UNAVAILABLE,
            HearingRoleCallFailureCode.CLAIM_TIMEOUT: BacklogReasonCode.PROVIDER_UNAVAILABLE,
            HearingRoleCallFailureCode.HEARING_BUDGET_EXHAUSTED: (
                BacklogReasonCode.BUDGET_EXCEEDED
            ),
            HearingRoleCallFailureCode.RESPONSE_INTEGRITY_FAILURE: (
                BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
            ),
            HearingRoleCallFailureCode.STRUCTURE_REPAIR_PREPARATION_FAILED: (
                BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
            ),
            HearingRoleCallFailureCode.PROMPT_REGISTRATION_FAILED: (
                BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
            ),
        }.get(error.reason_code)
        if reason is None:
            raise error
        return reason

    @staticmethod
    def _backlog_exhaustion_receipt(
        authority: HearingBacklogRetryAuthority,
    ) -> HearingHumanReviewReceipt:
        checkpoint = authority.checkpoint
        return HearingHumanReviewReceipt(
            run_id=checkpoint.run_id,
            case_id=checkpoint.case_id,
            hearing_session_id=checkpoint.hearing_session_id,
            current_evidence_pack_id=checkpoint.current_evidence_pack_id,
            current_evidence_pack_version=checkpoint.current_evidence_pack_version,
            judge_cycle=checkpoint.judge_cycle,
            reason=HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED,
            source_checkpoint_id=checkpoint.checkpoint_id,
            source_checkpoint_sha256=checkpoint.checkpoint_sha256,
            source_checkpoint_version=checkpoint.version,
            backlog_item_ref=ArtifactRef(
                kind=ArtifactKind.BACKLOG_ITEM,
                artifact_id=authority.item.item_id,
            ),
            manifest_id=checkpoint.manifest_id,
        )

    @staticmethod
    def _advance_role(
        authority: HearingBacklogRetryAuthority,
        result: HearingRoleCallResult,
    ) -> HearingTransition:
        role = authority.item.role
        assert role is not None
        if role == VlmRole.PROSECUTOR:
            checkpoint = complete_prosecutor(
                authority.session,
                authority.checkpoint,
                result.output,
                result.trace,
            )
            return HearingTransition(checkpoint=checkpoint)
        if role == VlmRole.DEFENDER:
            checkpoint = complete_defender(
                authority.session,
                authority.checkpoint,
                result.output,
                result.trace,
            )
            return HearingTransition(checkpoint=checkpoint)
        payload = result.output.payload
        acquisition: AcquisitionRequest | None = None
        if (
            isinstance(payload, JudgeModelPayload)
            and isinstance(payload.outcome, JudgeAcquisitionDecisionPayload)
            and authority.checkpoint.prior_acquisition_rounds
            < authority.session.acquisition_round_limit
        ):
            acquisition = build_acquisition_request(
                authority.session,
                authority.checkpoint,
                result.output,
            )
        return complete_judge(
            authority.session,
            authority.checkpoint,
            result.output,
            result.trace,
            acquisition_request=acquisition,
        )

    def _commit(
        self,
        authority: HearingBacklogRetryAuthority,
        outcome: HearingBacklogRetryOutcome,
        *,
        model_call_failure: HearingModelCallFailureIntent | None = None,
    ) -> HearingBacklogRetryCommit:
        # The provider boundary may already have durably appended the exact
        # request/response/usage/parse closure named by ``outcome``.  Reloading
        # and comparing the whole pre-call authority here would therefore
        # reject the expected aggregate-budget change.  The repository commit
        # is the atomic boundary: it must revalidate the active lease,
        # Case/audit CAS, checkpoint and every closure referenced by outcome.
        committed = self._repository.commit_hearing_backlog_retry(
            authority.item.run_id,
            authority.case.revision,
            authority.audit_head,
            outcome,
            model_call_failure,
        )
        if not isinstance(committed, HearingBacklogRetryCommit):
            raise ContractViolation("hearing backlog repository returned an invalid commit")
        if committed.receipt.outcome != outcome:
            raise ContractViolation("hearing backlog repository committed another outcome")
        if model_call_failure is not None and committed.failure_authority is None:
            raise ContractViolation("hearing backlog repository omitted provider failure authority")
        return committed

    def _require_current_authority(self, authority: HearingBacklogRetryAuthority) -> None:
        try:
            current = self._repository.load_hearing_backlog_retry_authority(
                authority.item.run_id,
                authority.lease,
            )
        except ConcurrentModification:
            raise
        if current != authority:
            raise ConcurrentModification("hearing backlog authority changed during retry")

    @staticmethod
    def _validate_plan(
        authority: HearingBacklogRetryAuthority,
        plan: HearingBacklogCallPlan,
    ) -> None:
        if (
            plan.context.session != authority.session
            or plan.context.cycle_scope != authority.cycle_scope
            or plan.context.run_manifest.manifest_id != authority.item.manifest_id
            or plan.context.backlog_lease != authority.lease
            or plan.context.budget_usage_before_primary.reserved_images
            != authority.reserved_images_before_primary
            or plan.context.budget_usage_before_primary.accounted_output_tokens
            != authority.accounted_output_tokens_before_primary
        ):
            raise ContractViolation("hearing backlog plan resets or changes frozen authority")
        unfinished = authority.unfinished_request
        if unfinished is None:
            if (
                authority.reserved_images_before_primary != authority.reserved_images
                or authority.accounted_output_tokens_before_primary
                != authority.accounted_output_tokens
            ):
                raise ContractViolation(
                    "fresh hearing retry generation changed its before-primary budget"
                )
        elif (
            authority.reserved_images_before_primary + len(authority.primary_template_request.media)
            != authority.reserved_images
        ):
            raise ContractViolation(
                "unfinished hearing retry changed its image reservation history"
            )
        if unfinished is not None:
            if unfinished.attempt_index == 0:
                if plan.repair is not None or plan.primary.request != unfinished:
                    raise ContractViolation(
                        "primary provider failure must resume its exact request"
                    )
                return
            primary_failure = authority.prior_primary_failure
            if (
                plan.repair is None
                or plan.repair.request != unfinished
                or primary_failure is None
                or plan.primary.request != primary_failure.request
            ):
                raise ContractViolation("repair provider failure must resume only its exact repair")
            return

        request = plan.primary.request
        context = request.backlog_retry_context
        template = authority.primary_template_request
        if (
            plan.repair is not None
            or request.attempt_index != 0
            or context is None
            or context.backlog_item_id != authority.item.item_id
            or context.retry_generation != authority.item.retry_generation
            or any(
                getattr(request, field) != getattr(template, field)
                for field in _REQUEST_SCOPE_FIELDS
            )
        ):
            raise ContractViolation(
                "strict parse proof must restart only this role's exact primary scope"
            )

    @staticmethod
    def _validate_result(
        authority: HearingBacklogRetryAuthority,
        plan: HearingBacklogCallPlan,
        result: HearingRoleCallResult,
    ) -> None:
        if not isinstance(result, HearingRoleCallResult):
            raise ContractViolation("hearing role executor returned an invalid result")
        calls = result.trace.calls
        if (
            result.prepared_primary != plan.primary
            or (plan.repair is not None and result.prepared_repair != plan.repair)
            or result.output.role != authority.item.role
            or calls[0].request != plan.primary.request
        ):
            raise ContractViolation("hearing role result changed the exact retry plan")
        if plan.repair is not None and (len(calls) != 2 or calls[1].request != plan.repair.request):
            raise ContractViolation("repair resume replayed or replaced an exact call")


__all__ = [
    "HearingBacklogCallPlan",
    "HearingBacklogRetryRecoveryCode",
    "HearingBacklogRetryRecoveryRequired",
    "HearingBacklogRetryService",
    "HearingBacklogRoleCallExecutor",
]
