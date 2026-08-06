"""Exact-lease backlog retry workflow for M3 screening."""

from __future__ import annotations

from labcourt.application._screening_model_workflow import ScreeningModelWorkflow
from labcourt.application._screening_workflow_types import (
    _BacklogRequired,
    _CurrentAuthority,
    _RetryPublicationRecoveryRequired,
)
from labcourt.application.screening_failures import classify_screening_failure
from labcourt.application.screening_request import prepare_screening_request
from labcourt.contracts.backlog import (
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogRetryContext,
    BacklogRetryFailure,
    BacklogRetrySuccess,
    BacklogStrictParseFailureProof,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    ScreeningDecision,
    VlmRole,
)
from labcourt.contracts.screening import ScreeningResult
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.exceptions import ConcurrentModification, ContractViolation, ManifestMismatch
from labcourt.ports.screening_repository import (
    M3BacklogRetryCommit,
    ModelCallFailureIntent,
)


class ScreeningBacklogWorkflow(ScreeningModelWorkflow):
    """Retry one exact SCREENING lease without bypassing aggregate authority."""

    def retry_leased_item(self, leased_item: BacklogItem) -> M3BacklogRetryCommit:
        """Retry one exact leased SCREENING item through an atomic queue outcome."""

        if not isinstance(leased_item, BacklogItem):
            raise TypeError("leased_item must be a BacklogItem")
        if leased_item.status != BacklogStatus.LEASED:
            raise ContractViolation("backlog retry requires an active leased item")
        if leased_item.stage != BacklogStage.SCREENING:
            raise ContractViolation("M3 backlog worker only accepts SCREENING work")

        authority = self._retry_authority(leased_item)
        if not authority.closure.passed:
            return self._commit_retry_failure(
                leased_item,
                BacklogReasonCode.CURRENT_PACK_CHANGED,
            )
        if authority.snapshot.case.screening_results:
            return self._retry_existing_screening(leased_item, authority)

        manifest = self._evidence.load_run_manifest(leased_item.run_id)
        response_ids: tuple[str, ...] = ()
        try:
            if manifest.manifest_id != leased_item.manifest_id:
                raise ManifestMismatch("backlog item and authoritative run manifest do not match")
            retry_context = BacklogRetryContext(
                backlog_item_id=leased_item.item_id,
                retry_generation=leased_item.retry_generation,
            )
            prepared = prepare_screening_request(
                authority.pack,
                self._config,
                manifest,
                self._catalog,
                backlog_retry_context=retry_context,
            )
            self._prompts.register(prepared.rendered_prompt)

            # Recheck the exact lease and current pack immediately before entering
            # request-level singleflight.  A stale worker must never start new work.
            authority = self._retry_authority(leased_item)
            if not authority.closure.passed:
                raise _BacklogRequired(
                    BacklogReasonCode.CURRENT_PACK_CHANGED,
                    VlmRole.SCREENING,
                )
            parsed = self._parse_model_stage(
                prepared.request,
                manifest=manifest,
                catalog=self._catalog,
                backlog_lease=self._backlog_lease_identity(leased_item),
            )
            response_ids = tuple(receipt.response_id for receipt in parsed.history)

            authority = self._retry_authority(leased_item)
            if not authority.closure.passed:
                raise _BacklogRequired(
                    BacklogReasonCode.CURRENT_PACK_CHANGED,
                    VlmRole.SCREENING,
                    response_ids,
                )
            screening = self._semantic_verifier.rebuild_screening(
                parsed.output,
                authority.pack,
                len(authority.snapshot.case.screening_results) + 1,
            )
            self._verify_parse_history_raw(leased_item.run_id, parsed.history)
            response_refs = self._parse_history_response_refs(parsed.history)
            lease = self._backlog_lease_identity(leased_item)
            if screening.decision == ScreeningDecision.ESCALATE:
                success = BacklogRetrySuccess(
                    lease=lease,
                    completion_case_status=CaseStatus.ESCALATED,
                    completion_ref=ArtifactRef(
                        kind=ArtifactKind.SCREENING_RESULT,
                        artifact_id=screening.screening_id,
                    ),
                    response_refs=response_refs,
                    manifest_id=leased_item.manifest_id,
                )
                return self._commit_retry_screening_success(
                    leased_item,
                    authority,
                    success,
                    screening,
                )

            verdict = self._semantic_verifier.rebuild_fast_verdict(
                screening,
                authority.pack,
                response_refs,
                len(authority.snapshot.case.verdicts) + 1,
            )
            review = self._review_verifier.rebuild_review(
                verdict=verdict,
                evidence_pack=authority.pack,
                current_closure=authority.closure,
                parse_history=parsed.history,
                review_version=len(authority.snapshot.case.procedural_reviews) + 1,
            )
            self._verify_parse_history_raw(leased_item.run_id, parsed.history)
            target = (
                CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
            )
            success = BacklogRetrySuccess(
                lease=lease,
                completion_case_status=target,
                completion_ref=ArtifactRef(
                    kind=ArtifactKind.PROCEDURAL_REVIEW,
                    artifact_id=review.review_id,
                ),
                response_refs=response_refs,
                manifest_id=leased_item.manifest_id,
            )
            return self._commit_retry_verdict_success(
                leased_item,
                authority,
                success,
                verdict,
                review,
                screening=screening,
            )
        except _RetryPublicationRecoveryRequired as recovery:
            # Preserve the active claim/journal for startup recovery.  Do not
            # create a failure receipt before a durable response reference exists.
            raise recovery.original from recovery
        except _BacklogRequired as failure:
            return self._commit_retry_failure(
                leased_item,
                failure.reason,
                response_ids=failure.response_ids,
                strict_parse_failure=failure.strict_parse_failure,
                model_call_failure=failure.model_call_failure,
            )
        except ConcurrentModification:
            raise
        except Exception as error:
            reason = classify_screening_failure(error)
            if reason is None:
                raise
            return self._commit_retry_failure(
                leased_item,
                reason,
                response_ids=response_ids,
            )

    def _retry_existing_screening(
        self,
        leased_item: BacklogItem,
        authority: _CurrentAuthority,
    ) -> M3BacklogRetryCommit:
        """Resume the verdict/review boundary without another model request."""

        response_ids: tuple[str, ...] = ()
        try:
            if (
                leased_item.reason_code != BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
                or not authority.snapshot.case.screening_results
            ):
                raise ContractViolation(
                    "screening-resume retry requires raw-integrity screening authority"
                )
            screening = authority.snapshot.case.screening_results[-1]
            if screening.decision == ScreeningDecision.ESCALATE:
                raise ContractViolation(
                    "an escalating screening cannot resume the fast-verdict boundary"
                )
            history = self._screening.load_parse_history_for_output(
                leased_item.run_id,
                screening.parsed_output.parsed_output_id,
            )
            response_ids = tuple(receipt.response_id for receipt in history)
            self._verify_parse_history_raw(leased_item.run_id, history)
            response_refs = self._parse_history_response_refs(history)
            verdict = self._semantic_verifier.rebuild_fast_verdict(
                screening,
                authority.pack,
                response_refs,
                len(authority.snapshot.case.verdicts) + 1,
            )
            review = self._review_verifier.rebuild_review(
                verdict=verdict,
                evidence_pack=authority.pack,
                current_closure=authority.closure,
                parse_history=history,
                review_version=len(authority.snapshot.case.procedural_reviews) + 1,
            )
            self._verify_parse_history_raw(leased_item.run_id, history)
            target = (
                CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
            )
            success = BacklogRetrySuccess(
                lease=self._backlog_lease_identity(leased_item),
                completion_case_status=target,
                completion_ref=ArtifactRef(
                    kind=ArtifactKind.PROCEDURAL_REVIEW,
                    artifact_id=review.review_id,
                ),
                response_refs=response_refs,
                manifest_id=leased_item.manifest_id,
            )
            return self._commit_retry_verdict_success(
                leased_item,
                authority,
                success,
                verdict,
                review,
                screening=None,
            )
        except _BacklogRequired as failure:
            return self._commit_retry_failure(
                leased_item,
                failure.reason,
                response_ids=failure.response_ids,
                strict_parse_failure=failure.strict_parse_failure,
                model_call_failure=failure.model_call_failure,
            )
        except ConcurrentModification:
            raise
        except Exception as error:
            reason = classify_screening_failure(error)
            if reason is None:
                raise
            return self._commit_retry_failure(
                leased_item,
                reason,
                response_ids=response_ids,
            )

    def _retry_authority(self, leased_item: BacklogItem) -> _CurrentAuthority:
        # Retry transitions are M3 aggregate state.  Read their authoritative
        # snapshot through the M3 repository rather than an M2-only projection.
        snapshot = self._screening.load_case(leased_item.run_id, leased_item.case_id)
        self._validate_case_scope(snapshot, leased_item.run_id, leased_item.case_id)
        if (
            snapshot.case.status != CaseStatus.BACKLOGGED
            or snapshot.case.current_backlog_item_id != leased_item.item_id
        ):
            raise ConcurrentModification("leased backlog item is no longer the Case boundary")
        current = self._screening.load_backlog_item(
            leased_item.run_id,
            leased_item.item_id,
        )
        if current != leased_item:
            raise ConcurrentModification("backlog lease identity changed during retry")
        authority = self._current_authority(snapshot)
        if (
            leased_item.manifest_id != snapshot.case.manifest_id
            or leased_item.stage_input_ref
            != ArtifactRef(
                kind=ArtifactKind.EVIDENCE_PACK,
                artifact_id=authority.pack.pack_id,
            )
            or leased_item.stage_input_sha256 != sha256_hex(authority.pack.model_dump(mode="json"))
        ):
            raise ConcurrentModification("backlog stage input is no longer authoritative")
        return authority

    @staticmethod
    def _backlog_lease_identity(leased_item: BacklogItem) -> BacklogLeaseIdentity:
        if leased_item.lease_id is None:
            raise ContractViolation("leased backlog item is missing its lease identity")
        return BacklogLeaseIdentity(
            run_id=leased_item.run_id,
            item_id=leased_item.item_id,
            lease_id=leased_item.lease_id,
            attempt_count=leased_item.attempt_count,
            retry_generation=leased_item.retry_generation,
        )

    def _commit_retry_screening_success(
        self,
        leased_item: BacklogItem,
        authority: _CurrentAuthority,
        success: BacklogRetrySuccess,
        screening: ScreeningResult,
    ) -> M3BacklogRetryCommit:
        for attempt in range(2):
            try:
                return self._screening.commit_backlog_screening_success(
                    leased_item.run_id,
                    authority.snapshot.revision,
                    authority.audit_head,
                    authority.closure,
                    success,
                    screening,
                )
            except ConcurrentModification:
                if attempt == 1:
                    raise
                authority = self._retry_authority(leased_item)
                if not authority.closure.passed:
                    raise _BacklogRequired(
                        BacklogReasonCode.CURRENT_PACK_CHANGED,
                        VlmRole.SCREENING,
                        tuple(ref.artifact_id for ref in success.response_refs),
                    ) from None
        raise AssertionError("bounded backlog screening commit did not terminate")

    def _commit_retry_verdict_success(
        self,
        leased_item: BacklogItem,
        authority: _CurrentAuthority,
        success: BacklogRetrySuccess,
        verdict: Verdict,
        review: ProceduralReview,
        *,
        screening: ScreeningResult | None,
    ) -> M3BacklogRetryCommit:
        for attempt in range(2):
            try:
                return self._screening.commit_backlog_verdict_review_success(
                    leased_item.run_id,
                    authority.snapshot.revision,
                    authority.audit_head,
                    authority.closure,
                    success,
                    verdict,
                    review,
                    screening,
                )
            except ConcurrentModification:
                if attempt == 1:
                    raise
                authority = self._retry_authority(leased_item)
                if not authority.closure.passed:
                    raise _BacklogRequired(
                        BacklogReasonCode.CURRENT_PACK_CHANGED,
                        VlmRole.SCREENING,
                        tuple(ref.artifact_id for ref in success.response_refs),
                    ) from None
        raise AssertionError("bounded backlog verdict commit did not terminate")

    def _commit_retry_failure(
        self,
        leased_item: BacklogItem,
        reason: BacklogReasonCode,
        *,
        response_ids: tuple[str, ...] = (),
        strict_parse_failure: BacklogStrictParseFailureProof | None = None,
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> M3BacklogRetryCommit:
        if reason == BacklogReasonCode.MODEL_OUTPUT_INVALID and strict_parse_failure is None:
            # Only two persisted strict-parser failures authorize a generation
            # advance.  Other controlled semantic defects retain this generation.
            reason = BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
        for attempt in range(2):
            authority = self._retry_authority(leased_item)
            effective_reason = (
                reason if authority.closure.passed else BacklogReasonCode.CURRENT_PACK_CHANGED
            )
            proof = (
                strict_parse_failure
                if effective_reason == BacklogReasonCode.MODEL_OUTPUT_INVALID
                else None
            )
            effective_model_call_failure = (
                model_call_failure if effective_reason == reason else None
            )
            refs = tuple(
                sorted(
                    {
                        ArtifactRef(
                            kind=ArtifactKind.MODEL_RESPONSE,
                            artifact_id=response_id,
                        )
                        for response_id in response_ids
                    },
                    key=lambda ref: ref.sort_key,
                )
            )
            failure = BacklogRetryFailure(
                lease=self._backlog_lease_identity(leased_item),
                reason_code=effective_reason,
                next_status=(
                    BacklogStatus.EXHAUSTED
                    if leased_item.attempt_count == leased_item.max_attempts
                    else BacklogStatus.PENDING
                ),
                response_refs=refs,
                strict_parse_failure=proof,
                manifest_id=leased_item.manifest_id,
            )
            try:
                return self._screening.commit_backlog_retry_failure(
                    leased_item.run_id,
                    authority.snapshot.revision,
                    authority.audit_head,
                    authority.closure,
                    failure,
                    effective_model_call_failure,
                )
            except ConcurrentModification:
                if attempt == 1:
                    raise
        raise AssertionError("bounded backlog failure commit did not terminate")
