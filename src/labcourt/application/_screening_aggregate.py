"""Authoritative aggregate reads, verification, and commits for M3 screening."""

from __future__ import annotations

from labcourt.application._screening_workflow_types import (
    ScreeningCoordinatorError,
    ScreeningCoordinatorErrorCode,
    ScreeningPipelineOutcome,
    _BacklogRequired,
    _CurrentAuthority,
)
from labcourt.application.screening_failures import classify_screening_failure
from labcourt.contracts.backlog import BacklogItem
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    CaseStatus,
    VlmRole,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.screening import ModelParseReceipt, ScreeningResult
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.exceptions import ConcurrentModification, ContractViolation, ManifestMismatch
from labcourt.ports.evidence_repository import CaseSnapshot, EvidenceRepository
from labcourt.ports.m3_semantics import M3SemanticVerifier
from labcourt.ports.procedural_review import ProceduralReviewVerifier
from labcourt.ports.prompts import PromptCatalog, RenderedPromptRegistrar
from labcourt.ports.screening_repository import (
    M3CaseCommit,
    ModelCallFailureIntent,
    ScreeningRepository,
)
from labcourt.ports.vlm import ModelResponseStore, VLMClient


class ScreeningAggregateWorkflow:
    """Provide the shared, transaction-aware aggregate operations for M3."""

    _config: AppConfig
    _evidence: EvidenceRepository
    _screening: ScreeningRepository
    _responses: ModelResponseStore
    _vlm: VLMClient
    _catalog: PromptCatalog
    _prompts: RenderedPromptRegistrar
    _review_verifier: ProceduralReviewVerifier
    _semantic_verifier: M3SemanticVerifier

    def _resume_screened(self, snapshot: CaseSnapshot) -> ScreeningPipelineOutcome:
        if not snapshot.case.screening_results:
            raise ScreeningCoordinatorError(ScreeningCoordinatorErrorCode.INVALID_CASE_STATE)
        screening = snapshot.case.screening_results[-1]
        history = self._screening.load_parse_history_for_output(
            snapshot.case.run_id,
            screening.parsed_output.parsed_output_id,
        )
        return self._finish_fast_verdict(
            snapshot,
            screening,
            history,
            cache_hit_count=0,
            recovered_response_count=0,
            repair_attempted=len(history) == 2,
        )

    def _finish_fast_verdict(
        self,
        snapshot: CaseSnapshot,
        screening: ScreeningResult,
        parse_history: tuple[ModelParseReceipt, ...],
        *,
        cache_hit_count: int,
        recovered_response_count: int,
        repair_attempted: bool,
    ) -> ScreeningPipelineOutcome:
        existing = self._existing_outcome(snapshot)
        if existing is not None:
            return existing
        try:
            self._verify_parse_history_raw(snapshot.case.run_id, parse_history)
        except Exception as error:
            reason = classify_screening_failure(error)
            if reason != BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE:
                raise
            return self._backlog_latest(
                snapshot.case.run_id,
                snapshot.case.case_id,
                BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
                VlmRole.SCREENING,
                response_ids=tuple(receipt.response_id for receipt in parse_history),
                resume_screened=False,
            )
        authority = self._current_authority(snapshot)
        if not authority.closure.passed:
            return self._backlog_latest(
                snapshot.case.run_id,
                snapshot.case.case_id,
                BacklogReasonCode.CURRENT_PACK_CHANGED,
                VlmRole.SCREENING,
            )
        response_refs = self._parse_history_response_refs(parse_history)
        verdict = self._semantic_verifier.rebuild_fast_verdict(
            screening,
            authority.pack,
            response_refs,
            len(snapshot.case.verdicts) + 1,
        )
        review = self._review_verifier.rebuild_review(
            verdict=verdict,
            evidence_pack=authority.pack,
            current_closure=authority.closure,
            parse_history=parse_history,
            review_version=len(snapshot.case.procedural_reviews) + 1,
        )
        try:
            # Verify exact raw bytes again immediately before the verdict/review
            # transaction, including resumed SCREENED cases.
            self._verify_parse_history_raw(snapshot.case.run_id, parse_history)
        except Exception as error:
            reason = classify_screening_failure(error)
            if reason != BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE:
                raise
            return self._backlog_latest(
                snapshot.case.run_id,
                snapshot.case.case_id,
                BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
                VlmRole.SCREENING,
                response_ids=tuple(receipt.response_id for receipt in parse_history),
                resume_screened=False,
            )
        try:
            committed = self._commit_verdict_with_head_rebase(
                authority,
                verdict,
                review,
            )
        except ConcurrentModification:
            return self._backlog_latest(
                snapshot.case.run_id,
                snapshot.case.case_id,
                BacklogReasonCode.CURRENT_PACK_CHANGED,
                VlmRole.SCREENING,
            )
        except Exception as error:
            reason = classify_screening_failure(error)
            if reason != BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE:
                raise
            return self._backlog_latest(
                snapshot.case.run_id,
                snapshot.case.case_id,
                reason,
                VlmRole.SCREENING,
                response_ids=tuple(receipt.response_id for receipt in parse_history),
                resume_screened=False,
            )
        if isinstance(committed, ScreeningPipelineOutcome):
            return committed
        return ScreeningPipelineOutcome(
            case=committed.case,
            screening_result=screening,
            verdict=verdict,
            procedural_review=review,
            cache_hit_count=cache_hit_count,
            recovered_response_count=recovered_response_count,
            repair_attempted=repair_attempted,
        )

    @staticmethod
    def _parse_history_response_refs(
        history: tuple[ModelParseReceipt, ...],
    ) -> tuple[ArtifactRef, ...]:
        return tuple(
            sorted(
                {
                    ArtifactRef(
                        kind=ArtifactKind.MODEL_RESPONSE,
                        artifact_id=receipt.response_id,
                    )
                    for receipt in history
                },
                key=lambda ref: ref.sort_key,
            )
        )

    def _verify_parse_history_raw(
        self,
        run_id: str,
        parse_history: tuple[ModelParseReceipt, ...],
    ) -> None:
        if not parse_history:
            raise ContractViolation("screening parse history must not be empty")
        for receipt in parse_history:
            response = self._screening.load_raw_response(run_id, receipt.response_id)
            if (
                response.run_id != run_id
                or response.request_id != receipt.request_id
                or response.request_sha256 != receipt.request_sha256
                or response.response_id != receipt.response_id
                or response.content_sha256 != receipt.response_content_sha256
                or response.case_id != receipt.case_id
                or response.evidence_pack_id != receipt.evidence_pack_id
                or response.evidence_pack_version != receipt.evidence_pack_version
                or response.attempt_index != receipt.attempt_index
                or response.manifest_id != receipt.manifest_id
            ):
                raise ContractViolation("parse history differs from its exact raw response receipt")
            self._responses.verify(run_id, response)
            self._responses.read_bytes(run_id, response, response.size_bytes)

    def _commit_screening_with_head_rebase(
        self,
        authority: _CurrentAuthority,
        screening: ScreeningResult,
    ) -> M3CaseCommit | ScreeningPipelineOutcome:
        try:
            return self._screening.commit_screening(
                authority.snapshot.case.run_id,
                authority.snapshot.revision,
                authority.audit_head,
                authority.closure,
                screening,
            )
        except ConcurrentModification:
            current = self._evidence.load_case(
                authority.snapshot.case.run_id,
                authority.snapshot.case.case_id,
            )
            existing = self._existing_outcome(current)
            if existing is not None:
                return existing
            if not self._same_case_input(authority.snapshot, current):
                raise
            rebound = self._current_authority(current)
            if not rebound.closure.passed:
                raise
            return self._screening.commit_screening(
                current.case.run_id,
                current.revision,
                rebound.audit_head,
                rebound.closure,
                screening,
            )

    def _commit_verdict_with_head_rebase(
        self,
        authority: _CurrentAuthority,
        verdict: Verdict,
        review: ProceduralReview,
    ) -> M3CaseCommit | ScreeningPipelineOutcome:
        try:
            return self._screening.commit_verdict_review(
                authority.snapshot.case.run_id,
                authority.snapshot.revision,
                authority.audit_head,
                authority.closure,
                verdict,
                review,
            )
        except ConcurrentModification:
            current = self._evidence.load_case(
                authority.snapshot.case.run_id,
                authority.snapshot.case.case_id,
            )
            existing = self._existing_outcome(current)
            if existing is not None:
                return existing
            if not self._same_case_input(authority.snapshot, current):
                raise
            rebound = self._current_authority(current)
            if not rebound.closure.passed:
                raise
            return self._screening.commit_verdict_review(
                current.case.run_id,
                current.revision,
                rebound.audit_head,
                rebound.closure,
                verdict,
                review,
            )

    def _backlog_latest(
        self,
        run_id: str,
        case_id: str,
        reason: BacklogReasonCode,
        role: VlmRole,
        *,
        response_ids: tuple[str, ...] = (),
        resume_screened: bool = True,
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> ScreeningPipelineOutcome:
        for attempt in range(2):
            snapshot = self._evidence.load_case(run_id, case_id)
            existing = self._existing_outcome(snapshot)
            if existing is not None:
                return existing
            authority = self._current_authority(snapshot)
            if (
                resume_screened
                and snapshot.case.status == CaseStatus.SCREENED
                and authority.closure.passed
            ):
                # Another worker may have completed screening while this worker
                # was preparing/calling the provider.  Preserve that successful
                # progress instead of replacing it with a stale failure backlog.
                return self._resume_screened(snapshot)
            effective_reason = (
                reason if authority.closure.passed else BacklogReasonCode.CURRENT_PACK_CHANGED
            )
            effective_model_call_failure = (
                model_call_failure if effective_reason == reason else None
            )
            item = BacklogItem(
                run_id=run_id,
                case_id=case_id,
                stage=BacklogStage.SCREENING,
                role=role,
                reason_code=effective_reason,
                stage_input_ref=ArtifactRef(
                    kind=ArtifactKind.EVIDENCE_PACK,
                    artifact_id=authority.pack.pack_id,
                ),
                stage_input_sha256=sha256_hex(authority.pack.model_dump(mode="json")),
                max_attempts=self._config.screening.backlog_max_attempts,
                retry_generation=(
                    1 if effective_reason == BacklogReasonCode.MODEL_OUTPUT_INVALID else 0
                ),
                manifest_id=snapshot.case.manifest_id,
            )
            try:
                commit = self._screening.commit_backlog(
                    run_id,
                    snapshot.revision,
                    authority.audit_head,
                    authority.closure,
                    item,
                    response_ids,
                    effective_model_call_failure,
                )
                return ScreeningPipelineOutcome(case=commit.case, backlog_item=item)
            except ConcurrentModification:
                if attempt == 1:
                    raise
        raise AssertionError("bounded backlog retry did not terminate")

    def _current_authority(self, snapshot: CaseSnapshot) -> _CurrentAuthority:
        case = snapshot.case
        if not case.evidence_packs or not case.evidence_packs[-1].complete:
            raise ScreeningCoordinatorError(ScreeningCoordinatorErrorCode.CURRENT_PACK_MISSING)
        embedded = case.evidence_packs[-1]
        pack = self._evidence.load_pack(case.run_id, embedded.pack_id)
        if pack != embedded:
            raise ScreeningCoordinatorError(
                ScreeningCoordinatorErrorCode.CURRENT_PACK_BINDING_INVALID
            )
        closure = self._evidence.verify_current_pack(case.run_id, pack.pack_id)
        self._validate_closure(pack, closure)
        head = self._evidence.get_audit_head(case.run_id)
        if head.manifest_id != case.manifest_id:
            raise ManifestMismatch("audit head and case manifest do not match")
        return _CurrentAuthority(snapshot, pack, closure, head)

    @staticmethod
    def _validate_closure(pack: EvidencePack, closure: ClosureReport) -> None:
        root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
        expected_by_key = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
        expected = tuple(expected_by_key[key] for key in sorted(expected_by_key))
        if (
            closure.run_id != pack.run_id
            or closure.root_ref != root
            or closure.manifest_id != pack.manifest_id
            or closure.input_sha256 != pack.closure_input_sha256
            or closure.checked_refs != expected
        ):
            raise ScreeningCoordinatorError(
                ScreeningCoordinatorErrorCode.CURRENT_PACK_BINDING_INVALID
            )

    def _require_unchanged_case_input(self, authority: _CurrentAuthority) -> None:
        current = self._evidence.load_case(
            authority.snapshot.case.run_id,
            authority.snapshot.case.case_id,
        )
        if not self._same_case_input(authority.snapshot, current):
            raise _BacklogRequired(
                BacklogReasonCode.CURRENT_PACK_CHANGED,
                VlmRole.SCREENING,
            )

    @staticmethod
    def _same_case_input(first: CaseSnapshot, second: CaseSnapshot) -> bool:
        if first.revision != second.revision:
            return False
        if not first.case.evidence_packs or not second.case.evidence_packs:
            return False
        first_pack = first.case.evidence_packs[-1]
        second_pack = second.case.evidence_packs[-1]
        return first.case.manifest_id == second.case.manifest_id and (
            first_pack.pack_id,
            first_pack.version,
        ) == (second_pack.pack_id, second_pack.version)

    def _existing_outcome(
        self,
        snapshot: CaseSnapshot,
    ) -> ScreeningPipelineOutcome | None:
        case = snapshot.case
        if case.status == CaseStatus.BACKLOGGED:
            if case.current_backlog_item_id is None:
                raise ScreeningCoordinatorError(ScreeningCoordinatorErrorCode.INVALID_CASE_STATE)
            return ScreeningPipelineOutcome(
                case=snapshot,
                screening_result=(case.screening_results[-1] if case.screening_results else None),
                backlog_item=self._screening.load_backlog_item(
                    case.run_id,
                    case.current_backlog_item_id,
                ),
            )
        if case.status == CaseStatus.ESCALATED:
            return ScreeningPipelineOutcome(
                case=snapshot,
                screening_result=case.screening_results[-1],
            )
        if case.status in {
            CaseStatus.READY_FOR_ALERT_POLICY,
            CaseStatus.REWORK_REQUIRED,
        }:
            return ScreeningPipelineOutcome(
                case=snapshot,
                screening_result=case.screening_results[-1],
                verdict=case.verdicts[-1],
                procedural_review=case.procedural_reviews[-1],
            )
        return None

    @staticmethod
    def _validate_case_scope(
        snapshot: CaseSnapshot,
        run_id: str,
        case_id: str,
    ) -> None:
        if snapshot.case.run_id != run_id or snapshot.case.case_id != case_id:
            raise ScreeningCoordinatorError(ScreeningCoordinatorErrorCode.CASE_SCOPE_MISMATCH)
