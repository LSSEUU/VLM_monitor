"""Public bounded, crash-resumable M4 hearing coordinator."""

from __future__ import annotations

from typing import NoReturn, cast

from labcourt.application._hearing_workflow_types import (
    HearingCoordinatorError,
    HearingCoordinatorErrorCode,
    HearingPipelineOutcome,
)
from labcourt.application.hearing_acquisition import (
    HearingAcquisitionContext,
    HearingAcquisitionError,
    HearingAcquisitionFailureCode,
    HearingAcquisitionService,
)
from labcourt.application.hearing_finalization import (
    HearingReviewVerifier,
    complete_and_review_hearing_round,
)
from labcourt.application.hearing_precedent_outcomes import (
    AppendOnlyHearingPrecedentOutcomeCommitter,
)
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_rework import (
    prepare_hearing_rework,
)
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.application.hearing_role_orchestrator import (
    advance_pending_hearing_role,
)
from labcourt.application.hearing_session import prepare_hearing_session
from labcourt.application.hearing_situation import (
    HearingSituationBuildError,
    build_hearing_situation_text,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingHumanReviewReason,
    HearingSession,
    ToolExecutionReceipt,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.domain.hearing_fsm import (
    complete_acquisition,
    complete_precedent_retrieval,
    start_rework_cycle,
    transfer_to_human_review,
)
from labcourt.domain.hearing_verdict_builder import (
    HearingReviewClosure,
    build_hearing_verdict,
)
from labcourt.exceptions import ConcurrentModification, EvidenceMissing
from labcourt.ports.evidence_repository import (
    AuditHead,
    CaseSnapshot,
    EvidenceRepository,
)
from labcourt.ports.hearing_backlog import HearingBacklogRepository
from labcourt.ports.hearing_precedents import (
    HearingPrecedentRetrievalOutcomeCommitter,
)
from labcourt.ports.hearing_repository import HearingRepository
from labcourt.ports.prompts import PromptCatalog

_MAX_DRIVER_STEPS = 64
_ROLE_PHASES = {
    HearingCheckpointPhase.PROSECUTOR_PENDING,
    HearingCheckpointPhase.DEFENDER_PENDING,
    HearingCheckpointPhase.JUDGE_PENDING,
}


class HearingCoordinator:
    """Drive one Case to ready, backlog, or typed human review."""

    def __init__(
        self,
        *,
        config: AppConfig,
        evidence_repository: EvidenceRepository,
        hearing_repository: HearingRepository,
        precedent_retrieval: HearingPrecedentRetrievalService,
        role_calls: HearingRoleCallService,
        acquisition: HearingAcquisitionService,
        prompt_catalog: PromptCatalog,
        review_verifier: HearingReviewVerifier,
        backlog_repository: HearingBacklogRepository | None = None,
        precedent_outcome_committer: HearingPrecedentRetrievalOutcomeCommitter | None = None,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        dependencies = (
            (evidence_repository, "load_case", "evidence_repository"),
            (evidence_repository, "load_run_manifest", "evidence_repository"),
            (evidence_repository, "get_audit_head", "evidence_repository"),
            (evidence_repository, "verify_current_pack", "evidence_repository"),
            (hearing_repository, "begin_hearing_case", "hearing_repository"),
            (hearing_repository, "load_active_hearing", "hearing_repository"),
            (
                hearing_repository,
                "load_latest_hearing_checkpoint",
                "hearing_repository",
            ),
            (precedent_retrieval, "retrieve", "precedent_retrieval"),
            (role_calls, "execute", "role_calls"),
            (acquisition, "execute", "acquisition"),
            (prompt_catalog, "render", "prompt_catalog"),
            (review_verifier, "rebuild_review", "review_verifier"),
        )
        for dependency, method, name in dependencies:
            if not callable(getattr(dependency, method, None)):
                raise TypeError(f"{name} does not implement {method}")
        effective_backlog = backlog_repository
        if effective_backlog is None:
            effective_backlog = cast(HearingBacklogRepository, hearing_repository)
        if not callable(getattr(effective_backlog, "commit_hearing_backlog", None)):
            raise TypeError("backlog_repository does not implement commit_hearing_backlog")
        effective_precedent_committer = precedent_outcome_committer
        if effective_precedent_committer is None:
            effective_precedent_committer = AppendOnlyHearingPrecedentOutcomeCommitter(
                hearing_repository
            )
        if not callable(getattr(effective_precedent_committer, "commit", None)):
            raise TypeError("precedent_outcome_committer does not implement commit")
        self._config = config
        self._evidence = evidence_repository
        self._hearings = hearing_repository
        self._precedents = precedent_retrieval
        self._role_calls = role_calls
        self._acquisition = acquisition
        self._catalog = prompt_catalog
        self._review = review_verifier
        self._backlog = effective_backlog
        self._precedent_outcomes = effective_precedent_committer

    def process_case(self, run_id: str, case_id: str) -> HearingPipelineOutcome:
        """Process or resume one Case through the complete bounded M4 slice."""

        safe_case_id = case_id if isinstance(case_id, str) else "invalid-case"
        if not isinstance(run_id, str) or not run_id or not isinstance(case_id, str) or not case_id:
            raise HearingCoordinatorError(
                HearingCoordinatorErrorCode.INVALID_ARGUMENT,
                case_id=safe_case_id,
            )
        cache_hits = 0
        recovered = 0
        for _ in range(_MAX_DRIVER_STEPS):
            snapshot = self._evidence.load_case(run_id, case_id)
            self._validate_case(snapshot, run_id, case_id)
            terminal = self._terminal_outcome(
                snapshot,
                cache_hits=cache_hits,
                recovered=recovered,
            )
            if terminal is not None:
                return terminal

            session = self._hearings.load_active_hearing(run_id, case_id)
            if snapshot.case.status == CaseStatus.BACKLOGGED:
                if session is None:
                    self._fail(case_id, HearingCoordinatorErrorCode.INVALID_CASE_STATE)
                checkpoint = self._hearings.load_latest_hearing_checkpoint(
                    run_id,
                    session.session_id,
                )
                return HearingPipelineOutcome(
                    case=snapshot,
                    session=session,
                    checkpoint=checkpoint,
                    backlog_item_id=snapshot.case.current_backlog_item_id,
                    cache_hit_count=cache_hits,
                    recovered_response_count=recovered,
                )

            manifest = self._evidence.load_run_manifest(run_id)
            if (
                manifest.manifest_id != snapshot.case.manifest_id
                or manifest.config_sha256 != self._config.config_sha256
            ):
                self._fail(case_id, HearingCoordinatorErrorCode.AUTHORITY_MISMATCH)
            if session is None:
                if snapshot.case.status not in {
                    CaseStatus.ESCALATED,
                    CaseStatus.REWORK_REQUIRED,
                }:
                    self._fail(case_id, HearingCoordinatorErrorCode.INVALID_CASE_STATE)
                prepared = prepare_hearing_session(
                    snapshot,
                    config=self._config,
                    run_manifest=manifest,
                    catalog=self._catalog,
                )
                try:
                    self._hearings.begin_hearing_case(
                        run_id,
                        snapshot.revision,
                        self._evidence.get_audit_head(run_id),
                        prepared.session,
                        prepared.cycle_scope,
                        prepared.checkpoint,
                    )
                except ConcurrentModification:
                    continue
                continue

            checkpoint = self._hearings.load_latest_hearing_checkpoint(
                run_id,
                session.session_id,
            )
            self._validate_active(snapshot, session, checkpoint)
            head = self._evidence.get_audit_head(run_id)
            try:
                if checkpoint.phase == HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING:
                    disposition = self._advance_precedent(
                        snapshot,
                        head,
                        session,
                        checkpoint,
                        manifest,
                    )
                    if disposition is not None:
                        return self._outcome(
                            disposition,
                            session,
                            cache_hits,
                            recovered,
                        )
                    continue
                if checkpoint.phase in _ROLE_PHASES:
                    evidence = self._hearings.load_hearing_evidence_authority(
                        run_id,
                        session.session_id,
                        checkpoint.cycle_evidence_pack_id,
                    )
                    advanced = advance_pending_hearing_role(
                        session=session,
                        checkpoint=checkpoint,
                        source_case=snapshot,
                        audit_head=head,
                        evidence=evidence,
                        run_manifest=manifest,
                        config=self._config,
                        catalog=self._catalog,
                        repository=self._hearings,
                        backlog_repository=self._backlog,
                        role_calls=self._role_calls,
                    )
                    cache_hits += advanced.cache_hit_count
                    recovered += advanced.recovered_response_count
                    if advanced.case is not None:
                        return HearingPipelineOutcome(
                            case=advanced.case,
                            session=session,
                            checkpoint=advanced.checkpoint,
                            backlog_item_id=advanced.backlog_item_id,
                            cache_hit_count=cache_hits,
                            recovered_response_count=recovered,
                        )
                    continue
                if checkpoint.phase == HearingCheckpointPhase.ACQUISITION_PENDING:
                    disposition = self._advance_acquisition(
                        snapshot,
                        head,
                        session,
                        checkpoint,
                        manifest,
                    )
                    if disposition is not None:
                        return self._outcome(
                            disposition,
                            session,
                            cache_hits,
                            recovered,
                        )
                    continue
                if checkpoint.phase == HearingCheckpointPhase.ROUND_COMPLETE:
                    advanced_round = complete_and_review_hearing_round(
                        session=session,
                        checkpoint=checkpoint,
                        source_case=snapshot,
                        audit_head=head,
                        repository=self._hearings,
                        evidence_repository=self._evidence,
                        review_verifier=self._review,
                    )
                    if advanced_round.case is None:
                        continue
                    if advanced_round.case.case.status == CaseStatus.REWORK_REQUIRED:
                        continue
                    return HearingPipelineOutcome(
                        case=advanced_round.case,
                        session=session,
                        checkpoint=advanced_round.checkpoint,
                        record=advanced_round.record,
                        verdict=advanced_round.verdict,
                        review=advanced_round.review,
                        cache_hit_count=cache_hits,
                        recovered_response_count=recovered,
                    )
                if checkpoint.phase == HearingCheckpointPhase.REWORK_READY:
                    disposition = self._advance_rework(
                        snapshot,
                        head,
                        session,
                        checkpoint,
                    )
                    if disposition is not None:
                        return self._outcome(
                            disposition,
                            session,
                            cache_hits,
                            recovered,
                        )
                    continue
                self._fail(case_id, HearingCoordinatorErrorCode.INVALID_CASE_STATE)
            except ConcurrentModification:
                continue
        self._fail(case_id, HearingCoordinatorErrorCode.STEP_LIMIT_EXCEEDED)

    def _advance_precedent(
        self,
        snapshot: CaseSnapshot,
        head: AuditHead,
        session: HearingSession,
        checkpoint: HearingCheckpoint,
        manifest: RunManifest,
    ) -> tuple[CaseSnapshot, HearingCheckpoint] | None:
        try:
            evidence = self._hearings.load_hearing_evidence_authority(
                checkpoint.run_id,
                session.session_id,
                checkpoint.cycle_evidence_pack_id,
            )
            situation = build_hearing_situation_text(evidence.pack)
        except (EvidenceMissing, HearingSituationBuildError):
            return self._commit_human(
                snapshot,
                head,
                session,
                checkpoint,
                HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
            )
        cycle = self._hearings.load_hearing_cycle(
            checkpoint.run_id,
            checkpoint.cycle_scope_id,
        )
        outcome = self._precedents.retrieve(
            session=session,
            cycle_scope=cycle,
            evidence_pack=evidence.pack,
            run_manifest=manifest,
            config=self._config,
            situation_text=situation,
        )
        canonical_receipt = self._precedent_outcomes.commit(outcome)
        successor = complete_precedent_retrieval(
            session,
            checkpoint,
            canonical_receipt,
        )
        self._hearings.append_hearing_checkpoint(
            checkpoint.run_id,
            successor,
        )
        return None

    def _advance_acquisition(
        self,
        snapshot: CaseSnapshot,
        head: AuditHead,
        session: HearingSession,
        checkpoint: HearingCheckpoint,
        manifest: RunManifest,
    ) -> tuple[CaseSnapshot, HearingCheckpoint] | None:
        request = checkpoint.acquisition_request
        if request is None or not snapshot.case.evidence_packs:
            self._fail(checkpoint.case_id, HearingCoordinatorErrorCode.AUTHORITY_MISMATCH)
        receipt = self._published_acquisition_receipt(snapshot, session, checkpoint)
        if receipt is None:
            try:
                evidence = self._hearings.load_hearing_evidence_authority(
                    checkpoint.run_id,
                    session.session_id,
                    request.current_evidence_pack_id,
                )
                result = self._acquisition.execute(
                    HearingAcquisitionContext(
                        case=snapshot,
                        audit_head=head,
                        request=request,
                        evidence=evidence,
                        run_manifest=manifest,
                    )
                )
                receipt = result.publication.receipt
            except HearingAcquisitionError as exc:
                refreshed = self._evidence.load_case(
                    checkpoint.run_id,
                    checkpoint.case_id,
                )
                receipt = self._published_acquisition_receipt(
                    refreshed,
                    session,
                    checkpoint,
                )
                if receipt is None:
                    if exc.reason_code in {
                        HearingAcquisitionFailureCode.EXECUTION_IN_PROGRESS,
                        HearingAcquisitionFailureCode.PERSISTENCE_CONFLICT,
                    }:
                        self._fail(
                            checkpoint.case_id,
                            HearingCoordinatorErrorCode.PERSISTENCE_CONFLICT,
                        )
                    return self._commit_human(
                        refreshed,
                        self._evidence.get_audit_head(checkpoint.run_id),
                        session,
                        checkpoint,
                        HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE,
                    )
        successor = complete_acquisition(session, checkpoint, receipt)
        self._hearings.append_hearing_checkpoint(checkpoint.run_id, successor)
        return None

    def _published_acquisition_receipt(
        self,
        snapshot: CaseSnapshot,
        session: HearingSession,
        checkpoint: HearingCheckpoint,
    ) -> ToolExecutionReceipt | None:
        request = checkpoint.acquisition_request
        if request is None or not snapshot.case.evidence_packs:
            return None
        current = snapshot.case.evidence_packs[-1]
        predecessor = (
            request.current_evidence_pack_id,
            request.current_evidence_pack_version,
        )
        if (current.pack_id, current.version) == predecessor:
            return None
        if current.version != request.current_evidence_pack_version + 1:
            return None
        try:
            authority = self._hearings.load_hearing_evidence_authority(
                checkpoint.run_id,
                session.session_id,
                current.pack_id,
            )
        except EvidenceMissing:
            return None
        matches = tuple(
            item
            for item in authority.receipts
            if item.request == request
            and item.resulting_evidence_pack_id == current.pack_id
            and item.resulting_evidence_pack_version == current.version
        )
        return matches[0] if len(matches) == 1 else None

    def _advance_rework(
        self,
        snapshot: CaseSnapshot,
        head: AuditHead,
        session: HearingSession,
        checkpoint: HearingCheckpoint,
    ) -> tuple[CaseSnapshot, HearingCheckpoint] | None:
        case = snapshot.case
        record = self._hearings.load_hearing_record(
            checkpoint.run_id,
            session.session_id,
        )
        if (
            record is None
            or not case.evidence_packs
            or not case.verdicts
            or not case.procedural_reviews
        ):
            self._fail(checkpoint.case_id, HearingCoordinatorErrorCode.AUTHORITY_MISMATCH)
        verdict = case.verdicts[-1]
        review = case.procedural_reviews[-1]
        built = build_hearing_verdict(
            record,
            case.evidence_packs[-1].event.violation_type,
            version=verdict.version,
        )
        if built.verdict != verdict:
            self._fail(checkpoint.case_id, HearingCoordinatorErrorCode.AUTHORITY_MISMATCH)
        closure = HearingReviewClosure(
            record=record,
            verdict=verdict,
            binding=built.binding,
            review=review,
        )
        transition = start_rework_cycle(session, checkpoint, closure)
        if transition.human_review_receipt is not None:
            committed = self._hearings.commit_hearing_human_review(
                checkpoint.run_id,
                snapshot.revision,
                head,
                transition.human_review_receipt,
                transition.checkpoint,
            )
            return committed.case, committed.checkpoint
        prepared = prepare_hearing_rework(session, checkpoint, closure)
        self._hearings.begin_hearing_rework(
            checkpoint.run_id,
            snapshot.revision,
            head,
            prepared.receipt,
            prepared.cycle_scope,
            prepared.checkpoint,
        )
        return None

    def _commit_human(
        self,
        snapshot: CaseSnapshot,
        head: AuditHead,
        session: HearingSession,
        checkpoint: HearingCheckpoint,
        reason: HearingHumanReviewReason,
    ) -> tuple[CaseSnapshot, HearingCheckpoint]:
        acquisition_ref = (
            checkpoint.acquisition_request.source_model_request_ref
            if reason == HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE
            and checkpoint.acquisition_request is not None
            else None
        )
        transition = transfer_to_human_review(
            session,
            checkpoint,
            reason,
            acquisition_request_ref=acquisition_ref,
        )
        assert transition.human_review_receipt is not None
        committed = self._hearings.commit_hearing_human_review(
            checkpoint.run_id,
            snapshot.revision,
            head,
            transition.human_review_receipt,
            transition.checkpoint,
        )
        return committed.case, committed.checkpoint

    @staticmethod
    def _validate_case(
        snapshot: CaseSnapshot,
        run_id: str,
        case_id: str,
    ) -> None:
        if (
            not isinstance(snapshot, CaseSnapshot)
            or snapshot.case.run_id != run_id
            or snapshot.case.case_id != case_id
        ):
            raise HearingCoordinatorError(
                HearingCoordinatorErrorCode.AUTHORITY_MISMATCH,
                case_id=case_id,
            )

    @staticmethod
    def _validate_active(
        snapshot: CaseSnapshot,
        session: HearingSession,
        checkpoint: HearingCheckpoint,
    ) -> None:
        allowed = snapshot.case.status == CaseStatus.DELIBERATING or (
            snapshot.case.status == CaseStatus.REWORK_REQUIRED
            and checkpoint.phase == HearingCheckpointPhase.REWORK_READY
        )
        if (
            not allowed
            or session.run_id != snapshot.case.run_id
            or session.case_id != snapshot.case.case_id
            or session.manifest_id != snapshot.case.manifest_id
            or checkpoint.hearing_session_id != session.session_id
        ):
            raise HearingCoordinatorError(
                HearingCoordinatorErrorCode.INVALID_CASE_STATE,
                case_id=snapshot.case.case_id,
            )

    @staticmethod
    def _terminal_outcome(
        snapshot: CaseSnapshot,
        *,
        cache_hits: int,
        recovered: int,
    ) -> HearingPipelineOutcome | None:
        case = snapshot.case
        if case.status == CaseStatus.HUMAN_REVIEW:
            return HearingPipelineOutcome(
                case=snapshot,
                cache_hit_count=cache_hits,
                recovered_response_count=recovered,
            )
        if case.status != CaseStatus.READY_FOR_ALERT_POLICY:
            return None
        if (
            not case.verdicts
            or not case.procedural_reviews
            or not case.procedural_reviews[-1].passed
        ):
            raise HearingCoordinatorError(
                HearingCoordinatorErrorCode.AUTHORITY_MISMATCH,
                case_id=case.case_id,
            )
        return HearingPipelineOutcome(
            case=snapshot,
            verdict=case.verdicts[-1],
            review=case.procedural_reviews[-1],
            cache_hit_count=cache_hits,
            recovered_response_count=recovered,
        )

    @staticmethod
    def _outcome(
        disposition: tuple[CaseSnapshot, HearingCheckpoint],
        session: HearingSession,
        cache_hits: int,
        recovered: int,
    ) -> HearingPipelineOutcome:
        case, checkpoint = disposition
        return HearingPipelineOutcome(
            case=case,
            session=session,
            checkpoint=checkpoint,
            cache_hit_count=cache_hits,
            recovered_response_count=recovered,
        )

    @staticmethod
    def _fail(
        case_id: str,
        code: HearingCoordinatorErrorCode,
    ) -> NoReturn:
        raise HearingCoordinatorError(code, case_id=case_id)


__all__ = [
    "HearingCoordinator",
    "HearingCoordinatorError",
    "HearingCoordinatorErrorCode",
    "HearingPipelineOutcome",
]
