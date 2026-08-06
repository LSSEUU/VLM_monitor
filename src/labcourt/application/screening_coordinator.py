"""Public façade for the crash-resumable M3 screening workflow."""

from __future__ import annotations

from math import ceil
from typing import cast

from labcourt.application._screening_backlog_workflow import ScreeningBacklogWorkflow
from labcourt.application._screening_workflow_types import (
    ScreeningCoordinatorError,
    ScreeningCoordinatorErrorCode,
    ScreeningPipelineOutcome,
    _BacklogRequired,
)
from labcourt.application.screening_failures import classify_screening_failure
from labcourt.application.screening_request import prepare_screening_request
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    BacklogReasonCode,
    CaseStatus,
    ScreeningDecision,
    VlmRole,
)
from labcourt.exceptions import ConcurrentModification, ManifestMismatch
from labcourt.ports.evidence_repository import EvidenceRepository
from labcourt.ports.m3_semantics import M3SemanticVerifier
from labcourt.ports.procedural_review import ProceduralReviewVerifier
from labcourt.ports.prompts import PromptCatalog, RenderedPromptRegistrar
from labcourt.ports.screening_repository import ScreeningRepository
from labcourt.ports.vlm import ModelResponseStore, VLMClient


class ScreeningCoordinator(ScreeningBacklogWorkflow):
    """Coordinate M3 while delegated components enforce its internal boundaries."""

    def __init__(
        self,
        *,
        config: AppConfig,
        evidence_repository: EvidenceRepository,
        screening_repository: ScreeningRepository,
        response_store: ModelResponseStore,
        vlm_client: VLMClient,
        prompt_catalog: PromptCatalog,
        prompt_registrar: RenderedPromptRegistrar,
        procedural_review_verifier: ProceduralReviewVerifier,
        semantic_verifier: M3SemanticVerifier | None = None,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        for dependency, method, name in (
            (evidence_repository, "load_case", "evidence_repository"),
            (screening_repository, "commit_screening", "screening_repository"),
            (screening_repository, "claim_model_call", "screening_repository"),
            (screening_repository, "complete_model_call", "screening_repository"),
            (response_store, "recover", "response_store"),
            (response_store, "acknowledge", "response_store"),
            (response_store, "verify", "response_store"),
            (response_store, "read_bytes", "response_store"),
            (vlm_client, "complete", "vlm_client"),
            (prompt_catalog, "render", "prompt_catalog"),
            (prompt_registrar, "register", "prompt_registrar"),
            (
                procedural_review_verifier,
                "rebuild_review",
                "procedural_review_verifier",
            ),
        ):
            if not callable(getattr(dependency, method, None)):
                raise TypeError(f"{name} does not implement its required capability")
        self._config = config
        self._evidence = evidence_repository
        self._screening = screening_repository
        self._responses = response_store
        self._vlm = vlm_client
        self._catalog = prompt_catalog
        self._prompts = prompt_registrar
        self._review_verifier = procedural_review_verifier
        effective_semantic_verifier = semantic_verifier or procedural_review_verifier
        for method in ("rebuild_screening", "rebuild_fast_verdict"):
            if not callable(getattr(effective_semantic_verifier, method, None)):
                raise TypeError(f"semantic_verifier does not implement {method}")
        self._semantic_verifier = cast(M3SemanticVerifier, effective_semantic_verifier)

    @property
    def minimum_backlog_lease_seconds(self) -> int:
        """Lease floor for stale-claim wait, two calls, and commit margin."""

        claim_grace_seconds = 5.0
        commit_margin_seconds = 30.0
        return ceil(
            3 * (self._config.screening.timeout_seconds + claim_grace_seconds)
            + commit_margin_seconds
        )

    def process_case(self, run_id: str, case_id: str) -> ScreeningPipelineOutcome:
        """Process or resume one case through the complete M3 boundary."""

        snapshot = self._evidence.load_case(run_id, case_id)
        self._validate_case_scope(snapshot, run_id, case_id)
        existing = self._existing_outcome(snapshot)
        if existing is not None:
            return existing
        if snapshot.case.status == CaseStatus.SCREENED:
            return self._resume_screened(snapshot)
        if snapshot.case.status != CaseStatus.EVIDENCE_READY:
            raise ScreeningCoordinatorError(ScreeningCoordinatorErrorCode.INVALID_CASE_STATE)

        authority = self._current_authority(snapshot)
        if not authority.closure.passed:
            return self._backlog_latest(
                run_id,
                case_id,
                BacklogReasonCode.CURRENT_PACK_CHANGED,
                VlmRole.SCREENING,
            )
        manifest = self._evidence.load_run_manifest(run_id)
        if manifest.manifest_id != snapshot.case.manifest_id:
            raise ManifestMismatch("case and authoritative run manifest do not match")
        try:
            prepared = prepare_screening_request(
                authority.pack,
                self._config,
                manifest,
                self._catalog,
            )
            self._prompts.register(prepared.rendered_prompt)
        except ManifestMismatch:
            # Pinned authority mismatches are deployment/configuration defects,
            # not retryable model work.
            raise
        except Exception as error:
            reason = classify_screening_failure(error)
            if reason is None:
                raise
            return self._backlog_latest(
                run_id,
                case_id,
                reason,
                VlmRole.SCREENING,
            )

        # Do not call a model for evidence that ceased to be current during request setup.
        try:
            self._require_unchanged_case_input(authority)
        except _BacklogRequired as failure:
            return self._backlog_latest(
                run_id,
                case_id,
                failure.reason,
                failure.role,
                response_ids=failure.response_ids,
                model_call_failure=failure.model_call_failure,
            )
        try:
            parsed = self._parse_model_stage(
                prepared.request,
                manifest=manifest,
                catalog=self._catalog,
            )
        except _BacklogRequired as failure:
            return self._backlog_latest(
                run_id,
                case_id,
                failure.reason,
                failure.role,
                response_ids=failure.response_ids,
                model_call_failure=failure.model_call_failure,
            )

        current = self._evidence.load_case(run_id, case_id)
        if not self._same_case_input(authority.snapshot, current):
            return self._backlog_latest(
                run_id,
                case_id,
                BacklogReasonCode.CURRENT_PACK_CHANGED,
                VlmRole.SCREENING,
                response_ids=tuple(receipt.response_id for receipt in parsed.history),
            )
        routed_authority = self._current_authority(current)
        if not routed_authority.closure.passed:
            return self._backlog_latest(
                run_id,
                case_id,
                BacklogReasonCode.CURRENT_PACK_CHANGED,
                VlmRole.SCREENING,
                response_ids=tuple(receipt.response_id for receipt in parsed.history),
            )
        screening = self._semantic_verifier.rebuild_screening(
            parsed.output,
            routed_authority.pack,
            len(current.case.screening_results) + 1,
        )
        try:
            committed = self._commit_screening_with_head_rebase(
                routed_authority,
                screening,
            )
        except ConcurrentModification:
            return self._backlog_latest(
                run_id,
                case_id,
                BacklogReasonCode.CURRENT_PACK_CHANGED,
                VlmRole.SCREENING,
                response_ids=tuple(receipt.response_id for receipt in parsed.history),
            )
        except Exception as error:
            reason = classify_screening_failure(error)
            if reason != BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE:
                raise
            return self._backlog_latest(
                run_id,
                case_id,
                reason,
                VlmRole.SCREENING,
                response_ids=tuple(receipt.response_id for receipt in parsed.history),
            )
        if isinstance(committed, ScreeningPipelineOutcome):
            return committed
        if screening.decision == ScreeningDecision.ESCALATE:
            return ScreeningPipelineOutcome(
                case=committed.case,
                screening_result=screening,
                cache_hit_count=parsed.cache_hit_count,
                recovered_response_count=parsed.recovered_response_count,
                repair_attempted=parsed.repair_attempted,
            )
        return self._finish_fast_verdict(
            committed.case,
            screening,
            parsed.history,
            cache_hit_count=parsed.cache_hit_count,
            recovered_response_count=parsed.recovered_response_count,
            repair_attempted=parsed.repair_attempted,
        )


__all__ = [
    "ScreeningCoordinator",
    "ScreeningCoordinatorError",
    "ScreeningCoordinatorErrorCode",
    "ScreeningPipelineOutcome",
]
