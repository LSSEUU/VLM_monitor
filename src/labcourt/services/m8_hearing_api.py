"""Authenticated M8 facade over the existing M4 hearing coordinator and storage."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager, nullcontext
from typing import TypeVar

from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.m8_prehearing import M8PreHearingCoordinator
from labcourt.contracts.enums import ArtifactKind, CaseStatus, ScreeningDecision, VlmRole
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingCheckpoint,
    HearingModelCallFailureAuthority,
    HearingModelResponse,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
)
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8ActorScopeKind,
    M8Capability,
)
from labcourt.contracts.m8_acquisition_v2 import (
    M8HearingAcquisitionResultV2,
    M8HearingAcquisitionResultViewV2,
)
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_hearing_api import (
    M8HearingEligibility,
    M8HearingL5Status,
    M8HearingModelMode,
    M8HearingProviderSelectionV1,
    M8HearingStartRequestV1,
    M8HearingViewV1,
)
from labcourt.contracts.m8_prehearing import (
    M8PreHearingPreparationV1,
    M8PreHearingPreparationViewV1,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Verdict
from labcourt.exceptions import (
    BudgetExceeded,
    ConcurrentModification,
    EvidenceMissing,
    LabCourtError,
)
from labcourt.ports.evidence_repository import EvidenceRepository
from labcourt.ports.hearing_repository import HearingRepository
from labcourt.ports.m8_hearing_api import M8HearingRuntime, M8HearingSessionLocator
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.ports.m8_prehearing import M8PreHearingRepository
from labcourt.services.m8_operations_api import M8ApiServiceError, M8ApiServiceFailureCode

_ROLE_RANK = {VlmRole.PROSECUTOR: 0, VlmRole.DEFENDER: 1, VlmRole.JUDGE: 2}
_T = TypeVar("_T")


class M4HearingApiRuntime:
    """Project and drive exactly one run through its already-built M4 coordinator."""

    def __init__(
        self,
        *,
        run_id: str,
        location_by_zone: Mapping[str, str],
        model_mode: M8HearingModelMode,
        provider_selections: tuple[M8HearingProviderSelectionV1, ...],
        evidence_repository: EvidenceRepository,
        hearing_repository: HearingRepository,
        session_locator: M8HearingSessionLocator,
        coordinator: HearingCoordinator,
    ) -> None:
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("M8 hearing runtime requires a run ID")
        if tuple(item.role for item in provider_selections) != (
            VlmRole.PROSECUTOR,
            VlmRole.DEFENDER,
            VlmRole.JUDGE,
        ):
            raise ValueError("M8 hearing runtime requires exact prosecutor/defender/judge routes")
        self._run_id = run_id
        self._locations = dict(location_by_zone)
        self._model_mode = model_mode
        self._providers = provider_selections
        self._evidence = evidence_repository
        self._hearings = hearing_repository
        self._sessions = session_locator
        self._coordinator = coordinator

    @property
    def run_id(self) -> str:
        return self._run_id

    def start(self, request: M8HearingStartRequestV1) -> M8HearingViewV1:
        if request.run_id != self._run_id or request.model_mode != self._model_mode:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        snapshot = self._evidence.load_case(self._run_id, request.case_id)
        case = snapshot.case
        session = self._sessions.load_hearing_for_case(self._run_id, request.case_id)
        if session is not None:
            if (
                request.source_status.value != session.entry_status.value
                or request.source_screening_id != session.screening_id
                or request.source_evidence_pack_id != session.initial_evidence_pack_id
                or request.source_evidence_pack_version != session.initial_evidence_pack_version
                or request.request_manifest_id != session.manifest_id
            ):
                raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
            if case.status in {
                CaseStatus.DELIBERATING,
                CaseStatus.REWORK_REQUIRED,
                CaseStatus.BACKLOGGED,
            }:
                self._coordinator.process_case(self._run_id, request.case_id)
            return self._project(request.case_id, start_request_id=request.start_request_id)

        if not case.screening_results or not case.evidence_packs:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        screening = case.screening_results[-1]
        pack = case.evidence_packs[-1]
        if (
            case.status != request.source_status
            or screening.screening_id != request.source_screening_id
            or pack.pack_id != request.source_evidence_pack_id
            or pack.version != request.source_evidence_pack_version
            or case.manifest_id != request.request_manifest_id
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        if case.status == CaseStatus.ESCALATED and screening.decision != ScreeningDecision.ESCALATE:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        if case.status not in {CaseStatus.ESCALATED, CaseStatus.REWORK_REQUIRED}:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)

        self._coordinator.process_case(self._run_id, request.case_id)
        return self._project(request.case_id, start_request_id=request.start_request_id)

    def view(self, case_id: str) -> M8HearingViewV1:
        return self._project(case_id, start_request_id=None)

    def prehearing_coordinator(
        self,
        repository: M8PreHearingRepository,
    ) -> M8PreHearingCoordinator:
        """Bind the additive M8 gate to this runtime's persisted M4 authorities."""

        return M8PreHearingCoordinator(
            evidence_repository=self._evidence,
            preparation_repository=repository,
            session_locator=self._sessions,
        )

    def _project(self, case_id: str, *, start_request_id: str | None) -> M8HearingViewV1:
        snapshot = self._evidence.load_case(self._run_id, case_id)
        case = snapshot.case
        if not case.screening_results or not case.evidence_packs:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        try:
            location_id = self._locations[case.event.zone_id]
        except KeyError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from error
        screening = case.screening_results[-1]
        current_pack = case.evidence_packs[-1]
        session = self._sessions.load_hearing_for_case(self._run_id, case_id)

        checkpoint: HearingCheckpoint | None = None
        rounds: tuple[HearingRound, ...] = ()
        outputs: tuple[HearingRoleOutput, ...] = ()
        responses: tuple[HearingModelResponse, ...] = ()
        failures: tuple[HearingModelCallFailureAuthority, ...] = ()
        has_hearing_record = False
        if session is not None:
            checkpoint = self._hearings.load_latest_hearing_checkpoint(
                self._run_id, session.session_id
            )
            rounds = self._hearings.list_hearing_rounds(self._run_id, session.session_id)
            outputs = self._stable_outputs(
                self._hearings.list_hearing_role_outputs(self._run_id, session.session_id)
            )
            responses = self._stable_responses(
                self._hearings.list_hearing_model_responses(self._run_id, session.session_id)
            )
            failures = self._stable_failures(
                self._hearings.list_hearing_failure_authorities(self._run_id, session.session_id)
            )
            has_hearing_record = (
                self._hearings.load_hearing_record(self._run_id, session.session_id) is not None
            )

        final_verdict = case.verdicts[-1] if has_hearing_record and case.verdicts else None
        evidence_refs, precedent_refs = self._cited_refs(outputs, final_verdict)
        reviews = case.procedural_reviews
        if not reviews:
            l5_status = M8HearingL5Status.NOT_RUN
        elif reviews[-1].passed:
            l5_status = M8HearingL5Status.PASSED
        else:
            l5_status = M8HearingL5Status.FAILED
        return M8HearingViewV1(
            run_id=self._run_id,
            case_id=case_id,
            case_location_id=location_id,
            model_mode=self._model_mode,
            provider_selections=self._providers,
            case_revision=snapshot.revision,
            case_status=case.status,
            eligibility=self._eligibility(case.status, screening.decision, session),
            request_manifest_id=case.manifest_id,
            screening_id=screening.screening_id,
            screening_decision=screening.decision,
            screening_conflict_flags=tuple(flag.value for flag in screening.conflict_codes),
            current_evidence_pack_id=current_pack.pack_id,
            current_evidence_pack_version=current_pack.version,
            hearing_session=session,
            checkpoint=checkpoint,
            rounds=rounds,
            role_outputs=outputs,
            model_responses=responses,
            typed_failures=failures,
            cited_evidence_refs=evidence_refs,
            cited_precedent_refs=precedent_refs,
            acquisition_requests=tuple(
                item.acquisition_request for item in rounds if item.acquisition_request is not None
            ),
            tool_execution_receipts=tuple(
                item.tool_execution_receipt
                for item in rounds
                if item.tool_execution_receipt is not None
            ),
            final_verdict=final_verdict,
            procedural_reviews=reviews,
            l5_status=l5_status,
            current_backlog_item_id=case.current_backlog_item_id,
            start_request_id=start_request_id,
        )

    @staticmethod
    def _eligibility(
        status: CaseStatus,
        decision: ScreeningDecision,
        session: HearingSession | None,
    ) -> M8HearingEligibility:
        # Objective insufficiency may enter typed human review before any M4
        # session exists.  Project the persisted Case truth instead of making
        # the UI infer that a hearing occurred.
        if status == CaseStatus.HUMAN_REVIEW:
            return M8HearingEligibility.HUMAN_REVIEW
        if session is None:
            if status == CaseStatus.ESCALATED and decision == ScreeningDecision.ESCALATE:
                return M8HearingEligibility.ELIGIBLE_ESCALATED
            if status == CaseStatus.REWORK_REQUIRED:
                return M8HearingEligibility.ELIGIBLE_REWORK_REQUIRED
            return M8HearingEligibility.NOT_ELIGIBLE
        if status == CaseStatus.BACKLOGGED:
            return M8HearingEligibility.BACKLOGGED
        if status == CaseStatus.READY_FOR_ALERT_POLICY:
            return M8HearingEligibility.COMPLETED
        if status in {CaseStatus.DELIBERATING, CaseStatus.REWORK_REQUIRED}:
            return M8HearingEligibility.IN_PROGRESS
        return M8HearingEligibility.NOT_ELIGIBLE

    @staticmethod
    def _stable_outputs(outputs: tuple[HearingRoleOutput, ...]) -> tuple[HearingRoleOutput, ...]:
        return tuple(sorted(outputs, key=lambda item: (item.round_index, _ROLE_RANK[item.role])))

    @staticmethod
    def _stable_responses(
        responses: tuple[HearingModelResponse, ...],
    ) -> tuple[HearingModelResponse, ...]:
        return tuple(
            sorted(
                responses,
                key=lambda item: (item.round_index, _ROLE_RANK[item.role], item.attempt_index),
            )
        )

    @staticmethod
    def _stable_failures(
        failures: tuple[HearingModelCallFailureAuthority, ...],
    ) -> tuple[HearingModelCallFailureAuthority, ...]:
        return tuple(
            sorted(
                failures,
                key=lambda item: (
                    item.request.round_index,
                    _ROLE_RANK[item.role],
                    item.retry_generation,
                    item.authority_id,
                ),
            )
        )

    @staticmethod
    def _cited_refs(
        outputs: tuple[HearingRoleOutput, ...],
        verdict: Verdict | None,
    ) -> tuple[tuple[ArtifactRef, ...], tuple[ArtifactRef, ...]]:
        refs: set[ArtifactRef] = set()
        for output in outputs:
            payload = output.payload
            if isinstance(payload, (ProsecutorModelPayload, DefenderModelPayload)):
                for argument in payload.arguments:
                    refs.update(argument.evidence_refs)
            elif isinstance(payload, JudgeModelPayload):
                for response in payload.judge_responses:
                    refs.update(response.evidence_refs)
                for application in payload.precedent_applications:
                    refs.add(application.precedent_ref)
                    refs.update(application.fact_difference_refs)
                outcome = payload.outcome
                if isinstance(outcome, JudgeFinalDecisionPayload):
                    refs.update(item.evidence_ref for item in outcome.evidence_citations)
                    refs.update(item.evidence_ref for item in outcome.objective_claims)
                else:
                    refs.update(outcome.request.supporting_evidence_refs)
        if verdict is not None:
            refs.update(item.evidence_ref for item in verdict.evidence_citations)
            for argument in verdict.prosecution_arguments + verdict.defense_arguments:
                refs.update(argument.evidence_refs)
            for response in verdict.judge_responses:
                refs.update(response.evidence_refs)
            for application in verdict.precedent_applications:
                refs.add(application.precedent_ref)
                refs.update(application.fact_difference_refs)
            refs.update(item.evidence_ref for item in verdict.objective_claims)
        evidence = tuple(
            sorted(
                (ref for ref in refs if ref.kind != ArtifactKind.PRECEDENT),
                key=lambda ref: ref.sort_key,
            )
        )
        precedents = tuple(
            sorted(
                (ref for ref in refs if ref.kind == ArtifactKind.PRECEDENT),
                key=lambda ref: ref.sort_key,
            )
        )
        return evidence, precedents


class M8HearingApiService:
    """Authenticate from persisted actor authority, then delegate to a run runtime."""

    def __init__(
        self,
        operations_repository: M8OperationsRepository,
        runtimes: Mapping[str, M8HearingRuntime],
        *,
        start_enabled: bool = True,
        runtime_resolver: Callable[[str], AbstractContextManager[M8HearingRuntime]] | None = None,
        case_id_resolver: Callable[[str, str], str] | None = None,
        prehearing_resolver: (Callable[[str, str], M8PreHearingPreparationV1 | None] | None) = None,
        prehearing_router: (Callable[[str, str], M8PreHearingPreparationV1 | None] | None) = None,
        acquisition_resolver: (
            Callable[[str, str], tuple[M8HearingAcquisitionResultV2, ...]] | None
        ) = None,
    ) -> None:
        if not isinstance(start_enabled, bool):
            raise TypeError("start_enabled must be a bool")
        self._operations = operations_repository
        self._runtimes = dict(runtimes)
        self._start_enabled = start_enabled
        self._runtime_resolver = runtime_resolver
        self._case_id_resolver = case_id_resolver
        self._prehearing_resolver = prehearing_resolver
        self._prehearing_router = prehearing_router
        self._acquisition_resolver = acquisition_resolver
        if any(run_id != runtime.run_id for run_id, runtime in self._runtimes.items()):
            raise ValueError("M8 hearing runtime map conflicts with runtime run IDs")

    def start(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        case_id: str,
        request: M8HearingStartRequestV1,
    ) -> M8HearingViewV1:
        if not self._start_enabled:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        if request.run_id != run_id or request.case_id != case_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        return self._call(lambda: self._start(principal, run_id, case_id, request))

    def _start(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        case_id: str,
        request: M8HearingStartRequestV1,
    ) -> M8HearingViewV1:
        with self._runtime(run_id) as runtime:
            source_case_id = self._source_case_id(run_id, case_id)
            view = runtime.view(source_case_id)
            self._authorize(principal, view, start=True)
            if self._prehearing_router is not None:
                preparation = self._prehearing_router(run_id, source_case_id)
                if preparation is not None:
                    raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
            if view.hearing_session is None and view.eligibility not in {
                M8HearingEligibility.ELIGIBLE_ESCALATED,
                M8HearingEligibility.ELIGIBLE_REWORK_REQUIRED,
            }:
                raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
            source_request = (
                request
                if source_case_id == case_id
                else request.model_copy(update={"case_id": source_case_id})
            )
            started = runtime.start(source_request)
            return self._platform_case_view(started, case_id)

    def status(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        case_id: str,
    ) -> M8HearingViewV1:
        return self._call(lambda: self._status(principal, run_id, case_id))

    def _status(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        case_id: str,
    ) -> M8HearingViewV1:
        with self._runtime(run_id) as runtime:
            view = runtime.view(self._source_case_id(run_id, case_id))
            self._authorize(principal, view, start=False)
            return self._platform_case_view(view, case_id)

    def preparation(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        case_id: str,
    ) -> M8PreHearingPreparationViewV1 | None:
        """Read the persisted objective-evidence gate under hearing permissions."""

        return self._call(lambda: self._preparation(principal, run_id, case_id))

    def _preparation(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        case_id: str,
    ) -> M8PreHearingPreparationViewV1 | None:
        if self._prehearing_resolver is None:
            return None
        with self._runtime(run_id) as runtime:
            source_case_id = self._source_case_id(run_id, case_id)
            view = runtime.view(source_case_id)
            self._authorize(principal, view, start=False)
            preparation = self._prehearing_resolver(run_id, source_case_id)
            if preparation is None:
                return None
            return M8PreHearingPreparationViewV1.project(
                preparation,
                platform_case_id=case_id,
            )

    def acquisitions(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        case_id: str,
    ) -> tuple[M8HearingAcquisitionResultViewV2, ...]:
        """Read persisted v2 tool results under the same cropped hearing access."""

        return self._call(lambda: self._acquisitions(principal, run_id, case_id))

    def _acquisitions(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        case_id: str,
    ) -> tuple[M8HearingAcquisitionResultViewV2, ...]:
        if self._acquisition_resolver is None:
            return ()
        with self._runtime(run_id) as runtime:
            source_case_id = self._source_case_id(run_id, case_id)
            view = runtime.view(source_case_id)
            self._authorize(principal, view, start=False)
            return tuple(
                M8HearingAcquisitionResultViewV2.project(
                    result,
                    platform_case_id=case_id,
                )
                for result in self._acquisition_resolver(run_id, source_case_id)
            )

    @staticmethod
    def _platform_case_view(view: M8HearingViewV1, case_id: str) -> M8HearingViewV1:
        if view.case_id == case_id:
            return view
        return view.model_copy(update={"case_id": case_id})

    def _source_case_id(self, run_id: str, platform_case_id: str) -> str:
        if self._case_id_resolver is None:
            return platform_case_id
        return self._case_id_resolver(run_id, platform_case_id)

    def _runtime(self, run_id: str) -> AbstractContextManager[M8HearingRuntime]:
        runtime = self._runtimes.get(run_id)
        if runtime is not None:
            return nullcontext(runtime)
        if self._runtime_resolver is not None:
            return self._runtime_resolver(run_id)
        raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)

    def _authorize(
        self,
        principal: M8ApiPrincipalV1,
        view: M8HearingViewV1,
        *,
        start: bool,
    ) -> None:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        receipt = self._call(
            lambda: self._operations.get_current_actor_authority(principal.actor_id)
        )
        actor = receipt.authority
        safety_access = (
            actor.active
            and actor.actor_id == principal.actor_id
            and actor.role == M8ActorRole.SAFETY_OFFICER
            and M8Capability.REQUEST_CASE_EVIDENCE in actor.capabilities
        )
        leader_read = (
            not start
            and actor.active
            and actor.actor_id == principal.actor_id
            and actor.role == M8ActorRole.LEADER
            and M8Capability.VIEW_MAJOR_EVENTS in actor.capabilities
            and view.eligibility
            in {M8HearingEligibility.COMPLETED, M8HearingEligibility.HUMAN_REVIEW}
        )
        if not safety_access and not leader_read:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        if actor.scope_kind == M8ActorScopeKind.CAMPUS_WIDE:
            return
        if (
            actor.scope_kind != M8ActorScopeKind.LOCATIONS
            or view.case_location_id not in actor.scope_location_ids
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)

    @staticmethod
    def _call(function: Callable[[], _T]) -> _T:
        try:
            return function()
        except M8ApiServiceError:
            raise
        except EvidenceMissing as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from error
        except ConcurrentModification as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION) from error
        except (BudgetExceeded, RepositoryIntegrityError) as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from error
        except (LabCourtError, OSError, ValueError) as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from error


__all__ = ["M4HearingApiRuntime", "M8HearingApiService"]
