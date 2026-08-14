from __future__ import annotations

from dataclasses import dataclass

import pytest

from labcourt.application.m8_prehearing import M8PreHearingCoordinator
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    AuditAction,
    CaseStatus,
    EvidenceFailureCode,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import (
    EvidencePack,
    EvidencePackDraft,
    ObservationSufficiencyInput,
    TrackSummary,
)
from labcourt.contracts.m8_prehearing import (
    M8PreHearingOutcomeCode,
    M8PreHearingPreparationState,
    M8PreHearingPreparationV1,
)
from labcourt.domain.screening_router import ScreeningRoutePolicy, route_screening
from labcourt.exceptions import ConcurrentModification, EvidenceMissing
from labcourt.ports.evidence_repository import CaseSnapshot
from tests.unit.test_m3_screening_router import (
    FIXTURES,
    _absence_crop,
    _close_pack,
    _parsed,
)


def _pack(*, sufficient: bool) -> EvidencePack:
    event = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    temporal = tuple(
        _absence_crop(event, frame_index, clear=clear)
        for frame_index, clear in (
            (0, True),
            (75, sufficient),
            (149, False),
        )
    )
    clear_ids = tuple(
        sorted(
            crop.crop_id
            for crop in temporal
            if crop.observability is not None and crop.observability.total >= 0.5
        )
    )
    unclear_ids = tuple(sorted({crop.crop_id for crop in temporal} - set(clear_ids)))
    return _close_pack(
        EvidencePackDraft(
            run_id="run-01",
            case_id=derive_case_id(event.event_id),
            version=1,
            event=event,
            key_frame_ids=tuple(
                f"{event.camera_id}:{event.stream_id}:{index}" for index in (0, 75, 149, 150, 151)
            ),
            temporal_crops=temporal,
            objective_facts=event.objective_facts,
            track_summary=TrackSummary(
                primary_track_ref=event.primary_track_ref,
                start_frame=0,
                end_frame_exclusive=152,
                observed_frame_count=151,
            ),
            confirmation_record=event.confirmation,
            observation_sufficiency_input=ObservationSufficiencyInput(
                clear_crop_ids=clear_ids,
                unclear_crop_ids=unclear_ids,
                clear_threshold=0.5,
                required_clear_count=2,
                selected_by_observability=True,
            ),
            manifest_id=event.manifest_id,
        )
    )


def _snapshot(*, sufficient: bool) -> CaseSnapshot:
    pack = _pack(sufficient=sufficient)
    screening = route_screening(
        _parsed(pack, probability=0.5),
        pack,
        ScreeningRoutePolicy(
            low_probability=0.35,
            high_probability=0.65,
            strong_signal_threshold=0.8,
        ),
    )
    return CaseSnapshot(
        case=Case(
            run_id=pack.run_id,
            status=CaseStatus.ESCALATED,
            event=pack.event,
            evidence_packs=(pack,),
            screening_results=(screening,),
            manifest_id=pack.manifest_id,
        ),
        revision=3,
    )


class _Evidence:
    def __init__(self, snapshot: CaseSnapshot) -> None:
        self.snapshot = snapshot
        self.failure_calls = 0

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot:
        assert (run_id, case_id) == (self.snapshot.case.run_id, self.snapshot.case.case_id)
        return self.snapshot

    def record_evidence_failure(
        self,
        run_id: str,
        expected_revision: int,
        case_id: str,
        failure_code: EvidenceFailureCode,
    ) -> CaseSnapshot:
        assert (run_id, case_id) == (self.snapshot.case.run_id, self.snapshot.case.case_id)
        if self.snapshot.case.status == CaseStatus.HUMAN_REVIEW:
            return self.snapshot
        if expected_revision != self.snapshot.revision:
            raise ConcurrentModification("fake Case revision changed")
        assert failure_code == EvidenceFailureCode.EVIDENCE_MISSING
        case = self.snapshot.case
        entry = TimelineEntry(
            sequence=len(case.timeline),
            action=AuditAction.CASE_STATE_CHANGED.value,
            stage="EVIDENCE",
            object_ref=case.case_id,
            details={"failure_code": failure_code.value},
        )
        self.snapshot = CaseSnapshot(
            case=case.model_copy(
                update={
                    "status": CaseStatus.HUMAN_REVIEW,
                    "timeline": (*case.timeline, entry),
                }
            ),
            revision=self.snapshot.revision + 1,
        )
        self.failure_calls += 1
        return self.snapshot


class _Preparations:
    def __init__(self) -> None:
        self.current: M8PreHearingPreparationV1 | None = None
        self.put_calls = 0
        self.fail_completion_once = False

    def put(
        self,
        preparation: M8PreHearingPreparationV1,
        expected_prior_revision: int | None,
    ) -> M8PreHearingPreparationV1:
        if self.current is None:
            assert expected_prior_revision is None and preparation.revision == 1
        elif self.current == preparation:
            return self.current
        elif (
            expected_prior_revision != self.current.revision
            or preparation.revision != self.current.revision + 1
        ):
            raise ConcurrentModification("fake preparation revision changed")
        if preparation.revision == 2 and self.fail_completion_once:
            self.fail_completion_once = False
            raise RuntimeError("simulated process loss before terminal preparation commit")
        self.current = preparation
        self.put_calls += 1
        return preparation

    def get(self, preparation_id: str) -> M8PreHearingPreparationV1:
        if self.current is None or self.current.preparation_id != preparation_id:
            raise EvidenceMissing("fake preparation absent")
        return self.current

    def load_for_case(
        self,
        run_id: str,
        case_id: str,
    ) -> M8PreHearingPreparationV1 | None:
        if self.current is None:
            return None
        assert (run_id, case_id) == (self.current.run_id, self.current.case_id)
        return self.current


@dataclass
class _Sessions:
    present: bool = False
    calls: int = 0

    def load_hearing_for_case(self, run_id: str, case_id: str) -> object | None:
        del run_id, case_id
        self.calls += 1
        return object() if self.present else None


def _coordinator(
    *,
    sufficient: bool,
    session_present: bool = False,
) -> tuple[M8PreHearingCoordinator, _Evidence, _Preparations, _Sessions]:
    evidence = _Evidence(_snapshot(sufficient=sufficient))
    preparations = _Preparations()
    sessions = _Sessions(present=session_present)
    coordinator = M8PreHearingCoordinator(
        evidence_repository=evidence,  # type: ignore[arg-type]
        preparation_repository=preparations,
        session_locator=sessions,  # type: ignore[arg-type]
    )
    return coordinator, evidence, preparations, sessions


def test_insufficient_first_escalation_terminates_before_any_hearing_role_call() -> None:
    coordinator, evidence, preparations, sessions = _coordinator(sufficient=False)
    case_id = evidence.snapshot.case.case_id

    completed = coordinator.route("run-01", case_id)

    assert completed is not None
    assert completed.state == M8PreHearingPreparationState.COMPLETED
    assert completed.outcome_code == M8PreHearingOutcomeCode.NO_NOVEL_CLEAR_FRAME
    assert completed.hearing_role_call_count == 0
    assert evidence.snapshot.case.status == CaseStatus.HUMAN_REVIEW
    assert evidence.failure_calls == 1
    assert preparations.put_calls == 2
    assert sessions.calls == 2

    # Process-level replay resumes the completed authority without another
    # evidence transition, preparation revision, or M4 session lookup.
    assert coordinator.route("run-01", case_id) == completed
    assert evidence.failure_calls == 1
    assert preparations.put_calls == 2
    assert sessions.calls == 2


def test_sufficient_objective_evidence_keeps_escalated_case_for_semantic_m4() -> None:
    coordinator, evidence, preparations, sessions = _coordinator(sufficient=True)

    assert coordinator.route("run-01", evidence.snapshot.case.case_id) is None
    assert evidence.snapshot.case.status == CaseStatus.ESCALATED
    assert evidence.failure_calls == 0
    assert preparations.current is None
    assert sessions.calls == 0


def test_existing_hearing_session_prevents_prehearing_preparation() -> None:
    coordinator, evidence, preparations, sessions = _coordinator(
        sufficient=False,
        session_present=True,
    )

    assert coordinator.route("run-01", evidence.snapshot.case.case_id) is None
    assert evidence.snapshot.case.status == CaseStatus.ESCALATED
    assert preparations.current is None
    assert evidence.failure_calls == 0
    assert sessions.calls == 1


def test_pending_preparation_resumes_after_case_transition_and_process_restart() -> None:
    coordinator, evidence, preparations, sessions = _coordinator(sufficient=False)
    preparations.fail_completion_once = True
    case_id = evidence.snapshot.case.case_id

    with pytest.raises(RuntimeError, match="simulated process loss"):
        coordinator.route("run-01", case_id)
    assert evidence.snapshot.case.status == CaseStatus.HUMAN_REVIEW
    assert evidence.failure_calls == 1
    assert preparations.current is not None
    assert preparations.current.state == M8PreHearingPreparationState.PENDING

    restarted = M8PreHearingCoordinator(
        evidence_repository=evidence,  # type: ignore[arg-type]
        preparation_repository=preparations,
        session_locator=sessions,  # type: ignore[arg-type]
    )
    completed = restarted.route("run-01", case_id)

    assert completed is not None
    assert completed.state == M8PreHearingPreparationState.COMPLETED
    assert evidence.failure_calls == 1
