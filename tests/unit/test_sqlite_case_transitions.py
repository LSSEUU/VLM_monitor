from __future__ import annotations

from labcourt.adapters.storage.sqlite_case_transitions import (
    case_transition_audit,
    evidence_failure_code,
    evidence_failure_timeline_entry,
)
from labcourt.contracts.alert_policy import AlertPolicyDisposition
from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    AlertLevel,
    ArtifactKind,
    AuditAction,
    CaseStatus,
    EvidenceFailureCode,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.storage import ArtifactRef
from tests.contract.test_m3_contracts import (
    RUN_ID,
    _parsed,
    _presence_pack,
    _review,
    _screening,
    _verdict,
)


def _candidate() -> tuple[Case, EvidencePack]:
    pack = _presence_pack()
    case = Case(
        run_id=RUN_ID,
        status=CaseStatus.CANDIDATE,
        event=pack.event,
        manifest_id=pack.manifest_id,
    )
    return case, pack


def test_creation_remains_outside_adjacent_transition_recognition() -> None:
    candidate, _pack = _candidate()

    assert case_transition_audit(candidate, candidate) is None


def test_evidence_transitions_and_failure_timeline_share_one_authority() -> None:
    candidate, pack = _candidate()
    case_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=candidate.case_id)
    published = candidate.model_copy(
        update={
            "status": CaseStatus.EVIDENCE_READY,
            "evidence_packs": (pack,),
        }
    )
    failure = evidence_failure_timeline_entry(
        sequence=0,
        case_id=candidate.case_id,
        failure_code=EvidenceFailureCode.EVIDENCE_MISSING,
    )
    human_review = candidate.model_copy(
        update={
            "status": CaseStatus.HUMAN_REVIEW,
            "timeline": (failure,),
        }
    )

    assert case_transition_audit(candidate, published) == (
        AuditAction.EVIDENCE_PACK_PUBLISHED,
        case_ref,
    )
    assert evidence_failure_code(failure, case_id=candidate.case_id) == (
        EvidenceFailureCode.EVIDENCE_MISSING
    )
    assert case_transition_audit(candidate, human_review) == (
        AuditAction.CASE_STATE_CHANGED,
        case_ref,
    )


def test_initial_m3_backlog_transition_binds_monotonic_usage() -> None:
    candidate, pack = _candidate()
    evidence_ready = candidate.model_copy(
        update={
            "status": CaseStatus.EVIDENCE_READY,
            "evidence_packs": (pack,),
        }
    )
    backlog_item_id = "b" * 64
    backlog_entry = TimelineEntry(
        sequence=0,
        action=AuditAction.CASE_STATE_CHANGED.value,
        stage="BACKLOG",
        object_ref=backlog_item_id,
        details={
            "reason_code": "MODEL_OUTPUT_INVALID",
            "stage": "SCREENING",
        },
    )
    accounted_usage = evidence_ready.usage.model_copy(
        update={
            "input_images": 1,
            "input_pixels": 20_000,
            "input_tokens": 30,
            "output_tokens": 16,
            "provider_latency_ms": 11,
            "retries": 1,
        }
    )
    backlogged = evidence_ready.model_copy(
        update={
            "status": CaseStatus.BACKLOGGED,
            "current_backlog_item_id": backlog_item_id,
            "usage": accounted_usage,
            "timeline": (backlog_entry,),
        }
    )

    assert case_transition_audit(evidence_ready, backlogged) == (
        AuditAction.CASE_STATE_CHANGED,
        ArtifactRef(kind=ArtifactKind.BACKLOG_ITEM, artifact_id=backlog_item_id),
    )

    higher_prior_usage = evidence_ready.model_copy(
        update={"usage": accounted_usage.model_copy(update={"input_tokens": 31})}
    )
    assert case_transition_audit(higher_prior_usage, backlogged) is None


def test_shared_recognizer_preserves_m3_m4_and_m5_dispatch() -> None:
    candidate, pack = _candidate()
    evidence_ready = candidate.model_copy(
        update={
            "status": CaseStatus.EVIDENCE_READY,
            "evidence_packs": (pack,),
        }
    )
    parsed = _parsed(
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        probability=0.95,
        manifest_id=pack.manifest_id,
    )
    screening = _screening(parsed, l1_score=pack.event.l1_score)
    screening_entry = TimelineEntry(
        sequence=0,
        action=AuditAction.CASE_STATE_CHANGED.value,
        stage="SCREENING",
        object_ref=screening.screening_id,
        details={"decision": screening.decision.value},
    )
    screened = evidence_ready.model_copy(
        update={
            "status": CaseStatus.SCREENED,
            "screening_results": (screening,),
            "timeline": (screening_entry,),
        }
    )
    assert case_transition_audit(evidence_ready, screened) == (
        AuditAction.CASE_STATE_CHANGED,
        ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id=screening.screening_id,
        ),
    )

    escalating_output = _parsed(
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        probability=0.5,
        manifest_id=pack.manifest_id,
    )
    escalating_screening = _screening(escalating_output, l1_score=pack.event.l1_score)
    escalated = evidence_ready.model_copy(
        update={
            "status": CaseStatus.ESCALATED,
            "screening_results": (escalating_screening,),
            "timeline": (
                TimelineEntry(
                    sequence=0,
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="SCREENING",
                    object_ref=escalating_screening.screening_id,
                    details={"decision": escalating_screening.decision.value},
                ),
            ),
        }
    )
    hearing_entry = TimelineEntry(
        sequence=1,
        action=AuditAction.CASE_STATE_CHANGED.value,
        stage="HEARING",
        object_ref=escalated.case_id,
        details={"status": CaseStatus.DELIBERATING.value},
    )
    deliberating = escalated.model_copy(
        update={
            "status": CaseStatus.DELIBERATING,
            "timeline": (*escalated.timeline, hearing_entry),
        }
    )
    assert case_transition_audit(escalated, deliberating) == (
        AuditAction.CASE_STATE_CHANGED,
        ArtifactRef(kind=ArtifactKind.CASE, artifact_id=escalated.case_id),
    )

    verdict = _verdict(screening)
    review = _review(verdict)
    ready = screened.model_copy(
        update={
            "status": CaseStatus.READY_FOR_ALERT_POLICY,
            "verdicts": (verdict,),
            "procedural_reviews": (review,),
        }
    )
    alert = AlertDecision(
        alert_id="alert-shared-transition",
        case_id=ready.case_id,
        level=AlertLevel.CONFIRMED,
        recipients=("safety-officer",),
        policy_rule_ids=("m5-alert-policy-v1",),
    )
    close_entry = TimelineEntry(
        sequence=1,
        action=AuditAction.CASE_CLOSED.value,
        stage="ALERT_POLICY",
        object_ref=alert.alert_id,
        details={
            "alert_id": alert.alert_id,
            "disposition": AlertPolicyDisposition.ENQUEUE.value,
            "status": CaseStatus.CLOSED.value,
        },
    )
    closed = ready.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "alerts": (alert,),
            "final_decision": verdict.decision,
            "timeline": (*ready.timeline, close_entry),
        }
    )
    assert case_transition_audit(ready, closed) == (
        AuditAction.CASE_CLOSED,
        ArtifactRef(kind=ArtifactKind.ALERT, artifact_id=alert.alert_id),
    )
