from __future__ import annotations

from labcourt.adapters.storage.sqlite_m5_case_transitions import m5_case_transition_audit
from labcourt.contracts.alert_policy import AlertPolicyDisposition
from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.appeals import Appeal
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    AlertLevel,
    AppealStatus,
    ArtifactKind,
    AuditAction,
    CaseStatus,
    VerdictDecision,
)
from labcourt.contracts.storage import ArtifactRef
from tests.contract.test_m3_contracts import (
    RUN_ID,
    _parsed,
    _presence_pack,
    _review,
    _screening,
    _verdict,
)


def _ready_case() -> Case:
    pack = _presence_pack()
    parsed = _parsed(
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        probability=0.95,
        manifest_id=pack.manifest_id,
    )
    screening = _screening(parsed, l1_score=pack.event.l1_score)
    verdict = _verdict(screening)
    review = _review(verdict)
    return Case(
        run_id=RUN_ID,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        event=pack.event,
        evidence_packs=(pack,),
        screening_results=(screening,),
        verdicts=(verdict,),
        procedural_reviews=(review,),
        manifest_id=pack.manifest_id,
    )


def _case_update(case: Case, **updates: object) -> Case:
    payload = case.model_dump(mode="json", exclude_computed_fields=True)
    payload.update(updates)
    return Case.model_validate(payload)


def _close_with_alert(ready: Case) -> Case:
    alert = AlertDecision(
        alert_id="alert-01",
        case_id=ready.case_id,
        level=AlertLevel.CONFIRMED,
        recipients=("safety-officer",),
        policy_rule_ids=("m5-alert-policy-v1",),
    )
    return _case_update(
        ready,
        status=CaseStatus.CLOSED.value,
        alerts=[alert.model_dump(mode="json")],
        final_decision=ready.verdicts[-1].decision.value,
        timeline=[
            TimelineEntry(
                sequence=0,
                action=AuditAction.CASE_CLOSED.value,
                stage="ALERT_POLICY",
                object_ref=alert.alert_id,
                details={
                    "alert_id": alert.alert_id,
                    "disposition": AlertPolicyDisposition.ENQUEUE.value,
                    "status": CaseStatus.CLOSED.value,
                },
            ).model_dump(mode="json")
        ],
    )


def test_close_transition_supports_deliverable_and_typed_no_alert() -> None:
    ready = _ready_case()
    closed = _close_with_alert(ready)
    assert m5_case_transition_audit(ready, closed) == (
        AuditAction.CASE_CLOSED,
        ArtifactRef(kind=ArtifactKind.ALERT, artifact_id="alert-01"),
    )

    no_alert = _case_update(
        ready,
        status=CaseStatus.CLOSED.value,
        final_decision=ready.verdicts[-1].decision.value,
        timeline=[
            TimelineEntry(
                sequence=0,
                action=AuditAction.CASE_CLOSED.value,
                stage="ALERT_POLICY",
                object_ref=ready.case_id,
                details={
                    "alert_id": "NONE",
                    "disposition": AlertPolicyDisposition.CLOSE_NO_ALERT.value,
                    "status": CaseStatus.CLOSED.value,
                },
            ).model_dump(mode="json")
        ],
    )
    assert m5_case_transition_audit(ready, no_alert) == (
        AuditAction.CASE_CLOSED,
        ArtifactRef(kind=ArtifactKind.CASE, artifact_id=ready.case_id),
    )


def test_appeal_versions_are_the_only_supported_post_close_transitions() -> None:
    closed = _close_with_alert(_ready_case())
    submitted_appeal = Appeal(
        appeal_id="appeal-01",
        case_id=closed.case_id,
        status=AppealStatus.SUBMITTED,
        reason="The evidence was interpreted incorrectly.",
        submitted_by="anon-subject",
    )
    submitted = _case_update(
        closed,
        status=CaseStatus.APPEALED.value,
        appeals=[submitted_appeal.model_dump(mode="json")],
        timeline=[
            *(entry.model_dump(mode="json") for entry in closed.timeline),
            TimelineEntry(
                sequence=1,
                action=AuditAction.CASE_STATE_CHANGED.value,
                stage="APPEAL",
                object_ref=submitted_appeal.appeal_id,
                details={
                    "final_decision": closed.final_decision.value,
                    "status": AppealStatus.SUBMITTED.value,
                    "version": 1,
                },
            ).model_dump(mode="json"),
        ],
    )
    assert m5_case_transition_audit(closed, submitted) == (
        AuditAction.CASE_STATE_CHANGED,
        ArtifactRef(kind=ArtifactKind.APPEAL, artifact_id="appeal-01"),
    )

    review_appeal = submitted_appeal.model_copy(update={"status": AppealStatus.UNDER_REVIEW})
    under_review = _case_update(
        submitted,
        appeals=[review_appeal.model_dump(mode="json")],
        timeline=[
            *(entry.model_dump(mode="json") for entry in submitted.timeline),
            TimelineEntry(
                sequence=2,
                action=AuditAction.CASE_STATE_CHANGED.value,
                stage="APPEAL",
                object_ref=review_appeal.appeal_id,
                details={
                    "final_decision": submitted.final_decision.value,
                    "status": AppealStatus.UNDER_REVIEW.value,
                    "version": 2,
                },
            ).model_dump(mode="json"),
        ],
    )
    assert m5_case_transition_audit(submitted, under_review) is not None

    overturned_appeal = Appeal(
        appeal_id=review_appeal.appeal_id,
        case_id=review_appeal.case_id,
        status=AppealStatus.OVERTURNED,
        reason=review_appeal.reason,
        submitted_by=review_appeal.submitted_by,
        reviewer_id="safety-officer",
        resolution_summary="Human review confirms the original decision should be reversed.",
        resolved_decision=VerdictDecision.NOT_ESTABLISHED,
    )
    overturned = _case_update(
        under_review,
        status=CaseStatus.APPEAL_RESOLVED.value,
        alerts=[
            alert.model_copy(update={"rescinded": True}).model_dump(mode="json")
            for alert in under_review.alerts
        ],
        appeals=[overturned_appeal.model_dump(mode="json")],
        final_decision=VerdictDecision.NOT_ESTABLISHED.value,
        timeline=[
            *(entry.model_dump(mode="json") for entry in under_review.timeline),
            TimelineEntry(
                sequence=3,
                action=AuditAction.CASE_STATE_CHANGED.value,
                stage="APPEAL",
                object_ref=overturned_appeal.appeal_id,
                details={
                    "final_decision": VerdictDecision.NOT_ESTABLISHED.value,
                    "status": AppealStatus.OVERTURNED.value,
                    "version": 3,
                },
            ).model_dump(mode="json"),
        ],
    )
    assert m5_case_transition_audit(under_review, overturned) == (
        AuditAction.CASE_STATE_CHANGED,
        ArtifactRef(kind=ArtifactKind.APPEAL, artifact_id="appeal-01"),
    )


def test_transition_recognizer_rejects_rewrites_and_wrong_terminal_meaning() -> None:
    ready = _ready_case()
    closed = _close_with_alert(ready)
    rewritten = closed.model_copy(update={"usage": closed.usage.model_copy(update={"retries": 1})})
    assert m5_case_transition_audit(ready, rewritten) is None

    wrong_action = _case_update(
        closed,
        timeline=[
            closed.timeline[0]
            .model_copy(update={"action": AuditAction.CASE_STATE_CHANGED.value})
            .model_dump(mode="json")
        ],
    )
    assert m5_case_transition_audit(ready, wrong_action) is None
