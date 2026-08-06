"""Pure M5 Case-transition recognition for the shared SQLite read authority."""

from __future__ import annotations

from labcourt.contracts.alert_policy import AlertPolicyDisposition
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    AppealStatus,
    ArtifactKind,
    AuditAction,
    CaseStatus,
)
from labcourt.contracts.storage import ArtifactRef


def _single_timeline_append(before: Case, after: Case) -> bool:
    return (
        len(after.timeline) == len(before.timeline) + 1 and after.timeline[:-1] == before.timeline
    )


def _close_transition(
    before: Case,
    after: Case,
) -> tuple[AuditAction, ArtifactRef] | None:
    if before.status != CaseStatus.READY_FOR_ALERT_POLICY or after.status != CaseStatus.CLOSED:
        return None
    if not before.verdicts or not before.procedural_reviews:
        return None
    if after.final_decision != before.verdicts[-1].decision:
        return None

    entry = after.timeline[-1]
    if entry.action != AuditAction.CASE_CLOSED.value or entry.stage != "ALERT_POLICY":
        return None
    if set(entry.details) != {"alert_id", "disposition", "status"}:
        return None
    if entry.details["status"] != CaseStatus.CLOSED.value:
        return None
    try:
        disposition = AlertPolicyDisposition(str(entry.details["disposition"]))
    except ValueError:
        return None

    if disposition == AlertPolicyDisposition.CLOSE_NO_ALERT:
        if after.alerts != before.alerts or entry.details["alert_id"] != "NONE":
            return None
        expected_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=after.case_id)
    else:
        if len(after.alerts) != len(before.alerts) + 1 or after.alerts[:-1] != before.alerts:
            return None
        alert = after.alerts[-1]
        if entry.details["alert_id"] != alert.alert_id or entry.object_ref != alert.alert_id:
            return None
        if disposition == AlertPolicyDisposition.ENQUEUE and alert.suppressed_by_cooldown:
            return None
        if disposition == AlertPolicyDisposition.SUPPRESSED_MERGED and (
            not alert.suppressed_by_cooldown or alert.merged_into_alert_id is None
        ):
            return None
        expected_ref = ArtifactRef(kind=ArtifactKind.ALERT, artifact_id=alert.alert_id)

    expected = before.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "alerts": after.alerts,
            "final_decision": after.final_decision,
            "timeline": after.timeline,
        }
    )
    if entry.object_ref != expected_ref.artifact_id or expected != after:
        return None
    return AuditAction.CASE_CLOSED, expected_ref


def _appeal_transition(
    before: Case,
    after: Case,
) -> tuple[AuditAction, ArtifactRef] | None:
    if after.final_decision is None:
        return None
    entry = after.timeline[-1]
    if entry.action != AuditAction.CASE_STATE_CHANGED.value or entry.stage != "APPEAL":
        return None
    if set(entry.details) != {"final_decision", "status", "version"}:
        return None
    version = entry.details["version"]
    if not isinstance(version, int) or isinstance(version, bool):
        return None

    if before.status == CaseStatus.CLOSED:
        if (
            after.status != CaseStatus.APPEALED
            or len(after.appeals) != len(before.appeals) + 1
            or after.appeals[:-1] != before.appeals
            or version != 1
        ):
            return None
        appeal = after.appeals[-1]
        if appeal.status != AppealStatus.SUBMITTED:
            return None
        if after.final_decision != before.final_decision:
            return None
    elif before.status == CaseStatus.APPEALED:
        if not before.appeals or len(after.appeals) != len(before.appeals):
            return None
        if after.appeals[:-1] != before.appeals[:-1]:
            return None
        appeal = after.appeals[-1]
        if appeal.appeal_id != before.appeals[-1].appeal_id:
            return None
        if appeal.status == AppealStatus.UNDER_REVIEW:
            if after.status != CaseStatus.APPEALED or version != 2:
                return None
            if after.final_decision != before.final_decision:
                return None
        elif appeal.status in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}:
            if after.status != CaseStatus.APPEAL_RESOLVED or version != 3:
                return None
            if appeal.status == AppealStatus.UPHELD and (
                after.final_decision != before.final_decision
            ):
                return None
            if appeal.status == AppealStatus.OVERTURNED and (
                after.final_decision == before.final_decision
            ):
                return None
        else:
            return None
    else:
        return None

    if (
        entry.object_ref != appeal.appeal_id
        or entry.details["status"] != appeal.status.value
        or entry.details["final_decision"] != after.final_decision.value
    ):
        return None
    if appeal.status != AppealStatus.OVERTURNED and after.alerts != before.alerts:
        return None
    if appeal.status == AppealStatus.OVERTURNED:
        if len(after.alerts) != len(before.alerts):
            return None
        for old, current in zip(before.alerts, after.alerts, strict=True):
            if current != old.model_copy(update={"rescinded": True}):
                return None

    expected = before.model_copy(
        update={
            "status": after.status,
            "alerts": after.alerts,
            "appeals": after.appeals,
            "final_decision": after.final_decision,
            "timeline": after.timeline,
        }
    )
    if expected != after:
        return None
    return (
        AuditAction.CASE_STATE_CHANGED,
        ArtifactRef(kind=ArtifactKind.APPEAL, artifact_id=appeal.appeal_id),
    )


def m5_case_transition_audit(
    before: Case,
    after: Case,
) -> tuple[AuditAction, ArtifactRef] | None:
    """Return the exact M5 audit shape for one adjacent aggregate revision."""

    if not _single_timeline_append(before, after):
        return None
    return _close_transition(before, after) or _appeal_transition(before, after)


__all__ = ["m5_case_transition_audit"]
