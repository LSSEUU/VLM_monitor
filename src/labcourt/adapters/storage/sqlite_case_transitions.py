"""Pure Case-transition recognition shared by SQLite authority readers."""

from __future__ import annotations

from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    BacklogReasonCode,
    BacklogStatus,
    CaseStatus,
    EvidenceFailureCode,
    ScreeningDecision,
)
from labcourt.contracts.storage import ArtifactRef

from .sqlite_hearing_case_transitions import m4_case_transition_audit
from .sqlite_m5_case_transitions import m5_case_transition_audit


def evidence_failure_timeline_entry(
    *,
    sequence: int,
    case_id: str,
    failure_code: EvidenceFailureCode,
) -> TimelineEntry:
    return TimelineEntry(
        sequence=sequence,
        action=AuditAction.CASE_STATE_CHANGED.value,
        stage="EVIDENCE",
        object_ref=case_id,
        details={"failure_code": failure_code.value},
    )


def evidence_failure_code(
    entry: TimelineEntry,
    *,
    case_id: str,
) -> EvidenceFailureCode | None:
    if (
        entry.action != AuditAction.CASE_STATE_CHANGED.value
        or entry.stage != "EVIDENCE"
        or entry.object_ref != case_id
        or set(entry.details) != {"failure_code"}
    ):
        return None
    value = entry.details["failure_code"]
    if not isinstance(value, str):
        return None
    try:
        return EvidenceFailureCode(value)
    except ValueError:
        return None


def _is_evidence_failure_transition(before: Case, after: Case) -> bool:
    if (
        after.status != CaseStatus.HUMAN_REVIEW
        or len(after.timeline) != len(before.timeline) + 1
        or after.timeline[:-1] != before.timeline
        or evidence_failure_code(after.timeline[-1], case_id=after.case_id) is None
    ):
        return False
    expected = before.model_copy(
        update={
            "status": CaseStatus.HUMAN_REVIEW,
            "timeline": after.timeline,
        }
    )
    return expected == after


def _is_evidence_pack_publication_transition(before: Case, after: Case) -> bool:
    if (
        len(after.evidence_packs) != len(before.evidence_packs) + 1
        or after.evidence_packs[:-1] != before.evidence_packs
    ):
        return False
    latest = after.evidence_packs[-1]
    expected_status = CaseStatus.EVIDENCE_READY if latest.complete else CaseStatus.CANDIDATE
    expected = before.model_copy(
        update={
            "status": expected_status,
            "evidence_packs": after.evidence_packs,
        }
    )
    return expected == after


def _m3_state_transition_object_ref(before: Case, after: Case) -> ArtifactRef | None:
    """Return the audited M3 root when ``after`` is one exact legal append.

    ``SQLiteEvidenceRepository`` remains the read authority for Case aggregates
    even when ``SQLiteM3Repository`` writes their later versions.  Consequently
    its immutable-history validator must understand the M3 transitions rather
    than treating every post-M2 revision as corruption.
    """

    if len(after.timeline) != len(before.timeline) + 1 or after.timeline[:-1] != before.timeline:
        return None
    entry = after.timeline[-1]
    if entry.action != AuditAction.CASE_STATE_CHANGED.value:
        return None

    if (
        before.status == CaseStatus.EVIDENCE_READY
        and after.status in {CaseStatus.SCREENED, CaseStatus.ESCALATED}
        and len(after.screening_results) == len(before.screening_results) + 1
        and after.screening_results[:-1] == before.screening_results
        and all(
            after_value >= before_value
            for before_value, after_value in zip(
                before.usage.model_dump(mode="json").values(),
                after.usage.model_dump(mode="json").values(),
                strict=True,
            )
        )
    ):
        screening = after.screening_results[-1]
        expected_status = (
            CaseStatus.ESCALATED
            if screening.decision == ScreeningDecision.ESCALATE
            else CaseStatus.SCREENED
        )
        expected = before.model_copy(
            update={
                "status": expected_status,
                "usage": after.usage,
                "screening_results": after.screening_results,
                "timeline": after.timeline,
            }
        )
        if (
            after.status == expected_status
            and entry.stage == "SCREENING"
            and entry.object_ref == screening.screening_id
            and entry.details == {"decision": screening.decision.value}
            and expected == after
        ):
            return ArtifactRef(
                kind=ArtifactKind.SCREENING_RESULT,
                artifact_id=screening.screening_id,
            )

    if (
        before.status == CaseStatus.SCREENED
        and after.status
        in {
            CaseStatus.READY_FOR_ALERT_POLICY,
            CaseStatus.REWORK_REQUIRED,
        }
        and len(after.verdicts) == len(before.verdicts) + 1
        and after.verdicts[:-1] == before.verdicts
        and len(after.procedural_reviews) == len(before.procedural_reviews) + 1
        and after.procedural_reviews[:-1] == before.procedural_reviews
    ):
        verdict = after.verdicts[-1]
        review = after.procedural_reviews[-1]
        expected_status = (
            CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
        )
        expected = before.model_copy(
            update={
                "status": expected_status,
                "verdicts": after.verdicts,
                "procedural_reviews": after.procedural_reviews,
                "timeline": after.timeline,
            }
        )
        if (
            after.status == expected_status
            and entry.stage == "PROCEDURAL_GATE"
            and entry.object_ref == review.review_id
            and entry.details
            == {
                "passed": review.passed,
                "verdict_id": verdict.verdict_id,
            }
            and expected == after
        ):
            return ArtifactRef(
                kind=ArtifactKind.PROCEDURAL_REVIEW,
                artifact_id=review.review_id,
            )

    if (
        before.status in {CaseStatus.EVIDENCE_READY, CaseStatus.SCREENED}
        and after.status == CaseStatus.BACKLOGGED
        and after.current_backlog_item_id is not None
        and all(
            after_value >= before_value
            for before_value, after_value in zip(
                before.usage.model_dump(mode="json").values(),
                after.usage.model_dump(mode="json").values(),
                strict=True,
            )
        )
    ):
        expected = before.model_copy(
            update={
                "status": CaseStatus.BACKLOGGED,
                "current_backlog_item_id": after.current_backlog_item_id,
                "usage": after.usage,
                "timeline": after.timeline,
            }
        )
        if (
            entry.stage == "BACKLOG"
            and entry.object_ref == after.current_backlog_item_id
            and set(entry.details) == {"reason_code", "stage"}
            and expected == after
        ):
            return ArtifactRef(
                kind=ArtifactKind.BACKLOG_ITEM,
                artifact_id=after.current_backlog_item_id,
            )

    if before.status == CaseStatus.BACKLOGGED and before.current_backlog_item_id is not None:
        backlog_item_id = before.current_backlog_item_id
        usage_is_monotonic = all(
            after_value >= before_value
            for before_value, after_value in zip(
                before.usage.model_dump(mode="json").values(),
                after.usage.model_dump(mode="json").values(),
                strict=True,
            )
        )

        if (
            after.status == CaseStatus.ESCALATED
            and after.current_backlog_item_id is None
            and len(after.screening_results) == len(before.screening_results) + 1
            and after.screening_results[:-1] == before.screening_results
            and after.verdicts == before.verdicts
            and after.procedural_reviews == before.procedural_reviews
            and usage_is_monotonic
        ):
            screening = after.screening_results[-1]
            expected = before.model_copy(
                update={
                    "status": CaseStatus.ESCALATED,
                    "current_backlog_item_id": None,
                    "usage": after.usage,
                    "screening_results": after.screening_results,
                    "timeline": after.timeline,
                }
            )
            if (
                screening.decision == ScreeningDecision.ESCALATE
                and entry.stage == "BACKLOG"
                and entry.object_ref == screening.screening_id
                and entry.details
                == {
                    "outcome": "SUCCESS",
                    "item_id": backlog_item_id,
                    "decision": ScreeningDecision.ESCALATE.value,
                }
                and expected == after
            ):
                return ArtifactRef(
                    kind=ArtifactKind.SCREENING_RESULT,
                    artifact_id=screening.screening_id,
                )

        screening_append_count = len(after.screening_results) - len(before.screening_results)
        if (
            after.status
            in {
                CaseStatus.READY_FOR_ALERT_POLICY,
                CaseStatus.REWORK_REQUIRED,
            }
            and after.current_backlog_item_id is None
            and screening_append_count in {0, 1}
            and after.screening_results[: len(before.screening_results)] == before.screening_results
            and len(after.verdicts) == len(before.verdicts) + 1
            and after.verdicts[:-1] == before.verdicts
            and len(after.procedural_reviews) == len(before.procedural_reviews) + 1
            and after.procedural_reviews[:-1] == before.procedural_reviews
            and usage_is_monotonic
        ):
            verdict = after.verdicts[-1]
            review = after.procedural_reviews[-1]
            expected_status = (
                CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
            )
            expected = before.model_copy(
                update={
                    "status": expected_status,
                    "current_backlog_item_id": None,
                    "usage": after.usage,
                    "screening_results": after.screening_results,
                    "verdicts": after.verdicts,
                    "procedural_reviews": after.procedural_reviews,
                    "timeline": after.timeline,
                }
            )
            if (
                after.status == expected_status
                and after.screening_results
                and verdict.screening_id == after.screening_results[-1].screening_id
                and after.screening_results[-1].decision != ScreeningDecision.ESCALATE
                and review.reviewed_verdict_id == verdict.verdict_id
                and review.reviewed_verdict_version == verdict.version
                and entry.stage == "BACKLOG"
                and entry.object_ref == review.review_id
                and entry.details
                == {
                    "outcome": "SUCCESS",
                    "item_id": backlog_item_id,
                    "passed": review.passed,
                }
                and expected == after
            ):
                return ArtifactRef(
                    kind=ArtifactKind.PROCEDURAL_REVIEW,
                    artifact_id=review.review_id,
                )

        expected_item_id = (
            before.current_backlog_item_id if after.status == CaseStatus.BACKLOGGED else None
        )
        expected_backlog_status = (
            BacklogStatus.PENDING
            if after.status == CaseStatus.BACKLOGGED
            else BacklogStatus.EXHAUSTED
        )
        expected = before.model_copy(
            update={
                "status": after.status,
                "current_backlog_item_id": expected_item_id,
                "usage": after.usage,
                "timeline": after.timeline,
            }
        )
        if (
            after.status in {CaseStatus.BACKLOGGED, CaseStatus.HUMAN_REVIEW}
            and after.current_backlog_item_id == expected_item_id
            and entry.stage == "BACKLOG"
            and entry.object_ref == before.current_backlog_item_id
            and set(entry.details) == {"outcome", "reason_code", "status", "retry_generation"}
            and entry.details["outcome"] == "FAILURE"
            and entry.details["reason_code"] in {reason.value for reason in BacklogReasonCode}
            and entry.details["status"] == expected_backlog_status.value
            and isinstance(entry.details["retry_generation"], int)
            and entry.details["retry_generation"] >= 0
            and all(
                after_value >= before_value
                for before_value, after_value in zip(
                    before.usage.model_dump(mode="json").values(),
                    after.usage.model_dump(mode="json").values(),
                    strict=True,
                )
            )
            and expected == after
        ):
            return ArtifactRef(
                kind=ArtifactKind.BACKLOG_ITEM,
                artifact_id=before.current_backlog_item_id,
            )

    return None


def case_transition_audit(
    before: Case,
    after: Case,
) -> tuple[AuditAction, ArtifactRef] | None:
    """Return the exact audit action/object for one supported Case transition."""

    case_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=after.case_id)
    if _is_evidence_failure_transition(before, after):
        return AuditAction.CASE_STATE_CHANGED, case_ref
    if _is_evidence_pack_publication_transition(before, after):
        return AuditAction.EVIDENCE_PACK_PUBLISHED, case_ref
    m3_object_ref = _m3_state_transition_object_ref(before, after)
    if m3_object_ref is not None:
        return AuditAction.CASE_STATE_CHANGED, m3_object_ref

    m4_audit = m4_case_transition_audit(before, after)
    if m4_audit is not None:
        return m4_audit
    return m5_case_transition_audit(before, after)


__all__ = [
    "case_transition_audit",
    "evidence_failure_code",
    "evidence_failure_timeline_entry",
]
