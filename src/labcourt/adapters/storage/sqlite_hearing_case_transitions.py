"""Pure M4 Case-transition recognition for the shared SQLite read authority."""

from __future__ import annotations

from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    AcquisitionAction,
    ArtifactKind,
    AuditAction,
    BacklogReasonCode,
    CaseStatus,
)
from labcourt.contracts.storage import ArtifactRef


def m4_case_transition_audit(
    before: Case,
    after: Case,
) -> tuple[AuditAction, ArtifactRef] | None:
    """Return the exact M4 audit shape for one adjacent aggregate revision."""

    if len(after.timeline) != len(before.timeline) + 1 or after.timeline[:-1] != before.timeline:
        return None
    entry = after.timeline[-1]
    if entry.action != AuditAction.CASE_STATE_CHANGED.value:
        return None

    case_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=after.case_id)
    if (
        before.status in {CaseStatus.ESCALATED, CaseStatus.REWORK_REQUIRED}
        and after.status == CaseStatus.DELIBERATING
        and after.current_backlog_item_id is None
        and entry.stage == "HEARING"
        and entry.details == {"status": CaseStatus.DELIBERATING.value}
    ):
        expected = before.model_copy(
            update={
                "status": after.status,
                "current_backlog_item_id": after.current_backlog_item_id,
                "timeline": after.timeline,
            }
        )
        if expected == after:
            return AuditAction.CASE_STATE_CHANGED, case_ref

    if (
        before.status == CaseStatus.REWORK_REQUIRED
        and after.status == CaseStatus.DELIBERATING
        and after.current_backlog_item_id is None
        and entry.stage == "HEARING"
        and set(entry.details) == {"rework_index", "status"}
        and isinstance(entry.details["rework_index"], int)
        and not isinstance(entry.details["rework_index"], bool)
        and 1 <= entry.details["rework_index"] <= 2
        and entry.details["status"] == CaseStatus.DELIBERATING.value
    ):
        expected = before.model_copy(
            update={
                "status": after.status,
                "current_backlog_item_id": after.current_backlog_item_id,
                "timeline": after.timeline,
            }
        )
        if expected == after:
            return (
                AuditAction.CASE_STATE_CHANGED,
                ArtifactRef(
                    kind=ArtifactKind.PROCEDURAL_REVIEW,
                    artifact_id=before.procedural_reviews[-1].review_id,
                ),
            )

    if (
        before.status == CaseStatus.DELIBERATING
        and after.status in {CaseStatus.READY_FOR_ALERT_POLICY, CaseStatus.REWORK_REQUIRED}
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
            and entry.details == {"passed": review.passed, "verdict_id": verdict.verdict_id}
            and expected == after
        ):
            return (
                AuditAction.CASE_STATE_CHANGED,
                ArtifactRef(
                    kind=ArtifactKind.PROCEDURAL_REVIEW,
                    artifact_id=review.review_id,
                ),
            )

    if (
        before.status == CaseStatus.DELIBERATING
        and after.status == CaseStatus.DELIBERATING
        and len(after.evidence_packs) == len(before.evidence_packs) + 1
        and after.evidence_packs[:-1] == before.evidence_packs
    ):
        pack = after.evidence_packs[-1]
        expected = before.model_copy(
            update={"evidence_packs": after.evidence_packs, "timeline": after.timeline}
        )
        if (
            entry.stage == "HEARING"
            and set(entry.details)
            == {"action", "evidence_pack_id", "evidence_pack_version", "tool_receipt_id"}
            and entry.details["evidence_pack_id"] == pack.pack_id
            and entry.details["evidence_pack_version"] == pack.version
            and entry.details["action"] in {action.value for action in AcquisitionAction}
            and isinstance(entry.details["tool_receipt_id"], str)
            and len(entry.details["tool_receipt_id"]) == 64
            and all(
                character in "0123456789abcdef" for character in entry.details["tool_receipt_id"]
            )
            and expected == after
        ):
            return AuditAction.EVIDENCE_PACK_PUBLISHED, case_ref

    if before.status == CaseStatus.DELIBERATING and after.status == CaseStatus.BACKLOGGED:
        retry_generation = entry.details.get("retry_generation")
        role = entry.details.get("role")
        expected = before.model_copy(
            update={
                "status": CaseStatus.BACKLOGGED,
                "current_backlog_item_id": after.current_backlog_item_id,
                "timeline": after.timeline,
            }
        )
        if (
            after.current_backlog_item_id is not None
            and entry.stage == "BACKLOG"
            and entry.object_ref == after.current_backlog_item_id
            and set(entry.details) == {"reason_code", "retry_generation", "role", "status"}
            and entry.details["status"] == CaseStatus.BACKLOGGED.value
            and entry.details["reason_code"] in {reason.value for reason in BacklogReasonCode}
            and role in {"PROSECUTOR", "DEFENDER", "JUDGE"}
            and isinstance(retry_generation, int)
            and not isinstance(retry_generation, bool)
            and retry_generation in {0, 1}
            and expected == after
        ):
            return (
                AuditAction.CASE_STATE_CHANGED,
                ArtifactRef(
                    kind=ArtifactKind.BACKLOG_ITEM,
                    artifact_id=after.current_backlog_item_id,
                ),
            )

    if before.status == CaseStatus.BACKLOGGED and before.current_backlog_item_id is not None:
        backlog_ref = ArtifactRef(
            kind=ArtifactKind.BACKLOG_ITEM,
            artifact_id=before.current_backlog_item_id,
        )
        retry_generation = entry.details.get("retry_generation")
        valid_generation = (
            isinstance(retry_generation, int)
            and not isinstance(retry_generation, bool)
            and retry_generation >= 0
        )
        if after.status == CaseStatus.BACKLOGGED:
            expected = before.model_copy(update={"timeline": after.timeline})
            if (
                after.current_backlog_item_id == before.current_backlog_item_id
                and entry.stage == "BACKLOG"
                and entry.object_ref == before.current_backlog_item_id
                and set(entry.details) == {"outcome", "reason_code", "status", "retry_generation"}
                and entry.details["outcome"] == "FAILURE"
                and entry.details["reason_code"] in {reason.value for reason in BacklogReasonCode}
                and entry.details["status"] == "PENDING"
                and valid_generation
                and expected == after
            ):
                return AuditAction.CASE_STATE_CHANGED, backlog_ref
        elif after.status == CaseStatus.DELIBERATING:
            expected = before.model_copy(
                update={
                    "status": CaseStatus.DELIBERATING,
                    "current_backlog_item_id": None,
                    "timeline": after.timeline,
                }
            )
            if (
                entry.stage == "BACKLOG"
                and entry.object_ref == before.current_backlog_item_id
                and set(entry.details) == {"outcome", "role", "status", "retry_generation"}
                and entry.details["outcome"] == "SUCCESS"
                and entry.details["role"] in {"PROSECUTOR", "DEFENDER", "JUDGE"}
                and entry.details["status"] == CaseStatus.DELIBERATING.value
                and valid_generation
                and expected == after
            ):
                return AuditAction.CASE_STATE_CHANGED, backlog_ref
        elif after.status == CaseStatus.HUMAN_REVIEW:
            expected = before.model_copy(
                update={
                    "status": CaseStatus.HUMAN_REVIEW,
                    "current_backlog_item_id": None,
                    "timeline": after.timeline,
                }
            )
            if (
                entry.stage == "BACKLOG"
                and entry.object_ref == before.current_backlog_item_id
                and set(entry.details) == {"outcome", "reason_code", "status", "retry_generation"}
                and entry.details["outcome"] == "FAILURE"
                and entry.details["reason_code"] in {reason.value for reason in BacklogReasonCode}
                and entry.details["status"] == "EXHAUSTED"
                and valid_generation
                and expected == after
            ):
                return AuditAction.CASE_STATE_CHANGED, backlog_ref
            if (
                entry.stage == "HEARING"
                and set(entry.details) == {"reason", "hearing_session_id", "judge_cycle"}
                and entry.details["reason"] == "ACQUISITION_LIMIT_EXHAUSTED"
                and expected == after
            ):
                return AuditAction.CASE_STATE_CHANGED, backlog_ref

    if (
        before.status
        in {
            CaseStatus.DELIBERATING,
            CaseStatus.REWORK_REQUIRED,
            CaseStatus.BACKLOGGED,
        }
        and after.status == CaseStatus.HUMAN_REVIEW
    ):
        expected = before.model_copy(
            update={
                "status": CaseStatus.HUMAN_REVIEW,
                "current_backlog_item_id": None,
                "timeline": after.timeline,
            }
        )
        if (
            entry.stage == "HEARING"
            and set(entry.details) == {"reason", "hearing_session_id", "judge_cycle"}
            and expected == after
        ):
            return AuditAction.CASE_STATE_CHANGED, case_ref
    return None


__all__ = ["m4_case_transition_audit"]
