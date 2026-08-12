"""M8 deterministic response-deadline and escalation assessment authority."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import ModelWrapValidatorHandler, computed_field, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_notification_persistence import M8NotificationCommitReceiptV1
from labcourt.contracts.m8_notifications import M8NotificationStatus


class M8NotificationEscalationOutcome(StrEnum):
    NOT_DUE = "NOT_DUE"
    OVERDUE = "OVERDUE"
    RESPONSE_SATISFIED = "RESPONSE_SATISFIED"


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 {name} must be timezone-aware UTC")
    return value


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(
                f"serialized {name} conflicts with derived M8 notification escalation authority"
            )


class M8NotificationEscalationAssessmentV1(FrozenContractModel):
    """Read-only overdue assessment over one exact persisted notification version."""

    schema_version: Literal["m8-notification-escalation-assessment-v1"] = (
        "m8-notification-escalation-assessment-v1"
    )
    source_notification: M8NotificationCommitReceiptV1
    evaluated_at: datetime
    evaluator_manifest_id: Sha256Hex

    @field_validator("evaluated_at")
    @classmethod
    def validate_evaluated_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "notification escalation evaluated_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "response_due_at",
                "outcome",
                "overdue_seconds",
                "routing_roles",
                "notification_plan_recommended",
                "system_queue_permitted_by_policy",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "assessment_id",
            ),
        )
        assessment = handler(payload)
        _verify_computed_claims(assessment, claims)
        return assessment

    @computed_field  # type: ignore[prop-decorator]
    @property
    def response_due_at(self) -> datetime:
        return self.source_notification.audit_event.notification_authority.plan.response_due_at

    @computed_field  # type: ignore[prop-decorator]
    @property
    def outcome(self) -> M8NotificationEscalationOutcome:
        if self.source_notification.status in {
            M8NotificationStatus.ACKNOWLEDGED,
            M8NotificationStatus.RESPONDED,
        }:
            return M8NotificationEscalationOutcome.RESPONSE_SATISFIED
        if self.evaluated_at < self.response_due_at:
            return M8NotificationEscalationOutcome.NOT_DUE
        return M8NotificationEscalationOutcome.OVERDUE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def overdue_seconds(self) -> int:
        if self.outcome != M8NotificationEscalationOutcome.OVERDUE:
            return 0
        return (self.evaluated_at - self.response_due_at) // timedelta(seconds=1)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def routing_roles(self) -> tuple[M8ActorRole, ...]:
        if self.outcome != M8NotificationEscalationOutcome.OVERDUE:
            return ()
        authority = self.source_notification.audit_event.notification_authority
        policy = authority.plan.escalation_policy
        return policy.escalation_roles

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_plan_recommended(self) -> bool:
        return self.outcome == M8NotificationEscalationOutcome.OVERDUE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def system_queue_permitted_by_policy(self) -> bool:
        policy = self.source_notification.audit_event.notification_authority.plan.escalation_policy
        return self.notification_plan_recommended and not policy.requires_human_send_confirmation

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def assessment_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-escalation-assessment",
                1,
                self.source_notification.commit_receipt_id,
                _canonical_utc(self.evaluated_at),
                self.evaluator_manifest_id,
                _canonical_utc(self.response_due_at),
                self.outcome,
                self.overdue_seconds,
                [role.value for role in self.routing_roles],
                self.notification_plan_recommended,
                self.system_queue_permitted_by_policy,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = [
    "M8NotificationEscalationAssessmentV1",
    "M8NotificationEscalationOutcome",
]
