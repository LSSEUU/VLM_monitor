"""One-shot persistent dispatch claim authorities for M8 notification workers."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import ModelWrapValidatorHandler, computed_field, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
    M8NotificationInitiatorKind,
)
from labcourt.contracts.m8_notification_persistence import M8NotificationCommitReceiptV1
from labcourt.contracts.m8_notifications import M8NotificationStatus

MAX_M8_NOTIFICATION_DISPATCH_CLAIM_SECONDS = 300


class M8NotificationDispatchClaimState(StrEnum):
    CALL_IN_PROGRESS = "CALL_IN_PROGRESS"
    CLAIMED = "CLAIMED"
    COMPLETED = "COMPLETED"
    EXPIRED_PRE_CALL = "EXPIRED_PRE_CALL"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 notification dispatch {name} must be timezone-aware UTC")
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
    if not any(present for present, _claimed in claims.values()):
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(
                f"serialized {name} conflicts with derived M8 dispatch claim authority"
            )


class M8NotificationDispatchClaimReceiptV1(FrozenContractModel):
    """Exclusive claim for one exact QUEUED notification version and attempt."""

    schema_version: Literal["m8-notification-dispatch-claim-receipt-v1"] = (
        "m8-notification-dispatch-claim-receipt-v1"
    )
    request: M8NotificationDispatchRequestV1
    worker_owner_sha256: Sha256Hex
    claimed_at: datetime
    lease_expires_at: datetime
    claim_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @field_validator("claimed_at", "lease_expires_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return _require_utc(value, "claim time")

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
                "notification_id",
                "source_notification_version",
                "attempt_number",
                "dispatch_call_claimed",
                "dispatch_call_permitted",
                "automatic_takeover_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "claim_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_claim_window(self) -> Self:
        if self.request.dispatched_at != self.claimed_at:
            raise ValueError("M8 dispatch request time must equal its persisted claim time")
        minimum_expiry = self.claimed_at + timedelta(
            milliseconds=self.request.timeout_ms,
            seconds=1,
        )
        maximum_expiry = self.claimed_at + timedelta(
            seconds=MAX_M8_NOTIFICATION_DISPATCH_CLAIM_SECONDS
        )
        if not minimum_expiry <= self.lease_expires_at <= maximum_expiry:
            raise ValueError("M8 notification dispatch claim lease is outside the bounded window")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_id(self) -> Sha256Hex:
        return self.request.plan.notification_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_notification_version(self) -> int:
        return self.request.source_notification_version

    @computed_field  # type: ignore[prop-decorator]
    @property
    def attempt_number(self) -> int:
        return self.request.attempt_number

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dispatch_call_claimed(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dispatch_call_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_takeover_permitted(self) -> bool:
        return False

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
    def claim_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-dispatch-claim-receipt",
                1,
                self.request.dispatch_request_id,
                self.worker_owner_sha256,
                _canonical_utc(self.claimed_at),
                _canonical_utc(self.lease_expires_at),
                self.claim_manifest_id,
                self.repository_manifest_id,
                self.dispatch_call_claimed,
                self.dispatch_call_permitted,
                self.automatic_takeover_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


class M8NotificationDispatchCallFenceReceiptV1(FrozenContractModel):
    """Append-only proof that the one-shot provider call boundary was crossed."""

    schema_version: Literal["m8-notification-dispatch-call-fence-receipt-v1"] = (
        "m8-notification-dispatch-call-fence-receipt-v1"
    )
    claim: M8NotificationDispatchClaimReceiptV1
    dispatch_authorization_id: Sha256Hex
    fenced_at: datetime
    call_fence_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @field_validator("fenced_at")
    @classmethod
    def validate_fenced_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "call fenced_at")

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
                "external_call_boundary_crossed",
                "additional_dispatch_call_permitted",
                "automatic_retry_permitted",
                "call_fence_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_fence(self) -> Self:
        if self.repository_manifest_id != self.claim.repository_manifest_id:
            raise ValueError("M8 dispatch call fence crosses repositories")
        if not self.claim.claimed_at <= self.fenced_at < self.claim.lease_expires_at:
            raise ValueError("M8 dispatch call fence is outside its live claim")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_call_boundary_crossed(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def additional_dispatch_call_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_retry_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def call_fence_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-dispatch-call-fence-receipt",
                1,
                self.claim.claim_id,
                self.dispatch_authorization_id,
                _canonical_utc(self.fenced_at),
                self.call_fence_manifest_id,
                self.repository_manifest_id,
                self.external_call_boundary_crossed,
                self.additional_dispatch_call_permitted,
                self.automatic_retry_permitted,
            ]
        )


class M8NotificationDispatchCompletionReceiptV1(FrozenContractModel):
    """Atomic binding of a fenced provider result to its notification transition."""

    schema_version: Literal["m8-notification-dispatch-completion-receipt-v1"] = (
        "m8-notification-dispatch-completion-receipt-v1"
    )
    claim: M8NotificationDispatchClaimReceiptV1
    call_fence: M8NotificationDispatchCallFenceReceiptV1
    dispatch_result: M8NotificationDispatchResultV1
    notification_commit: M8NotificationCommitReceiptV1
    committed_at: datetime
    completion_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @field_validator("committed_at")
    @classmethod
    def validate_committed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "completion committed_at")

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
                "notification_transition_committed",
                "unknown_delivery",
                "additional_dispatch_call_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "completion_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_completion(self) -> Self:
        if self.call_fence.claim != self.claim:
            raise ValueError("M8 dispatch completion grafts another claim fence")
        if self.dispatch_result.request != self.claim.request:
            raise ValueError("M8 dispatch completion result belongs to another claim")
        if any(
            manifest != self.repository_manifest_id
            for manifest in (
                self.claim.repository_manifest_id,
                self.call_fence.repository_manifest_id,
                self.notification_commit.repository_manifest_id,
            )
        ):
            raise ValueError("M8 dispatch completion crosses repositories")
        transition = self.notification_commit.audit_event.transition_command
        if (
            transition is None
            or transition.dispatch_result != self.dispatch_result
            or transition.initiator_kind != M8NotificationInitiatorKind.CHANNEL_ADAPTER
        ):
            raise ValueError("M8 dispatch completion lacks the exact channel transition")
        expected_action = (
            M8NotificationAction.RECORD_SENT
            if self.dispatch_result.disposition == M8NotificationDispatchDisposition.ACCEPTED
            else M8NotificationAction.RECORD_FAILED
        )
        expected_status = (
            M8NotificationStatus.SENT
            if self.dispatch_result.disposition == M8NotificationDispatchDisposition.ACCEPTED
            else M8NotificationStatus.FAILED
        )
        if (
            transition.action != expected_action
            or self.notification_commit.status != expected_status
            or self.notification_commit.notification_version
            != self.claim.source_notification_version + 1
        ):
            raise ValueError("M8 dispatch completion notification outcome conflicts with result")
        if self.committed_at < self.dispatch_result.completed_at:
            raise ValueError("M8 dispatch completion cannot predate its provider result")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_transition_committed(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def unknown_delivery(self) -> bool:
        return (
            self.dispatch_result.disposition == M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def additional_dispatch_call_permitted(self) -> bool:
        return False

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
    def completion_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-dispatch-completion-receipt",
                1,
                self.claim.claim_id,
                self.call_fence.call_fence_id,
                self.dispatch_result.dispatch_result_id,
                self.notification_commit.commit_receipt_id,
                _canonical_utc(self.committed_at),
                self.completion_manifest_id,
                self.repository_manifest_id,
                self.notification_transition_committed,
                self.unknown_delivery,
                self.additional_dispatch_call_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


class M8NotificationDispatchClaimStatusV1(FrozenContractModel):
    """Time-relative claim status; stale call fences always require reconciliation."""

    schema_version: Literal["m8-notification-dispatch-claim-status-v1"] = (
        "m8-notification-dispatch-claim-status-v1"
    )
    claim: M8NotificationDispatchClaimReceiptV1
    call_fence: M8NotificationDispatchCallFenceReceiptV1 | None = None
    completion: M8NotificationDispatchCompletionReceiptV1 | None = None
    assessed_at: datetime
    repository_manifest_id: Sha256Hex

    @field_validator("assessed_at")
    @classmethod
    def validate_assessed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "claim status assessed_at")

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
                "state",
                "new_dispatch_call_permitted",
                "automatic_retry_permitted",
                "reconciliation_required",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "status_id",
            ),
        )
        status = handler(payload)
        _verify_computed_claims(status, claims)
        return status

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.assessed_at < self.claim.claimed_at:
            raise ValueError("M8 dispatch claim status cannot predate the claim")
        if self.repository_manifest_id != self.claim.repository_manifest_id:
            raise ValueError("M8 dispatch claim status crosses repositories")
        if self.call_fence is not None and self.call_fence.claim != self.claim:
            raise ValueError("M8 dispatch claim status grafts another call fence")
        if self.completion is not None and (
            self.call_fence is None
            or self.completion.claim != self.claim
            or self.completion.call_fence != self.call_fence
        ):
            raise ValueError("M8 dispatch claim status grafts another completion")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def state(self) -> M8NotificationDispatchClaimState:
        if self.completion is not None:
            return M8NotificationDispatchClaimState.COMPLETED
        if self.call_fence is not None:
            if self.assessed_at < self.claim.lease_expires_at:
                return M8NotificationDispatchClaimState.CALL_IN_PROGRESS
            return M8NotificationDispatchClaimState.RECONCILIATION_REQUIRED
        if self.assessed_at < self.claim.lease_expires_at:
            return M8NotificationDispatchClaimState.CLAIMED
        return M8NotificationDispatchClaimState.EXPIRED_PRE_CALL

    @computed_field  # type: ignore[prop-decorator]
    @property
    def new_dispatch_call_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_retry_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reconciliation_required(self) -> bool:
        return self.state == M8NotificationDispatchClaimState.RECONCILIATION_REQUIRED

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
    def status_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-dispatch-claim-status",
                1,
                self.claim.claim_id,
                self.call_fence.call_fence_id if self.call_fence is not None else None,
                self.completion.completion_id if self.completion is not None else None,
                _canonical_utc(self.assessed_at),
                self.repository_manifest_id,
                self.state,
                self.new_dispatch_call_permitted,
                self.automatic_retry_permitted,
                self.reconciliation_required,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = [
    "MAX_M8_NOTIFICATION_DISPATCH_CLAIM_SECONDS",
    "M8NotificationDispatchCallFenceReceiptV1",
    "M8NotificationDispatchClaimReceiptV1",
    "M8NotificationDispatchClaimState",
    "M8NotificationDispatchClaimStatusV1",
    "M8NotificationDispatchCompletionReceiptV1",
]
