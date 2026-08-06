"""Additive M5 alert-policy, outbox, and at-least-once delivery contracts.

The established ``AlertDecision`` and ``EmergencySafetyIncident`` wire shapes are
intentionally reused unchanged.  These contracts add immutable authority around
them so future persistence can close a Case and enqueue an alert atomically.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from fractions import Fraction
from math import gcd
from typing import Literal, Self, TypeVar

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.alerts import (
    AlertDecision,
    DeliveryReceipt,
    EmergencySafetyIncident,
)
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    AlertLevel,
    CaseStatus,
    RiskLevel,
    SafetySignalType,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import (
    ReferenceToken,
    TrackRef,
    parse_track_ref,
    require_reference_token,
)

ALERT_POLICY_VERSION: Literal["alert-policy-v1"] = "alert-policy-v1"
DISABLED_REPEAT_MODE: Literal["DISABLED_UNTRUSTED_DEMO"] = "DISABLED_UNTRUSTED_DEMO"
MAX_ALERT_DISPATCH_ATTEMPTS = 3

_ContractT = TypeVar("_ContractT", bound=FrozenContractModel)

_DIRECT_SIGNAL_VIOLATIONS: dict[SafetySignalType, ViolationType] = {
    SafetySignalType.OPEN_FLAME: ViolationType.OPEN_FLAME,
    SafetySignalType.SMOKE: ViolationType.SMOKE_ABNORMAL,
}


class AlertPolicyFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_CASE_STATE = "INVALID_CASE_STATE"
    REVIEW_AUTHORITY_MISMATCH = "REVIEW_AUTHORITY_MISMATCH"
    MANIFEST_AUTHORITY_MISMATCH = "MANIFEST_AUTHORITY_MISMATCH"
    CONFIG_AUTHORITY_MISMATCH = "CONFIG_AUTHORITY_MISMATCH"
    STREAM_AUTHORITY_MISMATCH = "STREAM_AUTHORITY_MISMATCH"
    ZONE_AUTHORITY_MISMATCH = "ZONE_AUTHORITY_MISMATCH"
    COOLDOWN_FRAME_REGRESSION = "COOLDOWN_FRAME_REGRESSION"
    EMERGENCY_DELIVERY_AUTHORITY_MISMATCH = "EMERGENCY_DELIVERY_AUTHORITY_MISMATCH"


class AlertOutboxPriority(StrEnum):
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertChannelIdempotencyGuarantee(StrEnum):
    NONE = "NONE"
    EXACT_ALERT_ID = "EXACT_ALERT_ID"


class AlertDispatchDisposition(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    UNKNOWN_DELIVERY = "UNKNOWN_DELIVERY"


class AlertDispatchContinuation(StrEnum):
    CLOSED = "CLOSED"
    RETRY_ALLOWED = "RETRY_ALLOWED"
    ATTENTION_REQUIRED = "ATTENTION_REQUIRED"


class AlertDispatchFailureCode(StrEnum):
    CHANNEL_EXCEPTION = "CHANNEL_EXCEPTION"
    CHANNEL_DEFINITELY_NOT_SENT = "CHANNEL_DEFINITELY_NOT_SENT"
    CHANNEL_REJECTED = "CHANNEL_REJECTED"
    RECEIPT_MISMATCH = "RECEIPT_MISMATCH"
    LEASE_EXPIRED = "LEASE_EXPIRED"


class AlertPolicyDisposition(StrEnum):
    ENQUEUE = "ENQUEUE"
    SUPPRESSED_MERGED = "SUPPRESSED_MERGED"
    CLOSE_NO_ALERT = "CLOSE_NO_ALERT"


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware UTC")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{name} must use UTC")
    return value


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _ceil_cooldown_frames(seconds: float, fps_num: int, fps_den: int) -> int:
    duration = Fraction(Decimal(str(seconds)))
    frames = duration * fps_num / fps_den
    return (frames.numerator + frames.denominator - 1) // frames.denominator


def _validate_claimed_digest(
    value: object,
    handler: ModelWrapValidatorHandler[_ContractT],
    *,
    field_name: str,
) -> _ContractT:
    if not isinstance(value, dict):
        return handler(value)
    payload = dict(value)
    claimed_present = field_name in payload
    claimed = payload.pop(field_name, None)
    model = handler(payload)
    if claimed_present and (not isinstance(claimed, str) or claimed != getattr(model, field_name)):
        raise ValueError(f"serialized {field_name} does not match contract content")
    return model


class AlertCooldownKey(FrozenContractModel):
    """Frame-space deduplication key scoped by the complete anonymous track ref."""

    zone_id: ReferenceToken
    violation_type: ViolationType
    track_ref: TrackRef

    @field_validator("zone_id")
    @classmethod
    def validate_zone_id(cls, value: str) -> str:
        return require_reference_token(value, "alert cooldown zone")

    @field_validator("track_ref")
    @classmethod
    def validate_track_ref(cls, value: str) -> str:
        parse_track_ref(value)
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_key_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="key_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def key_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "alert-cooldown-key",
                1,
                self.zone_id,
                self.violation_type.value,
                self.track_ref,
            ]
        )

    @property
    def camera_id(self) -> str:
        return parse_track_ref(self.track_ref)[0]

    @property
    def tracker_epoch(self) -> str:
        return parse_track_ref(self.track_ref)[1]


class AlertCooldownAuthority(FrozenContractModel):
    """The last emitted alert and its exclusive frame-space cooldown bound."""

    key: AlertCooldownKey
    stream_id: ReferenceToken
    source_alert_id: str = Field(min_length=1, max_length=128)
    source_trigger_frame: int = Field(ge=0, strict=True)
    cooldown_frames: int = Field(ge=0, strict=True)
    cooldown_until_frame_exclusive: int = Field(ge=0, strict=True)

    @field_validator("stream_id")
    @classmethod
    def validate_stream_id(cls, value: str) -> str:
        return require_reference_token(value, "alert cooldown stream")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="authority_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "alert-cooldown-authority",
                1,
                self.key.key_id,
                self.stream_id,
                self.source_alert_id,
                self.source_trigger_frame,
                self.cooldown_frames,
                self.cooldown_until_frame_exclusive,
            ]
        )

    @model_validator(mode="after")
    def validate_frame_bound(self) -> AlertCooldownAuthority:
        if self.cooldown_until_frame_exclusive != (
            self.source_trigger_frame + self.cooldown_frames
        ):
            raise ValueError("cooldown frame bound must equal source frame plus cooldown_frames")
        return self


class ImmediateSafetyDeliveryAuthority(FrozenContractModel):
    """Proof that a certified case-external hard signal was already accepted."""

    incident: EmergencySafetyIncident
    delivery_receipt: DeliveryReceipt

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="authority_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "immediate-safety-delivery-authority",
                1,
                self.incident.model_dump(mode="json"),
                self.delivery_receipt.model_dump(mode="json"),
            ]
        )

    @model_validator(mode="after")
    def validate_accepted_exact_delivery(self) -> ImmediateSafetyDeliveryAuthority:
        receipt = self.delivery_receipt
        if receipt.alert_id != self.incident.incident_id:
            raise ValueError("emergency delivery receipt identifies another incident")
        if receipt.idempotency_key != self.incident.delivery_idempotency_key:
            raise ValueError("emergency delivery idempotency key does not match the incident")
        if not receipt.accepted:
            raise ValueError("emergency delivery authority requires an accepted receipt")
        return self


class AlertPolicyRequest(FrozenContractModel):
    """Exact immutable roots consumed by the deterministic case alert policy."""

    policy_version: Literal["alert-policy-v1"] = ALERT_POLICY_VERSION
    run_id: ReferenceToken
    case_id: ReferenceToken
    case_authority_sha256: Sha256Hex
    source_case_status: Literal[CaseStatus.READY_FOR_ALERT_POLICY]
    config_sha256: Sha256Hex
    manifest_id: Sha256Hex
    camera_id: ReferenceToken
    stream_id: ReferenceToken
    stream_authority_sha256: Sha256Hex
    fps_num: int = Field(gt=0, strict=True)
    fps_den: int = Field(gt=0, strict=True)
    zone_id: ReferenceToken
    zone_risk: RiskLevel
    violation_type: ViolationType
    primary_track_ref: TrackRef | None = None
    trigger_frame: int = Field(ge=0, strict=True)
    hard_rule: StrictBool
    verdict_id: Sha256Hex
    verdict_version: int = Field(gt=0, strict=True)
    verdict_sha256: Sha256Hex
    verdict_decision: VerdictDecision
    verdict_confidence: StrictFloat = Field(ge=0, le=1)
    recommended_alert_level: AlertLevel
    procedural_review_id: Sha256Hex
    procedural_review_version: int = Field(gt=0, strict=True)
    procedural_review_passed: Literal[True]
    observation_sufficiency_sha256: Sha256Hex | None = None
    cooldown_seconds: StrictFloat = Field(ge=0)
    cooldown_frames: int = Field(ge=0, strict=True)
    confirmed_min_confidence: StrictFloat = Field(ge=0, le=1)
    insufficient_evidence_max_level: Literal[AlertLevel.ADVISORY]
    repeat_history_mode: Literal["DISABLED_UNTRUSTED_DEMO"] = DISABLED_REPEAT_MODE
    cross_day_repeat_count: Literal[0] = 0
    prior_cooldown: AlertCooldownAuthority | None = None
    prior_emergency_delivery: ImmediateSafetyDeliveryAuthority | None = None

    @field_validator("run_id", "case_id", "camera_id", "stream_id", "zone_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "alert policy reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_request_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="request_id")

    def input_projection(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"request_id"})

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_id(self) -> Sha256Hex:
        return sha256_hex(["alert-policy-request", 1, self.input_projection()])

    @property
    def expected_alert_id(self) -> Sha256Hex:
        return sha256_hex(["adjudicated-alert", 1, self.request_id])

    @model_validator(mode="after")
    def validate_scope_and_timebase(self) -> AlertPolicyRequest:
        if gcd(self.fps_num, self.fps_den) != 1:
            raise ValueError("alert policy FPS must use lowest terms")
        expected_frames = _ceil_cooldown_frames(
            self.cooldown_seconds,
            self.fps_num,
            self.fps_den,
        )
        if self.cooldown_frames != expected_frames:
            raise ValueError("cooldown_frames does not match seconds and rational FPS")
        if self.primary_track_ref is not None:
            track_camera_id, _, _ = parse_track_ref(self.primary_track_ref)
            if track_camera_id != self.camera_id:
                raise ValueError("alert policy track_ref belongs to another camera")

        emergency = self.prior_emergency_delivery
        if emergency is not None:
            expected_violation = _DIRECT_SIGNAL_VIOLATIONS.get(emergency.incident.signal_type)
            if (
                not self.hard_rule
                or emergency.incident.zone_id != self.zone_id
                or expected_violation != self.violation_type
            ):
                raise ValueError("prior emergency delivery is outside this hard-signal case")
        return self


class AlertOutboxItem(FrozenContractModel):
    """Deliverable alert payload created in the same transaction as Case closure."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    case_authority_sha256: Sha256Hex
    policy_request_id: Sha256Hex
    manifest_id: Sha256Hex
    alert: AlertDecision
    priority: AlertOutboxPriority
    idempotency_key: str = Field(min_length=1, max_length=128)

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "alert outbox reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_outbox_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="outbox_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def outbox_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "alert-outbox-item",
                1,
                self.run_id,
                self.case_id,
                self.case_authority_sha256,
                self.policy_request_id,
                self.manifest_id,
                self.alert.model_dump(mode="json"),
                self.priority.value,
                self.idempotency_key,
            ]
        )

    @model_validator(mode="after")
    def validate_deliverable_payload(self) -> AlertOutboxItem:
        if self.alert.case_id != self.case_id:
            raise ValueError("outbox alert belongs to another case")
        if self.idempotency_key != self.alert.alert_id:
            raise ValueError("outbox idempotency key must equal alert_id")
        if (
            self.alert.suppressed_by_cooldown
            or self.alert.merged_into_alert_id is not None
            or self.alert.rescinded
        ):
            raise ValueError("outbox accepts only a deliverable current alert")
        expected_priority = {
            AlertLevel.ADVISORY: AlertOutboxPriority.NORMAL,
            AlertLevel.CONFIRMED: AlertOutboxPriority.HIGH,
            AlertLevel.EMERGENCY: AlertOutboxPriority.CRITICAL,
        }[self.alert.level]
        if self.priority != expected_priority:
            raise ValueError("outbox priority does not match alert level")
        return self


class AlertPolicyAuthority(FrozenContractModel):
    """Pure close-and-enqueue intent for one current READY Case snapshot."""

    request: AlertPolicyRequest
    disposition: AlertPolicyDisposition
    policy_rule_ids: tuple[ReferenceToken, ...] = Field(min_length=1)
    decision: AlertDecision | None = None
    cooldown_write: AlertCooldownAuthority | None = None
    outbox_item: AlertOutboxItem | None = None
    target_case_status: Literal[CaseStatus.CLOSED] = CaseStatus.CLOSED
    final_decision: VerdictDecision

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="authority_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "alert-policy-authority",
                1,
                self.request.request_id,
                self.disposition.value,
                list(self.policy_rule_ids),
                self.decision.model_dump(mode="json") if self.decision is not None else None,
                (
                    self.cooldown_write.model_dump(mode="json")
                    if self.cooldown_write is not None
                    else None
                ),
                (
                    self.outbox_item.model_dump(mode="json")
                    if self.outbox_item is not None
                    else None
                ),
                self.target_case_status.value,
                self.final_decision.value,
            ]
        )

    @model_validator(mode="after")
    def validate_atomic_intent(self) -> AlertPolicyAuthority:
        request = self.request
        decision = self.decision
        stable_rules = tuple(sorted(self.policy_rule_ids))
        if (
            len(self.policy_rule_ids) != len(set(self.policy_rule_ids))
            or self.policy_rule_ids != stable_rules
        ):
            raise ValueError("alert policy rule IDs must be unique and stable")
        if self.disposition == AlertPolicyDisposition.CLOSE_NO_ALERT:
            if request.verdict_decision != VerdictDecision.NOT_ESTABLISHED:
                raise ValueError("no-alert closure requires a NOT_ESTABLISHED verdict")
            if (
                decision is not None
                or self.outbox_item is not None
                or self.cooldown_write is not None
            ):
                raise ValueError("no-alert closure cannot create alert or delivery state")
            if self.final_decision != request.verdict_decision:
                raise ValueError("alert policy final decision does not match its verdict")
            return self
        if decision is None:
            raise ValueError("alerting disposition requires an AlertDecision")
        if decision.policy_rule_ids != self.policy_rule_ids:
            raise ValueError("alert decision rule IDs do not match policy authority")
        if decision.case_id != request.case_id:
            raise ValueError("alert policy decision belongs to another case")
        if decision.alert_id != request.expected_alert_id:
            raise ValueError("alert policy decision ID does not match its request")
        if self.final_decision != request.verdict_decision:
            raise ValueError("alert policy final decision does not match its verdict")

        if self.disposition == AlertPolicyDisposition.SUPPRESSED_MERGED:
            if not decision.suppressed_by_cooldown:
                raise ValueError("merged disposition requires a suppressed decision")
            if decision.merged_into_alert_id is None:
                raise ValueError("suppressed alert requires a merged alert identity")
            if self.outbox_item is not None or self.cooldown_write is not None:
                raise ValueError("suppressed alert cannot create outbox or cooldown writes")
            return self

        if self.disposition != AlertPolicyDisposition.ENQUEUE:
            raise ValueError("unsupported alert policy disposition")
        if decision.suppressed_by_cooldown:
            raise ValueError("enqueue disposition cannot contain a suppressed decision")
        if decision.merged_into_alert_id is not None:
            raise ValueError("deliverable alert cannot merge into another alert")
        if self.outbox_item is None:
            raise ValueError("deliverable alert requires an outbox item")
        expected_outbox_scope = (
            request.run_id,
            request.case_id,
            request.case_authority_sha256,
            request.request_id,
            request.manifest_id,
            decision,
            decision.alert_id,
        )
        actual_outbox_scope = (
            self.outbox_item.run_id,
            self.outbox_item.case_id,
            self.outbox_item.case_authority_sha256,
            self.outbox_item.policy_request_id,
            self.outbox_item.manifest_id,
            self.outbox_item.alert,
            self.outbox_item.idempotency_key,
        )
        if actual_outbox_scope != expected_outbox_scope:
            raise ValueError("outbox item does not exactly bind the policy request and decision")

        if request.primary_track_ref is None:
            if self.cooldown_write is not None:
                raise ValueError("untracked alert cannot create a track cooldown write")
            return self
        if self.cooldown_write is None:
            raise ValueError("tracked deliverable alert requires a cooldown write")
        expected_key = AlertCooldownKey(
            zone_id=request.zone_id,
            violation_type=request.violation_type,
            track_ref=request.primary_track_ref,
        )
        cooldown = self.cooldown_write
        if (
            cooldown.key != expected_key
            or cooldown.stream_id != request.stream_id
            or cooldown.source_alert_id != decision.alert_id
            or cooldown.source_trigger_frame != request.trigger_frame
            or cooldown.cooldown_frames != request.cooldown_frames
        ):
            raise ValueError("cooldown write does not exactly bind the delivered alert")
        return self


class AlertChannelCapabilityAuthority(FrozenContractModel):
    """Durable channel claim governing retries after an unknown delivery."""

    run_id: ReferenceToken
    manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    channel: ReferenceToken
    capability_revision: ReferenceToken
    idempotency_guarantee: AlertChannelIdempotencyGuarantee
    provider_idempotency_key: Literal["alert_id"] | None = None

    @field_validator("run_id", "channel", "capability_revision")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "alert channel capability")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_capability_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="capability_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def capability_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "alert-channel-capability-authority",
                2,
                self.run_id,
                self.manifest_id,
                self.config_sha256,
                self.channel,
                self.capability_revision,
                self.idempotency_guarantee.value,
                self.provider_idempotency_key,
            ]
        )

    @model_validator(mode="after")
    def validate_provider_idempotency_claim(self) -> AlertChannelCapabilityAuthority:
        expected_key = (
            "alert_id"
            if self.idempotency_guarantee == AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID
            else None
        )
        if self.provider_idempotency_key != expected_key:
            raise ValueError("exact alert channel idempotency requires provider key alert_id")
        return self


def derive_dispatch_attempt_id(
    *,
    outbox_id: str,
    alert_id: str,
    case_id: str,
    attempt_number: int,
    fence: int,
    lease_owner_sha256: str,
    started_at: datetime,
    lease_expires_at: datetime,
    channel_capability: AlertChannelCapabilityAuthority,
) -> Sha256Hex:
    return sha256_hex(
        [
            "alert-dispatch-attempt",
            2,
            outbox_id,
            alert_id,
            case_id,
            attempt_number,
            fence,
            lease_owner_sha256,
            _canonical_utc(started_at),
            _canonical_utc(lease_expires_at),
            channel_capability.model_dump(mode="json"),
        ]
    )


class AlertDispatchAttempt(FrozenContractModel):
    outbox_id: Sha256Hex
    alert_id: str = Field(min_length=1, max_length=128)
    case_id: ReferenceToken
    attempt_number: int = Field(gt=0, strict=True)
    fence: int = Field(gt=0, strict=True)
    lease_owner_sha256: Sha256Hex
    started_at: datetime
    lease_expires_at: datetime
    channel_capability: AlertChannelCapabilityAuthority
    idempotency_key: str = Field(min_length=1, max_length=128)

    @field_validator("case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "alert dispatch reference")

    @field_validator("started_at", "lease_expires_at")
    @classmethod
    def validate_utc_timestamps(cls, value: datetime) -> datetime:
        return _require_utc(value, "alert dispatch attempt timestamp")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_attempt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="attempt_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def attempt_id(self) -> Sha256Hex:
        return derive_dispatch_attempt_id(
            outbox_id=self.outbox_id,
            alert_id=self.alert_id,
            case_id=self.case_id,
            attempt_number=self.attempt_number,
            fence=self.fence,
            lease_owner_sha256=self.lease_owner_sha256,
            started_at=self.started_at,
            lease_expires_at=self.lease_expires_at,
            channel_capability=self.channel_capability,
        )

    @model_validator(mode="after")
    def validate_fence_lease_and_idempotency(self) -> AlertDispatchAttempt:
        if self.idempotency_key != self.alert_id:
            raise ValueError("dispatch attempt idempotency key must equal alert_id")
        if self.fence != self.attempt_number:
            raise ValueError("dispatch attempt fence must equal its monotonic attempt number")
        if self.lease_expires_at <= self.started_at:
            raise ValueError("dispatch attempt lease must expire after it starts")
        return self


class AlertDispatchReceipt(FrozenContractModel):
    attempt_id: Sha256Hex
    outbox_id: Sha256Hex
    alert_id: str = Field(min_length=1, max_length=128)
    case_id: ReferenceToken
    attempt_number: int = Field(gt=0, strict=True)
    fence: int = Field(gt=0, strict=True)
    lease_owner_sha256: Sha256Hex
    started_at: datetime
    lease_expires_at: datetime
    channel_capability: AlertChannelCapabilityAuthority
    idempotency_key: str = Field(min_length=1, max_length=128)
    disposition: AlertDispatchDisposition
    continuation: AlertDispatchContinuation
    failure_code: AlertDispatchFailureCode | None = None
    delivery_receipt: DeliveryReceipt | None = None

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        return require_reference_token(value, "alert dispatch case")

    @field_validator("started_at", "lease_expires_at")
    @classmethod
    def validate_utc_timestamps(cls, value: datetime) -> datetime:
        return _require_utc(value, "alert dispatch receipt timestamp")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="receipt_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "alert-dispatch-receipt",
                1,
                self.attempt_id,
                self.outbox_id,
                self.alert_id,
                self.case_id,
                self.attempt_number,
                self.fence,
                self.lease_owner_sha256,
                _canonical_utc(self.started_at),
                _canonical_utc(self.lease_expires_at),
                self.channel_capability.model_dump(mode="json"),
                self.idempotency_key,
                self.disposition.value,
                self.continuation.value,
                self.failure_code.value if self.failure_code is not None else None,
                (
                    self.delivery_receipt.model_dump(mode="json")
                    if self.delivery_receipt is not None
                    else None
                ),
            ]
        )

    @model_validator(mode="after")
    def validate_dispatch_outcome(self) -> AlertDispatchReceipt:
        if self.idempotency_key != self.alert_id:
            raise ValueError("dispatch receipt idempotency key must equal alert_id")
        expected_attempt_id = derive_dispatch_attempt_id(
            outbox_id=self.outbox_id,
            alert_id=self.alert_id,
            case_id=self.case_id,
            attempt_number=self.attempt_number,
            fence=self.fence,
            lease_owner_sha256=self.lease_owner_sha256,
            started_at=self.started_at,
            lease_expires_at=self.lease_expires_at,
            channel_capability=self.channel_capability,
        )
        if self.attempt_id != expected_attempt_id:
            raise ValueError("dispatch receipt does not bind its attempt")
        delivery = self.delivery_receipt
        if delivery is not None and (
            delivery.alert_id != self.alert_id or delivery.idempotency_key != self.alert_id
        ):
            raise ValueError("channel delivery receipt does not bind alert idempotency")

        if self.fence != self.attempt_number:
            raise ValueError("dispatch receipt fence must equal its monotonic attempt number")
        if self.lease_expires_at <= self.started_at:
            raise ValueError("dispatch receipt lease must expire after it starts")

        if self.disposition == AlertDispatchDisposition.SUCCEEDED:
            if (
                self.continuation != AlertDispatchContinuation.CLOSED
                or self.failure_code is not None
                or delivery is None
                or not delivery.accepted
                or delivery.channel != self.channel_capability.channel
            ):
                raise ValueError("successful dispatch requires one accepted exact receipt")
            return self

        if self.failure_code is None:
            raise ValueError("failed or unknown dispatch requires a typed failure code")
        if delivery is not None and delivery.accepted:
            raise ValueError("non-success dispatch cannot contain an accepted delivery receipt")

        exhausted = self.attempt_number >= MAX_ALERT_DISPATCH_ATTEMPTS
        if self.disposition == AlertDispatchDisposition.RETRYABLE_FAILURE:
            if self.failure_code not in {
                AlertDispatchFailureCode.CHANNEL_DEFINITELY_NOT_SENT,
                AlertDispatchFailureCode.CHANNEL_REJECTED,
            }:
                raise ValueError("retryable dispatch requires a definitely-not-sent outcome")
            expected = (
                AlertDispatchContinuation.ATTENTION_REQUIRED
                if exhausted
                else AlertDispatchContinuation.RETRY_ALLOWED
            )
        elif self.disposition == AlertDispatchDisposition.UNKNOWN_DELIVERY:
            if self.failure_code not in {
                AlertDispatchFailureCode.CHANNEL_EXCEPTION,
                AlertDispatchFailureCode.RECEIPT_MISMATCH,
                AlertDispatchFailureCode.LEASE_EXPIRED,
            }:
                raise ValueError("unknown dispatch requires an uncertainty failure code")
            retry_safe = (
                self.channel_capability.idempotency_guarantee
                == AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID
                and self.channel_capability.provider_idempotency_key == "alert_id"
            )
            expected = (
                AlertDispatchContinuation.RETRY_ALLOWED
                if retry_safe and not exhausted
                else AlertDispatchContinuation.ATTENTION_REQUIRED
            )
        else:  # pragma: no cover - enum exhaustiveness guard
            raise ValueError("unsupported alert dispatch disposition")
        if self.continuation != expected:
            raise ValueError("dispatch continuation does not match delivery certainty")
        return self


__all__ = [
    "ALERT_POLICY_VERSION",
    "DISABLED_REPEAT_MODE",
    "MAX_ALERT_DISPATCH_ATTEMPTS",
    "AlertChannelCapabilityAuthority",
    "AlertChannelIdempotencyGuarantee",
    "AlertCooldownAuthority",
    "AlertCooldownKey",
    "AlertDispatchAttempt",
    "AlertDispatchContinuation",
    "AlertDispatchDisposition",
    "AlertDispatchFailureCode",
    "AlertDispatchReceipt",
    "AlertOutboxItem",
    "AlertOutboxPriority",
    "AlertPolicyAuthority",
    "AlertPolicyDisposition",
    "AlertPolicyFailureCode",
    "AlertPolicyRequest",
    "ImmediateSafetyDeliveryAuthority",
    "derive_dispatch_attempt_id",
]
