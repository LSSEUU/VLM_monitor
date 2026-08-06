"""Candidate events and objective facts emitted by deterministic perception."""

from __future__ import annotations

import uuid
from math import isfinite
from typing import Any, Self, TypeAlias

from pydantic import (
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictFloat,
    StrictInt,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel, Scalar
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    ArtifactKind,
    ConfirmationPolicy,
    EvidenceClass,
    ObjectiveFactKind,
    RiskLevel,
    SafetySignalType,
    SafetySourceClass,
    ViolationType,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import (
    FrameId,
    ReferenceToken,
    TrackRef,
    parse_frame_id,
    require_reference_token,
    require_track_ref_camera,
)
from labcourt.contracts.registry import VIOLATION_REGISTRY
from labcourt.contracts.storage import ArtifactRef

ObjectiveValue: TypeAlias = Scalar | tuple[int, int]
LABCOURT_NAMESPACE = uuid.UUID("ae3dd949-dd55-534c-89ff-cd0676838374")
OBJECTIVE_VALUE_SCHEMA: dict[str, Any] = {
    "allOf": [
        {
            "if": {
                "properties": {
                    "kind": {
                        "enum": [
                            ObjectiveFactKind.DURATION_FRAMES.value,
                            ObjectiveFactKind.PERSON_COUNT.value,
                        ]
                    }
                },
                "required": ["kind"],
            },
            "then": {"properties": {"value": {"type": "integer", "minimum": 0}}},
        },
        {
            "if": {
                "properties": {
                    "kind": {
                        "enum": [
                            ObjectiveFactKind.FRAME_INTERVAL.value,
                            ObjectiveFactKind.TRACK_PRESENCE_INTERVAL.value,
                        ]
                    }
                },
                "required": ["kind"],
            },
            "then": {
                "properties": {
                    "value": {
                        "type": "array",
                        "prefixItems": [
                            {"type": "integer", "minimum": 0},
                            {"type": "integer", "minimum": 1},
                        ],
                        "minItems": 2,
                        "maxItems": 2,
                    }
                }
            },
        },
        {
            "if": {
                "properties": {"kind": {"const": ObjectiveFactKind.ZONE_ID.value}},
                "required": ["kind"],
            },
            "then": {"properties": {"value": {"type": "string", "minLength": 1}}},
        },
        {
            "if": {
                "properties": {"kind": {"const": ObjectiveFactKind.RISK_LEVEL.value}},
                "required": ["kind"],
            },
            "then": {
                "properties": {
                    "value": {
                        "type": "string",
                        "enum": [item.value for item in RiskLevel],
                    }
                }
            },
        },
        {
            "if": {
                "properties": {
                    "kind": {
                        "enum": [
                            ObjectiveFactKind.DETECTION_SCORE.value,
                            ObjectiveFactKind.OBSERVABILITY.value,
                        ]
                    }
                },
                "required": ["kind"],
            },
            "then": {
                "properties": {
                    "value": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    }
                }
            },
        },
    ]
}


def derive_event_id(
    *,
    camera_id: str,
    stream_id: str,
    violation_type: ViolationType,
    primary_track_ref: str | None,
    start_frame: int,
    rule_version: str,
) -> str:
    payload = [
        "event",
        1,
        camera_id,
        stream_id,
        violation_type.value,
        primary_track_ref,
        start_frame,
        rule_version,
    ]
    name = canonical_json(payload)
    return str(uuid.uuid5(LABCOURT_NAMESPACE, name))


def derive_case_id(event_id: str) -> str:
    normalized_event_id = str(uuid.UUID(event_id))
    return str(
        uuid.uuid5(
            LABCOURT_NAMESPACE,
            canonical_json(["case", 1, normalized_event_id]),
        )
    )


def validate_objective_value(
    kind: ObjectiveFactKind,
    value: ObjectiveValue,
) -> ObjectiveValue:
    """Enforce the value shape associated with an objective-fact discriminator."""

    if kind in {
        ObjectiveFactKind.DURATION_FRAMES,
        ObjectiveFactKind.PERSON_COUNT,
    }:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{kind} requires a non-negative integer value")
    elif kind in {
        ObjectiveFactKind.FRAME_INTERVAL,
        ObjectiveFactKind.TRACK_PRESENCE_INTERVAL,
    }:
        if (
            not isinstance(value, tuple)
            or len(value) != 2
            or any(not isinstance(item, int) or isinstance(item, bool) for item in value)
        ):
            raise ValueError(f"{kind} requires a two-integer interval")
        if value[0] < 0 or value[0] >= value[1]:
            raise ValueError("frame interval must be non-empty and non-negative")
    elif kind == ObjectiveFactKind.ZONE_ID:
        if not isinstance(value, str) or not value:
            raise ValueError("ZONE_ID requires a non-empty string value")
    elif kind == ObjectiveFactKind.RISK_LEVEL:
        if not isinstance(value, str):
            raise ValueError("RISK_LEVEL requires a RiskLevel string value")
        try:
            RiskLevel(value)
        except ValueError as exc:
            raise ValueError("RISK_LEVEL requires a valid RiskLevel value") from exc
    elif kind in {
        ObjectiveFactKind.DETECTION_SCORE,
        ObjectiveFactKind.OBSERVABILITY,
    } and (
        not isinstance(value, int | float)
        or isinstance(value, bool)
        or not isfinite(value)
        or not 0 <= value <= 1
    ):
        raise ValueError(f"{kind} requires a finite numeric value in [0, 1]")
    return value


class ObjectiveFact(FrozenContractModel):
    model_config = ConfigDict(json_schema_extra=OBJECTIVE_VALUE_SCHEMA)

    fact_id: ReferenceToken
    kind: ObjectiveFactKind
    value: ObjectiveValue
    source_ref: ArtifactRef
    source_manifest_id: Sha256Hex
    unit: str | None = None

    @model_validator(mode="after")
    def validate_value_shape(self) -> ObjectiveFact:
        validate_objective_value(self.kind, self.value)
        if self.source_ref.kind not in {
            ArtifactKind.FRAME,
            ArtifactKind.DETECTION,
            ArtifactKind.SAFETY_SIGNAL,
            ArtifactKind.CROP,
            ArtifactKind.TOOL_RESULT,
        }:
            raise ValueError("objective fact source kind is not an observable M2 artifact")
        return self


class ConfirmationRecord(FrozenContractModel):
    policy: ConfirmationPolicy
    examined_frame_ids: tuple[FrameId, ...] = ()
    counterevidence_frame_ids: tuple[FrameId, ...] = ()
    post_threshold_recovery_frame_id: FrameId | None = None
    suppressed: StrictBool = False
    suppression_reason: str | None = None
    resolved_frame: int | None = Field(default=None, ge=0, strict=True)
    causal_risk: StrictBool = False

    @model_validator(mode="after")
    def validate_confirmation(self) -> ConfirmationRecord:
        if len(self.examined_frame_ids) != len(set(self.examined_frame_ids)):
            raise ValueError("examined_frame_ids must be unique")
        if len(self.counterevidence_frame_ids) != len(set(self.counterevidence_frame_ids)):
            raise ValueError("counterevidence_frame_ids must be unique")
        if not set(self.counterevidence_frame_ids).issubset(self.examined_frame_ids):
            raise ValueError("counterevidence must refer to an examined frame")
        if self.suppressed and not self.suppression_reason:
            raise ValueError("suppressed confirmation requires a reason")
        if self.suppressed and not self.counterevidence_frame_ids:
            raise ValueError("suppressed confirmation requires counterevidence")
        if not self.suppressed and self.suppression_reason is not None:
            raise ValueError("unsuppressed confirmation cannot contain a suppression reason")
        if self.policy == ConfirmationPolicy.SOURCE_COMPAT and not self.causal_risk:
            raise ValueError("SOURCE_COMPAT records must declare causal_risk=true")
        if self.policy == ConfirmationPolicy.STRICT_CAUSAL and not self.examined_frame_ids:
            raise ValueError("STRICT_CAUSAL confirmation requires examined frames")
        if (self.post_threshold_recovery_frame_id is None) != (self.resolved_frame is None):
            raise ValueError(
                "post-threshold recovery frame and resolved_frame must be set together"
            )
        if self.policy == ConfirmationPolicy.NONE and (
            self.post_threshold_recovery_frame_id is not None
            or self.resolved_frame is not None
            or self.causal_risk
        ):
            raise ValueError("NONE confirmation cannot contain causal resolution fields")
        return self


class CandidateEvent(FrozenContractModel):
    camera_id: ReferenceToken
    stream_id: ReferenceToken
    rule_version: str = Field(min_length=1)
    violation_type: ViolationType
    evidence_class: EvidenceClass
    zone_id: ReferenceToken
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    trigger_frame: int = Field(ge=0, strict=True)
    primary_track_ref: TrackRef | None = None
    related_track_refs: tuple[TrackRef, ...] = ()
    hard_rule: StrictBool = False
    l1_score: StrictFloat = Field(ge=0, le=1)
    confirmation: ConfirmationRecord
    objective_facts: tuple[ObjectiveFact, ...] = ()
    manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_event_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "event_id" in payload
        claimed = payload.pop("event_id", None)
        event = handler(payload)
        if claimed_present and not isinstance(claimed, str):
            raise ValueError("serialized event_id must be a string")
        if claimed_present and claimed != event.event_id:
            raise ValueError("serialized event_id does not match event identity fields")
        return event

    @computed_field  # type: ignore[prop-decorator]
    @property
    def event_id(self) -> str:
        return derive_event_id(
            camera_id=self.camera_id,
            stream_id=self.stream_id,
            violation_type=self.violation_type,
            primary_track_ref=self.primary_track_ref,
            start_frame=self.start_frame,
            rule_version=self.rule_version,
        )

    @field_validator("camera_id", "stream_id")
    @classmethod
    def validate_unambiguous_stream_tokens(cls, value: str) -> str:
        return require_reference_token(value, "camera_id or stream_id")

    @model_validator(mode="after")
    def validate_interval_and_tracks(self) -> CandidateEvent:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("event interval must be non-empty")
        if not self.start_frame <= self.trigger_frame < self.end_frame_exclusive:
            raise ValueError("trigger_frame must lie within the event interval")
        if len(self.related_track_refs) != len(set(self.related_track_refs)):
            raise ValueError("related_track_refs must be unique")
        if self.confirmation.suppressed:
            raise ValueError("suppressed observations must not be emitted as CandidateEvent")
        if self.primary_track_ref is not None:
            require_track_ref_camera(self.primary_track_ref, self.camera_id)
        for track_ref in self.related_track_refs:
            require_track_ref_camera(track_ref, self.camera_id)
        expected_class = VIOLATION_REGISTRY[self.violation_type].evidence_class
        if self.evidence_class != expected_class:
            raise ValueError(f"{self.violation_type} requires evidence_class={expected_class}")
        if self.evidence_class == EvidenceClass.ABSENCE:
            if self.primary_track_ref is None:
                raise ValueError("absence events require a primary_track_ref")
            if self.confirmation.policy == ConfirmationPolicy.NONE:
                raise ValueError("absence events require causal confirmation")
        confirmation_refs = (
            self.confirmation.examined_frame_ids + self.confirmation.counterevidence_frame_ids
        )
        for frame_id in confirmation_refs:
            camera_id, stream_id, frame_index = parse_frame_id(frame_id)
            if (camera_id, stream_id) != (self.camera_id, self.stream_id):
                raise ValueError("confirmation frame belongs to another stream")
            if (
                self.confirmation.policy == ConfirmationPolicy.STRICT_CAUSAL
                and not self.start_frame <= frame_index < self.end_frame_exclusive
            ):
                raise ValueError(
                    "STRICT_CAUSAL confirmation frame lies outside the alleged interval"
                )
        recovery_frame_id = self.confirmation.post_threshold_recovery_frame_id
        if recovery_frame_id is not None:
            camera_id, stream_id, frame_index = parse_frame_id(recovery_frame_id)
            if (camera_id, stream_id) != (self.camera_id, self.stream_id):
                raise ValueError("post-threshold recovery belongs to another stream")
            if frame_index != self.confirmation.resolved_frame:
                raise ValueError("post-threshold recovery frame does not match resolved_frame")
            if frame_index < self.end_frame_exclusive:
                raise ValueError("post-threshold recovery must follow the alleged interval")
        if self.hard_rule and not VIOLATION_REGISTRY[self.violation_type].is_hard_rule_eligible:
            raise ValueError(f"{self.violation_type} is not hard-rule eligible")
        return self


class SafetySignal(FrozenContractModel):
    signal_id: ReferenceToken
    signal_type: SafetySignalType
    zone_id: ReferenceToken
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    value: StrictFloat | StrictInt | StrictBool
    unit: str | None = None
    source_class: SafetySourceClass
    certification_id: str | None = None
    quality: StrictFloat = Field(ge=0, le=1)

    @field_validator("signal_id", "zone_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "signal or zone reference")

    @model_validator(mode="after")
    def validate_signal(self) -> SafetySignal:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("safety signal interval must be non-empty")
        if (
            self.source_class
            in {
                SafetySourceClass.PHYSICAL_SENSOR,
                SafetySourceClass.VALIDATED_DETERMINISTIC,
            }
            and not self.certification_id
        ):
            raise ValueError("validated safety sources require certification_id")
        if self.certification_id is not None and (
            not self.certification_id.strip() or len(self.certification_id) > 128
        ):
            raise ValueError("certification_id must be bounded non-empty text")
        return self
