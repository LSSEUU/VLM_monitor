"""M8 typed sensor samples, polling, simulation, and risk authorities."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, Self, TypeAlias

from pydantic import (
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictInt,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8OperationalRiskLevel
from labcourt.contracts.m8_operations import (
    M8OperationalSource,
    M8OperationalSourceKind,
    M8OperationalSourceMode,
    M8SensorType,
    M8SourceTimebase,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_SENSOR_BATCH_SIZE = 1024
MAX_M8_SENSOR_SCENARIO_READINGS = 100_000
MAX_M8_SENSOR_RISK_RULES = 1024
MAX_M8_RAW_SIGNAL_REF_LENGTH = 512

M8SensorScalar: TypeAlias = StrictBool | StrictInt


class M8SensorUnit(StrEnum):
    BOOLEAN = "BOOLEAN"
    MILLI_CELSIUS = "MILLI_CELSIUS"
    MILLI_PERCENT_LFL = "MILLI_PERCENT_LFL"
    MILLI_PPM = "MILLI_PPM"


class M8SensorQuality(StrEnum):
    GOOD = "GOOD"
    DEGRADED = "DEGRADED"
    INVALID = "INVALID"


class M8SensorRiskOperator(StrEnum):
    BOOLEAN_EQUALS = "BOOLEAN_EQUALS"
    INTEGER_GTE = "INTEGER_GTE"


class M8SensorRiskPolicyPurpose(StrEnum):
    DEMONSTRATION = "DEMONSTRATION"
    OPERATIONAL = "OPERATIONAL"


class M8SensorAssessmentReasonCode(StrEnum):
    MATCHED_RULE = "MATCHED_RULE"
    NO_MATCHING_RULE = "NO_MATCHING_RULE"
    SAMPLE_QUALITY_NOT_GOOD = "SAMPLE_QUALITY_NOT_GOOD"


_SENSOR_UNIT = {
    M8SensorType.SMOKE: M8SensorUnit.BOOLEAN,
    M8SensorType.TEMPERATURE: M8SensorUnit.MILLI_CELSIUS,
    M8SensorType.COMBUSTIBLE_GAS: M8SensorUnit.MILLI_PERCENT_LFL,
    M8SensorType.TOXIC_GAS: M8SensorUnit.MILLI_PPM,
    M8SensorType.DOOR_CONTACT: M8SensorUnit.BOOLEAN,
    M8SensorType.WATER_LEAK: M8SensorUnit.BOOLEAN,
    M8SensorType.EMERGENCY_BUTTON: M8SensorUnit.BOOLEAN,
}
_BOOLEAN_SENSOR_TYPES = frozenset(
    sensor_type for sensor_type, unit in _SENSOR_UNIT.items() if unit == M8SensorUnit.BOOLEAN
)
_NUMERIC_SENSOR_TYPES = frozenset(set(M8SensorType) - _BOOLEAN_SENSOR_TYPES)
_RISK_LEVEL_RANK = {
    M8OperationalRiskLevel.REMINDER: 0,
    M8OperationalRiskLevel.GENERAL: 1,
    M8OperationalRiskLevel.SEVERE: 2,
    M8OperationalRiskLevel.EMERGENCY: 3,
}


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
    if not claims:
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 sensor authority")


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware UTC")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{name} must use UTC")
    return value


def _validate_raw_signal_ref(value: str) -> str:
    if not value or len(value) > MAX_M8_RAW_SIGNAL_REF_LENGTH:
        raise ValueError("M8 raw_signal_ref must be a bounded relative POSIX reference")
    if "\\" in value or ":" in value:
        raise ValueError("M8 raw_signal_ref must be a relative POSIX reference")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError("M8 raw_signal_ref must be a controlled relative POSIX reference")
    if any(part in {"", "."} for part in path.parts):
        raise ValueError("M8 raw_signal_ref must not contain empty or dot segments")
    return value


def _validate_sensor_value(sensor_type: M8SensorType, value: bool | int) -> None:
    if sensor_type in _BOOLEAN_SENSOR_TYPES:
        if not isinstance(value, bool):
            raise ValueError(f"M8 {sensor_type.value} requires a strict boolean value")
        return
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"M8 {sensor_type.value} requires a strict integer value")
    if sensor_type == M8SensorType.TEMPERATURE:
        if not -273_150 <= value <= 500_000:
            raise ValueError("M8 temperature must be within [-273150, 500000] milli Celsius")
    elif not 0 <= value <= 2_147_483_647:
        raise ValueError("M8 gas value must be a non-negative signed 32-bit fixed-point integer")


def _sensor_sample_json_schema(schema: dict[str, Any]) -> None:
    branches: list[dict[str, Any]] = []
    for sensor_type in M8SensorType:
        unit = _SENSOR_UNIT[sensor_type]
        value_schema: dict[str, Any]
        if sensor_type in _BOOLEAN_SENSOR_TYPES:
            value_schema = {"type": "boolean"}
        elif sensor_type == M8SensorType.TEMPERATURE:
            value_schema = {"type": "integer", "minimum": -273150, "maximum": 500000}
        else:
            value_schema = {
                "type": "integer",
                "minimum": 0,
                "maximum": 2147483647,
            }
        branches.append(
            {
                "if": {
                    "properties": {"sensor_type": {"const": sensor_type.value}},
                    "required": ["sensor_type"],
                },
                "then": {
                    "properties": {
                        "value": value_schema,
                        "unit": {"const": unit.value},
                    }
                },
            }
        )
    branches.extend(
        [
            {
                "if": {
                    "properties": {"timebase": {"const": M8SourceTimebase.SIMULATION_TICK.value}},
                    "required": ["timebase"],
                },
                "then": {
                    "properties": {
                        "observed_at_utc": {"type": "null"},
                        "simulation_tick": {"type": "integer", "minimum": 0},
                        "simulated": {"const": True},
                        "display_badge": {"const": "SIMULATED · SENSOR"},
                    },
                    "required": ["simulation_tick"],
                },
                "else": {
                    "properties": {
                        "observed_at_utc": {"type": "string", "format": "date-time"},
                        "simulation_tick": {"type": "null"},
                        "simulated": {"const": False},
                        "display_badge": {"const": "LIVE · SENSOR"},
                    },
                    "required": ["observed_at_utc"],
                },
            }
        ]
    )
    schema["allOf"] = branches


def _risk_rule_json_schema(schema: dict[str, Any]) -> None:
    schema["allOf"] = [
        {
            "if": {
                "properties": {"operator": {"const": M8SensorRiskOperator.BOOLEAN_EQUALS.value}},
                "required": ["operator"],
            },
            "then": {
                "properties": {
                    "boolean_threshold": {"type": "boolean"},
                    "integer_threshold": {"type": "null"},
                },
                "required": ["boolean_threshold"],
            },
            "else": {
                "properties": {
                    "boolean_threshold": {"type": "null"},
                    "integer_threshold": {"type": "integer"},
                },
                "required": ["integer_threshold"],
            },
        },
        {
            "if": {
                "properties": {"create_pending_case": {"const": True}},
                "required": ["create_pending_case"],
            },
            "then": {
                "properties": {"response_deadline_seconds": {"type": "integer", "minimum": 1}},
                "required": ["response_deadline_seconds"],
            },
            "else": {"properties": {"response_deadline_seconds": {"type": "null"}}},
        },
    ]


def _risk_assessment_json_schema(schema: dict[str, Any]) -> None:
    schema["allOf"] = [
        {
            "properties": {
                "human_verification_required": {"const": True},
                "direct_disciplinary_action_permitted": {"const": False},
                "life_safety_action_permitted": {"const": False},
                "certified_fire_detection_claim_permitted": {"const": False},
            }
        }
    ]


class M8SensorSample(FrozenContractModel):
    """One integrity-bound sample from a catalogued sensor source."""

    model_config = ConfigDict(json_schema_extra=_sensor_sample_json_schema)

    schema_version: Literal["m8-sensor-sample-v1"] = "m8-sensor-sample-v1"
    source_catalog_id: Sha256Hex
    source: M8OperationalSource
    source_sequence: int = Field(ge=0, strict=True)
    observed_at_utc: datetime | None = None
    simulation_tick: int | None = Field(default=None, ge=0, strict=True)
    value: M8SensorScalar
    quality: M8SensorQuality
    raw_signal_ref: str = Field(min_length=1, max_length=MAX_M8_RAW_SIGNAL_REF_LENGTH)
    raw_signal_sha256: Sha256Hex
    adapter_input_authority_id: Sha256Hex
    adapter_manifest_id: Sha256Hex

    @field_validator("observed_at_utc")
    @classmethod
    def validate_observed_at_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _validate_utc(value, "M8 observed_at_utc")

    @field_validator("raw_signal_ref")
    @classmethod
    def validate_raw_signal_ref(cls, value: str) -> str:
        return _validate_raw_signal_ref(value)

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
                "source_id",
                "device_id",
                "location_id",
                "sensor_type",
                "timebase",
                "unit",
                "simulated",
                "display_badge",
                "sample_integrity_sha256",
                "sample_id",
            ),
        )
        sample = handler(payload)
        _verify_computed_claims(sample, claims)
        return sample

    @model_validator(mode="after")
    def validate_source_and_value(self) -> Self:
        if self.source.source_kind != M8OperationalSourceKind.SENSOR:
            raise ValueError("M8 sensor sample requires a SENSOR operational source")
        if self.source.mode not in {
            M8OperationalSourceMode.LIVE_SENSOR,
            M8OperationalSourceMode.SIMULATED_SENSOR,
        }:
            raise ValueError("M8 sensor sample source must use a sensor mode")
        if self.source.sensor_type is None:
            raise ValueError("M8 sensor sample source requires sensor_type")
        if self.adapter_manifest_id != self.source.manifest_id:
            raise ValueError("M8 sample adapter manifest must match source authority")
        if self.source.timebase == M8SourceTimebase.SIMULATION_TICK:
            if self.simulation_tick is None or self.observed_at_utc is not None:
                raise ValueError("M8 simulated sample requires only simulation_tick time")
        elif self.observed_at_utc is None or self.simulation_tick is not None:
            raise ValueError("M8 live sample requires observed_at_utc and forbids simulation_tick")
        _validate_sensor_value(self.source.sensor_type, self.value)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_id(self) -> ReferenceToken:
        return self.source.source_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def device_id(self) -> ReferenceToken:
        return self.source.device_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def location_id(self) -> ReferenceToken:
        return self.source.location_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sensor_type(self) -> M8SensorType:
        sensor_type = self.source.sensor_type
        if sensor_type is None:  # pragma: no cover - guarded by the model validator
            raise ValueError("M8 sensor sample source is missing sensor_type")
        return sensor_type

    @computed_field  # type: ignore[prop-decorator]
    @property
    def timebase(self) -> M8SourceTimebase:
        return self.source.timebase

    @computed_field  # type: ignore[prop-decorator]
    @property
    def unit(self) -> M8SensorUnit:
        return _SENSOR_UNIT[self.sensor_type]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulated(self) -> bool:
        return self.source.simulated

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_badge(self) -> str:
        return self.source.display_badge

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_integrity_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-sample-integrity",
                1,
                self.source_catalog_id,
                self.source.model_dump(mode="json"),
                self.source_sequence,
                _canonical_utc(self.observed_at_utc) if self.observed_at_utc else None,
                self.simulation_tick,
                self.value,
                self.quality,
                self.raw_signal_ref,
                self.raw_signal_sha256,
                self.adapter_input_authority_id,
                self.adapter_manifest_id,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-sample",
                1,
                self.source_id,
                self.source_sequence,
                self.sample_integrity_sha256,
            ]
        )


class M8SensorAdapterCapabilityAuthorityV1(FrozenContractModel):
    """Pinned sensor-adapter modes, types, bounds, and offline/replay behavior."""

    schema_version: Literal["m8-sensor-adapter-capability-authority-v1"] = (
        "m8-sensor-adapter-capability-authority-v1"
    )
    adapter_id: ReferenceToken
    adapter_manifest_id: Sha256Hex
    supported_source_modes: tuple[M8OperationalSourceMode, ...] = Field(min_length=1)
    supported_sensor_types: tuple[M8SensorType, ...] = Field(min_length=1)
    offline_capable: StrictBool
    network_required: StrictBool
    deterministic_replay: StrictBool
    raw_reference_required: StrictBool
    max_batch_size: int = Field(ge=1, le=MAX_M8_SENSOR_BATCH_SIZE, strict=True)
    poll_timeout_ms: int = Field(ge=1, le=60_000, strict=True)

    @field_validator("adapter_id")
    @classmethod
    def validate_adapter_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 sensor adapter_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("capability_id",))
        capability = handler(payload)
        _verify_computed_claims(capability, claims)
        return capability

    @model_validator(mode="after")
    def validate_capability_inventory(self) -> Self:
        allowed_modes = {
            M8OperationalSourceMode.LIVE_SENSOR,
            M8OperationalSourceMode.SIMULATED_SENSOR,
        }
        if not set(self.supported_source_modes).issubset(allowed_modes):
            raise ValueError("M8 sensor adapter supports only sensor source modes")
        if self.supported_source_modes != tuple(
            sorted(self.supported_source_modes, key=lambda item: item.value)
        ) or len(self.supported_source_modes) != len(set(self.supported_source_modes)):
            raise ValueError("M8 supported_source_modes must be unique and stable")
        if self.supported_sensor_types != tuple(
            sorted(self.supported_sensor_types, key=lambda item: item.value)
        ) or len(self.supported_sensor_types) != len(set(self.supported_sensor_types)):
            raise ValueError("M8 supported_sensor_types must be unique and stable")
        if self.raw_reference_required is not True:
            raise ValueError("M8 sensor adapters must retain raw signal references")
        if self.offline_capable and self.network_required:
            raise ValueError("M8 offline-capable adapter cannot require network access")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def capability_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-adapter-capability-authority",
                1,
                self.adapter_id,
                self.adapter_manifest_id,
                self.supported_source_modes,
                self.supported_sensor_types,
                self.offline_capable,
                self.network_required,
                self.deterministic_replay,
                self.raw_reference_required,
                self.max_batch_size,
                self.poll_timeout_ms,
            ]
        )


class M8SensorPollRequestV1(FrozenContractModel):
    """Bounded, manifest-pinned request for samples after one source sequence."""

    schema_version: Literal["m8-sensor-poll-request-v1"] = "m8-sensor-poll-request-v1"
    source_catalog_id: Sha256Hex
    source: M8OperationalSource
    adapter_capability: M8SensorAdapterCapabilityAuthorityV1
    after_source_sequence: int | None = Field(default=None, ge=0, strict=True)
    limit: int = Field(ge=1, le=MAX_M8_SENSOR_BATCH_SIZE, strict=True)
    timeout_ms: int = Field(ge=1, le=60_000, strict=True)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("request_id", "cache_key"))
        request = handler(payload)
        _verify_computed_claims(request, claims)
        return request

    @model_validator(mode="after")
    def validate_adapter_binding(self) -> Self:
        capability = self.adapter_capability
        if self.source.source_kind != M8OperationalSourceKind.SENSOR:
            raise ValueError("M8 sensor poll requires a SENSOR source")
        if self.source.adapter_id != capability.adapter_id:
            raise ValueError("M8 sensor poll source adapter_id conflicts with capability")
        if self.source.manifest_id != capability.adapter_manifest_id:
            raise ValueError("M8 sensor poll source manifest conflicts with capability")
        if self.source.mode not in capability.supported_source_modes:
            raise ValueError("M8 sensor poll source mode is not supported")
        if self.source.sensor_type not in capability.supported_sensor_types:
            raise ValueError("M8 sensor poll sensor_type is not supported")
        if self.limit > capability.max_batch_size:
            raise ValueError("M8 sensor poll limit exceeds adapter capability")
        if self.timeout_ms > capability.poll_timeout_ms:
            raise ValueError("M8 sensor poll timeout exceeds adapter capability")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-poll-request",
                1,
                self.source_catalog_id,
                self.source.model_dump(mode="json"),
                self.adapter_capability.capability_id,
                self.after_source_sequence,
                self.limit,
                self.timeout_ms,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cache_key(self) -> Sha256Hex:
        return sha256_hex(["m8-sensor-poll-cache", 1, self.request_id])


class M8SensorPollResultV1(FrozenContractModel):
    """Stable sample inventory returned for one exact poll request."""

    schema_version: Literal["m8-sensor-poll-result-v1"] = "m8-sensor-poll-result-v1"
    request: M8SensorPollRequestV1
    samples: tuple[M8SensorSample, ...] = Field(max_length=MAX_M8_SENSOR_BATCH_SIZE)
    exhausted: StrictBool

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
                "sample_count",
                "first_source_sequence",
                "last_source_sequence",
                "sample_inventory_sha256",
                "result_id",
            ),
        )
        result = handler(payload)
        _verify_computed_claims(result, claims)
        return result

    @model_validator(mode="after")
    def validate_sample_inventory(self) -> Self:
        if len(self.samples) > self.request.limit:
            raise ValueError("M8 sensor result exceeds requested sample limit")
        sequences = tuple(sample.source_sequence for sample in self.samples)
        if sequences != tuple(sorted(sequences)) or len(sequences) != len(set(sequences)):
            raise ValueError("M8 sensor result sequences must be unique and stable")
        if self.request.after_source_sequence is not None and any(
            sequence <= self.request.after_source_sequence for sequence in sequences
        ):
            raise ValueError("M8 sensor result contains a sequence at or before the request cut")
        for sample in self.samples:
            if sample.source_catalog_id != self.request.source_catalog_id:
                raise ValueError("M8 sensor result sample belongs to another source catalog")
            if sample.source != self.request.source:
                raise ValueError("M8 sensor result sample belongs to another source")
            if sample.adapter_manifest_id != self.request.adapter_capability.adapter_manifest_id:
                raise ValueError("M8 sensor result sample uses another adapter manifest")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_count(self) -> int:
        return len(self.samples)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def first_source_sequence(self) -> int | None:
        return self.samples[0].source_sequence if self.samples else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def last_source_sequence(self) -> int | None:
        return self.samples[-1].source_sequence if self.samples else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            ["m8-sensor-sample-inventory", 1, [sample.sample_id for sample in self.samples]]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def result_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-poll-result",
                1,
                self.request.request_id,
                self.sample_count,
                self.sample_inventory_sha256,
                self.exhausted,
            ]
        )


class M8SimulatedSensorReading(FrozenContractModel):
    """One deterministic reading in an offline simulation fixture."""

    schema_version: Literal["m8-simulated-sensor-reading-v1"] = "m8-simulated-sensor-reading-v1"
    source_sequence: int = Field(ge=0, strict=True)
    simulation_tick: int = Field(ge=0, strict=True)
    value: M8SensorScalar
    quality: M8SensorQuality = M8SensorQuality.GOOD


class M8SimulatedSensorScenarioAuthorityV1(FrozenContractModel):
    """Complete ordered fixture consumed by the default offline adapter."""

    schema_version: Literal["m8-simulated-sensor-scenario-authority-v1"] = (
        "m8-simulated-sensor-scenario-authority-v1"
    )
    scenario_id: ReferenceToken
    source_catalog_id: Sha256Hex
    source: M8OperationalSource
    readings: tuple[M8SimulatedSensorReading, ...] = Field(
        min_length=1,
        max_length=MAX_M8_SENSOR_SCENARIO_READINGS,
    )
    fixture_manifest_id: Sha256Hex

    @field_validator("scenario_id")
    @classmethod
    def validate_scenario_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 simulated sensor scenario_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("reading_inventory_sha256", "scenario_authority_id"),
        )
        scenario = handler(payload)
        _verify_computed_claims(scenario, claims)
        return scenario

    @model_validator(mode="after")
    def validate_scenario(self) -> Self:
        if self.source.mode != M8OperationalSourceMode.SIMULATED_SENSOR:
            raise ValueError("M8 simulated scenario requires a SIMULATED_SENSOR source")
        if self.source.sensor_type is None:
            raise ValueError("M8 simulated scenario source requires sensor_type")
        sequences = tuple(reading.source_sequence for reading in self.readings)
        ticks = tuple(reading.simulation_tick for reading in self.readings)
        if sequences != tuple(sorted(sequences)) or len(sequences) != len(set(sequences)):
            raise ValueError("M8 simulated source sequences must be unique and stable")
        if ticks != tuple(sorted(ticks)) or len(ticks) != len(set(ticks)):
            raise ValueError("M8 simulation ticks must be unique and stable")
        for reading in self.readings:
            _validate_sensor_value(self.source.sensor_type, reading.value)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reading_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-simulated-sensor-reading-inventory",
                1,
                [reading.model_dump(mode="json") for reading in self.readings],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def scenario_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-simulated-sensor-scenario-authority",
                1,
                self.scenario_id,
                self.source_catalog_id,
                self.source.model_dump(mode="json"),
                self.reading_inventory_sha256,
                self.fixture_manifest_id,
            ]
        )


class M8SensorRiskRule(FrozenContractModel):
    """One explicitly configured typed threshold; never free-text parsed."""

    model_config = ConfigDict(json_schema_extra=_risk_rule_json_schema)

    schema_version: Literal["m8-sensor-risk-rule-v1"] = "m8-sensor-risk-rule-v1"
    rule_id: ReferenceToken
    sensor_type: M8SensorType
    priority: int = Field(ge=0, strict=True)
    operator: M8SensorRiskOperator
    boolean_threshold: StrictBool | None = None
    integer_threshold: StrictInt | None = None
    risk_level: M8OperationalRiskLevel
    create_pending_case: StrictBool
    response_deadline_seconds: int | None = Field(default=None, ge=1, strict=True)

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 sensor risk rule_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("unit",))
        rule = handler(payload)
        _verify_computed_claims(rule, claims)
        return rule

    @model_validator(mode="after")
    def validate_threshold(self) -> Self:
        expected_operator = (
            M8SensorRiskOperator.BOOLEAN_EQUALS
            if self.sensor_type in _BOOLEAN_SENSOR_TYPES
            else M8SensorRiskOperator.INTEGER_GTE
        )
        if self.operator != expected_operator:
            raise ValueError("M8 sensor risk operator conflicts with sensor type")
        if self.operator == M8SensorRiskOperator.BOOLEAN_EQUALS:
            if self.boolean_threshold is None or self.integer_threshold is not None:
                raise ValueError("M8 boolean rule requires only boolean_threshold")
        elif self.integer_threshold is None or self.boolean_threshold is not None:
            raise ValueError("M8 integer rule requires only integer_threshold")
        if self.integer_threshold is not None:
            _validate_sensor_value(self.sensor_type, self.integer_threshold)
        if self.create_pending_case:
            if self.risk_level == M8OperationalRiskLevel.REMINDER:
                raise ValueError("M8 REMINDER rule cannot create a pending case")
            if self.response_deadline_seconds is None:
                raise ValueError("M8 case-creating rule requires a response deadline")
        elif self.response_deadline_seconds is not None:
            raise ValueError("M8 non-case rule cannot declare a response deadline")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def unit(self) -> M8SensorUnit:
        return _SENSOR_UNIT[self.sensor_type]


class M8SensorRiskPolicyAuthorityV1(FrozenContractModel):
    """Versioned, ordered rule inventory separate from ordinary documents."""

    schema_version: Literal["m8-sensor-risk-policy-authority-v1"] = (
        "m8-sensor-risk-policy-authority-v1"
    )
    policy_id: ReferenceToken
    revision: int = Field(gt=0, strict=True)
    purpose: M8SensorRiskPolicyPurpose
    rules: tuple[M8SensorRiskRule, ...] = Field(
        min_length=1,
        max_length=MAX_M8_SENSOR_RISK_RULES,
    )
    policy_manifest_id: Sha256Hex

    @field_validator("policy_id")
    @classmethod
    def validate_policy_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 sensor risk policy_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("rule_inventory_sha256", "policy_authority_id"),
        )
        policy = handler(payload)
        _verify_computed_claims(policy, claims)
        return policy

    @model_validator(mode="after")
    def validate_rule_inventory(self) -> Self:
        keys = tuple((rule.sensor_type.value, rule.priority, rule.rule_id) for rule in self.rules)
        if keys != tuple(sorted(keys)):
            raise ValueError("M8 sensor risk rules must use stable type/priority/id order")
        if len(keys) != len(set(keys)):
            raise ValueError("M8 sensor risk rules must be unique")
        type_priorities = tuple((rule.sensor_type, rule.priority) for rule in self.rules)
        if len(type_priorities) != len(set(type_priorities)):
            raise ValueError("M8 sensor risk rule priority must be unique per sensor type")
        for sensor_type in M8SensorType:
            type_rules = tuple(rule for rule in self.rules if rule.sensor_type == sensor_type)
            levels = tuple(_RISK_LEVEL_RANK[rule.risk_level] for rule in type_rules)
            if levels != tuple(sorted(levels, reverse=True)):
                raise ValueError("M8 sensor risk priority must order higher risk first")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-risk-rule-inventory",
                1,
                [rule.model_dump(mode="json") for rule in self.rules],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def policy_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-risk-policy-authority",
                1,
                self.policy_id,
                self.revision,
                self.purpose,
                self.rule_inventory_sha256,
                self.policy_manifest_id,
            ]
        )


class M8SensorRiskAssessmentV1(FrozenContractModel):
    """Deterministic advisory assessment that can only recommend a pending case."""

    model_config = ConfigDict(json_schema_extra=_risk_assessment_json_schema)

    schema_version: Literal["m8-sensor-risk-assessment-v1"] = "m8-sensor-risk-assessment-v1"
    sample: M8SensorSample
    policy: M8SensorRiskPolicyAuthorityV1
    evaluator_manifest_id: Sha256Hex

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
                "matched_rule_id",
                "assessment_reason_code",
                "risk_level",
                "create_pending_case_recommended",
                "response_deadline_seconds",
                "human_verification_required",
                "direct_disciplinary_action_permitted",
                "life_safety_action_permitted",
                "certified_fire_detection_claim_permitted",
                "display_badge",
                "risk_assessment_id",
            ),
        )
        assessment = handler(payload)
        _verify_computed_claims(assessment, claims)
        return assessment

    def _matched_rule(self) -> M8SensorRiskRule | None:
        if self.sample.quality != M8SensorQuality.GOOD:
            return None
        for rule in self.policy.rules:
            if rule.sensor_type != self.sample.sensor_type:
                continue
            if rule.operator == M8SensorRiskOperator.BOOLEAN_EQUALS:
                if self.sample.value is rule.boolean_threshold:
                    return rule
            elif (
                isinstance(self.sample.value, int)
                and not isinstance(self.sample.value, bool)
                and rule.integer_threshold is not None
                and self.sample.value >= rule.integer_threshold
            ):
                return rule
        return None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def matched_rule_id(self) -> ReferenceToken | None:
        rule = self._matched_rule()
        return rule.rule_id if rule else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def assessment_reason_code(self) -> M8SensorAssessmentReasonCode:
        if self.sample.quality != M8SensorQuality.GOOD:
            return M8SensorAssessmentReasonCode.SAMPLE_QUALITY_NOT_GOOD
        if self._matched_rule() is None:
            return M8SensorAssessmentReasonCode.NO_MATCHING_RULE
        return M8SensorAssessmentReasonCode.MATCHED_RULE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_level(self) -> M8OperationalRiskLevel:
        rule = self._matched_rule()
        return rule.risk_level if rule else M8OperationalRiskLevel.REMINDER

    @computed_field  # type: ignore[prop-decorator]
    @property
    def create_pending_case_recommended(self) -> bool:
        rule = self._matched_rule()
        return bool(rule and rule.create_pending_case)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def response_deadline_seconds(self) -> int | None:
        rule = self._matched_rule()
        return rule.response_deadline_seconds if rule else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def human_verification_required(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def life_safety_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def certified_fire_detection_claim_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_badge(self) -> str:
        if self.sample.simulated and self.risk_level == M8OperationalRiskLevel.EMERGENCY:
            return "SIMULATED · EMERGENCY CANDIDATE · NOT CERTIFIED FIRE DETECTION"
        if self.sample.simulated:
            return f"SIMULATED · {self.risk_level.value} CANDIDATE"
        return f"LIVE SENSOR · {self.risk_level.value} CANDIDATE · NOT CERTIFIED BY LABCOURT"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_assessment_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-sensor-risk-assessment",
                1,
                self.sample.sample_id,
                self.policy.policy_authority_id,
                self.matched_rule_id,
                self.assessment_reason_code,
                self.risk_level,
                self.create_pending_case_recommended,
                self.response_deadline_seconds,
                self.human_verification_required,
                self.direct_disciplinary_action_permitted,
                self.life_safety_action_permitted,
                self.certified_fire_detection_claim_permitted,
                self.evaluator_manifest_id,
            ]
        )


__all__ = [
    "MAX_M8_RAW_SIGNAL_REF_LENGTH",
    "MAX_M8_SENSOR_BATCH_SIZE",
    "MAX_M8_SENSOR_RISK_RULES",
    "MAX_M8_SENSOR_SCENARIO_READINGS",
    "M8SensorAdapterCapabilityAuthorityV1",
    "M8SensorAssessmentReasonCode",
    "M8SensorPollRequestV1",
    "M8SensorPollResultV1",
    "M8SensorQuality",
    "M8SensorRiskAssessmentV1",
    "M8SensorRiskOperator",
    "M8SensorRiskPolicyAuthorityV1",
    "M8SensorRiskPolicyPurpose",
    "M8SensorRiskRule",
    "M8SensorSample",
    "M8SensorScalar",
    "M8SensorUnit",
    "M8SimulatedSensorReading",
    "M8SimulatedSensorScenarioAuthorityV1",
]
