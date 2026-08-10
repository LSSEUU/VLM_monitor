"""Additive M8 campus topology and operational-source truth contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_CAMPUS_LOCATIONS = 10_000
MAX_M8_OPERATIONAL_SOURCES = 20_000


class M8CampusLocationKind(StrEnum):
    CAMPUS = "CAMPUS"
    BUILDING = "BUILDING"
    FLOOR = "FLOOR"
    ROOM = "ROOM"


class M8OperationalSourceMode(StrEnum):
    LIVE_CAMERA = "LIVE_CAMERA"
    RECORDED_VIDEO_SIMULATION = "RECORDED_VIDEO_SIMULATION"
    LIVE_SENSOR = "LIVE_SENSOR"
    SIMULATED_SENSOR = "SIMULATED_SENSOR"


class M8OperationalSourceKind(StrEnum):
    CAMERA = "CAMERA"
    SENSOR = "SENSOR"


class M8SourceTimebase(StrEnum):
    FRAME_INDEX = "FRAME_INDEX"
    DEVICE_TIMESTAMP_UTC = "DEVICE_TIMESTAMP_UTC"
    SIMULATION_TICK = "SIMULATION_TICK"


class M8SensorType(StrEnum):
    SMOKE = "SMOKE"
    TEMPERATURE = "TEMPERATURE"
    COMBUSTIBLE_GAS = "COMBUSTIBLE_GAS"
    TOXIC_GAS = "TOXIC_GAS"
    DOOR_CONTACT = "DOOR_CONTACT"
    WATER_LEAK = "WATER_LEAK"
    EMERGENCY_BUTTON = "EMERGENCY_BUTTON"


_LOCATION_RANK = {
    M8CampusLocationKind.CAMPUS: 0,
    M8CampusLocationKind.BUILDING: 1,
    M8CampusLocationKind.FLOOR: 2,
    M8CampusLocationKind.ROOM: 3,
}
_PARENT_KIND = {
    M8CampusLocationKind.BUILDING: M8CampusLocationKind.CAMPUS,
    M8CampusLocationKind.FLOOR: M8CampusLocationKind.BUILDING,
    M8CampusLocationKind.ROOM: M8CampusLocationKind.FLOOR,
}
_CAMERA_MODES = frozenset(
    {
        M8OperationalSourceMode.LIVE_CAMERA,
        M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION,
    }
)
_SIMULATED_MODES = frozenset(
    {
        M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION,
        M8OperationalSourceMode.SIMULATED_SENSOR,
    }
)
_MODE_TIMEBASE = {
    M8OperationalSourceMode.LIVE_CAMERA: M8SourceTimebase.FRAME_INDEX,
    M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION: M8SourceTimebase.FRAME_INDEX,
    M8OperationalSourceMode.LIVE_SENSOR: M8SourceTimebase.DEVICE_TIMESTAMP_UTC,
    M8OperationalSourceMode.SIMULATED_SENSOR: M8SourceTimebase.SIMULATION_TICK,
}
_MODE_BADGE = {
    M8OperationalSourceMode.LIVE_CAMERA: "LIVE · CAMERA",
    M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION: "SIMULATED · RECORDED VIDEO",
    M8OperationalSourceMode.LIVE_SENSOR: "LIVE · SENSOR",
    M8OperationalSourceMode.SIMULATED_SENSOR: "SIMULATED · SENSOR",
}


def _operational_source_json_schema(schema: dict[str, Any]) -> None:
    """Mirror the source-truth matrix for non-Python schema consumers."""

    schema["allOf"] = [
        {
            "properties": {"raw_reference_required": {"const": True}},
            "required": ["raw_reference_required"],
        },
        {
            "if": {
                "properties": {"mode": {"const": M8OperationalSourceMode.LIVE_CAMERA.value}},
                "required": ["mode"],
            },
            "then": {
                "properties": {
                    "sensor_type": {"type": "null"},
                    "certification_id": {"type": "null"},
                    "emergency_authority_enabled": {"const": False},
                    "source_kind": {"const": M8OperationalSourceKind.CAMERA.value},
                    "timebase": {"const": M8SourceTimebase.FRAME_INDEX.value},
                    "simulated": {"const": False},
                    "display_badge": {"const": _MODE_BADGE[M8OperationalSourceMode.LIVE_CAMERA]},
                    "life_safety_eligible": {"const": False},
                }
            },
        },
        {
            "if": {
                "properties": {
                    "mode": {"const": M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION.value}
                },
                "required": ["mode"],
            },
            "then": {
                "properties": {
                    "sensor_type": {"type": "null"},
                    "certification_id": {"type": "null"},
                    "emergency_authority_enabled": {"const": False},
                    "source_kind": {"const": M8OperationalSourceKind.CAMERA.value},
                    "timebase": {"const": M8SourceTimebase.FRAME_INDEX.value},
                    "simulated": {"const": True},
                    "display_badge": {
                        "const": _MODE_BADGE[M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION]
                    },
                    "life_safety_eligible": {"const": False},
                }
            },
        },
        {
            "if": {
                "properties": {"mode": {"const": M8OperationalSourceMode.LIVE_SENSOR.value}},
                "required": ["mode"],
            },
            "then": {
                "properties": {
                    "sensor_type": {
                        "type": "string",
                        "enum": [item.value for item in M8SensorType],
                    },
                    "certification_id": {
                        "anyOf": [
                            {"type": "null"},
                            {"type": "string", "pattern": r"^\S{1,128}$"},
                        ]
                    },
                    "source_kind": {"const": M8OperationalSourceKind.SENSOR.value},
                    "timebase": {"const": M8SourceTimebase.DEVICE_TIMESTAMP_UTC.value},
                    "simulated": {"const": False},
                    "display_badge": {"const": _MODE_BADGE[M8OperationalSourceMode.LIVE_SENSOR]},
                },
                "allOf": [
                    {
                        "if": {
                            "properties": {"emergency_authority_enabled": {"const": True}},
                            "required": ["emergency_authority_enabled"],
                        },
                        "then": {
                            "properties": {
                                "certification_id": {
                                    "type": "string",
                                    "pattern": r"^\S{1,128}$",
                                },
                                "life_safety_eligible": {"const": True},
                            },
                            "required": ["certification_id"],
                        },
                        "else": {"properties": {"life_safety_eligible": {"const": False}}},
                    }
                ],
            },
        },
        {
            "if": {
                "properties": {"mode": {"const": M8OperationalSourceMode.SIMULATED_SENSOR.value}},
                "required": ["mode"],
            },
            "then": {
                "properties": {
                    "sensor_type": {
                        "type": "string",
                        "enum": [item.value for item in M8SensorType],
                    },
                    "certification_id": {"type": "null"},
                    "emergency_authority_enabled": {"const": False},
                    "source_kind": {"const": M8OperationalSourceKind.SENSOR.value},
                    "timebase": {"const": M8SourceTimebase.SIMULATION_TICK.value},
                    "simulated": {"const": True},
                    "display_badge": {
                        "const": _MODE_BADGE[M8OperationalSourceMode.SIMULATED_SENSOR]
                    },
                    "life_safety_eligible": {"const": False},
                }
            },
        },
    ]


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
            raise ValueError(f"serialized {name} conflicts with derived M8 authority")


class M8CampusLocation(FrozenContractModel):
    """One stable node in the campus/building/floor/room hierarchy."""

    schema_version: Literal["m8-campus-location-v1"] = "m8-campus-location-v1"
    location_id: ReferenceToken
    kind: M8CampusLocationKind
    parent_location_id: ReferenceToken | None
    display_name: str = Field(min_length=1, max_length=128)

    @field_validator("location_id")
    @classmethod
    def validate_location_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 location_id")

    @field_validator("parent_location_id")
    @classmethod
    def validate_parent_location_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 parent_location_id")

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("M8 display_name must be bounded visible text without edge whitespace")
        return value

    @model_validator(mode="after")
    def validate_local_hierarchy_shape(self) -> Self:
        if self.kind == M8CampusLocationKind.CAMPUS:
            if self.parent_location_id is not None:
                raise ValueError("M8 CAMPUS location cannot have a parent")
        elif self.parent_location_id is None:
            raise ValueError("non-campus M8 location requires a parent")
        if self.parent_location_id == self.location_id:
            raise ValueError("M8 location cannot parent itself")
        return self


class M8CampusTopologyAuthorityV1(FrozenContractModel):
    """Complete parent-first campus topology snapshot."""

    schema_version: Literal["m8-campus-topology-authority-v1"] = "m8-campus-topology-authority-v1"
    revision: int = Field(gt=0, strict=True)
    locations: tuple[M8CampusLocation, ...] = Field(
        min_length=4,
        max_length=MAX_M8_CAMPUS_LOCATIONS,
    )
    manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("campus_id", "location_count", "topology_id"),
        )
        topology = handler(payload)
        _verify_computed_claims(topology, claims)
        return topology

    @model_validator(mode="after")
    def validate_complete_topology(self) -> Self:
        location_ids = tuple(location.location_id for location in self.locations)
        if len(location_ids) != len(set(location_ids)):
            raise ValueError("M8 topology location_id values must be unique")
        roots = tuple(
            location for location in self.locations if location.kind == M8CampusLocationKind.CAMPUS
        )
        if len(roots) != 1:
            raise ValueError("M8 topology requires exactly one CAMPUS root")
        expected_order = tuple(
            sorted(
                self.locations,
                key=lambda location: (
                    _LOCATION_RANK[location.kind],
                    location.parent_location_id or "",
                    location.location_id,
                ),
            )
        )
        if self.locations != expected_order:
            raise ValueError("M8 locations must use canonical parent-first stable order")

        prior: dict[str, M8CampusLocation] = {}
        for location in self.locations:
            if location.kind == M8CampusLocationKind.CAMPUS:
                if prior:
                    raise ValueError("M8 CAMPUS root must be the first location")
            else:
                parent = prior.get(location.parent_location_id or "")
                if parent is None:
                    raise ValueError("M8 location references an absent or later parent")
                if parent.kind != _PARENT_KIND[location.kind]:
                    raise ValueError("M8 location parent kind is not the adjacent hierarchy level")
            prior[location.location_id] = location
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def campus_id(self) -> ReferenceToken:
        return next(
            location.location_id
            for location in self.locations
            if location.kind == M8CampusLocationKind.CAMPUS
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def location_count(self) -> int:
        return len(self.locations)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def topology_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-campus-topology-authority",
                1,
                self.revision,
                [
                    location.model_dump(mode="json", exclude_computed_fields=True)
                    for location in self.locations
                ],
                self.manifest_id,
            ]
        )


class M8OperationalSource(FrozenContractModel):
    """One camera or sensor source with machine-enforced truth labeling."""

    model_config = ConfigDict(json_schema_extra=_operational_source_json_schema)

    schema_version: Literal["m8-operational-source-v1"] = "m8-operational-source-v1"
    source_id: ReferenceToken
    device_id: ReferenceToken
    location_id: ReferenceToken
    mode: M8OperationalSourceMode
    sensor_type: M8SensorType | None = None
    adapter_id: ReferenceToken
    manifest_id: Sha256Hex
    certification_id: str | None = Field(default=None, max_length=128)
    emergency_authority_enabled: StrictBool = False
    raw_reference_required: StrictBool = True

    @field_validator("source_id", "device_id", "location_id", "adapter_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 operational source reference")

    @field_validator("certification_id")
    @classmethod
    def validate_certification_id(cls, value: str | None) -> str | None:
        if value is not None and (
            not value or value != value.strip() or any(ord(character) < 33 for character in value)
        ):
            raise ValueError("M8 certification_id must be bounded visible text without whitespace")
        return value

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
                "source_kind",
                "timebase",
                "simulated",
                "display_badge",
                "life_safety_eligible",
            ),
        )
        source = handler(payload)
        _verify_computed_claims(source, claims)
        return source

    @model_validator(mode="after")
    def validate_source_truth_matrix(self) -> Self:
        if self.raw_reference_required is not True:
            raise ValueError("M8 operational sources require raw signal/media references")
        if self.mode in _CAMERA_MODES:
            if self.sensor_type is not None:
                raise ValueError("M8 camera source cannot declare a sensor_type")
        elif self.sensor_type is None:
            raise ValueError("M8 sensor source requires a closed sensor_type")
        if self.certification_id is not None and self.mode != M8OperationalSourceMode.LIVE_SENSOR:
            raise ValueError("only an M8 LIVE_SENSOR can declare certification_id")
        if self.emergency_authority_enabled and (
            self.mode != M8OperationalSourceMode.LIVE_SENSOR or self.certification_id is None
        ):
            raise ValueError(
                "M8 emergency authority requires a certified LIVE_SENSOR configuration"
            )
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_kind(self) -> M8OperationalSourceKind:
        if self.mode in _CAMERA_MODES:
            return M8OperationalSourceKind.CAMERA
        return M8OperationalSourceKind.SENSOR

    @computed_field  # type: ignore[prop-decorator]
    @property
    def timebase(self) -> M8SourceTimebase:
        return _MODE_TIMEBASE[self.mode]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulated(self) -> bool:
        return self.mode in _SIMULATED_MODES

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_badge(self) -> str:
        return _MODE_BADGE[self.mode]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def life_safety_eligible(self) -> bool:
        return bool(
            self.mode == M8OperationalSourceMode.LIVE_SENSOR
            and self.certification_id is not None
            and self.emergency_authority_enabled
        )


class M8OperationalSourceCatalogAuthorityV1(FrozenContractModel):
    """Complete topology-bound source catalog for one M8 revision."""

    schema_version: Literal["m8-operational-source-catalog-authority-v1"] = (
        "m8-operational-source-catalog-authority-v1"
    )
    revision: int = Field(gt=0, strict=True)
    topology: M8CampusTopologyAuthorityV1
    sources: tuple[M8OperationalSource, ...] = Field(
        min_length=1,
        max_length=MAX_M8_OPERATIONAL_SOURCES,
    )
    catalog_manifest_id: Sha256Hex

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
                "source_count",
                "simulated_source_count",
                "life_safety_eligible_source_count",
                "source_inventory_sha256",
                "catalog_id",
            ),
        )
        catalog = handler(payload)
        _verify_computed_claims(catalog, claims)
        return catalog

    @model_validator(mode="after")
    def validate_topology_bound_inventory(self) -> Self:
        source_ids = tuple(source.source_id for source in self.sources)
        device_ids = tuple(source.device_id for source in self.sources)
        if source_ids != tuple(sorted(source_ids)):
            raise ValueError("M8 catalog sources must use stable source_id order")
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("M8 catalog source_id values must be unique")
        if len(device_ids) != len(set(device_ids)):
            raise ValueError("M8 catalog device_id values must be unique")
        locations = {location.location_id: location for location in self.topology.locations}
        for source in self.sources:
            location = locations.get(source.location_id)
            if location is None:
                raise ValueError("M8 source references an unknown location")
            if location.kind != M8CampusLocationKind.ROOM:
                raise ValueError("M8 operational sources must bind to a room")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_count(self) -> int:
        return len(self.sources)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulated_source_count(self) -> int:
        return sum(source.simulated for source in self.sources)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def life_safety_eligible_source_count(self) -> int:
        return sum(source.life_safety_eligible for source in self.sources)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-source-inventory",
                1,
                [source.model_dump(mode="json") for source in self.sources],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def catalog_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-source-catalog-authority",
                1,
                self.revision,
                self.topology.topology_id,
                self.source_count,
                self.source_inventory_sha256,
                self.catalog_manifest_id,
            ]
        )


__all__ = [
    "MAX_M8_CAMPUS_LOCATIONS",
    "MAX_M8_OPERATIONAL_SOURCES",
    "M8CampusLocation",
    "M8CampusLocationKind",
    "M8CampusTopologyAuthorityV1",
    "M8OperationalSource",
    "M8OperationalSourceCatalogAuthorityV1",
    "M8OperationalSourceKind",
    "M8OperationalSourceMode",
    "M8SensorType",
    "M8SourceTimebase",
]
