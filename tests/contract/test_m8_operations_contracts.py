from __future__ import annotations

from collections.abc import Callable

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from labcourt.contracts.m8_operations import (
    M8CampusLocation,
    M8CampusLocationKind,
    M8CampusTopologyAuthorityV1,
    M8OperationalSource,
    M8OperationalSourceCatalogAuthorityV1,
    M8OperationalSourceKind,
    M8OperationalSourceMode,
    M8SensorType,
    M8SourceTimebase,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _locations() -> tuple[M8CampusLocation, ...]:
    return (
        M8CampusLocation(
            location_id="campus-main",
            kind=M8CampusLocationKind.CAMPUS,
            parent_location_id=None,
            display_name="主校区",
        ),
        M8CampusLocation(
            location_id="building-chem",
            kind=M8CampusLocationKind.BUILDING,
            parent_location_id="campus-main",
            display_name="化学楼",
        ),
        M8CampusLocation(
            location_id="floor-chem-03",
            kind=M8CampusLocationKind.FLOOR,
            parent_location_id="building-chem",
            display_name="三层",
        ),
        M8CampusLocation(
            location_id="room-chem-301",
            kind=M8CampusLocationKind.ROOM,
            parent_location_id="floor-chem-03",
            display_name="实验室 301",
        ),
    )


def _topology() -> M8CampusTopologyAuthorityV1:
    return M8CampusTopologyAuthorityV1(
        revision=1,
        locations=_locations(),
        manifest_id=SHA_A,
    )


def _source(
    mode: M8OperationalSourceMode,
    *,
    source_id: str = "source-01",
    device_id: str = "device-01",
    location_id: str = "room-chem-301",
    sensor_type: M8SensorType | None = None,
    certification_id: str | None = None,
    emergency_authority_enabled: bool = False,
) -> M8OperationalSource:
    return M8OperationalSource(
        source_id=source_id,
        device_id=device_id,
        location_id=location_id,
        mode=mode,
        sensor_type=sensor_type,
        adapter_id="adapter-offline-v1",
        manifest_id=SHA_B,
        certification_id=certification_id,
        emergency_authority_enabled=emergency_authority_enabled,
        raw_reference_required=True,
    )


def test_topology_is_complete_ordered_content_addressed_and_strict() -> None:
    topology = _topology()

    assert topology.campus_id == "campus-main"
    assert topology.location_count == 4
    assert len(topology.topology_id) == 64
    assert M8CampusTopologyAuthorityV1.model_validate(topology.model_dump(mode="json")) == topology

    forged = topology.model_dump(mode="json")
    forged["topology_id"] = "0" * 64
    with pytest.raises(ValidationError, match="topology_id"):
        M8CampusTopologyAuthorityV1.model_validate(forged)

    extra = topology.model_dump(mode="json")
    extra["wall_clock"] = "forbidden"
    with pytest.raises(ValidationError, match="Extra inputs"):
        M8CampusTopologyAuthorityV1.model_validate(extra)


@pytest.mark.parametrize(
    ("index", "updates"),
    (
        (1, {"parent_location_id": "missing"}),
        (2, {"kind": M8CampusLocationKind.ROOM}),
        (3, {"location_id": "floor-chem-03"}),
        (
            3,
            {
                "kind": M8CampusLocationKind.CAMPUS,
                "parent_location_id": None,
            },
        ),
    ),
)
def test_topology_rejects_orphans_wrong_levels_duplicates_and_multiple_roots(
    index: int,
    updates: dict[str, object],
) -> None:
    items = list(_locations())
    with pytest.raises(ValidationError):
        items[index] = items[index].model_copy(update=updates)
        _topology().model_copy(update={"locations": tuple(items)})


def test_topology_rejects_noncanonical_parent_first_order_and_bool_revision() -> None:
    locations = _locations()
    with pytest.raises(ValidationError, match="parent-first stable order"):
        _topology().model_copy(
            update={"locations": (locations[0], locations[1], locations[3], locations[2])}
        )
    with pytest.raises(ValidationError):
        _topology().model_copy(update={"revision": True})


@pytest.mark.parametrize(
    (
        "mode",
        "sensor_type",
        "certification_id",
        "emergency_enabled",
        "expected_kind",
        "expected_timebase",
        "expected_simulated",
        "expected_badge",
        "expected_life_safety",
    ),
    (
        (
            M8OperationalSourceMode.LIVE_CAMERA,
            None,
            None,
            False,
            M8OperationalSourceKind.CAMERA,
            M8SourceTimebase.FRAME_INDEX,
            False,
            "LIVE · CAMERA",
            False,
        ),
        (
            M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION,
            None,
            None,
            False,
            M8OperationalSourceKind.CAMERA,
            M8SourceTimebase.FRAME_INDEX,
            True,
            "SIMULATED · RECORDED VIDEO",
            False,
        ),
        (
            M8OperationalSourceMode.LIVE_SENSOR,
            M8SensorType.SMOKE,
            "campus-fire-cert-2026",
            True,
            M8OperationalSourceKind.SENSOR,
            M8SourceTimebase.DEVICE_TIMESTAMP_UTC,
            False,
            "LIVE · SENSOR",
            True,
        ),
        (
            M8OperationalSourceMode.SIMULATED_SENSOR,
            M8SensorType.SMOKE,
            None,
            False,
            M8OperationalSourceKind.SENSOR,
            M8SourceTimebase.SIMULATION_TICK,
            True,
            "SIMULATED · SENSOR",
            False,
        ),
    ),
)
def test_source_mode_derives_unforgeable_truth_and_life_safety_matrix(
    mode: M8OperationalSourceMode,
    sensor_type: M8SensorType | None,
    certification_id: str | None,
    emergency_enabled: bool,
    expected_kind: M8OperationalSourceKind,
    expected_timebase: M8SourceTimebase,
    expected_simulated: bool,
    expected_badge: str,
    expected_life_safety: bool,
) -> None:
    source = _source(
        mode,
        sensor_type=sensor_type,
        certification_id=certification_id,
        emergency_authority_enabled=emergency_enabled,
    )

    assert source.source_kind == expected_kind
    assert source.timebase == expected_timebase
    assert source.simulated is expected_simulated
    assert source.display_badge == expected_badge
    assert source.life_safety_eligible is expected_life_safety
    Draft202012Validator(M8OperationalSource.model_json_schema(mode="serialization")).validate(
        source.model_dump(mode="json")
    )

    payload = source.model_dump(mode="json")
    payload["simulated"] = not expected_simulated
    with pytest.raises(ValidationError, match="simulated"):
        M8OperationalSource.model_validate(payload)


@pytest.mark.parametrize(
    "source",
    (
        lambda: _source(
            M8OperationalSourceMode.LIVE_CAMERA,
            sensor_type=M8SensorType.SMOKE,
        ),
        lambda: _source(
            M8OperationalSourceMode.SIMULATED_SENSOR,
            sensor_type=None,
        ),
        lambda: _source(
            M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION,
            certification_id="forbidden",
        ),
        lambda: _source(
            M8OperationalSourceMode.SIMULATED_SENSOR,
            sensor_type=M8SensorType.EMERGENCY_BUTTON,
            certification_id="forbidden",
        ),
        lambda: _source(
            M8OperationalSourceMode.LIVE_SENSOR,
            sensor_type=M8SensorType.SMOKE,
            emergency_authority_enabled=True,
        ),
    ),
)
def test_source_rejects_kind_certification_and_emergency_grafts(
    source: Callable[[], M8OperationalSource],
) -> None:
    with pytest.raises(ValidationError):
        source()


def test_source_requires_raw_reference_and_strict_boolean() -> None:
    payload = _source(M8OperationalSourceMode.LIVE_CAMERA).model_dump(mode="json")
    payload["raw_reference_required"] = False
    with pytest.raises(ValidationError):
        M8OperationalSource.model_validate(payload)
    payload["raw_reference_required"] = "true"
    with pytest.raises(ValidationError):
        M8OperationalSource.model_validate(payload)


def test_catalog_binds_sources_to_rooms_and_derives_inventory_identity() -> None:
    catalog = M8OperationalSourceCatalogAuthorityV1(
        revision=1,
        topology=_topology(),
        sources=(
            _source(
                M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION,
                source_id="camera-recorded-01",
                device_id="camera-01",
            ),
            _source(
                M8OperationalSourceMode.SIMULATED_SENSOR,
                source_id="sensor-simulated-01",
                device_id="sensor-01",
                sensor_type=M8SensorType.SMOKE,
            ),
        ),
        catalog_manifest_id=SHA_C,
    )

    assert catalog.source_count == 2
    assert catalog.simulated_source_count == 2
    assert catalog.life_safety_eligible_source_count == 0
    assert len(catalog.source_inventory_sha256) == 64
    assert len(catalog.catalog_id) == 64
    Draft202012Validator(
        M8OperationalSourceCatalogAuthorityV1.model_json_schema(mode="serialization")
    ).validate(catalog.model_dump(mode="json"))
    assert (
        M8OperationalSourceCatalogAuthorityV1.model_validate(catalog.model_dump(mode="json"))
        == catalog
    )

    forged = catalog.model_dump(mode="json")
    forged["source_count"] = 3
    with pytest.raises(ValidationError, match="source_count"):
        M8OperationalSourceCatalogAuthorityV1.model_validate(forged)


def test_catalog_rejects_non_room_unknown_duplicate_and_unstable_sources() -> None:
    first = _source(
        M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION,
        source_id="source-a",
        device_id="device-a",
    )
    second = _source(
        M8OperationalSourceMode.SIMULATED_SENSOR,
        source_id="source-b",
        device_id="device-b",
        sensor_type=M8SensorType.WATER_LEAK,
    )

    def build(sources: tuple[M8OperationalSource, ...]) -> None:
        M8OperationalSourceCatalogAuthorityV1(
            revision=1,
            topology=_topology(),
            sources=sources,
            catalog_manifest_id=SHA_C,
        )

    with pytest.raises(ValidationError, match="stable source_id order"):
        build((second, first))
    with pytest.raises(ValidationError, match="room"):
        build((first.model_copy(update={"location_id": "floor-chem-03"}),))
    with pytest.raises(ValidationError, match="unknown location"):
        build((first.model_copy(update={"location_id": "room-unknown"}),))
    with pytest.raises(ValidationError, match="source_id"):
        build((first, second.model_copy(update={"source_id": first.source_id})))
    with pytest.raises(ValidationError, match="device_id"):
        build((first, second.model_copy(update={"device_id": first.device_id})))


def test_m8_schemas_are_registered_as_strict_serialization_contracts() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-campus-location": M8CampusLocation,
        "m8-campus-topology-authority-v1": M8CampusTopologyAuthorityV1,
        "m8-operational-source": M8OperationalSource,
        "m8-operational-source-catalog-authority-v1": (M8OperationalSourceCatalogAuthorityV1),
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)

    for model in expected.values():
        schema = model.model_json_schema(mode="serialization")
        assert schema["additionalProperties"] is False

    source_schema = M8OperationalSource.model_json_schema(mode="serialization")
    for field_name in (
        "source_kind",
        "timebase",
        "simulated",
        "display_badge",
        "life_safety_eligible",
    ):
        assert source_schema["properties"][field_name]["readOnly"] is True
        assert field_name in source_schema["required"]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sensor_type", M8SensorType.SMOKE.value),
        ("certification_id", "forbidden"),
        ("emergency_authority_enabled", True),
        ("raw_reference_required", False),
        ("source_kind", M8OperationalSourceKind.SENSOR.value),
        ("simulated", True),
    ),
)
def test_operational_source_schema_rejects_expressible_truth_grafts(
    field: str,
    value: object,
) -> None:
    payload = _source(M8OperationalSourceMode.LIVE_CAMERA).model_dump(mode="json")
    payload[field] = value
    validator = Draft202012Validator(M8OperationalSource.model_json_schema(mode="serialization"))

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(payload)
