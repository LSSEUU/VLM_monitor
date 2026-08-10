from __future__ import annotations

from pathlib import Path

from labcourt.adapters.simulated_sensors import DeterministicSimulatedSensorAdapter
from labcourt.adapters.storage.sqlite_m8_inventory_repository import SQLiteM8InventoryRepository
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.adapters.storage.sqlite_m8_sensor_persistence_repository import (
    SQLiteM8SensorPersistenceRepository,
)
from labcourt.application.m8_sensor_demo import build_offline_smoke_demo_bundle
from labcourt.contracts.m8_access_cases import (
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseCreateCommandV1,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_operations import (
    M8CampusLocation,
    M8CampusLocationKind,
    M8CampusTopologyAuthorityV1,
    M8OperationalSource,
    M8OperationalSourceCatalogAuthorityV1,
    M8OperationalSourceMode,
    M8SensorType,
)
from labcourt.contracts.m8_projections import M8ProjectionSourceObservationState
from labcourt.contracts.m8_sensor_signals import M8SensorPollRequestV1
from labcourt.services.m8_operations_projection import M8OperationsProjectionService

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BUSY_TIMEOUT_MS = 5_000


def _topology() -> M8CampusTopologyAuthorityV1:
    return M8CampusTopologyAuthorityV1(
        revision=1,
        locations=(
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
        ),
        manifest_id=SHA_A,
    )


def _source() -> M8OperationalSource:
    return M8OperationalSource(
        source_id="sensor-simulated-smoke-01",
        device_id="device-simulated-smoke-01",
        location_id="room-chem-301",
        mode=M8OperationalSourceMode.SIMULATED_SENSOR,
        sensor_type=M8SensorType.SMOKE,
        adapter_id="m8-offline-sensor-simulator",
        manifest_id=SHA_B,
    )


def _catalog(revision: int = 1) -> M8OperationalSourceCatalogAuthorityV1:
    return M8OperationalSourceCatalogAuthorityV1(
        revision=revision,
        topology=_topology(),
        sources=(_source(),),
        catalog_manifest_id=SHA_C,
    )


def test_projection_service_builds_stable_current_cut_and_survives_catalog_revision(
    tmp_path: Path,
) -> None:
    root = tmp_path / "operations"
    root.mkdir()
    database = root / "labcourt.sqlite3"
    inventory = SQLiteM8InventoryRepository.initialize(database, BUSY_TIMEOUT_MS, SHA_A)
    topology_receipt = inventory.publish_topology(_topology(), None)
    catalog_receipt = inventory.publish_source_catalog(_catalog(), None)
    operations = SQLiteM8OperationsRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    sensors = SQLiteM8SensorPersistenceRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    notifications = SQLiteM8NotificationRepository(database, BUSY_TIMEOUT_MS, SHA_A)

    bundle = build_offline_smoke_demo_bundle(
        source_catalog_id=catalog_receipt.catalog.catalog_id,
        location_id="room-chem-301",
        adapter_manifest_id=SHA_B,
        fixture_manifest_id=SHA_C,
        policy_manifest_id=SHA_D,
    )
    adapter = DeterministicSimulatedSensorAdapter(bundle.scenario, bundle.capability)
    request = M8SensorPollRequestV1(
        source_catalog_id=catalog_receipt.catalog.catalog_id,
        source=bundle.scenario.source,
        adapter_capability=bundle.capability,
        limit=2,
        timeout_ms=500,
    )
    poll = adapter.poll(request)
    raw = tuple(adapter.read_raw_signal(item.raw_signal_ref) for item in poll.samples)
    cache = sensors.commit_poll_result(poll, raw, SHA_D, SHA_E)
    latest_sample = cache.sample_receipts[-1]
    case = operations.create_operational_case(
        M8OperationalCaseCreateCommandV1(
            source_catalog_id=catalog_receipt.catalog.catalog_id,
            location_id="room-chem-301",
            risk_level=M8OperationalRiskLevel.EMERGENCY,
            policy_rule_id="simulated-smoke-active-emergency-v1",
            policy_manifest_id=SHA_D,
            source_ids=(_source().source_id,),
            simulated_source_ids=(_source().source_id,),
            trigger_authorities=(
                M8AuthorityReference(
                    kind=M8AuthorityReferenceKind.SENSOR_SIGNAL,
                    authority_id=latest_sample.sample.sample_id,
                    document_sha256=latest_sample.sample_document_sha256,
                ),
            ),
            automation_component_id="m8-offline-case-builder",
            automation_manifest_id=SHA_E,
        ),
        "student-01",
        SHA_D,
        SHA_E,
    )
    service = M8OperationsProjectionService(
        inventory,
        operations,
        sensors,
        notifications,
        SHA_E,
    )

    projection = service.current_projection("campus-main")
    assert projection.topology_receipt == topology_receipt
    assert projection.source_catalog_receipt == catalog_receipt
    assert projection.current_cases == (case,)
    assert projection.case_audit_events == (case.audit_event,)
    assert projection.current_notifications == ()
    assert projection.sources[0].latest_sample_receipt == latest_sample
    assert projection.sources[0].observation_state == (
        M8ProjectionSourceObservationState.PERSISTED_SIMULATED_SENSOR_SAMPLE
    )
    assert projection.sources[0].display_badge == "SIMULATED · SENSOR"
    assert projection.overview.observed_sensor_count == 1
    assert projection.overview.active_major_case_count == 1

    catalog_v2 = inventory.publish_source_catalog(_catalog(revision=2), 1)
    revised = service.current_projection("campus-main")
    assert revised.source_catalog_receipt == catalog_v2
    assert revised.current_cases == (case,)
    assert revised.sources[0].latest_sample_receipt is None
    assert revised.sources[0].observation_state == (
        M8ProjectionSourceObservationState.NO_PERSISTED_SAMPLE
    )
