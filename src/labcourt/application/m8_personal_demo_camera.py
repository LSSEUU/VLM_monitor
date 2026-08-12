"""Add one clearly simulated recorded-video camera to the personal Demo catalog."""

from __future__ import annotations

import hashlib
from pathlib import Path

from labcourt.adapters.simulated_sensors import DeterministicSimulatedSensorAdapter
from labcourt.adapters.storage.sqlite_m8_inventory_repository import SQLiteM8InventoryRepository
from labcourt.adapters.storage.sqlite_m8_sensor_persistence_repository import (
    SQLiteM8SensorPersistenceRepository,
)
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.application.m8_sensor_demo import build_offline_smoke_demo_bundle
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_operations import (
    M8OperationalSource,
    M8OperationalSourceCatalogAuthorityV1,
    M8OperationalSourceMode,
)
from labcourt.contracts.m8_personal_demo import M8PersonalDemoCameraReceiptV1
from labcourt.contracts.m8_sensor_signals import (
    M8SensorPollRequestV1,
    M8SimulatedSensorReading,
    M8SimulatedSensorScenarioAuthorityV1,
)

_BUSY_TIMEOUT_MS = 5_000


def _manifest(name: str) -> Sha256Hex:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def register_m8_personal_demo_camera(database_path: Path) -> M8PersonalDemoCameraReceiptV1:
    """Publish catalog revision 2 and refresh the sensor sample against that cut."""

    bootstrap = bootstrap_m8_personal_demo(database_path)
    repository_manifest_id = bootstrap.projection.topology_receipt.repository_manifest_id
    inventory = SQLiteM8InventoryRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    current = inventory.get_current_source_catalog(bootstrap.receipt.campus_id)
    camera = M8OperationalSource(
        source_id="camera-recorded-demo-01",
        device_id="device-recorded-camera-01",
        location_id="room-chem-301",
        mode=M8OperationalSourceMode.RECORDED_VIDEO_SIMULATION,
        adapter_id="m8-recorded-video-simulator",
        manifest_id=_manifest("labcourt-personal-demo-recorded-camera-adapter-v1"),
    )
    if current.catalog.revision == 1:
        catalog = M8OperationalSourceCatalogAuthorityV1(
            revision=2,
            topology=current.catalog.topology,
            sources=tuple(
                sorted((*current.catalog.sources, camera), key=lambda item: item.source_id)
            ),
            catalog_manifest_id=_manifest("labcourt-personal-demo-source-catalog-v2"),
        )
        current = inventory.publish_source_catalog(catalog, 1)
    elif current.catalog.revision != 2 or camera not in current.catalog.sources:
        raise ValueError("M8 personal Demo camera catalog authority changed")

    sensor_source = next(
        source
        for source in current.catalog.sources
        if source.source_id == bootstrap.receipt.source_id
    )
    smoke = build_offline_smoke_demo_bundle(
        source_catalog_id=current.catalog.catalog_id,
        location_id=bootstrap.receipt.case_location_id,
        adapter_manifest_id=sensor_source.manifest_id,
        fixture_manifest_id=_manifest("labcourt-personal-demo-smoke-fixture-v1"),
        policy_manifest_id=_manifest("labcourt-personal-demo-smoke-policy-v1"),
    )
    scenario = M8SimulatedSensorScenarioAuthorityV1(
        scenario_id="offline-smoke-emergency-demo-catalog-refresh-v2",
        source_catalog_id=current.catalog.catalog_id,
        source=sensor_source,
        readings=(
            M8SimulatedSensorReading(source_sequence=2, simulation_tick=10, value=False),
            M8SimulatedSensorReading(source_sequence=3, simulation_tick=15, value=True),
        ),
        fixture_manifest_id=_manifest("labcourt-personal-demo-smoke-camera-catalog-refresh-v2"),
    )
    adapter = DeterministicSimulatedSensorAdapter(scenario, smoke.capability)
    poll = adapter.poll(
        M8SensorPollRequestV1(
            source_catalog_id=current.catalog.catalog_id,
            source=sensor_source,
            adapter_capability=smoke.capability,
            limit=2,
            timeout_ms=500,
        )
    )
    raw_signals = tuple(adapter.read_raw_signal(sample.raw_signal_ref) for sample in poll.samples)
    sensors = SQLiteM8SensorPersistenceRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    sensor_commit = sensors.commit_poll_result(
        poll,
        raw_signals,
        _manifest("labcourt-personal-demo-raw-signal-store-v1"),
        _manifest("labcourt-personal-demo-sensor-cache-v1"),
    )
    return M8PersonalDemoCameraReceiptV1(
        source_catalog_id=current.catalog.catalog_id,
        source_catalog_commit_receipt_id=current.commit_receipt_id,
        sensor_refresh_commit_receipt_id=sensor_commit.commit_receipt_id,
        camera_manifest_id=_manifest("labcourt-personal-demo-camera-registration-v1"),
    )


__all__ = ["register_m8_personal_demo_camera"]
