from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.simulated_sensors import DeterministicSimulatedSensorAdapter
from labcourt.adapters.storage.sqlite_m8_inventory_repository import SQLiteM8InventoryRepository
from labcourt.adapters.storage.sqlite_m8_sensor_persistence_repository import (
    SQLiteM8SensorPersistenceRepository,
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
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorPollRequestV1,
    M8SensorPollResultV1,
    M8SimulatedSensorReading,
    M8SimulatedSensorScenarioAuthorityV1,
)
from labcourt.exceptions import ConcurrentModification

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
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
        device_id="sensor-smoke-01",
        location_id="room-chem-301",
        mode=M8OperationalSourceMode.SIMULATED_SENSOR,
        sensor_type=M8SensorType.SMOKE,
        adapter_id="m8-offline-sensor-simulator",
        manifest_id=SHA_B,
    )


def _catalog() -> M8OperationalSourceCatalogAuthorityV1:
    return M8OperationalSourceCatalogAuthorityV1(
        revision=1,
        topology=_topology(),
        sources=(_source(),),
        catalog_manifest_id=SHA_C,
    )


def _capability() -> M8SensorAdapterCapabilityAuthorityV1:
    return M8SensorAdapterCapabilityAuthorityV1(
        adapter_id=_source().adapter_id,
        adapter_manifest_id=_source().manifest_id,
        supported_source_modes=(M8OperationalSourceMode.SIMULATED_SENSOR,),
        supported_sensor_types=(M8SensorType.SMOKE,),
        offline_capable=True,
        network_required=False,
        deterministic_replay=True,
        raw_reference_required=True,
        max_batch_size=8,
        poll_timeout_ms=1_000,
    )


def _poll(
    catalog_id: str,
    *,
    scenario_id: str = "offline-smoke",
    value: bool = True,
    timeout_ms: int = 500,
    after_source_sequence: int | None = None,
) -> tuple[M8SensorPollResultV1, tuple[bytes, ...]]:
    scenario = M8SimulatedSensorScenarioAuthorityV1(
        scenario_id=scenario_id,
        source_catalog_id=catalog_id,
        source=_source(),
        readings=(
            M8SimulatedSensorReading(
                source_sequence=1,
                simulation_tick=5,
                value=value,
            ),
        ),
        fixture_manifest_id=SHA_D,
    )
    adapter = DeterministicSimulatedSensorAdapter(scenario, _capability())
    request = M8SensorPollRequestV1(
        source_catalog_id=catalog_id,
        source=_source(),
        adapter_capability=_capability(),
        after_source_sequence=after_source_sequence,
        limit=1,
        timeout_ms=timeout_ms,
    )
    result = adapter.poll(request)
    raw = tuple(adapter.read_raw_signal(sample.raw_signal_ref) for sample in result.samples)
    return result, raw


def _repositories(
    tmp_path: Path,
) -> tuple[SQLiteM8SensorPersistenceRepository, str, Path]:
    root = tmp_path / "operations"
    root.mkdir()
    database = root / "labcourt.sqlite3"
    inventory = SQLiteM8InventoryRepository.initialize(database, BUSY_TIMEOUT_MS, SHA_A)
    inventory.publish_topology(_topology(), None)
    catalog = inventory.publish_source_catalog(_catalog(), None)
    repository = SQLiteM8SensorPersistenceRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    return repository, catalog.catalog.catalog_id, database


def test_sensor_repository_atomically_persists_reloads_and_replays_exact_raw_bytes(
    tmp_path: Path,
) -> None:
    repository, catalog_id, database = _repositories(tmp_path)
    result, raw = _poll(catalog_id)
    receipt = repository.commit_poll_result(result, raw, SHA_B, SHA_C)
    assert repository.commit_poll_result(result, raw, SHA_B, SHA_C) == receipt

    reopened = SQLiteM8SensorPersistenceRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    assert reopened.get_poll_cache(result.request.request_id) == receipt
    sample_receipt = receipt.sample_receipts[0]
    assert reopened.get_sample(sample_receipt.sample.sample_id) == sample_receipt
    assert reopened.list_latest_sensor_samples(10) == (sample_receipt,)
    assert reopened.read_raw_signal(sample_receipt.sample.raw_signal_ref) == raw[0]


def test_sensor_repository_rejects_raw_hash_mismatch_without_partial_rows(tmp_path: Path) -> None:
    repository, catalog_id, database = _repositories(tmp_path)
    result, raw = _poll(catalog_id)
    with pytest.raises(ConcurrentModification, match="sample hash"):
        repository.commit_poll_result(result, (raw[0] + b"x",), SHA_B, SHA_C)
    with sqlite3.connect(database) as connection:
        counts = tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "m8_sensor_raw_signals",
                "m8_sensor_samples",
                "m8_sensor_poll_cache",
            )
        )
    assert counts == (0, 0, 0)


def test_sensor_repository_rejects_manifest_graft_on_idempotent_retry(tmp_path: Path) -> None:
    repository, catalog_id, _database = _repositories(tmp_path)
    result, raw = _poll(catalog_id)
    committed = repository.commit_poll_result(result, raw, SHA_B, SHA_C)
    with pytest.raises(ConcurrentModification, match="identity already exists"):
        repository.commit_poll_result(result, raw, SHA_D, SHA_C)
    assert repository.get_poll_cache(result.request.request_id) == committed


def test_sensor_repository_rolls_back_raw_when_source_sequence_conflicts(tmp_path: Path) -> None:
    repository, catalog_id, database = _repositories(tmp_path)
    first, first_raw = _poll(catalog_id, value=True, timeout_ms=500)
    repository.commit_poll_result(first, first_raw, SHA_B, SHA_C)
    second, second_raw = _poll(
        catalog_id,
        scenario_id="offline-smoke-conflict",
        value=False,
        timeout_ms=600,
    )
    with pytest.raises(ConcurrentModification, match="sample append was rejected"):
        repository.commit_poll_result(second, second_raw, SHA_B, SHA_C)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM m8_sensor_raw_signals").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM m8_sensor_samples").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM m8_sensor_poll_cache").fetchone()[0] == 1


def test_sensor_repository_persists_empty_poll_without_inventing_raw_or_samples(
    tmp_path: Path,
) -> None:
    repository, catalog_id, database = _repositories(tmp_path)
    result, raw = _poll(catalog_id, after_source_sequence=1)
    receipt = repository.commit_poll_result(result, raw, SHA_B, SHA_C)
    assert receipt.sample_receipts == ()
    assert receipt.total_raw_signal_size_bytes == 0
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM m8_sensor_raw_signals").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM m8_sensor_samples").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM m8_sensor_poll_cache").fetchone()[0] == 1


def test_sensor_persistence_tables_are_append_only(tmp_path: Path) -> None:
    repository, catalog_id, database = _repositories(tmp_path)
    result, raw = _poll(catalog_id)
    receipt = repository.commit_poll_result(result, raw, SHA_B, SHA_C)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA recursive_triggers = ON")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                UPDATE m8_sensor_raw_signals SET raw_signal_size_bytes = 1
                WHERE raw_signal_ref = ?
                """,
                (receipt.sample_receipts[0].sample.raw_signal_ref,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM m8_sensor_poll_cache WHERE cache_key = ?",
                (receipt.cache_key,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO m8_sensor_samples
                SELECT * FROM m8_sensor_samples WHERE sample_id = ?
                """,
                (receipt.sample_receipts[0].sample.sample_id,),
            )
