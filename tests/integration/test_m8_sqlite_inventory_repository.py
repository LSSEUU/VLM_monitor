from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m8_inventory_repository import (
    SQLiteM8InventoryRepository,
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
from labcourt.exceptions import ConcurrentModification

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
BUSY_TIMEOUT_MS = 5_000


def _topology(revision: int = 1) -> M8CampusTopologyAuthorityV1:
    return M8CampusTopologyAuthorityV1(
        revision=revision,
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


def _catalog(
    revision: int = 1,
    *,
    topology_revision: int = 1,
) -> M8OperationalSourceCatalogAuthorityV1:
    return M8OperationalSourceCatalogAuthorityV1(
        revision=revision,
        topology=_topology(topology_revision),
        sources=(
            M8OperationalSource(
                source_id="sensor-simulated-smoke-01",
                device_id="sensor-smoke-01",
                location_id="room-chem-301",
                mode=M8OperationalSourceMode.SIMULATED_SENSOR,
                sensor_type=M8SensorType.SMOKE,
                adapter_id="m8-offline-sensor-simulator",
                manifest_id=SHA_B,
            ),
        ),
        catalog_manifest_id=SHA_C,
    )


def _repository(tmp_path: Path) -> SQLiteM8InventoryRepository:
    root = tmp_path / "operations"
    root.mkdir()
    return SQLiteM8InventoryRepository.initialize(
        root / "labcourt.sqlite3",
        BUSY_TIMEOUT_MS,
        SHA_C,
    )


def test_inventory_repository_persists_idempotent_snapshots_and_reloads(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    topology = _topology()
    topology_receipt = repository.publish_topology(topology, None)
    assert repository.publish_topology(topology, None) == topology_receipt

    catalog = _catalog()
    catalog_receipt = repository.publish_source_catalog(catalog, None)
    assert repository.publish_source_catalog(catalog, None) == catalog_receipt
    assert catalog_receipt.resolved_topology_commit_receipt_id == (
        topology_receipt.commit_receipt_id
    )

    reopened = SQLiteM8InventoryRepository(
        tmp_path / "operations" / "labcourt.sqlite3",
        BUSY_TIMEOUT_MS,
        SHA_C,
    )
    assert reopened.get_current_topology("campus-main") == topology_receipt
    assert reopened.get_current_source_catalog("campus-main") == catalog_receipt
    assert reopened.get_source_catalog(catalog.catalog_id) == catalog_receipt


def test_catalog_rejects_stale_embedded_topology_after_current_revision_advances(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    repository.publish_topology(_topology(), None)
    first_catalog = repository.publish_source_catalog(_catalog(), None)
    repository.publish_topology(_topology(2), 1)

    with pytest.raises(ConcurrentModification, match="current persisted topology"):
        repository.publish_source_catalog(_catalog(2, topology_revision=1), 1)
    assert repository.get_current_source_catalog("campus-main") == first_catalog

    second = repository.publish_source_catalog(_catalog(2, topology_revision=2), 1)
    assert second.catalog.revision == 2
    assert second.resolved_topology_commit_receipt_id == (
        repository.get_current_topology("campus-main").commit_receipt_id
    )


def test_inventory_repository_rejects_stale_expected_revisions(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    repository.publish_topology(_topology(), None)
    with pytest.raises(ConcurrentModification, match="expected revision is stale"):
        repository.publish_topology(_topology(2), None)

    repository.publish_source_catalog(_catalog(), None)
    with pytest.raises(ConcurrentModification, match="expected revision is stale"):
        repository.publish_source_catalog(_catalog(2), None)


def test_inventory_compare_and_swap_allows_only_one_successor_per_revision(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    repository.publish_topology(_topology(), None)
    topology_winner = _topology(2)
    topology_loser = topology_winner.model_copy(update={"manifest_id": SHA_B})
    repository.publish_topology(topology_winner, 1)
    with pytest.raises(ConcurrentModification, match="revision already exists"):
        repository.publish_topology(topology_loser, 1)

    repository.publish_source_catalog(_catalog(topology_revision=2), None)
    catalog_winner = _catalog(2, topology_revision=2)
    catalog_loser = catalog_winner.model_copy(update={"catalog_manifest_id": SHA_A})
    repository.publish_source_catalog(catalog_winner, 1)
    with pytest.raises(ConcurrentModification, match="revision already exists"):
        repository.publish_source_catalog(catalog_loser, 1)


def test_inventory_tables_are_append_only_at_sql_boundary(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    repository.publish_topology(_topology(), None)
    repository.publish_source_catalog(_catalog(), None)
    database = tmp_path / "operations" / "labcourt.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA recursive_triggers = ON")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m8_campus_topology_versions SET revision = 2 WHERE campus_id = ?",
                ("campus-main",),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM m8_source_catalog_versions WHERE campus_id = ?",
                ("campus-main",),
            )
