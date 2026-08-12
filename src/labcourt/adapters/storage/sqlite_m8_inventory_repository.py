"""SQLite persistence for M8 campus topology and source snapshots."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from labcourt.application.m8_inventory_workflow import (
    build_source_catalog_commit,
    build_topology_commit,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_operations import (
    M8CampusTopologyAuthorityV1,
    M8OperationalSourceCatalogAuthorityV1,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, EvidenceMissing

from .sqlite_m8_operations_repository import M8_MIGRATIONS
from .sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _row_int,
    _row_optional_str,
    _row_str,
    _validate_busy_timeout,
)

_M8_INVENTORY_REQUIRED_OBJECTS = frozenset(
    {
        "m8_campus_topology_versions",
        "m8_source_catalog_versions",
        "idx_m8_campus_topologies_current",
        "idx_m8_source_catalogs_current",
        "m8_campus_topologies_validate_contiguous",
        "m8_campus_topologies_no_update",
        "m8_campus_topologies_no_delete",
        "m8_campus_topologies_no_replace",
        "m8_source_catalogs_validate_contiguous",
        "m8_source_catalogs_no_update",
        "m8_source_catalogs_no_delete",
        "m8_source_catalogs_no_replace",
    }
)


def _validate_repository_manifest(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("M8 repository_manifest_id must be lowercase SHA-256 hex")
    return value


def _validate_expected_revision(value: int | None) -> int | None:
    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
        raise ValueError("M8 expected_prior_revision must be a positive strict integer")
    return value


class SQLiteM8InventoryRepository:
    """Append-only inventory repository using the isolated M8 operations database."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        self._repository_manifest_id = _validate_repository_manifest(repository_manifest_id)
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8InventoryRepository:
        MigrationRunner(
            database_path,
            busy_timeout_ms,
            migrations_path=M8_MIGRATIONS,
        ).apply_all()
        return cls(database_path, busy_timeout_ms, repository_manifest_id)

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = _open_connection(
            self._database_path, self._busy_timeout_ms, allow_create=False
        )
        try:
            connection.execute("BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(
                self._database_path,
                self._busy_timeout_ms,
                allow_create=False,
            )
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException as error:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            if isinstance(error, sqlite3.OperationalError) and _is_sqlite_concurrency_error(error):
                raise ConcurrentModification(
                    "M8 SQLite writer lock could not be acquired"
                ) from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        try:
            migrations = connection.execute(
                """
                SELECT version, name FROM schema_migrations
                WHERE version IN (1, 2) ORDER BY version
                """
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError("M8 inventory migration ledger is invalid") from error
        observed_migrations = tuple(
            (_row_int(row, "version"), _row_str(row, "name")) for row in migrations
        )
        if observed_migrations != (
            (1, "m8_actor_case_authority"),
            (2, "m8_campus_inventory"),
        ):
            raise RepositoryIntegrityError("M8 inventory migrations 0001/0002 are not installed")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _M8_INVENTORY_REQUIRED_OBJECTS)
                ),
                tuple(sorted(_M8_INVENTORY_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _M8_INVENTORY_REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 inventory authority layout is incomplete")

    def publish_topology(
        self,
        topology: M8CampusTopologyAuthorityV1,
        expected_prior_revision: int | None,
    ) -> M8CampusTopologyCommitReceiptV1:
        if not isinstance(topology, M8CampusTopologyAuthorityV1):
            raise TypeError("M8 topology publication requires M8CampusTopologyAuthorityV1")
        expected = _validate_expected_revision(expected_prior_revision)
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT * FROM m8_campus_topology_versions WHERE campus_id = ? AND revision = ?",
                (topology.campus_id, topology.revision),
            ).fetchone()
            if row is not None:
                existing = self._load_topology_row(row)
                expected_for_existing = topology.revision - 1 or None
                if existing.topology == topology and expected == expected_for_existing:
                    return existing
                raise ConcurrentModification("M8 topology revision already exists")
            prior_row = connection.execute(
                """
                SELECT * FROM m8_campus_topology_versions
                WHERE campus_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (topology.campus_id,),
            ).fetchone()
            prior = self._load_topology_row(prior_row) if prior_row is not None else None
            observed = prior.topology.revision if prior else None
            if expected != observed:
                raise ConcurrentModification("M8 topology expected revision is stale")
            try:
                receipt = build_topology_commit(topology, prior, self._repository_manifest_id)
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_topology(connection, receipt)
            return receipt

    def get_current_topology(self, campus_id: str) -> M8CampusTopologyCommitReceiptV1:
        require_reference_token(campus_id, "M8 campus_id")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_campus_topology_versions
                WHERE campus_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (campus_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 campus topology was not found")
            return self._load_topology_row(row)

    def publish_source_catalog(
        self,
        catalog: M8OperationalSourceCatalogAuthorityV1,
        expected_prior_revision: int | None,
    ) -> M8OperationalSourceCatalogCommitReceiptV1:
        if not isinstance(catalog, M8OperationalSourceCatalogAuthorityV1):
            raise TypeError(
                "M8 source catalog publication requires M8OperationalSourceCatalogAuthorityV1"
            )
        expected = _validate_expected_revision(expected_prior_revision)
        campus_id = catalog.topology.campus_id
        with self._immediate() as connection:
            existing_row = connection.execute(
                "SELECT * FROM m8_source_catalog_versions WHERE campus_id = ? AND revision = ?",
                (campus_id, catalog.revision),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_catalog_row(existing_row)
                expected_for_existing = catalog.revision - 1 or None
                if existing.catalog == catalog and expected == expected_for_existing:
                    return existing
                raise ConcurrentModification("M8 source catalog revision already exists")
            topology_row = connection.execute(
                """
                SELECT * FROM m8_campus_topology_versions
                WHERE campus_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (campus_id,),
            ).fetchone()
            if topology_row is None:
                raise EvidenceMissing("M8 current persisted topology was not found")
            resolved_topology = self._load_topology_row(topology_row)
            prior_row = connection.execute(
                """
                SELECT * FROM m8_source_catalog_versions
                WHERE campus_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (campus_id,),
            ).fetchone()
            prior = self._load_catalog_row(prior_row) if prior_row is not None else None
            observed = prior.catalog.revision if prior else None
            if expected != observed:
                raise ConcurrentModification("M8 source catalog expected revision is stale")
            try:
                receipt = build_source_catalog_commit(
                    catalog,
                    resolved_topology,
                    prior,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_catalog(connection, receipt)
            return receipt

    def get_current_source_catalog(
        self,
        campus_id: str,
    ) -> M8OperationalSourceCatalogCommitReceiptV1:
        require_reference_token(campus_id, "M8 campus_id")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_source_catalog_versions
                WHERE campus_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (campus_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 source catalog was not found")
            return self._load_catalog_row(row)

    def get_source_catalog(
        self,
        catalog_id: str,
    ) -> M8OperationalSourceCatalogCommitReceiptV1:
        require_reference_token(catalog_id, "M8 catalog_id")
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_source_catalog_versions WHERE catalog_id = ?",
                (catalog_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 source catalog was not found")
            return self._load_catalog_row(row)

    def _insert_topology(
        self,
        connection: sqlite3.Connection,
        receipt: M8CampusTopologyCommitReceiptV1,
    ) -> None:
        topology = receipt.topology
        try:
            connection.execute(
                """
                INSERT INTO m8_campus_topology_versions(
                    campus_id, revision, topology_id, topology_document_sha256,
                    prior_topology_id, prior_document_sha256, topology_manifest_id,
                    repository_manifest_id, commit_receipt_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    topology.campus_id,
                    topology.revision,
                    topology.topology_id,
                    receipt.topology_document_sha256,
                    receipt.prior_topology_id,
                    receipt.prior_document_sha256,
                    topology.manifest_id,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 topology append was rejected") from error

    def _insert_catalog(
        self,
        connection: sqlite3.Connection,
        receipt: M8OperationalSourceCatalogCommitReceiptV1,
    ) -> None:
        catalog = receipt.catalog
        try:
            connection.execute(
                """
                INSERT INTO m8_source_catalog_versions(
                    campus_id, revision, catalog_id, catalog_document_sha256,
                    topology_id, resolved_topology_document_sha256,
                    resolved_topology_commit_receipt_id, prior_catalog_id,
                    prior_document_sha256, source_count, simulated_source_count,
                    life_safety_eligible_source_count, catalog_manifest_id,
                    repository_manifest_id, commit_receipt_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    catalog.topology.campus_id,
                    catalog.revision,
                    catalog.catalog_id,
                    receipt.catalog_document_sha256,
                    catalog.topology.topology_id,
                    receipt.resolved_topology_document_sha256,
                    receipt.resolved_topology_commit_receipt_id,
                    receipt.prior_catalog_id,
                    receipt.prior_document_sha256,
                    catalog.source_count,
                    catalog.simulated_source_count,
                    catalog.life_safety_eligible_source_count,
                    catalog.catalog_manifest_id,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 source catalog append was rejected") from error

    def _load_topology_row(self, row: sqlite3.Row) -> M8CampusTopologyCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8CampusTopologyCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 topology is invalid") from error
        topology = receipt.topology
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or topology.campus_id != _row_str(row, "campus_id")
            or topology.revision != _row_int(row, "revision")
            or topology.topology_id != _row_str(row, "topology_id")
            or receipt.topology_document_sha256 != _row_str(row, "topology_document_sha256")
            or receipt.prior_topology_id != _row_optional_str(row, "prior_topology_id")
            or receipt.prior_document_sha256 != _row_optional_str(row, "prior_document_sha256")
            or topology.manifest_id != _row_str(row, "topology_manifest_id")
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 topology index columns conflict with receipt")
        return receipt

    def _load_catalog_row(
        self,
        row: sqlite3.Row,
    ) -> M8OperationalSourceCatalogCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8OperationalSourceCatalogCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 source catalog is invalid") from error
        catalog = receipt.catalog
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or catalog.topology.campus_id != _row_str(row, "campus_id")
            or catalog.revision != _row_int(row, "revision")
            or catalog.catalog_id != _row_str(row, "catalog_id")
            or receipt.catalog_document_sha256 != _row_str(row, "catalog_document_sha256")
            or catalog.topology.topology_id != _row_str(row, "topology_id")
            or receipt.resolved_topology_document_sha256
            != _row_str(row, "resolved_topology_document_sha256")
            or receipt.resolved_topology_commit_receipt_id
            != _row_str(row, "resolved_topology_commit_receipt_id")
            or receipt.prior_catalog_id != _row_optional_str(row, "prior_catalog_id")
            or receipt.prior_document_sha256 != _row_optional_str(row, "prior_document_sha256")
            or catalog.source_count != _row_int(row, "source_count")
            or catalog.simulated_source_count != _row_int(row, "simulated_source_count")
            or catalog.life_safety_eligible_source_count
            != _row_int(row, "life_safety_eligible_source_count")
            or catalog.catalog_manifest_id != _row_str(row, "catalog_manifest_id")
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 source catalog index columns conflict with receipt")
        return receipt


__all__ = ["SQLiteM8InventoryRepository"]
