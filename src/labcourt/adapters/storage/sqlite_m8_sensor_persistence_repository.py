"""SQLite-backed atomic M8 sensor sample, raw BLOB, and poll cache."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from labcourt.application.m8_sensor_persistence_workflow import (
    build_sensor_poll_cache_commit,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_inventory_persistence import (
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_sensor_persistence import (
    M8SensorPollCacheCommitReceiptV1,
    M8SensorSampleCommitReceiptV1,
)
from labcourt.contracts.m8_sensor_signals import M8SensorPollResultV1
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing

from .sqlite_m8_operations_repository import M8_MIGRATIONS
from .sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _row_int,
    _row_str,
    _validate_busy_timeout,
)

_M8_SENSOR_REQUIRED_OBJECTS = frozenset(
    {
        "idx_m8_source_catalog_receipt_binding",
        "m8_sensor_raw_signals",
        "m8_sensor_samples",
        "idx_m8_sensor_samples_source_sequence",
        "m8_sensor_poll_cache",
        "m8_sensor_poll_cache_samples",
        "m8_sensor_raw_signals_no_update",
        "m8_sensor_raw_signals_no_delete",
        "m8_sensor_raw_signals_no_replace",
        "m8_sensor_samples_no_update",
        "m8_sensor_samples_no_delete",
        "m8_sensor_samples_no_replace",
        "m8_sensor_poll_cache_no_update",
        "m8_sensor_poll_cache_no_delete",
        "m8_sensor_poll_cache_no_replace",
        "m8_sensor_poll_cache_samples_no_update",
        "m8_sensor_poll_cache_samples_no_delete",
        "m8_sensor_poll_cache_samples_no_replace",
    }
)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 {name} must be lowercase SHA-256 hex")
    return value


def _validate_raw_signal_ref(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("M8 raw_signal_ref must be a bounded relative POSIX reference")
    path = PurePosixPath(value)
    if (
        "\\" in value
        or ":" in value
        or path.is_absolute()
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ValueError("M8 raw_signal_ref must be a controlled relative POSIX reference")
    return value


class SQLiteM8SensorPersistenceRepository:
    """Persist exact sensor raw bytes and cache receipts in one transaction."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        self._repository_manifest_id = _validate_sha256(
            repository_manifest_id,
            "repository_manifest_id",
        )
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8SensorPersistenceRepository:
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
                WHERE version IN (1, 2, 3) ORDER BY version
                """
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError("M8 sensor migration ledger is invalid") from error
        observed_migrations = tuple(
            (_row_int(row, "version"), _row_str(row, "name")) for row in migrations
        )
        if observed_migrations != (
            (1, "m8_actor_case_authority"),
            (2, "m8_campus_inventory"),
            (3, "m8_sensor_cache"),
        ):
            raise RepositoryIntegrityError("M8 sensor migrations 0001/0002/0003 are not installed")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _M8_SENSOR_REQUIRED_OBJECTS)
                ),
                tuple(sorted(_M8_SENSOR_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _M8_SENSOR_REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 sensor persistence layout is incomplete")

    def commit_poll_result(
        self,
        result: M8SensorPollResultV1,
        raw_signals: tuple[bytes, ...],
        raw_storage_manifest_id: str,
        cache_manifest_id: str,
    ) -> M8SensorPollCacheCommitReceiptV1:
        if not isinstance(result, M8SensorPollResultV1):
            raise TypeError("M8 sensor persistence requires M8SensorPollResultV1")
        if not isinstance(raw_signals, tuple):
            raise TypeError("M8 raw_signals must be a tuple of exact bytes")
        raw_manifest = _validate_sha256(raw_storage_manifest_id, "raw_storage_manifest_id")
        cache_manifest = _validate_sha256(cache_manifest_id, "cache_manifest_id")
        with self._immediate() as connection:
            catalog = self._load_catalog_by_id(connection, result.request.source_catalog_id)
            try:
                candidate = build_sensor_poll_cache_commit(
                    result,
                    raw_signals,
                    catalog,
                    raw_manifest,
                    cache_manifest,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error

            existing_row = connection.execute(
                """
                SELECT * FROM m8_sensor_poll_cache
                WHERE request_id = ? OR cache_key = ?
                """,
                (result.request.request_id, result.request.cache_key),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_poll_row(connection, existing_row)
                if existing != candidate:
                    raise ConcurrentModification("M8 sensor poll cache identity already exists")
                self._verify_raw_tuple(connection, existing, raw_signals)
                return existing

            for sample_receipt, raw_signal in zip(
                candidate.sample_receipts,
                raw_signals,
                strict=True,
            ):
                self._insert_or_verify_raw(connection, sample_receipt, raw_signal)
                self._insert_or_verify_sample(connection, sample_receipt)
            self._insert_poll(connection, candidate)
            return candidate

    def get_poll_cache(self, request_id: str) -> M8SensorPollCacheCommitReceiptV1:
        require_reference_token(request_id, "M8 sensor request_id")
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_sensor_poll_cache WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 sensor poll cache was not found")
            return self._load_poll_row(connection, row)

    def get_sample(self, sample_id: str) -> M8SensorSampleCommitReceiptV1:
        require_reference_token(sample_id, "M8 sensor sample_id")
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_sensor_samples WHERE sample_id = ?",
                (sample_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 sensor sample was not found")
            receipt = self._load_sample_row(row)
            self._read_raw_row(connection, receipt.sample.raw_signal_ref, receipt)
            return receipt

    def list_latest_sensor_samples(
        self,
        limit: int,
    ) -> tuple[M8SensorSampleCommitReceiptV1, ...]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 20_000:
            raise ValueError("M8 latest sensor sample limit must be from 1 through 20000")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT current.* FROM m8_sensor_samples AS current
                WHERE NOT EXISTS (
                    SELECT 1 FROM m8_sensor_samples AS newer
                    WHERE newer.source_id = current.source_id
                      AND newer.source_sequence > current.source_sequence
                )
                ORDER BY current.source_id LIMIT ?
                """,
                (limit + 1,),
            ).fetchall()
            if len(rows) > limit:
                raise BudgetExceeded("M8 latest sensor sample inventory exceeds the limit")
            receipts = tuple(self._load_sample_row(row) for row in rows)
            for receipt in receipts:
                self._read_raw_row(connection, receipt.sample.raw_signal_ref, receipt)
            return receipts

    def read_raw_signal(self, raw_signal_ref: str) -> bytes:
        _validate_raw_signal_ref(raw_signal_ref)
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_sensor_raw_signals WHERE raw_signal_ref = ?",
                (raw_signal_ref,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 raw sensor signal was not found")
            return self._validated_raw_bytes(row)

    def _load_catalog_by_id(
        self,
        connection: sqlite3.Connection,
        catalog_id: str,
    ) -> M8OperationalSourceCatalogCommitReceiptV1:
        row = connection.execute(
            "SELECT * FROM m8_source_catalog_versions WHERE catalog_id = ?",
            (catalog_id,),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 persisted source catalog was not found")
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8OperationalSourceCatalogCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 source catalog is invalid") from error
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.catalog.catalog_id != _row_str(row, "catalog_id")
            or receipt.catalog_document_sha256 != _row_str(row, "catalog_document_sha256")
            or receipt.catalog.topology.topology_id != _row_str(row, "topology_id")
            or receipt.resolved_topology_commit_receipt_id
            != _row_str(row, "resolved_topology_commit_receipt_id")
            or receipt.catalog.source_count != _row_int(row, "source_count")
            or receipt.catalog.simulated_source_count != _row_int(row, "simulated_source_count")
            or receipt.catalog.life_safety_eligible_source_count
            != _row_int(row, "life_safety_eligible_source_count")
            or receipt.catalog.catalog_manifest_id != _row_str(row, "catalog_manifest_id")
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
        ):
            raise RepositoryIntegrityError("M8 source catalog conflicts with sensor persistence")
        return receipt

    def _insert_or_verify_raw(
        self,
        connection: sqlite3.Connection,
        receipt: M8SensorSampleCommitReceiptV1,
        raw_signal: bytes,
    ) -> None:
        sample = receipt.sample
        row = connection.execute(
            "SELECT * FROM m8_sensor_raw_signals WHERE raw_signal_ref = ?",
            (sample.raw_signal_ref,),
        ).fetchone()
        if row is not None:
            if self._validated_raw_bytes(row) != raw_signal:
                raise ConcurrentModification("M8 raw signal reference contains different bytes")
            if (
                _row_str(row, "raw_signal_sha256") != sample.raw_signal_sha256
                or _row_int(row, "raw_signal_size_bytes") != receipt.raw_signal_size_bytes
                or _row_str(row, "raw_storage_manifest_id") != receipt.raw_storage_manifest_id
                or _row_str(row, "repository_manifest_id") != self._repository_manifest_id
            ):
                raise ConcurrentModification("M8 raw signal metadata conflicts with receipt")
            return
        try:
            connection.execute(
                """
                INSERT INTO m8_sensor_raw_signals(
                    raw_signal_ref, raw_signal_sha256, raw_signal_size_bytes,
                    raw_signal_bytes, raw_storage_manifest_id, repository_manifest_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sample.raw_signal_ref,
                    sample.raw_signal_sha256,
                    receipt.raw_signal_size_bytes,
                    raw_signal,
                    receipt.raw_storage_manifest_id,
                    self._repository_manifest_id,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 raw signal append was rejected") from error

    def _insert_or_verify_sample(
        self,
        connection: sqlite3.Connection,
        receipt: M8SensorSampleCommitReceiptV1,
    ) -> None:
        sample = receipt.sample
        row = connection.execute(
            "SELECT * FROM m8_sensor_samples WHERE sample_id = ?",
            (sample.sample_id,),
        ).fetchone()
        if row is not None:
            if self._load_sample_row(row) != receipt:
                raise ConcurrentModification("M8 sensor sample identity already exists")
            return
        try:
            connection.execute(
                """
                INSERT INTO m8_sensor_samples(
                    sample_id, source_id, source_sequence, source_catalog_id,
                    sample_document_sha256, raw_signal_ref, raw_signal_sha256,
                    raw_signal_size_bytes, resolved_source_catalog_commit_receipt_id,
                    raw_storage_manifest_id, repository_manifest_id,
                    commit_receipt_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample.sample_id,
                    sample.source_id,
                    sample.source_sequence,
                    sample.source_catalog_id,
                    receipt.sample_document_sha256,
                    sample.raw_signal_ref,
                    sample.raw_signal_sha256,
                    receipt.raw_signal_size_bytes,
                    receipt.resolved_source_catalog_commit_receipt_id,
                    receipt.raw_storage_manifest_id,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 sensor sample append was rejected") from error

    def _insert_poll(
        self,
        connection: sqlite3.Connection,
        receipt: M8SensorPollCacheCommitReceiptV1,
    ) -> None:
        result = receipt.poll_result
        try:
            connection.execute(
                """
                INSERT INTO m8_sensor_poll_cache(
                    cache_key, request_id, result_id, source_catalog_id,
                    resolved_source_catalog_commit_receipt_id,
                    poll_result_document_sha256, sample_count,
                    sample_receipt_inventory_sha256, total_raw_signal_size_bytes,
                    raw_storage_manifest_id, cache_manifest_id, repository_manifest_id,
                    commit_receipt_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.cache_key,
                    result.request.request_id,
                    result.result_id,
                    result.request.source_catalog_id,
                    receipt.resolved_source_catalog_commit_receipt_id,
                    receipt.poll_result_document_sha256,
                    result.sample_count,
                    receipt.sample_receipt_inventory_sha256,
                    receipt.total_raw_signal_size_bytes,
                    receipt.raw_storage_manifest_id,
                    receipt.cache_manifest_id,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
            connection.executemany(
                """
                INSERT INTO m8_sensor_poll_cache_samples(cache_key, position, sample_id)
                VALUES (?, ?, ?)
                """,
                tuple(
                    (receipt.cache_key, position, sample_receipt.sample.sample_id)
                    for position, sample_receipt in enumerate(receipt.sample_receipts)
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 sensor poll cache append was rejected") from error

    def _load_sample_row(self, row: sqlite3.Row) -> M8SensorSampleCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8SensorSampleCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 sensor sample is invalid") from error
        sample = receipt.sample
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or sample.sample_id != _row_str(row, "sample_id")
            or sample.source_id != _row_str(row, "source_id")
            or sample.source_sequence != _row_int(row, "source_sequence")
            or sample.source_catalog_id != _row_str(row, "source_catalog_id")
            or receipt.sample_document_sha256 != _row_str(row, "sample_document_sha256")
            or sample.raw_signal_ref != _row_str(row, "raw_signal_ref")
            or sample.raw_signal_sha256 != _row_str(row, "raw_signal_sha256")
            or receipt.raw_signal_size_bytes != _row_int(row, "raw_signal_size_bytes")
            or receipt.resolved_source_catalog_commit_receipt_id
            != _row_str(row, "resolved_source_catalog_commit_receipt_id")
            or receipt.raw_storage_manifest_id != _row_str(row, "raw_storage_manifest_id")
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 sensor sample index columns conflict with receipt")
        return receipt

    def _load_poll_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M8SensorPollCacheCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8SensorPollCacheCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 sensor poll cache is invalid") from error
        result = receipt.poll_result
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.cache_key != _row_str(row, "cache_key")
            or result.request.request_id != _row_str(row, "request_id")
            or result.result_id != _row_str(row, "result_id")
            or result.request.source_catalog_id != _row_str(row, "source_catalog_id")
            or receipt.resolved_source_catalog_commit_receipt_id
            != _row_str(row, "resolved_source_catalog_commit_receipt_id")
            or receipt.poll_result_document_sha256 != _row_str(row, "poll_result_document_sha256")
            or result.sample_count != _row_int(row, "sample_count")
            or receipt.sample_receipt_inventory_sha256
            != _row_str(row, "sample_receipt_inventory_sha256")
            or receipt.total_raw_signal_size_bytes != _row_int(row, "total_raw_signal_size_bytes")
            or receipt.raw_storage_manifest_id != _row_str(row, "raw_storage_manifest_id")
            or receipt.cache_manifest_id != _row_str(row, "cache_manifest_id")
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError(
                "M8 sensor poll cache index columns conflict with receipt"
            )
        links = connection.execute(
            """
            SELECT position, sample_id FROM m8_sensor_poll_cache_samples
            WHERE cache_key = ? ORDER BY position
            """,
            (receipt.cache_key,),
        ).fetchall()
        expected_links = tuple(
            (position, item.sample.sample_id)
            for position, item in enumerate(receipt.sample_receipts)
        )
        observed_links = tuple(
            (_row_int(link, "position"), _row_str(link, "sample_id")) for link in links
        )
        if observed_links != expected_links:
            raise RepositoryIntegrityError("M8 sensor poll cache sample links are incomplete")
        for item in receipt.sample_receipts:
            sample_row = connection.execute(
                "SELECT * FROM m8_sensor_samples WHERE sample_id = ?",
                (item.sample.sample_id,),
            ).fetchone()
            if sample_row is None or self._load_sample_row(sample_row) != item:
                raise RepositoryIntegrityError("M8 sensor poll cache sample receipt is missing")
            self._read_raw_row(connection, item.sample.raw_signal_ref, item)
        return receipt

    def _read_raw_row(
        self,
        connection: sqlite3.Connection,
        raw_signal_ref: str,
        receipt: M8SensorSampleCommitReceiptV1,
    ) -> bytes:
        row = connection.execute(
            "SELECT * FROM m8_sensor_raw_signals WHERE raw_signal_ref = ?",
            (raw_signal_ref,),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("M8 sensor sample raw bytes are missing")
        raw_signal = self._validated_raw_bytes(row)
        if (
            _row_str(row, "raw_signal_sha256") != receipt.sample.raw_signal_sha256
            or _row_int(row, "raw_signal_size_bytes") != receipt.raw_signal_size_bytes
            or _row_str(row, "raw_storage_manifest_id") != receipt.raw_storage_manifest_id
            or _row_str(row, "repository_manifest_id") != self._repository_manifest_id
        ):
            raise RepositoryIntegrityError("M8 sensor raw metadata conflicts with sample receipt")
        return raw_signal

    def _validated_raw_bytes(self, row: sqlite3.Row) -> bytes:
        value = row["raw_signal_bytes"]
        if not isinstance(value, bytes):
            raise RepositoryIntegrityError("M8 raw signal column must contain bytes")
        if len(value) != _row_int(row, "raw_signal_size_bytes"):
            raise RepositoryIntegrityError("M8 raw signal byte size is invalid")
        if hashlib.sha256(value).hexdigest() != _row_str(row, "raw_signal_sha256"):
            raise RepositoryIntegrityError("M8 raw signal byte hash is invalid")
        if _row_str(row, "repository_manifest_id") != self._repository_manifest_id:
            raise RepositoryIntegrityError("M8 raw signal repository manifest is invalid")
        return value

    def _verify_raw_tuple(
        self,
        connection: sqlite3.Connection,
        receipt: M8SensorPollCacheCommitReceiptV1,
        raw_signals: tuple[bytes, ...],
    ) -> None:
        if len(raw_signals) != len(receipt.sample_receipts):
            raise ConcurrentModification("M8 sensor poll retry raw inventory conflicts")
        for sample_receipt, supplied in zip(
            receipt.sample_receipts,
            raw_signals,
            strict=True,
        ):
            persisted = self._read_raw_row(
                connection,
                sample_receipt.sample.raw_signal_ref,
                sample_receipt,
            )
            if persisted != supplied:
                raise ConcurrentModification("M8 sensor poll retry raw bytes conflict")


__all__ = ["SQLiteM8SensorPersistenceRepository"]
