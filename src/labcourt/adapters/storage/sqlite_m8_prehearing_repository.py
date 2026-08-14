"""Append-only SQLite authority for deterministic M8 pre-hearing routing."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_prehearing import M8PreHearingPreparationV1
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, EvidenceMissing

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

_REQUIRED_OBJECTS = frozenset(
    {
        "m8_prehearing_preparation_versions",
        "idx_m8_prehearing_preparations_case_current",
        "m8_prehearing_preparations_validate_contiguous",
        "m8_prehearing_preparations_reject_second_identity",
        "m8_prehearing_preparations_validate_source",
        "m8_prehearing_preparations_no_update",
        "m8_prehearing_preparations_no_delete",
    }
)


def _document(preparation: M8PreHearingPreparationV1) -> tuple[str, str]:
    raw = canonical_json(preparation.model_dump(mode="json", exclude_computed_fields=True))
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_document(row: sqlite3.Row) -> M8PreHearingPreparationV1:
    raw = _row_str(row, "preparation_json")
    digest = _row_str(row, "document_sha256")
    if hashlib.sha256(raw.encode("utf-8")).hexdigest() != digest:
        raise RepositoryIntegrityError("M8 pre-hearing document hash mismatch")
    try:
        preparation = M8PreHearingPreparationV1.model_validate_json(raw)
    except ValidationError as error:
        raise RepositoryIntegrityError("M8 pre-hearing document is invalid") from error
    canonical, _ = _document(preparation)
    if canonical != raw:
        raise RepositoryIntegrityError("M8 pre-hearing document is not canonical")
    indexed = (
        _row_str(row, "preparation_id"),
        _row_int(row, "revision"),
        _row_str(row, "run_id"),
        _row_str(row, "case_id"),
        _row_int(row, "source_case_revision"),
        _row_str(row, "source_screening_id"),
        _row_int(row, "source_screening_version"),
        _row_str(row, "source_evidence_pack_id"),
        _row_int(row, "source_evidence_pack_version"),
        _row_str(row, "manifest_id"),
        _row_str(row, "state"),
    )
    expected = (
        preparation.preparation_id,
        preparation.revision,
        preparation.run_id,
        preparation.case_id,
        preparation.source_case_revision,
        preparation.source_screening_id,
        preparation.source_screening_version,
        preparation.source_evidence_pack_id,
        preparation.source_evidence_pack_version,
        preparation.manifest_id,
        preparation.state.value,
    )
    if indexed != expected:
        raise RepositoryIntegrityError("M8 pre-hearing indexed authority is inconsistent")
    return preparation


class SQLiteM8PreHearingRepository:
    """CAS repository whose current document survives process restarts."""

    def __init__(self, database_path: str | Path, busy_timeout_ms: int) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
    ) -> SQLiteM8PreHearingRepository:
        MigrationRunner(
            database_path,
            busy_timeout_ms,
            migrations_path=M8_MIGRATIONS,
        ).apply_all()
        return cls(database_path, busy_timeout_ms)

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = _open_connection(
            self._database_path,
            self._busy_timeout_ms,
            allow_create=False,
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
                raise ConcurrentModification("M8 pre-hearing writer lock unavailable") from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        try:
            migration = connection.execute(
                "SELECT name FROM schema_migrations WHERE version = 14"
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError("M8 pre-hearing migration ledger is invalid") from error
        if migration is None or _row_str(migration, "name") != "m8_prehearing":
            raise RepositoryIntegrityError("M8 pre-hearing migration 0014 is absent")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _REQUIRED_OBJECTS)
                ),
                tuple(sorted(_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 pre-hearing persistence layout is incomplete")

    def put(
        self,
        preparation: M8PreHearingPreparationV1,
        expected_prior_revision: int | None,
    ) -> M8PreHearingPreparationV1:
        """Append one exact revision or return an exact idempotent retry."""

        if not isinstance(preparation, M8PreHearingPreparationV1):
            raise TypeError("pre-hearing publication requires a typed preparation")
        raw, digest = _document(preparation)
        with self._immediate() as connection:
            existing = connection.execute(
                """
                SELECT * FROM m8_prehearing_preparation_versions
                WHERE preparation_id = ? AND revision = ?
                """,
                (preparation.preparation_id, preparation.revision),
            ).fetchone()
            if existing is not None:
                loaded = _load_document(existing)
                if loaded == preparation and (
                    expected_prior_revision == preparation.revision - 1
                    or (preparation.revision == 1 and expected_prior_revision is None)
                ):
                    return loaded
                raise ConcurrentModification("M8 pre-hearing preparation revision already exists")

            conflicting = connection.execute(
                """
                SELECT preparation_id FROM m8_prehearing_preparation_versions
                WHERE run_id = ? AND case_id = ? LIMIT 1
                """,
                (preparation.run_id, preparation.case_id),
            ).fetchone()
            if (
                conflicting is not None
                and _row_str(conflicting, "preparation_id") != preparation.preparation_id
            ):
                raise ConcurrentModification("M8 pre-hearing Case already has another preparation")

            prior = connection.execute(
                """
                SELECT revision FROM m8_prehearing_preparation_versions
                WHERE preparation_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (preparation.preparation_id,),
            ).fetchone()
            observed = _row_int(prior, "revision") if prior is not None else None
            if observed != expected_prior_revision or preparation.revision != (observed or 0) + 1:
                raise ConcurrentModification("M8 pre-hearing preparation revision is stale")
            connection.execute(
                """
                INSERT INTO m8_prehearing_preparation_versions(
                    preparation_id, revision, run_id, case_id,
                    source_case_revision, source_screening_id,
                    source_screening_version, source_evidence_pack_id,
                    source_evidence_pack_version, manifest_id, state,
                    document_sha256, preparation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    preparation.preparation_id,
                    preparation.revision,
                    preparation.run_id,
                    preparation.case_id,
                    preparation.source_case_revision,
                    preparation.source_screening_id,
                    preparation.source_screening_version,
                    preparation.source_evidence_pack_id,
                    preparation.source_evidence_pack_version,
                    preparation.manifest_id,
                    preparation.state.value,
                    digest,
                    raw,
                ),
            )
        return preparation

    def get(self, preparation_id: str) -> M8PreHearingPreparationV1:
        """Load the current revision by its content-addressed preparation ID."""

        if (
            not isinstance(preparation_id, str)
            or len(preparation_id) != 64
            or any(character not in "0123456789abcdef" for character in preparation_id)
        ):
            raise ValueError("preparation_id must be lowercase SHA-256")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_prehearing_preparation_versions
                WHERE preparation_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (preparation_id,),
            ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 pre-hearing preparation is absent")
        return _load_document(row)

    def load_for_case(
        self,
        run_id: str,
        case_id: str,
    ) -> M8PreHearingPreparationV1 | None:
        """Return the current gate record for platform projection, if one exists."""

        require_reference_token(run_id, "pre-hearing repository run_id")
        require_reference_token(case_id, "pre-hearing repository case_id")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM m8_prehearing_preparation_versions
                WHERE run_id = ? AND case_id = ?
                ORDER BY revision DESC LIMIT 2
                """,
                (run_id, case_id),
            ).fetchall()
        if not rows:
            return None
        identities = {_row_str(row, "preparation_id") for row in rows}
        if len(identities) != 1:
            raise RepositoryIntegrityError(
                "M8 pre-hearing Case has multiple preparation identities"
            )
        return _load_document(rows[0])


__all__ = ["SQLiteM8PreHearingRepository"]
