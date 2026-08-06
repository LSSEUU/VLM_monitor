"""SQLite connection, transaction, and recovery-fence foundation."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import datetime
from pathlib import Path
from typing import cast

from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
)
from labcourt.ports.m3_semantics import M3SemanticVerifier
from labcourt.ports.procedural_review import ProceduralReviewVerifier
from labcourt.ports.vlm import (
    RawModelResponseVerifier,
)

from .sqlite_m3_repository_host import SQLiteM3RepositoryHost
from .sqlite_m3_repository_support import (
    CurrentPackVerifier,
)
from .sqlite_repository import (
    MigrationIntegrityError,
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _row_str,
    _validate_busy_timeout,
)
from .sqlite_schema import m3_authority_hardening_installed


class SQLiteM3RepositoryFoundation(SQLiteM3RepositoryHost):
    """SQLite connection, transaction, and recovery-fence foundation."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        clock: object | None = None,
        *,
        current_pack_verifier: CurrentPackVerifier | None = None,
        raw_response_verifier: RawModelResponseVerifier | None = None,
        procedural_review_verifier: ProceduralReviewVerifier | None = None,
        semantic_verifier: M3SemanticVerifier | None = None,
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        if current_pack_verifier is not None and not callable(current_pack_verifier):
            raise TypeError("current_pack_verifier must be callable")
        if raw_response_verifier is not None and not callable(
            getattr(raw_response_verifier, "verify_raw_response", None)
        ):
            raise TypeError("raw_response_verifier must implement verify_raw_response")
        if procedural_review_verifier is not None and not callable(
            getattr(procedural_review_verifier, "rebuild_review", None)
        ):
            raise TypeError("procedural_review_verifier must implement rebuild_review")
        effective_semantic_verifier = semantic_verifier
        if (
            effective_semantic_verifier is None
            and procedural_review_verifier is not None
            and all(
                callable(getattr(procedural_review_verifier, method, None))
                for method in ("rebuild_screening", "rebuild_fast_verdict")
            )
        ):
            effective_semantic_verifier = cast(
                M3SemanticVerifier,
                procedural_review_verifier,
            )
        if effective_semantic_verifier is not None and not all(
            callable(getattr(effective_semantic_verifier, method, None))
            for method in ("rebuild_screening", "rebuild_fast_verdict")
        ):
            raise TypeError(
                "semantic_verifier must implement rebuild_screening and rebuild_fast_verdict"
            )
        self._clock = cast(Callable[[], datetime] | None, clock)
        self._current_pack_verifier = current_pack_verifier
        self._raw_response_verifier = raw_response_verifier
        self._procedural_review_verifier = procedural_review_verifier
        self._semantic_verifier = effective_semantic_verifier
        self._artifact_recovery_fence_connection: ContextVar[sqlite3.Connection | None] = (
            ContextVar(
                "labcourt_m3_artifact_recovery_fence_connection",
                default=None,
            )
        )

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        if self._artifact_recovery_fence_connection.get() is not None:
            raise ConcurrentModification("M3 writes are prohibited inside artifact recovery fence")
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connection()
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException as exc:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            if isinstance(exc, sqlite3.OperationalError) and _is_sqlite_concurrency_error(exc):
                raise ConcurrentModification("SQLite writer lock could not be acquired") from exc
            raise
        finally:
            if connection is not None:
                connection.close()

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        fenced_connection = self._artifact_recovery_fence_connection.get()
        if fenced_connection is not None:
            yield fenced_connection
            return
        connection = self._connection()
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

    def _connection(self) -> sqlite3.Connection:
        connection = _open_connection(
            self._database_path,
            self._busy_timeout_ms,
            allow_create=False,
        )
        try:
            migrated = m3_authority_hardening_installed(connection)
            tables = {
                _row_str(row, "name")
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'table' AND name IN (
                        'model_responses', 'parsed_screening_outputs',
                        'model_parse_receipts', 'model_cache',
                        'model_call_claims', 'model_call_usage_accounting',
                        'screening_results', 'verdicts', 'procedural_reviews',
                        'procedural_defects', 'backlog_items',
                        'backlog_item_versions', 'backlog_heads',
                        'backlog_completion_receipts',
                        'model_call_failure_authorities'
                    )
                    """
                ).fetchall()
            }
            expected = {
                "model_responses",
                "parsed_screening_outputs",
                "model_parse_receipts",
                "model_cache",
                "model_call_claims",
                "model_call_usage_accounting",
                "screening_results",
                "verdicts",
                "procedural_reviews",
                "procedural_defects",
                "backlog_items",
                "backlog_item_versions",
                "backlog_heads",
                "backlog_completion_receipts",
                "model_call_failure_authorities",
            }
            backlog_version_columns = {
                _row_str(row, "name")
                for row in connection.execute("PRAGMA table_info(backlog_item_versions)").fetchall()
            }
            if (
                not migrated
                or tables != expected
                or "retry_generation" not in backlog_version_columns
            ):
                raise MigrationIntegrityError(
                    "SQLite M3 schema is not migrated; run MigrationRunner.apply_all() first"
                )
        except BaseException:
            connection.close()
            raise
        return connection

    @contextmanager
    def model_response_artifact_recovery_fence(
        self,
        run_id: str,
    ) -> Iterator[None]:
        """Hold the SQLite writer slot while allowing only recovery reads.

        Claim recovery runs once before this fence with its normal short
        transactions.  While fenced, a second claim scan and every reverse
        reference query share this connection; all M3 writes through this
        repository are rejected.  Other repository instances cannot acquire a
        SQLite writer slot until the filesystem phase exits.
        """

        require_reference_token(run_id, "model response artifact fence run_id")
        if self._artifact_recovery_fence_connection.get() is not None:
            raise ContractViolation("model response artifact recovery fence cannot nest")
        connection: sqlite3.Connection | None = None
        context_token: Token[sqlite3.Connection | None] | None = None
        initial_changes = 0
        try:
            connection = self._connection()
            connection.execute("BEGIN IMMEDIATE")
            if (
                connection.execute(
                    "SELECT 1 FROM runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                is None
            ):
                raise ContractViolation("model response artifact recovery requires an existing run")
            initial_changes = connection.total_changes
            context_token = self._artifact_recovery_fence_connection.set(connection)
            yield
            if connection.total_changes != initial_changes:
                raise RepositoryIntegrityError(
                    "model response artifact recovery fence observed a database write"
                )
            connection.commit()
        except BaseException as exc:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            if isinstance(exc, sqlite3.OperationalError) and _is_sqlite_concurrency_error(exc):
                raise ConcurrentModification(
                    "model response artifact recovery writer fence could not be acquired"
                ) from exc
            raise
        finally:
            if context_token is not None:
                self._artifact_recovery_fence_connection.reset(context_token)
            if connection is not None:
                connection.close()
