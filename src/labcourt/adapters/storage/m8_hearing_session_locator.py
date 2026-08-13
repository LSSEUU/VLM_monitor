"""Read-only M8 locator over existing M4 session persistence."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.hearing import HearingSession
from labcourt.contracts.references import require_reference_token
from labcourt.ports.hearing_repository import HearingRepository


class SQLiteM8HearingSessionLocator:
    """Locate the sole persisted M4 session without changing its repository port."""

    def __init__(self, database_path: Path, hearing_repository: HearingRepository) -> None:
        self._database_path = database_path.resolve()
        self._hearings = hearing_repository

    def load_hearing_for_case(self, run_id: str, case_id: str) -> HearingSession | None:
        require_reference_token(run_id, "M8 hearing locator run_id")
        require_reference_token(case_id, "M8 hearing locator case_id")
        connection = sqlite3.connect(
            f"{self._database_path.as_uri()}?mode=ro",
            uri=True,
            timeout=5.0,
        )
        try:
            connection.execute("PRAGMA query_only = ON")
            rows = connection.execute(
                """
                SELECT hearing_id
                FROM m4_hearings
                WHERE run_id = ? AND case_id = ?
                ORDER BY created_audit_sequence, hearing_id
                """,
                (run_id, case_id),
            ).fetchall()
        finally:
            connection.close()
        if len(rows) > 1:
            raise RepositoryIntegrityError("M8 projection found multiple M4 sessions for one Case")
        if not rows:
            return None
        hearing_id = rows[0][0]
        if not isinstance(hearing_id, str):
            raise RepositoryIntegrityError("M8 projection found an invalid M4 session ID")
        return self._hearings.load_hearing_session(run_id, hearing_id)


__all__ = ["SQLiteM8HearingSessionLocator"]
