from __future__ import annotations

import sqlite3

import pytest

from labcourt.adapters.storage.sqlite_m8_prehearing_repository import (
    SQLiteM8PreHearingRepository,
)
from labcourt.exceptions import ConcurrentModification
from tests.contract.test_m8_prehearing_contracts import _pending


def test_prehearing_preparation_is_append_only_cas_and_survives_restart(tmp_path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository = SQLiteM8PreHearingRepository.initialize(database, 5_000)
    pending = repository.put(_pending(), None)
    assert repository.put(pending, None) == pending

    restarted = SQLiteM8PreHearingRepository(database, 5_000)
    assert restarted.get(pending.preparation_id) == pending
    assert restarted.load_for_case(pending.run_id, pending.case_id) == pending

    completed = pending.complete_no_novel_clear_frame(4)
    assert restarted.put(completed, 1) == completed
    assert restarted.put(completed, 1) == completed
    assert restarted.load_for_case(pending.run_id, pending.case_id) == completed

    with pytest.raises(ConcurrentModification):
        restarted.put(pending, 1)
    with (
        sqlite3.connect(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        connection.execute("UPDATE m8_prehearing_preparation_versions SET state = 'PENDING'")
