from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.contracts.enums import CaseStatus
from labcourt.services.pilot_a4 import close_pilot_run
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m5_sqlite_alert_repository import _clock, _prepare_ready_case


def test_pilot_a4_closes_run_scoped_authority_without_dispatch(tmp_path: Path) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    database, evidence, _, ready, _, config = _prepare_ready_case(run_root)

    report = close_pilot_run(
        config=config,
        runs_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=_clock,
    )
    repeated = close_pilot_run(
        config=config,
        runs_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=_clock,
    )

    assert report.selected_count == 1
    assert report.outcomes[0].case_id == ready.case.case_id
    assert report.outcomes[0].closed_revision == ready.revision + 1
    assert report.production_delivery_count == 0
    assert repeated.selected_count == 0
    assert evidence.load_case(RUN_ID, ready.case.case_id).case.status == CaseStatus.CLOSED


def test_pilot_a4_rejects_database_outside_selected_run(tmp_path: Path) -> None:
    config = _prepare_ready_case(tmp_path)[-1]

    with pytest.raises(ValueError, match="selected pilot run"):
        close_pilot_run(
            config=config,
            runs_root=tmp_path,
            database_path=tmp_path / config.storage.database_filename,
            run_id=RUN_ID,
            clock=_clock,
        )
