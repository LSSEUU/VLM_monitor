from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_rows import (
    read_backlog_support_rows,
    read_base_support_rows,
    read_hearing_support_rows,
    read_primary_rows,
)
from labcourt.adapters.storage.sqlite_repository import MigrationRunner

BUSY_TIMEOUT_MS = 1_000


def test_every_m4_metadata_query_executes_on_the_migrated_schema(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))

    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            assert selector.execute("SELECT 1 AS ready").fetchone()["ready"] == 1
        with cut.reader() as reader:
            primary = read_primary_rows(reader, run_id="missing-run", case_id="missing-case")
            hearing = read_hearing_support_rows(
                reader,
                run_id="missing-run",
                case_id="missing-case",
            )
            backlog = read_backlog_support_rows(
                reader,
                run_id="missing-run",
                case_id="missing-case",
            )
            base = read_base_support_rows(
                reader,
                run_id="missing-run",
                case_id="missing-case",
                selected_case_revision=1,
                selected_audit_sequence=0,
            )
            assert not any(
                (
                    primary.claims,
                    primary.responses,
                    primary.caches,
                    primary.receipts,
                    primary.outputs,
                    primary.failures,
                    primary.usages,
                    hearing.sessions,
                    hearing.cycles,
                    hearing.retrievals,
                    hearing.rounds,
                    hearing.checkpoints,
                    backlog.items,
                    backlog.versions,
                    backlog.heads,
                    backlog.retry_outcomes,
                    backlog.completions,
                    backlog.strict_attempts,
                    backlog.strict_proofs,
                    backlog.human_reviews,
                    base.run,
                    base.case_version,
                    base.audit,
                    base.case_history,
                    base.audit_history,
                    base.packs,
                    base.screenings,
                    base.reviews,
                )
            )
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS ready").fetchone()["ready"] == 1
