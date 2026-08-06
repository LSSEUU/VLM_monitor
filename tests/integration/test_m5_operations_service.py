from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from labcourt.config_loader import load_config
from labcourt.contracts.alert_policy import AlertDispatchDisposition
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus, PrecedentStatus, VerdictDecision
from labcourt.contracts.m5_precedents import MAX_M5_PRECEDENTS, M5EmbeddingVector
from labcourt.exceptions import ContractViolation, ManifestMismatch
from labcourt.services.m5_operations import (
    MAX_M5_IMPORT_FILE_BYTES,
    MAX_M5_IMPORT_LINE_BYTES,
    activate_m5_precedents_for_run,
    dispatch_m5_alerts,
    finalize_m5_run,
    import_m5_precedent_file,
    reconcile_m5_precedents_for_run,
)
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m5_sqlite_alert_repository import (
    _clock,
    _prepare_ready_case,
)
from tests.integration.test_m5_sqlite_precedents import (
    _authority as _preset_authority,
)
from tests.integration.test_m5_sqlite_precedents import _install as _install_precedent_run

ROOT = Path(__file__).parents[2]


def test_m5_services_finalize_and_dispatch_real_sqlite_authority_offline(
    tmp_path: Path,
) -> None:
    database, evidence, _, ready, _, config = _prepare_ready_case(tmp_path)

    finalized = finalize_m5_run(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=_clock,
    )
    repeated_finalize = finalize_m5_run(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=_clock,
    )

    assert finalized.selected_count == 1
    assert finalized.outcomes[0].case_id == ready.case.case_id
    assert finalized.outcomes[0].closed_revision == ready.revision + 1
    assert repeated_finalize.selected_count == 0
    closed = evidence.load_case(RUN_ID, ready.case.case_id)
    assert closed.case.status == CaseStatus.CLOSED

    dispatched = dispatch_m5_alerts(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        worker_id="offline-worker-01",
    )
    repeated_dispatch = dispatch_m5_alerts(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        worker_id="offline-worker-02",
    )

    assert dispatched.selected_count == 1
    assert dispatched.succeeded_count == 1
    assert dispatched.receipts[0].disposition == AlertDispatchDisposition.SUCCEEDED
    assert repeated_dispatch.selected_count == 0

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alert_outbox").fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM alert_dispatch_receipts WHERE disposition = 'SUCCEEDED'"
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM alert_channel_capabilities").fetchone() == (
            1,
        )
        assert connection.execute(
            """
            SELECT status FROM precedents
            WHERE source = 'AUTOMATIC' AND source_case_id = ?
            """,
            (ready.case.case_id,),
        ).fetchone() == (PrecedentStatus.PROVISIONAL.value,)

    activated = activate_m5_precedents_for_run(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        clock=lambda: _clock() + timedelta(days=7),
    )
    assert activated.selected_count == 1
    assert activated.receipts[0].status_after == PrecedentStatus.ACTIVE


def test_m5_precedent_import_and_conflict_services_use_real_sqlite_authority(
    tmp_path: Path,
) -> None:
    database, _, manifest = _install_precedent_run(tmp_path)
    config = load_config(ROOT / "configs/demo.yaml")
    established = _preset_authority(
        manifest,
        "precedent-established",
        direction=VerdictDecision.ESTABLISHED,
    )
    rejected = _preset_authority(
        manifest,
        "precedent-rejected",
        direction=VerdictDecision.NOT_ESTABLISHED,
    )
    source = tmp_path / "precedents.jsonl"
    source.write_text(
        "\n".join(canonical_json(item.model_dump(mode="json")) for item in (rejected, established))
        + "\n",
        encoding="utf-8",
    )

    imported = import_m5_precedent_file(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        source_path=source,
    )
    replayed = import_m5_precedent_file(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
        source_path=source,
    )
    reconciled = reconcile_m5_precedents_for_run(
        config=config,
        workspace_root=tmp_path,
        database_path=database,
        run_id=RUN_ID,
    )

    assert imported == replayed
    assert imported.precedent_ids == (
        "precedent-established",
        "precedent-rejected",
    )
    assert reconciled.evaluated_pair_count == 1
    assert len(reconciled.applied_receipts) == 1
    assert reconciled.current_conflict_precedent_ids == (
        "precedent-established",
        "precedent-rejected",
    )


def test_m5_precedent_import_rejects_claimed_vector_before_any_write(tmp_path: Path) -> None:
    database, _, manifest = _install_precedent_run(tmp_path)
    config = load_config(ROOT / "configs/demo.yaml")
    authority = _preset_authority(manifest, "precedent-forged-import")
    assert authority.text_embedding is not None
    forged_embedding = M5EmbeddingVector(
        request=authority.text_embedding.request,
        values=tuple(-value for value in authority.text_embedding.values),
    )
    forged_precedent = authority.precedent.model_copy(
        update={"text_embedding_ref": forged_embedding.embedding_id}
    )
    forged_authority = authority.model_copy(
        update={
            "precedent": forged_precedent,
            "text_embedding": forged_embedding,
        }
    )
    source = tmp_path / "forged-precedent.jsonl"
    source.write_text(
        canonical_json(forged_authority.model_dump(mode="json")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractViolation, match="controlled fake reconstruction"):
        import_m5_precedent_file(
            config=config,
            workspace_root=tmp_path,
            database_path=database,
            run_id=RUN_ID,
            source_path=source,
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM precedent_embeddings").fetchone() == (0,)


def test_conflict_service_rejects_foreign_valid_config_even_without_candidates(
    tmp_path: Path,
) -> None:
    database, _, manifest = _install_precedent_run(tmp_path)
    config = load_config(ROOT / "configs/demo.yaml")
    foreign_precedents = config.precedents.model_copy(
        update={"conflict_similarity": config.precedents.conflict_similarity - 0.01}
    )
    foreign_config = config.model_copy(update={"precedents": foreign_precedents})
    assert foreign_config.config_sha256 != manifest.config_sha256

    with pytest.raises(ManifestMismatch, match="conflict config"):
        reconcile_m5_precedents_for_run(
            config=foreign_config,
            workspace_root=tmp_path,
            database_path=database,
            run_id=RUN_ID,
        )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("max_file_bytes", MAX_M5_IMPORT_FILE_BYTES + 1),
        ("max_line_bytes", MAX_M5_IMPORT_LINE_BYTES + 1),
        ("max_entries", MAX_M5_PRECEDENTS + 1),
    ],
)
def test_m5_precedent_import_service_rejects_budget_expansion(
    tmp_path: Path,
    name: str,
    value: int,
) -> None:
    database, _, _manifest = _install_precedent_run(tmp_path)
    source = tmp_path / "precedents.jsonl"
    source.write_text("", encoding="utf-8")
    budgets = {name: value}

    with pytest.raises(ContractViolation, match=name):
        import_m5_precedent_file(
            config=load_config(ROOT / "configs/demo.yaml"),
            workspace_root=tmp_path,
            database_path=database,
            run_id=RUN_ID,
            source_path=source,
            **budgets,
        )
