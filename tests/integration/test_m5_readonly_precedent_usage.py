from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.application.m5_hearing_precedent_bridge import build_m5_precedent_exposure
from labcourt.application.m5_precedents import ExactM5PrecedentRetrievalService
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.services.m5_projection import rebuild_m5_projection
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m5_applied_close_sqlite import _finalizer, _prepare_ready


def _drop_trigger_update_restore(
    database: Path,
    *,
    trigger_name: str,
    statement: str,
) -> None:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (trigger_name,),
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        trigger_sql = row[0]
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
        connection.execute(statement)
        connection.execute(trigger_sql)


def _drop_trigger_delete_restore(
    database: Path,
    *,
    trigger_name: str,
    statement: str,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (trigger_name,),
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        trigger_sql = row[0]
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
        connection.execute(statement)
        connection.execute(trigger_sql)


def test_readonly_projection_includes_exact_exposed_and_applied_authorities(
    tmp_path: Path,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)
    _finalizer(runtime).finalize(RUN_ID)

    authority = ReadonlyM5ArtifactRepository(runtime.database, config=runtime.config).scan(RUN_ID)

    assert authority.failures == ()
    counts = {item.authority_kind: item.count for item in authority.traversed}
    assert counts[M5AuthorityKind.PRECEDENT_EXPOSURE] == 1
    assert counts[M5AuthorityKind.PRECEDENT_APPLICATION_BATCH] == 1
    assert counts[M5AuthorityKind.PRECEDENT_CITATION] == 1
    assert counts[M5AuthorityKind.PRECEDENT_CAUSAL_EVENT] == 3

    result = rebuild_m5_projection(
        config=runtime.config,
        run_id=RUN_ID,
        database_path=runtime.database,
        workspace_root=tmp_path / "projection",
    )
    precedent_path = next(path for path in result.jsonl_paths if path.name == "precedents.jsonl")
    kinds = {
        json.loads(line)["authority_kind"]
        for line in precedent_path.read_text(encoding="utf-8").splitlines()
    }
    assert M5AuthorityKind.PRECEDENT_EXPOSURE.value in kinds
    assert M5AuthorityKind.PRECEDENT_APPLICATION_BATCH.value in kinds
    assert M5AuthorityKind.PRECEDENT_CAUSAL_EVENT.value in kinds


def test_readonly_validation_never_constructs_an_embedding_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)
    _finalizer(runtime).finalize(RUN_ID)

    def poison_new(cls: type[object]) -> object:
        raise AssertionError(f"readonly validation constructed provider {cls.__name__}")

    monkeypatch.setattr(
        DeterministicFakePrecedentEmbeddingProvider,
        "__new__",
        staticmethod(poison_new),
    )

    authority = ReadonlyM5ArtifactRepository(runtime.database, config=runtime.config).scan(RUN_ID)

    assert authority.failures == ()


def test_readonly_requires_empty_application_batch_for_zero_binding_exposure(
    tmp_path: Path,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=0)
    _finalizer(runtime).finalize(RUN_ID)
    _drop_trigger_delete_restore(
        runtime.database,
        trigger_name="m5_precedent_application_batches_no_delete",
        statement="DELETE FROM m5_precedent_application_batches",
    )

    authority = ReadonlyM5ArtifactRepository(runtime.database, config=runtime.config).scan(RUN_ID)

    assert any(
        failure.reason_code == "FINAL_EXPOSED_APPLICATION_BATCH_CLOSURE_INVALID"
        for failure in authority.failures
    )


def test_readonly_accepts_final_degraded_usage_without_application_roots(
    tmp_path: Path,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=0, degraded=True)
    _finalizer(runtime).finalize(RUN_ID)

    authority = ReadonlyM5ArtifactRepository(runtime.database, config=runtime.config).scan(RUN_ID)

    assert authority.failures == ()
    counts = {item.authority_kind: item.count for item in authority.traversed}
    assert counts[M5AuthorityKind.PRECEDENT_EXPOSURE] == 0
    assert counts[M5AuthorityKind.PRECEDENT_APPLICATION_BATCH] == 0
    assert counts[M5AuthorityKind.PRECEDENT_CITATION] == 0
    assert counts[M5AuthorityKind.PRECEDENT_CAUSAL_EVENT] == 1


def test_readonly_citation_discriminator_never_trial_parses_applied_commit(
    tmp_path: Path,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)
    _finalizer(runtime).finalize(RUN_ID)
    with sqlite3.connect(runtime.database) as connection:
        row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'precedent_citations_no_update'
            """
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        trigger_sql = row[0]
        connection.execute('DROP TRIGGER "precedent_citations_no_update"')
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            """
            UPDATE precedent_citations
            SET citation_kind = 'DIRECT', application_batch_id = NULL,
                application_binding_id = NULL
            WHERE citation_kind = 'APPLIED'
            """
        )
        connection.execute(trigger_sql)

    authority = ReadonlyM5ArtifactRepository(runtime.database, config=runtime.config).scan(RUN_ID)

    assert any(
        failure.reason_code == "CANONICAL_DOCUMENT_INVALID"
        and failure.authority_kind == M5AuthorityKind.PRECEDENT_CITATION
        for failure in authority.failures
    )


def test_readonly_rebuilds_trusted_query_for_exposure_without_application_batch(
    tmp_path: Path,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)
    with sqlite3.connect(runtime.database) as connection:
        raw = connection.execute(
            "SELECT exposure_json FROM m5_precedent_exposures WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()[0]
    original = M5PrecedentExposureBatchAuthority.model_validate_json(raw)
    original_query = original.m5_retrieval_result.query
    forged_policy = original_query.policy.model_copy(
        update={
            "conflict_similarity": (
                -1.0 if original_query.policy.conflict_similarity != -1.0 else 1.0
            )
        }
    )
    forged_query = original_query.model_copy(update={"policy": forged_policy})
    forged_result = ExactM5PrecedentRetrievalService().retrieve(
        forged_query,
        tuple(
            evaluation.authority
            for evaluation in original.m5_retrieval_result.candidate_evaluations
        ),
    )
    forged = build_m5_precedent_exposure(
        outcome=original.m4_retrieval_outcome,
        result=forged_result,
    )
    forged_raw = canonical_json(forged.model_dump(mode="json"))
    with sqlite3.connect(runtime.database) as connection:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'm5_precedent_exposures_no_update'
            """
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        trigger_sql = trigger_row[0]
        connection.execute('DROP TRIGGER "m5_precedent_exposures_no_update"')
        connection.execute(
            """
            UPDATE m5_precedent_exposures
            SET exposure_id = ?, exposure_sha256 = ?, m5_query_id = ?,
                m5_result_id = ?, policy_id = ?, exposure_json = ?, document_sha256 = ?
            WHERE run_id = ?
            """,
            (
                forged.exposure_id,
                forged.exposure_sha256,
                forged.m5_retrieval_result.query.query_id,
                forged.m5_retrieval_result.result_id,
                forged.policy_id,
                forged_raw,
                hashlib.sha256(forged_raw.encode("utf-8")).hexdigest(),
                RUN_ID,
            ),
        )
        connection.execute(trigger_sql)

    authority = ReadonlyM5ArtifactRepository(runtime.database, config=runtime.config).scan(RUN_ID)

    assert any(
        failure.reason_code == "PRECEDENT_EXPOSURE_TRUSTED_QUERY_MISMATCH"
        for failure in authority.failures
    )


def test_readonly_exposure_requires_its_exact_durable_m4_receipt(tmp_path: Path) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)
    _finalizer(runtime).finalize(RUN_ID)
    _drop_trigger_update_restore(
        runtime.database,
        trigger_name="m4_precedent_retrieval_receipts_no_update",
        statement=(
            "UPDATE m4_precedent_retrieval_receipts SET receipt_json = '{}', "
            "document_sha256 = "
            "'44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'"
        ),
    )

    authority = ReadonlyM5ArtifactRepository(runtime.database, config=runtime.config).scan(RUN_ID)

    assert any(
        failure.reason_code == "PRECEDENT_EXPOSURE_M4_RECEIPT_INVALID"
        for failure in authority.failures
    )


def test_readonly_rejects_missing_historical_candidate_and_application_citation(
    tmp_path: Path,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)
    _finalizer(runtime).finalize(RUN_ID)
    _drop_trigger_delete_restore(
        runtime.database,
        trigger_name="m5_precedent_causal_events_no_delete",
        statement="""
        DELETE FROM m5_precedent_causal_events
        WHERE (
            event_kind = 'PRECEDENT_CITATION_APPENDED'
            AND source_id IN (
                SELECT citation_id FROM precedent_citations
                WHERE citation_kind = 'APPLIED'
            )
        ) OR (
            event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
            AND source_id IN (
                SELECT authority_id FROM precedents WHERE source <> 'AUTOMATIC'
            )
        )
        """,
    )
    _drop_trigger_delete_restore(
        runtime.database,
        trigger_name="precedent_citations_no_delete",
        statement="DELETE FROM precedent_citations WHERE citation_kind = 'APPLIED'",
    )
    _drop_trigger_delete_restore(
        runtime.database,
        trigger_name="precedents_no_delete",
        statement="DELETE FROM precedents WHERE source <> 'AUTOMATIC'",
    )

    authority = ReadonlyM5ArtifactRepository(runtime.database, config=runtime.config).scan(RUN_ID)

    reasons = {failure.reason_code for failure in authority.failures}
    assert "PRECEDENT_EXPOSURE_RETRIEVAL_REPLAY_INVALID" in reasons
    assert "APPLICATION_BATCH_CITATION_CLOSURE_INVALID" in reasons


def test_readonly_rejects_applied_raw_score_index_tamper(tmp_path: Path) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)
    _finalizer(runtime).finalize(RUN_ID)
    _drop_trigger_update_restore(
        runtime.database,
        trigger_name="precedent_citations_no_update",
        statement="UPDATE precedent_citations SET score = score + 0.125",
    )

    authority = ReadonlyM5ArtifactRepository(runtime.database, config=runtime.config).scan(RUN_ID)

    assert any(
        failure.reason_code == "INDEX_BINDING_MISMATCH"
        and failure.authority_kind == M5AuthorityKind.PRECEDENT_CITATION
        for failure in authority.failures
    )
