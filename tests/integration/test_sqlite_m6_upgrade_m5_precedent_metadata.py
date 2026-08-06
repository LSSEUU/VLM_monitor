from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveCursor,
    M6LiveReader,
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    read_m6_sqlite_case_authority,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_documents import (
    plan_m6_sqlite_m4_model_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_metadata import (
    M6SQLiteM5PrecedentDocumentError,
    plan_m6_sqlite_m5_precedent_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_plan import (
    M6SQLiteM5PrecedentDocumentsPlan,
    M6SQLiteM5PrecedentPlanFailureCode,
)
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from tests.integration.test_m3_sqlite_repository import BUSY_TIMEOUT_MS, RUN_ID
from tests.integration.test_m5_applied_close_sqlite import _prepare_ready, _ReadyRuntime
from tests.integration.test_sqlite_m6_upgrade_acquisition_documents import (
    _historical_binding,
    _m4_inputs,
)


@pytest.fixture(scope="module")
def successful_runtime(tmp_path_factory: pytest.TempPathFactory) -> _ReadyRuntime:
    return _prepare_ready(
        tmp_path_factory.mktemp("m6-m5-metadata-success"),
        selected_precedent_count=0,
    )


@pytest.fixture(scope="module")
def degraded_runtime(tmp_path_factory: pytest.TempPathFactory) -> _ReadyRuntime:
    return _prepare_ready(
        tmp_path_factory.mktemp("m6-m5-metadata-degraded"),
        selected_precedent_count=0,
        degraded=True,
    )


def _hearing_id(database: Path, case_id: str) -> str:
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT hearing_id FROM m4_hearings WHERE run_id = ? AND case_id = ?",
            (RUN_ID, case_id),
        ).fetchall()
    assert len(rows) == 1
    return str(rows[0][0])


def _successful_observations(
    runtime: _ReadyRuntime,
) -> tuple[M6UpgradeObservedArtifactIdentity, ...]:
    with sqlite3.connect(runtime.database) as connection:
        row = connection.execute(
            """
            SELECT exposure_id, exposure_json
            FROM m5_precedent_exposures
            WHERE run_id = ? AND case_id = ?
            """,
            (RUN_ID, runtime.ready.case.case_id),
        ).fetchone()
    assert row is not None
    exposure = M5PrecedentExposureBatchAuthority.model_validate_json(str(row[1]))
    vector = exposure.m5_retrieval_result.query.text_embedding
    assert vector is not None
    return tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                    kind=M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
                    artifact_id=str(row[0]),
                    usage=M6UpgradeArtifactUsage.PRODUCED,
                ),
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                    kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
                    artifact_id=vector.embedding_id,
                    usage=M6UpgradeArtifactUsage.PRODUCED,
                ),
            ),
            key=lambda value: value.sort_key,
        )
    )


def _plan(
    runtime: _ReadyRuntime,
    observations: tuple[M6UpgradeObservedArtifactIdentity, ...],
    *,
    recording: list[bool] | None = None,
) -> M6SQLiteM5PrecedentDocumentsPlan:
    case_id = runtime.ready.case.case_id
    hearing_id = _hearing_id(runtime.database, case_id)
    repository = SQLiteEvidenceRepository(runtime.database, BUSY_TIMEOUT_MS)
    role_bindings, model_observations = _m4_inputs(repository, hearing_id=hearing_id)
    binding = _historical_binding(
        runtime.database,
        case_id=case_id,
        revision=runtime.ready.revision,
    )
    with m6_live_committed_read_cut(runtime.database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            assert selector.execute("SELECT 1 AS ready").fetchone() is not None
        with cut.reader() as reader:
            authority = read_m6_sqlite_case_authority(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=runtime.manifest.manifest_id,
                expected_manifest_rule_version=runtime.manifest.rule_version,
                candidate_case_binding=binding,
            )
            upstream = plan_m6_sqlite_m4_model_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=runtime.manifest.manifest_id,
                expected_role_model_manifests=role_bindings,
                selected_case_authority=authority,
                observed_model_calls=model_observations,
            )
            if recording is not None:
                recording[0] = True
            try:
                plan = plan_m6_sqlite_m5_precedent_documents(
                    connection=reader,
                    manifest=runtime.manifest,
                    config=runtime.config,
                    selected_case_authority=authority,
                    upstream_m4_model_plan=upstream,
                    observed_precedent_artifacts=observations,
                )
            finally:
                if recording is not None:
                    recording[0] = False
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS ready").fetchone() is not None
    return plan


_BODY_COLUMNS = (
    "hearing_json",
    "cycle_json",
    "receipt_json",
    "exposure_json",
    "embedding_json",
    "authority_json",
)


def _assert_metadata_only(statements: list[str]) -> None:
    assert statements
    for statement in statements:
        lowered = statement.lower()
        assert "json_extract" not in lowered
        for column in _BODY_COLUMNS:
            stripped = re.sub(
                rf"(?:typeof|octet_length)\(\s*(?:\w+\.)?{column}\s*\)",
                "",
                statement,
                flags=re.IGNORECASE,
            )
            assert re.search(rf"\b(?:\w+\.)?{column}\b", stripped, re.IGNORECASE) is None


def test_success_plan_derives_query_embedding_without_provider_or_body_reads(
    successful_runtime: _ReadyRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations = _successful_observations(successful_runtime)
    statements: list[str] = []
    recording = [False]
    original_execute = M6LiveReader.execute

    def execute_spy(
        self: M6LiveReader,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        if recording[0]:
            statements.append(statement)
        return original_execute(self, statement, parameters)

    def forbidden_embed(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("metadata planning must not invoke an embedding provider")

    monkeypatch.setattr(M6LiveReader, "execute", execute_spy)
    monkeypatch.setattr(
        DeterministicFakePrecedentEmbeddingProvider,
        "embed",
        forbidden_embed,
    )
    first = _plan(successful_runtime, observations, recording=recording)
    second = _plan(successful_runtime, observations)

    assert first == second
    assert len(first.retrievals) == 1
    assert len(first.exposures) == 1
    assert len(first.derived_query_embeddings) == 1
    assert first.durable_embeddings == ()
    assert first.precedent_revisions == ()
    assert first.observed_artifacts == observations
    assert tuple(value.kind for value in first.planned_artifact_refs) == (
        M6UpgradePhysicalArtifactKind.EMBEDDING,
        M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
    )
    _assert_metadata_only(statements)


def test_bridge_degraded_plan_is_legal_and_has_no_m5_refs(
    degraded_runtime: _ReadyRuntime,
) -> None:
    plan = _plan(degraded_runtime, ())

    assert len(plan.retrievals) == 1
    assert plan.retrievals[0].precedent_retrieval_degraded
    assert plan.exposures == ()
    assert plan.derived_query_embeddings == ()
    assert plan.durable_embeddings == ()
    assert plan.precedent_revisions == ()
    assert plan.planned_artifact_refs == ()


@pytest.mark.parametrize("mutation", ("missing_exposure", "wrong_usage", "extra_embedding"))
def test_observation_inventory_tampering_fails_closed(
    successful_runtime: _ReadyRuntime,
    mutation: str,
) -> None:
    observations = _successful_observations(successful_runtime)
    if mutation == "missing_exposure":
        observations = tuple(
            value
            for value in observations
            if value.kind != M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE
        )
    elif mutation == "wrong_usage":
        observations = tuple(
            value.model_copy(update={"usage": M6UpgradeArtifactUsage.CONSUMED})
            if value.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
            else value
            for value in observations
        )
    else:
        observations = tuple(
            sorted(
                (
                    *observations,
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                        kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
                        artifact_id="f" * 64,
                        usage=M6UpgradeArtifactUsage.CONSUMED,
                    ),
                ),
                key=lambda value: value.sort_key,
            )
        )

    with pytest.raises(M6SQLiteM5PrecedentDocumentError) as captured:
        _plan(successful_runtime, observations)
    assert captured.value.reason_code == M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
