from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage import SecureHearingModelResponseStore, SecureWorkspace
from labcourt.adapters.storage.sqlite_hearing_repository import SQLiteHearingRepository
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_m5_precedent_usage import (
    SQLiteM5PrecedentExposureCommitter,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.vlm import DeterministicFakeHearingVLMClient
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.automatic_precedent_verifier import (
    ConfiguredAutomaticPrecedentVerifier,
)
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.application.hearing_situation import build_hearing_situation_text
from labcourt.application.m5_finalization import M5FinalizationCoordinator
from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
    M5HearingPrecedentRetriever,
)
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.application.m5_precedent_usage_verifier import (
    ConfiguredM5PrecedentApplicationVerifier,
)
from labcourt.application.m5_precedents import (
    ExactM5PrecedentRetrievalService,
    record_m5_precedent_citation,
    revoke_m5_precedent,
)
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.config_loader import load_config
from labcourt.contracts.alert_policy import AlertPolicyAuthority
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import CaseStatus, PrecedentSource
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
)
from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.services.m5_operations import finalize_m5_run
from tests.integration.test_m3_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    RUN_ID,
    _clock,
    _complete_call,
    _detection,
    _draft,
    _event,
    _frame,
    _parsed,
    _parsed_receipt,
    _RawVerifier,
    _request,
    _response,
    _screening_for,
    _Verifier,
)
from tests.integration.test_m4_hearing_coordinator import (
    _fixtures_for_terminal_hearing,
    _NeverAcquisitionExecutor,
    _PromptRegistrar,
)
from tests.integration.test_m5_sqlite_precedents import _authority, _query
from tests.unit.test_m4_hearing_prompt_renderer import _hearing_schema_documents
from tests.unit.test_m5_alert_policy import _manifest_with_stream

ROOT = Path(__file__).parents[2]
CLOSE_TIME = datetime(2026, 8, 3, 9, 10, 11, 120000, tzinfo=UTC)


@dataclass(frozen=True)
class _ReadyRuntime:
    database: Path
    workspace_root: Path
    config: AppConfig
    manifest: RunManifest
    ready: CaseSnapshot


def _escalated_case_with_stream(
    tmp_path: Path,
) -> tuple[Path, SQLiteEvidenceRepository, EvidencePack, CaseSnapshot]:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    frame = _frame()
    base_manifest = _manifest_with_stream()
    stream = base_manifest.streams[0].model_copy(
        update={
            "fps_num": frame.fps_num,
            "fps_den": frame.fps_den,
            "width": frame.width,
            "height": frame.height,
        }
    )
    manifest = base_manifest.model_copy(update={"streams": (stream,)})
    evidence = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=_clock,
    )
    evidence.register_run(RUN_ID, manifest)
    event = _event().model_copy(update={"manifest_id": manifest.manifest_id})
    evidence.register_frame(RUN_ID, frame)
    evidence.register_detection(RUN_ID, _detection())
    evidence.create_or_get_case(RUN_ID, event)
    draft = _draft(version=1, complete=True).model_copy(
        update={
            "event": event,
            "objective_facts": event.objective_facts,
            "manifest_id": manifest.manifest_id,
        }
    )
    source_crop = draft.focus_crops[0]
    crop = source_crop.model_copy(
        update={"local_path": f"{RUN_ID}/frames/{source_crop.media_sha256}.png"}
    )
    published = evidence.publish_pack(
        RUN_ID,
        1,
        draft.model_copy(update={"focus_crops": (crop,)}),
    )
    pack = published.pack
    closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)
    config = load_config(ROOT / "configs" / "demo.yaml")
    m3 = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
        procedural_review_verifier=DeterministicProceduralReviewVerifier(config, evidence),
    )
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    output = _parsed(request, response, violation_probability=0.5)
    receipt = _parsed_receipt(request, response, output)
    _complete_call(m3, request, response)
    m3.append_parse_receipt(receipt, output)
    committed = m3.commit_screening(
        RUN_ID,
        published.case.revision,
        evidence.get_audit_head(RUN_ID),
        closure,
        _screening_for(pack, output),
    )
    assert committed.case.case.status == CaseStatus.ESCALATED
    return database, evidence, pack, committed.case


def _prepare_ready(
    tmp_path: Path,
    *,
    selected_precedent_count: int,
    degraded: bool = False,
) -> _ReadyRuntime:
    database, evidence, pack, escalated = _escalated_case_with_stream(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = evidence.load_run_manifest(RUN_ID)
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    policy_verifier = ConfiguredM5PrecedentPolicyVerifier(config)
    m5 = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        m5_precedent_policy_verifier=policy_verifier,
    )
    embedding_provider = DeterministicFakePrecedentEmbeddingProvider()
    situation_text = build_hearing_situation_text(pack)
    for ordinal in range(selected_precedent_count):
        m5.append_authority(
            _authority(
                manifest,
                f"applied-close-precedent-{ordinal}",
                situation_text=situation_text,
            ),
            None,
        )

    if degraded:
        precedents = HearingPrecedentRetrievalService(
            FakeHearingPrecedentRetriever(()),
            retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
            retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
        )
    else:
        precedents = HearingPrecedentRetrievalService(
            M5HearingPrecedentRetriever(
                repository=m5,
                manifest=manifest,
                policy=policy_verifier.expected_policy(manifest),
                run_mode=policy_verifier.run_mode,
                embedding_provider=embedding_provider,
            ),
            retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
            retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
        )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=escalated,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
        include_precedent_applications=not degraded,
    )
    hearing_workspace = tmp_path / "hearing-workspace"
    hearing_workspace.mkdir()
    hearings = SQLiteHearingRepository(evidence)
    with SecureWorkspace(hearing_workspace, config.storage.max_media_bytes) as workspace:
        response_store = SecureHearingModelResponseStore(workspace)
        role_calls = HearingRoleCallService(
            repository=hearings,
            response_store=response_store,
            vlm_client=DeterministicFakeHearingVLMClient(fixtures, response_store),
            prompt_registrar=_PromptRegistrar(),
            owner_token_factory=lambda: "o" * 43,
        )
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=evidence,
            hearing_repository=hearings,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=hearings,
                executor=_NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(config, evidence),
            precedent_outcome_committer=SQLiteM5PrecedentExposureCommitter(
                repository=m5,
                hearing_repository=hearings,
                embedding_provider=embedding_provider,
            ),
        )
        outcome = coordinator.process_case(RUN_ID, pack.case_id)
    assert outcome.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    return _ReadyRuntime(
        database=database,
        workspace_root=tmp_path,
        config=config,
        manifest=manifest,
        ready=outcome.case,
    )


def _finalizer(
    runtime: _ReadyRuntime,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> M5FinalizationCoordinator:
    embedding_provider = DeterministicFakePrecedentEmbeddingProvider()
    alert_verifier = ConfiguredAlertPolicyVerifier(runtime.config)
    repository = SQLiteM5Repository(
        runtime.database,
        BUSY_TIMEOUT_MS,
        clock=lambda: CLOSE_TIME,
        alert_policy_verifier=alert_verifier,
        automatic_precedent_verifier=ConfiguredAutomaticPrecedentVerifier(
            runtime.config,
            embedding_provider,
        ),
        m5_precedent_policy_verifier=ConfiguredM5PrecedentPolicyVerifier(runtime.config),
        m5_precedent_application_verifier=ConfiguredM5PrecedentApplicationVerifier(runtime.config),
        fault_injector=fault_injector,
    )
    return M5FinalizationCoordinator(
        repository=repository,
        verifier=alert_verifier,
        embedding_provider=embedding_provider,
        config=runtime.config,
        manifest=runtime.manifest,
        clock=lambda: CLOSE_TIME,
    )


def _load_committed_roots(
    runtime: _ReadyRuntime,
) -> tuple[
    AlertPolicyAuthority,
    M5PrecedentAuthority,
    M5PrecedentApplicationBatchAuthority,
    tuple[M5PrecedentApplicationCitationCommit, ...],
]:
    with sqlite3.connect(runtime.database) as connection:
        alert_raw = connection.execute(
            "SELECT authority_json FROM alerts WHERE run_id = ? AND case_id = ?",
            (RUN_ID, runtime.ready.case.case_id),
        ).fetchone()[0]
        automatic_raw = connection.execute(
            """
            SELECT authority_json FROM precedents
            WHERE run_id = ? AND source_case_id = ? AND source = 'AUTOMATIC'
            """,
            (RUN_ID, runtime.ready.case.case_id),
        ).fetchone()[0]
        batch_raw = connection.execute(
            """
            SELECT application_batch_json FROM m5_precedent_application_batches
            WHERE run_id = ? AND case_id = ?
            """,
            (RUN_ID, runtime.ready.case.case_id),
        ).fetchone()[0]
        citation_rows = connection.execute(
            """
            SELECT commit_json FROM precedent_citations
            WHERE run_id = ? AND case_id = ? AND citation_kind = 'APPLIED'
            ORDER BY application_binding_id
            """,
            (RUN_ID, runtime.ready.case.case_id),
        ).fetchall()
    return (
        AlertPolicyAuthority.model_validate_json(alert_raw),
        M5PrecedentAuthority.model_validate_json(automatic_raw),
        M5PrecedentApplicationBatchAuthority.model_validate_json(batch_raw),
        tuple(
            M5PrecedentApplicationCitationCommit.model_validate_json(row[0])
            for row in citation_rows
        ),
    )


def test_final_exposed_close_persists_and_exactly_replays_applied_roots(
    tmp_path: Path,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)

    report = finalize_m5_run(
        config=runtime.config,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        run_id=RUN_ID,
        clock=lambda: CLOSE_TIME,
    )

    outcome = report.outcomes[0]
    assert outcome.application_batch_id is not None
    assert outcome.applied_citation_count == 1
    alert, automatic, batch, citations = _load_committed_roots(runtime)
    assert batch.application_batch_id == outcome.application_batch_id
    assert len(batch.application_bindings) == len(citations) == 1
    assert automatic.created_at == CLOSE_TIME
    assert citations[0].citation.cited_at == CLOSE_TIME
    assert citations[0].application_batch == batch
    raw_evaluation = citations[0].application_binding.exposure_item.candidate_evaluation
    assert citations[0].citation.score == raw_evaluation.score
    with sqlite3.connect(runtime.database) as connection:
        citation_kind, stored_score = connection.execute(
            """
            SELECT citation_kind, score FROM precedent_citations
            WHERE run_id = ? AND citation_id = ?
            """,
            (RUN_ID, citations[0].citation.citation_id),
        ).fetchone()
    assert citation_kind == "APPLIED"
    assert stored_score == raw_evaluation.score

    repository = _finalizer(runtime)._repository
    replayed = repository.commit_alert_policy(
        RUN_ID,
        runtime.ready.revision,
        alert,
        automatic,
        batch,
        citations,
    )
    assert replayed.revision == runtime.ready.revision + 1
    assert replayed.case.status == CaseStatus.CLOSED
    with pytest.raises(ContractViolation, match="APPLIED roots"):
        repository.commit_alert_policy(
            RUN_ID,
            runtime.ready.revision,
            alert,
            automatic,
            batch,
            (),
        )


def test_applied_citation_replay_requires_its_causal_event(tmp_path: Path) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)
    finalize_m5_run(
        config=runtime.config,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        run_id=RUN_ID,
        clock=lambda: CLOSE_TIME,
    )
    alert, automatic, batch, citations = _load_committed_roots(runtime)
    assert len(citations) == 1

    with sqlite3.connect(runtime.database) as connection:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm5_precedent_causal_events_no_delete'
            """
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        connection.execute("DROP TRIGGER m5_precedent_causal_events_no_delete")
        cursor = connection.execute(
            """
            DELETE FROM m5_precedent_causal_events
            WHERE run_id = ? AND source_id = ?
            """,
            (RUN_ID, citations[0].citation.citation_id),
        )
        assert cursor.rowcount == 1
        connection.execute(trigger_row[0])
        remaining_events = connection.execute(
            "SELECT COUNT(*) FROM m5_precedent_causal_events WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()[0]

    repository = _finalizer(runtime)._repository
    with pytest.raises(RepositoryIntegrityError, match="causal"):
        repository.commit_alert_policy(
            RUN_ID,
            runtime.ready.revision,
            alert,
            automatic,
            batch,
            citations,
        )
    with sqlite3.connect(runtime.database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m5_precedent_causal_events WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone() == (remaining_events,)


def test_final_exposed_with_zero_visible_precedents_persists_empty_batch(
    tmp_path: Path,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=0)

    report = finalize_m5_run(
        config=runtime.config,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        run_id=RUN_ID,
        clock=lambda: CLOSE_TIME,
    )

    outcome = report.outcomes[0]
    assert outcome.application_batch_id is not None
    assert outcome.applied_citation_count == 0
    _, _, batch, citations = _load_committed_roots(runtime)
    assert batch.application_batch_id == outcome.application_batch_id
    assert batch.application_bindings == ()
    assert citations == ()


def test_final_degraded_close_has_no_application_roots(tmp_path: Path) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=0, degraded=True)

    report = finalize_m5_run(
        config=runtime.config,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        run_id=RUN_ID,
        clock=lambda: CLOSE_TIME,
    )

    outcome = report.outcomes[0]
    assert outcome.application_batch_id is None
    assert outcome.applied_citation_count == 0
    with sqlite3.connect(runtime.database) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM m5_precedent_application_batches").fetchone()[
                0
            ]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM precedent_citations WHERE citation_kind = 'APPLIED'"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM m5_precedent_exposures").fetchone()[0] == 0


def test_mixed_direct_and_applied_citations_survive_snapshot_revocation_and_appeal_scan(
    tmp_path: Path,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)
    _finalizer(runtime).finalize(RUN_ID)
    _, _, batch, applied_commits = _load_committed_roots(runtime)
    applied = applied_commits[0]
    precedent_id = applied.citation.precedent_id
    repository = _finalizer(runtime)._repository
    direct_query = _query(runtime.manifest, runtime.ready.case.case_id)
    assert direct_query.query_id != batch.exposure.m5_retrieval_result.query.query_id
    direct_result = ExactM5PrecedentRetrievalService().retrieve(
        direct_query,
        repository.list_for_retrieval(direct_query),
    )
    direct = record_m5_precedent_citation(
        result=direct_result,
        precedent_id=precedent_id,
        cited_at=CLOSE_TIME,
    )
    assert repository.commit_citation(direct) == direct

    snapshot = repository.citation_snapshot(RUN_ID, precedent_id)
    assert snapshot.observed_citation_count == 2
    assert {citation.citation_id for citation in snapshot.citations} == {
        applied.citation.citation_id,
        direct.citation.citation_id,
    }
    current = repository.get_precedent(RUN_ID, precedent_id)
    assert current is not None
    revoked = revoke_m5_precedent(
        authority=current,
        citation_snapshot=snapshot,
        revoked_by_ref="mixed-citation-appeal-scan",
        revoked_at=CLOSE_TIME,
    )
    committed = repository.commit_revocation(revoked)
    assert committed.receipt.historical_case_ids == (runtime.ready.case.case_id,)
    assert set(committed.receipt.historical_citation_ids) == {
        applied.citation.citation_id,
        direct.citation.citation_id,
    }
    historical = repository.citation_snapshot(RUN_ID, precedent_id)
    assert historical.citations == snapshot.citations
    assert batch.exposure.exposed_precedents[0].historical_authority == current

    with closing(repository._connection()) as connection:
        affected = repository._affected_citations(connection, RUN_ID, precedent_id)
    assert {item.source_citation_id for item in affected} == {
        applied.citation.citation_id,
        direct.citation.citation_id,
    }
    assert {item.citing_case_id for item in affected} == {runtime.ready.case.case_id}


@pytest.mark.parametrize(
    "fault_phase",
    (
        "m5.alert.application_batch_inserted",
        "m5.alert.application_citation.1.before_causal_event",
        "m5.alert.application_citation.1.after_causal_event",
        "m5.alert.application_citation.1.inserted",
        "m5.alert.application_citations_complete",
    ),
)
def test_applied_root_faults_roll_back_the_entire_close(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    runtime = _prepare_ready(tmp_path, selected_precedent_count=1)

    def inject(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected APPLIED close fault")

    with pytest.raises(RuntimeError, match="injected APPLIED close fault"):
        _finalizer(runtime, fault_injector=inject).finalize(RUN_ID)

    with sqlite3.connect(runtime.database) as connection:
        status, revision = connection.execute(
            "SELECT status, current_revision FROM cases WHERE run_id = ? AND case_id = ?",
            (RUN_ID, runtime.ready.case.case_id),
        ).fetchone()
        assert (status, revision) == (
            CaseStatus.READY_FOR_ALERT_POLICY.value,
            runtime.ready.revision,
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM m5_precedent_application_batches").fetchone()[
                0
            ]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM precedent_citations WHERE citation_kind = 'APPLIED'"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM alert_outbox").fetchone()[0] == 0
        automatic_count = connection.execute(
            "SELECT COUNT(*) FROM precedents WHERE source = ?",
            (PrecedentSource.AUTOMATIC.value,),
        ).fetchone()[0]
        assert automatic_count == 0
        assert connection.execute("SELECT COUNT(*) FROM m5_precedent_causal_events").fetchone() == (
            1,
        )
