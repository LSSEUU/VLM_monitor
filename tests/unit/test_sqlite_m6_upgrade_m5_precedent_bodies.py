"""Canonical same-snapshot body tests for the M6 M5-precedent plan."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_bodies as bodies
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveCursor,
    M6LiveReader,
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_metadata import (
    M6SQLiteM5PrecedentDocumentError,
    resolve_m6_sqlite_m5_precedent_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_plan import (
    M6SQLiteM5PrecedentCycleSlot,
    M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot,
    M6SQLiteM5PrecedentDocumentsPlan,
    M6SQLiteM5PrecedentDurableEmbeddingSlot,
    M6SQLiteM5PrecedentExposureSlot,
    M6SQLiteM5PrecedentHearingSlot,
    M6SQLiteM5PrecedentPlanFailureCode,
    M6SQLiteM5PrecedentRetrievalKey,
    M6SQLiteM5PrecedentRetrievalSlot,
    M6SQLiteM5PrecedentRevisionSlot,
)
from labcourt.adapters.storage.sqlite_repository import MigrationRunner, _open_connection
from labcourt.application.m5_embedding_integrity import derive_m5_controlled_fake_embedding
from labcourt.application.m5_hearing_precedent_bridge import (
    build_m4_success_outcome,
    build_m5_precedent_exposure,
    project_m5_result_to_m4,
)
from labcourt.application.m5_precedents import ExactM5PrecedentRetrievalService
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    PrecedentSource,
    PrecedentStatus,
    VerdictDecision,
)
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5PrecedentAuthority,
)
from labcourt.contracts.m6_replay_locked import M6LockedEmbeddingScope
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.precedents import Precedent
from tests.unit.test_sqlite_m6_upgrade_m5_precedent_query import _fixture as _query_fixture


def _raw_sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _json_sha256(value: object) -> str:
    return _raw_sha256(canonical_json(value))


def _canonical(value: object) -> str:
    return canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]


@dataclass(frozen=True, slots=True)
class _Upstream:
    plan_identity_sha256: str
    run_id: str
    case_id: str
    manifest_id: str


@dataclass(frozen=True, slots=True)
class _Prepared:
    reader: M6LiveReader
    plan: M6SQLiteM5PrecedentDocumentsPlan
    upstream: _Upstream
    selected_case: Case
    config: AppConfig
    manifest: RunManifest
    authority: M5PrecedentAuthority


def _candidate_authority(
    *,
    run_id: str,
    config: AppConfig,
    manifest: RunManifest,
    query: object,
) -> M5PrecedentAuthority:
    situation = "Historical controlled precedent situation for body recovery."
    vector = derive_m5_controlled_fake_embedding(
        channel=M5EmbeddingChannel.TEXT,
        situation_text=situation,
        model_manifest=manifest.models["text_embedding"],
    )
    now = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
    activation = now.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return M5PrecedentAuthority(
        run_id=run_id,
        config_sha256=config.config_sha256,
        revision=1,
        precedent=Precedent(
            precedent_id="precedent-body-candidate",
            situation_text=situation,
            text_embedding_ref=vector.embedding_id,
            decision_direction=VerdictDecision.ESTABLISHED,
            source=PrecedentSource.PRESET,
            status=PrecedentStatus.ACTIVE,
            evidence_class=query.evidence_class,  # type: ignore[attr-defined]
            violation_type=query.violation_type,  # type: ignore[attr-defined]
            rule_version=query.rule_version,  # type: ignore[attr-defined]
            source_case_id="historical-case-body-candidate",
            activation_at=activation,
        ),
        created_at=now,
        activated_at=now,
        text_embedding=vector,
    )


def _plan_and_documents() -> tuple[
    M6SQLiteM5PrecedentDocumentsPlan,
    _Upstream,
    Case,
    AppConfig,
    RunManifest,
    M5PrecedentAuthority,
    dict[str, str],
]:
    source = _query_fixture()
    assert isinstance(source.selected_case, Case)
    assert isinstance(source.config, AppConfig)
    assert isinstance(source.manifest, RunManifest)
    selected_case = source.selected_case
    config = source.config
    manifest = source.manifest
    rebuilt = source.reconstruct()
    authority = _candidate_authority(
        run_id=selected_case.run_id,
        config=config,
        manifest=manifest,
        query=rebuilt.m4_query,
    )
    result = ExactM5PrecedentRetrievalService().retrieve(
        rebuilt.m5_query,
        (authority,),
    )
    m4_result = project_m5_result_to_m4(query=rebuilt.m4_query, result=result)
    outcome = build_m4_success_outcome(
        query=rebuilt.m4_query,
        result=m4_result,
        cycle_scope=rebuilt.cycle_scope,
    )
    exposure = build_m5_precedent_exposure(outcome=outcome, result=result)
    receipt = outcome.receipt
    query_vector = rebuilt.query_embedding_authority.vector
    assert authority.text_embedding is not None
    candidate_vector = authority.text_embedding

    hearing_document = _canonical(rebuilt.hearing_session)
    cycle_document = _canonical(rebuilt.cycle_scope)
    receipt_document = _canonical(receipt)
    exposure_document = _canonical(exposure)
    candidate_document = _canonical(candidate_vector)
    authority_document = _canonical(authority)

    hearing = M6SQLiteM5PrecedentHearingSlot(
        run_id=source.hearing.run_id,
        case_id=source.hearing.case_id,
        rowid=10,
        hearing_id=source.hearing.hearing_id,
        screening_id=source.hearing.screening_id,
        entry_status=source.hearing.entry_status,
        trigger_review_id=source.hearing.trigger_review_id,
        initial_defect_codes=(),
        initial_defect_codes_sha256=_json_sha256([]),
        initial_pack_id=source.hearing.initial_pack_id,
        initial_pack_version=source.hearing.initial_pack_version,
        max_acquisition_rounds=source.hearing.max_acquisition_rounds,
        max_rework_rounds=source.hearing.max_rework_rounds,
        max_total_images=source.hearing.max_total_images,
        max_total_output_tokens=source.hearing.max_total_output_tokens,
        max_judge_cycles=source.hearing.max_judge_cycles,
        hearing_prompt_bundle_sha256=source.hearing.hearing_prompt_bundle_sha256,
        prosecutor_model_manifest_id=source.hearing.prosecutor_model_manifest_id,
        defender_model_manifest_id=source.hearing.defender_model_manifest_id,
        judge_model_manifest_id=source.hearing.judge_model_manifest_id,
        manifest_id=source.hearing.manifest_id,
        created_audit_sequence=1,
        document_sha256=rebuilt.hearing_session.session_sha256,
        document_bytes=len(hearing_document.encode("utf-8")),
    )
    cycle = M6SQLiteM5PrecedentCycleSlot(
        run_id=source.cycle.run_id,
        case_id=source.cycle.case_id,
        rowid=20,
        cycle_id=source.cycle.cycle_id,
        cycle_sha256=source.cycle.cycle_sha256,
        hearing_id=source.cycle.hearing_id,
        cycle_index=source.cycle.cycle_index,
        prior_acquisition_rounds=source.cycle.prior_acquisition_rounds,
        prior_rework_rounds=source.cycle.prior_rework_rounds,
        cycle_pack_id=source.cycle.cycle_pack_id,
        cycle_pack_version=source.cycle.cycle_pack_version,
        initial_trigger_review_id=None,
        initial_defect_codes=(),
        initial_defect_codes_sha256=_json_sha256([]),
        rework_review_id=None,
        rework_defect_codes=(),
        rework_defect_codes_sha256=_json_sha256([]),
        manifest_id=source.cycle.manifest_id,
        created_audit_sequence=2,
        document_sha256=rebuilt.cycle_scope.cycle_sha256,
        document_bytes=len(cycle_document.encode("utf-8")),
    )
    candidate_refs = [value.model_dump(mode="json") for value in receipt.candidate_precedent_refs]
    visible_refs = [value.model_dump(mode="json") for value in receipt.visible_precedent_refs]
    scored = [value.model_dump(mode="json") for value in receipt.scored_precedents]
    retrieval = M6SQLiteM5PrecedentRetrievalSlot(
        run_id=receipt.run_id,
        case_id=receipt.case_id,
        rowid=1,
        retrieval_receipt_id=receipt.receipt_id,
        hearing_id=receipt.hearing_session_id,
        cycle_scope_id=receipt.cycle_scope_id,
        cycle_scope_sha256=receipt.cycle_scope_sha256,
        prior_acquisition_rounds=receipt.prior_acquisition_rounds,
        prior_rework_rounds=receipt.prior_rework_rounds,
        current_pack_id=receipt.current_evidence_pack_id,
        current_pack_version=receipt.current_evidence_pack_version,
        evidence_class=receipt.evidence_class,
        violation_type=receipt.violation_type,
        rule_version=receipt.rule_version,
        top_k=receipt.top_k,
        initial_trigger_review_id=None,
        initial_defect_codes=receipt.initial_defect_codes,
        initial_defect_codes_sha256=_json_sha256([]),
        rework_review_id=None,
        rework_defect_codes=receipt.rework_defect_codes,
        rework_defect_codes_sha256=_json_sha256([]),
        candidate_precedent_ids=tuple(
            value.artifact_id for value in receipt.candidate_precedent_refs
        ),
        candidate_refs_sha256=_json_sha256(candidate_refs),
        candidate_snapshot_sha256=receipt.candidate_snapshot_sha256,
        visible_precedent_ids=tuple(value.artifact_id for value in receipt.visible_precedent_refs),
        visible_refs_sha256=_json_sha256(visible_refs),
        visible_snapshot_sha256=receipt.visible_snapshot_sha256,
        scored_precedents_sha256=_json_sha256(scored),
        retrieval_status=receipt.status,
        degraded_reason=receipt.degraded_reason,
        precedent_retrieval_degraded=False,
        retriever_version=receipt.retriever_version,
        retriever_manifest_id=receipt.retriever_manifest_id,
        query_sha256=receipt.query_sha256,
        embedding_model_manifest_id=receipt.embedding_model_manifest_id,
        manifest_id=receipt.manifest_id,
        document_sha256=receipt.receipt_sha256,
        document_bytes=len(receipt_document.encode("utf-8")),
    )
    exposure_slot = M6SQLiteM5PrecedentExposureSlot(
        run_id=exposure.run_id,
        case_id=exposure.case_id,
        rowid=1,
        exposure_id=exposure.exposure_id,
        exposure_sha256=exposure.exposure_sha256,
        hearing_id=exposure.hearing_session_id,
        cycle_index=exposure.cycle_index,
        cycle_scope_id=exposure.cycle_scope_id,
        cycle_scope_sha256=exposure.cycle_scope_sha256,
        retrieval_receipt_id=receipt.receipt_id,
        m4_query_id=outcome.query.query_id,
        m5_query_id=result.query.query_id,
        m5_result_id=result.result_id,
        candidate_count=result.candidate_count,
        exposed_count=len(exposure.exposed_precedents),
        policy_id=exposure.policy_id,
        bridge_manifest_id=exposure.bridge_manifest_id,
        manifest_id=exposure.manifest_id,
        document_sha256=_raw_sha256(exposure_document),
        document_bytes=len(exposure_document.encode("utf-8")),
    )
    derived = M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot(
        run_id=exposure.run_id,
        case_id=exposure.case_id,
        hearing_id=exposure.hearing_session_id,
        cycle_scope_id=exposure.cycle_scope_id,
        retrieval_receipt_id=receipt.receipt_id,
        m4_query_id=outcome.query.query_id,
        m5_query_id=result.query.query_id,
        channel=query_vector.request.channel,
        channel_index=0,
        request_id=query_vector.request.request_id,
        input_ref=query_vector.request.input_ref,
        input_sha256=query_vector.request.input_sha256,
        model_manifest_id=query_vector.request.model_manifest_id,
        dimensions=query_vector.request.dimensions,
        algorithm=query_vector.request.algorithm,
        physical_ref=rebuilt.query_embedding_ref,
    )
    durable = M6SQLiteM5PrecedentDurableEmbeddingSlot(
        run_id=authority.run_id,
        rowid=1,
        embedding_id=candidate_vector.embedding_id,
        request_id=candidate_vector.request.request_id,
        channel=candidate_vector.request.channel,
        input_ref=candidate_vector.request.input_ref,
        input_sha256=candidate_vector.request.input_sha256,
        model_manifest_id=candidate_vector.request.model_manifest_id,
        dimensions=candidate_vector.request.dimensions,
        algorithm=candidate_vector.request.algorithm,
        manifest_id=manifest.manifest_id,
        document_sha256=_raw_sha256(candidate_document),
        document_bytes=len(candidate_document.encode("utf-8")),
    )
    authority_dump = authority.model_dump(mode="json")
    revision = M6SQLiteM5PrecedentRevisionSlot(
        run_id=authority.run_id,
        rowid=1,
        precedent_id=authority.precedent.precedent_id,
        revision=authority.revision,
        authority_id=authority.authority_id,
        status=authority.precedent.status,
        source=authority.precedent.source,
        evidence_class=authority.precedent.evidence_class,
        violation_type=authority.precedent.violation_type,
        decision_direction=authority.precedent.decision_direction,
        rule_version=authority.precedent.rule_version,
        source_case_id=authority.precedent.source_case_id,
        citation_count=authority.precedent.citation_count,
        text_embedding_id=candidate_vector.embedding_id,
        visual_embedding_ids=(),
        visual_embedding_ids_sha256=_json_sha256([]),
        created_at=authority_dump["created_at"],
        activation_not_before=authority_dump["activation_not_before"],
        activated_at=authority_dump["activated_at"],
        manifest_id=manifest.manifest_id,
        document_sha256=_raw_sha256(authority_document),
        document_bytes=len(authority_document.encode("utf-8")),
    )
    observations = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                    kind=M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
                    artifact_id=exposure.exposure_id,
                    usage=M6UpgradeArtifactUsage.PRODUCED,
                ),
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                    kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
                    artifact_id=query_vector.embedding_id,
                    usage=M6UpgradeArtifactUsage.PRODUCED,
                ),
                M6UpgradeObservedArtifactIdentity(
                    source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                    kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
                    artifact_id=candidate_vector.embedding_id,
                    usage=M6UpgradeArtifactUsage.CONSUMED,
                ),
            ),
            key=lambda value: value.sort_key,
        )
    )
    upstream = _Upstream(
        plan_identity_sha256=sha256_hex(["m6-m5-body-upstream", 1]),
        run_id=selected_case.run_id,
        case_id=selected_case.case_id,
        manifest_id=manifest.manifest_id,
    )
    plan = M6SQLiteM5PrecedentDocumentsPlan(
        run_id=selected_case.run_id,
        case_id=selected_case.case_id,
        manifest_id=manifest.manifest_id,
        upstream_m4_plan_identity_sha256=upstream.plan_identity_sha256,
        upstream_retrieval_keys=(
            M6SQLiteM5PrecedentRetrievalKey(
                hearing_id=receipt.hearing_session_id,
                cycle_scope_id=receipt.cycle_scope_id,
                retrieval_receipt_id=receipt.receipt_id,
            ),
        ),
        observed_artifacts=observations,
        hearings=(hearing,),
        cycles=(cycle,),
        retrievals=(retrieval,),
        exposures=(exposure_slot,),
        derived_query_embeddings=(derived,),
        durable_embeddings=(durable,),
        precedent_revisions=(revision,),
    )
    return (
        plan,
        upstream,
        selected_case,
        config,
        manifest,
        authority,
        {
            "receipt": receipt_document,
            "exposure": exposure_document,
            "embedding": candidate_document,
            "authority": authority_document,
        },
    )


def _seed(
    database: Path, documents: dict[str, str], plan: M6SQLiteM5PrecedentDocumentsPlan
) -> None:
    retrieval = plan.retrievals[0]
    exposure = plan.exposures[0]
    embedding = plan.durable_embeddings[0]
    authority = plan.precedent_revisions[0]
    MigrationRunner(database, 5_000).apply_all()
    connection = _open_connection(database, 5_000, allow_create=False)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.executescript(
            """
            DROP TABLE m4_precedent_retrieval_receipts;
            DROP TABLE m5_precedent_exposures;
            DROP TABLE precedent_embeddings;
            DROP TABLE precedents;
            CREATE TABLE m4_precedent_retrieval_receipts(
                run_id TEXT NOT NULL,
                retrieval_receipt_id TEXT NOT NULL,
                receipt_json TEXT NOT NULL
            );
            CREATE TABLE m5_precedent_exposures(
                run_id TEXT NOT NULL,
                exposure_id TEXT NOT NULL,
                exposure_json TEXT NOT NULL
            );
            CREATE TABLE precedent_embeddings(
                run_id TEXT NOT NULL,
                embedding_id TEXT NOT NULL,
                embedding_json TEXT NOT NULL
            );
            CREATE TABLE precedents(
                run_id TEXT NOT NULL,
                precedent_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                authority_id TEXT NOT NULL,
                authority_json TEXT NOT NULL
            );
            """
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT INTO m4_precedent_retrieval_receipts VALUES (?, ?, ?)",
            (retrieval.run_id, retrieval.retrieval_receipt_id, documents["receipt"]),
        )
        connection.execute(
            "INSERT INTO m5_precedent_exposures VALUES (?, ?, ?)",
            (exposure.run_id, exposure.exposure_id, documents["exposure"]),
        )
        connection.execute(
            "INSERT INTO precedent_embeddings VALUES (?, ?, ?)",
            (embedding.run_id, embedding.embedding_id, documents["embedding"]),
        )
        connection.execute(
            "INSERT INTO precedents VALUES (?, ?, ?, ?, ?)",
            (
                authority.run_id,
                authority.precedent_id,
                authority.revision,
                authority.authority_id,
                documents["authority"],
            ),
        )
        connection.commit()
    finally:
        connection.close()


@pytest.fixture
def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Prepared]:
    plan, upstream, selected_case, config, manifest, authority, documents = _plan_and_documents()
    database = tmp_path / "labcourt.sqlite3"
    _seed(database, documents, plan)
    monkeypatch.setattr(bodies, "_m4_plan_is_consistent", lambda _value: True)
    monkeypatch.setattr(
        bodies,
        "_fresh_plan",
        lambda _connection, selected, **_kwargs: selected,
    )
    with m6_live_committed_read_cut(database, 5_000) as cut:
        with cut.selector() as selector:
            assert selector.execute("SELECT 1 AS ready").fetchone()["ready"] == 1
        with cut.reader() as reader:
            yield _Prepared(
                reader=reader,
                plan=plan,
                upstream=upstream,
                selected_case=selected_case,
                config=config,
                manifest=manifest,
                authority=authority,
            )
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS ready").fetchone()["ready"] == 1


def _resolve(prepared: _Prepared) -> bodies.M6SQLiteM5PrecedentAuthoritySnapshot:
    return resolve_m6_sqlite_m5_precedent_documents(
        connection=prepared.reader,
        metadata_plan=prepared.plan,
        selected_case=prepared.selected_case,
        config=prepared.config,
        manifest=prepared.manifest,
        upstream_m4_model_plan=prepared.upstream,
    )


class _RowsCursor:
    def __init__(self, rows: tuple[object, ...]) -> None:
        self._rows = rows

    def fetchmany(self, _size: int) -> tuple[object, ...]:
        return self._rows

    def close(self) -> None:
        return None


def test_recovers_exact_physical_closure_without_promoting_support_bodies(
    prepared: _Prepared,
) -> None:
    snapshot = _resolve(prepared)

    assert snapshot.source_identity_sha256 == prepared.plan.plan_identity_sha256
    assert snapshot.planned_artifact_refs == prepared.plan.planned_artifact_refs
    assert snapshot.observed_artifacts == prepared.plan.observed_artifacts
    assert snapshot.historical_precedent_authorities == (prepared.authority,)
    assert len(snapshot.exposures) == len(snapshot.retrieval_receipts) == 1
    assert {value.scope for value in snapshot.resolved_embeddings} == {
        M6LockedEmbeddingScope.QUERY,
        M6LockedEmbeddingScope.PRECEDENT,
    }
    physical_ids = {value.artifact_id for value in snapshot.planned_artifact_refs}
    assert snapshot.retrieval_receipts[0].receipt_id not in physical_ids
    assert prepared.authority.authority_id not in physical_ids
    assert len(physical_ids) == 3


@pytest.mark.parametrize(
    ("table", "column"),
    (
        ("m4_precedent_retrieval_receipts", "receipt_json"),
        ("m5_precedent_exposures", "exposure_json"),
        ("precedent_embeddings", "embedding_json"),
        ("precedents", "authority_json"),
    ),
)
def test_tampered_canonical_body_fails_closed(
    prepared: _Prepared,
    monkeypatch: pytest.MonkeyPatch,
    table: str,
    column: str,
) -> None:
    original_execute = M6LiveReader.execute

    def execute_spy(
        self: M6LiveReader,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        if f"FROM {table}" in statement:
            cursor = original_execute(self, statement, parameters)
            try:
                rows = tuple(cursor.fetchmany(2))
            finally:
                cursor.close()
            assert len(rows) == 1
            row = dict(rows[0])
            row[column] = f"{row[column]} "
            return _RowsCursor((row,))  # type: ignore[return-value]
        return original_execute(self, statement, parameters)

    monkeypatch.setattr(M6LiveReader, "execute", execute_spy)
    with pytest.raises(M6SQLiteM5PrecedentDocumentError) as raised:
        _resolve(prepared)

    assert raised.value.reason_code == M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_INVALID


def test_plan_drift_rejects_before_first_body_read(
    prepared: _Prepared,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body_reads: list[str] = []
    original_execute = M6LiveReader.execute

    def execute_spy(
        self: M6LiveReader,
        statement: str,
        parameters: tuple[object, ...] | dict[str, object] = (),
    ) -> M6LiveCursor:
        if any(
            token in statement
            for token in ("receipt_json", "exposure_json", "embedding_json", "authority_json")
        ):
            body_reads.append(statement)
        return original_execute(self, statement, parameters)

    def reject_drift(*_args: object, **_kwargs: object) -> object:
        bodies._fail(M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH)

    monkeypatch.setattr(M6LiveReader, "execute", execute_spy)
    monkeypatch.setattr(bodies, "_fresh_plan", reject_drift)
    with pytest.raises(M6SQLiteM5PrecedentDocumentError) as raised:
        _resolve(prepared)

    assert raised.value.reason_code == M6SQLiteM5PrecedentPlanFailureCode.CLOSURE_MISMATCH
    assert body_reads == []


def test_recovery_never_invokes_an_embedding_provider(
    prepared: _Prepared,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("body recovery must not invoke an embedding provider")

    monkeypatch.setattr(DeterministicFakePrecedentEmbeddingProvider, "embed", forbidden)

    snapshot = _resolve(prepared)

    assert len(snapshot.resolved_embeddings) == 2
