from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage.sqlite_hearing_repository import SQLiteHearingRepository
from labcourt.adapters.storage.sqlite_m5_precedent_usage import (
    SQLiteM5PrecedentExposureCommitter,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_session import (
    PreparedHearingSession,
    prepare_hearing_session,
)
from labcourt.application.hearing_situation import build_hearing_situation_text
from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
    M5HearingPrecedentRetriever,
)
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.application.m5_precedents import revoke_m5_precedent
from labcourt.config_loader import load_config
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import ViolationType
from labcourt.contracts.hearing_retrieval import HearingPrecedentRetrievalOutcome
from labcourt.contracts.hearing_state import HearingPrecedentRetrievalStatus
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.evidence_repository import EvidenceRepository
from tests.integration.test_m3_sqlite_repository import BUSY_TIMEOUT_MS, RUN_ID, _clock
from tests.integration.test_m4_hearing_coordinator import _escalated_case
from tests.integration.test_m5_sqlite_precedents import _authority
from tests.unit.test_m4_hearing_prompt_renderer import _hearing_schema_documents

ROOT = Path(__file__).parents[2]


@dataclass(frozen=True)
class _ExposureRuntime:
    database: Path
    config: AppConfig
    manifest: RunManifest
    evidence: EvidenceRepository
    prepared: PreparedHearingSession
    m5: SQLiteM5Repository
    retrieval: HearingPrecedentRetrievalService
    committer: SQLiteM5PrecedentExposureCommitter


def _runtime(
    tmp_path: Path,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> _ExposureRuntime:
    database, evidence, _pack, escalated = _escalated_case(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = evidence.load_run_manifest(RUN_ID)
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    prepared = prepare_hearing_session(
        escalated,
        config=config,
        run_manifest=manifest,
        catalog=catalog,
    )
    evidence.begin_hearing_case(
        RUN_ID,
        escalated.revision,
        evidence.get_audit_head(RUN_ID),
        prepared.session,
        prepared.cycle_scope,
        prepared.checkpoint,
    )
    verifier = ConfiguredM5PrecedentPolicyVerifier(config)
    m5 = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        m5_precedent_policy_verifier=verifier,
        fault_injector=fault_injector,
    )
    embedding_provider = DeterministicFakePrecedentEmbeddingProvider()
    retrieval = HearingPrecedentRetrievalService(
        M5HearingPrecedentRetriever(
            repository=m5,
            manifest=manifest,
            policy=verifier.expected_policy(manifest),
            run_mode=verifier.run_mode,
            embedding_provider=embedding_provider,
        ),
        retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
        retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    )
    return _ExposureRuntime(
        database=database,
        config=config,
        manifest=manifest,
        evidence=evidence,
        prepared=prepared,
        m5=m5,
        retrieval=retrieval,
        committer=SQLiteM5PrecedentExposureCommitter(
            repository=m5,
            hearing_repository=SQLiteHearingRepository(evidence),
            embedding_provider=embedding_provider,
        ),
    )


def _proposed(runtime: _ExposureRuntime) -> HearingPrecedentRetrievalOutcome:
    prepared = runtime.prepared
    return runtime.retrieval.retrieve(
        session=prepared.session,
        cycle_scope=prepared.cycle_scope,
        evidence_pack=prepared.evidence_pack,
        run_manifest=runtime.manifest,
        config=runtime.config,
        situation_text=build_hearing_situation_text(prepared.evidence_pack),
    )


def _degraded(runtime: _ExposureRuntime) -> HearingPrecedentRetrievalOutcome:
    prepared = runtime.prepared
    service = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
        retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    )
    return service.retrieve(
        session=prepared.session,
        cycle_scope=prepared.cycle_scope,
        evidence_pack=prepared.evidence_pack,
        run_manifest=runtime.manifest,
        config=runtime.config,
        situation_text=build_hearing_situation_text(prepared.evidence_pack),
    )


def _counts(database: Path) -> tuple[int, int, int]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "m4_precedent_retrieval_receipts",
                "m5_precedent_exposures",
                "precedent_citations",
            )
        )  # type: ignore[return-value]


def test_new_corpus_id_before_exposure_rejects_old_outcome_with_double_zero_write(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    runtime.m5.append_authority(
        _authority(runtime.manifest, "precedent-before-a"),
        None,
    )
    stale = _proposed(runtime)
    runtime.m5.append_authority(
        _authority(runtime.manifest, "precedent-before-b"),
        None,
    )

    with pytest.raises(ConcurrentModification, match="corpus changed"):
        runtime.committer.commit(stale)

    assert _counts(runtime.database) == (0, 0, 0)
    refreshed = _proposed(runtime)
    canonical = runtime.committer.commit(refreshed)
    exposure = runtime.committer.load_exposure(
        RUN_ID,
        runtime.prepared.cycle_scope.cycle_id,
    )
    assert exposure is not None
    assert canonical == refreshed.receipt == exposure.m4_retrieval_outcome.receipt
    assert exposure.m5_retrieval_result.candidate_count == 2
    assert _counts(runtime.database) == (1, 1, 0)


def test_degraded_commit_is_receipt_only_and_exactly_replays_after_corpus_growth(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    degraded = _degraded(runtime)

    canonical = runtime.committer.commit(degraded)
    assert degraded.receipt.status == HearingPrecedentRetrievalStatus.DEGRADED
    assert canonical == degraded.receipt
    assert (
        runtime.committer.load_exposure(
            RUN_ID,
            runtime.prepared.cycle_scope.cycle_id,
        )
        is None
    )
    assert _counts(runtime.database) == (1, 0, 0)
    runtime.m5.append_authority(
        _authority(runtime.manifest, "precedent-after-degraded-receipt"),
        None,
    )
    verifier = ConfiguredM5PrecedentPolicyVerifier(runtime.config)
    fresh_repository = SQLiteM5Repository(
        runtime.database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        m5_precedent_policy_verifier=verifier,
    )
    fresh_committer = SQLiteM5PrecedentExposureCommitter(
        repository=fresh_repository,
        hearing_repository=SQLiteHearingRepository(runtime.evidence),
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
    )

    assert fresh_committer.commit(degraded) == canonical
    assert (
        fresh_committer.load_exposure(
            RUN_ID,
            runtime.prepared.cycle_scope.cycle_id,
        )
        is None
    )
    assert _counts(runtime.database) == (1, 0, 0)


def test_degraded_replay_cannot_replace_an_existing_success_exposure(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    successful = _proposed(runtime)
    runtime.committer.commit(successful)

    with pytest.raises(ContractViolation, match="already has an exposure"):
        runtime.committer.commit(_degraded(runtime))

    assert (
        runtime.committer.load_exposure(
            RUN_ID,
            runtime.prepared.cycle_scope.cycle_id,
        )
        is not None
    )
    assert _counts(runtime.database) == (1, 1, 0)


@pytest.mark.parametrize(
    "fault_phase",
    (
        "m5.precedent_exposure.before_m4_receipt",
        "m5.precedent_exposure.after_m4_receipt",
    ),
)
def test_degraded_commit_fault_rolls_back_receipt_without_m5_usage_rows(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    def inject(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected degraded commit fault")

    runtime = _runtime(tmp_path, fault_injector=inject)

    with pytest.raises(RuntimeError, match="injected degraded commit fault"):
        runtime.committer.commit(_degraded(runtime))

    assert _counts(runtime.database) == (0, 0, 0)


def test_head_revocation_before_exposure_rejects_old_outcome_with_double_zero_write(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    original = _authority(runtime.manifest, "precedent-revoked-before-exposure")
    runtime.m5.append_authority(original, None)
    stale = _proposed(runtime)
    snapshot = runtime.m5.citation_snapshot(
        RUN_ID,
        original.precedent.precedent_id,
    )
    runtime.m5.commit_revocation(
        revoke_m5_precedent(
            authority=original,
            citation_snapshot=snapshot,
            revoked_by_ref="appeal-revocation-before-exposure",
            revoked_at=_clock(),
        )
    )

    with pytest.raises(ConcurrentModification, match="corpus changed"):
        runtime.committer.commit(stale)

    assert _counts(runtime.database) == (0, 0, 0)


def test_durable_exposure_replay_returns_old_receipt_after_growth_and_head_revocation(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    original = _authority(runtime.manifest, "precedent-durable-active")
    other_violation = _authority(
        runtime.manifest,
        "precedent-durable-other",
        violation_type=ViolationType.OPEN_FLAME,
    )
    runtime.m5.append_authorities(RUN_ID, (original, other_violation))
    first = _proposed(runtime)
    canonical = runtime.committer.commit(first)
    durable = runtime.committer.load_exposure(
        RUN_ID,
        runtime.prepared.cycle_scope.cycle_id,
    )
    assert durable is not None

    runtime.m5.append_authority(
        _authority(runtime.manifest, "precedent-added-after-exposure"),
        None,
    )
    snapshot = runtime.m5.citation_snapshot(
        RUN_ID,
        original.precedent.precedent_id,
    )
    runtime.m5.commit_revocation(
        revoke_m5_precedent(
            authority=original,
            citation_snapshot=snapshot,
            revoked_by_ref="appeal-revocation-after-exposure",
            revoked_at=_clock(),
        )
    )
    changed = _proposed(runtime)
    assert changed.receipt != canonical

    replayed = runtime.committer.commit(changed)
    reloaded = runtime.committer.load_exposure(
        RUN_ID,
        runtime.prepared.cycle_scope.cycle_id,
    )
    assert replayed == canonical
    assert reloaded == durable
    assert reloaded.m5_retrieval_result.candidate_count == 2
    assert _counts(runtime.database) == (1, 1, 0)


@pytest.mark.parametrize(
    "fault_phase",
    (
        "m5.precedent_exposure.after_m4_receipt",
        "m5.precedent_exposure.after_exposure",
    ),
)
def test_exposure_fault_rolls_back_m4_and_m5_rows(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    def inject(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected exposure fault")

    runtime = _runtime(tmp_path, fault_injector=inject)
    runtime.m5.append_authority(
        _authority(runtime.manifest, "precedent-fault-atomic"),
        None,
    )
    proposed = _proposed(runtime)

    with pytest.raises(RuntimeError, match="injected exposure fault"):
        runtime.committer.commit(proposed)

    assert _counts(runtime.database) == (0, 0, 0)


def test_exposure_document_hash_and_index_tampering_fail_closed(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    runtime.m5.append_authority(
        _authority(runtime.manifest, "precedent-exposure-tamper"),
        None,
    )
    runtime.committer.commit(_proposed(runtime))
    cycle_id = runtime.prepared.cycle_scope.cycle_id
    with sqlite3.connect(runtime.database) as connection:
        connection.execute("DROP TRIGGER m5_precedent_exposures_no_update")
        connection.execute(
            """
            UPDATE m5_precedent_exposures
            SET document_sha256 = ?
            WHERE run_id = ? AND cycle_scope_id = ?
            """,
            (hashlib.sha256(b"tampered").hexdigest(), RUN_ID, cycle_id),
        )
        connection.execute(
            """
            CREATE TRIGGER m5_precedent_exposures_no_update
            BEFORE UPDATE ON m5_precedent_exposures
            BEGIN
                SELECT RAISE(ABORT, 'm5_precedent_exposures is append-only');
            END
            """
        )
        connection.commit()

    with pytest.raises(RepositoryIntegrityError, match="indexes conflict"):
        runtime.committer.load_exposure(RUN_ID, cycle_id)
