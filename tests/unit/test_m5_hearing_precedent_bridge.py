from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage.sqlite_m5_precedent_usage import (
    SQLiteM5PrecedentExposureCommitter,
)
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.m5_embedding_integrity import build_m5_controlled_fake_embedding
from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
    M5HearingPrecedentBridgeError,
    M5HearingPrecedentBridgeErrorCode,
    M5HearingPrecedentRetriever,
    derive_m5_query_for_hearing,
)
from labcourt.application.m5_precedents import (
    create_m5_precedent_authority,
    m5_precedent_policy_from_config,
)
from labcourt.contracts.enums import (
    PrecedentSource,
    PrecedentStatus,
    RunMode,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.hearing_state import HearingPrecedentRetrievalStatus
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5PrecedentAuthority,
    M5PrecedentRetrievalQuery,
)

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 8, 3, 10, tzinfo=UTC)
SITUATION_TEXT = "A reagent container remained open during controlled laboratory work."


def _load_hearing_helpers() -> ModuleType:
    module_name = "_labcourt_test_m5_hearing_bridge_helpers"
    specification = importlib.util.spec_from_file_location(
        module_name,
        ROOT / "tests" / "unit" / "test_m4_hearing_request.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[module_name] = module
    specification.loader.exec_module(module)
    return module


hearing_helpers = _load_hearing_helpers()


class _Candidates:
    def __init__(self, authorities: tuple[M5PrecedentAuthority, ...]) -> None:
        self.authorities = authorities
        self.queries: list[M5PrecedentRetrievalQuery] = []

    def list_for_retrieval(
        self,
        query: M5PrecedentRetrievalQuery,
    ) -> tuple[M5PrecedentAuthority, ...]:
        self.queries.append(query)
        return self.authorities


def _authority(
    scenario,  # type: ignore[no-untyped-def]
    precedent_id: str,
    *,
    source: PrecedentSource = PrecedentSource.PRESET,
    violation_type: ViolationType = ViolationType.REAGENT_CONTAINER_OPEN,
) -> M5PrecedentAuthority:
    situation = f"Controlled authority {precedent_id}."
    embedding = build_m5_controlled_fake_embedding(
        channel=M5EmbeddingChannel.TEXT,
        situation_text=situation,
        model_manifest=scenario.manifest.models["text_embedding"],
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
    )
    return create_m5_precedent_authority(
        run_id=scenario.pack.run_id,
        precedent_id=precedent_id,
        situation_text=situation,
        decision_direction=VerdictDecision.ESTABLISHED,
        source=source,
        evidence_class=scenario.pack.event.evidence_class,
        violation_type=violation_type,
        rule_version=scenario.manifest.rule_version,
        source_case_id=(scenario.pack.case_id if source == PrecedentSource.AUTOMATIC else None),
        created_at=NOW,
        policy=m5_precedent_policy_from_config(scenario.config),
        text_embedding=embedding,
    )


def _service(scenario, repository: _Candidates, *, policy=None):  # type: ignore[no-untyped-def]
    return HearingPrecedentRetrievalService(
        M5HearingPrecedentRetriever(
            repository=repository,
            manifest=scenario.manifest,
            policy=policy or m5_precedent_policy_from_config(scenario.config),
            run_mode=RunMode.STANDARD,
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        ),
        retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
        retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    )


def _retrieve(scenario, service):  # type: ignore[no-untyped-def]
    return service.retrieve(
        session=scenario.session,
        cycle_scope=scenario.scope,
        evidence_pack=scenario.pack,
        run_manifest=scenario.manifest,
        config=scenario.config,
        situation_text=SITUATION_TEXT,
    )


def test_bridge_projects_complete_inventory_then_filters_violation_and_provisional() -> None:
    scenario = hearing_helpers._scenario()
    candidates = _Candidates(
        (
            _authority(scenario, "precedent-z-active"),
            _authority(
                scenario,
                "precedent-a-other-violation",
                violation_type=ViolationType.OPEN_FLAME,
            ),
            _authority(
                scenario,
                "precedent-m-provisional",
                source=PrecedentSource.AUTOMATIC,
            ),
        )
    )
    service = _service(scenario, candidates)

    first = _retrieve(scenario, service)
    second = _retrieve(scenario, service)

    assert first == second
    assert first.receipt.status == HearingPrecedentRetrievalStatus.SUCCESS
    assert first.result is not None
    assert tuple(item.precedent_id for item in first.result.candidate_precedents) == (
        "precedent-a-other-violation",
        "precedent-m-provisional",
        "precedent-z-active",
    )
    assert tuple(item.precedent_id for item in first.result.visible_precedents) == (
        "precedent-z-active",
    )
    assert tuple(item.precedent.precedent_id for item in first.result.scored_precedents) == (
        "precedent-z-active",
    )
    assert all(query.run_mode == RunMode.STANDARD for query in candidates.queries)
    assert all(not query.include_provisional_experiment for query in candidates.queries)
    assert all(not query.visual_embeddings for query in candidates.queries)
    provisional_query = candidates.queries[0]
    assert provisional_query.text_embedding is not None
    assert all(
        authority.precedent.status == PrecedentStatus.PROVISIONAL
        for authority in candidates.authorities
        if authority.precedent.precedent_id == "precedent-m-provisional"
    )


def test_readonly_query_derivation_exactly_matches_the_provider_path() -> None:
    scenario = hearing_helpers._scenario()
    candidates = _Candidates(())
    outcome = _retrieve(scenario, _service(scenario, candidates))

    derived = derive_m5_query_for_hearing(
        query=outcome.query,
        manifest=scenario.manifest,
        policy=m5_precedent_policy_from_config(scenario.config),
        run_mode=RunMode.STANDARD,
    )

    assert candidates.queries == [derived]


def test_committer_boundary_accepts_controlled_degraded_while_real_bridge_stays_success() -> None:
    scenario = hearing_helpers._scenario()
    degraded_service = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
        retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    )
    degraded = _retrieve(scenario, degraded_service)
    successful = _retrieve(scenario, _service(scenario, _Candidates(())))

    assert degraded.receipt.status == HearingPrecedentRetrievalStatus.DEGRADED
    assert degraded.result is None
    assert SQLiteM5PrecedentExposureCommitter._validated_outcome(degraded) == degraded
    assert successful.receipt.status == HearingPrecedentRetrievalStatus.SUCCESS
    assert successful.result is not None


def test_bridge_rejects_policy_that_can_exceed_frozen_m4_score_without_clamping() -> None:
    scenario = hearing_helpers._scenario()
    policy = m5_precedent_policy_from_config(scenario.config)
    source_weights = dict(policy.source_weights)
    source_weights[PrecedentSource.PRESET] = 1.26
    incompatible = policy.model_copy(update={"source_weights": source_weights})
    service = _service(
        scenario,
        _Candidates((_authority(scenario, "precedent-score-bound"),)),
        policy=incompatible,
    )

    with pytest.raises(M5HearingPrecedentBridgeError) as raised:
        _retrieve(scenario, service)

    assert raised.value.code == M5HearingPrecedentBridgeErrorCode.SCORE_RANGE_INCOMPATIBLE
