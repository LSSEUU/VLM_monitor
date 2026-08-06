from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
from pydantic import ValidationError

from labcourt.adapters.fake_hearing_precedents import (
    FakeHearingPrecedentFixture,
    FakeHearingPrecedentRetriever,
)
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
    HearingPrecedentRetrievalServiceError,
    HearingPrecedentRetrievalServiceErrorCode,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.hearing_retrieval import (
    HearingPrecedentRetrievalQuery,
    derive_hearing_candidate_snapshot_sha256,
    derive_hearing_evidence_pack_document_sha256,
)
from labcourt.contracts.hearing_state import (
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.precedents import Precedent, ScoredPrecedent
from labcourt.ports.hearing_precedents import HearingPrecedentRetrievalUnavailable

ROOT = Path(__file__).parents[2]
RETRIEVER_VERSION = "fake-hearing-precedent-v1"
RETRIEVER_MANIFEST_ID = sha256_hex(["m4-fake-hearing-precedent-manifest", 1])
SITUATION_TEXT = "A reagent container remained open during controlled laboratory work."


def _load_hearing_helpers() -> ModuleType:
    module_name = "_labcourt_test_m4_hearing_retrieval_helpers"
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


@pytest.fixture
def scenario():
    return hearing_helpers._scenario()


def _service(
    retriever: FakeHearingPrecedentRetriever | None = None,
) -> HearingPrecedentRetrievalService:
    return HearingPrecedentRetrievalService(
        retriever or FakeHearingPrecedentRetriever(()),
        retriever_version=RETRIEVER_VERSION,
        retriever_manifest_id=RETRIEVER_MANIFEST_ID,
    )


def _query(scenario) -> HearingPrecedentRetrievalQuery:
    return _service().prepare_query(
        session=scenario.session,
        cycle_scope=scenario.scope,
        evidence_pack=scenario.pack,
        run_manifest=scenario.manifest,
        config=scenario.config,
        situation_text=SITUATION_TEXT,
    )


def _precedent(
    query: HearingPrecedentRetrievalQuery,
    precedent_id: str,
    *,
    situation_text: str | None = None,
    status: PrecedentStatus = PrecedentStatus.ACTIVE,
    evidence_class: EvidenceClass | None = None,
    violation_type: ViolationType | None = None,
    rule_version: str | None = None,
) -> Precedent:
    return Precedent(
        precedent_id=precedent_id,
        situation_text=situation_text or f"Controlled precedent {precedent_id}.",
        text_embedding_ref=f"embedding-{precedent_id}",
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.PRESET,
        status=status,
        evidence_class=evidence_class or query.evidence_class,
        violation_type=violation_type or query.violation_type,
        rule_version=rule_version or query.rule_version,
        source_case_id=f"case-{precedent_id}",
    )


def _scored(precedent: Precedent, score: float) -> ScoredPrecedent:
    return ScoredPrecedent(
        precedent=precedent,
        text_similarity=float(min(score, 1.0)),
        fused_score=float(score),
    )


def test_success_filters_before_stable_ranking_and_truncation(scenario) -> None:
    query = _query(scenario)
    eligible = {
        identifier: _precedent(query, identifier)
        for identifier in (
            "precedent-a",
            "precedent-b",
            "precedent-c",
            "precedent-d",
            "precedent-e",
        )
    }
    inactive = _precedent(
        query,
        "precedent-inactive",
        status=PrecedentStatus.INVALIDATED,
    )
    wrong_rule = _precedent(query, "precedent-old-rule", rule_version="laboratory-v0")
    wrong_violation = _precedent(
        query,
        "precedent-other-violation",
        violation_type=ViolationType.OPEN_FLAME,
    )
    fixture = FakeHearingPrecedentFixture(
        query=query,
        candidate_precedents=(
            wrong_violation,
            eligible["precedent-e"],
            inactive,
            eligible["precedent-c"],
            eligible["precedent-a"],
            wrong_rule,
            eligible["precedent-d"],
            eligible["precedent-b"],
        ),
        scored_precedents=(
            _scored(eligible["precedent-d"], 0.60),
            _scored(eligible["precedent-a"], 0.80),
            _scored(eligible["precedent-c"], 0.95),
            _scored(eligible["precedent-e"], 0.70),
            _scored(eligible["precedent-b"], 0.95),
        ),
    )
    service = _service(FakeHearingPrecedentRetriever((fixture,)))

    outcome = service.retrieve(
        session=scenario.session,
        cycle_scope=scenario.scope,
        evidence_pack=scenario.pack,
        run_manifest=scenario.manifest,
        config=scenario.config,
        situation_text=SITUATION_TEXT,
    )

    assert outcome.receipt.status == HearingPrecedentRetrievalStatus.SUCCESS
    assert outcome.result is not None
    assert tuple(item.precedent.precedent_id for item in outcome.result.scored_precedents) == (
        "precedent-b",
        "precedent-c",
        "precedent-a",
        "precedent-e",
    )
    assert tuple(item.precedent_id for item in outcome.result.visible_precedents) == (
        "precedent-a",
        "precedent-b",
        "precedent-c",
        "precedent-e",
    )
    assert tuple(ref.artifact_id for ref in outcome.receipt.visible_precedent_refs) == tuple(
        item.precedent_id for item in outcome.result.visible_precedents
    )
    assert set(ref.artifact_id for ref in outcome.receipt.visible_precedent_refs) == set(
        item.precedent.precedent_id for item in outcome.receipt.scored_precedents
    )
    assert outcome.receipt.embedding_model_manifest_id == (
        scenario.manifest.models["text_embedding"].model_manifest_id
    )
    assert tuple(item.precedent_id for item in outcome.result.candidate_precedents) == tuple(
        sorted(item.precedent_id for item in fixture.candidate_precedents)
    )


def test_query_receipt_and_result_have_stable_canonical_bytes(scenario) -> None:
    query = _query(scenario)
    precedent = _precedent(query, "precedent-stable")
    fixture = FakeHearingPrecedentFixture(
        query=query,
        candidate_precedents=(precedent,),
        scored_precedents=(_scored(precedent, 0.75),),
    )
    service = _service(FakeHearingPrecedentRetriever((fixture,)))
    arguments = {
        "session": scenario.session,
        "cycle_scope": scenario.scope,
        "evidence_pack": scenario.pack,
        "run_manifest": scenario.manifest,
        "config": scenario.config,
        "situation_text": SITUATION_TEXT,
    }

    first = service.retrieve(**arguments)
    second = service.retrieve(**arguments)

    assert first == second
    query_json = canonical_json(first.query.model_dump(mode="json"))
    receipt_json = canonical_json(first.receipt.model_dump(mode="json"))
    assert HearingPrecedentRetrievalQuery.model_validate_json(query_json) == first.query
    assert HearingPrecedentRetrievalReceipt.model_validate_json(receipt_json) == first.receipt
    assert canonical_json(second.query.model_dump(mode="json")) == query_json
    assert canonical_json(second.receipt.model_dump(mode="json")) == receipt_json


def test_candidate_snapshot_hashes_full_documents_not_only_ids(scenario) -> None:
    query = _query(scenario)
    first = _precedent(
        query,
        "precedent-same-id",
        situation_text="First immutable precedent document.",
    )
    changed = first.model_copy(update={"situation_text": "Second immutable precedent document."})

    assert first.precedent_id == changed.precedent_id
    assert derive_hearing_candidate_snapshot_sha256((first,)) != (
        derive_hearing_candidate_snapshot_sha256((changed,))
    )


def test_query_binds_complete_pack_document_session_cycle_manifest_and_config(scenario) -> None:
    query = _query(scenario)
    same_semantics_new_version = scenario.pack.model_copy(update={"version": 2})

    assert same_semantics_new_version.pack_id == scenario.pack.pack_id
    assert derive_hearing_evidence_pack_document_sha256(same_semantics_new_version) != (
        query.current_evidence_pack_sha256
    )
    assert query.hearing_session_id == scenario.session.session_id
    assert query.hearing_session_sha256 == scenario.session.session_sha256
    assert query.cycle_scope_id == scenario.scope.cycle_id
    assert query.cycle_scope_sha256 == scenario.scope.cycle_sha256
    assert query.current_evidence_pack_id == scenario.pack.pack_id
    assert query.current_evidence_pack_version == scenario.pack.version
    assert query.config_sha256 == scenario.config.config_sha256
    assert query.top_k == scenario.config.hearing.precedent_top_k
    assert query.manifest_id == scenario.manifest.manifest_id


def test_cross_cycle_pack_manifest_and_top_k_queries_cannot_reuse_fixture(scenario) -> None:
    query = _query(scenario)
    fixture = FakeHearingPrecedentFixture(query=query)
    retriever = FakeHearingPrecedentRetriever((fixture,))
    changed_queries = (
        query.model_copy(
            update={
                "cycle_scope_id": sha256_hex(["other-cycle-id"]),
                "cycle_scope_sha256": sha256_hex(["other-cycle-document"]),
            }
        ),
        query.model_copy(
            update={
                "current_evidence_pack_version": query.current_evidence_pack_version + 1,
                "current_evidence_pack_sha256": sha256_hex(["other-pack-document"]),
            }
        ),
        query.model_copy(update={"manifest_id": sha256_hex(["other-manifest"])}),
        query.model_copy(update={"top_k": query.top_k - 1}),
    )

    assert len({query.query_id, *(item.query_id for item in changed_queries)}) == 5
    for changed_query in changed_queries:
        with pytest.raises(HearingPrecedentRetrievalUnavailable) as raised:
            retriever.retrieve(changed_query)
        assert raised.value.reason == (HearingPrecedentDegradedReason.PRECEDENT_INDEX_UNAVAILABLE)


@pytest.mark.parametrize("reason", tuple(HearingPrecedentDegradedReason))
def test_unavailability_is_explicit_empty_degraded_receipt(scenario, reason) -> None:
    query = _query(scenario)
    fixture = FakeHearingPrecedentFixture(
        query=query,
        unavailable_reason=reason,
    )
    service = _service(FakeHearingPrecedentRetriever((fixture,)))

    outcome = service.retrieve(
        session=scenario.session,
        cycle_scope=scenario.scope,
        evidence_pack=scenario.pack,
        run_manifest=scenario.manifest,
        config=scenario.config,
        situation_text=SITUATION_TEXT,
    )

    assert outcome.result is None
    assert outcome.receipt.status == HearingPrecedentRetrievalStatus.DEGRADED
    assert outcome.receipt.degraded_reason == reason
    assert outcome.receipt.candidate_precedent_refs == ()
    assert outcome.receipt.visible_precedent_refs == ()
    assert outcome.receipt.scored_precedents == ()
    assert outcome.receipt.embedding_model_manifest_id == (
        scenario.manifest.models["text_embedding"].model_manifest_id
    )


def test_unknown_query_degrades_as_index_unavailable_without_partial_context(scenario) -> None:
    service = _service()

    outcome = service.retrieve(
        session=scenario.session,
        cycle_scope=scenario.scope,
        evidence_pack=scenario.pack,
        run_manifest=scenario.manifest,
        config=scenario.config,
        situation_text=SITUATION_TEXT,
    )

    assert outcome.receipt.degraded_reason == (
        HearingPrecedentDegradedReason.PRECEDENT_INDEX_UNAVAILABLE
    )
    assert outcome.result is None
    assert outcome.receipt.scored_precedents == ()


def test_fake_fixture_rejects_duplicate_candidate_and_score_ids(scenario) -> None:
    query = _query(scenario)
    precedent = _precedent(query, "precedent-duplicate")
    scored = _scored(precedent, 0.8)

    with pytest.raises(ValidationError, match="duplicate precedent ID"):
        FakeHearingPrecedentFixture(
            query=query,
            candidate_precedents=(precedent, precedent),
            scored_precedents=(scored,),
        )
    with pytest.raises(ValidationError, match="duplicate precedent ID"):
        FakeHearingPrecedentFixture(
            query=query,
            candidate_precedents=(precedent,),
            scored_precedents=(scored, scored),
        )


def test_fake_fixture_rejects_out_of_range_missing_and_unfiltered_scores(scenario) -> None:
    query = _query(scenario)
    first = _precedent(query, "precedent-first")
    second = _precedent(query, "precedent-second")
    inactive = _precedent(
        query,
        "precedent-inactive-score",
        status=PrecedentStatus.REVOKED,
    )
    wrong_scope = _precedent(
        query,
        "precedent-wrong-scope",
        evidence_class=(
            EvidenceClass.ABSENCE
            if query.evidence_class == EvidenceClass.PRESENCE
            else EvidenceClass.PRESENCE
        ),
    )

    with pytest.raises(ValidationError, match="bounded fused score"):
        FakeHearingPrecedentFixture(
            query=query,
            candidate_precedents=(first,),
            scored_precedents=(_scored(first, 1.26),),
        )
    bypassed_score = ScoredPrecedent.model_construct(
        precedent=first,
        text_similarity=2.0,
        visual_similarity=None,
        fused_score=0.9,
    )
    with pytest.raises(ValidationError, match="strict score bounds"):
        FakeHearingPrecedentFixture(
            query=query,
            candidate_precedents=(first,),
            scored_precedents=(bypassed_score,),
        )
    with pytest.raises(ValidationError, match="score every and only"):
        FakeHearingPrecedentFixture(
            query=query,
            candidate_precedents=(first, second),
            scored_precedents=(_scored(first, 0.8),),
        )
    for unfiltered in (inactive, wrong_scope):
        with pytest.raises(ValidationError, match="bypasses the exact active-scope filter"):
            FakeHearingPrecedentFixture(
                query=query,
                candidate_precedents=(unfiltered,),
                scored_precedents=(_scored(unfiltered, 0.99),),
            )


def test_unavailable_fixture_rejects_partial_success_payload(scenario) -> None:
    query = _query(scenario)
    precedent = _precedent(query, "precedent-partial")

    with pytest.raises(ValidationError, match="cannot expose partial candidates"):
        FakeHearingPrecedentFixture(
            query=query,
            candidate_precedents=(precedent,),
            unavailable_reason=(HearingPrecedentDegradedReason.EMBEDDING_PROVIDER_UNAVAILABLE),
        )


def test_success_query_requires_text_embedding_manifest(scenario) -> None:
    query = _query(scenario)

    with pytest.raises(ValidationError, match="requires the text_embedding manifest"):
        query.model_copy(
            update={"embedding_model_manifest": scenario.manifest.models["visual_embedding"]}
        )


def test_success_receipt_rejects_visible_and_scored_set_divergence(scenario) -> None:
    query = _query(scenario)
    precedent = _precedent(query, "precedent-consistency")
    fixture = FakeHearingPrecedentFixture(
        query=query,
        candidate_precedents=(precedent,),
        scored_precedents=(_scored(precedent, 0.8),),
    )
    outcome = _service(FakeHearingPrecedentRetriever((fixture,))).retrieve(
        session=scenario.session,
        cycle_scope=scenario.scope,
        evidence_pack=scenario.pack,
        run_manifest=scenario.manifest,
        config=scenario.config,
        situation_text=SITUATION_TEXT,
    )

    with pytest.raises(ValidationError, match="exactly equal its visible set"):
        outcome.receipt.model_copy(update={"scored_precedents": ()})


def test_service_rejects_cross_pack_scope_and_unpinned_config(scenario) -> None:
    mismatched_scope = scenario.scope.model_copy(
        update={"cycle_evidence_pack_id": sha256_hex(["other-current-pack"])}
    )
    with pytest.raises(HearingPrecedentRetrievalServiceError) as cross_pack:
        _service().prepare_query(
            session=scenario.session,
            cycle_scope=mismatched_scope,
            evidence_pack=scenario.pack,
            run_manifest=scenario.manifest,
            config=scenario.config,
            situation_text=SITUATION_TEXT,
        )
    assert cross_pack.value.code == (HearingPrecedentRetrievalServiceErrorCode.AUTHORITY_MISMATCH)

    changed_hearing = scenario.config.hearing.model_copy(
        update={"precedent_top_k": scenario.config.hearing.precedent_top_k - 1}
    )
    changed_config = scenario.config.model_copy(update={"hearing": changed_hearing})
    with pytest.raises(HearingPrecedentRetrievalServiceError) as config_mismatch:
        _service().prepare_query(
            session=scenario.session,
            cycle_scope=scenario.scope,
            evidence_pack=scenario.pack,
            run_manifest=scenario.manifest,
            config=changed_config,
            situation_text=SITUATION_TEXT,
        )
    assert config_mismatch.value.code == (HearingPrecedentRetrievalServiceErrorCode.CONFIG_MISMATCH)
