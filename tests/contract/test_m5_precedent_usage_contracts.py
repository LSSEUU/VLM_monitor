from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TypeVar

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

import labcourt.contracts as public_contracts
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    EvidenceClass,
    PrecedentApplicationMode,
    PrecedentSource,
    PrecedentStatus,
    RunMode,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.hearing_retrieval import (
    HearingPrecedentRetrievalOutcome,
    HearingPrecedentRetrievalQuery,
    HearingPrecedentRetrievalResult,
    derive_hearing_evidence_pack_document_sha256,
)
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationBinding,
    M5PrecedentApplicationCitationCommit,
    M5PrecedentExposureBatchAuthority,
    M5PrecedentExposureItem,
    derive_ready_case_document_sha256,
)
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5EmbeddingRequest,
    M5EmbeddingVector,
    M5PrecedentAuthority,
    M5PrecedentCandidateDisposition,
    M5PrecedentCandidateEvaluation,
    M5PrecedentCitationAuthority,
    M5PrecedentCitationCommit,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    M5PrecedentRetrievalResult,
)
from labcourt.contracts.manifests import ModelManifest
from labcourt.contracts.precedents import Precedent, ScoredPrecedent
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import PrecedentApplication, Verdict
from labcourt.schema_export import expected_schema_files
from tests.contract.test_m3_contracts import (
    _parsed,
    _presence_pack,
    _review,
    _screening,
    _verdict,
)

CONFIG_SHA256 = "c" * 64
BRIDGE_MANIFEST_ID = "d" * 64
VISUAL_MODEL_MANIFEST_ID = "e" * 64
SESSION_ID = "1" * 64
SESSION_SHA256 = "2" * 64
CYCLE_ID = "3" * 64
CYCLE_SHA256 = "4" * 64
NOW = datetime(2026, 8, 3, 9, tzinfo=UTC)
SITUATION_TEXT = "An open reagent container remained in active laboratory work."

FOLLOW_ID = "precedent-z-follow"
DISTINGUISH_ID = "precedent-a-distinguish"
OTHER_VIOLATION_ID = "precedent-m-other-violation"

ModelT = TypeVar("ModelT", bound=BaseModel)


def _constructed_copy(model: ModelT, **updates: object) -> ModelT:
    values = {name: getattr(model, name) for name in type(model).model_fields}
    values.update(updates)
    return type(model).model_construct(**values)


def _text_manifest() -> ModelManifest:
    return ModelManifest(
        component="text_embedding",
        provider="fake",
        model="deterministic-text-embedding",
        revision="1.0.0",
        license_id="synthetic-fixture",
    )


def _embedding(input_ref: str, model_manifest_id: str) -> M5EmbeddingVector:
    return M5EmbeddingVector(
        request=M5EmbeddingRequest(
            channel=M5EmbeddingChannel.TEXT,
            input_ref=input_ref,
            input_sha256=sha256_hex(["precedent-usage-input", input_ref]),
            model_manifest_id=model_manifest_id,
            dimensions=2,
        ),
        values=(1.0, 0.25),
    )


def _policy(config_sha256: str = CONFIG_SHA256) -> M5PrecedentPolicy:
    return M5PrecedentPolicy(
        config_sha256=config_sha256,
        text_weight=0.8,
        visual_weight=0.2,
        source_weights={
            PrecedentSource.PRESET: 1.0,
            PrecedentSource.AUTOMATIC: 0.75,
            PrecedentSource.HUMAN_REVIEW: 1.1,
            PrecedentSource.APPEAL_OVERTURN: 1.25,
        },
        source_priorities={
            PrecedentSource.AUTOMATIC: 100,
            PrecedentSource.PRESET: 200,
            PrecedentSource.HUMAN_REVIEW: 300,
            PrecedentSource.APPEAL_OVERTURN: 400,
        },
        conflict_similarity=0.55,
        automatic_activation_delay_seconds=86_400,
    )


def _authority(
    precedent_id: str,
    *,
    text_model_manifest_id: str,
    source: PrecedentSource,
    direction: VerdictDecision,
    violation_type: ViolationType = ViolationType.REAGENT_CONTAINER_OPEN,
    revision: int = 1,
    config_sha256: str = CONFIG_SHA256,
) -> M5PrecedentAuthority:
    pack = _presence_pack()
    embedding = _embedding(f"historical-{precedent_id}", text_model_manifest_id)
    activation = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    precedent = Precedent(
        precedent_id=precedent_id,
        situation_text=f"Historical situation for {precedent_id}.",
        text_embedding_ref=embedding.embedding_id,
        decision_direction=direction,
        source=source,
        status=PrecedentStatus.ACTIVE,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=violation_type,
        rule_version=pack.event.rule_version,
        source_case_id=f"historical-case-{precedent_id}",
        activation_at=activation,
    )
    return M5PrecedentAuthority(
        run_id=pack.run_id,
        config_sha256=config_sha256,
        revision=revision,
        precedent=precedent,
        created_at=NOW,
        activated_at=NOW,
        text_embedding=embedding,
    )


def _evaluation(
    authority: M5PrecedentAuthority,
    text_similarity: float,
    policy: M5PrecedentPolicy,
) -> M5PrecedentCandidateEvaluation:
    source_weight = policy.source_weights[authority.precedent.source]
    return M5PrecedentCandidateEvaluation(
        authority=authority,
        disposition=M5PrecedentCandidateDisposition.SCORED,
        text_similarity=text_similarity,
        normalized_text_weight=1.0,
        normalized_visual_weight=0.0,
        base_similarity=text_similarity,
        source_weight=source_weight,
        score=text_similarity * source_weight,
    )


def _exposure(
    config_sha256: str = CONFIG_SHA256,
    *,
    policy: M5PrecedentPolicy | None = None,
    m4_top_k: int = 2,
) -> M5PrecedentExposureBatchAuthority:
    pack = _presence_pack()
    text_manifest = _text_manifest()
    policy = policy or _policy(config_sha256)
    assert policy.config_sha256 == config_sha256
    authorities = {
        DISTINGUISH_ID: _authority(
            DISTINGUISH_ID,
            text_model_manifest_id=text_manifest.model_manifest_id,
            source=PrecedentSource.PRESET,
            direction=VerdictDecision.NOT_ESTABLISHED,
            config_sha256=config_sha256,
        ),
        OTHER_VIOLATION_ID: _authority(
            OTHER_VIOLATION_ID,
            text_model_manifest_id=text_manifest.model_manifest_id,
            source=PrecedentSource.PRESET,
            direction=VerdictDecision.ESTABLISHED,
            violation_type=ViolationType.OPEN_FLAME,
            config_sha256=config_sha256,
        ),
        FOLLOW_ID: _authority(
            FOLLOW_ID,
            text_model_manifest_id=text_manifest.model_manifest_id,
            source=PrecedentSource.APPEAL_OVERTURN,
            direction=VerdictDecision.ESTABLISHED,
            config_sha256=config_sha256,
        ),
    }
    evaluations = {
        DISTINGUISH_ID: _evaluation(authorities[DISTINGUISH_ID], 0.7, policy),
        OTHER_VIOLATION_ID: _evaluation(authorities[OTHER_VIOLATION_ID], 0.95, policy),
        FOLLOW_ID: _evaluation(authorities[FOLLOW_ID], 0.88, policy),
    }
    candidate_evaluations = tuple(evaluations[precedent_id] for precedent_id in sorted(evaluations))
    m5_query = M5PrecedentRetrievalQuery(
        run_id=pack.run_id,
        case_id=pack.case_id,
        evidence_class=pack.event.evidence_class,
        rule_version=pack.event.rule_version,
        situation_text=SITUATION_TEXT,
        text_embedding_model_manifest_id=text_manifest.model_manifest_id,
        visual_embedding_model_manifest_id=VISUAL_MODEL_MANIFEST_ID,
        text_embedding=_embedding("current-situation", text_manifest.model_manifest_id),
        policy=policy,
        top_k=1,
    )
    m5_result = M5PrecedentRetrievalResult(
        query=m5_query,
        candidate_evaluations=candidate_evaluations,
        scored_precedents=(evaluations[FOLLOW_ID].as_scored_precedent(),),
    )

    cycle_authority = HearingPrecedentRetrievalReceipt(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=SESSION_ID,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=pack.version,
        evidence_class=pack.event.evidence_class,
        violation_type=pack.event.violation_type,
        rule_version=pack.event.rule_version,
        top_k=m4_top_k,
        query_sha256="0" * 64,
        candidate_snapshot_sha256="0" * 64,
        visible_snapshot_sha256="0" * 64,
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version="m4-m5-precedent-bridge-v1",
        retriever_manifest_id=BRIDGE_MANIFEST_ID,
        embedding_model_manifest_id=text_manifest.model_manifest_id,
        manifest_id=pack.manifest_id,
    )
    m4_query = HearingPrecedentRetrievalQuery(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=SESSION_ID,
        hearing_session_sha256=SESSION_SHA256,
        cycle_scope_id=cycle_authority.cycle_scope_id,
        cycle_scope_sha256=cycle_authority.cycle_scope_sha256,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=pack.version,
        current_evidence_pack_sha256=derive_hearing_evidence_pack_document_sha256(pack),
        evidence_class=pack.event.evidence_class,
        violation_type=pack.event.violation_type,
        rule_version=pack.event.rule_version,
        situation_text=SITUATION_TEXT,
        top_k=m4_top_k,
        config_sha256=config_sha256,
        retriever_version="m4-m5-precedent-bridge-v1",
        retriever_manifest_id=BRIDGE_MANIFEST_ID,
        embedding_model_manifest=text_manifest,
        manifest_id=pack.manifest_id,
    )
    ranked_ids = (FOLLOW_ID, DISTINGUISH_ID)
    scored = tuple(
        ScoredPrecedent(
            precedent=evaluations[precedent_id].authority.precedent,
            text_similarity=evaluations[precedent_id].text_similarity,
            visual_similarity=evaluations[precedent_id].visual_similarity,
            fused_score=evaluations[precedent_id].score,
        )
        for precedent_id in ranked_ids
    )
    m4_result = HearingPrecedentRetrievalResult(
        query=m4_query,
        candidate_precedents=tuple(
            evaluation.authority.precedent for evaluation in candidate_evaluations
        ),
        visible_precedents=tuple(
            evaluations[precedent_id].authority.precedent for precedent_id in sorted(ranked_ids)
        ),
        scored_precedents=scored,
    )
    receipt = HearingPrecedentRetrievalReceipt(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=SESSION_ID,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=pack.version,
        evidence_class=pack.event.evidence_class,
        violation_type=pack.event.violation_type,
        rule_version=pack.event.rule_version,
        top_k=m4_top_k,
        query_sha256=m4_query.query_sha256,
        candidate_precedent_refs=tuple(
            ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id=item.precedent_id)
            for item in m4_result.candidate_precedents
        ),
        candidate_snapshot_sha256=m4_result.candidate_snapshot_sha256,
        visible_precedent_refs=tuple(
            ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id=item.precedent_id)
            for item in m4_result.visible_precedents
        ),
        visible_snapshot_sha256=m4_result.visible_snapshot_sha256,
        scored_precedents=m4_result.scored_precedents,
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version=m4_query.retriever_version,
        retriever_manifest_id=m4_query.retriever_manifest_id,
        embedding_model_manifest_id=text_manifest.model_manifest_id,
        manifest_id=pack.manifest_id,
    )
    outcome = HearingPrecedentRetrievalOutcome(
        query=m4_query,
        result=m4_result,
        receipt=receipt,
    )
    items = tuple(
        M5PrecedentExposureItem(
            rank=rank,
            precedent_id=precedent_id,
            precedent_authority_id=evaluations[precedent_id].authority.authority_id,
            precedent_revision=evaluations[precedent_id].authority.revision,
            candidate_evaluation_id=evaluations[precedent_id].evaluation_id,
            historical_authority=evaluations[precedent_id].authority,
            candidate_evaluation=evaluations[precedent_id],
            m4_scored_precedent=scored[rank - 1],
        )
        for rank, precedent_id in enumerate(ranked_ids, start=1)
    )
    return M5PrecedentExposureBatchAuthority(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=SESSION_ID,
        hearing_session_sha256=SESSION_SHA256,
        cycle_index=1,
        cycle_scope_id=cycle_authority.cycle_scope_id,
        cycle_scope_sha256=cycle_authority.cycle_scope_sha256,
        manifest_id=pack.manifest_id,
        config_sha256=config_sha256,
        policy_id=policy.policy_id,
        bridge_version=m4_query.retriever_version,
        bridge_manifest_id=m4_query.retriever_manifest_id,
        text_embedding_model_manifest_id=text_manifest.model_manifest_id,
        visual_embedding_model_manifest_id=VISUAL_MODEL_MANIFEST_ID,
        m4_retrieval_outcome=outcome,
        m5_retrieval_result=m5_result,
        exposed_precedents=items,
    )


def _default_applications(
    exposure: M5PrecedentExposureBatchAuthority,
) -> tuple[PrecedentApplication, ...]:
    pack = _presence_pack()
    fact_ref = ArtifactRef(
        kind=ArtifactKind.OBJECTIVE_FACT,
        artifact_id=pack.objective_facts[0].fact_id,
    )
    by_id = {item.precedent_id: item for item in exposure.exposed_precedents}
    applications = (
        PrecedentApplication(
            precedent_ref=ArtifactRef(
                kind=ArtifactKind.PRECEDENT,
                artifact_id=DISTINGUISH_ID,
            ),
            mode=PrecedentApplicationMode.DISTINGUISHED,
            similarity_score=by_id[DISTINGUISH_ID].m4_scored_precedent.fused_score,
            distinguishing_reason="The current duration fact materially differs.",
            fact_difference_refs=(fact_ref,),
        ),
        PrecedentApplication(
            precedent_ref=ArtifactRef(
                kind=ArtifactKind.PRECEDENT,
                artifact_id=FOLLOW_ID,
            ),
            mode=PrecedentApplicationMode.FOLLOWED,
            similarity_score=1.0,
        ),
    )
    return tuple(sorted(applications, key=lambda item: item.sort_key))


def _ready_case(applications: tuple[PrecedentApplication, ...]) -> tuple[Case, Verdict]:
    pack = _presence_pack()
    parsed = _parsed(
        run_id=pack.run_id,
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        manifest_id=pack.manifest_id,
    )
    screening = _screening(parsed, l1_score=pack.event.l1_score)
    verdict = _verdict(screening).model_copy(update={"precedent_applications": applications})
    review = _review(verdict)
    ready = Case(
        run_id=pack.run_id,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        event=pack.event,
        evidence_packs=(pack,),
        screening_results=(screening,),
        verdicts=(verdict,),
        procedural_reviews=(review,),
        manifest_id=pack.manifest_id,
    )
    return ready, verdict


def _application_batch(
    *,
    exposure: M5PrecedentExposureBatchAuthority | None = None,
    applications: tuple[PrecedentApplication, ...] | None = None,
    threshold: float = 0.7,
) -> M5PrecedentApplicationBatchAuthority:
    exposure = exposure or _exposure()
    applications = applications or _default_applications(exposure)
    ready, verdict = _ready_case(applications)
    items = {item.precedent_id: item for item in exposure.exposed_precedents}
    bindings = tuple(
        M5PrecedentApplicationBinding(
            application=application,
            exposure_item=items[application.precedent_ref.artifact_id],
        )
        for application in verdict.precedent_applications
    )
    return M5PrecedentApplicationBatchAuthority(
        run_id=ready.run_id,
        case_id=ready.case_id,
        manifest_id=ready.manifest_id,
        config_sha256=exposure.config_sha256,
        ready_case_revision=7,
        ready_case=ready,
        verdict=verdict,
        exposure=exposure,
        precedent_similarity_min=threshold,
        application_bindings=bindings,
    )


def _application_citation(
    batch: M5PrecedentApplicationBatchAuthority,
    precedent_id: str,
    *,
    cited_at: datetime = NOW,
) -> M5PrecedentCitationAuthority:
    binding = next(
        item
        for item in batch.application_bindings
        if item.application.precedent_ref.artifact_id == precedent_id
    )
    exposure_item = binding.exposure_item
    score = exposure_item.candidate_evaluation.score
    assert score is not None
    return M5PrecedentCitationAuthority(
        run_id=batch.run_id,
        case_id=batch.case_id,
        precedent_id=precedent_id,
        precedent_authority_id=exposure_item.precedent_authority_id,
        precedent_revision=exposure_item.precedent_revision,
        query_id=batch.exposure.m5_retrieval_result.query.query_id,
        score=score,
        cited_at=cited_at,
    )


def test_exposure_binds_full_inventory_and_not_only_the_m5_top_k() -> None:
    exposure = _exposure()

    assert exposure.authority_kind == "EXPOSED"
    assert exposure.m5_retrieval_result.query.top_k == 1
    assert len(exposure.m5_retrieval_result.scored_precedents) == 1
    assert len(exposure.m5_retrieval_result.candidate_evaluations) == 3
    assert tuple(item.precedent_id for item in exposure.exposed_precedents) == (
        FOLLOW_ID,
        DISTINGUISH_ID,
    )
    assert tuple(
        item.precedent_id
        for item in exposure.m4_retrieval_outcome.result.visible_precedents  # type: ignore[union-attr]
    ) == (DISTINGUISH_ID, FOLLOW_ID)
    assert (
        M5PrecedentExposureBatchAuthority.model_validate(exposure.model_dump(mode="json"))
        == exposure
    )

    forged = exposure.model_dump(mode="json")
    forged["exposure_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="exposure_sha256"):
        M5PrecedentExposureBatchAuthority.model_validate(forged)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bridge_version", "other-bridge-v1"),
        ("bridge_manifest_id", "0" * 64),
        ("text_embedding_model_manifest_id", "0" * 64),
        ("policy_id", "0" * 64),
        ("config_sha256", "0" * 64),
        ("hearing_session_id", "0" * 64),
    ],
)
def test_exposure_rejects_forged_top_level_authorities(field: str, value: str) -> None:
    payload = _exposure().model_dump(mode="json")
    payload.pop("exposure_id")
    payload.pop("exposure_sha256")
    payload[field] = value
    with pytest.raises(ValidationError):
        M5PrecedentExposureBatchAuthority.model_validate(payload)


def test_exposure_rejects_scope_experiments_and_model_construct_inventory_omission() -> None:
    exposure = _exposure()
    m5 = exposure.m5_retrieval_result

    changed_query = m5.query.model_copy(update={"situation_text": "A different situation."})
    changed_result = m5.model_copy(update={"query": changed_query})
    with pytest.raises(ValidationError, match="scope or situation"):
        exposure.model_copy(update={"m5_retrieval_result": changed_result})

    experimental_query = m5.query.model_copy(update={"run_mode": RunMode.OFFLINE_EXPERIMENT})
    experimental_result = m5.model_copy(update={"query": experimental_query})
    with pytest.raises(ValidationError, match="STANDARD retrieval"):
        exposure.model_copy(update={"m5_retrieval_result": experimental_result})

    incomplete_result = M5PrecedentRetrievalResult.model_construct(
        query=m5.query,
        candidate_evaluations=tuple(
            item
            for item in m5.candidate_evaluations
            if item.authority.precedent.precedent_id != OTHER_VIOLATION_ID
        ),
        scored_precedents=m5.scored_precedents,
    )
    forged = _constructed_copy(exposure, m5_retrieval_result=incomplete_result)
    with pytest.raises(ValidationError, match="complete M5 inventory"):
        M5PrecedentExposureBatchAuthority.model_validate(forged.model_dump(mode="json"))


def test_exposure_rejects_rank_score_and_historical_revision_substitution() -> None:
    exposure = _exposure()
    first, second = exposure.exposed_precedents

    duplicate_rank = second.model_copy(update={"rank": 1})
    with pytest.raises(ValidationError, match="ranks must be complete"):
        exposure.model_copy(update={"exposed_precedents": (first, duplicate_rank)})

    wrong_score = first.m4_scored_precedent.model_copy(update={"fused_score": 0.9})
    with pytest.raises(ValidationError, match="scores do not exactly map"):
        first.model_copy(update={"m4_scored_precedent": wrong_score})

    successor = first.historical_authority.model_copy(update={"revision": 2})
    successor_evaluation = first.candidate_evaluation.model_copy(update={"authority": successor})
    substituted = first.model_copy(
        update={
            "precedent_authority_id": successor.authority_id,
            "precedent_revision": successor.revision,
            "candidate_evaluation_id": successor_evaluation.evaluation_id,
            "historical_authority": successor,
            "candidate_evaluation": successor_evaluation,
        }
    )
    with pytest.raises(ValidationError, match="wrong historical mapping"):
        exposure.model_copy(update={"exposed_precedents": (substituted, second)})


def test_application_is_exact_threshold_complete_and_uses_l5_clamp() -> None:
    batch = _application_batch(threshold=0.7)

    assert batch.authority_kind == "APPLIED"
    assert tuple(
        binding.application.precedent_ref.artifact_id for binding in batch.application_bindings
    ) == (DISTINGUISH_ID, FOLLOW_ID)
    followed = next(
        binding.application
        for binding in batch.application_bindings
        if binding.application.precedent_ref.artifact_id == FOLLOW_ID
    )
    assert followed.similarity_score == 1.0
    assert batch.ready_case_document_sha256 == sha256_hex(batch.ready_case.model_dump(mode="json"))
    assert derive_ready_case_document_sha256(batch.ready_case) == (batch.ready_case_document_sha256)
    assert (
        M5PrecedentApplicationBatchAuthority.model_validate(batch.model_dump(mode="json")) == batch
    )

    forged = batch.model_dump(mode="json")
    forged["ready_case_document_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="ready_case_document_sha256"):
        M5PrecedentApplicationBatchAuthority.model_validate(forged)


def test_application_rejects_silent_omission_low_threshold_item_and_duplicate() -> None:
    batch = _application_batch()
    missing = _constructed_copy(
        batch,
        application_bindings=batch.application_bindings[1:],
    )
    with pytest.raises(ValidationError, match="every and only"):
        M5PrecedentApplicationBatchAuthority.model_validate(missing.model_dump(mode="json"))

    with pytest.raises(ValidationError, match="every and only"):
        batch.model_copy(update={"precedent_similarity_min": 0.8})

    duplicate = _constructed_copy(
        batch,
        application_bindings=(batch.application_bindings[0], batch.application_bindings[0]),
    )
    with pytest.raises(ValidationError, match="at most once"):
        M5PrecedentApplicationBatchAuthority.model_validate(duplicate.model_dump(mode="json"))


def test_application_rejects_wrong_score_and_mode_content_matrix() -> None:
    exposure = _exposure()
    defaults = {item.precedent_ref.artifact_id: item for item in _default_applications(exposure)}
    fact_ref = defaults[DISTINGUISH_ID].fact_difference_refs[0]

    wrong_score = defaults[FOLLOW_ID].model_copy(update={"similarity_score": 0.9})
    with pytest.raises(ValidationError, match="score differs"):
        _application_batch(
            exposure=exposure,
            applications=tuple(
                sorted((defaults[DISTINGUISH_ID], wrong_score), key=lambda item: item.sort_key)
            ),
        )

    wrong_direction = PrecedentApplication(
        precedent_ref=defaults[DISTINGUISH_ID].precedent_ref,
        mode=PrecedentApplicationMode.FOLLOWED,
        similarity_score=0.7,
    )
    with pytest.raises(ValidationError, match="direction conflicts"):
        _application_batch(
            exposure=exposure,
            applications=tuple(
                sorted((wrong_direction, defaults[FOLLOW_ID]), key=lambda item: item.sort_key)
            ),
        )

    followed_with_distinction = defaults[FOLLOW_ID].model_copy(
        update={
            "distinguishing_reason": "Conflicting mode content.",
            "fact_difference_refs": (fact_ref,),
        }
    )
    with pytest.raises(ValidationError, match="cannot claim distinguishing"):
        _application_batch(
            exposure=exposure,
            applications=tuple(
                sorted(
                    (defaults[DISTINGUISH_ID], followed_with_distinction),
                    key=lambda item: item.sort_key,
                )
            ),
        )

    empty_distinction = defaults[DISTINGUISH_ID].model_copy(
        update={"distinguishing_reason": None, "fact_difference_refs": ()}
    )
    with pytest.raises(ValidationError, match="requires a reason and fact differences"):
        _application_batch(
            exposure=exposure,
            applications=tuple(
                sorted((empty_distinction, defaults[FOLLOW_ID]), key=lambda item: item.sort_key)
            ),
        )


def test_application_rejects_foreign_fact_nonvisible_and_cross_scope_documents() -> None:
    batch = _application_batch()
    defaults = {
        item.precedent_ref.artifact_id: item for item in batch.verdict.precedent_applications
    }
    foreign_fact = ArtifactRef(
        kind=ArtifactKind.OBJECTIVE_FACT,
        artifact_id="foreign-case-fact",
    )
    foreign_distinction = defaults[DISTINGUISH_ID].model_copy(
        update={"fact_difference_refs": (foreign_fact,)}
    )
    with pytest.raises(ValidationError, match="exact Verdict evidence pack"):
        _application_batch(
            exposure=batch.exposure,
            applications=tuple(
                sorted((foreign_distinction, defaults[FOLLOW_ID]), key=lambda item: item.sort_key)
            ),
        )

    crossed = batch.model_dump(mode="json")
    crossed.pop("application_batch_id")
    crossed.pop("application_batch_sha256")
    crossed.pop("ready_case_document_sha256")
    crossed["case_id"] = "another-case"
    with pytest.raises(ValidationError, match="crosses run, case"):
        M5PrecedentApplicationBatchAuthority.model_validate(crossed)

    other_verdict = batch.verdict.model_copy(update={"confidence": 0.9})
    with pytest.raises(ValidationError, match="exact latest READY verdict"):
        batch.model_copy(update={"verdict": other_verdict})

    nonvisible_application = PrecedentApplication(
        precedent_ref=ArtifactRef(
            kind=ArtifactKind.PRECEDENT,
            artifact_id=OTHER_VIOLATION_ID,
        ),
        mode=PrecedentApplicationMode.FOLLOWED,
        similarity_score=0.95,
    )
    ready, verdict = _ready_case(
        tuple(
            sorted(
                (*batch.verdict.precedent_applications, nonvisible_application),
                key=lambda item: item.sort_key,
            )
        )
    )
    invalid_binding = M5PrecedentApplicationBinding.model_construct(
        application=nonvisible_application,
        exposure_item=batch.exposure.exposed_precedents[0],
    )
    nonvisible = _constructed_copy(
        batch,
        ready_case=ready,
        verdict=verdict,
        application_bindings=(*batch.application_bindings, invalid_binding),
    )
    with pytest.raises(ValidationError):
        M5PrecedentApplicationBatchAuthority.model_validate(nonvisible.model_dump(mode="json"))


def test_later_revoked_head_does_not_rewrite_frozen_exposure_or_application() -> None:
    batch = _application_batch()
    historical = batch.exposure.exposed_precedents[0].historical_authority
    revoked_precedent = historical.precedent.model_copy(
        update={
            "status": PrecedentStatus.REVOKED,
            "invalidated_by": "appeal-resolution-later",
        }
    )
    later_head = historical.model_copy(
        update={"revision": historical.revision + 1, "precedent": revoked_precedent}
    )

    assert later_head.precedent.status == PrecedentStatus.REVOKED
    assert batch.exposure.exposed_precedents[0].historical_authority.precedent.status == (
        PrecedentStatus.ACTIVE
    )
    assert (
        M5PrecedentApplicationBatchAuthority.model_validate(batch.model_dump(mode="json")) == batch
    )


def test_application_citation_closes_full_inventory_outside_m5_top_k() -> None:
    batch = _application_batch()
    citation = _application_citation(batch, DISTINGUISH_ID)
    binding = next(
        item
        for item in batch.application_bindings
        if item.application.precedent_ref.artifact_id == DISTINGUISH_ID
    )
    assert DISTINGUISH_ID not in {
        item.authority.precedent.precedent_id
        for item in batch.exposure.m5_retrieval_result.scored_precedents
    }
    with pytest.raises(ValidationError, match="historical authority bindings"):
        M5PrecedentCitationCommit(
            retrieval_result=batch.exposure.m5_retrieval_result,
            citation=citation,
        )

    commit = M5PrecedentApplicationCitationCommit(
        application_batch=batch,
        application_binding=binding,
        citation=citation,
    )
    assert (
        M5PrecedentApplicationCitationCommit.model_validate(commit.model_dump(mode="json"))
        == commit
    )
    forged = commit.model_dump(mode="json")
    forged["commit_id"] = "0" * 64
    with pytest.raises(ValidationError, match="commit_id"):
        M5PrecedentApplicationCitationCommit.model_validate(forged)


def test_application_citation_rejects_clamped_score_early_time_and_wrong_binding() -> None:
    batch = _application_batch()
    followed_binding = next(
        item
        for item in batch.application_bindings
        if item.application.precedent_ref.artifact_id == FOLLOW_ID
    )
    followed = _application_citation(batch, FOLLOW_ID)
    clamped = followed.model_copy(update={"score": followed_binding.application.similarity_score})
    forged = M5PrecedentApplicationCitationCommit.model_construct(
        application_batch=batch,
        application_binding=followed_binding,
        citation=clamped,
    )
    with pytest.raises(ValidationError, match="exact exposure evaluation"):
        M5PrecedentApplicationCitationCommit.model_validate(forged.model_dump(mode="json"))

    early = _application_citation(
        batch,
        FOLLOW_ID,
        cited_at=datetime(2026, 8, 3, 8, 59, tzinfo=UTC),
    )
    with pytest.raises(ValidationError, match="precede historical authority visibility"):
        M5PrecedentApplicationCitationCommit(
            application_batch=batch,
            application_binding=followed_binding,
            citation=early,
        )

    distinguished_binding = next(
        item
        for item in batch.application_bindings
        if item.application.precedent_ref.artifact_id == DISTINGUISH_ID
    )
    with pytest.raises(ValidationError, match="exact exposure evaluation"):
        M5PrecedentApplicationCitationCommit(
            application_batch=batch,
            application_binding=distinguished_binding,
            citation=followed,
        )


def test_public_exposure_and_application_schemas_validate_complete_documents() -> None:
    exposure = _exposure()
    application = _application_batch(exposure=exposure)
    schemas = expected_schema_files()

    for name, document in (
        ("m5-precedent-exposure-batch-authority", exposure),
        ("m5-precedent-application-batch-authority", application),
        (
            "m5-precedent-application-citation-commit",
            M5PrecedentApplicationCitationCommit(
                application_batch=application,
                application_binding=application.application_bindings[0],
                citation=_application_citation(application, DISTINGUISH_ID),
            ),
        ),
    ):
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator(schema).validate(document.model_dump(mode="json"))
        if isinstance(
            document,
            (M5PrecedentExposureBatchAuthority, M5PrecedentApplicationBatchAuthority),
        ):
            assert schema["properties"]["authority_kind"]["const"] == document.authority_kind


def test_precedent_usage_contracts_are_exported_from_the_public_package() -> None:
    assert public_contracts.M5PrecedentExposureItem is M5PrecedentExposureItem
    assert public_contracts.M5PrecedentExposureBatchAuthority is M5PrecedentExposureBatchAuthority
    assert public_contracts.M5PrecedentApplicationBinding is M5PrecedentApplicationBinding
    assert (
        public_contracts.M5PrecedentApplicationBatchAuthority
        is M5PrecedentApplicationBatchAuthority
    )
    assert (
        public_contracts.M5PrecedentApplicationCitationCommit
        is M5PrecedentApplicationCitationCommit
    )
