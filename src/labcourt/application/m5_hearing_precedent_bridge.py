"""Deterministic M5 SQLite corpus projection into the frozen M4 hearing port."""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn

from labcourt.application.m5_embedding_integrity import (
    M5EmbeddingIntegrityError,
    build_m5_controlled_fake_embedding,
    derive_m5_controlled_fake_embedding,
)
from labcourt.application.m5_precedents import (
    ExactM5PrecedentRetrievalService,
    M5PrecedentServiceError,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import ArtifactKind, PrecedentStatus, RunMode
from labcourt.contracts.hearing_common import HearingCycleScope
from labcourt.contracts.hearing_retrieval import (
    MAX_HEARING_PRECEDENT_FUSED_SCORE,
    HearingPrecedentRetrievalOutcome,
    HearingPrecedentRetrievalQuery,
    HearingPrecedentRetrievalResult,
)
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentExposureBatchAuthority,
    M5PrecedentExposureItem,
)
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5EmbeddingVector,
    M5PrecedentAuthority,
    M5PrecedentCandidateDisposition,
    M5PrecedentCandidateEvaluation,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    M5PrecedentRetrievalResult,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.precedents import ScoredPrecedent
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ContractViolation
from labcourt.ports.m5_precedents import (
    M5PrecedentEmbeddingProvider,
    M5PrecedentRepository,
)

M5_HEARING_PRECEDENT_BRIDGE_VERSION = "m5-hearing-precedent-bridge-v1"
M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID = sha256_hex(
    [
        "m5-hearing-precedent-bridge-manifest",
        1,
        M5_HEARING_PRECEDENT_BRIDGE_VERSION,
        "controlled-fake-text-embedding-v1",
        "exact-m5-precedent-retrieval-v1",
        "complete-candidate-evaluations",
        "violation-type-filter-after-evaluation",
    ]
)


class M5HearingPrecedentBridgeErrorCode(StrEnum):
    """Stable reasons why an M5 result cannot inhabit the frozen M4 contract."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    MANIFEST_MISMATCH = "MANIFEST_MISMATCH"
    NON_STANDARD_RUN = "NON_STANDARD_RUN"
    SCORE_RANGE_INCOMPATIBLE = "SCORE_RANGE_INCOMPATIBLE"
    RETRIEVAL_CONTRACT_VIOLATION = "RETRIEVAL_CONTRACT_VIOLATION"


class M5HearingPrecedentBridgeError(ContractViolation):
    """Typed fail-closed bridge error; no score or ranking is silently rewritten."""

    def __init__(self, code: M5HearingPrecedentBridgeErrorCode) -> None:
        if not isinstance(code, M5HearingPrecedentBridgeErrorCode):
            raise TypeError("code must be an M5HearingPrecedentBridgeErrorCode")
        self.code = code
        super().__init__(code.value)


def _fail(code: M5HearingPrecedentBridgeErrorCode) -> NoReturn:
    raise M5HearingPrecedentBridgeError(code)


def require_m5_hearing_bridge_authorities(
    *,
    query: HearingPrecedentRetrievalQuery,
    manifest: RunManifest,
    policy: M5PrecedentPolicy,
    run_mode: RunMode,
) -> None:
    """Validate the immutable authorities needed by the production bridge."""

    if (
        not isinstance(query, HearingPrecedentRetrievalQuery)
        or not isinstance(manifest, RunManifest)
        or not isinstance(policy, M5PrecedentPolicy)
        or not isinstance(run_mode, RunMode)
    ):
        _fail(M5HearingPrecedentBridgeErrorCode.INVALID_ARGUMENT)
    if run_mode != RunMode.STANDARD:
        _fail(M5HearingPrecedentBridgeErrorCode.NON_STANDARD_RUN)
    text_manifest = manifest.models.get("text_embedding")
    visual_manifest = manifest.models.get("visual_embedding")
    if (
        query.run_id == ""
        or query.manifest_id != manifest.manifest_id
        or query.config_sha256 != manifest.config_sha256
        or query.rule_version != manifest.rule_version
        or policy.config_sha256 != manifest.config_sha256
        or text_manifest is None
        or visual_manifest is None
        or query.embedding_model_manifest != text_manifest
    ):
        _fail(M5HearingPrecedentBridgeErrorCode.MANIFEST_MISMATCH)
    # M5 permits source weights up to 10, while the frozen M4 result permits a
    # fused score no greater than 1.25.  Reject an incompatible policy instead
    # of clamping a score and silently changing rank/tie semantics.
    if any(
        float(weight) > MAX_HEARING_PRECEDENT_FUSED_SCORE
        for weight in policy.source_weights.values()
    ):
        _fail(M5HearingPrecedentBridgeErrorCode.SCORE_RANGE_INCOMPATIBLE)


def _build_m5_query_with_embedding(
    *,
    query: HearingPrecedentRetrievalQuery,
    manifest: RunManifest,
    policy: M5PrecedentPolicy,
    text_embedding: M5EmbeddingVector,
) -> M5PrecedentRetrievalQuery:
    return M5PrecedentRetrievalQuery(
        run_id=query.run_id,
        case_id=query.case_id,
        evidence_class=query.evidence_class,
        rule_version=query.rule_version,
        situation_text=query.situation_text,
        text_embedding_model_manifest_id=(manifest.models["text_embedding"].model_manifest_id),
        visual_embedding_model_manifest_id=(manifest.models["visual_embedding"].model_manifest_id),
        text_embedding=text_embedding,
        visual_embeddings=(),
        policy=policy,
        top_k=query.top_k,
        run_mode=RunMode.STANDARD,
        include_provisional_experiment=False,
    )


def build_m5_query_for_hearing(
    *,
    query: HearingPrecedentRetrievalQuery,
    manifest: RunManifest,
    policy: M5PrecedentPolicy,
    run_mode: RunMode,
    embedding_provider: M5PrecedentEmbeddingProvider,
) -> M5PrecedentRetrievalQuery:
    """Build the exact local TEXT-only M5 query for one frozen M4 query."""

    require_m5_hearing_bridge_authorities(
        query=query,
        manifest=manifest,
        policy=policy,
        run_mode=run_mode,
    )
    try:
        text_embedding = build_m5_controlled_fake_embedding(
            channel=M5EmbeddingChannel.TEXT,
            situation_text=query.situation_text,
            model_manifest=manifest.models["text_embedding"],
            embedding_provider=embedding_provider,
        )
        return _build_m5_query_with_embedding(
            query=query,
            manifest=manifest,
            policy=policy,
            text_embedding=text_embedding,
        )
    except M5HearingPrecedentBridgeError:
        raise
    except (KeyError, M5EmbeddingIntegrityError, TypeError, ValueError) as exc:
        raise M5HearingPrecedentBridgeError(
            M5HearingPrecedentBridgeErrorCode.RETRIEVAL_CONTRACT_VIOLATION
        ) from exc


def derive_m5_query_for_hearing(
    *,
    query: HearingPrecedentRetrievalQuery,
    manifest: RunManifest,
    policy: M5PrecedentPolicy,
    run_mode: RunMode,
) -> M5PrecedentRetrievalQuery:
    """Purely rebuild the trusted M5 query for readonly verification."""

    require_m5_hearing_bridge_authorities(
        query=query,
        manifest=manifest,
        policy=policy,
        run_mode=run_mode,
    )
    try:
        text_embedding = derive_m5_controlled_fake_embedding(
            channel=M5EmbeddingChannel.TEXT,
            situation_text=query.situation_text,
            model_manifest=manifest.models["text_embedding"],
        )
        return _build_m5_query_with_embedding(
            query=query,
            manifest=manifest,
            policy=policy,
            text_embedding=text_embedding,
        )
    except M5HearingPrecedentBridgeError:
        raise
    except (KeyError, M5EmbeddingIntegrityError, TypeError, ValueError) as exc:
        raise M5HearingPrecedentBridgeError(
            M5HearingPrecedentBridgeErrorCode.RETRIEVAL_CONTRACT_VIOLATION
        ) from exc


def _eligible_m4_evaluations(
    *,
    query: HearingPrecedentRetrievalQuery,
    result: M5PrecedentRetrievalResult,
) -> tuple[M5PrecedentCandidateEvaluation, ...]:
    def required_score(evaluation: M5PrecedentCandidateEvaluation) -> float:
        if evaluation.score is None:
            _fail(M5HearingPrecedentBridgeErrorCode.RETRIEVAL_CONTRACT_VIOLATION)
        return evaluation.score

    eligible = tuple(
        sorted(
            (
                evaluation
                for evaluation in result.candidate_evaluations
                if evaluation.disposition == M5PrecedentCandidateDisposition.SCORED
                and evaluation.authority.precedent.status == PrecedentStatus.ACTIVE
                and evaluation.authority.precedent.violation_type == query.violation_type
            ),
            key=lambda evaluation: (
                -required_score(evaluation),
                evaluation.authority.precedent.precedent_id,
            ),
        )[: query.top_k]
    )
    for evaluation in eligible:
        score = evaluation.score
        if score is None or not -1.0 <= score <= MAX_HEARING_PRECEDENT_FUSED_SCORE:
            _fail(M5HearingPrecedentBridgeErrorCode.SCORE_RANGE_INCOMPATIBLE)
    return eligible


def project_m5_result_to_m4(
    *,
    query: HearingPrecedentRetrievalQuery,
    result: M5PrecedentRetrievalResult,
) -> HearingPrecedentRetrievalResult:
    """Project complete M5 evaluations, then filter M4 visibility by violation."""

    if not isinstance(query, HearingPrecedentRetrievalQuery) or not isinstance(
        result,
        M5PrecedentRetrievalResult,
    ):
        _fail(M5HearingPrecedentBridgeErrorCode.INVALID_ARGUMENT)
    if (
        result.query.run_id != query.run_id
        or result.query.case_id != query.case_id
        or result.query.evidence_class != query.evidence_class
        or result.query.rule_version != query.rule_version
        or result.query.situation_text != query.situation_text
        or result.query.run_mode != RunMode.STANDARD
        or result.query.include_provisional_experiment
    ):
        _fail(M5HearingPrecedentBridgeErrorCode.RETRIEVAL_CONTRACT_VIOLATION)
    eligible = _eligible_m4_evaluations(query=query, result=result)
    scored = tuple(
        ScoredPrecedent(
            precedent=evaluation.authority.precedent,
            text_similarity=evaluation.text_similarity,
            visual_similarity=evaluation.visual_similarity,
            fused_score=evaluation.score,
        )
        for evaluation in eligible
        if evaluation.score is not None
    )
    try:
        return HearingPrecedentRetrievalResult(
            query=query,
            candidate_precedents=tuple(
                evaluation.authority.precedent for evaluation in result.candidate_evaluations
            ),
            visible_precedents=tuple(
                sorted(
                    (evaluation.authority.precedent for evaluation in eligible),
                    key=lambda precedent: precedent.precedent_id,
                )
            ),
            scored_precedents=scored,
        )
    except (TypeError, ValueError) as exc:
        raise M5HearingPrecedentBridgeError(
            M5HearingPrecedentBridgeErrorCode.RETRIEVAL_CONTRACT_VIOLATION
        ) from exc


def build_m4_success_outcome(
    *,
    query: HearingPrecedentRetrievalQuery,
    result: HearingPrecedentRetrievalResult,
    cycle_scope: HearingCycleScope,
) -> HearingPrecedentRetrievalOutcome:
    """Independently rebuild the canonical M4 outcome from its persisted cycle."""

    if (
        not isinstance(query, HearingPrecedentRetrievalQuery)
        or not isinstance(result, HearingPrecedentRetrievalResult)
        or not isinstance(cycle_scope, HearingCycleScope)
        or result.query != query
        or cycle_scope.run_id != query.run_id
        or cycle_scope.case_id != query.case_id
        or cycle_scope.hearing_session_id != query.hearing_session_id
        or cycle_scope.cycle_id != query.cycle_scope_id
        or cycle_scope.cycle_sha256 != query.cycle_scope_sha256
        or cycle_scope.cycle_evidence_pack_id != query.current_evidence_pack_id
        or cycle_scope.cycle_evidence_pack_version != query.current_evidence_pack_version
        or cycle_scope.manifest_id != query.manifest_id
    ):
        _fail(M5HearingPrecedentBridgeErrorCode.RETRIEVAL_CONTRACT_VIOLATION)
    receipt = HearingPrecedentRetrievalReceipt(
        run_id=query.run_id,
        case_id=query.case_id,
        hearing_session_id=query.hearing_session_id,
        round_index=cycle_scope.cycle_index,
        prior_acquisition_rounds=cycle_scope.prior_acquisition_rounds,
        prior_rework_rounds=cycle_scope.prior_rework_rounds,
        current_evidence_pack_id=query.current_evidence_pack_id,
        current_evidence_pack_version=query.current_evidence_pack_version,
        evidence_class=query.evidence_class,
        violation_type=query.violation_type,
        rule_version=query.rule_version,
        top_k=query.top_k,
        query_sha256=query.query_sha256,
        initial_trigger_review_ref=cycle_scope.initial_trigger_review_ref,
        initial_defect_codes=cycle_scope.initial_defect_codes,
        rework_review_ref=cycle_scope.rework_review_ref,
        rework_defect_codes=cycle_scope.rework_defect_codes,
        candidate_precedent_refs=tuple(
            ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id=item.precedent_id)
            for item in result.candidate_precedents
        ),
        candidate_snapshot_sha256=result.candidate_snapshot_sha256,
        visible_precedent_refs=tuple(
            ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id=item.precedent_id)
            for item in result.visible_precedents
        ),
        visible_snapshot_sha256=result.visible_snapshot_sha256,
        scored_precedents=result.scored_precedents,
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version=query.retriever_version,
        retriever_manifest_id=query.retriever_manifest_id,
        embedding_model_manifest_id=query.embedding_model_manifest.model_manifest_id,
        manifest_id=query.manifest_id,
    )
    return HearingPrecedentRetrievalOutcome(query=query, result=result, receipt=receipt)


def build_m5_precedent_exposure(
    *,
    outcome: HearingPrecedentRetrievalOutcome,
    result: M5PrecedentRetrievalResult,
) -> M5PrecedentExposureBatchAuthority:
    """Seal one successful M4 prompt-visible batch as an EXPOSED authority."""

    if (
        not isinstance(outcome, HearingPrecedentRetrievalOutcome)
        or not isinstance(result, M5PrecedentRetrievalResult)
        or outcome.result is None
        or outcome.receipt.status != HearingPrecedentRetrievalStatus.SUCCESS
    ):
        _fail(M5HearingPrecedentBridgeErrorCode.INVALID_ARGUMENT)
    m4_result = outcome.result
    if m4_result is None:
        _fail(M5HearingPrecedentBridgeErrorCode.INVALID_ARGUMENT)
    expected_m4_result = project_m5_result_to_m4(query=outcome.query, result=result)
    if m4_result != expected_m4_result:
        _fail(M5HearingPrecedentBridgeErrorCode.RETRIEVAL_CONTRACT_VIOLATION)
    eligible = _eligible_m4_evaluations(query=outcome.query, result=result)
    items = tuple(
        M5PrecedentExposureItem(
            rank=rank,
            precedent_id=evaluation.authority.precedent.precedent_id,
            precedent_authority_id=evaluation.authority.authority_id,
            precedent_revision=evaluation.authority.revision,
            candidate_evaluation_id=evaluation.evaluation_id,
            historical_authority=evaluation.authority,
            candidate_evaluation=evaluation,
            m4_scored_precedent=scored,
        )
        for rank, (evaluation, scored) in enumerate(
            zip(eligible, m4_result.scored_precedents, strict=True),
            start=1,
        )
    )
    return M5PrecedentExposureBatchAuthority(
        run_id=outcome.query.run_id,
        case_id=outcome.query.case_id,
        hearing_session_id=outcome.query.hearing_session_id,
        hearing_session_sha256=outcome.query.hearing_session_sha256,
        cycle_index=outcome.receipt.round_index,
        cycle_scope_id=outcome.query.cycle_scope_id,
        cycle_scope_sha256=outcome.query.cycle_scope_sha256,
        manifest_id=outcome.query.manifest_id,
        config_sha256=outcome.query.config_sha256,
        policy_id=result.query.policy.policy_id,
        bridge_version=outcome.query.retriever_version,
        bridge_manifest_id=outcome.query.retriever_manifest_id,
        text_embedding_model_manifest_id=(result.query.text_embedding_model_manifest_id),
        visual_embedding_model_manifest_id=(result.query.visual_embedding_model_manifest_id),
        m4_retrieval_outcome=outcome,
        m5_retrieval_result=result,
        exposed_precedents=items,
    )


def retrieve_m5_for_hearing(
    *,
    query: HearingPrecedentRetrievalQuery,
    manifest: RunManifest,
    policy: M5PrecedentPolicy,
    run_mode: RunMode,
    candidates: tuple[M5PrecedentAuthority, ...],
    embedding_provider: M5PrecedentEmbeddingProvider,
) -> tuple[M5PrecedentRetrievalResult, HearingPrecedentRetrievalResult]:
    """Run exact M5 retrieval and its deterministic M4 projection."""

    m5_query = build_m5_query_for_hearing(
        query=query,
        manifest=manifest,
        policy=policy,
        run_mode=run_mode,
        embedding_provider=embedding_provider,
    )
    try:
        m5_result = ExactM5PrecedentRetrievalService().retrieve(m5_query, candidates)
    except M5PrecedentServiceError as exc:
        raise M5HearingPrecedentBridgeError(
            M5HearingPrecedentBridgeErrorCode.RETRIEVAL_CONTRACT_VIOLATION
        ) from exc
    return m5_result, project_m5_result_to_m4(query=query, result=m5_result)


class M5HearingPrecedentRetriever:
    """Offline production implementation of the frozen M4 retrieval port."""

    def __init__(
        self,
        *,
        repository: M5PrecedentRepository,
        manifest: RunManifest,
        policy: M5PrecedentPolicy,
        run_mode: RunMode,
        embedding_provider: M5PrecedentEmbeddingProvider,
    ) -> None:
        if not callable(getattr(repository, "list_for_retrieval", None)):
            raise TypeError("repository must implement list_for_retrieval")
        if (
            not isinstance(manifest, RunManifest)
            or not isinstance(policy, M5PrecedentPolicy)
            or not isinstance(run_mode, RunMode)
            or not callable(getattr(embedding_provider, "embed", None))
        ):
            raise TypeError(
                "manifest, policy, run_mode, and embedding_provider must be canonical authorities"
            )
        self._repository = repository
        self._manifest = RunManifest.model_validate(manifest.model_dump(mode="json"))
        self._policy = M5PrecedentPolicy.model_validate(policy.model_dump(mode="json"))
        self._run_mode = run_mode
        self._embedding_provider = embedding_provider

    def retrieve(
        self,
        query: HearingPrecedentRetrievalQuery,
    ) -> HearingPrecedentRetrievalResult:
        m5_query = build_m5_query_for_hearing(
            query=query,
            manifest=self._manifest,
            policy=self._policy,
            run_mode=self._run_mode,
            embedding_provider=self._embedding_provider,
        )
        candidates = self._repository.list_for_retrieval(m5_query)
        m5_result, projected = retrieve_m5_for_hearing(
            query=query,
            manifest=self._manifest,
            policy=self._policy,
            run_mode=self._run_mode,
            candidates=candidates,
            embedding_provider=self._embedding_provider,
        )
        if m5_result.query != m5_query:
            _fail(M5HearingPrecedentBridgeErrorCode.RETRIEVAL_CONTRACT_VIOLATION)
        return projected


__all__ = [
    "M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID",
    "M5_HEARING_PRECEDENT_BRIDGE_VERSION",
    "M5HearingPrecedentBridgeError",
    "M5HearingPrecedentBridgeErrorCode",
    "M5HearingPrecedentRetriever",
    "build_m4_success_outcome",
    "build_m5_precedent_exposure",
    "build_m5_query_for_hearing",
    "derive_m5_query_for_hearing",
    "project_m5_result_to_m4",
    "require_m5_hearing_bridge_authorities",
    "retrieve_m5_for_hearing",
]
