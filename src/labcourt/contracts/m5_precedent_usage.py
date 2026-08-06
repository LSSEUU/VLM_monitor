"""Frozen M4-to-M5 precedent exposure and application authorities.

Exposure records what the hearing prompt was allowed to see.  It is not a
citation and it is not evidence that a verdict used a precedent.  Application
is a later, separate authority that binds the exact reviewed verdict to the
eligible subset of that frozen exposure.
"""

from __future__ import annotations

from typing import Literal, Self, TypeVar

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    PrecedentApplicationMode,
    PrecedentStatus,
    RunMode,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.hearing_retrieval import (
    HearingPrecedentRetrievalOutcome,
    derive_hearing_evidence_pack_document_sha256,
)
from labcourt.contracts.hearing_state import HearingPrecedentRetrievalStatus
from labcourt.contracts.m5_precedents import (
    M5PrecedentAuthority,
    M5PrecedentCandidateDisposition,
    M5PrecedentCandidateEvaluation,
    M5PrecedentCitationAuthority,
    M5PrecedentRetrievalResult,
)
from labcourt.contracts.precedents import ScoredPrecedent
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import PrecedentApplication, Verdict

MAX_M5_HEARING_PRECEDENT_EXPOSURES = 64

_ContractT = TypeVar("_ContractT", bound=FrozenContractModel)


def _validate_claimed_fields(
    value: object,
    handler: ModelWrapValidatorHandler[_ContractT],
    *,
    field_names: tuple[str, ...],
    document_name: str,
) -> _ContractT:
    if not isinstance(value, dict):
        return handler(value)
    payload = dict(value)
    present = {name: name in payload for name in field_names}
    claimed = {name: payload.pop(name, None) for name in field_names}
    document = handler(payload)
    for name in field_names:
        if present[name] and (
            not isinstance(claimed[name], str) or claimed[name] != getattr(document, name)
        ):
            raise ValueError(f"serialized {name} conflicts with {document_name} content")
    return document


def _clamp_l5_similarity(score: float) -> float:
    """Project the bounded M4 fused score into the frozen L5 [-1, 1] wire."""

    return max(-1.0, min(1.0, float(score)))


def _required_m5_score(evaluation: M5PrecedentCandidateEvaluation) -> float:
    if evaluation.score is None:
        raise ValueError("SCORED M5 candidate is missing its final score")
    return evaluation.score


def derive_ready_case_document_sha256(case: Case) -> Sha256Hex:
    """Hash the complete Case document using the repository's canonical formula."""

    if not isinstance(case, Case):
        raise TypeError("case must be a Case")
    return sha256_hex(case.model_dump(mode="json"))


class M5PrecedentExposureItem(FrozenContractModel):
    """One prompt rank mapped to its exact historical M5 evaluation authority."""

    schema_version: Literal["m5-precedent-exposure-item-v1"] = "m5-precedent-exposure-item-v1"
    rank: int = Field(gt=0, le=MAX_M5_HEARING_PRECEDENT_EXPOSURES, strict=True)
    precedent_id: ReferenceToken
    precedent_authority_id: Sha256Hex
    precedent_revision: int = Field(gt=0, strict=True)
    candidate_evaluation_id: Sha256Hex
    historical_authority: M5PrecedentAuthority
    candidate_evaluation: M5PrecedentCandidateEvaluation
    m4_scored_precedent: ScoredPrecedent

    @field_validator("precedent_id")
    @classmethod
    def validate_precedent_id(cls, value: str) -> str:
        return require_reference_token(value, "exposed precedent ID")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_exposure_item_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_fields(
            value,
            handler,
            field_names=("exposure_item_id",),
            document_name="precedent exposure item",
        )

    def item_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "rank": self.rank,
            "precedent_id": self.precedent_id,
            "precedent_authority_id": self.precedent_authority_id,
            "precedent_revision": self.precedent_revision,
            "candidate_evaluation_id": self.candidate_evaluation_id,
            "historical_authority": self.historical_authority.model_dump(mode="json"),
            "candidate_evaluation": self.candidate_evaluation.model_dump(mode="json"),
            "m4_scored_precedent": self.m4_scored_precedent.model_dump(mode="json"),
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def exposure_item_id(self) -> Sha256Hex:
        return sha256_hex(["m5-precedent-exposure-item", 1, self.item_projection()])

    @model_validator(mode="after")
    def validate_exact_historical_mapping(self) -> M5PrecedentExposureItem:
        authority = self.historical_authority
        evaluation = self.candidate_evaluation
        scored = self.m4_scored_precedent
        if (
            self.precedent_id != authority.precedent.precedent_id
            or self.precedent_authority_id != authority.authority_id
            or self.precedent_revision != authority.revision
            or self.candidate_evaluation_id != evaluation.evaluation_id
        ):
            raise ValueError("precedent exposure item identity conflicts with historical authority")
        if evaluation.authority != authority:
            raise ValueError("precedent exposure evaluation rewrites its historical authority")
        if evaluation.disposition != M5PrecedentCandidateDisposition.SCORED:
            raise ValueError("only a fully scored M5 candidate may be exposed")
        if authority.precedent.status != PrecedentStatus.ACTIVE:
            raise ValueError("only an ACTIVE historical M5 authority may be exposed")
        if scored.precedent != authority.precedent:
            raise ValueError("M4 exposed precedent rewrites the historical M5 document")
        if (
            scored.text_similarity != evaluation.text_similarity
            or scored.visual_similarity != evaluation.visual_similarity
            or scored.fused_score != evaluation.score
        ):
            raise ValueError("M4 exposure scores do not exactly map the M5 evaluation")
        return self


class M5PrecedentExposureBatchAuthority(FrozenContractModel):
    """Complete content-addressed authority for one M4 prompt-visible batch."""

    schema_version: Literal["m5-precedent-exposure-batch-authority-v1"] = (
        "m5-precedent-exposure-batch-authority-v1"
    )
    authority_kind: Literal["EXPOSED"] = "EXPOSED"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    hearing_session_sha256: Sha256Hex
    cycle_index: int = Field(gt=0, strict=True)
    cycle_scope_id: Sha256Hex
    cycle_scope_sha256: Sha256Hex
    manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    policy_id: Sha256Hex
    bridge_version: ReferenceToken
    bridge_manifest_id: Sha256Hex
    text_embedding_model_manifest_id: Sha256Hex
    visual_embedding_model_manifest_id: Sha256Hex
    m4_retrieval_outcome: HearingPrecedentRetrievalOutcome
    m5_retrieval_result: M5PrecedentRetrievalResult
    exposed_precedents: tuple[M5PrecedentExposureItem, ...] = Field(
        default=(),
        max_length=MAX_M5_HEARING_PRECEDENT_EXPOSURES,
    )

    @field_validator("run_id", "case_id", "bridge_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "precedent exposure authority reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_fields(
            value,
            handler,
            field_names=("exposure_id", "exposure_sha256"),
            document_name="precedent exposure authority",
        )

    def exposure_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "authority_kind": self.authority_kind,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "hearing_session_id": self.hearing_session_id,
            "hearing_session_sha256": self.hearing_session_sha256,
            "cycle_index": self.cycle_index,
            "cycle_scope_id": self.cycle_scope_id,
            "cycle_scope_sha256": self.cycle_scope_sha256,
            "manifest_id": self.manifest_id,
            "config_sha256": self.config_sha256,
            "policy_id": self.policy_id,
            "bridge_version": self.bridge_version,
            "bridge_manifest_id": self.bridge_manifest_id,
            "text_embedding_model_manifest_id": self.text_embedding_model_manifest_id,
            "visual_embedding_model_manifest_id": self.visual_embedding_model_manifest_id,
            "m4_retrieval_outcome": self.m4_retrieval_outcome.model_dump(mode="json"),
            "m5_retrieval_result": self.m5_retrieval_result.model_dump(mode="json"),
            "exposed_precedents": [
                item.model_dump(mode="json") for item in self.exposed_precedents
            ],
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def exposure_id(self) -> Sha256Hex:
        return sha256_hex(["m5-precedent-exposure-batch", 1, self.exposure_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def exposure_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-exposure-batch-document",
                1,
                self.exposure_id,
                self.exposure_projection(),
            ]
        )

    @model_validator(mode="after")
    def validate_complete_bridge(self) -> M5PrecedentExposureBatchAuthority:
        # Revalidate serialized nested documents so an in-memory model_construct cannot
        # smuggle an invalid frozen child through Pydantic's instance fast path.
        m4 = HearingPrecedentRetrievalOutcome.model_validate(
            self.m4_retrieval_outcome.model_dump(mode="json")
        )
        m5 = M5PrecedentRetrievalResult.model_validate(
            self.m5_retrieval_result.model_dump(mode="json")
        )
        if m4 != self.m4_retrieval_outcome or m5 != self.m5_retrieval_result:
            raise ValueError("precedent exposure contains a non-canonical retrieval document")
        if m4.receipt.status != HearingPrecedentRetrievalStatus.SUCCESS or m4.result is None:
            raise ValueError("precedent exposure requires a complete successful M4 outcome")

        m4_query = m4.query
        m4_result = m4.result
        m5_query = m5.query
        if (
            self.run_id != m4_query.run_id
            or self.case_id != m4_query.case_id
            or self.hearing_session_id != m4_query.hearing_session_id
            or self.hearing_session_sha256 != m4_query.hearing_session_sha256
            or self.cycle_index != m4.receipt.round_index
            or self.cycle_scope_id != m4_query.cycle_scope_id
            or self.cycle_scope_sha256 != m4_query.cycle_scope_sha256
            or self.manifest_id != m4_query.manifest_id
            or self.config_sha256 != m4_query.config_sha256
            or self.bridge_version != m4_query.retriever_version
            or self.bridge_manifest_id != m4_query.retriever_manifest_id
        ):
            raise ValueError("precedent exposure conflicts with its M4 hearing authorities")
        if (
            m5_query.run_id != self.run_id
            or m5_query.case_id != self.case_id
            or m5_query.evidence_class != m4_query.evidence_class
            or m5_query.rule_version != m4_query.rule_version
            or m5_query.situation_text != m4_query.situation_text
        ):
            raise ValueError("M4 and M5 precedent query scope or situation differs")
        if m5_query.run_mode != RunMode.STANDARD or m5_query.include_provisional_experiment:
            raise ValueError(
                "precedent exposure requires STANDARD retrieval without provisional data"
            )
        if (
            self.config_sha256 != m5_query.policy.config_sha256
            or self.policy_id != m5_query.policy.policy_id
        ):
            raise ValueError("precedent exposure conflicts with its M5 policy authority")
        if (
            self.text_embedding_model_manifest_id != m5_query.text_embedding_model_manifest_id
            or self.text_embedding_model_manifest_id
            != m4_query.embedding_model_manifest.model_manifest_id
            or self.visual_embedding_model_manifest_id
            != m5_query.visual_embedding_model_manifest_id
        ):
            raise ValueError("precedent exposure conflicts with its embedding model authorities")

        projected_candidates = tuple(
            evaluation.authority.precedent for evaluation in m5.candidate_evaluations
        )
        if m4_result.candidate_precedents != projected_candidates:
            raise ValueError(
                "M4 candidate documents must exactly project the complete M5 inventory"
            )

        eligible = tuple(
            sorted(
                (
                    evaluation
                    for evaluation in m5.candidate_evaluations
                    if evaluation.disposition == M5PrecedentCandidateDisposition.SCORED
                    and evaluation.authority.precedent.status == PrecedentStatus.ACTIVE
                    and evaluation.authority.precedent.violation_type == m4_query.violation_type
                ),
                key=lambda evaluation: (
                    -_required_m5_score(evaluation),
                    evaluation.authority.precedent.precedent_id,
                ),
            )[: m4_query.top_k]
        )
        expected_scored = tuple(
            ScoredPrecedent(
                precedent=evaluation.authority.precedent,
                text_similarity=evaluation.text_similarity,
                visual_similarity=evaluation.visual_similarity,
                fused_score=_required_m5_score(evaluation),
            )
            for evaluation in eligible
        )
        expected_visible = tuple(
            sorted(
                (evaluation.authority.precedent for evaluation in eligible),
                key=lambda precedent: precedent.precedent_id,
            )
        )
        if m4_result.visible_precedents != expected_visible:
            raise ValueError("M4 visible precedents are not the complete stable M5 projection")
        if m4_result.scored_precedents != expected_scored:
            raise ValueError("M4 scored precedents do not exactly map the M5 ranking")

        expected_ranks = tuple(range(1, len(eligible) + 1))
        if tuple(item.rank for item in self.exposed_precedents) != expected_ranks:
            raise ValueError("precedent exposure ranks must be complete, unique, and contiguous")
        if len({item.precedent_id for item in self.exposed_precedents}) != len(
            self.exposed_precedents
        ):
            raise ValueError("precedent exposure items must use unique precedent IDs")
        for item, evaluation, scored in zip(
            self.exposed_precedents,
            eligible,
            expected_scored,
            strict=True,
        ):
            if (
                item.historical_authority != evaluation.authority
                or item.candidate_evaluation != evaluation
                or item.m4_scored_precedent != scored
            ):
                raise ValueError("precedent exposure rank has the wrong historical mapping")
        return self


class M5PrecedentApplicationBinding(FrozenContractModel):
    """Map one Verdict application back to one exact frozen exposure item."""

    schema_version: Literal["m5-precedent-application-binding-v1"] = (
        "m5-precedent-application-binding-v1"
    )
    application: PrecedentApplication
    exposure_item: M5PrecedentExposureItem

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_binding_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_fields(
            value,
            handler,
            field_names=("binding_id",),
            document_name="precedent application binding",
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def binding_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-application-binding",
                1,
                self.application.model_dump(mode="json"),
                self.exposure_item.model_dump(mode="json"),
            ]
        )

    @model_validator(mode="after")
    def validate_mapping(self) -> M5PrecedentApplicationBinding:
        item = M5PrecedentExposureItem.model_validate(self.exposure_item.model_dump(mode="json"))
        application = PrecedentApplication.model_validate(self.application.model_dump(mode="json"))
        if item != self.exposure_item or application != self.application:
            raise ValueError("precedent application binding contains non-canonical content")
        if application.precedent_ref != ArtifactRef(
            kind=ArtifactKind.PRECEDENT,
            artifact_id=item.precedent_id,
        ):
            raise ValueError("precedent application does not identify its exposure item")
        return self


class M5PrecedentApplicationBatchAuthority(FrozenContractModel):
    """Exact APPLIED authority for one passed Verdict and READY Case revision."""

    schema_version: Literal["m5-precedent-application-batch-authority-v1"] = (
        "m5-precedent-application-batch-authority-v1"
    )
    authority_kind: Literal["APPLIED"] = "APPLIED"
    run_id: ReferenceToken
    case_id: ReferenceToken
    manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    ready_case_revision: int = Field(gt=0, strict=True)
    ready_case: Case
    verdict: Verdict
    exposure: M5PrecedentExposureBatchAuthority
    precedent_similarity_min: StrictFloat = Field(ge=-1, le=1)
    application_bindings: tuple[M5PrecedentApplicationBinding, ...] = Field(
        default=(),
        max_length=MAX_M5_HEARING_PRECEDENT_EXPOSURES,
    )

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "precedent application authority reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_fields(
            value,
            handler,
            field_names=(
                "ready_case_document_sha256",
                "application_batch_id",
                "application_batch_sha256",
            ),
            document_name="precedent application authority",
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ready_case_document_sha256(self) -> Sha256Hex:
        return derive_ready_case_document_sha256(self.ready_case)

    def application_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "authority_kind": self.authority_kind,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "manifest_id": self.manifest_id,
            "config_sha256": self.config_sha256,
            "ready_case_revision": self.ready_case_revision,
            "ready_case_document_sha256": self.ready_case_document_sha256,
            "ready_case": self.ready_case.model_dump(mode="json"),
            "verdict": self.verdict.model_dump(mode="json"),
            "exposure": self.exposure.model_dump(mode="json"),
            "precedent_similarity_min": self.precedent_similarity_min,
            "application_bindings": [
                binding.model_dump(mode="json") for binding in self.application_bindings
            ],
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def application_batch_id(self) -> Sha256Hex:
        return sha256_hex(["m5-precedent-application-batch", 1, self.application_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def application_batch_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-application-batch-document",
                1,
                self.application_batch_id,
                self.application_projection(),
            ]
        )

    @model_validator(mode="after")
    def validate_applied_subset(self) -> M5PrecedentApplicationBatchAuthority:
        ready_case = Case.model_validate(self.ready_case.model_dump(mode="json"))
        verdict = Verdict.model_validate(self.verdict.model_dump(mode="json"))
        exposure = M5PrecedentExposureBatchAuthority.model_validate(
            self.exposure.model_dump(mode="json")
        )
        if ready_case != self.ready_case or verdict != self.verdict or exposure != self.exposure:
            raise ValueError("precedent application contains non-canonical authority content")
        if ready_case.status != CaseStatus.READY_FOR_ALERT_POLICY:
            raise ValueError("precedent application requires a READY_FOR_ALERT_POLICY Case")
        if not ready_case.verdicts or ready_case.verdicts[-1] != verdict:
            raise ValueError("precedent application must bind the exact latest READY verdict")
        if (
            self.run_id != ready_case.run_id
            or self.run_id != verdict.run_id
            or self.run_id != exposure.run_id
            or self.case_id != ready_case.case_id
            or self.case_id != verdict.case_id
            or self.case_id != exposure.case_id
            or self.manifest_id != ready_case.manifest_id
            or self.manifest_id != verdict.manifest_id
            or self.manifest_id != exposure.manifest_id
            or self.config_sha256 != exposure.config_sha256
        ):
            raise ValueError("precedent application crosses run, case, manifest, or config scope")

        m4_query = exposure.m4_retrieval_outcome.query
        if (
            verdict.violation_type != m4_query.violation_type
            or verdict.evidence_pack_id != m4_query.current_evidence_pack_id
            or verdict.evidence_pack_version != m4_query.current_evidence_pack_version
        ):
            raise ValueError("precedent application verdict conflicts with its hearing exposure")
        verdict_packs = tuple(
            pack
            for pack in ready_case.evidence_packs
            if pack.pack_id == verdict.evidence_pack_id
            and pack.version == verdict.evidence_pack_version
        )
        if len(verdict_packs) != 1:
            raise ValueError("precedent application cannot resolve the exact verdict evidence pack")
        verdict_pack = verdict_packs[0]
        if (
            derive_hearing_evidence_pack_document_sha256(verdict_pack)
            != m4_query.current_evidence_pack_sha256
        ):
            raise ValueError("precedent application evidence pack differs from the exposure")

        visible_by_id = {item.precedent_id: item for item in exposure.exposed_precedents}
        eligible_by_id = {
            precedent_id: item
            for precedent_id, item in visible_by_id.items()
            if _clamp_l5_similarity(item.m4_scored_precedent.fused_score)
            >= self.precedent_similarity_min
        }
        application_ids = tuple(
            binding.application.precedent_ref.artifact_id for binding in self.application_bindings
        )
        if len(application_ids) != len(set(application_ids)):
            raise ValueError("one exposed precedent may be applied at most once")
        if set(application_ids) != set(eligible_by_id):
            raise ValueError(
                "verdict must apply every and only prompt-visible precedent meeting threshold"
            )
        if tuple(binding.application for binding in self.application_bindings) != (
            verdict.precedent_applications
        ):
            raise ValueError("application bindings must exactly preserve the Verdict applications")

        allowed_fact_refs = frozenset(
            ref
            for ref in verdict_pack.expected_closure_refs()
            if ref.kind == ArtifactKind.OBJECTIVE_FACT
        )
        for binding in self.application_bindings:
            application = binding.application
            item = eligible_by_id[application.precedent_ref.artifact_id]
            if binding.exposure_item != item:
                raise ValueError("Verdict application maps to the wrong frozen exposure item")
            expected_similarity = _clamp_l5_similarity(item.m4_scored_precedent.fused_score)
            if application.similarity_score != expected_similarity:
                raise ValueError("Verdict application score differs from the M4/L5 projection")
            if (
                application.mode == PrecedentApplicationMode.FOLLOWED
                and item.historical_authority.precedent.decision_direction != verdict.decision
            ):
                raise ValueError("FOLLOWED precedent direction conflicts with the Verdict")
            if application.mode == PrecedentApplicationMode.FOLLOWED and (
                application.distinguishing_reason is not None or application.fact_difference_refs
            ):
                raise ValueError("FOLLOWED precedent cannot claim distinguishing content")
            if application.mode == PrecedentApplicationMode.DISTINGUISHED and (
                application.distinguishing_reason is None or not application.fact_difference_refs
            ):
                raise ValueError("DISTINGUISHED precedent requires a reason and fact differences")
            if any(ref not in allowed_fact_refs for ref in application.fact_difference_refs):
                raise ValueError(
                    "precedent fact differences must belong to the exact Verdict evidence pack"
                )
        return self


class M5PrecedentApplicationCitationCommit(FrozenContractModel):
    """Append-only citation proof derived from one exact APPLIED binding.

    Unlike the direct M5 retrieval citation commit, this bridge may cite an item
    that M4 exposed from the complete M5 SCORED inventory even when that item was
    outside the M5 query's own top_k projection.
    """

    schema_version: Literal["m5-precedent-application-citation-commit-v1"] = (
        "m5-precedent-application-citation-commit-v1"
    )
    application_batch: M5PrecedentApplicationBatchAuthority
    application_binding: M5PrecedentApplicationBinding
    citation: M5PrecedentCitationAuthority

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_commit_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_fields(
            value,
            handler,
            field_names=("commit_id",),
            document_name="precedent application citation commit",
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-application-citation-commit",
                1,
                self.application_batch.model_dump(mode="json"),
                self.application_binding.model_dump(mode="json"),
                self.citation.model_dump(mode="json"),
            ]
        )

    @model_validator(mode="after")
    def validate_commit(self) -> M5PrecedentApplicationCitationCommit:
        batch = M5PrecedentApplicationBatchAuthority.model_validate(
            self.application_batch.model_dump(mode="json")
        )
        binding = M5PrecedentApplicationBinding.model_validate(
            self.application_binding.model_dump(mode="json")
        )
        citation = M5PrecedentCitationAuthority.model_validate(
            self.citation.model_dump(mode="json")
        )
        if (
            batch != self.application_batch
            or binding != self.application_binding
            or citation != self.citation
        ):
            raise ValueError("application citation commit contains non-canonical content")
        if batch.application_bindings.count(binding) != 1:
            raise ValueError("application citation must bind one exact APPLIED item")

        item = binding.exposure_item
        evaluation = item.candidate_evaluation
        authority = item.historical_authority
        query = batch.exposure.m5_retrieval_result.query
        if (
            citation.run_id != batch.run_id
            or citation.case_id != batch.case_id
            or citation.precedent_id != item.precedent_id
            or citation.precedent_authority_id != authority.authority_id
            or citation.precedent_revision != authority.revision
            or citation.query_id != query.query_id
            or citation.score != _required_m5_score(evaluation)
        ):
            raise ValueError("application citation conflicts with its exact exposure evaluation")
        if (
            citation.cited_at < authority.created_at
            or authority.activated_at is None
            or citation.cited_at < authority.activated_at
        ):
            raise ValueError("application citation cannot precede historical authority visibility")
        return self


__all__ = [
    "MAX_M5_HEARING_PRECEDENT_EXPOSURES",
    "M5PrecedentApplicationBatchAuthority",
    "M5PrecedentApplicationBinding",
    "M5PrecedentApplicationCitationCommit",
    "M5PrecedentExposureBatchAuthority",
    "M5PrecedentExposureItem",
    "derive_ready_case_document_sha256",
]
