"""Additive M5 precedent authorities and exact-retrieval contracts.

The M0-M4 ``Precedent`` and ``ScoredPrecedent`` wire models are deliberately
embedded rather than changed.  M5 adds durable authority, lifecycle, and
retrieval documents around those frozen snapshots.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self, TypeVar

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictFloat,
    StrictInt,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    RunMode,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
)
from labcourt.contracts.precedents import Precedent
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M5_PRECEDENTS = 9_999
MAX_M5_EMBEDDING_DIMENSIONS = 4_096
MAX_M5_VISUAL_EMBEDDINGS = 32
MAX_M5_RETRIEVAL_RESULTS = 100
MAX_M5_CITATION_SNAPSHOT_ENTRIES = 100_000
MAX_M5_CONFLICT_PAIR_COUNT = MAX_M5_PRECEDENTS * (MAX_M5_PRECEDENTS - 1) // 2

_ContractT = TypeVar("_ContractT", bound=FrozenContractModel)


def m5_precedent_active_head_root_sha256(
    *,
    run_id: str,
    heads: tuple[tuple[str, str, int], ...],
) -> Sha256Hex:
    """Hash one complete ACTIVE-head inventory independently of input order."""

    require_reference_token(run_id, "M5 conflict active-head run_id")
    if not isinstance(heads, tuple):
        raise TypeError("M5 conflict active heads must be a tuple")
    normalized: list[tuple[str, str, int]] = []
    for precedent_id, authority_id, revision in heads:
        require_reference_token(precedent_id, "M5 conflict active-head precedent_id")
        if (
            not isinstance(authority_id, str)
            or len(authority_id) != 64
            or any(character not in "0123456789abcdef" for character in authority_id)
        ):
            raise ValueError("M5 conflict active-head authority_id must be sha256")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise ValueError("M5 conflict active-head revision must be positive")
        normalized.append((precedent_id, authority_id, revision))
    ordered = tuple(sorted(normalized, key=lambda item: item[0]))
    precedent_ids = tuple(item[0] for item in ordered)
    if len(precedent_ids) != len(set(precedent_ids)):
        raise ValueError("M5 conflict active heads must contain unique precedent IDs")
    return sha256_hex(
        [
            "m5-precedent-conflict-active-head-root",
            1,
            run_id,
            [list(item) for item in ordered],
        ]
    )


class M5EmbeddingChannel(StrEnum):
    TEXT = "TEXT"
    VISUAL = "VISUAL"


class M5PrecedentActivationOutcome(StrEnum):
    ACTIVATED = "ACTIVATED"
    TOO_EARLY = "TOO_EARLY"
    APPEAL_PRESENT = "APPEAL_PRESENT"
    NOT_AUTOMATIC = "NOT_AUTOMATIC"
    NOT_PROVISIONAL = "NOT_PROVISIONAL"


class M5PrecedentConflictOutcome(StrEnum):
    NO_CONFLICT = "NO_CONFLICT"
    NEW_INVALIDATED = "NEW_INVALIDATED"
    EXISTING_INVALIDATED = "EXISTING_INVALIDATED"
    PEER_CONFLICT = "PEER_CONFLICT"


class M5PrecedentRevocationOutcome(StrEnum):
    REVOKED = "REVOKED"
    ALREADY_REVOKED = "ALREADY_REVOKED"


class M5PrecedentCandidateDisposition(StrEnum):
    """Exhaustive disposition for one exact retrieval input authority."""

    SCOPE_EXCLUDED = "SCOPE_EXCLUDED"
    STATUS_EXCLUDED = "STATUS_EXCLUDED"
    UNSCORABLE = "UNSCORABLE"
    SCORED = "SCORED"


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware UTC")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{name} must use UTC")
    return value


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_claimed_digest(
    value: object,
    handler: ModelWrapValidatorHandler[_ContractT],
    *,
    field_name: str,
) -> _ContractT:
    if not isinstance(value, dict):
        return handler(value)
    payload = dict(value)
    claimed_present = field_name in payload
    claimed = payload.pop(field_name, None)
    document = handler(payload)
    expected = getattr(document, field_name)
    if claimed_present and (not isinstance(claimed, str) or claimed != expected):
        raise ValueError(f"serialized {field_name} does not match document content")
    return document


class M5EmbeddingRequest(FrozenContractModel):
    schema_version: Literal["m5-embedding-request-v1"] = "m5-embedding-request-v1"
    channel: M5EmbeddingChannel
    input_ref: ReferenceToken
    input_sha256: Sha256Hex
    model_manifest_id: Sha256Hex
    dimensions: int = Field(gt=0, le=MAX_M5_EMBEDDING_DIMENSIONS, strict=True)
    algorithm: Literal["FAKE_SHA256_SIGNED_PROJECTION_V1"] = "FAKE_SHA256_SIGNED_PROJECTION_V1"

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_request_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="request_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-embedding-request",
                1,
                self.channel,
                self.input_ref,
                self.input_sha256,
                self.model_manifest_id,
                self.dimensions,
                self.algorithm,
            ]
        )


class M5EmbeddingVector(FrozenContractModel):
    schema_version: Literal["m5-embedding-vector-v1"] = "m5-embedding-vector-v1"
    request: M5EmbeddingRequest
    values: tuple[StrictFloat, ...] = Field(
        min_length=1,
        max_length=MAX_M5_EMBEDDING_DIMENSIONS,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_embedding_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="embedding_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def embedding_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-embedding-vector",
                1,
                self.request.model_dump(mode="json"),
                self.values,
            ]
        )

    @model_validator(mode="after")
    def validate_vector(self) -> M5EmbeddingVector:
        if len(self.values) != self.request.dimensions:
            raise ValueError("embedding vector dimensions do not match its request")
        if not any(value != 0.0 for value in self.values):
            raise ValueError("embedding vector must have a non-zero norm")
        return self


class M5PrecedentPolicy(FrozenContractModel):
    schema_version: Literal["m5-precedent-policy-v1"] = "m5-precedent-policy-v1"
    config_sha256: Sha256Hex
    text_weight: StrictFloat = Field(ge=0, le=1)
    visual_weight: StrictFloat = Field(ge=0, le=1)
    source_weights: dict[PrecedentSource, StrictFloat]
    source_priorities: dict[PrecedentSource, StrictInt]
    conflict_similarity: StrictFloat = Field(ge=-1, le=1)
    automatic_activation_delay_seconds: int = Field(
        ge=0,
        le=10 * 366 * 24 * 60 * 60,
        strict=True,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_policy_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="policy_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def policy_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-policy",
                1,
                self.config_sha256,
                self.text_weight,
                self.visual_weight,
                {
                    source.value: value
                    for source, value in sorted(
                        self.source_weights.items(), key=lambda item: item[0].value
                    )
                },
                {
                    source.value: value
                    for source, value in sorted(
                        self.source_priorities.items(), key=lambda item: item[0].value
                    )
                },
                self.conflict_similarity,
                self.automatic_activation_delay_seconds,
            ]
        )

    @model_validator(mode="after")
    def validate_policy(self) -> M5PrecedentPolicy:
        if abs(self.text_weight + self.visual_weight - 1.0) > 1e-12:
            raise ValueError("M5 text and visual weights must sum to one")
        if set(self.source_weights) != set(PrecedentSource):
            raise ValueError("M5 source weights must define every precedent source")
        if set(self.source_priorities) != set(PrecedentSource):
            raise ValueError("M5 source priorities must define every precedent source")
        if any(not 0 < value <= 10 for value in self.source_weights.values()):
            raise ValueError("M5 source weights must be in (0, 10]")
        if any(
            isinstance(value, bool) or not 0 <= value <= 1_000
            for value in self.source_priorities.values()
        ):
            raise ValueError("M5 source priorities must be integer values in [0, 1000]")
        return self


class M5PrecedentAuthority(FrozenContractModel):
    schema_version: Literal["m5-precedent-authority-v1"] = "m5-precedent-authority-v1"
    run_id: ReferenceToken
    config_sha256: Sha256Hex
    revision: int = Field(gt=0, strict=True)
    precedent: Precedent
    created_at: datetime
    activation_not_before: datetime | None = None
    activated_at: datetime | None = None
    text_embedding: M5EmbeddingVector | None = None
    visual_embeddings: tuple[M5EmbeddingVector, ...] = Field(
        default=(),
        max_length=MAX_M5_VISUAL_EMBEDDINGS,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="authority_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-authority",
                1,
                self.run_id,
                self.config_sha256,
                self.revision,
                self.precedent.model_dump(mode="json"),
                self.created_at.isoformat(),
                self.activation_not_before.isoformat() if self.activation_not_before else None,
                self.activated_at.isoformat() if self.activated_at else None,
                (
                    self.text_embedding.model_dump(mode="json")
                    if self.text_embedding is not None
                    else None
                ),
                [embedding.model_dump(mode="json") for embedding in self.visual_embeddings],
            ]
        )

    @field_validator("created_at", "activation_not_before", "activated_at")
    @classmethod
    def validate_utc_times(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _require_utc(value, "M5 precedent authority timestamp")

    @model_validator(mode="after")
    def validate_authority(self) -> M5PrecedentAuthority:
        require_reference_token(self.precedent.precedent_id, "M5 precedent_id")
        require_reference_token(self.precedent.rule_version, "M5 precedent rule_version")
        if self.precedent.source_case_id is not None:
            require_reference_token(self.precedent.source_case_id, "M5 precedent source_case_id")
        if self.precedent.citation_count != 0:
            raise ValueError(
                "M5 precedent citation_count is a frozen compatibility field and must be zero"
            )

        if self.text_embedding is not None:
            if self.text_embedding.request.channel != M5EmbeddingChannel.TEXT:
                raise ValueError("M5 text embedding must use the TEXT channel")
            if self.precedent.text_embedding_ref != self.text_embedding.embedding_id:
                raise ValueError("M5 text embedding reference does not match authority content")
        elif self.precedent.text_embedding_ref is not None:
            raise ValueError("M5 authority is missing its referenced text embedding")

        visual_ids = tuple(item.embedding_id for item in self.visual_embeddings)
        if any(
            item.request.channel != M5EmbeddingChannel.VISUAL for item in self.visual_embeddings
        ):
            raise ValueError("M5 visual embeddings must use the VISUAL channel")
        if len(visual_ids) != len(set(visual_ids)):
            raise ValueError("M5 visual embeddings must be unique")
        if visual_ids != tuple(sorted(visual_ids)):
            raise ValueError("M5 visual embeddings must use stable embedding_id order")
        if self.precedent.visual_embedding_refs != visual_ids:
            raise ValueError("M5 visual embedding references do not match authority content")

        if self.activation_not_before is not None and self.activation_not_before < self.created_at:
            raise ValueError("M5 activation eligibility cannot precede authority creation")
        if self.activated_at is not None and self.activated_at < self.created_at:
            raise ValueError("M5 activation cannot precede authority creation")
        if (
            self.activation_not_before is not None
            and self.activated_at is not None
            and self.activated_at < self.activation_not_before
        ):
            raise ValueError("M5 activation cannot precede its cooling period")

        status = self.precedent.status
        if self.precedent.source == PrecedentSource.AUTOMATIC:
            if self.precedent.source_case_id is None:
                raise ValueError("automatic M5 precedent requires a source case")
            if self.activation_not_before is None:
                raise ValueError("automatic M5 precedent requires activation eligibility")
        elif status == PrecedentStatus.PROVISIONAL:
            raise ValueError("only automatic M5 precedents may be provisional")

        terminal = {
            PrecedentStatus.CONFLICT,
            PrecedentStatus.INVALIDATED,
            PrecedentStatus.REVOKED,
        }
        if status == PrecedentStatus.PROVISIONAL:
            if self.activated_at is not None or self.precedent.activation_at is not None:
                raise ValueError("provisional M5 precedent cannot claim activation")
            if self.precedent.invalidated_by is not None:
                raise ValueError("provisional M5 precedent cannot claim invalidation")
        elif status == PrecedentStatus.ACTIVE:
            if self.activated_at is None or self.precedent.activation_at != _canonical_utc(
                self.activated_at
            ):
                raise ValueError("active M5 precedent must preserve canonical activation")
        elif (self.activated_at is None) != (self.precedent.activation_at is None):
            raise ValueError("terminal M5 precedent activation fields must remain paired")
        elif self.activated_at is not None and self.precedent.activation_at != _canonical_utc(
            self.activated_at
        ):
            raise ValueError("terminal M5 precedent must preserve canonical activation")
        elif self.activated_at is None and self.precedent.source != PrecedentSource.AUTOMATIC:
            raise ValueError("only never-activated automatic precedent may terminate unactivated")

        if status in terminal:
            if self.precedent.invalidated_by is None:
                raise ValueError("terminal M5 precedent requires invalidated_by authority")
            require_reference_token(
                self.precedent.invalidated_by,
                "M5 precedent invalidated_by",
            )
        elif self.precedent.invalidated_by is not None:
            raise ValueError("visible M5 precedent cannot claim invalidated_by")
        return self


class M5PrecedentRetrievalQuery(FrozenContractModel):
    schema_version: Literal["m5-precedent-retrieval-query-v1"] = "m5-precedent-retrieval-query-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    evidence_class: EvidenceClass
    rule_version: ReferenceToken
    situation_text: str = Field(min_length=1, max_length=16_384)
    text_embedding_model_manifest_id: Sha256Hex
    visual_embedding_model_manifest_id: Sha256Hex
    text_embedding: M5EmbeddingVector | None = None
    visual_embeddings: tuple[M5EmbeddingVector, ...] = Field(
        default=(),
        max_length=MAX_M5_VISUAL_EMBEDDINGS,
    )
    policy: M5PrecedentPolicy
    top_k: int = Field(gt=0, le=MAX_M5_RETRIEVAL_RESULTS, strict=True)
    run_mode: RunMode = RunMode.STANDARD
    include_provisional_experiment: StrictBool = False

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_query_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="query_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def query_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-retrieval-query",
                1,
                self.run_id,
                self.case_id,
                self.evidence_class,
                self.rule_version,
                self.situation_text,
                self.text_embedding_model_manifest_id,
                self.visual_embedding_model_manifest_id,
                self.text_embedding.embedding_id if self.text_embedding else None,
                [item.embedding_id for item in self.visual_embeddings],
                self.policy.policy_id,
                self.top_k,
                self.run_mode,
                self.include_provisional_experiment,
            ]
        )

    @model_validator(mode="after")
    def validate_query(self) -> M5PrecedentRetrievalQuery:
        if self.text_embedding is not None and (
            self.text_embedding.request.channel != M5EmbeddingChannel.TEXT
        ):
            raise ValueError("M5 retrieval text embedding must use the TEXT channel")
        if self.text_embedding is not None and (
            self.text_embedding.request.model_manifest_id != self.text_embedding_model_manifest_id
        ):
            raise ValueError("M5 retrieval text embedding differs from its bound model manifest")
        if any(
            item.request.channel != M5EmbeddingChannel.VISUAL for item in self.visual_embeddings
        ):
            raise ValueError("M5 retrieval visual embeddings must use the VISUAL channel")
        if any(
            item.request.model_manifest_id != self.visual_embedding_model_manifest_id
            for item in self.visual_embeddings
        ):
            raise ValueError("M5 retrieval visual embedding differs from its bound model manifest")
        visual_ids = tuple(item.embedding_id for item in self.visual_embeddings)
        if len(visual_ids) != len(set(visual_ids)) or visual_ids != tuple(sorted(visual_ids)):
            raise ValueError("M5 retrieval visual embeddings must be unique and stably ordered")
        if self.text_embedding is None and not self.visual_embeddings:
            raise ValueError("M5 retrieval requires at least one embedding channel")
        if self.include_provisional_experiment and self.run_mode != RunMode.OFFLINE_EXPERIMENT:
            raise ValueError("provisional precedents require explicit OFFLINE_EXPERIMENT mode")
        return self


class M5ScoredPrecedent(FrozenContractModel):
    authority: M5PrecedentAuthority
    text_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    visual_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    normalized_text_weight: StrictFloat = Field(ge=0, le=1)
    normalized_visual_weight: StrictFloat = Field(ge=0, le=1)
    base_similarity: StrictFloat = Field(ge=-1, le=1)
    source_weight: StrictFloat = Field(gt=0, le=10)
    score: StrictFloat = Field(ge=-10, le=10)

    @model_validator(mode="after")
    def validate_fusion(self) -> M5ScoredPrecedent:
        if self.text_similarity is None and self.visual_similarity is None:
            raise ValueError("M5 scored precedent requires at least one shared channel")
        expected_text_weight = 0.0 if self.text_similarity is None else self.normalized_text_weight
        expected_visual_weight = (
            0.0 if self.visual_similarity is None else self.normalized_visual_weight
        )
        if self.normalized_text_weight != expected_text_weight:
            raise ValueError("missing M5 text channel must receive zero normalized weight")
        if self.normalized_visual_weight != expected_visual_weight:
            raise ValueError("missing M5 visual channel must receive zero normalized weight")
        if abs(expected_text_weight + expected_visual_weight - 1.0) > 1e-12:
            raise ValueError("available M5 channels must be renormalized to one")
        expected_base = expected_text_weight * (self.text_similarity or 0.0) + (
            expected_visual_weight * (self.visual_similarity or 0.0)
        )
        if abs(self.base_similarity - expected_base) > 1e-12:
            raise ValueError("M5 base similarity conflicts with normalized channel fusion")
        if abs(self.score - self.base_similarity * self.source_weight) > 1e-12:
            raise ValueError("M5 score must equal base similarity times source weight")
        return self


class M5PrecedentCandidateEvaluation(FrozenContractModel):
    """Content-addressed evaluation of every authority supplied to retrieval."""

    schema_version: Literal["m5-precedent-candidate-evaluation-v1"] = (
        "m5-precedent-candidate-evaluation-v1"
    )
    authority: M5PrecedentAuthority
    disposition: M5PrecedentCandidateDisposition
    text_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    visual_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    normalized_text_weight: StrictFloat | None = Field(default=None, ge=0, le=1)
    normalized_visual_weight: StrictFloat | None = Field(default=None, ge=0, le=1)
    base_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    source_weight: StrictFloat | None = Field(default=None, gt=0, le=10)
    score: StrictFloat | None = Field(default=None, ge=-10, le=10)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_evaluation_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="evaluation_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evaluation_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-candidate-evaluation",
                1,
                self.authority.authority_id,
                self.disposition,
                self.text_similarity,
                self.visual_similarity,
                self.normalized_text_weight,
                self.normalized_visual_weight,
                self.base_similarity,
                self.source_weight,
                self.score,
            ]
        )

    @model_validator(mode="after")
    def validate_evaluation(self) -> M5PrecedentCandidateEvaluation:
        metrics = (
            self.text_similarity,
            self.visual_similarity,
            self.normalized_text_weight,
            self.normalized_visual_weight,
            self.base_similarity,
            self.source_weight,
            self.score,
        )
        if self.disposition != M5PrecedentCandidateDisposition.SCORED:
            if any(value is not None for value in metrics):
                raise ValueError("non-scored M5 candidate evaluation cannot claim score metrics")
            return self
        if any(
            value is None
            for value in (
                self.normalized_text_weight,
                self.normalized_visual_weight,
                self.base_similarity,
                self.source_weight,
                self.score,
            )
        ):
            raise ValueError("scored M5 candidate evaluation requires complete fusion metrics")
        M5ScoredPrecedent(
            authority=self.authority,
            text_similarity=self.text_similarity,
            visual_similarity=self.visual_similarity,
            normalized_text_weight=self.normalized_text_weight,
            normalized_visual_weight=self.normalized_visual_weight,
            base_similarity=self.base_similarity,
            source_weight=self.source_weight,
            score=self.score,
        )
        return self

    def as_scored_precedent(self) -> M5ScoredPrecedent:
        if self.disposition != M5PrecedentCandidateDisposition.SCORED:
            raise ValueError("only a scored M5 candidate has a ranking projection")
        assert self.normalized_text_weight is not None
        assert self.normalized_visual_weight is not None
        assert self.base_similarity is not None
        assert self.source_weight is not None
        assert self.score is not None
        return M5ScoredPrecedent(
            authority=self.authority,
            text_similarity=self.text_similarity,
            visual_similarity=self.visual_similarity,
            normalized_text_weight=self.normalized_text_weight,
            normalized_visual_weight=self.normalized_visual_weight,
            base_similarity=self.base_similarity,
            source_weight=self.source_weight,
            score=self.score,
        )


class M5PrecedentRetrievalResult(FrozenContractModel):
    schema_version: Literal["m5-precedent-retrieval-result-v1"] = "m5-precedent-retrieval-result-v1"
    query: M5PrecedentRetrievalQuery
    candidate_evaluations: tuple[M5PrecedentCandidateEvaluation, ...] = Field(
        max_length=MAX_M5_PRECEDENTS,
    )
    scored_precedents: tuple[M5ScoredPrecedent, ...] = Field(
        default=(),
        max_length=MAX_M5_RETRIEVAL_RESULTS,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_result_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claims = {
            name: payload.pop(name, None)
            for name in (
                "candidate_count",
                "eligible_count",
                "unscorable_count",
                "result_id",
            )
            if name in payload
        }
        document = handler(payload)
        for name, claimed in claims.items():
            expected = getattr(document, name)
            if (
                name != "result_id" and (isinstance(claimed, bool) or not isinstance(claimed, int))
            ) or claimed != expected:
                raise ValueError(f"serialized {name} does not match retrieval inventory")
        return document

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_count(self) -> int:
        return len(self.candidate_evaluations)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def eligible_count(self) -> int:
        return sum(
            item.disposition
            in {
                M5PrecedentCandidateDisposition.UNSCORABLE,
                M5PrecedentCandidateDisposition.SCORED,
            }
            for item in self.candidate_evaluations
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def unscorable_count(self) -> int:
        return sum(
            item.disposition == M5PrecedentCandidateDisposition.UNSCORABLE
            for item in self.candidate_evaluations
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def result_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-retrieval-result",
                1,
                self.query.query_id,
                self.candidate_count,
                self.eligible_count,
                self.unscorable_count,
                [item.model_dump(mode="json") for item in self.candidate_evaluations],
                [item.model_dump(mode="json") for item in self.scored_precedents],
            ]
        )

    @model_validator(mode="after")
    def validate_result(self) -> M5PrecedentRetrievalResult:
        identifiers = tuple(
            item.authority.precedent.precedent_id for item in self.candidate_evaluations
        )
        if identifiers != tuple(sorted(identifiers)) or len(identifiers) != len(set(identifiers)):
            raise ValueError(
                "M5 candidate evaluations must be unique and stably ordered by precedent_id"
            )
        allowed_statuses = {PrecedentStatus.ACTIVE}
        if self.query.include_provisional_experiment:
            allowed_statuses.add(PrecedentStatus.PROVISIONAL)
        for item in self.candidate_evaluations:
            precedent = item.authority.precedent
            if item.authority.run_id != self.query.run_id:
                raise ValueError("M5 candidate precedent belongs to another run")
            if item.authority.config_sha256 != self.query.policy.config_sha256:
                raise ValueError("M5 candidate precedent uses another config authority")
            if (
                precedent.evidence_class != self.query.evidence_class
                or precedent.rule_version != self.query.rule_version
            ):
                expected = M5PrecedentCandidateDisposition.SCOPE_EXCLUDED
            elif precedent.status not in allowed_statuses:
                expected = M5PrecedentCandidateDisposition.STATUS_EXCLUDED
            else:
                has_text = (
                    self.query.policy.text_weight > 0
                    and self.query.text_embedding is not None
                    and item.authority.text_embedding is not None
                )
                has_visual = (
                    self.query.policy.visual_weight > 0
                    and bool(self.query.visual_embeddings)
                    and bool(item.authority.visual_embeddings)
                )
                expected = (
                    M5PrecedentCandidateDisposition.SCORED
                    if has_text or has_visual
                    else M5PrecedentCandidateDisposition.UNSCORABLE
                )
            if item.disposition != expected:
                raise ValueError("M5 candidate disposition conflicts with its deterministic state")
            if item.disposition == M5PrecedentCandidateDisposition.SCORED:
                if item.source_weight != self.query.policy.source_weights[precedent.source]:
                    raise ValueError("M5 candidate score uses the wrong source weight")
                expected_text = (
                    self.query.text_embedding is not None
                    and item.authority.text_embedding is not None
                )
                expected_visual = bool(
                    self.query.visual_embeddings and item.authority.visual_embeddings
                )
                if (item.text_similarity is not None) != expected_text or (
                    item.visual_similarity is not None
                ) != expected_visual:
                    raise ValueError("M5 candidate score omits or invents a shared channel")
        ranked = tuple(
            sorted(
                (
                    item.as_scored_precedent()
                    for item in self.candidate_evaluations
                    if item.disposition == M5PrecedentCandidateDisposition.SCORED
                ),
                key=lambda item: (-item.score, item.authority.precedent.precedent_id),
            )[: self.query.top_k]
        )
        if self.scored_precedents != ranked:
            raise ValueError(
                "M5 visible ranking must be the exact stable top_k projection of full inventory"
            )
        return self


class M5PrecedentCitationAuthority(FrozenContractModel):
    schema_version: Literal["m5-precedent-citation-authority-v1"] = (
        "m5-precedent-citation-authority-v1"
    )
    run_id: ReferenceToken
    case_id: ReferenceToken
    precedent_id: ReferenceToken
    precedent_authority_id: Sha256Hex
    precedent_revision: int = Field(gt=0, strict=True)
    query_id: Sha256Hex
    score: StrictFloat = Field(ge=-10, le=10)
    cited_at: datetime

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_citation_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="citation_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def citation_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-citation",
                1,
                self.run_id,
                self.case_id,
                self.precedent_id,
                self.precedent_authority_id,
                self.precedent_revision,
                self.query_id,
                self.score,
                self.cited_at.isoformat(),
            ]
        )

    @field_validator("cited_at")
    @classmethod
    def validate_cited_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "M5 citation timestamp")


class M5PrecedentCitationCommit(FrozenContractModel):
    schema_version: Literal["m5-precedent-citation-commit-v1"] = "m5-precedent-citation-commit-v1"
    retrieval_result: M5PrecedentRetrievalResult
    citation: M5PrecedentCitationAuthority

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_commit_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="commit_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-citation-commit",
                1,
                self.retrieval_result.result_id,
                self.citation.model_dump(mode="json"),
            ]
        )

    @model_validator(mode="after")
    def validate_commit(self) -> M5PrecedentCitationCommit:
        selected = next(
            (
                item
                for item in self.retrieval_result.scored_precedents
                if item.authority.precedent.precedent_id == self.citation.precedent_id
            ),
            None,
        )
        if (
            selected is None
            or self.retrieval_result.query.run_id != self.citation.run_id
            or self.retrieval_result.query.case_id != self.citation.case_id
            or self.retrieval_result.query.query_id != self.citation.query_id
            or selected.score != self.citation.score
            or selected.authority.authority_id != self.citation.precedent_authority_id
            or selected.authority.revision != self.citation.precedent_revision
        ):
            raise ValueError("M5 citation commit has inconsistent historical authority bindings")
        if self.citation.cited_at < selected.authority.created_at or (
            selected.authority.precedent.status == PrecedentStatus.ACTIVE
            and (
                selected.authority.activated_at is None
                or self.citation.cited_at < selected.authority.activated_at
            )
        ):
            raise ValueError("M5 citation cannot precede its historical authority visibility")
        return self


class M5PrecedentCitationSnapshot(FrozenContractModel):
    schema_version: Literal["m5-precedent-citation-snapshot-v1"] = (
        "m5-precedent-citation-snapshot-v1"
    )
    run_id: ReferenceToken
    precedent_id: ReferenceToken
    captured_at: datetime
    complete: Literal[True] = True
    citations: tuple[M5PrecedentCitationAuthority, ...] = Field(
        default=(),
        max_length=MAX_M5_CITATION_SNAPSHOT_ENTRIES,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_snapshot_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_count_present = "observed_citation_count" in payload
        claimed_count = payload.pop("observed_citation_count", None)
        snapshot = _validate_claimed_digest(payload, handler, field_name="snapshot_id")
        if claimed_count_present and (
            isinstance(claimed_count, bool)
            or not isinstance(claimed_count, int)
            or claimed_count != snapshot.observed_citation_count
        ):
            raise ValueError("serialized observed citation count differs from complete inventory")
        return snapshot

    @computed_field  # type: ignore[prop-decorator]
    @property
    def observed_citation_count(self) -> int:
        """Derived observation only; never part of precedent semantic authority."""

        return len(self.citations)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def snapshot_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-citation-snapshot",
                1,
                self.run_id,
                self.precedent_id,
                self.captured_at.isoformat(),
                self.observed_citation_count,
                [item.citation_id for item in self.citations],
            ]
        )

    @field_validator("captured_at")
    @classmethod
    def validate_captured_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "M5 citation snapshot timestamp")

    @model_validator(mode="after")
    def validate_snapshot(self) -> M5PrecedentCitationSnapshot:
        keys = tuple((item.case_id, item.citation_id) for item in self.citations)
        if len(keys) != len(set(keys)):
            raise ValueError("M5 citation snapshot must not contain duplicate citations")
        if keys != tuple(sorted(keys)):
            raise ValueError("M5 citation snapshot must use stable (case_id, citation_id) order")
        if any(
            item.run_id != self.run_id or item.precedent_id != self.precedent_id
            for item in self.citations
        ):
            raise ValueError("M5 citation snapshot contains a cross-scope citation")
        if any(item.cited_at > self.captured_at for item in self.citations):
            raise ValueError("M5 citation snapshot cannot observe a future citation")
        return self


class M5AppealWindowSnapshot(FrozenContractModel):
    schema_version: Literal["m5-appeal-window-snapshot-v1"] = "m5-appeal-window-snapshot-v1"
    run_id: ReferenceToken
    source_case_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    source_case_document_sha256: Sha256Hex
    observed_through: datetime
    complete: Literal[True] = True
    appeal_ids: tuple[ReferenceToken, ...] = Field(default=(), max_length=1_000)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_snapshot_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="snapshot_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def snapshot_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-appeal-window-snapshot",
                1,
                self.run_id,
                self.source_case_id,
                self.source_case_revision,
                self.source_case_document_sha256,
                self.observed_through.isoformat(),
                self.appeal_ids,
            ]
        )

    @field_validator("observed_through")
    @classmethod
    def validate_observed_through(cls, value: datetime) -> datetime:
        return _require_utc(value, "M5 appeal snapshot timestamp")

    @model_validator(mode="after")
    def validate_appeals(self) -> M5AppealWindowSnapshot:
        if len(self.appeal_ids) != len(set(self.appeal_ids)):
            raise ValueError("M5 appeal snapshot IDs must be unique")
        if self.appeal_ids != tuple(sorted(self.appeal_ids)):
            raise ValueError("M5 appeal snapshot IDs must use stable order")
        return self


class M5PrecedentActivationReceipt(FrozenContractModel):
    schema_version: Literal["m5-precedent-activation-receipt-v1"] = (
        "m5-precedent-activation-receipt-v1"
    )
    run_id: ReferenceToken
    precedent_id: ReferenceToken
    prior_authority_id: Sha256Hex
    prior_revision: int = Field(gt=0, strict=True)
    appeal_snapshot_id: Sha256Hex
    evaluated_at: datetime
    outcome: M5PrecedentActivationOutcome
    resulting_authority_id: Sha256Hex
    resulting_revision: int = Field(gt=0, strict=True)
    status_before: PrecedentStatus
    status_after: PrecedentStatus

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="receipt_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"receipt_id"})
        return sha256_hex(["m5-precedent-activation-receipt", 1, payload])

    @field_validator("evaluated_at")
    @classmethod
    def validate_evaluated_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "M5 activation evaluation timestamp")

    @model_validator(mode="after")
    def validate_transition(self) -> M5PrecedentActivationReceipt:
        if self.outcome == M5PrecedentActivationOutcome.ACTIVATED:
            if (
                self.status_before != PrecedentStatus.PROVISIONAL
                or self.status_after != PrecedentStatus.ACTIVE
                or self.resulting_revision != self.prior_revision + 1
                or self.resulting_authority_id == self.prior_authority_id
            ):
                raise ValueError("M5 activation receipt does not describe PROVISIONAL -> ACTIVE")
        elif (
            self.status_after != self.status_before
            or self.resulting_revision != self.prior_revision
            or self.resulting_authority_id != self.prior_authority_id
        ):
            raise ValueError("non-activating M5 evaluation cannot mutate precedent authority")
        return self


class M5PrecedentActivationResult(FrozenContractModel):
    appeal_snapshot: M5AppealWindowSnapshot
    receipt: M5PrecedentActivationReceipt
    authority: M5PrecedentAuthority

    @model_validator(mode="after")
    def validate_result(self) -> M5PrecedentActivationResult:
        if (
            self.appeal_snapshot.snapshot_id != self.receipt.appeal_snapshot_id
            or self.appeal_snapshot.run_id != self.receipt.run_id
            or self.appeal_snapshot.observed_through != self.receipt.evaluated_at
            or (
                self.authority.precedent.source_case_id is not None
                and self.appeal_snapshot.source_case_id != self.authority.precedent.source_case_id
            )
            or self.authority.run_id != self.receipt.run_id
            or self.authority.precedent.precedent_id != self.receipt.precedent_id
            or self.authority.authority_id != self.receipt.resulting_authority_id
            or self.authority.revision != self.receipt.resulting_revision
            or self.authority.precedent.status != self.receipt.status_after
        ):
            raise ValueError("M5 activation result conflicts with its receipt")
        return self


class M5PrecedentConflictReceipt(FrozenContractModel):
    schema_version: Literal["m5-precedent-conflict-receipt-v1"] = "m5-precedent-conflict-receipt-v1"
    run_id: ReferenceToken
    policy_id: Sha256Hex
    existing_precedent_id: ReferenceToken
    new_precedent_id: ReferenceToken
    existing_prior_authority_id: Sha256Hex
    new_prior_authority_id: Sha256Hex
    existing_prior_revision: int = Field(gt=0, strict=True)
    new_prior_revision: int = Field(gt=0, strict=True)
    text_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    visual_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    normalized_text_weight: StrictFloat = Field(ge=0, le=1)
    normalized_visual_weight: StrictFloat = Field(ge=0, le=1)
    similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    threshold: StrictFloat = Field(ge=-1, le=1)
    existing_priority: int = Field(ge=0, le=1_000, strict=True)
    new_priority: int = Field(ge=0, le=1_000, strict=True)
    outcome: M5PrecedentConflictOutcome
    existing_resulting_authority_id: Sha256Hex
    new_resulting_authority_id: Sha256Hex
    existing_resulting_revision: int = Field(gt=0, strict=True)
    new_resulting_revision: int = Field(gt=0, strict=True)
    existing_status_after: PrecedentStatus
    new_status_after: PrecedentStatus

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="receipt_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"receipt_id"})
        return sha256_hex(["m5-precedent-conflict-receipt", 1, payload])

    @model_validator(mode="after")
    def validate_similarity(self) -> M5PrecedentConflictReceipt:
        if self.similarity is None:
            if self.text_similarity is not None or self.visual_similarity is not None:
                raise ValueError("unscorable M5 conflict cannot expose channel similarities")
            if self.normalized_text_weight or self.normalized_visual_weight:
                raise ValueError("unscorable M5 conflict cannot expose normalized weights")
        else:
            if self.text_similarity is None and self.visual_similarity is None:
                raise ValueError("scorable M5 conflict requires a shared channel")
            expected_text_weight = (
                0.0 if self.text_similarity is None else self.normalized_text_weight
            )
            expected_visual_weight = (
                0.0 if self.visual_similarity is None else self.normalized_visual_weight
            )
            if (
                expected_text_weight != self.normalized_text_weight
                or expected_visual_weight != self.normalized_visual_weight
                or abs(expected_text_weight + expected_visual_weight - 1.0) > 1e-12
            ):
                raise ValueError("M5 conflict channels are not correctly renormalized")
            expected_similarity = expected_text_weight * (self.text_similarity or 0.0) + (
                expected_visual_weight * (self.visual_similarity or 0.0)
            )
            if abs(expected_similarity - self.similarity) > 1e-12:
                raise ValueError("M5 conflict similarity conflicts with channel fusion")

        existing_changed = self.existing_resulting_authority_id != (
            self.existing_prior_authority_id
        )
        new_changed = self.new_resulting_authority_id != self.new_prior_authority_id
        expected_changes = {
            M5PrecedentConflictOutcome.NO_CONFLICT: (False, False),
            M5PrecedentConflictOutcome.NEW_INVALIDATED: (False, True),
            M5PrecedentConflictOutcome.EXISTING_INVALIDATED: (True, False),
            M5PrecedentConflictOutcome.PEER_CONFLICT: (True, True),
        }[self.outcome]
        if (existing_changed, new_changed) != expected_changes:
            raise ValueError("M5 conflict outcome conflicts with changed authorities")
        expected_existing_revision = self.existing_prior_revision + int(existing_changed)
        expected_new_revision = self.new_prior_revision + int(new_changed)
        if (
            self.existing_resulting_revision != expected_existing_revision
            or self.new_resulting_revision != expected_new_revision
        ):
            raise ValueError("M5 conflict authority revisions do not match outcome")
        expected_statuses = {
            M5PrecedentConflictOutcome.NO_CONFLICT: (
                PrecedentStatus.ACTIVE,
                PrecedentStatus.ACTIVE,
            ),
            M5PrecedentConflictOutcome.NEW_INVALIDATED: (
                PrecedentStatus.ACTIVE,
                PrecedentStatus.INVALIDATED,
            ),
            M5PrecedentConflictOutcome.EXISTING_INVALIDATED: (
                PrecedentStatus.INVALIDATED,
                PrecedentStatus.ACTIVE,
            ),
            M5PrecedentConflictOutcome.PEER_CONFLICT: (
                PrecedentStatus.CONFLICT,
                PrecedentStatus.CONFLICT,
            ),
        }[self.outcome]
        if (self.existing_status_after, self.new_status_after) != expected_statuses:
            raise ValueError("M5 conflict statuses do not match outcome")
        return self


class M5PrecedentConflictResolution(FrozenContractModel):
    policy: M5PrecedentPolicy
    receipt: M5PrecedentConflictReceipt
    existing_authority: M5PrecedentAuthority
    new_authority: M5PrecedentAuthority

    @model_validator(mode="after")
    def validate_resolution(self) -> M5PrecedentConflictResolution:
        receipt = self.receipt
        if (
            self.policy.policy_id != receipt.policy_id
            or self.existing_authority.run_id != receipt.run_id
            or self.new_authority.run_id != receipt.run_id
            or self.existing_authority.precedent.precedent_id != receipt.existing_precedent_id
            or self.new_authority.precedent.precedent_id != receipt.new_precedent_id
            or self.existing_authority.authority_id != receipt.existing_resulting_authority_id
            or self.new_authority.authority_id != receipt.new_resulting_authority_id
            or self.existing_authority.revision != receipt.existing_resulting_revision
            or self.new_authority.revision != receipt.new_resulting_revision
            or self.existing_authority.precedent.status != receipt.existing_status_after
            or self.new_authority.precedent.status != receipt.new_status_after
        ):
            raise ValueError("M5 conflict authorities conflict with their receipt")
        return self


class M5PrecedentConflictCandidateAuthority(FrozenContractModel):
    """One exact ACTIVE head in a complete conflict-scan snapshot."""

    precedent_id: ReferenceToken
    authority_id: Sha256Hex
    revision: int = Field(gt=0, strict=True)
    source: PrecedentSource
    source_priority: int = Field(ge=0, le=1_000, strict=True)
    evidence_class: EvidenceClass
    violation_type: ViolationType
    rule_version: ReferenceToken
    decision_direction: VerdictDecision

    @model_validator(mode="after")
    def validate_candidate(self) -> M5PrecedentConflictCandidateAuthority:
        require_reference_token(self.precedent_id, "M5 conflict candidate precedent_id")
        require_reference_token(self.rule_version, "M5 conflict candidate rule_version")
        return self

    @property
    def sort_key(self) -> str:
        return self.precedent_id


class M5PrecedentConflictCausalCut(FrozenContractModel):
    """Authority-only ledger watermark and complete ACTIVE-head root."""

    schema_version: Literal["m5-precedent-conflict-causal-cut-v1"] = (
        "m5-precedent-conflict-causal-cut-v1"
    )
    run_id: ReferenceToken
    manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    policy_id: Sha256Hex
    authority_event_sequence: int = Field(ge=0, strict=True)
    authority_event_sha256: Sha256Hex
    active_head_count: int = Field(ge=0, le=MAX_M5_PRECEDENTS, strict=True)
    active_head_root_sha256: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_cut_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="cut_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cut_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-precedent-conflict-causal-cut",
                1,
                self.run_id,
                self.manifest_id,
                self.config_sha256,
                self.policy_id,
                self.authority_event_sequence,
                self.authority_event_sha256,
                self.active_head_count,
                self.active_head_root_sha256,
            ]
        )

    @model_validator(mode="after")
    def validate_cut(self) -> M5PrecedentConflictCausalCut:
        require_reference_token(self.run_id, "M5 conflict causal cut run_id")
        is_zero_sequence = self.authority_event_sequence == 0
        is_genesis = self.authority_event_sha256 == M5_PRECEDENT_CAUSAL_GENESIS_SHA256
        if is_zero_sequence != is_genesis:
            raise ValueError(
                "zero authority watermark must use genesis and later watermarks must not"
            )
        if is_zero_sequence and self.active_head_count != 0:
            raise ValueError("zero authority watermark cannot contain ACTIVE heads")
        return self


class M5PrecedentConflictSnapshot(FrozenContractModel):
    """One complete, stably ordered ACTIVE authority inventory at a causal cut."""

    schema_version: Literal["m5-precedent-conflict-snapshot-v1"] = (
        "m5-precedent-conflict-snapshot-v1"
    )
    causal_cut: M5PrecedentConflictCausalCut
    authorities: tuple[M5PrecedentAuthority, ...] = Field(
        default=(),
        max_length=MAX_M5_PRECEDENTS,
    )

    @model_validator(mode="after")
    def validate_snapshot(self) -> M5PrecedentConflictSnapshot:
        keys = tuple(item.precedent.precedent_id for item in self.authorities)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("M5 conflict snapshot authorities must be unique and stably ordered")
        cut = self.causal_cut
        if len(self.authorities) != cut.active_head_count or any(
            item.run_id != cut.run_id
            or item.config_sha256 != cut.config_sha256
            or item.precedent.status != PrecedentStatus.ACTIVE
            for item in self.authorities
        ):
            raise ValueError("M5 conflict snapshot is outside its ACTIVE causal cut")
        root = m5_precedent_active_head_root_sha256(
            run_id=cut.run_id,
            heads=tuple(
                (
                    item.precedent.precedent_id,
                    item.authority_id,
                    item.revision,
                )
                for item in self.authorities
            ),
        )
        if root != cut.active_head_root_sha256:
            raise ValueError("M5 conflict snapshot differs from its ACTIVE head root")
        return self


class M5PrecedentConflictEdge(FrozenContractModel):
    """One threshold-qualified opposite-direction edge in the complete graph."""

    left_precedent_id: ReferenceToken
    right_precedent_id: ReferenceToken
    left_authority_id: Sha256Hex
    right_authority_id: Sha256Hex
    left_priority: int = Field(ge=0, le=1_000, strict=True)
    right_priority: int = Field(ge=0, le=1_000, strict=True)
    text_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    visual_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    normalized_text_weight: StrictFloat = Field(ge=0, le=1)
    normalized_visual_weight: StrictFloat = Field(ge=0, le=1)
    similarity: StrictFloat = Field(ge=-1, le=1)
    threshold: StrictFloat = Field(ge=-1, le=1)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_edge_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="edge_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def edge_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"edge_id"})
        return sha256_hex(["m5-precedent-conflict-edge", 1, payload])

    @model_validator(mode="after")
    def validate_edge(self) -> M5PrecedentConflictEdge:
        if self.left_precedent_id >= self.right_precedent_id:
            raise ValueError("M5 conflict edge endpoints must use stable precedent_id order")
        if self.text_similarity is None and self.visual_similarity is None:
            raise ValueError("M5 conflict edge requires a shared embedding channel")
        expected_text_weight = 0.0 if self.text_similarity is None else self.normalized_text_weight
        expected_visual_weight = (
            0.0 if self.visual_similarity is None else self.normalized_visual_weight
        )
        if (
            expected_text_weight != self.normalized_text_weight
            or expected_visual_weight != self.normalized_visual_weight
            or abs(expected_text_weight + expected_visual_weight - 1.0) > 1e-12
        ):
            raise ValueError("M5 conflict edge channels are not correctly renormalized")
        expected_similarity = expected_text_weight * (self.text_similarity or 0.0) + (
            expected_visual_weight * (self.visual_similarity or 0.0)
        )
        if abs(expected_similarity - self.similarity) > 1e-12:
            raise ValueError("M5 conflict edge similarity conflicts with channel fusion")
        if self.similarity < self.threshold:
            raise ValueError("M5 conflict edge is below the policy threshold")
        return self

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.left_precedent_id, self.right_precedent_id)


class M5PrecedentConflictBatchAuthority(FrozenContractModel):
    """Content-addressed evidence for one complete, budgeted ACTIVE snapshot."""

    schema_version: Literal["m5-precedent-conflict-batch-authority-v1"] = (
        "m5-precedent-conflict-batch-authority-v1"
    )
    run_id: ReferenceToken
    config_sha256: Sha256Hex
    policy_id: Sha256Hex
    causal_cut: M5PrecedentConflictCausalCut
    scan_limit: int = Field(gt=0, le=MAX_M5_PRECEDENTS, strict=True)
    candidates: tuple[M5PrecedentConflictCandidateAuthority, ...] = Field(
        default=(),
        max_length=MAX_M5_PRECEDENTS,
    )
    evaluated_pair_count: int = Field(ge=0, le=MAX_M5_CONFLICT_PAIR_COUNT, strict=True)
    edges: tuple[M5PrecedentConflictEdge, ...] = Field(
        default=(),
        max_length=MAX_M5_CONFLICT_PAIR_COUNT,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_batch_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="batch_authority_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def batch_authority_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"batch_authority_id"})
        return sha256_hex(["m5-precedent-conflict-batch-authority", 1, payload])

    @model_validator(mode="after")
    def validate_complete_graph(self) -> M5PrecedentConflictBatchAuthority:
        candidate_keys = tuple(item.sort_key for item in self.candidates)
        if candidate_keys != tuple(sorted(set(candidate_keys))):
            raise ValueError("M5 conflict batch candidates must be unique and stably ordered")
        cut = self.causal_cut
        candidate_root = m5_precedent_active_head_root_sha256(
            run_id=self.run_id,
            heads=tuple(
                (item.precedent_id, item.authority_id, item.revision) for item in self.candidates
            ),
        )
        if (
            cut.run_id != self.run_id
            or cut.config_sha256 != self.config_sha256
            or cut.policy_id != self.policy_id
            or cut.active_head_count != len(self.candidates)
            or cut.active_head_root_sha256 != candidate_root
        ):
            raise ValueError("M5 conflict batch differs from its complete causal cut")
        if len(self.candidates) > self.scan_limit:
            raise ValueError("M5 conflict batch exceeds its complete snapshot budget")
        maximum_pairs = len(self.candidates) * (len(self.candidates) - 1) // 2
        if self.evaluated_pair_count > maximum_pairs or len(self.edges) > self.evaluated_pair_count:
            raise ValueError("M5 conflict batch pair inventory is impossible")
        edge_keys = tuple(item.sort_key for item in self.edges)
        if edge_keys != tuple(sorted(set(edge_keys))):
            raise ValueError("M5 conflict batch edges must be unique and stably ordered")
        by_id = {item.precedent_id: item for item in self.candidates}
        for edge in self.edges:
            left = by_id.get(edge.left_precedent_id)
            right = by_id.get(edge.right_precedent_id)
            if (
                left is None
                or right is None
                or edge.left_authority_id != left.authority_id
                or edge.right_authority_id != right.authority_id
                or edge.left_priority != left.source_priority
                or edge.right_priority != right.source_priority
                or left.evidence_class != right.evidence_class
                or left.violation_type != right.violation_type
                or left.rule_version != right.rule_version
                or {left.decision_direction, right.decision_direction}
                != {VerdictDecision.ESTABLISHED, VerdictDecision.NOT_ESTABLISHED}
            ):
                raise ValueError("M5 conflict edge is outside its candidate authority graph")
        return self


class M5PrecedentConflictNodeResult(FrozenContractModel):
    """The unique graph-wide result selected for one candidate head."""

    precedent_id: ReferenceToken
    prior_authority_id: Sha256Hex
    prior_revision: int = Field(gt=0, strict=True)
    resulting_authority_id: Sha256Hex
    resulting_revision: int = Field(gt=0, strict=True)
    status_after: PrecedentStatus
    invalidated_by_precedent_id: ReferenceToken | None = None

    @model_validator(mode="after")
    def validate_result(self) -> M5PrecedentConflictNodeResult:
        require_reference_token(self.precedent_id, "M5 conflict result precedent_id")
        changed = self.resulting_authority_id != self.prior_authority_id
        if self.status_after == PrecedentStatus.ACTIVE:
            if (
                changed
                or self.resulting_revision != self.prior_revision
                or self.invalidated_by_precedent_id is not None
            ):
                raise ValueError("unchanged M5 conflict node must preserve its ACTIVE authority")
        elif self.status_after in {PrecedentStatus.CONFLICT, PrecedentStatus.INVALIDATED}:
            if (
                not changed
                or self.resulting_revision != self.prior_revision + 1
                or self.invalidated_by_precedent_id is None
                or self.invalidated_by_precedent_id == self.precedent_id
            ):
                raise ValueError("terminal M5 conflict node must describe one successor")
        else:
            raise ValueError("M5 conflict batch may only produce ACTIVE, CONFLICT, or INVALIDATED")
        return self

    @property
    def sort_key(self) -> str:
        return self.precedent_id


class M5PrecedentConflictBatchReceipt(FrozenContractModel):
    """Atomic commit receipt covering every node in a conflict batch."""

    schema_version: Literal["m5-precedent-conflict-batch-receipt-v1"] = (
        "m5-precedent-conflict-batch-receipt-v1"
    )
    run_id: ReferenceToken
    config_sha256: Sha256Hex
    policy_id: Sha256Hex
    batch_authority_id: Sha256Hex
    causal_cut_id: Sha256Hex
    results: tuple[M5PrecedentConflictNodeResult, ...] = Field(
        default=(),
        max_length=MAX_M5_PRECEDENTS,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="receipt_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"receipt_id"})
        return sha256_hex(["m5-precedent-conflict-batch-receipt", 1, payload])

    @model_validator(mode="after")
    def validate_results(self) -> M5PrecedentConflictBatchReceipt:
        keys = tuple(item.sort_key for item in self.results)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("M5 conflict batch results must be unique and stably ordered")
        return self


class M5PrecedentConflictBatchResolution(FrozenContractModel):
    """Pure graph result supplied to the atomic repository commit boundary."""

    policy: M5PrecedentPolicy
    batch_authority: M5PrecedentConflictBatchAuthority
    receipt: M5PrecedentConflictBatchReceipt
    prior_authorities: tuple[M5PrecedentAuthority, ...] = Field(
        default=(),
        max_length=MAX_M5_PRECEDENTS,
    )
    resulting_authorities: tuple[M5PrecedentAuthority, ...] = Field(
        default=(),
        max_length=MAX_M5_PRECEDENTS,
    )

    @model_validator(mode="after")
    def validate_resolution(self) -> M5PrecedentConflictBatchResolution:
        batch = self.batch_authority
        receipt = self.receipt
        prior_keys = tuple(item.precedent.precedent_id for item in self.prior_authorities)
        resulting_keys = tuple(item.precedent.precedent_id for item in self.resulting_authorities)
        candidate_keys = tuple(item.precedent_id for item in batch.candidates)
        result_keys = tuple(item.precedent_id for item in receipt.results)
        if (
            self.policy.policy_id != batch.policy_id
            or self.policy.config_sha256 != batch.config_sha256
            or receipt.run_id != batch.run_id
            or receipt.config_sha256 != batch.config_sha256
            or receipt.policy_id != batch.policy_id
            or receipt.batch_authority_id != batch.batch_authority_id
            or receipt.causal_cut_id != batch.causal_cut.cut_id
            or prior_keys != candidate_keys
            or resulting_keys != candidate_keys
            or result_keys != candidate_keys
        ):
            raise ValueError("M5 conflict batch resolution scopes do not close")
        if any(
            candidate.source_priority != self.policy.source_priorities[candidate.source]
            for candidate in batch.candidates
        ):
            raise ValueError("M5 conflict candidate priority differs from its policy")
        if any(edge.threshold != self.policy.conflict_similarity for edge in batch.edges):
            raise ValueError("M5 conflict edge threshold differs from its policy")
        for candidate, node, prior, resulting in zip(
            batch.candidates,
            receipt.results,
            self.prior_authorities,
            self.resulting_authorities,
            strict=True,
        ):
            if (
                prior.run_id != batch.run_id
                or resulting.run_id != batch.run_id
                or prior.config_sha256 != batch.config_sha256
                or resulting.config_sha256 != batch.config_sha256
                or prior.precedent.status != PrecedentStatus.ACTIVE
                or prior.authority_id != candidate.authority_id
                or prior.revision != candidate.revision
                or prior.precedent.source != candidate.source
                or prior.precedent.evidence_class != candidate.evidence_class
                or prior.precedent.violation_type != candidate.violation_type
                or prior.precedent.rule_version != candidate.rule_version
                or prior.precedent.decision_direction != candidate.decision_direction
                or resulting.authority_id != node.resulting_authority_id
                or resulting.revision != node.resulting_revision
                or resulting.precedent.status != node.status_after
                or resulting.precedent.invalidated_by != node.invalidated_by_precedent_id
            ):
                raise ValueError("M5 conflict batch authorities do not match their graph refs")
        return self


class M5PrecedentRevocationReceipt(FrozenContractModel):
    schema_version: Literal["m5-precedent-revocation-receipt-v1"] = (
        "m5-precedent-revocation-receipt-v1"
    )
    run_id: ReferenceToken
    precedent_id: ReferenceToken
    prior_authority_id: Sha256Hex
    prior_revision: int = Field(gt=0, strict=True)
    citation_snapshot_id: Sha256Hex
    revoked_by_ref: ReferenceToken
    revoked_at: datetime
    outcome: M5PrecedentRevocationOutcome
    resulting_authority_id: Sha256Hex
    resulting_revision: int = Field(gt=0, strict=True)
    historical_case_ids: tuple[ReferenceToken, ...] = Field(
        default=(),
        max_length=MAX_M5_CITATION_SNAPSHOT_ENTRIES,
    )
    historical_citation_ids: tuple[Sha256Hex, ...] = Field(
        default=(),
        max_length=MAX_M5_CITATION_SNAPSHOT_ENTRIES,
    )
    old_cases_rewritten: Literal[False] = False

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_digest(value, handler, field_name="receipt_id")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"receipt_id"})
        return sha256_hex(["m5-precedent-revocation-receipt", 1, payload])

    @field_validator("revoked_at")
    @classmethod
    def validate_revoked_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "M5 revocation timestamp")

    @model_validator(mode="after")
    def validate_revocation(self) -> M5PrecedentRevocationReceipt:
        if self.historical_case_ids != tuple(sorted(set(self.historical_case_ids))):
            raise ValueError("M5 historical citation case IDs must be unique and sorted")
        if self.historical_citation_ids != tuple(sorted(set(self.historical_citation_ids))):
            raise ValueError("M5 historical citation IDs must be unique and sorted")
        if self.outcome == M5PrecedentRevocationOutcome.REVOKED:
            if (
                self.resulting_revision != self.prior_revision + 1
                or self.resulting_authority_id == self.prior_authority_id
            ):
                raise ValueError("M5 revocation must advance authority revision")
        elif (
            self.resulting_revision != self.prior_revision
            or self.resulting_authority_id != self.prior_authority_id
        ):
            raise ValueError("idempotent M5 revocation cannot mutate authority")
        return self


class M5PrecedentRevocationResult(FrozenContractModel):
    citation_snapshot: M5PrecedentCitationSnapshot
    receipt: M5PrecedentRevocationReceipt
    authority: M5PrecedentAuthority

    @model_validator(mode="after")
    def validate_result(self) -> M5PrecedentRevocationResult:
        if (
            self.citation_snapshot.snapshot_id != self.receipt.citation_snapshot_id
            or self.citation_snapshot.run_id != self.receipt.run_id
            or self.citation_snapshot.precedent_id != self.receipt.precedent_id
            or self.citation_snapshot.captured_at != self.receipt.revoked_at
            or self.authority.run_id != self.receipt.run_id
            or self.authority.precedent.precedent_id != self.receipt.precedent_id
            or self.authority.authority_id != self.receipt.resulting_authority_id
            or self.authority.revision != self.receipt.resulting_revision
            or self.authority.precedent.status != PrecedentStatus.REVOKED
        ):
            raise ValueError("M5 revocation result conflicts with its receipt")
        return self


__all__ = [
    "MAX_M5_CITATION_SNAPSHOT_ENTRIES",
    "MAX_M5_CONFLICT_PAIR_COUNT",
    "MAX_M5_EMBEDDING_DIMENSIONS",
    "MAX_M5_PRECEDENTS",
    "MAX_M5_RETRIEVAL_RESULTS",
    "MAX_M5_VISUAL_EMBEDDINGS",
    "M5AppealWindowSnapshot",
    "M5EmbeddingChannel",
    "M5EmbeddingRequest",
    "M5EmbeddingVector",
    "M5PrecedentActivationOutcome",
    "M5PrecedentActivationReceipt",
    "M5PrecedentActivationResult",
    "M5PrecedentAuthority",
    "M5PrecedentCandidateDisposition",
    "M5PrecedentCandidateEvaluation",
    "M5PrecedentCitationAuthority",
    "M5PrecedentCitationCommit",
    "M5PrecedentCitationSnapshot",
    "M5PrecedentConflictBatchAuthority",
    "M5PrecedentConflictBatchReceipt",
    "M5PrecedentConflictBatchResolution",
    "M5PrecedentConflictCandidateAuthority",
    "M5PrecedentConflictCausalCut",
    "M5PrecedentConflictEdge",
    "M5PrecedentConflictNodeResult",
    "M5PrecedentConflictOutcome",
    "M5PrecedentConflictReceipt",
    "M5PrecedentConflictResolution",
    "M5PrecedentConflictSnapshot",
    "M5PrecedentPolicy",
    "M5PrecedentRetrievalQuery",
    "M5PrecedentRetrievalResult",
    "M5PrecedentRevocationOutcome",
    "M5PrecedentRevocationReceipt",
    "M5PrecedentRevocationResult",
    "M5ScoredPrecedent",
    "m5_precedent_active_head_root_sha256",
]
