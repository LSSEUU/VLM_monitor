"""M4 precedent-query and deterministic retrieval-result contracts.

The production precedent store belongs to M5.  These contracts give the M4
offline fake a narrow boundary while preserving the exact hearing, cycle,
evidence, configuration, and model authorities used to build the prompt.
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import ArtifactKind, EvidenceClass, PrecedentStatus, ViolationType
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.manifests import ModelManifest
from labcourt.contracts.precedents import Precedent, ScoredPrecedent
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef

MAX_HEARING_PRECEDENT_CANDIDATES = 10_000
MAX_HEARING_PRECEDENT_RESULTS = 64
MAX_HEARING_PRECEDENT_SITUATION_CHARS = 16_384
MAX_HEARING_PRECEDENT_FUSED_SCORE = 1.25


def derive_hearing_evidence_pack_document_sha256(pack: EvidencePack) -> Sha256Hex:
    """Hash the complete current EvidencePack document, not only its semantic ID."""

    if not isinstance(pack, EvidencePack):
        raise TypeError("pack must be an EvidencePack")
    return sha256_hex(
        [
            "m4-hearing-evidence-pack-document",
            1,
            pack.model_dump(mode="json"),
        ]
    )


def _precedent_documents(precedents: tuple[Precedent, ...]) -> list[dict[str, object]]:
    return [precedent.model_dump(mode="json") for precedent in precedents]


def derive_hearing_candidate_snapshot_sha256(
    candidates: tuple[Precedent, ...],
) -> Sha256Hex:
    """Hash full candidate documents in their required stable precedent-ID order."""

    return sha256_hex(
        [
            "m4-hearing-precedent-candidate-snapshot",
            1,
            _precedent_documents(candidates),
        ]
    )


def derive_hearing_visible_snapshot_sha256(
    visible_precedents: tuple[Precedent, ...],
) -> Sha256Hex:
    """Hash full prompt-visible precedent documents in stable precedent-ID order."""

    return sha256_hex(
        [
            "m4-hearing-precedent-visible-snapshot",
            1,
            _precedent_documents(visible_precedents),
        ]
    )


class HearingPrecedentRetrievalQuery(FrozenContractModel):
    """Content-addressed M4 query bound to every current retrieval authority."""

    schema_version: Literal["m4-hearing-precedent-query-v1"] = "m4-hearing-precedent-query-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    hearing_session_sha256: Sha256Hex
    cycle_scope_id: Sha256Hex
    cycle_scope_sha256: Sha256Hex
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    current_evidence_pack_sha256: Sha256Hex
    evidence_class: EvidenceClass
    violation_type: ViolationType
    rule_version: ReferenceToken
    situation_text: str = Field(
        min_length=1,
        max_length=MAX_HEARING_PRECEDENT_SITUATION_CHARS,
    )
    top_k: int = Field(gt=0, le=MAX_HEARING_PRECEDENT_RESULTS, strict=True)
    config_sha256: Sha256Hex
    retriever_version: ReferenceToken
    retriever_manifest_id: Sha256Hex
    embedding_model_manifest: ModelManifest
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "rule_version", "retriever_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing precedent query reference")

    @field_validator("situation_text")
    @classmethod
    def validate_situation_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("precedent situation text must contain visible content")
        if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
            raise ValueError("precedent situation text contains a forbidden control character")
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("precedent situation text contains an invalid Unicode surrogate")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        names = ("query_id", "query_sha256")
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        query = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(query, name):
                raise ValueError(f"serialized {name} conflicts with precedent query content")
        return query

    def query_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "hearing_session_id": self.hearing_session_id,
            "hearing_session_sha256": self.hearing_session_sha256,
            "cycle_scope_id": self.cycle_scope_id,
            "cycle_scope_sha256": self.cycle_scope_sha256,
            "current_evidence_pack_id": self.current_evidence_pack_id,
            "current_evidence_pack_version": self.current_evidence_pack_version,
            "current_evidence_pack_sha256": self.current_evidence_pack_sha256,
            "evidence_class": self.evidence_class.value,
            "violation_type": self.violation_type.value,
            "rule_version": self.rule_version,
            "situation_text": self.situation_text,
            "top_k": self.top_k,
            "config_sha256": self.config_sha256,
            "retriever_version": self.retriever_version,
            "retriever_manifest_id": self.retriever_manifest_id,
            "embedding_model_manifest": self.embedding_model_manifest.model_dump(mode="json"),
            "manifest_id": self.manifest_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def query_id(self) -> Sha256Hex:
        return sha256_hex(["m4-hearing-precedent-query", 1, self.query_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def query_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m4-hearing-precedent-query-document",
                1,
                self.query_id,
                self.query_projection(),
            ]
        )

    @model_validator(mode="after")
    def validate_embedding_manifest(self) -> HearingPrecedentRetrievalQuery:
        if self.embedding_model_manifest.component != "text_embedding":
            raise ValueError("hearing precedent query requires the text_embedding manifest")
        return self


class HearingPrecedentRetrievalResult(FrozenContractModel):
    """Successful, self-verifying candidate snapshot and prompt-visible ranking."""

    schema_version: Literal["m4-hearing-precedent-result-v1"] = "m4-hearing-precedent-result-v1"
    query: HearingPrecedentRetrievalQuery
    candidate_precedents: tuple[Precedent, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PRECEDENT_CANDIDATES,
    )
    visible_precedents: tuple[Precedent, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PRECEDENT_RESULTS,
    )
    scored_precedents: tuple[ScoredPrecedent, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PRECEDENT_RESULTS,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        names = (
            "candidate_snapshot_sha256",
            "visible_snapshot_sha256",
            "result_id",
            "result_sha256",
        )
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        result = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(result, name):
                raise ValueError(f"serialized {name} conflicts with precedent result content")
        return result

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_snapshot_sha256(self) -> Sha256Hex:
        return derive_hearing_candidate_snapshot_sha256(self.candidate_precedents)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def visible_snapshot_sha256(self) -> Sha256Hex:
        return derive_hearing_visible_snapshot_sha256(self.visible_precedents)

    def result_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "query_id": self.query.query_id,
            "query_sha256": self.query.query_sha256,
            "candidate_precedents": _precedent_documents(self.candidate_precedents),
            "candidate_snapshot_sha256": self.candidate_snapshot_sha256,
            "visible_precedents": _precedent_documents(self.visible_precedents),
            "visible_snapshot_sha256": self.visible_snapshot_sha256,
            "scored_precedents": [
                scored.model_dump(mode="json") for scored in self.scored_precedents
            ],
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def result_id(self) -> Sha256Hex:
        return sha256_hex(["m4-hearing-precedent-result", 1, self.result_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def result_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m4-hearing-precedent-result-document",
                1,
                self.result_id,
                self.result_projection(),
            ]
        )

    @model_validator(mode="after")
    def validate_result(self) -> HearingPrecedentRetrievalResult:
        candidate_ids = tuple(item.precedent_id for item in self.candidate_precedents)
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate precedents must use unique precedent IDs")
        if candidate_ids != tuple(sorted(candidate_ids)):
            raise ValueError("candidate precedents must use stable precedent-ID order")

        visible_ids = tuple(item.precedent_id for item in self.visible_precedents)
        if len(visible_ids) != len(set(visible_ids)):
            raise ValueError("visible precedents must use unique precedent IDs")
        if visible_ids != tuple(sorted(visible_ids)):
            raise ValueError("visible precedents must use stable precedent-ID order")
        if len(visible_ids) > self.query.top_k:
            raise ValueError("visible precedents exceed the query top_k")

        for precedent_id in candidate_ids:
            require_reference_token(precedent_id, "candidate precedent ID")
        candidate_by_id = {item.precedent_id: item for item in self.candidate_precedents}
        if any(candidate_by_id.get(item.precedent_id) != item for item in self.visible_precedents):
            raise ValueError("visible precedents must exactly match candidate documents")

        scored_ids = tuple(scored.precedent.precedent_id for scored in self.scored_precedents)
        if len(scored_ids) != len(set(scored_ids)):
            raise ValueError("scored precedents must use unique precedent IDs")
        if set(scored_ids) != set(visible_ids):
            raise ValueError("scored precedents must exactly equal the visible precedent set")
        visible_by_id = {item.precedent_id: item for item in self.visible_precedents}
        for scored in self.scored_precedents:
            precedent = scored.precedent
            if visible_by_id.get(precedent.precedent_id) != precedent:
                raise ValueError("scored precedent document conflicts with the visible snapshot")
            if (
                precedent.status != PrecedentStatus.ACTIVE
                or precedent.evidence_class != self.query.evidence_class
                or precedent.violation_type != self.query.violation_type
                or precedent.rule_version != self.query.rule_version
            ):
                raise ValueError("scored precedent lies outside the active query scope")
            if scored.fused_score > MAX_HEARING_PRECEDENT_FUSED_SCORE:
                raise ValueError("scored precedent exceeds the bounded fused score")

        score_order = tuple(
            (-item.fused_score, item.precedent.precedent_id) for item in self.scored_precedents
        )
        if score_order != tuple(sorted(score_order)):
            raise ValueError("scored precedents must use stable (-score, precedent_id) order")
        return self


class HearingPrecedentRetrievalOutcome(FrozenContractModel):
    """Exact application result joining a query, optional success result, and receipt."""

    query: HearingPrecedentRetrievalQuery
    result: HearingPrecedentRetrievalResult | None = None
    receipt: HearingPrecedentRetrievalReceipt

    @model_validator(mode="after")
    def validate_outcome(self) -> HearingPrecedentRetrievalOutcome:
        query = self.query
        receipt = self.receipt
        if (
            receipt.run_id != query.run_id
            or receipt.case_id != query.case_id
            or receipt.hearing_session_id != query.hearing_session_id
            or receipt.cycle_scope_id != query.cycle_scope_id
            or receipt.cycle_scope_sha256 != query.cycle_scope_sha256
            or receipt.current_evidence_pack_id != query.current_evidence_pack_id
            or receipt.current_evidence_pack_version != query.current_evidence_pack_version
            or receipt.evidence_class != query.evidence_class
            or receipt.violation_type != query.violation_type
            or receipt.rule_version != query.rule_version
            or receipt.top_k != query.top_k
            or receipt.query_sha256 != query.query_sha256
            or receipt.retriever_version != query.retriever_version
            or receipt.retriever_manifest_id != query.retriever_manifest_id
            or receipt.embedding_model_manifest_id
            != query.embedding_model_manifest.model_manifest_id
            or receipt.manifest_id != query.manifest_id
        ):
            raise ValueError("precedent receipt conflicts with its content-addressed query")

        if receipt.status == HearingPrecedentRetrievalStatus.DEGRADED:
            if self.result is not None:
                raise ValueError("degraded retrieval cannot expose a partial result")
            if (
                receipt.candidate_precedent_refs
                or receipt.visible_precedent_refs
                or receipt.scored_precedents
            ):
                raise ValueError("degraded retrieval cannot expose partial precedent context")
            return self

        result = self.result
        if result is None or result.query != query:
            raise ValueError("successful retrieval requires its exact typed result")
        candidate_refs = tuple(
            ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id=item.precedent_id)
            for item in result.candidate_precedents
        )
        visible_refs = tuple(
            ArtifactRef(kind=ArtifactKind.PRECEDENT, artifact_id=item.precedent_id)
            for item in result.visible_precedents
        )
        if (
            receipt.candidate_precedent_refs != candidate_refs
            or receipt.candidate_snapshot_sha256 != result.candidate_snapshot_sha256
            or receipt.visible_precedent_refs != visible_refs
            or receipt.visible_snapshot_sha256 != result.visible_snapshot_sha256
            or receipt.scored_precedents != result.scored_precedents
        ):
            raise ValueError("successful precedent receipt conflicts with its typed result")
        return self


__all__ = [
    "MAX_HEARING_PRECEDENT_CANDIDATES",
    "MAX_HEARING_PRECEDENT_FUSED_SCORE",
    "MAX_HEARING_PRECEDENT_RESULTS",
    "MAX_HEARING_PRECEDENT_SITUATION_CHARS",
    "HearingPrecedentRetrievalOutcome",
    "HearingPrecedentRetrievalQuery",
    "HearingPrecedentRetrievalResult",
    "derive_hearing_candidate_snapshot_sha256",
    "derive_hearing_evidence_pack_document_sha256",
    "derive_hearing_visible_snapshot_sha256",
]
