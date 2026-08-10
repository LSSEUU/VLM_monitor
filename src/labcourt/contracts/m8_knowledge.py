"""M8 versioned knowledge, exact citation, and offline answer authorities."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_KNOWLEDGE_CONTENT_BYTES = 1024 * 1024
MAX_M8_KNOWLEDGE_DOCUMENTS = 1000
MAX_M8_KNOWLEDGE_CITATIONS = 10


class M8KnowledgeDocumentType(StrEnum):
    DEVICE_MANUAL = "DEVICE_MANUAL"
    EMERGENCY_PLAN = "EMERGENCY_PLAN"
    FAQ = "FAQ"
    HISTORICAL_PRECEDENT = "HISTORICAL_PRECEDENT"
    POLICY = "POLICY"
    SOP = "SOP"


class M8KnowledgeContentType(StrEnum):
    MARKDOWN = "MARKDOWN"
    PLAIN_TEXT = "PLAIN_TEXT"


class M8KnowledgeAnswerOutcome(StrEnum):
    ANSWERED = "ANSWERED"
    NO_MATCH = "NO_MATCH"


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 {name} must be timezone-aware UTC")
    return value


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 knowledge authority")


class M8KnowledgeDocumentAuthorityV1(FrozenContractModel):
    """Metadata for one immutable ordinary knowledge document version."""

    schema_version: Literal["m8-knowledge-document-authority-v1"] = (
        "m8-knowledge-document-authority-v1"
    )
    logical_document_id: ReferenceToken
    document_version: int = Field(gt=0, strict=True)
    document_type: M8KnowledgeDocumentType
    title: str = Field(min_length=1, max_length=256, strict=True)
    locale: ReferenceToken
    issuer_id: ReferenceToken
    source_ref: ReferenceToken
    content_ref: ReferenceToken
    content_sha256: Sha256Hex
    content_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_KNOWLEDGE_CONTENT_BYTES,
        strict=True,
    )
    content_type: M8KnowledgeContentType
    published_at: datetime
    effective_at: datetime
    expires_at: datetime | None = None
    document_manifest_id: Sha256Hex

    @field_validator("logical_document_id", "locale", "issuer_id", "source_ref", "content_ref")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 knowledge document reference")

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("M8 knowledge title must be trimmed printable text")
        return value

    @field_validator("published_at", "effective_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _require_utc(value, "knowledge document time")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "ordinary_document_can_define_case_rule",
                "direct_case_decision_permitted",
                "document_authority_id",
            ),
        )
        document = handler(payload)
        _verify_computed_claims(document, claims)
        return document

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        if self.published_at > self.effective_at:
            raise ValueError("M8 knowledge document cannot be effective before publication")
        if self.expires_at is not None and self.expires_at <= self.effective_at:
            raise ValueError("M8 knowledge document expiry must follow its effective time")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ordinary_document_can_define_case_rule(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_case_decision_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def document_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-knowledge-document-authority",
                1,
                self.logical_document_id,
                self.document_version,
                self.document_type,
                self.title,
                self.locale,
                self.issuer_id,
                self.source_ref,
                self.content_ref,
                self.content_sha256,
                self.content_size_bytes,
                self.content_type,
                _canonical_utc(self.published_at),
                _canonical_utc(self.effective_at),
                _canonical_utc(self.expires_at) if self.expires_at is not None else None,
                self.document_manifest_id,
                self.ordinary_document_can_define_case_rule,
                self.direct_case_decision_permitted,
            ]
        )


class M8KnowledgeCatalogAuthorityV1(FrozenContractModel):
    """Stable inventory of immutable document versions with non-overlapping validity."""

    schema_version: Literal["m8-knowledge-catalog-authority-v1"] = (
        "m8-knowledge-catalog-authority-v1"
    )
    catalog_id: ReferenceToken
    catalog_revision: int = Field(gt=0, strict=True)
    documents: tuple[M8KnowledgeDocumentAuthorityV1, ...] = Field(
        min_length=1,
        max_length=MAX_M8_KNOWLEDGE_DOCUMENTS,
    )
    generated_at: datetime
    catalog_manifest_id: Sha256Hex

    @field_validator("catalog_id")
    @classmethod
    def validate_catalog_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 knowledge catalog")

    @field_validator("generated_at")
    @classmethod
    def validate_generated_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "knowledge catalog generated_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("ordinary_documents_can_define_case_rules", "catalog_authority_id"),
        )
        catalog = handler(payload)
        _verify_computed_claims(catalog, claims)
        return catalog

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        keys = tuple(
            (document.logical_document_id, document.document_version) for document in self.documents
        )
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M8 knowledge documents must be unique and stably ordered")
        content_refs = tuple(document.content_ref for document in self.documents)
        if len(content_refs) != len(set(content_refs)):
            raise ValueError("M8 knowledge content references must be unique")
        by_logical_id: dict[str, list[M8KnowledgeDocumentAuthorityV1]] = {}
        for document in self.documents:
            by_logical_id.setdefault(document.logical_document_id, []).append(document)
        for versions in by_logical_id.values():
            for prior, following in pairwise(versions):
                if prior.expires_at is None or prior.expires_at > following.effective_at:
                    raise ValueError("M8 knowledge document effective intervals cannot overlap")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ordinary_documents_can_define_case_rules(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def catalog_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-knowledge-catalog-authority",
                1,
                self.catalog_id,
                self.catalog_revision,
                [document.document_authority_id for document in self.documents],
                _canonical_utc(self.generated_at),
                self.catalog_manifest_id,
                self.ordinary_documents_can_define_case_rules,
            ]
        )


class M8KnowledgeQueryV1(FrozenContractModel):
    """Bounded lexical query over one exact catalog and requester authority."""

    schema_version: Literal["m8-knowledge-query-v1"] = "m8-knowledge-query-v1"
    catalog_authority_id: Sha256Hex
    requester_actor_id: ReferenceToken
    requester_actor_authority_id: Sha256Hex
    query_text: str = Field(min_length=1, max_length=512, strict=True)
    locale: ReferenceToken
    as_of: datetime
    allowed_document_types: tuple[M8KnowledgeDocumentType, ...] = Field(
        min_length=1,
        max_length=len(M8KnowledgeDocumentType),
    )
    max_citations: int = Field(gt=0, le=MAX_M8_KNOWLEDGE_CITATIONS, strict=True)
    query_manifest_id: Sha256Hex

    @field_validator("requester_actor_id", "locale")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M8 knowledge query reference")

    @field_validator("query_text")
    @classmethod
    def validate_query_text(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("M8 knowledge query must be trimmed printable text")
        return value

    @field_validator("as_of")
    @classmethod
    def validate_as_of(cls, value: datetime) -> datetime:
        return _require_utc(value, "knowledge query as_of")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("query_id",))
        query = handler(payload)
        _verify_computed_claims(query, claims)
        return query

    @model_validator(mode="after")
    def validate_allowed_types(self) -> Self:
        keys = tuple(item.value for item in self.allowed_document_types)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M8 knowledge query document types must be unique and stable")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def query_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-knowledge-query",
                1,
                self.catalog_authority_id,
                self.requester_actor_id,
                self.requester_actor_authority_id,
                self.query_text,
                self.locale,
                _canonical_utc(self.as_of),
                [item.value for item in self.allowed_document_types],
                self.max_citations,
                self.query_manifest_id,
            ]
        )


class M8KnowledgeCitationV1(FrozenContractModel):
    """Exact extractive span from one immutable knowledge document version."""

    schema_version: Literal["m8-knowledge-citation-v1"] = "m8-knowledge-citation-v1"
    document: M8KnowledgeDocumentAuthorityV1
    chunk_index: int = Field(ge=0, strict=True)
    snippet_start_char: int = Field(ge=0, strict=True)
    snippet_end_char: int = Field(gt=0, strict=True)
    snippet: str = Field(min_length=1, max_length=2000, strict=True)
    lexical_match_count: int = Field(gt=0, le=512, strict=True)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "source_ref",
                "source_version",
                "source_effective_at",
                "snippet_sha256",
                "citation_id",
            ),
        )
        citation = handler(payload)
        _verify_computed_claims(citation, claims)
        return citation

    @model_validator(mode="after")
    def validate_span(self) -> Self:
        if self.snippet_end_char <= self.snippet_start_char:
            raise ValueError("M8 knowledge citation end must follow start")
        if self.snippet_end_char - self.snippet_start_char != len(self.snippet):
            raise ValueError("M8 knowledge citation span must match snippet length")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_ref(self) -> ReferenceToken:
        return self.document.source_ref

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_version(self) -> int:
        return self.document.document_version

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_effective_at(self) -> datetime:
        return self.document.effective_at

    @computed_field  # type: ignore[prop-decorator]
    @property
    def snippet_sha256(self) -> Sha256Hex:
        return sha256_hex(self.snippet)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def citation_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-knowledge-citation",
                1,
                self.document.document_authority_id,
                self.chunk_index,
                self.snippet_start_char,
                self.snippet_end_char,
                self.snippet_sha256,
                self.lexical_match_count,
            ]
        )


class M8KnowledgeAnswerV1(FrozenContractModel):
    """Deterministic extractive answer with exact versioned citations."""

    schema_version: Literal["m8-knowledge-answer-v1"] = "m8-knowledge-answer-v1"
    catalog: M8KnowledgeCatalogAuthorityV1
    query: M8KnowledgeQueryV1
    citations: tuple[M8KnowledgeCitationV1, ...] = Field(max_length=MAX_M8_KNOWLEDGE_CITATIONS)
    adapter_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "outcome",
                "answer_text",
                "network_used",
                "model_used",
                "ordinary_document_used_as_case_rule",
                "case_transition_permitted",
                "answer_id",
            ),
        )
        answer = handler(payload)
        _verify_computed_claims(answer, claims)
        return answer

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.query.catalog_authority_id != self.catalog.catalog_authority_id:
            raise ValueError("M8 knowledge answer query does not bind its catalog")
        if len(self.citations) > self.query.max_citations:
            raise ValueError("M8 knowledge answer exceeds query citation bound")
        catalog_documents = {
            document.document_authority_id: document for document in self.catalog.documents
        }
        seen: set[str] = set()
        for citation in self.citations:
            document = citation.document
            if catalog_documents.get(document.document_authority_id) != document:
                raise ValueError("M8 knowledge citation document is outside the catalog")
            if document.document_type not in self.query.allowed_document_types:
                raise ValueError("M8 knowledge citation type is outside the query scope")
            if document.effective_at > self.query.as_of or (
                document.expires_at is not None and self.query.as_of >= document.expires_at
            ):
                raise ValueError("M8 knowledge citation is not effective at query time")
            if citation.citation_id in seen:
                raise ValueError("M8 knowledge citations must be unique")
            seen.add(citation.citation_id)
        keys = tuple(
            (
                -citation.lexical_match_count,
                citation.document.logical_document_id,
                citation.document.document_version,
                citation.chunk_index,
                citation.snippet_start_char,
            )
            for citation in self.citations
        )
        if keys != tuple(sorted(keys)):
            raise ValueError("M8 knowledge citations must use deterministic ranking order")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def outcome(self) -> M8KnowledgeAnswerOutcome:
        if self.citations:
            return M8KnowledgeAnswerOutcome.ANSWERED
        return M8KnowledgeAnswerOutcome.NO_MATCH

    @computed_field  # type: ignore[prop-decorator]
    @property
    def answer_text(self) -> str:
        if not self.citations:
            return "未在当前生效且允许引用的知识文档中找到匹配内容。"
        return "\n\n".join(citation.snippet for citation in self.citations)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def network_used(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_used(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ordinary_document_used_as_case_rule(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def answer_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-knowledge-answer",
                1,
                self.catalog.catalog_authority_id,
                self.query.query_id,
                [citation.citation_id for citation in self.citations],
                self.adapter_manifest_id,
                self.outcome,
                self.answer_text,
                self.network_used,
                self.model_used,
                self.ordinary_document_used_as_case_rule,
                self.case_transition_permitted,
            ]
        )


__all__ = [
    "MAX_M8_KNOWLEDGE_CITATIONS",
    "MAX_M8_KNOWLEDGE_CONTENT_BYTES",
    "MAX_M8_KNOWLEDGE_DOCUMENTS",
    "M8KnowledgeAnswerOutcome",
    "M8KnowledgeAnswerV1",
    "M8KnowledgeCatalogAuthorityV1",
    "M8KnowledgeCitationV1",
    "M8KnowledgeContentType",
    "M8KnowledgeDocumentAuthorityV1",
    "M8KnowledgeDocumentType",
    "M8KnowledgeQueryV1",
]
