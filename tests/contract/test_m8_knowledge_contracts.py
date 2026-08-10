from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_knowledge import (
    M8KnowledgeAnswerOutcome,
    M8KnowledgeAnswerV1,
    M8KnowledgeCatalogAuthorityV1,
    M8KnowledgeCitationV1,
    M8KnowledgeContentType,
    M8KnowledgeDocumentAuthorityV1,
    M8KnowledgeDocumentType,
    M8KnowledgeQueryV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)


def _document(
    *,
    logical_id: str = "lab-goggles-sop",
    version: int = 1,
    effective_at: datetime = BASE_TIME,
    expires_at: datetime | None = None,
) -> M8KnowledgeDocumentAuthorityV1:
    return M8KnowledgeDocumentAuthorityV1(
        logical_document_id=logical_id,
        document_version=version,
        document_type=M8KnowledgeDocumentType.SOP,
        title="化学实验室护目镜操作规程",
        locale="zh-CN",
        issuer_id="campus-safety-office",
        source_ref=f"source-{logical_id}-v{version}",
        content_ref=f"content-{logical_id}-v{version}",
        content_sha256=SHA_A if version == 1 else SHA_B,
        content_size_bytes=120,
        content_type=M8KnowledgeContentType.MARKDOWN,
        published_at=effective_at - timedelta(days=1),
        effective_at=effective_at,
        expires_at=expires_at,
        document_manifest_id=SHA_C,
    )


def _catalog(*documents: M8KnowledgeDocumentAuthorityV1) -> M8KnowledgeCatalogAuthorityV1:
    selected = documents or (_document(),)
    return M8KnowledgeCatalogAuthorityV1(
        catalog_id="campus-safety-knowledge",
        catalog_revision=1,
        documents=selected,
        generated_at=BASE_TIME,
        catalog_manifest_id=SHA_D,
    )


def _query(catalog: M8KnowledgeCatalogAuthorityV1) -> M8KnowledgeQueryV1:
    return M8KnowledgeQueryV1(
        catalog_authority_id=catalog.catalog_authority_id,
        requester_actor_id="student-01",
        requester_actor_authority_id=SHA_B,
        query_text="护目镜什么时候必须佩戴",
        locale="zh-CN",
        as_of=BASE_TIME + timedelta(hours=1),
        allowed_document_types=(M8KnowledgeDocumentType.SOP,),
        max_citations=3,
        query_manifest_id=SHA_D,
    )


def test_document_and_catalog_freeze_version_effectivity_and_rule_separation() -> None:
    first = _document(expires_at=BASE_TIME + timedelta(days=30))
    second = _document(
        version=2,
        effective_at=BASE_TIME + timedelta(days=30),
    )
    catalog = _catalog(first, second)
    assert catalog.documents == (first, second)
    assert first.ordinary_document_can_define_case_rule is False
    assert first.direct_case_decision_permitted is False
    assert catalog.ordinary_documents_can_define_case_rules is False

    overlapping = second.model_copy(update={"effective_at": BASE_TIME + timedelta(days=29)})
    with pytest.raises(ValidationError, match="cannot overlap"):
        _catalog(first, overlapping)


def test_answer_is_exact_extractive_text_with_versioned_effective_source() -> None:
    document = _document()
    catalog = _catalog(document)
    query = _query(catalog)
    snippet = "进入化学实验区域前必须正确佩戴护目镜。"
    citation = M8KnowledgeCitationV1(
        document=document,
        chunk_index=0,
        snippet_start_char=0,
        snippet_end_char=len(snippet),
        snippet=snippet,
        lexical_match_count=3,
    )
    answer = M8KnowledgeAnswerV1(
        catalog=catalog,
        query=query,
        citations=(citation,),
        adapter_manifest_id=SHA_D,
    )
    assert answer.outcome == M8KnowledgeAnswerOutcome.ANSWERED
    assert answer.answer_text == snippet
    assert citation.source_ref == document.source_ref
    assert citation.source_version == 1
    assert citation.source_effective_at == BASE_TIME
    assert answer.network_used is False
    assert answer.model_used is False
    assert answer.ordinary_document_used_as_case_rule is False
    assert answer.case_transition_permitted is False


def test_answer_rejects_expired_sources_and_computed_claim_grafts() -> None:
    expired = _document(expires_at=BASE_TIME + timedelta(minutes=30))
    catalog = _catalog(expired)
    query = _query(catalog)
    snippet = "必须佩戴护目镜。"
    citation = M8KnowledgeCitationV1(
        document=expired,
        chunk_index=0,
        snippet_start_char=0,
        snippet_end_char=len(snippet),
        snippet=snippet,
        lexical_match_count=2,
    )
    with pytest.raises(ValidationError, match="not effective"):
        M8KnowledgeAnswerV1(
            catalog=catalog,
            query=query,
            citations=(citation,),
            adapter_manifest_id=SHA_D,
        )

    answer = M8KnowledgeAnswerV1(
        catalog=_catalog(),
        query=_query(_catalog()),
        citations=(),
        adapter_manifest_id=SHA_D,
    )
    payload = answer.model_dump(mode="json")
    payload["ordinary_document_used_as_case_rule"] = True
    with pytest.raises(ValidationError, match="ordinary_document_used_as_case_rule"):
        M8KnowledgeAnswerV1.model_validate(payload)


def test_no_match_and_all_authorities_round_trip_with_computed_claims() -> None:
    catalog = _catalog()
    query = _query(catalog)
    answer = M8KnowledgeAnswerV1(
        catalog=catalog,
        query=query,
        citations=(),
        adapter_manifest_id=SHA_D,
    )
    assert answer.outcome == M8KnowledgeAnswerOutcome.NO_MATCH
    assert "未在" in answer.answer_text
    for model in (catalog.documents[0], catalog, query, answer):
        assert type(model).model_validate_json(model.model_dump_json()) == model
