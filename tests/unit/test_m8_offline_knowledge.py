from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from labcourt.adapters.m8_offline_knowledge import DeterministicOfflineKnowledgeRetriever
from labcourt.application.m8_knowledge_demo import build_offline_knowledge_demo_bundle
from labcourt.contracts.m8_knowledge import (
    M8KnowledgeAnswerOutcome,
    M8KnowledgeCatalogAuthorityV1,
    M8KnowledgeDocumentType,
    M8KnowledgeQueryV1,
)
from labcourt.ports.m8_knowledge import (
    M8KnowledgeRetrieverError,
    M8KnowledgeRetrieverFailureCode,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)


def _bundle():
    return build_offline_knowledge_demo_bundle(
        generated_at=BASE_TIME,
        document_manifest_id=SHA_A,
        catalog_manifest_id=SHA_B,
        adapter_manifest_id=SHA_C,
    )


def _query(
    catalog: M8KnowledgeCatalogAuthorityV1,
    text: str,
    *,
    as_of: datetime = BASE_TIME,
) -> M8KnowledgeQueryV1:
    return M8KnowledgeQueryV1(
        catalog_authority_id=catalog.catalog_authority_id,
        requester_actor_id="student-01",
        requester_actor_authority_id=SHA_D,
        query_text=text,
        locale="zh-CN",
        as_of=as_of,
        allowed_document_types=tuple(sorted(M8KnowledgeDocumentType, key=lambda item: item.value)),
        max_citations=3,
        query_manifest_id=SHA_C,
    )


def test_offline_fixture_covers_all_types_and_returns_exact_ranked_citations() -> None:
    bundle = _bundle()
    assert {document.document_type for document in bundle.catalog.documents} == set(
        M8KnowledgeDocumentType
    )
    adapter = DeterministicOfflineKnowledgeRetriever(
        bundle.catalog,
        bundle.content_map(),
        bundle.adapter_manifest_id,
    )
    request = _query(bundle.catalog, "护目镜 佩戴")
    answer = adapter.query(request)

    assert answer.outcome == M8KnowledgeAnswerOutcome.ANSWERED
    assert 1 <= len(answer.citations) <= request.max_citations
    assert adapter.query(request) is answer
    assert adapter.replay(request.query_id) is answer
    assert adapter.generation_count == 1
    for citation in answer.citations:
        raw = adapter.read_content(citation.document.content_ref)
        assert hashlib.sha256(raw).hexdigest() == citation.document.content_sha256
        text = raw.decode("utf-8")
        assert text[citation.snippet_start_char : citation.snippet_end_char] == citation.snippet
        assert citation.source_version == citation.document.document_version
        assert citation.source_effective_at == citation.document.effective_at
    assert answer.answer_text == "\n\n".join(item.snippet for item in answer.citations)
    assert answer.network_used is False
    assert answer.model_used is False
    assert answer.ordinary_document_used_as_case_rule is False


def test_offline_retriever_returns_typed_no_match_for_text_and_effective_cut() -> None:
    bundle = _bundle()
    adapter = DeterministicOfflineKnowledgeRetriever(
        bundle.catalog,
        bundle.content_map(),
        bundle.adapter_manifest_id,
    )
    no_text_match = adapter.query(_query(bundle.catalog, "quantum-entanglement-xyz"))
    assert no_text_match.outcome == M8KnowledgeAnswerOutcome.NO_MATCH
    assert no_text_match.citations == ()

    before_effective = bundle.catalog.documents[0].effective_at - timedelta(seconds=1)
    no_effective_document = adapter.query(_query(bundle.catalog, "护目镜", as_of=before_effective))
    assert no_effective_document.outcome == M8KnowledgeAnswerOutcome.NO_MATCH


def test_offline_retriever_fails_typed_on_content_catalog_and_missing_replay() -> None:
    bundle = _bundle()
    contents = bundle.content_map()
    first_ref = bundle.catalog.documents[0].content_ref
    corrupted = dict(contents)
    corrupted[first_ref] = b"x" * len(corrupted[first_ref])
    with pytest.raises(M8KnowledgeRetrieverError) as hash_error:
        DeterministicOfflineKnowledgeRetriever(
            bundle.catalog,
            corrupted,
            bundle.adapter_manifest_id,
        )
    assert hash_error.value.reason_code == M8KnowledgeRetrieverFailureCode.CONTENT_HASH_MISMATCH

    incomplete = dict(contents)
    incomplete.pop(first_ref)
    with pytest.raises(M8KnowledgeRetrieverError) as inventory_error:
        DeterministicOfflineKnowledgeRetriever(
            bundle.catalog,
            incomplete,
            bundle.adapter_manifest_id,
        )
    assert inventory_error.value.reason_code == (
        M8KnowledgeRetrieverFailureCode.CONTENT_INVENTORY_MISMATCH
    )

    adapter = DeterministicOfflineKnowledgeRetriever(
        bundle.catalog,
        contents,
        bundle.adapter_manifest_id,
    )
    mismatched_query = _query(bundle.catalog, "护目镜").model_copy(
        update={"catalog_authority_id": SHA_D}
    )
    with pytest.raises(M8KnowledgeRetrieverError) as catalog_error:
        adapter.query(mismatched_query)
    assert catalog_error.value.reason_code == M8KnowledgeRetrieverFailureCode.CATALOG_MISMATCH

    with pytest.raises(M8KnowledgeRetrieverError) as replay_error:
        adapter.replay(SHA_D)
    assert replay_error.value.reason_code == (
        M8KnowledgeRetrieverFailureCode.QUERY_REPLAY_NOT_FOUND
    )
    with pytest.raises(M8KnowledgeRetrieverError) as content_error:
        adapter.read_content("missing-content")
    assert content_error.value.reason_code == M8KnowledgeRetrieverFailureCode.CONTENT_NOT_FOUND
