"""Explain existing offline knowledge answers and keep Case memory partitioned."""

from __future__ import annotations

import re

from labcourt.contracts.m8_api import M8ApiKnowledgeQueryRequestV1, M8ApiPrincipalV1
from labcourt.contracts.m8_knowledge_projection import (
    M8CaseMemoryAvailability,
    M8CaseMemoryProjectionV1,
    M8KnowledgeDocumentHitV1,
    M8KnowledgeNormalizedIntent,
    M8KnowledgeQueryProjectionV1,
)
from labcourt.ports.m8_case_memory import M8CaseMemoryAdapter
from labcourt.services.m8_knowledge_api import M8KnowledgeApiService

_INTENT_TERMS: tuple[tuple[M8KnowledgeNormalizedIntent, tuple[str, ...]], ...] = (
    (M8KnowledgeNormalizedIntent.CASE_MEMORY, ("案例", "先例", "历史案件", "case precedent")),
    (M8KnowledgeNormalizedIntent.EMERGENCY, ("应急", "泄漏", "火灾", "emergency")),
    (M8KnowledgeNormalizedIntent.DEVICE, ("设备", "传感器", "说明书", "device")),
    (M8KnowledgeNormalizedIntent.POLICY, ("制度", "规定", "政策", "policy")),
    (M8KnowledgeNormalizedIntent.SOP, ("规程", "步骤", "操作", "sop")),
    (M8KnowledgeNormalizedIntent.FAQ, ("常见问题", "为什么", "faq")),
    (M8KnowledgeNormalizedIntent.HISTORICAL_PRECEDENT, ("合成历史", "普通历史文档")),
)


def normalize_knowledge_query(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("M8 knowledge query normalization requires text")
    return re.sub(r"\s+", " ", value.strip()).casefold()


def classify_knowledge_intent(normalized_query: str) -> M8KnowledgeNormalizedIntent:
    for intent, terms in _INTENT_TERMS:
        if any(term in normalized_query for term in terms):
            return intent
    return M8KnowledgeNormalizedIntent.GENERAL


class M8KnowledgeProjectionService:
    def __init__(
        self,
        knowledge_api: M8KnowledgeApiService,
        case_memory: M8CaseMemoryAdapter,
    ) -> None:
        if not isinstance(knowledge_api, M8KnowledgeApiService) or case_memory is None:
            raise TypeError("M8 knowledge projection requires existing knowledge and memory ports")
        self._knowledge = knowledge_api
        self._case_memory = case_memory

    def query(
        self,
        principal: M8ApiPrincipalV1,
        catalog_id: str,
        request: M8ApiKnowledgeQueryRequestV1,
    ) -> M8KnowledgeQueryProjectionV1:
        normalized = normalize_knowledge_query(request.query_text)
        intent = classify_knowledge_intent(normalized)
        receipt = self._knowledge.query(principal, catalog_id, request)
        hits = tuple(
            M8KnowledgeDocumentHitV1(
                document_type=citation.document.document_type,
                logical_document_id=citation.document.logical_document_id,
                document_version=citation.document.document_version,
                source_ref=citation.document.source_ref,
                effective_at=citation.document.effective_at,
                citation_id=citation.citation_id,
                start_char=citation.snippet_start_char,
                end_char=citation.snippet_end_char,
                exact_snippet=citation.snippet,
            )
            for citation in receipt.answer.citations
        )
        case_memory = (
            self._case_memory.query(principal, normalized, 3)
            if intent == M8KnowledgeNormalizedIntent.CASE_MEMORY
            else M8CaseMemoryProjectionV1(availability=M8CaseMemoryAvailability.NO_MATCH)
        )
        return M8KnowledgeQueryProjectionV1(
            normalized_query=normalized,
            normalized_intent=intent,
            applied_document_types=receipt.answer.query.allowed_document_types,
            outcome=receipt.answer.outcome,
            document_hits=hits,
            answer_receipt=receipt,
            case_memory=case_memory,
        )


__all__ = [
    "M8KnowledgeProjectionService",
    "classify_knowledge_intent",
    "normalize_knowledge_query",
]
