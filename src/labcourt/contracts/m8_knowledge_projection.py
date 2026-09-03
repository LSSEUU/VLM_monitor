"""Additive explainability and separated Case-memory projections for M8 knowledge."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8OperationalCaseStatus, M8OperationalRiskLevel
from labcourt.contracts.m8_knowledge import M8KnowledgeAnswerOutcome, M8KnowledgeDocumentType
from labcourt.contracts.m8_knowledge_persistence import M8KnowledgeAnswerCommitReceiptV1
from labcourt.contracts.references import ReferenceToken


class M8KnowledgeNormalizedIntent(StrEnum):
    CASE_MEMORY = "CASE_MEMORY"
    DEVICE = "DEVICE"
    EMERGENCY = "EMERGENCY"
    FAQ = "FAQ"
    GENERAL = "GENERAL"
    HISTORICAL_PRECEDENT = "HISTORICAL_PRECEDENT"
    POLICY = "POLICY"
    SOP = "SOP"


class M8CaseMemoryAvailability(StrEnum):
    AVAILABLE = "AVAILABLE"
    NO_MATCH = "NO_MATCH"
    NO_PLATFORM_AUTHORITY = "NO_PLATFORM_AUTHORITY"


class M8KnowledgeDocumentHitV1(FrozenContractModel):
    schema_version: Literal["m8-knowledge-document-hit-v1"] = "m8-knowledge-document-hit-v1"
    document_type: M8KnowledgeDocumentType
    logical_document_id: ReferenceToken
    document_version: int = Field(gt=0, strict=True)
    source_ref: ReferenceToken
    effective_at: datetime
    citation_id: Sha256Hex
    start_char: int = Field(ge=0, strict=True)
    end_char: int = Field(gt=0, strict=True)
    exact_snippet: str = Field(min_length=1, max_length=2_048)

    @model_validator(mode="after")
    def validate_span(self) -> Self:
        if self.start_char >= self.end_char:
            raise ValueError("M8 knowledge hit requires a positive exact character span")
        return self


class M8CaseMemoryEntryV1(FrozenContractModel):
    """One role-scoped, persisted Case citation; never a rule or ground truth."""

    schema_version: Literal["m8-case-memory-entry-v1"] = "m8-case-memory-entry-v1"
    case_id: Sha256Hex
    case_version: int = Field(gt=0, strict=True)
    status: M8OperationalCaseStatus
    risk_level: M8OperationalRiskLevel
    location_id: ReferenceToken
    case_authority_id: Sha256Hex
    case_document_sha256: Sha256Hex
    audit_event_id: Sha256Hex
    summary: str = Field(min_length=1, max_length=512)
    persisted_case_authority: Literal[True] = True
    machine_weak_label_is_ground_truth: Literal[False] = False
    current_rule_rewrite_permitted: Literal[False] = False


class M8CaseMemoryProjectionV1(FrozenContractModel):
    schema_version: Literal["m8-case-memory-projection-v1"] = "m8-case-memory-projection-v1"
    availability: M8CaseMemoryAvailability
    entries: tuple[M8CaseMemoryEntryV1, ...] = Field(default=(), max_length=8)
    partition: Literal["CASE_PRECEDENT_AUTHORITY"] = "CASE_PRECEDENT_AUTHORITY"
    ordinary_document_partition_used: Literal[False] = False
    machine_weak_label_is_ground_truth: Literal[False] = False
    current_rule_rewrite_permitted: Literal[False] = False

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        if (self.availability == M8CaseMemoryAvailability.AVAILABLE) != bool(self.entries):
            raise ValueError("M8 Case-memory availability must match its exact entry inventory")
        return self


class M8KnowledgeQueryProjectionV1(FrozenContractModel):
    """Explain one existing deterministic answer without inventing quality metrics."""

    schema_version: Literal["m8-knowledge-query-projection-v1"] = "m8-knowledge-query-projection-v1"
    normalized_query: str = Field(min_length=1, max_length=1_024)
    normalized_intent: M8KnowledgeNormalizedIntent
    applied_document_types: tuple[M8KnowledgeDocumentType, ...] = Field(
        min_length=1,
        max_length=len(M8KnowledgeDocumentType),
    )
    outcome: M8KnowledgeAnswerOutcome
    document_hits: tuple[M8KnowledgeDocumentHitV1, ...] = Field(default=(), max_length=32)
    answer_receipt: M8KnowledgeAnswerCommitReceiptV1
    case_memory: M8CaseMemoryProjectionV1
    exact_citations_only: Literal[True] = True
    similarity_score_reported: Literal[False] = False
    accuracy_claimed: Literal[False] = False
    recall_claimed: Literal[False] = False
    latency_claimed: Literal[False] = False
    network_used: Literal[False] = False
    model_used: Literal[False] = False

    @model_validator(mode="after")
    def validate_answer_binding(self) -> Self:
        answer = self.answer_receipt.answer
        if self.outcome != answer.outcome:
            raise ValueError("M8 knowledge projection outcome conflicts with persisted answer")
        if self.applied_document_types != answer.query.allowed_document_types:
            raise ValueError("M8 knowledge projection filters conflict with the exact query")
        if len(self.document_hits) != len(answer.citations):
            raise ValueError("M8 knowledge projection must explain every exact citation")
        for hit, citation in zip(self.document_hits, answer.citations, strict=True):
            document = citation.document
            if (
                hit.document_type != document.document_type
                or hit.logical_document_id != document.logical_document_id
                or hit.document_version != document.document_version
                or hit.source_ref != document.source_ref
                or hit.effective_at != document.effective_at
                or hit.citation_id != citation.citation_id
                or hit.start_char != citation.snippet_start_char
                or hit.end_char != citation.snippet_end_char
                or hit.exact_snippet != citation.snippet
            ):
                raise ValueError("M8 knowledge hit conflicts with its exact citation")
        return self


__all__ = [
    "M8CaseMemoryAvailability",
    "M8CaseMemoryEntryV1",
    "M8CaseMemoryProjectionV1",
    "M8KnowledgeDocumentHitV1",
    "M8KnowledgeNormalizedIntent",
    "M8KnowledgeQueryProjectionV1",
]
