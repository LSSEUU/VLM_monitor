"""Precedent records and deterministic retrieval results."""

from __future__ import annotations

from pydantic import Field, StrictFloat

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    VerdictDecision,
    ViolationType,
)


class Precedent(FrozenContractModel):
    precedent_id: str = Field(min_length=1)
    situation_text: str = Field(min_length=1)
    text_embedding_ref: str | None = None
    visual_embedding_refs: tuple[str, ...] = ()
    decision_direction: VerdictDecision
    source: PrecedentSource
    status: PrecedentStatus
    evidence_class: EvidenceClass
    violation_type: ViolationType
    rule_version: str = Field(min_length=1)
    source_case_id: str | None = None
    activation_at: str | None = None
    invalidated_by: str | None = None
    citation_count: int = Field(default=0, ge=0, strict=True)


class ScoredPrecedent(FrozenContractModel):
    precedent: Precedent
    text_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    visual_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    fused_score: StrictFloat = Field(ge=-1)
