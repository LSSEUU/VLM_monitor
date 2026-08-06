"""Precedent persistence and retrieval port."""

from typing import Protocol

from labcourt.contracts.enums import EvidenceClass, ViolationType
from labcourt.contracts.m3_models import PrecedentLookupQuery, PrecedentResolution
from labcourt.contracts.precedents import Precedent, ScoredPrecedent


class PrecedentQuery(Protocol):
    case_id: str
    evidence_class: EvidenceClass
    violation_type: ViolationType
    rule_version: str
    situation_text: str


class PrecedentLookup(Protocol):
    def lookup(self, query: PrecedentLookupQuery) -> PrecedentResolution: ...


class PrecedentStore(Protocol):
    def add(self, run_id: str, precedent: Precedent) -> None: ...

    def retrieve(
        self,
        run_id: str,
        query: PrecedentQuery,
        limit: int,
    ) -> tuple[ScoredPrecedent, ...]: ...

    def record_citation(
        self,
        run_id: str,
        case_id: str,
        precedent_id: str,
        score: float,
    ) -> None: ...

    def find_conflicts(
        self,
        run_id: str,
        precedent: Precedent,
        limit: int,
    ) -> tuple[ScoredPrecedent, ...]: ...


__all__ = ["PrecedentLookup", "PrecedentQuery", "PrecedentStore"]
