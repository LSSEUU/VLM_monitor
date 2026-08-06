"""Trusted reconstruction boundary for deterministic M3 procedural reviews."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.screening import ModelParseReceipt
from labcourt.contracts.storage import ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict


class ProceduralReviewVerifier(Protocol):
    """Rebuild the only review eligible for an M3 verdict commit.

    The caller supplies already-persisted semantic roots.  Implementations own
    the trusted configuration and evidence authorities needed to reproduce L5.
    Keeping reconstruction behind this port lets persistence fail closed without
    importing application or domain implementations.
    """

    def rebuild_review(
        self,
        verdict: Verdict,
        evidence_pack: EvidencePack,
        current_closure: ClosureReport,
        parse_history: tuple[ModelParseReceipt, ...],
        review_version: int,
    ) -> ProceduralReview: ...


__all__ = ["ProceduralReviewVerifier"]
