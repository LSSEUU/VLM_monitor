"""Trusted reconstruction boundary for deterministic M3 derived semantics."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.screening import ParsedScreeningOutput, ScreeningResult
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Verdict


class M3SemanticVerifier(Protocol):
    """Rebuild the only screening and fast-verdict objects eligible for commit."""

    def rebuild_screening(
        self,
        parsed_output: ParsedScreeningOutput,
        evidence_pack: EvidencePack,
        screening_version: int,
    ) -> ScreeningResult: ...

    def rebuild_fast_verdict(
        self,
        screening_result: ScreeningResult,
        evidence_pack: EvidencePack,
        model_response_refs: tuple[ArtifactRef, ...],
        verdict_version: int,
    ) -> Verdict: ...


__all__ = ["M3SemanticVerifier"]
