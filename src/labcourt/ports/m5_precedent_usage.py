"""Persistence boundary for prompt exposure, distinct from later citation/application."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.hearing_retrieval import HearingPrecedentRetrievalOutcome
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingRecord,
    HearingRound,
    HearingVerdictBinding,
)
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
    M5PrecedentExposureBatchAuthority,
)
from labcourt.ports.evidence_repository import CaseSnapshot


class M5ReadyPrecedentUsageKind(StrEnum):
    FAST = "FAST"
    FINAL_DEGRADED = "FINAL_DEGRADED"
    FINAL_EXPOSED = "FINAL_EXPOSED"


@dataclass(frozen=True, slots=True)
class M5ReadyPrecedentUsage:
    """Strict origin of the latest Verdict in one READY Case revision."""

    kind: M5ReadyPrecedentUsageKind
    verdict_binding: HearingVerdictBinding | None = None
    hearing_record: HearingRecord | None = None
    hearing_round: HearingRound | None = None
    retrieval_receipt: HearingPrecedentRetrievalReceipt | None = None
    exposure: M5PrecedentExposureBatchAuthority | None = None

    def __post_init__(self) -> None:
        hearing_roots = (
            self.verdict_binding,
            self.hearing_record,
            self.hearing_round,
            self.retrieval_receipt,
        )
        if self.kind == M5ReadyPrecedentUsageKind.FAST:
            if any(item is not None for item in (*hearing_roots, self.exposure)):
                raise ValueError("FAST precedent usage cannot carry hearing roots")
            return
        if any(item is None for item in hearing_roots):
            raise ValueError("final hearing precedent usage requires complete M4 roots")
        binding = self.verdict_binding
        record = self.hearing_record
        hearing_round = self.hearing_round
        receipt = self.retrieval_receipt
        assert binding is not None
        assert record is not None
        assert hearing_round is not None
        assert receipt is not None
        if (
            not record.rounds
            or record.rounds[-1] != hearing_round
            or binding.hearing_record_id != record.record_id
            or binding.hearing_record_version != record.version
            or binding.hearing_record_sha256 != record.record_sha256
            or binding.judge_round_id != hearing_round.round_id
            or binding.judge_round_index != hearing_round.round_index
            or hearing_round.precedent_retrieval_receipt != receipt
        ):
            raise ValueError("final hearing precedent roots do not form one exact closure")
        if self.kind == M5ReadyPrecedentUsageKind.FINAL_DEGRADED:
            if (
                receipt.status != HearingPrecedentRetrievalStatus.DEGRADED
                or self.exposure is not None
            ):
                raise ValueError("FINAL_DEGRADED requires a degraded receipt and no exposure")
            return
        if self.kind != M5ReadyPrecedentUsageKind.FINAL_EXPOSED:
            raise ValueError("unknown READY precedent usage kind")
        exposure = self.exposure
        if (
            receipt.status != HearingPrecedentRetrievalStatus.SUCCESS
            or exposure is None
            or exposure.m4_retrieval_outcome.receipt != receipt
            or exposure.cycle_scope_id != hearing_round.cycle_scope_id
        ):
            raise ValueError("FINAL_EXPOSED requires the exact successful exposure")


class M5PrecedentExposureStore(Protocol):
    """Atomically persist M4 retrieval plus its independent EXPOSED authority."""

    def commit(
        self,
        outcome: HearingPrecedentRetrievalOutcome,
    ) -> HearingPrecedentRetrievalReceipt: ...

    def load_exposure(
        self,
        run_id: str,
        cycle_scope_id: str,
    ) -> M5PrecedentExposureBatchAuthority | None: ...


class M5PrecedentApplicationVerifier(Protocol):
    """Rebuild APPLIED authorities from a pinned AppConfig without repository I/O."""

    def rebuild_application(
        self,
        case_snapshot: CaseSnapshot,
        exposure: M5PrecedentExposureBatchAuthority,
    ) -> M5PrecedentApplicationBatchAuthority: ...

    def rebuild_citations(
        self,
        application_batch: M5PrecedentApplicationBatchAuthority,
        cited_at: datetime,
    ) -> tuple[M5PrecedentApplicationCitationCommit, ...]: ...


class M5PrecedentApplicationRepository(Protocol):
    def resolve_ready_precedent_usage(
        self,
        run_id: str,
        case_id: str,
        expected_revision: int,
    ) -> M5ReadyPrecedentUsage: ...


__all__ = [
    "M5PrecedentApplicationRepository",
    "M5PrecedentApplicationVerifier",
    "M5PrecedentExposureStore",
    "M5ReadyPrecedentUsage",
    "M5ReadyPrecedentUsageKind",
]
