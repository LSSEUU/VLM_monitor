"""Private workflow value types shared by the M3 coordinator components."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from labcourt.contracts.backlog import (
    BacklogItem,
    BacklogStrictParseFailureProof,
)
from labcourt.contracts.enums import BacklogReasonCode, VlmRole
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.screening import (
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningResult,
    VLMResponse,
)
from labcourt.contracts.storage import ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.screening_repository import ModelCallFailureIntent


class ScreeningCoordinatorErrorCode(StrEnum):
    INVALID_CASE_STATE = "INVALID_CASE_STATE"
    CASE_SCOPE_MISMATCH = "CASE_SCOPE_MISMATCH"
    CURRENT_PACK_MISSING = "CURRENT_PACK_MISSING"
    CURRENT_PACK_BINDING_INVALID = "CURRENT_PACK_BINDING_INVALID"


class ScreeningCoordinatorError(ValueError):
    """Controlled orchestration failure that contains no model-authored data."""

    def __init__(self, code: ScreeningCoordinatorErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class ScreeningPipelineOutcome:
    """One terminal or safely deferred result of an M3 processing invocation."""

    case: CaseSnapshot
    screening_result: ScreeningResult | None = None
    verdict: Verdict | None = None
    procedural_review: ProceduralReview | None = None
    backlog_item: BacklogItem | None = None
    cache_hit_count: int = 0
    recovered_response_count: int = 0
    repair_attempted: bool = False


@dataclass(frozen=True, slots=True)
class _CurrentAuthority:
    snapshot: CaseSnapshot
    pack: EvidencePack
    closure: ClosureReport
    audit_head: AuditHead


@dataclass(frozen=True, slots=True)
class _ModelCallResult:
    response: VLMResponse
    raw_bytes: bytes
    cache_hit: bool
    recovered: bool


@dataclass(frozen=True, slots=True)
class _ParsedStage:
    output: ParsedScreeningOutput
    history: tuple[ModelParseReceipt, ...]
    cache_hit_count: int
    recovered_response_count: int
    repair_attempted: bool


class _BacklogRequired(Exception):
    def __init__(
        self,
        reason: BacklogReasonCode,
        role: VlmRole,
        response_ids: tuple[str, ...] = (),
        strict_parse_failure: BacklogStrictParseFailureProof | None = None,
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> None:
        self.reason = reason
        self.role = role
        self.response_ids = response_ids
        self.strict_parse_failure = strict_parse_failure
        self.model_call_failure = model_call_failure
        super().__init__(reason.value)


class _RetryPublicationRecoveryRequired(Exception):
    """A retry response is durable on disk but not yet published in SQLite."""

    def __init__(self, original: Exception) -> None:
        self.original = original
        super().__init__(type(original).__name__)
