"""Application boundary for exact M3 model-call authority in locked M6 replay."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.cases import UsageSummary
from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    HearingUsageReceipt,
)
from labcourt.contracts.model_call_failures import ModelCallFailureAuthority
from labcourt.contracts.screening import (
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)


def _require_sha256(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _require_request(value: object) -> VLMCallRequest:
    if not isinstance(value, (VLMRequest, StructureRepairRequest)):
        raise TypeError("request must be a typed M3 VLM request")
    return value


@dataclass(frozen=True, slots=True)
class M6M3ModelRequestAuthorityDocument:
    request: VLMCallRequest
    document_sha256: str

    def __post_init__(self) -> None:
        _require_request(self.request)
        _require_sha256(self.document_sha256, "request document_sha256")


@dataclass(frozen=True, slots=True)
class M6M3ModelResponseAuthorityDocument:
    response: VLMResponse
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.response, VLMResponse):
            raise TypeError("response must be a typed M3 VLM response")
        _require_sha256(self.document_sha256, "response document_sha256")


@dataclass(frozen=True, slots=True)
class M6M3ModelCacheAuthorityDocument:
    request: VLMCallRequest
    request_document_sha256: str
    entry: ModelCacheEntry
    document_sha256: str

    def __post_init__(self) -> None:
        _require_request(self.request)
        if not isinstance(self.entry, ModelCacheEntry):
            raise TypeError("entry must be a typed M3 model-cache entry")
        _require_sha256(
            self.request_document_sha256,
            "cache request_document_sha256",
        )
        _require_sha256(self.document_sha256, "cache document_sha256")


@dataclass(frozen=True, slots=True)
class M6M3ModelParseReceiptAuthorityDocument:
    receipt: ModelParseReceipt
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, ModelParseReceipt):
            raise TypeError("receipt must be a typed M3 parse receipt")
        _require_sha256(self.document_sha256, "parse receipt document_sha256")


@dataclass(frozen=True, slots=True)
class M6M3ParsedOutputAuthorityDocument:
    output: ParsedScreeningOutput
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.output, ParsedScreeningOutput):
            raise TypeError("output must be a typed M3 parsed output")
        _require_sha256(self.document_sha256, "parsed output document_sha256")


@dataclass(frozen=True, slots=True)
class M6M3ModelCallFailureAuthorityDocument:
    authority: ModelCallFailureAuthority
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.authority, ModelCallFailureAuthority):
            raise TypeError("authority must be a typed M3 model-call failure")
        _require_sha256(self.document_sha256, "failure document_sha256")


@dataclass(frozen=True, slots=True)
class M6M3ModelUsageAuthorityDocument:
    """Canonical M3 usage plus its otherwise out-of-document SQLite bindings."""

    usage: UsageSummary
    request_id: str
    response_id: str
    case_id: str
    case_revision: int
    consumer_kind: str
    consumer_id: str
    accounted_at: str
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.usage, UsageSummary):
            raise TypeError("usage must be a typed M3 UsageSummary")
        _require_sha256(self.request_id, "M3 usage request_id")
        _require_sha256(self.response_id, "M3 usage response_id")
        if not isinstance(self.case_id, str) or not self.case_id:
            raise TypeError("M3 usage case_id must be a non-empty string")
        if (
            not isinstance(self.case_revision, int)
            or isinstance(self.case_revision, bool)
            or self.case_revision <= 0
        ):
            raise ValueError("M3 usage case_revision must be a positive integer")
        if self.consumer_kind not in {"SCREENING_RESULT", "BACKLOG_ITEM"}:
            raise ValueError("M3 usage consumer_kind is invalid")
        _require_sha256(self.consumer_id, "M3 usage consumer_id")
        if (
            not isinstance(self.accounted_at, str)
            or len(self.accounted_at) != 27
            or not self.accounted_at.endswith("Z")
        ):
            raise ValueError("M3 usage accounted_at must be a canonical UTC timestamp")
        _require_sha256(self.document_sha256, "M3 usage document_sha256")


@dataclass(frozen=True, slots=True)
class M6M3ModelCallAuthoritySnapshot:
    """Case-scoped M3 documents read from one immutable SQLite snapshot."""

    source_identity_sha256: str
    run_id: str
    case_id: str
    manifest_id: str
    requests: tuple[M6M3ModelRequestAuthorityDocument, ...]
    responses: tuple[M6M3ModelResponseAuthorityDocument, ...]
    caches: tuple[M6M3ModelCacheAuthorityDocument, ...]
    parse_receipts: tuple[M6M3ModelParseReceiptAuthorityDocument, ...]
    parsed_outputs: tuple[M6M3ParsedOutputAuthorityDocument, ...]
    failures: tuple[M6M3ModelCallFailureAuthorityDocument, ...]
    usages: tuple[M6M3ModelUsageAuthorityDocument, ...] = ()
    authority_failure_count: int = 0

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "source snapshot identity")
        if not isinstance(self.run_id, str) or not self.run_id:
            raise TypeError("run_id must be a non-empty string")
        if not isinstance(self.case_id, str) or not self.case_id:
            raise TypeError("case_id must be a non-empty string")
        _require_sha256(self.manifest_id, "manifest_id")
        groups: tuple[tuple[object, type[object]], ...] = (
            (self.requests, M6M3ModelRequestAuthorityDocument),
            (self.responses, M6M3ModelResponseAuthorityDocument),
            (self.caches, M6M3ModelCacheAuthorityDocument),
            (self.parse_receipts, M6M3ModelParseReceiptAuthorityDocument),
            (self.parsed_outputs, M6M3ParsedOutputAuthorityDocument),
            (self.failures, M6M3ModelCallFailureAuthorityDocument),
            (self.usages, M6M3ModelUsageAuthorityDocument),
        )
        for values, expected_type in groups:
            if not isinstance(values, tuple) or any(
                not isinstance(item, expected_type) for item in values
            ):
                raise TypeError("M3 authority documents must be typed tuples")
        if (
            not isinstance(self.authority_failure_count, int)
            or isinstance(self.authority_failure_count, bool)
            or self.authority_failure_count < 0
        ):
            raise ValueError("authority_failure_count must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class M6M4ModelRequestAuthorityDocument:
    request: HearingModelRequest
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.request, HearingModelRequest):
            raise TypeError("request must be a typed M4 hearing request")
        _require_sha256(self.document_sha256, "M4 request document_sha256")


@dataclass(frozen=True, slots=True)
class M6M4ModelResponseAuthorityDocument:
    response: HearingModelResponse
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.response, HearingModelResponse):
            raise TypeError("response must be a typed M4 hearing response")
        _require_sha256(self.document_sha256, "M4 response document_sha256")


@dataclass(frozen=True, slots=True)
class M6M4ModelCacheAuthorityDocument:
    entry: HearingModelCacheEntry
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.entry, HearingModelCacheEntry):
            raise TypeError("entry must be a typed M4 hearing cache entry")
        _require_sha256(self.document_sha256, "M4 cache document_sha256")


@dataclass(frozen=True, slots=True)
class M6M4ModelParseReceiptAuthorityDocument:
    receipt: HearingModelParseReceipt
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, HearingModelParseReceipt):
            raise TypeError("receipt must be a typed M4 hearing parse receipt")
        _require_sha256(self.document_sha256, "M4 parse receipt document_sha256")


@dataclass(frozen=True, slots=True)
class M6M4RoleOutputAuthorityDocument:
    output: HearingRoleOutput
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.output, HearingRoleOutput):
            raise TypeError("output must be a typed M4 hearing role output")
        _require_sha256(self.document_sha256, "M4 role output document_sha256")


@dataclass(frozen=True, slots=True)
class M6M4ModelCallFailureAuthorityDocument:
    authority: HearingModelCallFailureAuthority
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.authority, HearingModelCallFailureAuthority):
            raise TypeError("authority must be a typed M4 hearing model-call failure")
        _require_sha256(self.document_sha256, "M4 failure document_sha256")


@dataclass(frozen=True, slots=True)
class M6M4ModelUsageAuthorityDocument:
    receipt: HearingUsageReceipt
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, HearingUsageReceipt):
            raise TypeError("receipt must be a typed M4 hearing usage receipt")
        _require_sha256(self.document_sha256, "M4 usage document_sha256")


@dataclass(frozen=True, slots=True)
class M6M4ModelCallAuthoritySnapshot:
    """Case-scoped M4 hearing calls from one fully validated replay snapshot."""

    source_identity_sha256: str
    m4_replay_authority_root_sha256: str
    model_call_authority_root_sha256: str
    run_id: str
    case_id: str
    manifest_id: str
    requests: tuple[M6M4ModelRequestAuthorityDocument, ...]
    responses: tuple[M6M4ModelResponseAuthorityDocument, ...]
    caches: tuple[M6M4ModelCacheAuthorityDocument, ...]
    parse_receipts: tuple[M6M4ModelParseReceiptAuthorityDocument, ...]
    role_outputs: tuple[M6M4RoleOutputAuthorityDocument, ...]
    failures: tuple[M6M4ModelCallFailureAuthorityDocument, ...]
    usages: tuple[M6M4ModelUsageAuthorityDocument, ...] = ()
    authority_failure_count: int = 0

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "M4 source snapshot identity")
        _require_sha256(
            self.m4_replay_authority_root_sha256,
            "M4 replay authority root",
        )
        _require_sha256(
            self.model_call_authority_root_sha256,
            "M4 model-call authority root",
        )
        if not isinstance(self.run_id, str) or not self.run_id:
            raise TypeError("run_id must be a non-empty string")
        if not isinstance(self.case_id, str) or not self.case_id:
            raise TypeError("case_id must be a non-empty string")
        _require_sha256(self.manifest_id, "M4 manifest_id")
        groups: tuple[tuple[object, type[object]], ...] = (
            (self.requests, M6M4ModelRequestAuthorityDocument),
            (self.responses, M6M4ModelResponseAuthorityDocument),
            (self.caches, M6M4ModelCacheAuthorityDocument),
            (self.parse_receipts, M6M4ModelParseReceiptAuthorityDocument),
            (self.role_outputs, M6M4RoleOutputAuthorityDocument),
            (self.failures, M6M4ModelCallFailureAuthorityDocument),
            (self.usages, M6M4ModelUsageAuthorityDocument),
        )
        for values, expected_type in groups:
            if not isinstance(values, tuple) or any(
                not isinstance(item, expected_type) for item in values
            ):
                raise TypeError("M4 authority documents must be typed tuples")
        if (
            not isinstance(self.authority_failure_count, int)
            or isinstance(self.authority_failure_count, bool)
            or self.authority_failure_count < 0
        ):
            raise ValueError("authority_failure_count must be a non-negative integer")


__all__ = [
    "M6M3ModelCacheAuthorityDocument",
    "M6M3ModelCallAuthoritySnapshot",
    "M6M3ModelCallFailureAuthorityDocument",
    "M6M3ModelParseReceiptAuthorityDocument",
    "M6M3ModelRequestAuthorityDocument",
    "M6M3ModelResponseAuthorityDocument",
    "M6M3ModelUsageAuthorityDocument",
    "M6M3ParsedOutputAuthorityDocument",
    "M6M4ModelCacheAuthorityDocument",
    "M6M4ModelCallAuthoritySnapshot",
    "M6M4ModelCallFailureAuthorityDocument",
    "M6M4ModelParseReceiptAuthorityDocument",
    "M6M4ModelRequestAuthorityDocument",
    "M6M4ModelResponseAuthorityDocument",
    "M6M4ModelUsageAuthorityDocument",
    "M6M4RoleOutputAuthorityDocument",
]
