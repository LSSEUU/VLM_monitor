"""Identity-first M3 model-call physical resolution for M6 upgrades."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import TypeAdapter, ValidationError

from labcourt.application.m6_model_call_authority import (
    assemble_m6_locked_screening_model_calls,
)
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, UsageSummary
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6ReplayAuthorityRef,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.model_call_failures import ModelCallFailureAuthority
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import (
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_model_calls import (
    M6M3ModelCacheAuthorityDocument,
    M6M3ModelCallAuthoritySnapshot,
    M6M3ModelCallFailureAuthorityDocument,
    M6M3ModelParseReceiptAuthorityDocument,
    M6M3ModelRequestAuthorityDocument,
    M6M3ModelResponseAuthorityDocument,
    M6M3ModelUsageAuthorityDocument,
    M6M3ParsedOutputAuthorityDocument,
)
from labcourt.ports.m6_upgrade_model_physical import (
    M6ObservedModelCallPhysicalClosure,
    M6PlannedModelCallPhysicalClosure,
)
from labcourt.ports.vlm import RawModelResponseVerifier

_ModelT = TypeVar("_ModelT", bound=FrozenContractModel)
_REQUEST_ADAPTER: TypeAdapter[VLMCallRequest] = TypeAdapter(VLMCallRequest)
_SOURCE = M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL


class M6M3ModelPhysicalResolutionErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    AUTHORITY_ASSEMBLY_FAILED = "AUTHORITY_ASSEMBLY_FAILED"
    CALL_AUTHORITY_INVALID = "CALL_AUTHORITY_INVALID"
    CALL_BINDING_MISMATCH = "CALL_BINDING_MISMATCH"
    RAW_RESPONSE_EMPTY = "RAW_RESPONSE_EMPTY"
    PHYSICAL_BUDGET_EXCEEDED = "PHYSICAL_BUDGET_EXCEEDED"
    PHYSICAL_PLAN_INVALID = "PHYSICAL_PLAN_INVALID"
    RAW_RESPONSE_VERIFIER_FAILED = "RAW_RESPONSE_VERIFIER_FAILED"
    RAW_RESPONSE_NOT_EXACT = "RAW_RESPONSE_NOT_EXACT"
    PHYSICAL_REF_INVALID = "PHYSICAL_REF_INVALID"
    OBSERVED_CLOSURE_INVALID = "OBSERVED_CLOSURE_INVALID"


class M6M3ModelPhysicalResolutionError(LabCourtError):
    """Payload-free M3 physical model-call resolution failure."""

    def __init__(self, code: M6M3ModelPhysicalResolutionErrorCode) -> None:
        if not isinstance(code, M6M3ModelPhysicalResolutionErrorCode):
            raise TypeError("code must be an M6 M3 model physical resolution error code")
        self.code = code
        super().__init__(f"M6 M3 model physical resolution failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6M3ModelPhysicalPlan:
    """Complete M3 call graph planned before any raw response is read."""

    source_identity_sha256: str
    run_id: str
    case_id: str
    manifest_id: str
    planned_calls: tuple[M6PlannedModelCallPhysicalClosure, ...]
    declared_physical_bytes: int

    def __post_init__(self) -> None:
        for value, label in (
            (self.source_identity_sha256, "source_identity_sha256"),
            (self.manifest_id, "manifest_id"),
        ):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{label} must be a lowercase SHA-256")
        if not isinstance(self.run_id, str) or not isinstance(self.case_id, str):
            raise TypeError("M6 M3 physical plan scope must use strings")
        require_reference_token(self.run_id, "M6 M3 physical plan run_id")
        require_reference_token(self.case_id, "M6 M3 physical plan case_id")
        if type(self.planned_calls) is not tuple or any(
            type(item) is not M6PlannedModelCallPhysicalClosure for item in self.planned_calls
        ):
            raise TypeError("M6 M3 physical plan requires typed planned calls")
        if self.planned_calls != tuple(sorted(self.planned_calls, key=lambda item: item.sort_key)):
            raise ValueError("M6 M3 physical plan calls must be stably ordered")
        if any(
            item.source_identity_sha256 != self.source_identity_sha256
            or item.run_id != self.run_id
            or item.case_id != self.case_id
            or item.manifest_id != self.manifest_id
            or item.layer != M6LockedModelCallLayer.SCREENING
            or item.role != M6LockedModelRole.SCREENING
            for item in self.planned_calls
        ):
            raise ValueError("M6 M3 physical plan crosses its declared scope")
        refs = self.planned_refs
        if len({item.request_ref.physical_key for item in self.planned_calls}) != len(
            self.planned_calls
        ) or len({ref.physical_key for ref in refs}) != len(refs):
            raise ValueError("M6 M3 physical plan references must be globally unique")
        if (
            type(self.declared_physical_bytes) is not int
            or self.declared_physical_bytes < 0
            or self.declared_physical_bytes != sum(ref.size_bytes for ref in refs)
        ):
            raise ValueError("M6 M3 physical plan byte declaration is inconsistent")

    @property
    def planned_refs(self) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        """All planned refs in one deterministic physical-key order."""

        return tuple(
            sorted(
                (ref for planned_call in self.planned_calls for ref in planned_call.artifact_refs),
                key=lambda ref: ref.sort_key,
            )
        )


def _fail(code: M6M3ModelPhysicalResolutionErrorCode) -> NoReturn:
    raise M6M3ModelPhysicalResolutionError(code)


def _document_sha256(canonical_document: str) -> str:
    return hashlib.sha256(canonical_document.encode("utf-8")).hexdigest()


def _canonical_document(
    value: object,
    model_type: type[_ModelT],
    claimed_sha256: str,
) -> tuple[_ModelT, str]:
    if not isinstance(value, model_type):
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID)
    try:
        controlled = model_type.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
        canonical = canonical_json(controlled.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID)
    if (
        controlled != value
        or not isinstance(claimed_sha256, str)
        or _document_sha256(canonical) != claimed_sha256
    ):
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID)
    return controlled, canonical


def _canonical_request(
    document: M6M3ModelRequestAuthorityDocument,
) -> tuple[VLMCallRequest, str]:
    try:
        controlled = _REQUEST_ADAPTER.validate_python(
            document.request.model_dump(mode="json", exclude_computed_fields=True)
        )
        canonical = canonical_json(controlled.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID)
    if controlled != document.request or _document_sha256(canonical) != document.document_sha256:
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID)
    return controlled, canonical


def _canonical_physical_ref(
    *,
    kind: M6UpgradePhysicalArtifactKind,
    artifact_id: str,
    document: FrozenContractModel,
    canonical_document: str,
    claimed_sha256: str,
) -> M6UpgradePhysicalArtifactRef:
    if canonical_json(document.model_dump(mode="json")) != canonical_document:
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID)
    document_sha256 = _document_sha256(canonical_document)
    if document_sha256 != claimed_sha256:
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_AUTHORITY_INVALID)
    try:
        return M6UpgradePhysicalArtifactRef(
            source=_SOURCE,
            kind=kind,
            artifact_id=artifact_id,
            document_sha256=document_sha256,
            content_sha256=document_sha256,
            size_bytes=len(canonical_document.encode("utf-8")),
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_REF_INVALID)


def _response_physical_ref(
    document: M6M3ModelResponseAuthorityDocument,
    response: VLMResponse,
) -> M6UpgradePhysicalArtifactRef:
    try:
        return M6UpgradePhysicalArtifactRef(
            source=_SOURCE,
            kind=M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
            document_sha256=document.document_sha256,
            content_sha256=response.content_sha256,
            size_bytes=response.size_bytes,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_REF_INVALID)


def _require_locked_ref(
    ref: M6ReplayAuthorityRef | None,
    *,
    artifact_id: str,
    document_sha256: str,
) -> None:
    if ref is None or ref.artifact_id != artifact_id or ref.document_sha256 != document_sha256:
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)


@dataclass(frozen=True, slots=True)
class _PreparedCall:
    locked: M6LockedModelCallInput
    request: VLMCallRequest
    request_ref: M6UpgradePhysicalArtifactRef
    timeout_ms: int
    response_document: M6M3ModelResponseAuthorityDocument | None = None
    response: VLMResponse | None = None
    response_ref: M6UpgradePhysicalArtifactRef | None = None
    cache_ref: M6UpgradePhysicalArtifactRef | None = None
    parse_receipt_ref: M6UpgradePhysicalArtifactRef | None = None
    parsed_output_ref: M6UpgradePhysicalArtifactRef | None = None
    failure_ref: M6UpgradePhysicalArtifactRef | None = None
    usage_receipt_ref: M6UpgradePhysicalArtifactRef | None = None

    @property
    def planned_refs(self) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        return tuple(
            ref
            for ref in (
                self.request_ref,
                self.response_ref,
                self.cache_ref,
                self.parse_receipt_ref,
                self.parsed_output_ref,
                self.failure_ref,
                self.usage_receipt_ref,
            )
            if ref is not None
        )

    @property
    def declared_physical_bytes(self) -> int:
        return sum(ref.size_bytes for ref in self.planned_refs)


def _prepare_request(
    *,
    source_case: Case,
    locked: M6LockedModelCallInput,
    document: M6M3ModelRequestAuthorityDocument,
) -> tuple[VLMCallRequest, M6UpgradePhysicalArtifactRef, int]:
    request, canonical = _canonical_request(document)
    expected_attempt = 0 if isinstance(request, VLMRequest) else 1
    if (
        request.run_id != source_case.run_id
        or request.case_id != source_case.case_id
        or request.manifest_id != source_case.manifest_id
        or locked.layer != M6LockedModelCallLayer.SCREENING
        or locked.role != M6LockedModelRole.SCREENING
        or locked.attempt_index != expected_attempt
    ):
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
    _require_locked_ref(
        locked.request_ref,
        artifact_id=request.request_id,
        document_sha256=document.document_sha256,
    )
    timeout_ms = int(request.budget.timeout_seconds * 1_000)
    if not 0 < timeout_ms <= 3_600_000:
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
    request_ref = _canonical_physical_ref(
        kind=M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
        artifact_id=request.request_id,
        document=request,
        canonical_document=canonical,
        claimed_sha256=document.document_sha256,
    )
    return request, request_ref, timeout_ms


def _prepare_success(
    *,
    locked: M6LockedModelCallInput,
    request: VLMCallRequest,
    request_ref: M6UpgradePhysicalArtifactRef,
    timeout_ms: int,
    response_document: M6M3ModelResponseAuthorityDocument,
    cache_document: M6M3ModelCacheAuthorityDocument,
    receipt_document: M6M3ModelParseReceiptAuthorityDocument,
    output_document: M6M3ParsedOutputAuthorityDocument | None,
    usage_document: M6M3ModelUsageAuthorityDocument,
) -> _PreparedCall:
    response, _response_canonical = _canonical_document(
        response_document.response,
        VLMResponse,
        response_document.document_sha256,
    )
    cache, cache_canonical = _canonical_document(
        cache_document.entry,
        ModelCacheEntry,
        cache_document.document_sha256,
    )
    receipt, receipt_canonical = _canonical_document(
        receipt_document.receipt,
        ModelParseReceipt,
        receipt_document.document_sha256,
    )
    usage, usage_canonical = _canonical_document(
        usage_document.usage,
        UsageSummary,
        usage_document.document_sha256,
    )
    output: ParsedScreeningOutput | None = None
    output_canonical: str | None = None
    if output_document is not None:
        output, output_canonical = _canonical_document(
            output_document.output,
            ParsedScreeningOutput,
            output_document.document_sha256,
        )
    _require_locked_ref(
        locked.response_ref,
        artifact_id=response.response_id,
        document_sha256=response_document.document_sha256,
    )
    _require_locked_ref(
        locked.cache_ref,
        artifact_id=cache.cache_entry_id,
        document_sha256=cache_document.document_sha256,
    )
    _require_locked_ref(
        locked.parse_receipt_ref,
        artifact_id=receipt.parse_receipt_id,
        document_sha256=receipt_document.document_sha256,
    )
    if output_document is None:
        if locked.parsed_output_ref is not None:
            _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
    else:
        assert output is not None
        _require_locked_ref(
            locked.parsed_output_ref,
            artifact_id=output.parsed_output_id,
            document_sha256=output_document.document_sha256,
        )
    if (
        response.request_id != request.request_id
        or response.model_manifest_id != request.model_manifest_id
        or response.attempt_index != locked.attempt_index
        or usage_document.request_id != request.request_id
        or usage_document.response_id != response.response_id
        or locked.raw_content_sha256 != response.content_sha256
        or locked.raw_size_bytes != response.size_bytes
    ):
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
    if response.size_bytes <= 0:
        _fail(M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_EMPTY)
    cache_ref = _canonical_physical_ref(
        kind=M6UpgradePhysicalArtifactKind.MODEL_CACHE,
        artifact_id=cache.cache_entry_id,
        document=cache,
        canonical_document=cache_canonical,
        claimed_sha256=cache_document.document_sha256,
    )
    receipt_ref = _canonical_physical_ref(
        kind=M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
        artifact_id=receipt.parse_receipt_id,
        document=receipt,
        canonical_document=receipt_canonical,
        claimed_sha256=receipt_document.document_sha256,
    )
    output_ref = (
        _canonical_physical_ref(
            kind=M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
            artifact_id=output.parsed_output_id,
            document=output,
            canonical_document=output_canonical,
            claimed_sha256=output_document.document_sha256,
        )
        if output is not None and output_canonical is not None and output_document is not None
        else None
    )
    usage_ref = _canonical_physical_ref(
        kind=M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
        artifact_id=usage_document.request_id,
        document=usage,
        canonical_document=usage_canonical,
        claimed_sha256=usage_document.document_sha256,
    )
    response_ref = _response_physical_ref(response_document, response)
    return _PreparedCall(
        locked=locked,
        request=request,
        request_ref=request_ref,
        timeout_ms=timeout_ms,
        response_document=response_document,
        response=response,
        response_ref=response_ref,
        cache_ref=cache_ref,
        parse_receipt_ref=receipt_ref,
        parsed_output_ref=output_ref,
        usage_receipt_ref=usage_ref,
    )


def _prepare_failure(
    *,
    locked: M6LockedModelCallInput,
    request: VLMCallRequest,
    request_ref: M6UpgradePhysicalArtifactRef,
    timeout_ms: int,
    failure_document: M6M3ModelCallFailureAuthorityDocument,
) -> _PreparedCall:
    failure, failure_canonical = _canonical_document(
        failure_document.authority,
        ModelCallFailureAuthority,
        failure_document.document_sha256,
    )
    _require_locked_ref(
        locked.failure_ref,
        artifact_id=failure.authority_id,
        document_sha256=failure_document.document_sha256,
    )
    if (
        failure.request.request_id != request.request_id
        or failure.request.model_manifest_id != request.model_manifest_id
    ):
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
    failure_ref = _canonical_physical_ref(
        kind=M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
        artifact_id=failure.authority_id,
        document=failure,
        canonical_document=failure_canonical,
        claimed_sha256=failure_document.document_sha256,
    )
    return _PreparedCall(
        locked=locked,
        request=request,
        request_ref=request_ref,
        timeout_ms=timeout_ms,
        failure_ref=failure_ref,
    )


def _prepare_calls(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
    locked_calls: tuple[M6LockedModelCallInput, ...],
) -> tuple[_PreparedCall, ...]:
    requests = {item.request.request_id: item for item in snapshot.requests}
    responses = {item.response.response_id: item for item in snapshot.responses}
    caches = {item.entry.cache_entry_id: item for item in snapshot.caches}
    receipts = {item.receipt.parse_receipt_id: item for item in snapshot.parse_receipts}
    outputs = {item.output.parsed_output_id: item for item in snapshot.parsed_outputs}
    failures = {item.authority.authority_id: item for item in snapshot.failures}
    usages = {item.request_id: item for item in snapshot.usages}
    prepared: list[_PreparedCall] = []
    for locked in locked_calls:
        request_document = requests.get(locked.request_ref.artifact_id)
        if request_document is None:
            _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
        request, request_ref, timeout_ms = _prepare_request(
            source_case=source_case,
            locked=locked,
            document=request_document,
        )
        if locked.result_kind == M6LockedModelCallResultKind.RESPONSE:
            if (
                locked.response_ref is None
                or locked.cache_ref is None
                or locked.parse_receipt_ref is None
            ):
                _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
            response_document = responses.get(locked.response_ref.artifact_id)
            cache_document = caches.get(locked.cache_ref.artifact_id)
            receipt_document = receipts.get(locked.parse_receipt_ref.artifact_id)
            output_document = (
                outputs.get(locked.parsed_output_ref.artifact_id)
                if locked.parsed_output_ref is not None
                else None
            )
            usage_document = usages.get(request.request_id)
            if (
                response_document is None
                or cache_document is None
                or receipt_document is None
                or usage_document is None
            ):
                _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
            prepared.append(
                _prepare_success(
                    locked=locked,
                    request=request,
                    request_ref=request_ref,
                    timeout_ms=timeout_ms,
                    response_document=response_document,
                    cache_document=cache_document,
                    receipt_document=receipt_document,
                    output_document=output_document,
                    usage_document=usage_document,
                )
            )
            continue
        if locked.failure_ref is None:
            _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
        failure_document = failures.get(locked.failure_ref.artifact_id)
        if failure_document is None:
            _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
        prepared.append(
            _prepare_failure(
                locked=locked,
                request=request,
                request_ref=request_ref,
                timeout_ms=timeout_ms,
                failure_document=failure_document,
            )
        )
    return tuple(prepared)


def _verify_exact_raw_response(
    prepared: _PreparedCall,
    verifier: RawModelResponseVerifier,
) -> None:
    response = prepared.response
    document = prepared.response_document
    response_ref = prepared.response_ref
    if response is None or document is None or response_ref is None:
        _fail(M6M3ModelPhysicalResolutionErrorCode.CALL_BINDING_MISMATCH)
    if _response_physical_ref(document, response) != response_ref:
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    try:
        verifier_request = _REQUEST_ADAPTER.validate_python(
            prepared.request.model_dump(mode="json", exclude_computed_fields=True)
        )
        verifier_response = VLMResponse.model_validate(
            response.model_dump(mode="json", exclude_computed_fields=True)
        )
        observed = verifier.verify_raw_response(
            prepared.request.run_id,
            verifier_request,
            verifier_response,
        )
    except Exception:
        _fail(M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED)
    if not isinstance(observed, VLMResponse):
        _fail(M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_NOT_EXACT)
    try:
        controlled = VLMResponse.model_validate(
            observed.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_NOT_EXACT)
    if controlled != observed or controlled != response:
        _fail(M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_NOT_EXACT)


def _planned_closure(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
    prepared: _PreparedCall,
) -> M6PlannedModelCallPhysicalClosure:
    try:
        return M6PlannedModelCallPhysicalClosure(
            source_identity_sha256=snapshot.source_identity_sha256,
            run_id=source_case.run_id,
            case_id=source_case.case_id,
            manifest_id=source_case.manifest_id,
            layer=prepared.locked.layer,
            role=prepared.locked.role,
            attempt_index=prepared.locked.attempt_index,
            timeout_ms=prepared.timeout_ms,
            execution_model_manifest_id=prepared.request.model_manifest_id,
            request_ref=prepared.request_ref,
            result_kind=prepared.locked.result_kind,
            response_ref=prepared.response_ref,
            cache_ref=prepared.cache_ref,
            parse_receipt_ref=prepared.parse_receipt_ref,
            parsed_output_ref=prepared.parsed_output_ref,
            failure_ref=prepared.failure_ref,
            usage_receipt_ref=prepared.usage_receipt_ref,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)


def _controlled_planned_call(
    value: object,
) -> M6PlannedModelCallPhysicalClosure:
    if type(value) is not M6PlannedModelCallPhysicalClosure:
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    try:
        controlled = M6PlannedModelCallPhysicalClosure(
            source_identity_sha256=value.source_identity_sha256,
            run_id=value.run_id,
            case_id=value.case_id,
            manifest_id=value.manifest_id,
            layer=value.layer,
            role=value.role,
            attempt_index=value.attempt_index,
            timeout_ms=value.timeout_ms,
            execution_model_manifest_id=value.execution_model_manifest_id,
            request_ref=value.request_ref,
            result_kind=value.result_kind,
            response_ref=value.response_ref,
            cache_ref=value.cache_ref,
            parse_receipt_ref=value.parse_receipt_ref,
            parsed_output_ref=value.parsed_output_ref,
            failure_ref=value.failure_ref,
            usage_receipt_ref=value.usage_receipt_ref,
        )
    except Exception:
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    if controlled != value:
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    return controlled


def _controlled_plan(value: object) -> M6M3ModelPhysicalPlan:
    if type(value) is not M6M3ModelPhysicalPlan:
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    try:
        if type(value.planned_calls) is not tuple:
            _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
        controlled_calls = tuple(_controlled_planned_call(item) for item in value.planned_calls)
        controlled = M6M3ModelPhysicalPlan(
            source_identity_sha256=value.source_identity_sha256,
            run_id=value.run_id,
            case_id=value.case_id,
            manifest_id=value.manifest_id,
            planned_calls=controlled_calls,
            declared_physical_bytes=value.declared_physical_bytes,
        )
    except M6M3ModelPhysicalResolutionError:
        raise
    except Exception:
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    if controlled != value:
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    return controlled


def _observed_closure(
    planned: M6PlannedModelCallPhysicalClosure,
) -> M6ObservedModelCallPhysicalClosure:
    try:
        return M6ObservedModelCallPhysicalClosure(
            source_identity_sha256=planned.source_identity_sha256,
            run_id=planned.run_id,
            case_id=planned.case_id,
            manifest_id=planned.manifest_id,
            layer=planned.layer,
            role=planned.role,
            attempt_index=planned.attempt_index,
            timeout_ms=planned.timeout_ms,
            execution_model_manifest_id=planned.execution_model_manifest_id,
            request_ref=planned.request_ref,
            result_kind=planned.result_kind,
            response_ref=planned.response_ref,
            cache_ref=planned.cache_ref,
            parse_receipt_ref=planned.parse_receipt_ref,
            parsed_output_ref=planned.parsed_output_ref,
            failure_ref=planned.failure_ref,
            usage_receipt_ref=planned.usage_receipt_ref,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6M3ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID)


@dataclass(frozen=True, slots=True)
class _PlanningOutcome:
    plan: M6M3ModelPhysicalPlan
    prepared_calls: tuple[_PreparedCall, ...]


def _build_physical_plan(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> _PlanningOutcome:
    if not isinstance(source_case, Case) or not isinstance(
        snapshot, M6M3ModelCallAuthoritySnapshot
    ):
        _fail(M6M3ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT)
    try:
        locked_calls = assemble_m6_locked_screening_model_calls(
            source_case=source_case,
            snapshot=snapshot,
        )
    except Exception:
        _fail(M6M3ModelPhysicalResolutionErrorCode.AUTHORITY_ASSEMBLY_FAILED)

    prepared = _prepare_calls(
        source_case=source_case,
        snapshot=snapshot,
        locked_calls=locked_calls,
    )
    prepared_and_planned = tuple(
        (
            item,
            _planned_closure(source_case=source_case, snapshot=snapshot, prepared=item),
        )
        for item in prepared
    )
    ordered_pairs = tuple(sorted(prepared_and_planned, key=lambda item: item[1].sort_key))
    prepared = tuple(item[0] for item in ordered_pairs)
    planned_calls = tuple(item[1] for item in ordered_pairs)
    if len(planned_calls) != len(locked_calls):
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    declared_bytes = 0
    for item in prepared:
        item_bytes = item.declared_physical_bytes
        if item_bytes > MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES - declared_bytes:
            _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_BUDGET_EXCEEDED)
        declared_bytes += item_bytes
    try:
        plan = M6M3ModelPhysicalPlan(
            source_identity_sha256=snapshot.source_identity_sha256,
            run_id=source_case.run_id,
            case_id=source_case.case_id,
            manifest_id=source_case.manifest_id,
            planned_calls=planned_calls,
            declared_physical_bytes=declared_bytes,
        )
    except (TypeError, ValueError):
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    return _PlanningOutcome(plan=plan, prepared_calls=prepared)


def _require_raw_response_verifier(verifier: object) -> None:
    try:
        verify_raw_response = getattr(verifier, "verify_raw_response", None)
    except Exception:
        _fail(M6M3ModelPhysicalResolutionErrorCode.RAW_RESPONSE_VERIFIER_FAILED)
    if not callable(verify_raw_response):
        _fail(M6M3ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT)


def _same_call_projection(
    planned: M6PlannedModelCallPhysicalClosure,
    observed: M6ObservedModelCallPhysicalClosure,
) -> bool:
    return (
        observed.source_identity_sha256 == planned.source_identity_sha256
        and observed.run_id == planned.run_id
        and observed.case_id == planned.case_id
        and observed.manifest_id == planned.manifest_id
        and observed.layer == planned.layer
        and observed.role == planned.role
        and observed.attempt_index == planned.attempt_index
        and observed.timeout_ms == planned.timeout_ms
        and observed.execution_model_manifest_id == planned.execution_model_manifest_id
        and observed.result_kind == planned.result_kind
        and observed.artifact_refs == planned.artifact_refs
        and observed.sort_key == planned.sort_key
    )


def _resolve_planning_outcome(
    outcome: _PlanningOutcome,
    verifier: RawModelResponseVerifier,
) -> tuple[M6ObservedModelCallPhysicalClosure, ...]:
    if len(outcome.prepared_calls) != len(outcome.plan.planned_calls):
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)

    observed: list[M6ObservedModelCallPhysicalClosure] = []
    for prepared, planned in zip(
        outcome.prepared_calls,
        outcome.plan.planned_calls,
        strict=True,
    ):
        if prepared.locked.result_kind == M6LockedModelCallResultKind.RESPONSE:
            _verify_exact_raw_response(prepared, verifier)
        resolved = _observed_closure(planned)
        if not _same_call_projection(planned, resolved):
            _fail(M6M3ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID)
        observed.append(resolved)
    ordered = tuple(observed)
    observed_refs = tuple(
        sorted(
            (ref for item in ordered for ref in item.artifact_refs),
            key=lambda ref: ref.sort_key,
        )
    )
    if (
        len(ordered) != len(outcome.plan.planned_calls)
        or len({item.request_ref.artifact_id for item in ordered}) != len(ordered)
        or ordered != tuple(sorted(ordered, key=lambda item: item.sort_key))
        or observed_refs != outcome.plan.planned_refs
    ):
        _fail(M6M3ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID)
    return ordered


def _attempt_resolve_physical_plan(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
    plan: M6M3ModelPhysicalPlan,
    raw_response_verifier: RawModelResponseVerifier,
) -> tuple[M6ObservedModelCallPhysicalClosure, ...]:
    if not isinstance(source_case, Case) or not isinstance(
        snapshot, M6M3ModelCallAuthoritySnapshot
    ):
        _fail(M6M3ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT)
    controlled_plan = _controlled_plan(plan)
    outcome = _build_physical_plan(source_case=source_case, snapshot=snapshot)
    if controlled_plan != outcome.plan:
        _fail(M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID)
    _require_raw_response_verifier(raw_response_verifier)
    return _resolve_planning_outcome(outcome, raw_response_verifier)


def plan_m6_m3_observed_model_call_closures(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> M6M3ModelPhysicalPlan:
    """Rebuild the full M3 physical plan without reading raw response bytes."""

    failure_code = M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID
    try:
        result = _build_physical_plan(source_case=source_case, snapshot=snapshot).plan
    except M6M3ModelPhysicalResolutionError as error:
        failure_code = error.code
    except Exception:
        failure_code = M6M3ModelPhysicalResolutionErrorCode.PHYSICAL_PLAN_INVALID
    else:
        del source_case, snapshot
        return result
    del source_case, snapshot
    raise M6M3ModelPhysicalResolutionError(failure_code) from None


def resolve_m6_m3_observed_model_call_physical_plan(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
    plan: M6M3ModelPhysicalPlan,
    raw_response_verifier: RawModelResponseVerifier,
) -> tuple[M6ObservedModelCallPhysicalClosure, ...]:
    """Revalidate one exact plan, then verify raw bytes and refine its calls."""

    failure_code = M6M3ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID
    try:
        result = _attempt_resolve_physical_plan(
            source_case=source_case,
            snapshot=snapshot,
            plan=plan,
            raw_response_verifier=raw_response_verifier,
        )
    except M6M3ModelPhysicalResolutionError as error:
        failure_code = error.code
    except Exception:
        failure_code = M6M3ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID
    else:
        del source_case, snapshot, plan, raw_response_verifier
        return result
    del source_case, snapshot, plan, raw_response_verifier
    raise M6M3ModelPhysicalResolutionError(failure_code) from None


def _attempt_compatible_resolution(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
    raw_response_verifier: RawModelResponseVerifier,
) -> tuple[M6ObservedModelCallPhysicalClosure, ...]:
    if not isinstance(source_case, Case) or not isinstance(
        snapshot, M6M3ModelCallAuthoritySnapshot
    ):
        _fail(M6M3ModelPhysicalResolutionErrorCode.INVALID_ARGUMENT)
    _require_raw_response_verifier(raw_response_verifier)
    outcome = _build_physical_plan(source_case=source_case, snapshot=snapshot)
    return _resolve_planning_outcome(outcome, raw_response_verifier)


def resolve_m6_m3_observed_model_call_closures(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
    raw_response_verifier: RawModelResponseVerifier,
) -> tuple[M6ObservedModelCallPhysicalClosure, ...]:
    """Compatibility wrapper for the exact two-phase M3 physical workflow."""

    failure_code = M6M3ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID
    try:
        result = _attempt_compatible_resolution(
            source_case=source_case,
            snapshot=snapshot,
            raw_response_verifier=raw_response_verifier,
        )
    except M6M3ModelPhysicalResolutionError as error:
        failure_code = error.code
    except Exception:
        failure_code = M6M3ModelPhysicalResolutionErrorCode.OBSERVED_CLOSURE_INVALID
    else:
        del source_case, snapshot, raw_response_verifier
        return result
    del source_case, snapshot, raw_response_verifier
    raise M6M3ModelPhysicalResolutionError(failure_code) from None


__all__ = [
    "M6M3ModelPhysicalPlan",
    "M6M3ModelPhysicalResolutionError",
    "M6M3ModelPhysicalResolutionErrorCode",
    "plan_m6_m3_observed_model_call_closures",
    "resolve_m6_m3_observed_model_call_closures",
    "resolve_m6_m3_observed_model_call_physical_plan",
]
