"""Crash-resumable execution of one M4 hearing role and its sole repair.

This service owns only the provider-call boundary.  Case transitions, backlog
publication, acquisition, and verdict review stay in the hearing coordinator.
Raw bytes are durable before parsing, SQLite claims reserve media once, and a
rerun resumes the exact request without silently invoking another role.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from labcourt.application.hearing_model_parser import (
    HearingParseInspection,
    finalize_hearing_parse,
    inspect_hearing_response,
)
from labcourt.application.hearing_request import (
    HearingBudgetUsage,
    HearingRequestPreparationError,
    HearingRequestPreparationErrorCode,
    PreparedHearingRequest,
    prepare_hearing_repair_request,
)
from labcourt.application.hearing_role_output import build_hearing_role_output
from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    ModelParseStatus,
    VlmRole,
)
from labcourt.contracts.hearing import (
    HearingCycleScope,
    HearingModelCacheEntry,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    HearingSession,
    HearingUsageReceipt,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import (
    HearingCallClosure,
    HearingCallTrace,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.hearing_backlog import HearingModelCallFailureIntent
from labcourt.ports.hearing_repository import (
    HearingModelCallClaim,
    HearingModelCallClaimStatus,
    HearingRepository,
)
from labcourt.ports.hearing_vlm import (
    HearingModelResponseStore,
    HearingVLMClient,
)
from labcourt.ports.prompts import PromptCatalog, RenderedPromptRegistrar
from labcourt.ports.vlm import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)


class HearingRoleCallFailureCode(StrEnum):
    """Stable failure classes consumed by backlog or human-review routing."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    PROMPT_REGISTRATION_FAILED = "PROMPT_REGISTRATION_FAILED"
    CLAIM_TIMEOUT = "CLAIM_TIMEOUT"
    CLAIM_RECOVERY_REQUIRED = "CLAIM_RECOVERY_REQUIRED"
    PROVIDER_FAILED = "PROVIDER_FAILED"
    RESPONSE_PUBLICATION_RECOVERY_REQUIRED = "RESPONSE_PUBLICATION_RECOVERY_REQUIRED"
    RESPONSE_INTEGRITY_FAILURE = "RESPONSE_INTEGRITY_FAILURE"
    PERSISTENCE_FAILURE = "PERSISTENCE_FAILURE"
    STRUCTURE_REPAIR_PREPARATION_FAILED = "STRUCTURE_REPAIR_PREPARATION_FAILED"
    HEARING_BUDGET_EXHAUSTED = "HEARING_BUDGET_EXHAUSTED"
    STRICT_PARSE_FAILED = "STRICT_PARSE_FAILED"


class HearingRoleCallError(ContractViolation):
    """One exact hearing role could not reach a durable parsed output."""

    def __init__(
        self,
        reason_code: HearingRoleCallFailureCode,
        *,
        role: VlmRole,
        request_id: str,
        request: HearingModelRequest | None = None,
        failed_calls: tuple[HearingCallClosure, ...] = (),
        model_call_failure: HearingModelCallFailureIntent | None = None,
    ) -> None:
        if not isinstance(reason_code, HearingRoleCallFailureCode):
            raise TypeError("reason_code must be a HearingRoleCallFailureCode")
        if role not in {VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE}:
            raise TypeError("role must be one exact hearing role")
        if not isinstance(request_id, str):
            raise TypeError("request_id must be a string")
        if request is not None and (
            not isinstance(request, HearingModelRequest)
            or request.request_id != request_id
            or request.role != role
        ):
            raise TypeError("request must match the reported hearing call identity")
        if any(not isinstance(call, HearingCallClosure) for call in failed_calls):
            raise TypeError("failed_calls must contain HearingCallClosure values")
        if model_call_failure is not None and (
            not isinstance(model_call_failure, HearingModelCallFailureIntent)
            or reason_code != HearingRoleCallFailureCode.PROVIDER_FAILED
            or request is None
            or model_call_failure.request != request
            or failed_calls
        ):
            raise TypeError("model_call_failure must close the exact known provider failure")
        self.reason_code = reason_code
        self.role = role
        self.request_id = request_id
        self.request = request
        self.failed_calls = failed_calls
        self.model_call_failure = model_call_failure
        super().__init__(f"hearing role call failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class HearingRoleCallContext:
    """Frozen authorities needed only when constructing a repair request."""

    session: HearingSession
    cycle_scope: HearingCycleScope
    budget_usage_before_primary: HearingBudgetUsage
    config: AppConfig
    run_manifest: RunManifest
    catalog: PromptCatalog
    backlog_lease: BacklogLeaseIdentity | None = None

    def __post_init__(self) -> None:
        expected = (
            (self.session, HearingSession, "session"),
            (self.cycle_scope, HearingCycleScope, "cycle_scope"),
            (
                self.budget_usage_before_primary,
                HearingBudgetUsage,
                "budget_usage_before_primary",
            ),
            (self.config, AppConfig, "config"),
            (self.run_manifest, RunManifest, "run_manifest"),
        )
        for value, kind, name in expected:
            if not isinstance(value, kind):
                raise TypeError(f"{name} has the wrong contract type")
        if not isinstance(self.catalog, PromptCatalog):
            raise TypeError("catalog must implement PromptCatalog")
        if self.backlog_lease is not None and (
            not isinstance(self.backlog_lease, BacklogLeaseIdentity)
            or self.backlog_lease.run_id != self.session.run_id
        ):
            raise ValueError("backlog_lease must belong to the hearing run")


@dataclass(frozen=True, slots=True)
class HearingRoleCallResult:
    """A strictly parsed role output and its complete persisted call trace."""

    output: HearingRoleOutput
    trace: HearingCallTrace
    prepared_primary: PreparedHearingRequest
    prepared_repair: PreparedHearingRequest | None
    cache_hit_count: int
    recovered_response_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.output, HearingRoleOutput):
            raise TypeError("output must be a HearingRoleOutput")
        if not isinstance(self.trace, HearingCallTrace):
            raise TypeError("trace must be a HearingCallTrace")
        if not isinstance(self.prepared_primary, PreparedHearingRequest):
            raise TypeError("prepared_primary must be a PreparedHearingRequest")
        if self.prepared_repair is not None and not isinstance(
            self.prepared_repair,
            PreparedHearingRequest,
        ):
            raise TypeError("prepared_repair must be PreparedHearingRequest or None")
        for name, value in (
            ("cache_hit_count", self.cache_hit_count),
            ("recovered_response_count", self.recovered_response_count),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TypeError(f"{name} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class _DurableCall:
    request: HearingModelRequest
    response: HearingModelResponse
    usage: HearingUsageReceipt
    raw: bytes
    cache_hit: bool
    recovered: bool


class HearingRoleCallService:
    """Run one primary hearing call and at most one media-free repair."""

    def __init__(
        self,
        *,
        repository: HearingRepository,
        response_store: HearingModelResponseStore,
        vlm_client: HearingVLMClient,
        prompt_registrar: RenderedPromptRegistrar,
        owner_token_factory: Callable[[], str] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        capabilities = (
            (repository, "claim_hearing_model_call", "repository"),
            (repository, "complete_hearing_model_call", "repository"),
            (repository, "append_hearing_parse_receipt", "repository"),
            (repository, "load_hearing_model_response", "repository"),
            (repository, "load_hearing_model_cache_entry", "repository"),
            (repository, "load_hearing_usage_receipt", "repository"),
            (response_store, "recover", "response_store"),
            (response_store, "acknowledge", "response_store"),
            (response_store, "verify_raw_response", "response_store"),
            (response_store, "read_bytes", "response_store"),
            (vlm_client, "complete", "vlm_client"),
            (prompt_registrar, "register", "prompt_registrar"),
        )
        for dependency, method, name in capabilities:
            if not callable(getattr(dependency, method, None)):
                raise TypeError(f"{name} does not implement {method}")
        factory = owner_token_factory or (lambda: secrets.token_urlsafe(32))
        if not callable(factory) or not callable(monotonic) or not callable(sleeper):
            raise TypeError("clock, sleeper, and owner-token factory must be callable")
        self._repository = repository
        self._responses = response_store
        self._vlm = vlm_client
        self._prompts = prompt_registrar
        self._owner_token_factory = factory
        self._monotonic = monotonic
        self._sleep = sleeper

    def execute(
        self,
        prepared: PreparedHearingRequest,
        context: HearingRoleCallContext,
    ) -> HearingRoleCallResult:
        """Execute or resume one exact role boundary."""

        if not isinstance(prepared, PreparedHearingRequest) or not isinstance(
            context,
            HearingRoleCallContext,
        ):
            self._raise(
                HearingRoleCallFailureCode.INVALID_ARGUMENT,
                prepared.request if isinstance(prepared, PreparedHearingRequest) else None,
            )
        primary_request = prepared.request
        if (
            primary_request.attempt_index != 0
            or primary_request.hearing_session_id != context.session.session_id
            or primary_request.cycle_scope_id != context.cycle_scope.cycle_id
            or primary_request.cycle_scope_sha256 != context.cycle_scope.cycle_sha256
            or primary_request.manifest_id != context.run_manifest.manifest_id
        ):
            self._raise(HearingRoleCallFailureCode.INVALID_ARGUMENT, primary_request)
        self._register(prepared)
        primary = self._controlled_call(primary_request, context.backlog_lease)
        inspection = self._inspect(primary)
        if inspection.payload is not None:
            parsed = finalize_hearing_parse(inspection)
            output = build_hearing_role_output(
                request=primary.request,
                response=primary.response,
                parse_receipt=parsed.receipt,
                payload=inspection.payload,
            )
            self._append_parse(primary_request, parsed.receipt, output)
            closure = HearingCallClosure(
                request=primary.request,
                response=primary.response,
                parse_receipt=parsed.receipt,
                usage=primary.usage,
            )
            return HearingRoleCallResult(
                output=output,
                trace=HearingCallTrace(calls=(closure,)),
                prepared_primary=prepared,
                prepared_repair=None,
                cache_hit_count=int(primary.cache_hit),
                recovered_response_count=int(primary.recovered),
            )

        usage_after_primary = HearingBudgetUsage(
            reserved_images=(
                context.budget_usage_before_primary.reserved_images + len(primary_request.media)
            ),
            accounted_output_tokens=(
                context.budget_usage_before_primary.accounted_output_tokens
                + primary.response.output_tokens
            ),
        )
        try:
            repair = prepare_hearing_repair_request(
                original=prepared,
                response=primary.response,
                inspection=inspection,
                raw_response=primary.raw,
                session=context.session,
                cycle_scope=context.cycle_scope,
                budget_usage=usage_after_primary,
                config=context.config,
                run_manifest=context.run_manifest,
                catalog=context.catalog,
            )
        except HearingRequestPreparationError as error:
            budget_codes = {
                HearingRequestPreparationErrorCode.IMAGE_BUDGET_EXHAUSTED,
                HearingRequestPreparationErrorCode.OUTPUT_TOKEN_BUDGET_EXHAUSTED,
            }
            self._raise(
                (
                    HearingRoleCallFailureCode.HEARING_BUDGET_EXHAUSTED
                    if error.reason_code in budget_codes
                    else HearingRoleCallFailureCode.STRUCTURE_REPAIR_PREPARATION_FAILED
                ),
                primary_request,
            )
        except Exception:
            self._raise(
                HearingRoleCallFailureCode.STRUCTURE_REPAIR_PREPARATION_FAILED,
                primary_request,
            )

        first = finalize_hearing_parse(
            inspection,
            repair_request_id=repair.request.request_id,
        )
        self._append_parse(primary_request, first.receipt, None)
        primary_closure = HearingCallClosure(
            request=primary.request,
            response=primary.response,
            parse_receipt=first.receipt,
            usage=primary.usage,
        )
        self._register(repair)
        repaired = self._controlled_call(repair.request, context.backlog_lease)
        repaired_inspection = self._inspect(repaired)
        final = finalize_hearing_parse(repaired_inspection)
        if final.payload is None:
            self._append_parse(repair.request, final.receipt, None)
            repair_closure = HearingCallClosure(
                request=repaired.request,
                response=repaired.response,
                parse_receipt=final.receipt,
                usage=repaired.usage,
            )
            self._raise(
                HearingRoleCallFailureCode.STRICT_PARSE_FAILED,
                primary_request,
                failed_calls=(primary_closure, repair_closure),
            )
        output = build_hearing_role_output(
            request=repaired.request,
            response=repaired.response,
            parse_receipt=final.receipt,
            payload=final.payload,
        )
        self._append_parse(repair.request, final.receipt, output)
        repair_closure = HearingCallClosure(
            request=repaired.request,
            response=repaired.response,
            parse_receipt=final.receipt,
            usage=repaired.usage,
        )
        return HearingRoleCallResult(
            output=output,
            trace=HearingCallTrace(calls=(primary_closure, repair_closure)),
            prepared_primary=prepared,
            prepared_repair=repair,
            cache_hit_count=int(primary.cache_hit) + int(repaired.cache_hit),
            recovered_response_count=int(primary.recovered) + int(repaired.recovered),
        )

    def resume_repair(
        self,
        original: PreparedHearingRequest,
        repair: PreparedHearingRequest,
        primary_failure: HearingCallClosure,
        context: HearingRoleCallContext,
    ) -> HearingRoleCallResult:
        """Resume only an unfinished repair after its primary was persisted.

        The caller must reconstruct the exact original and repair preparations.
        This method never invokes the primary request and never grants a second
        repair.  It exists specifically for the crash boundary between a
        durable ``REPAIR_REQUIRED`` receipt and the repair provider call.
        """

        if (
            not isinstance(original, PreparedHearingRequest)
            or not isinstance(repair, PreparedHearingRequest)
            or not isinstance(primary_failure, HearingCallClosure)
            or not isinstance(context, HearingRoleCallContext)
        ):
            self._raise(
                HearingRoleCallFailureCode.INVALID_ARGUMENT,
                repair.request if isinstance(repair, PreparedHearingRequest) else None,
            )
        primary_request = original.request
        repair_request = repair.request
        if (
            primary_request.attempt_index != 0
            or repair_request.attempt_index != 1
            or primary_failure.request != primary_request
            or primary_failure.parse_receipt.status != ModelParseStatus.REPAIR_REQUIRED
            or primary_failure.parse_receipt.repair_request_id != repair_request.request_id
            or repair_request.original_request_id != primary_request.request_id
            or repair_request.original_response_id != primary_failure.response.response_id
            or repair_request.original_response_content_sha256
            != primary_failure.response.content_sha256
            or repair_request.role != primary_request.role
            or repair_request.backlog_retry_context != primary_request.backlog_retry_context
            or repair_request.hearing_session_id != context.session.session_id
            or repair_request.cycle_scope_id != context.cycle_scope.cycle_id
            or repair_request.cycle_scope_sha256 != context.cycle_scope.cycle_sha256
            or repair_request.manifest_id != context.run_manifest.manifest_id
        ):
            self._raise(HearingRoleCallFailureCode.INVALID_ARGUMENT, repair_request)

        self._register(repair)
        repaired = self._controlled_call(repair_request, context.backlog_lease)
        inspection = self._inspect(repaired)
        final = finalize_hearing_parse(inspection)
        repair_closure = HearingCallClosure(
            request=repaired.request,
            response=repaired.response,
            parse_receipt=final.receipt,
            usage=repaired.usage,
        )
        if final.payload is None:
            self._append_parse(repair_request, final.receipt, None)
            self._raise(
                HearingRoleCallFailureCode.STRICT_PARSE_FAILED,
                repair_request,
                failed_calls=(primary_failure, repair_closure),
            )
        output = build_hearing_role_output(
            request=repaired.request,
            response=repaired.response,
            parse_receipt=final.receipt,
            payload=final.payload,
        )
        self._append_parse(repair_request, final.receipt, output)
        return HearingRoleCallResult(
            output=output,
            trace=HearingCallTrace(calls=(primary_failure, repair_closure)),
            prepared_primary=original,
            prepared_repair=repair,
            cache_hit_count=int(repaired.cache_hit),
            recovered_response_count=int(repaired.recovered),
        )

    def _controlled_call(
        self,
        request: HearingModelRequest,
        backlog_lease: BacklogLeaseIdentity | None,
    ) -> _DurableCall:
        retry = request.backlog_retry_context
        if (backlog_lease is None and retry is not None) or (
            backlog_lease is not None
            and (
                backlog_lease.run_id != request.run_id
                or (retry is None and backlog_lease.retry_generation != 0)
                or (
                    retry is not None
                    and (
                        backlog_lease.item_id != retry.backlog_item_id
                        or backlog_lease.retry_generation != retry.retry_generation
                    )
                )
            )
        ):
            self._raise(HearingRoleCallFailureCode.INVALID_ARGUMENT, request)
        owner_token = self._owner_token_factory()
        if not isinstance(owner_token, str) or not 32 <= len(owner_token) <= 512:
            self._raise(HearingRoleCallFailureCode.INVALID_ARGUMENT, request)
        deadline = self._monotonic() + request.budget.claim_lease_seconds
        while True:
            try:
                if backlog_lease is None:
                    claim = self._repository.claim_hearing_model_call(
                        request.run_id,
                        request,
                        owner_token,
                    )
                else:
                    claim = self._repository.claim_hearing_model_call(
                        request.run_id,
                        request,
                        owner_token,
                        backlog_lease,
                    )
            except Exception:
                self._raise(HearingRoleCallFailureCode.PERSISTENCE_FAILURE, request)
            if claim.status == HearingModelCallClaimStatus.COMPLETED:
                return self._load_completed_call(request, claim)
            if claim.status == HearingModelCallClaimStatus.WAITING:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    self._raise(HearingRoleCallFailureCode.CLAIM_TIMEOUT, request)
                self._sleep(min(0.05, remaining))
                continue
            if claim.status == HearingModelCallClaimStatus.EXPIRED_REQUIRES_RECOVERY:
                self._raise(
                    HearingRoleCallFailureCode.CLAIM_RECOVERY_REQUIRED,
                    request,
                )
            if claim.status != HearingModelCallClaimStatus.ACQUIRED:
                self._raise(HearingRoleCallFailureCode.PERSISTENCE_FAILURE, request)
            return self._complete_acquired_call(request, claim, owner_token)

    def _load_completed_call(
        self,
        request: HearingModelRequest,
        claim: HearingModelCallClaim,
    ) -> _DurableCall:
        try:
            if claim.response_id is None:
                raise ValueError("completed claim lacks response")
            response = self._repository.load_hearing_model_response(
                request.run_id,
                claim.response_id,
            )
            entry = self._repository.load_hearing_model_cache_entry(
                request.run_id,
                request.cache_key,
            )
            if entry is None:
                raise ValueError("completed claim lacks cache entry")
            self._validate_cache_entry(request, response, entry)
            usage = self._usage_for(
                request,
                response,
                retry_count=claim.takeover_count,
            )
            stored_usage = self._repository.load_hearing_usage_receipt(
                request.run_id,
                usage.usage_receipt_id,
            )
            if stored_usage != usage:
                raise ValueError("persisted usage conflicts with completed call")
            raw = self._verify_and_read(request, response)
            journaled = self._responses.recover(request)
            if journaled is not None:
                if journaled != response:
                    raise ValueError("journal and SQLite bind different responses")
                self._responses.acknowledge(request, response)
            return _DurableCall(
                request=request,
                response=response,
                usage=usage,
                raw=raw,
                cache_hit=True,
                recovered=journaled is not None,
            )
        except HearingRoleCallError:
            raise
        except Exception:
            self._raise(HearingRoleCallFailureCode.RESPONSE_INTEGRITY_FAILURE, request)

    def _complete_acquired_call(
        self,
        request: HearingModelRequest,
        claim: HearingModelCallClaim,
        owner_token: str,
    ) -> _DurableCall:
        try:
            journaled = self._responses.recover(request)
        except Exception:
            self._raise(
                HearingRoleCallFailureCode.RESPONSE_PUBLICATION_RECOVERY_REQUIRED,
                request,
            )
        response = journaled
        recovered_response = response is not None
        if response is None:
            provider_error: Exception | None = None
            try:
                response = self._vlm.complete(request)
            except Exception as error:
                provider_error = error
                try:
                    response = self._responses.recover(request)
                except Exception:
                    self._raise(
                        HearingRoleCallFailureCode.RESPONSE_PUBLICATION_RECOVERY_REQUIRED,
                        request,
                    )
                if response is None:
                    failure_intent = self._provider_failure_intent(
                        request,
                        claim,
                        owner_token,
                        provider_error,
                    )
                    if failure_intent is not None:
                        self._raise(
                            HearingRoleCallFailureCode.PROVIDER_FAILED,
                            request,
                            model_call_failure=failure_intent,
                        )
                    # An untyped exception, UNKNOWN delivery, or a completed
                    # provider failure without exact response accounting must
                    # preserve the acquired claim for provider-free recovery.
                    # Turning any of those states into backlog authority would
                    # permit a duplicate external call or fabricated usage.
                    self._raise(
                        HearingRoleCallFailureCode.CLAIM_RECOVERY_REQUIRED,
                        request,
                    )
                recovered_response = True
            try:
                recovered = self._responses.recover(request)
            except Exception:
                self._raise(
                    HearingRoleCallFailureCode.RESPONSE_PUBLICATION_RECOVERY_REQUIRED,
                    request,
                )
            if recovered is None or recovered != response:
                self._raise(
                    HearingRoleCallFailureCode.RESPONSE_INTEGRITY_FAILURE,
                    request,
                )
        assert response is not None
        usage = self._usage_for(
            request,
            response,
            retry_count=claim.takeover_count,
        )
        try:
            entry = self._repository.complete_hearing_model_call(
                request.run_id,
                request,
                response,
                usage,
                owner_token,
            )
            self._validate_cache_entry(request, response, entry)
            raw = self._verify_and_read(request, response)
            self._responses.acknowledge(request, response)
        except HearingRoleCallError:
            raise
        except Exception:
            self._raise(HearingRoleCallFailureCode.PERSISTENCE_FAILURE, request)
        return _DurableCall(
            request=request,
            response=response,
            usage=usage,
            raw=raw,
            cache_hit=False,
            recovered=recovered_response,
        )

    @staticmethod
    def _provider_failure_intent(
        request: HearingModelRequest,
        claim: HearingModelCallClaim,
        owner_token: str,
        error: Exception,
    ) -> HearingModelCallFailureIntent | None:
        """Return exact fenced failure authority only when delivery is provable.

        The intent carries the transient owner capability through the initial
        enqueue or retry completion transaction.  Completed/unknown provider
        failures need exact response and usage authority, so the shared error
        boundary leaves them for provider-free recovery instead of inventing
        closure facts.
        """

        if (
            not isinstance(error, VLMProviderError)
            or claim.status != HearingModelCallClaimStatus.ACQUIRED
            or claim.lease_expires_at is None
        ):
            return None
        if error.delivery_certainty != VLMDeliveryCertainty.DEFINITELY_NOT_SENT:
            return None
        reason = {
            VLMProviderFailureCode.FIXTURE_MISSING: BacklogReasonCode.PROVIDER_UNAVAILABLE,
            VLMProviderFailureCode.PROVIDER_OUTAGE: BacklogReasonCode.PROVIDER_UNAVAILABLE,
            VLMProviderFailureCode.PROVIDER_TIMEOUT: BacklogReasonCode.PROVIDER_UNAVAILABLE,
            VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH: (
                BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
            ),
            VLMProviderFailureCode.PROMPT_MISSING: (BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE),
            VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE: (
                BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
            ),
            VLMProviderFailureCode.MEDIA_POLICY_REJECTED: (
                BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
            ),
            VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE: (
                BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
            ),
        }.get(error.reason_code)
        if reason is None:
            return None
        try:
            return HearingModelCallFailureIntent(
                request=request,
                owner_token=owner_token,
                claim_lease_expires_at=claim.lease_expires_at,
                claim_takeover_count=claim.takeover_count,
                failure_code=error.reason_code,
                delivery_certainty=error.delivery_certainty,
                backlog_reason_code=reason,
            )
        except (TypeError, ValueError):
            # A typed provider error that conflicts with the persisted claim is
            # not retry authority.  Recovery can inspect the exact claim later.
            return None

    @staticmethod
    def _usage_for(
        request: HearingModelRequest,
        response: HearingModelResponse,
        *,
        retry_count: int,
    ) -> HearingUsageReceipt:
        return HearingUsageReceipt(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            round_index=request.round_index,
            role=request.role,
            request_ref=ArtifactRef(
                kind=ArtifactKind.MODEL_REQUEST,
                artifact_id=request.request_id,
            ),
            response_ref=ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=response.response_id,
            ),
            input_images=len(request.media),
            input_pixels=sum(item.width * item.height for item in request.media),
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            latency_ms=response.latency_ms,
            retry_count=retry_count,
            estimated_cost=request.budget.estimate_cost(
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
            ),
            manifest_id=request.manifest_id,
        )

    @staticmethod
    def _validate_cache_entry(
        request: HearingModelRequest,
        response: HearingModelResponse,
        entry: HearingModelCacheEntry,
    ) -> None:
        expected = HearingModelCacheEntry(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            round_index=request.round_index,
            role=request.role,
            current_evidence_pack_id=request.current_evidence_pack_id,
            current_evidence_pack_version=request.current_evidence_pack_version,
            cache_key=request.cache_key,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            response_id=response.response_id,
            response_content_sha256=response.content_sha256,
            model_manifest_id=request.model_manifest_id,
            prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
            output_schema_sha256=request.prompt_manifest.output_schema_sha256,
            manifest_id=request.manifest_id,
        )
        if entry != expected:
            raise ValueError("hearing cache entry conflicts with exact call")

    def _verify_and_read(
        self,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> bytes:
        verified = self._responses.verify_raw_response(
            request.run_id,
            request,
            response,
        )
        if verified != response:
            raise ValueError("response verifier returned another receipt")
        return self._responses.read_bytes(
            request.run_id,
            response,
            request.budget.max_response_bytes,
        )

    def _inspect(self, durable: _DurableCall) -> HearingParseInspection:
        try:
            return inspect_hearing_response(
                durable.raw,
                request=durable.request,
                response=durable.response,
            )
        except Exception:
            self._raise(
                HearingRoleCallFailureCode.RESPONSE_INTEGRITY_FAILURE,
                durable.request,
            )

    def _register(self, prepared: PreparedHearingRequest) -> None:
        try:
            self._prompts.register(prepared.rendered_prompt)
        except Exception:
            self._raise(
                HearingRoleCallFailureCode.PROMPT_REGISTRATION_FAILED,
                prepared.request,
            )

    def _append_parse(
        self,
        request: HearingModelRequest,
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput | None,
    ) -> None:
        try:
            stored = self._repository.append_hearing_parse_receipt(receipt, output)
            if stored != receipt:
                raise ValueError("repository returned another parse receipt")
        except Exception:
            self._raise(HearingRoleCallFailureCode.PERSISTENCE_FAILURE, request)

    @staticmethod
    def _raise(
        reason: HearingRoleCallFailureCode,
        request: HearingModelRequest | None,
        *,
        failed_calls: tuple[HearingCallClosure, ...] = (),
        model_call_failure: HearingModelCallFailureIntent | None = None,
    ) -> NoReturn:
        role = request.role if request is not None else VlmRole.PROSECUTOR
        request_id = request.request_id if request is not None else "invalid-request"
        raise HearingRoleCallError(
            reason,
            role=role,
            request_id=request_id,
            request=request,
            failed_calls=failed_calls,
            model_call_failure=model_call_failure,
        )


__all__ = [
    "HearingRoleCallContext",
    "HearingRoleCallError",
    "HearingRoleCallFailureCode",
    "HearingRoleCallResult",
    "HearingRoleCallService",
]
