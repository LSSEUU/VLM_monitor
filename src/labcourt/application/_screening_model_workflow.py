"""Controlled model-call and strict parsing workflow for M3 screening."""

from __future__ import annotations

import secrets
import time
from typing import NoReturn

from labcourt.application._screening_aggregate import ScreeningAggregateWorkflow
from labcourt.application._screening_workflow_types import (
    _BacklogRequired,
    _ModelCallResult,
    _ParsedStage,
    _RetryPublicationRecoveryRequired,
)
from labcourt.application.model_parser import (
    ModelParseResult,
    ScreeningParseInspection,
    finalize_screening_parse,
    inspect_screening_response,
)
from labcourt.application.screening_failures import classify_screening_failure
from labcourt.application.structure_repair import prepare_structure_repair_request
from labcourt.contracts.backlog import (
    BacklogLeaseIdentity,
    BacklogParseFailureEvidence,
    BacklogStrictParseFailureProof,
)
from labcourt.contracts.enums import ArtifactKind, VlmRole
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelParseReceipt,
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ContractViolation, ModelOutputInvalid
from labcourt.ports.prompts import PromptCatalog
from labcourt.ports.screening_repository import (
    ModelCallClaim,
    ModelCallClaimStatus,
    ModelCallFailureIntent,
)
from labcourt.ports.vlm import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)


class ScreeningModelWorkflow(ScreeningAggregateWorkflow):
    """Own request singleflight, durable publication, and strict parse/repair."""

    def _parse_model_stage(
        self,
        request: VLMRequest,
        *,
        manifest: RunManifest,
        catalog: PromptCatalog,
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> _ParsedStage:
        initial = self._controlled_call(
            request,
            VlmRole.SCREENING,
            backlog_lease=backlog_lease,
        )
        inspection = self._controlled_inspection(
            initial.raw_bytes,
            request=request,
            response=initial.response,
            role=VlmRole.SCREENING,
            response_ids=(initial.response.response_id,),
        )
        if inspection.payload is not None:
            parsed = finalize_screening_parse(inspection)
            self._controlled_append_parse(
                parsed,
                VlmRole.SCREENING,
                response_ids=(initial.response.response_id,),
            )
            if parsed.output is None:
                raise AssertionError("successful parser inspection lost its output")
            return _ParsedStage(
                output=parsed.output,
                history=(parsed.receipt,),
                cache_hit_count=int(initial.cache_hit),
                recovered_response_count=int(initial.recovered),
                repair_attempted=False,
            )

        try:
            repair = prepare_structure_repair_request(
                original_request=request,
                original_response=initial.response,
                inspection=inspection,
                raw_response=initial.raw_bytes,
                run_manifest=manifest,
                catalog=catalog,
            )
        except Exception as error:
            self._raise_backlog_or_original(
                error,
                VlmRole.STRUCTURE_REPAIR,
                response_ids=(initial.response.response_id,),
            )
        repair_call_request = repair.request
        if request.backlog_retry_context is not None:
            repair_call_request = StructureRepairRequest.model_validate(
                {
                    **repair.request.model_dump(
                        mode="json",
                        exclude_computed_fields=True,
                    ),
                    "backlog_retry_context": request.backlog_retry_context.model_dump(mode="json"),
                    "original_backlog_retry_context_id": (request.backlog_retry_context.context_id),
                }
            )
        first = finalize_screening_parse(
            inspection,
            repair_request_id=repair_call_request.request_id,
        )
        self._controlled_append_parse(
            first,
            VlmRole.STRUCTURE_REPAIR,
            response_ids=(initial.response.response_id,),
        )
        try:
            self._prompts.register(repair.rendered_prompt)
        except Exception as error:
            self._raise_backlog_or_original(
                error,
                VlmRole.STRUCTURE_REPAIR,
                response_ids=(initial.response.response_id,),
            )
        repaired = self._controlled_call(
            repair_call_request,
            VlmRole.STRUCTURE_REPAIR,
            prior_response_ids=(initial.response.response_id,),
            backlog_lease=backlog_lease,
        )
        response_ids = (initial.response.response_id, repaired.response.response_id)
        repaired_inspection = self._controlled_inspection(
            repaired.raw_bytes,
            request=request,
            response=repaired.response,
            repair_request=repair_call_request,
            original_response=initial.response,
            role=VlmRole.STRUCTURE_REPAIR,
            response_ids=response_ids,
        )
        final = finalize_screening_parse(repaired_inspection)
        self._controlled_append_parse(
            final,
            VlmRole.STRUCTURE_REPAIR,
            response_ids=response_ids,
        )
        if final.output is None:
            strict_parse_failure = self._strict_retry_parse_failure_proof(
                request,
                first.receipt,
                repair_call_request,
                final.receipt,
            )
            self._raise_backlog_or_original(
                ModelOutputInvalid("structure repair output remained invalid"),
                VlmRole.STRUCTURE_REPAIR,
                response_ids=response_ids,
                strict_parse_failure=strict_parse_failure,
            )
            raise AssertionError("unreachable")
        return _ParsedStage(
            output=final.output,
            history=(first.receipt, final.receipt),
            cache_hit_count=int(initial.cache_hit) + int(repaired.cache_hit),
            recovered_response_count=int(initial.recovered) + int(repaired.recovered),
            repair_attempted=True,
        )

    def _controlled_call(
        self,
        request: VLMCallRequest,
        role: VlmRole,
        prior_response_ids: tuple[str, ...] = (),
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> _ModelCallResult:
        durable_response_ids = list(prior_response_ids)
        uncommitted_publication = False
        known_failure_intent: ModelCallFailureIntent | None = None
        acquired_claim: ModelCallClaim | None = None
        owner_token = secrets.token_urlsafe(32)
        try:
            deadline = time.monotonic() + request.budget.claim_lease_seconds
            while True:
                claim = self._screening.claim_model_call(
                    request.run_id,
                    request,
                    owner_token,
                    backlog_lease,
                )
                if claim.status == ModelCallClaimStatus.COMPLETED:
                    journaled = self._responses.recover(request)
                    cached = self._screening.get(request.run_id, request)
                    orphan = self._screening.load_raw_response_for_request(
                        request.run_id,
                        request.request_id,
                    )
                    observed = self._same_observed_response(journaled, cached, orphan)
                    if cached is None or claim.response_id != cached.response.response_id:
                        raise ContractViolation(
                            "completed model call claim is missing its exact cache response"
                        )
                    if observed is not None and observed != cached.response:
                        raise ContractViolation(
                            "completed model call observations bind different responses"
                        )
                    durable_response_ids.append(cached.response.response_id)
                    raw = self._verify_and_read_response(request, cached.response)
                    if journaled is not None:
                        self._responses.acknowledge(request, cached.response)
                    return _ModelCallResult(
                        cached.response,
                        raw,
                        cache_hit=True,
                        recovered=journaled is not None,
                    )

                if claim.status == ModelCallClaimStatus.WAITING:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise VLMProviderError(VLMProviderFailureCode.PROVIDER_TIMEOUT)
                    time.sleep(min(0.05, remaining))
                    continue

                if claim.status == ModelCallClaimStatus.EXPIRED_REQUIRES_RECOVERY:
                    raise VLMProviderError(VLMProviderFailureCode.EXPIRED_CLAIM_REQUIRES_RECOVERY)

                if claim.status != ModelCallClaimStatus.ACQUIRED:
                    raise ContractViolation("model call claim returned an unsupported state")
                acquired_claim = claim

                # The owner rechecks every recovery authority after acquiring the
                # SQLite claim.  This closes cache/journal races before an external call.
                journaled = self._responses.recover(request)
                cached = self._screening.get(request.run_id, request)
                orphan = self._screening.load_raw_response_for_request(
                    request.run_id,
                    request.request_id,
                )
                observed = self._same_observed_response(journaled, cached, orphan)
                if observed is not None:
                    uncommitted_publication = True
                    committed = self._screening.complete_model_call(
                        request.run_id,
                        request,
                        observed,
                        owner_token,
                    )
                    uncommitted_publication = False
                    durable_response_ids.append(committed.response.response_id)
                    raw = self._verify_and_read_response(request, committed.response)
                    if journaled is not None:
                        self._responses.acknowledge(request, committed.response)
                    return _ModelCallResult(
                        committed.response,
                        raw,
                        cache_hit=cached is not None,
                        recovered=journaled is not None or (orphan is not None and cached is None),
                    )

                try:
                    response = self._vlm.complete(request)
                except VLMProviderError as provider_error:
                    reason = classify_screening_failure(provider_error)
                    if (
                        provider_error.delivery_certainty != VLMDeliveryCertainty.UNKNOWN
                        and reason is not None
                        and acquired_claim.lease_expires_at is not None
                    ):
                        known_failure_intent = ModelCallFailureIntent(
                            request=request,
                            owner_token=owner_token,
                            claim_lease_expires_at=acquired_claim.lease_expires_at,
                            claim_takeover_count=acquired_claim.takeover_count,
                            failure_code=provider_error.reason_code,
                            delivery_certainty=provider_error.delivery_certainty,
                            backlog_reason_code=reason,
                        )
                    raise
                uncommitted_publication = True
                journaled = self._responses.recover(request)
                if journaled is None or journaled != response:
                    raise ContractViolation(
                        "provider return is not bound to an exact recoverable journal"
                    )
                committed = self._screening.complete_model_call(
                    request.run_id,
                    request,
                    response,
                    owner_token,
                )
                uncommitted_publication = False
                durable_response_ids.append(committed.response.response_id)
                raw = self._verify_and_read_response(request, committed.response)
                self._responses.acknowledge(request, committed.response)
                return _ModelCallResult(
                    committed.response,
                    raw,
                    cache_hit=False,
                    recovered=False,
                )
        except Exception as error:
            recovery_failure: Exception | None = None
            if not uncommitted_publication:
                try:
                    journal_after_error = self._responses.recover(request)
                except Exception as recovery_error:
                    recovery_failure = recovery_error
                else:
                    uncommitted_publication = journal_after_error is not None
            if uncommitted_publication:
                # A durable journal/final file exists but SQLite publication did
                # not finish.  Preserve the aggregate state so startup recovery
                # can converge the expired claim without another provider call.
                if request.backlog_retry_context is not None:
                    raise _RetryPublicationRecoveryRequired(error) from error
                raise
            if recovery_failure is not None:
                self._raise_backlog_or_original(
                    recovery_failure,
                    role,
                    response_ids=tuple(dict.fromkeys(durable_response_ids)),
                    model_call_failure=known_failure_intent,
                )
            self._raise_backlog_or_original(
                error,
                role,
                response_ids=tuple(dict.fromkeys(durable_response_ids)),
                model_call_failure=known_failure_intent,
            )

    @staticmethod
    def _same_observed_response(
        journaled: VLMResponse | None,
        cached: CachedModelResponse | None,
        orphan: VLMResponse | None,
    ) -> VLMResponse | None:
        cached_response = cached.response if cached is not None else None
        responses = tuple(
            response for response in (journaled, cached_response, orphan) if response is not None
        )
        if not responses:
            return None
        if any(not isinstance(response, VLMResponse) for response in responses):
            raise ContractViolation("model call observation is not a VLMResponse")
        first = responses[0]
        if any(response != first for response in responses[1:]):
            raise ContractViolation("model call recovery authorities disagree")
        return first

    def _verify_and_read_response(
        self,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> bytes:
        self._responses.verify(request.run_id, response)
        return self._responses.read_bytes(
            request.run_id,
            response,
            request.budget.max_response_bytes,
        )

    def _controlled_inspection(
        self,
        raw: bytes,
        *,
        request: VLMRequest,
        response: VLMResponse,
        role: VlmRole,
        response_ids: tuple[str, ...],
        repair_request: StructureRepairRequest | None = None,
        original_response: VLMResponse | None = None,
    ) -> ScreeningParseInspection:
        try:
            return inspect_screening_response(
                raw,
                request=request,
                response=response,
                repair_request=repair_request,
                original_response=original_response,
            )
        except Exception as error:
            self._raise_backlog_or_original(error, role, response_ids=response_ids)

    def _controlled_append_parse(
        self,
        result: ModelParseResult,
        role: VlmRole,
        *,
        response_ids: tuple[str, ...],
    ) -> None:
        try:
            self._screening.append_parse_receipt(result.receipt, result.output)
        except Exception as error:
            self._raise_backlog_or_original(error, role, response_ids=response_ids)

    @staticmethod
    def _raise_backlog_or_original(
        error: Exception,
        role: VlmRole,
        *,
        response_ids: tuple[str, ...] = (),
        strict_parse_failure: BacklogStrictParseFailureProof | None = None,
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> NoReturn:
        reason = classify_screening_failure(error)
        if reason is None:
            raise error
        raise _BacklogRequired(
            reason,
            role,
            response_ids,
            strict_parse_failure,
            model_call_failure,
        ) from None

    @staticmethod
    def _strict_retry_parse_failure_proof(
        request: VLMRequest,
        first_receipt: ModelParseReceipt,
        repair_request: StructureRepairRequest,
        final_receipt: ModelParseReceipt,
    ) -> BacklogStrictParseFailureProof | None:
        context = request.backlog_retry_context
        if context is None:
            return None
        if repair_request.backlog_retry_context != context:
            raise ContractViolation("structure repair lost its backlog retry context")
        return BacklogStrictParseFailureProof(
            retry_context=context,
            attempts=(
                BacklogParseFailureEvidence(
                    attempt_index=0,
                    role=VlmRole.SCREENING,
                    request_ref=ArtifactRef(
                        kind=ArtifactKind.MODEL_REQUEST,
                        artifact_id=request.request_id,
                    ),
                    response_ref=ArtifactRef(
                        kind=ArtifactKind.MODEL_RESPONSE,
                        artifact_id=first_receipt.response_id,
                    ),
                    parse_receipt_ref=ArtifactRef(
                        kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                        artifact_id=first_receipt.parse_receipt_id,
                    ),
                ),
                BacklogParseFailureEvidence(
                    attempt_index=1,
                    role=VlmRole.STRUCTURE_REPAIR,
                    request_ref=ArtifactRef(
                        kind=ArtifactKind.MODEL_REQUEST,
                        artifact_id=repair_request.request_id,
                    ),
                    response_ref=ArtifactRef(
                        kind=ArtifactKind.MODEL_RESPONSE,
                        artifact_id=final_receipt.response_id,
                    ),
                    parse_receipt_ref=ArtifactRef(
                        kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                        artifact_id=final_receipt.parse_receipt_id,
                    ),
                ),
            ),
        )
