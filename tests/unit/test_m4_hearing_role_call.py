from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage import (
    SecureHearingModelResponseStore,
    SecureWorkspace,
)
from labcourt.application.hearing_model_parser import inspect_hearing_response
from labcourt.application.hearing_request import (
    HearingBudgetUsage,
    HearingRequestGeneration,
    prepare_hearing_repair_request,
)
from labcourt.application.hearing_role_call import (
    HearingRoleCallContext,
    HearingRoleCallError,
    HearingRoleCallFailureCode,
    HearingRoleCallService,
)
from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import ArgumentStance, ArtifactKind, VlmRole
from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    HearingUsageReceipt,
    ProsecutorModelPayload,
)
from labcourt.contracts.verdicts import Argument
from labcourt.ports.hearing_repository import (
    HearingModelCallClaim,
    HearingModelCallClaimStatus,
)
from labcourt.ports.vlm import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from tests.unit.test_m4_hearing_backlog_retry import _strict_error
from tests.unit.test_m4_hearing_request import (
    Scenario,
    _prepare,
    _scenario,
)


class _PromptRegistrar:
    def __init__(self) -> None:
        self.prompts: dict[str, object] = {}

    def register(self, prompt) -> None:
        existing = self.prompts.get(prompt.rendered_prompt_sha256)
        if existing is not None and existing != prompt:
            raise ValueError("prompt conflict")
        self.prompts[prompt.rendered_prompt_sha256] = prompt


class _MemoryHearingCalls:
    def __init__(self) -> None:
        self.requests: dict[str, HearingModelRequest] = {}
        self.owners: dict[str, str] = {}
        self.responses: dict[str, HearingModelResponse] = {}
        self.cache: dict[str, HearingModelCacheEntry] = {}
        self.usage: dict[str, HearingUsageReceipt] = {}
        self.parses: dict[str, HearingModelParseReceipt] = {}
        self.outputs: dict[str, HearingRoleOutput] = {}
        self.backlog_leases: list[BacklogLeaseIdentity | None] = []

    def claim_hearing_model_call(
        self,
        run_id: str,
        request: HearingModelRequest,
        owner_token: str,
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> HearingModelCallClaim:
        assert run_id == request.run_id
        self.backlog_leases.append(backlog_lease)
        existing = self.requests.get(request.request_id)
        if existing is not None:
            assert existing == request
            response = next(
                (item for item in self.responses.values() if item.request_id == request.request_id),
                None,
            )
            if response is not None:
                return HearingModelCallClaim(
                    status=HearingModelCallClaimStatus.COMPLETED,
                    request_id=request.request_id,
                    response_id=response.response_id,
                )
            return HearingModelCallClaim(
                status=HearingModelCallClaimStatus.WAITING,
                request_id=request.request_id,
                lease_expires_at=datetime.now(UTC) + timedelta(seconds=30),
            )
        self.requests[request.request_id] = request
        self.owners[request.request_id] = owner_token
        return HearingModelCallClaim(
            status=HearingModelCallClaimStatus.ACQUIRED,
            request_id=request.request_id,
            lease_expires_at=datetime.now(UTC) + timedelta(seconds=30),
        )

    def complete_hearing_model_call(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
        usage: HearingUsageReceipt,
        owner_token: str,
    ) -> HearingModelCacheEntry:
        assert run_id == request.run_id
        assert self.requests[request.request_id] == request
        assert self.owners[request.request_id] == owner_token
        entry = HearingModelCacheEntry(
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
        existing_response = self.responses.get(response.response_id)
        if existing_response is not None:
            assert existing_response == response
            assert self.cache[request.cache_key] == entry
            assert self.usage[usage.usage_receipt_id] == usage
            return entry
        self.responses[response.response_id] = response
        self.cache[request.cache_key] = entry
        self.usage[usage.usage_receipt_id] = usage
        return entry

    def append_hearing_parse_receipt(
        self,
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput | None = None,
    ) -> HearingModelParseReceipt:
        existing = self.parses.get(receipt.parse_receipt_id)
        if existing is not None:
            assert existing == receipt
        else:
            self.parses[receipt.parse_receipt_id] = receipt
        if output is not None:
            existing_output = self.outputs.get(output.output_id)
            if existing_output is not None:
                assert existing_output == output
            else:
                self.outputs[output.output_id] = output
        return receipt

    def load_hearing_model_response(
        self,
        run_id: str,
        response_id: str,
    ) -> HearingModelResponse:
        response = self.responses[response_id]
        assert response.run_id == run_id
        return response

    def load_hearing_model_cache_entry(
        self,
        run_id: str,
        cache_key: str,
    ) -> HearingModelCacheEntry | None:
        entry = self.cache.get(cache_key)
        assert entry is None or entry.run_id == run_id
        return entry

    def load_hearing_usage_receipt(
        self,
        run_id: str,
        usage_receipt_id: str,
    ) -> HearingUsageReceipt:
        usage = self.usage[usage_receipt_id]
        assert usage.run_id == run_id
        return usage


class _PublishingVLM:
    def __init__(
        self,
        store: SecureHearingModelResponseStore,
        *,
        primary: bytes,
        repair: bytes | None = None,
        raise_before_publish: bool = False,
        raise_after_publish: bool = False,
        failure_delivery: VLMDeliveryCertainty = (VLMDeliveryCertainty.DEFINITELY_NOT_SENT),
    ) -> None:
        self.store = store
        self.primary = primary
        self.repair = repair
        self.raise_before_publish = raise_before_publish
        self.raise_after_publish = raise_after_publish
        self.failure_delivery = failure_delivery
        self.calls: list[HearingModelRequest] = []

    def complete(self, request: HearingModelRequest) -> HearingModelResponse:
        self.calls.append(request)
        if self.raise_before_publish:
            raise VLMProviderError(
                VLMProviderFailureCode.PROVIDER_OUTAGE,
                self.failure_delivery,
            )
        raw = self.primary if request.attempt_index == 0 else self.repair
        if raw is None:
            raise RuntimeError("missing repair fixture")
        response = self.store.publish(
            request,
            raw,
            input_tokens=2,
            output_tokens=3,
            latency_ms=4,
        )
        if self.raise_after_publish:
            self.raise_after_publish = False
            raise RuntimeError("simulated crash after durable publication")
        return response


def _payload(prepared) -> bytes:
    crop_ref = next(
        ref for ref in prepared.request.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
    )
    payload = ProsecutorModelPayload(
        arguments=(
            Argument(
                stance=ArgumentStance.PROSECUTION,
                claim="The disclosed crop supports the allegation.",
                evidence_refs=(crop_ref,),
                uncertainty=0.1,
            ),
        ),
        case_summary="The prosecutor cites only disclosed evidence.",
    )
    return canonical_bytes(payload.model_dump(mode="json", exclude_computed_fields=True))


def _context(
    scenario: Scenario,
    backlog_lease: BacklogLeaseIdentity | None = None,
) -> HearingRoleCallContext:
    return HearingRoleCallContext(
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage_before_primary=HearingBudgetUsage(),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
        backlog_lease=backlog_lease,
    )


def _service(
    repository: _MemoryHearingCalls,
    store: SecureHearingModelResponseStore,
    vlm: _PublishingVLM,
) -> HearingRoleCallService:
    return HearingRoleCallService(
        repository=repository,
        response_store=store,
        vlm_client=vlm,
        prompt_registrar=_PromptRegistrar(),
        owner_token_factory=lambda: "o" * 43,
    )


def _workspace(tmp_path: Path) -> SecureWorkspace:
    root = tmp_path / "workspace"
    root.mkdir()
    return SecureWorkspace(root, 256 * 1024)


def test_valid_primary_is_durable_and_repeat_uses_verified_cache(tmp_path: Path) -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    repository = _MemoryHearingCalls()
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        vlm = _PublishingVLM(store, primary=_payload(prepared))
        service = _service(repository, store, vlm)

        first = service.execute(prepared, _context(scenario))
        second = service.execute(prepared, _context(scenario))

    assert first.output == second.output
    assert first.cache_hit_count == 0
    assert second.cache_hit_count == 1
    assert len(vlm.calls) == 1
    assert len(repository.responses) == 1
    assert len(repository.usage) == 1
    assert len(repository.parses) == 1
    assert len(repository.outputs) == 1


def test_malformed_primary_gets_one_media_free_same_role_repair(tmp_path: Path) -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    repository = _MemoryHearingCalls()
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        vlm = _PublishingVLM(
            store,
            primary=b"{",
            repair=_payload(prepared),
        )
        result = _service(repository, store, vlm).execute(
            prepared,
            _context(scenario),
        )

    assert len(result.trace.calls) == 2
    assert result.prepared_repair is not None
    assert result.prepared_repair.request.media == ()
    assert result.prepared_repair.request.role == VlmRole.PROSECUTOR
    assert tuple(call.request.attempt_index for call in result.trace.calls) == (0, 1)
    assert len(repository.usage) == 2
    assert len(repository.parses) == 2


def test_two_malformed_responses_fail_exact_role_without_third_call(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    repository = _MemoryHearingCalls()
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        vlm = _PublishingVLM(store, primary=b"{", repair=b"{}")
        with pytest.raises(HearingRoleCallError) as captured:
            _service(repository, store, vlm).execute(
                prepared,
                _context(scenario),
            )

    assert captured.value.reason_code == HearingRoleCallFailureCode.STRICT_PARSE_FAILED
    assert captured.value.role == VlmRole.PROSECUTOR
    assert len(captured.value.failed_calls) == 2
    assert len(vlm.calls) == 2
    assert len(repository.outputs) == 0


def test_provider_failure_does_not_parse_or_forge_response(tmp_path: Path) -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    repository = _MemoryHearingCalls()
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        vlm = _PublishingVLM(
            store,
            primary=_payload(prepared),
            raise_before_publish=True,
        )
        with pytest.raises(HearingRoleCallError) as captured:
            _service(repository, store, vlm).execute(
                prepared,
                _context(scenario),
            )

    assert captured.value.reason_code == HearingRoleCallFailureCode.PROVIDER_FAILED
    assert captured.value.model_call_failure is not None
    assert captured.value.model_call_failure.request == prepared.request
    assert captured.value.model_call_failure.owner_token == "o" * 43
    assert repository.responses == {}
    assert repository.parses == {}


def test_retry_generation_provider_failure_keeps_exact_fenced_intent(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    prepared = _prepare(
        scenario,
        VlmRole.PROSECUTOR,
        generation=HearingRequestGeneration(
            retry_generation=2,
            backlog_item_id="b" * 64,
        ),
    )
    repository = _MemoryHearingCalls()
    lease = BacklogLeaseIdentity(
        run_id=prepared.request.run_id,
        item_id="b" * 64,
        lease_id="c" * 64,
        attempt_count=1,
        retry_generation=2,
    )
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        vlm = _PublishingVLM(
            store,
            primary=_payload(prepared),
            raise_before_publish=True,
        )
        with pytest.raises(HearingRoleCallError) as captured:
            _service(repository, store, vlm).execute(
                prepared,
                _context(scenario, lease),
            )

    failure = captured.value.model_call_failure
    assert captured.value.reason_code == HearingRoleCallFailureCode.PROVIDER_FAILED
    assert failure is not None and failure.request == prepared.request
    assert failure.request.backlog_retry_context is not None
    assert failure.request.backlog_retry_context.retry_generation == 2
    assert repository.backlog_leases == [lease]


def test_unknown_delivery_provider_error_requires_recovery_without_retry_authority(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    repository = _MemoryHearingCalls()
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        vlm = _PublishingVLM(
            store,
            primary=_payload(prepared),
            raise_before_publish=True,
            failure_delivery=VLMDeliveryCertainty.UNKNOWN,
        )
        with pytest.raises(HearingRoleCallError) as captured:
            _service(repository, store, vlm).execute(prepared, _context(scenario))

    assert captured.value.reason_code == HearingRoleCallFailureCode.CLAIM_RECOVERY_REQUIRED
    assert captured.value.model_call_failure is None


def test_crash_after_raw_publication_recovers_without_second_provider_call(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    repository = _MemoryHearingCalls()
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        vlm = _PublishingVLM(
            store,
            primary=_payload(prepared),
            raise_after_publish=True,
        )
        result = _service(repository, store, vlm).execute(
            prepared,
            _context(scenario),
        )

    assert result.recovered_response_count == 1
    assert len(vlm.calls) == 1
    assert len(repository.responses) == 1
    assert len(repository.outputs) == 1


def test_resume_repair_never_replays_the_already_persisted_primary(tmp_path: Path) -> None:
    scenario = _scenario()
    original = _prepare(scenario, VlmRole.PROSECUTOR)
    context = _context(scenario)
    strict = _strict_error(original, context)
    primary_failure = strict.failed_calls[0]
    inspection = inspect_hearing_response(
        b"{",
        request=original.request,
        response=primary_failure.response,
    )
    repair = prepare_hearing_repair_request(
        original=original,
        response=primary_failure.response,
        inspection=inspection,
        raw_response=b"{",
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage=HearingBudgetUsage(
            reserved_images=len(original.request.media),
            accounted_output_tokens=primary_failure.response.output_tokens,
        ),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
    )
    repository = _MemoryHearingCalls()
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        vlm = _PublishingVLM(
            store,
            primary=b"primary must never be used",
            repair=_payload(original),
        )
        result = _service(repository, store, vlm).resume_repair(
            original,
            repair,
            primary_failure,
            context,
        )

    assert [request.attempt_index for request in vlm.calls] == [1]
    assert result.trace.calls[0] == primary_failure
    assert result.trace.calls[1].request == repair.request
    assert len(repository.responses) == 1
