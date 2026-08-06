from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.adapters.storage import SecureHearingModelResponseStore
from labcourt.application.hearing_initial_backlog import (
    HearingInitialBacklogFailure,
    HearingInitialBacklogFailureCode,
    build_initial_hearing_backlog_intent,
)
from labcourt.application.hearing_role_call import (
    HearingRoleCallError,
    HearingRoleCallFailureCode,
)
from labcourt.contracts.enums import BacklogReasonCode, VlmRole
from labcourt.ports.vlm import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from tests.unit.test_m4_hearing_backlog_retry import (
    _context,
    _pending_checkpoint,
    _strict_error,
)
from tests.unit.test_m4_hearing_request import _prepare, _scenario
from tests.unit.test_m4_hearing_role_call import (
    _MemoryHearingCalls,
    _payload,
    _PublishingVLM,
    _service,
    _workspace,
)


class _UnknownDeliveryVLM:
    def complete(self, request):
        del request
        raise VLMProviderError(
            VLMProviderFailureCode.TRANSPORT_UNAVAILABLE,
            VLMDeliveryCertainty.UNKNOWN,
        )


class _CompletedWithoutMetricsVLM:
    def complete(self, request):
        del request
        raise VLMProviderError(
            VLMProviderFailureCode.RESPONSE_TOO_LARGE,
            VLMDeliveryCertainty.COMPLETED,
        )


def test_known_not_sent_failure_preserves_claim_and_builds_generation_zero(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    checkpoint = _pending_checkpoint(scenario)
    repository = _MemoryHearingCalls()
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        vlm = _PublishingVLM(
            store,
            primary=_payload(prepared),
            raise_before_publish=True,
        )
        with pytest.raises(HearingRoleCallError) as captured:
            _service(repository, store, vlm).execute(prepared, _context(scenario))

    failure = captured.value
    intent = build_initial_hearing_backlog_intent(
        failure,
        checkpoint,
        max_attempts=3,
    )

    assert failure.reason_code == HearingRoleCallFailureCode.PROVIDER_FAILED
    assert failure.model_call_failure is not None
    assert failure.model_call_failure.owner_token == repository.owners[prepared.request.request_id]
    assert failure.model_call_failure.claim_lease_expires_at is not None
    assert intent.model_call_failure == failure.model_call_failure
    assert intent.item.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
    assert intent.item.retry_generation == 0
    assert intent.stage_request == prepared.request


@pytest.mark.parametrize("vlm_type", [_UnknownDeliveryVLM, _CompletedWithoutMetricsVLM])
def test_unaccounted_delivery_is_recovery_required_not_backlog_authority(
    tmp_path: Path,
    vlm_type,
) -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    repository = _MemoryHearingCalls()
    with _workspace(tmp_path) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        with pytest.raises(HearingRoleCallError) as captured:
            _service(repository, store, vlm_type()).execute(
                prepared,
                _context(scenario),
            )

    failure = captured.value
    assert failure.reason_code == HearingRoleCallFailureCode.CLAIM_RECOVERY_REQUIRED
    assert failure.model_call_failure is None
    assert repository.responses == {}
    with pytest.raises(HearingInitialBacklogFailure) as bridge:
        build_initial_hearing_backlog_intent(
            failure,
            _pending_checkpoint(scenario),
            max_attempts=3,
        )
    assert bridge.value.reason_code == HearingInitialBacklogFailureCode.RECOVERY_REQUIRED


def test_two_strict_failures_build_initial_generation_one_proof() -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    checkpoint = _pending_checkpoint(scenario)
    failure = _strict_error(prepared, _context(scenario))

    intent = build_initial_hearing_backlog_intent(
        failure,
        checkpoint,
        max_attempts=3,
    )

    proof = intent.strict_parse_failure
    assert intent.item.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID
    assert intent.item.retry_generation == 1
    assert intent.stage_request == failure.failed_calls[0].request
    assert proof is not None
    assert proof.backlog_item_id == intent.item.item_id
    assert tuple(attempt.request for attempt in proof.attempts) == tuple(
        call.request for call in failure.failed_calls
    )
