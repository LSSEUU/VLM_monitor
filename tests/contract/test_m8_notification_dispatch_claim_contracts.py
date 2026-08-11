from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.application.m8_notification_workflow import build_notification_transition_commit
from labcourt.contracts.m8_access_cases import M8AuthorityReference, M8AuthorityReferenceKind
from labcourt.contracts.m8_notification_dispatch_claims import (
    MAX_M8_NOTIFICATION_DISPATCH_CLAIM_SECONDS,
    M8NotificationDispatchCallFenceReceiptV1,
    M8NotificationDispatchClaimReceiptV1,
    M8NotificationDispatchClaimState,
    M8NotificationDispatchClaimStatusV1,
    M8NotificationDispatchCompletionReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationChannelFailureCode,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
    M8NotificationInitiatorKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notifications import M8NotificationStatus
from tests.contract.test_m8_notification_lifecycle_contracts import _capability
from tests.contract.test_m8_notification_persistence_contracts import (
    BASE_TIME,
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    SHA_E,
    _queued_receipt,
)

CARD_BYTES = b'{"badge":"SIMULATED","card":"notification"}'
RESPONSE_BYTES = b'{"accepted":true,"provider":"fake"}'


def _request() -> M8NotificationDispatchRequestV1:
    queued = _queued_receipt()
    plan = queued.audit_event.notification_authority.plan
    claimed_at = BASE_TIME + timedelta(minutes=2)
    return M8NotificationDispatchRequestV1(
        plan=plan,
        source_notification_version=queued.notification_version,
        source_notification_authority_sha256=queued.notification_document_sha256,
        attempt_number=1,
        channel_capability=_capability(),
        rendered_card_ref="notification-claim-card-01",
        rendered_card_sha256=hashlib.sha256(CARD_BYTES).hexdigest(),
        dispatched_at=claimed_at,
        timeout_ms=_capability().request_timeout_ms,
        idempotency_key=plan.notification_id,
        request_manifest_id=SHA_D,
    )


def _claim(*, worker_owner_sha256: str = SHA_A) -> M8NotificationDispatchClaimReceiptV1:
    request = _request()
    return M8NotificationDispatchClaimReceiptV1(
        request=request,
        worker_owner_sha256=worker_owner_sha256,
        claimed_at=request.dispatched_at,
        lease_expires_at=request.dispatched_at + timedelta(seconds=60),
        claim_manifest_id=SHA_B,
        repository_manifest_id=SHA_C,
    )


def _fence(
    *,
    claim: M8NotificationDispatchClaimReceiptV1 | None = None,
) -> M8NotificationDispatchCallFenceReceiptV1:
    selected = claim or _claim()
    return M8NotificationDispatchCallFenceReceiptV1(
        claim=selected,
        dispatch_authorization_id=SHA_D,
        fenced_at=selected.claimed_at + timedelta(seconds=1),
        call_fence_manifest_id=SHA_E,
        repository_manifest_id=SHA_C,
    )


def _result(
    disposition: M8NotificationDispatchDisposition = M8NotificationDispatchDisposition.ACCEPTED,
) -> M8NotificationDispatchResultV1:
    return M8NotificationDispatchResultV1(
        request=_request(),
        disposition=disposition,
        provider_receipt_id=(
            "fake-provider-message-01"
            if disposition == M8NotificationDispatchDisposition.ACCEPTED
            else None
        ),
        raw_response_ref="notification-claim-response-01",
        raw_response_sha256=hashlib.sha256(RESPONSE_BYTES).hexdigest(),
        failure_code=(
            None
            if disposition == M8NotificationDispatchDisposition.ACCEPTED
            else (
                M8NotificationChannelFailureCode.UNKNOWN_DELIVERY
                if disposition == M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
                else M8NotificationChannelFailureCode.CHANNEL_REJECTED
            )
        ),
        completed_at=_request().dispatched_at + timedelta(seconds=2),
        result_manifest_id=SHA_E,
    )


def _notification_commit(
    result: M8NotificationDispatchResultV1,
):
    queued = _queued_receipt()
    command = M8NotificationTransitionCommandV1(
        notification_id=queued.notification_id,
        source_notification_version=queued.notification_version,
        source_notification_authority_sha256=queued.notification_document_sha256,
        source_status=queued.status,
        action=(
            M8NotificationAction.RECORD_SENT
            if result.disposition == M8NotificationDispatchDisposition.ACCEPTED
            else M8NotificationAction.RECORD_FAILED
        ),
        initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
        dispatch_result=result,
        supporting_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.NOTIFICATION_REPLY,
                authority_id="notification-dispatch-claim-01",
                document_sha256=SHA_A,
            ),
        ),
        explicit_human_confirmation=False,
        occurred_at=result.completed_at,
        command_manifest_id=SHA_E,
    )
    return build_notification_transition_commit(
        queued,
        command,
        (CARD_BYTES, RESPONSE_BYTES),
        SHA_D,
        None,
        SHA_E,
        SHA_C,
    )


def _completion(
    disposition: M8NotificationDispatchDisposition = M8NotificationDispatchDisposition.ACCEPTED,
) -> M8NotificationDispatchCompletionReceiptV1:
    claim = _claim()
    result = _result(disposition)
    return M8NotificationDispatchCompletionReceiptV1(
        claim=claim,
        call_fence=_fence(claim=claim),
        dispatch_result=result,
        notification_commit=_notification_commit(result),
        committed_at=result.completed_at + timedelta(seconds=1),
        completion_manifest_id=SHA_A,
        repository_manifest_id=SHA_C,
    )


def test_claim_binds_exact_queued_version_attempt_worker_and_bounded_lease() -> None:
    claim = _claim()

    assert claim.notification_id == claim.request.plan.notification_id
    assert claim.source_notification_version == 2
    assert claim.attempt_number == 1
    assert claim.dispatch_call_claimed is True
    assert claim.dispatch_call_permitted is False
    assert claim.automatic_takeover_permitted is False
    assert claim.case_transition_permitted is False
    assert claim.direct_disciplinary_action_permitted is False
    assert len(claim.claim_id) == 64

    payload = claim.model_dump(mode="json")
    payload["claim_id"] = SHA_E
    with pytest.raises(ValidationError, match="claim_id"):
        M8NotificationDispatchClaimReceiptV1.model_validate(payload)


def test_claim_rejects_retimed_request_and_unbounded_lease() -> None:
    claim = _claim()
    payload = claim.model_dump(mode="json", exclude={"claim_id"})
    payload["claimed_at"] = (claim.claimed_at + timedelta(seconds=1)).isoformat()
    with pytest.raises(ValidationError, match="request time"):
        M8NotificationDispatchClaimReceiptV1.model_validate(payload)

    payload = claim.model_dump(mode="json", exclude={"claim_id"})
    payload["lease_expires_at"] = (
        claim.claimed_at + timedelta(seconds=MAX_M8_NOTIFICATION_DISPATCH_CLAIM_SECONDS + 1)
    ).isoformat()
    with pytest.raises(ValidationError, match="bounded window"):
        M8NotificationDispatchClaimReceiptV1.model_validate(payload)


def test_call_fence_is_one_shot_boundary_proof_and_never_retry_authority() -> None:
    fence = _fence()

    assert fence.external_call_boundary_crossed is True
    assert fence.additional_dispatch_call_permitted is False
    assert fence.automatic_retry_permitted is False
    assert len(fence.call_fence_id) == 64

    payload = fence.model_dump(mode="json", exclude={"call_fence_id"})
    payload["fenced_at"] = fence.claim.lease_expires_at.isoformat()
    with pytest.raises(ValidationError, match="outside its live claim"):
        M8NotificationDispatchCallFenceReceiptV1.model_validate(payload)


@pytest.mark.parametrize(
    ("disposition", "expected_status", "unknown"),
    [
        (
            M8NotificationDispatchDisposition.ACCEPTED,
            M8NotificationStatus.SENT,
            False,
        ),
        (
            M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
            M8NotificationStatus.FAILED,
            False,
        ),
        (
            M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
            M8NotificationStatus.FAILED,
            True,
        ),
    ],
)
def test_completion_atomically_binds_result_to_exact_notification_transition(
    disposition: M8NotificationDispatchDisposition,
    expected_status: M8NotificationStatus,
    unknown: bool,
) -> None:
    completion = _completion(disposition)

    assert completion.notification_commit.status == expected_status
    assert completion.notification_transition_committed is True
    assert completion.unknown_delivery is unknown
    assert completion.additional_dispatch_call_permitted is False
    assert completion.case_transition_permitted is False
    assert completion.direct_disciplinary_action_permitted is False
    assert len(completion.completion_id) == 64


def test_completion_rejects_grafted_result_or_notification_commit() -> None:
    accepted = _completion()
    rejected_result = _result(M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT)
    payload = accepted.model_dump(mode="json", exclude={"completion_id"})
    payload["dispatch_result"] = rejected_result.model_dump(mode="json")

    with pytest.raises(ValidationError, match="exact channel transition"):
        M8NotificationDispatchCompletionReceiptV1.model_validate(payload)


def test_status_derives_pre_call_in_flight_reconciliation_and_completed_states() -> None:
    claim = _claim()
    fence = _fence(claim=claim)
    claimed = M8NotificationDispatchClaimStatusV1(
        claim=claim,
        assessed_at=claim.claimed_at + timedelta(seconds=1),
        repository_manifest_id=SHA_C,
    )
    expired = claimed.model_copy(update={"assessed_at": claim.lease_expires_at})
    in_flight = M8NotificationDispatchClaimStatusV1(
        claim=claim,
        call_fence=fence,
        assessed_at=claim.claimed_at + timedelta(seconds=2),
        repository_manifest_id=SHA_C,
    )
    reconciliation = in_flight.model_copy(update={"assessed_at": claim.lease_expires_at})
    completion = _completion()
    completed = M8NotificationDispatchClaimStatusV1(
        claim=completion.claim,
        call_fence=completion.call_fence,
        completion=completion,
        assessed_at=completion.committed_at,
        repository_manifest_id=SHA_C,
    )

    assert claimed.state == M8NotificationDispatchClaimState.CLAIMED
    assert expired.state == M8NotificationDispatchClaimState.EXPIRED_PRE_CALL
    assert in_flight.state == M8NotificationDispatchClaimState.CALL_IN_PROGRESS
    assert reconciliation.state == M8NotificationDispatchClaimState.RECONCILIATION_REQUIRED
    assert reconciliation.reconciliation_required is True
    assert completed.state == M8NotificationDispatchClaimState.COMPLETED
    for status in (claimed, expired, in_flight, reconciliation, completed):
        assert status.new_dispatch_call_permitted is False
        assert status.automatic_retry_permitted is False
        assert status.case_transition_permitted is False


def test_status_rejects_cross_claim_fence_and_forged_state() -> None:
    claim = _claim()
    another_fence = _fence(claim=_claim(worker_owner_sha256=SHA_B))
    with pytest.raises(ValidationError, match="another call fence"):
        M8NotificationDispatchClaimStatusV1(
            claim=claim,
            call_fence=another_fence,
            assessed_at=claim.claimed_at + timedelta(seconds=2),
            repository_manifest_id=SHA_C,
        )

    status = M8NotificationDispatchClaimStatusV1(
        claim=claim,
        assessed_at=claim.claimed_at + timedelta(seconds=1),
        repository_manifest_id=SHA_C,
    )
    payload = status.model_dump(mode="json")
    payload["state"] = M8NotificationDispatchClaimState.COMPLETED.value
    with pytest.raises(ValidationError, match="state"):
        M8NotificationDispatchClaimStatusV1.model_validate(payload)


def test_dispatch_claim_contracts_round_trip_and_validate_serialization_schemas() -> None:
    completion = _completion(M8NotificationDispatchDisposition.UNKNOWN_DELIVERY)
    status = M8NotificationDispatchClaimStatusV1(
        claim=completion.claim,
        call_fence=completion.call_fence,
        completion=completion,
        assessed_at=completion.committed_at,
        repository_manifest_id=SHA_C,
    )
    models = (completion.claim, completion.call_fence, completion, status)
    for model in models:
        restored = type(model).model_validate_json(model.model_dump_json())
        assert restored == model
        Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
            model.model_dump(mode="json")
        )
