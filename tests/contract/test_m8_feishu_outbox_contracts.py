from __future__ import annotations

from datetime import timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import M8AuthorityReference, M8AuthorityReferenceKind
from labcourt.contracts.m8_feishu_outbox import M8FeishuSandboxOutboxRunReceiptV1
from labcourt.contracts.m8_feishu_transport import M8FeishuSandboxSendOutcome
from labcourt.contracts.m8_notification_dispatch_claims import (
    M8NotificationDispatchCallFenceReceiptV1,
    M8NotificationDispatchClaimReceiptV1,
    M8NotificationDispatchCompletionReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationDispatchDisposition,
    M8NotificationInitiatorKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationAuditEventV1,
    M8NotificationAuthorityV1,
    M8NotificationCommitReceiptV1,
    M8NotificationRawArtifactCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import M8NotificationStatus
from tests.contract.test_m8_feishu_activation_contracts import (
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    SHA_E,
)
from tests.contract.test_m8_feishu_transport_contracts import _send_receipt


def _claim(
    outcome: M8FeishuSandboxSendOutcome = M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED,
    *,
    worker_sha256: str = SHA_A,
) -> M8NotificationDispatchClaimReceiptV1:
    request = _send_receipt(outcome).preflight.notification_request
    return M8NotificationDispatchClaimReceiptV1(
        request=request,
        worker_owner_sha256=worker_sha256,
        claimed_at=request.dispatched_at,
        lease_expires_at=request.dispatched_at + timedelta(seconds=60),
        claim_manifest_id=SHA_B,
        repository_manifest_id=SHA_C,
    )


def _fence(claim: M8NotificationDispatchClaimReceiptV1, authorization_id: str):
    return M8NotificationDispatchCallFenceReceiptV1(
        claim=claim,
        dispatch_authorization_id=authorization_id,
        fenced_at=claim.claimed_at + timedelta(seconds=1),
        call_fence_manifest_id=SHA_D,
        repository_manifest_id=SHA_C,
    )


def _notification_commit(send_receipt):
    result = send_receipt.dispatch_result
    request = result.request
    accepted = result.disposition == M8NotificationDispatchDisposition.ACCEPTED
    command = M8NotificationTransitionCommandV1(
        notification_id=request.plan.notification_id,
        source_notification_version=request.source_notification_version,
        source_notification_authority_sha256=request.source_notification_authority_sha256,
        source_status=M8NotificationStatus.QUEUED,
        action=(
            M8NotificationAction.RECORD_SENT if accepted else M8NotificationAction.RECORD_FAILED
        ),
        initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
        dispatch_result=result,
        supporting_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.NOTIFICATION_REPLY,
                authority_id="feishu-sandbox-outbox-support-01",
                document_sha256=SHA_E,
            ),
        ),
        explicit_human_confirmation=False,
        occurred_at=result.completed_at,
        command_manifest_id=SHA_D,
    )
    authority = M8NotificationAuthorityV1(
        plan=request.plan,
        notification_version=request.source_notification_version + 1,
        status=M8NotificationStatus.SENT if accepted else M8NotificationStatus.FAILED,
        prior_notification_document_sha256=request.source_notification_authority_sha256,
        last_transition_command_id=command.command_id,
        last_initiator_authority_id=(request.channel_capability.capability_authority_id),
        last_dispatch_result_id=result.dispatch_result_id,
        notification_manifest_id=request.plan.notification_manifest_id,
    )
    event = M8NotificationAuditEventV1(
        notification_authority=authority,
        event_sequence=authority.notification_version,
        transition_command=command,
        prior_audit_event_sha256=SHA_A,
        audit_manifest_id=SHA_E,
    )
    card_bytes = send_receipt.preflight.card.provider_content_json.encode()
    raw_response = b'{"code":0,"data":{"message_id":"om-sandbox-01"}}\n'
    return M8NotificationCommitReceiptV1(
        audit_event=event,
        raw_artifact_receipts=(
            M8NotificationRawArtifactCommitReceiptV1(
                raw_artifact_ref=request.rendered_card_ref,
                raw_artifact_sha256=request.rendered_card_sha256,
                raw_artifact_size_bytes=len(card_bytes),
                raw_storage_manifest_id=SHA_D,
                repository_manifest_id=SHA_C,
            ),
            M8NotificationRawArtifactCommitReceiptV1(
                raw_artifact_ref=result.raw_response_ref,
                raw_artifact_sha256=result.raw_response_sha256,
                raw_artifact_size_bytes=len(raw_response),
                raw_storage_manifest_id=SHA_D,
                repository_manifest_id=SHA_C,
            ),
        ),
        repository_manifest_id=SHA_C,
    )


def _run_receipt(
    outcome: M8FeishuSandboxSendOutcome = M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED,
) -> M8FeishuSandboxOutboxRunReceiptV1:
    send = _send_receipt(outcome)
    claim = _claim(outcome)
    fence = _fence(claim, send.activation_status.status_id)
    completion = M8NotificationDispatchCompletionReceiptV1(
        claim=claim,
        call_fence=fence,
        dispatch_result=send.dispatch_result,
        notification_commit=_notification_commit(send),
        committed_at=send.dispatch_result.completed_at + timedelta(seconds=1),
        completion_manifest_id=SHA_A,
        repository_manifest_id=SHA_C,
    )
    return M8FeishuSandboxOutboxRunReceiptV1(
        claim=claim,
        call_fence=fence,
        send_receipt=send,
        completion=completion,
        runner_manifest_id=SHA_B,
    )


def test_accepted_outbox_run_binds_one_attempt_without_claiming_delivery() -> None:
    receipt = _run_receipt()

    assert receipt.notification_id == (
        receipt.send_receipt.preflight.notification_request.plan.notification_id
    )
    assert receipt.attempt_number == 1
    assert receipt.provider_message_request_attempted is True
    assert receipt.provider_acceptance_confirmed is True
    assert receipt.notification_transition_committed is True
    assert receipt.notification_status == M8NotificationStatus.SENT
    assert receipt.unknown_delivery is False
    assert receipt.real_delivery_confirmed is False
    assert receipt.credential_material_persisted is False
    assert receipt.automatic_retry_permitted is False
    assert receipt.case_transition_permitted is False
    assert receipt.direct_disciplinary_action_permitted is False
    assert len(receipt.run_receipt_id) == 64


def test_unknown_delivery_run_commits_failed_without_retry_or_case_authority() -> None:
    receipt = _run_receipt(M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN)

    assert receipt.provider_acceptance_confirmed is False
    assert receipt.notification_status == M8NotificationStatus.FAILED
    assert receipt.unknown_delivery is True
    assert receipt.automatic_retry_permitted is False
    assert receipt.case_transition_permitted is False


def test_outbox_run_rejects_cross_claim_fence_and_activation_graft() -> None:
    receipt = _run_receipt()
    another_claim = _claim(worker_sha256=SHA_B)
    payload = receipt.model_dump(mode="json", exclude={"run_receipt_id"})
    payload["call_fence"] = _fence(
        another_claim,
        receipt.send_receipt.activation_status.status_id,
    ).model_dump(mode="json")
    with pytest.raises(ValidationError, match="another claim"):
        M8FeishuSandboxOutboxRunReceiptV1.model_validate(payload)

    payload = receipt.model_dump(mode="json", exclude={"run_receipt_id"})
    payload["call_fence"] = _fence(receipt.claim, SHA_A).model_dump(mode="json")
    with pytest.raises(ValidationError, match="exact activation status"):
        M8FeishuSandboxOutboxRunReceiptV1.model_validate(payload)


def test_outbox_run_rejects_completion_from_another_send() -> None:
    accepted = _run_receipt()
    unknown = _run_receipt(M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN)

    with pytest.raises(ValidationError, match="another send attempt"):
        M8FeishuSandboxOutboxRunReceiptV1(
            claim=accepted.claim,
            call_fence=accepted.call_fence,
            send_receipt=accepted.send_receipt,
            completion=unknown.completion,
            runner_manifest_id=accepted.runner_manifest_id,
        )


def test_outbox_run_computed_claims_round_trip_and_schema() -> None:
    receipt = _run_receipt()
    restored = M8FeishuSandboxOutboxRunReceiptV1.model_validate_json(receipt.model_dump_json())
    assert restored == receipt
    Draft202012Validator(
        M8FeishuSandboxOutboxRunReceiptV1.model_json_schema(mode="serialization")
    ).validate(receipt.model_dump(mode="json"))

    payload = receipt.model_dump(mode="json")
    payload["provider_acceptance_confirmed"] = False
    with pytest.raises(ValidationError, match="provider_acceptance_confirmed"):
        M8FeishuSandboxOutboxRunReceiptV1.model_validate(payload)
