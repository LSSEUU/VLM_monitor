from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertChannelIdempotencyGuarantee,
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertDispatchAttempt,
    AlertDispatchContinuation,
    AlertDispatchDisposition,
    AlertDispatchFailureCode,
    AlertDispatchReceipt,
    AlertOutboxItem,
    AlertOutboxPriority,
    AlertPolicyAuthority,
    AlertPolicyDisposition,
    AlertPolicyRequest,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.alerts import (
    AlertDecision,
    DeliveryReceipt,
    EmergencySafetyIncident,
)
from labcourt.contracts.enums import (
    AlertLevel,
    CaseStatus,
    RiskLevel,
    SafetySignalType,
    VerdictDecision,
    ViolationType,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
STARTED_AT = datetime(2026, 8, 2, 12, tzinfo=UTC)


def _channel_capability(
    guarantee: AlertChannelIdempotencyGuarantee = (AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID),
) -> AlertChannelCapabilityAuthority:
    return AlertChannelCapabilityAuthority(
        run_id="run-01",
        manifest_id=SHA_C,
        config_sha256=SHA_B,
        channel="fake-alert-channel",
        capability_revision="fake-alert-channel-v1",
        idempotency_guarantee=guarantee,
        provider_idempotency_key=(
            "alert_id" if guarantee == AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID else None
        ),
    )


def test_channel_capability_binds_run_manifest_and_config_into_its_identity() -> None:
    capability = _channel_capability()

    assert capability.run_id == "run-01"
    payload = capability.model_dump(mode="json")
    payload["config_sha256"] = SHA_D
    with pytest.raises(ValidationError, match="capability_id"):
        AlertChannelCapabilityAuthority.model_validate(payload)


def _cooldown_key(*, epoch: str = "epoch-01") -> AlertCooldownKey:
    return AlertCooldownKey(
        zone_id="hood-01",
        violation_type=ViolationType.OPEN_FLAME,
        track_ref=f"cam-01:{epoch}:burner-01",
    )


def _cooldown(*, epoch: str = "epoch-01") -> AlertCooldownAuthority:
    return AlertCooldownAuthority(
        key=_cooldown_key(epoch=epoch),
        stream_id="stream-01",
        source_alert_id=SHA_A,
        source_trigger_frame=100,
        cooldown_frames=1_800,
        cooldown_until_frame_exclusive=1_900,
    )


def _emergency_delivery() -> ImmediateSafetyDeliveryAuthority:
    incident = EmergencySafetyIncident(
        incident_id="incident-01",
        signal_id="signal-01",
        signal_type=SafetySignalType.OPEN_FLAME,
        zone_id="hood-01",
        certification_id="cert-01",
        delivery_idempotency_key="safety-delivery-01",
    )
    return ImmediateSafetyDeliveryAuthority(
        incident=incident,
        delivery_receipt=DeliveryReceipt(
            alert_id=incident.incident_id,
            channel="safety-channel",
            idempotency_key=incident.delivery_idempotency_key,
            accepted=True,
            provider_receipt_ref="provider-receipt-01",
        ),
    )


def _request(
    *,
    prior_cooldown: AlertCooldownAuthority | None = None,
    prior_emergency_delivery: ImmediateSafetyDeliveryAuthority | None = None,
) -> AlertPolicyRequest:
    return AlertPolicyRequest(
        run_id="run-01",
        case_id="case-01",
        case_authority_sha256=SHA_A,
        source_case_status=CaseStatus.READY_FOR_ALERT_POLICY,
        config_sha256=SHA_B,
        manifest_id=SHA_C,
        camera_id="cam-01",
        stream_id="stream-01",
        stream_authority_sha256=SHA_D,
        fps_num=30,
        fps_den=1,
        zone_id="hood-01",
        zone_risk=RiskLevel.HIGH,
        violation_type=ViolationType.OPEN_FLAME,
        primary_track_ref="cam-01:epoch-01:burner-01",
        trigger_frame=100,
        hard_rule=True,
        verdict_id=SHA_A,
        verdict_version=1,
        verdict_sha256=SHA_B,
        verdict_decision=VerdictDecision.ESTABLISHED,
        verdict_confidence=0.95,
        recommended_alert_level=AlertLevel.EMERGENCY,
        procedural_review_id=SHA_C,
        procedural_review_version=1,
        procedural_review_passed=True,
        observation_sufficiency_sha256=None,
        cooldown_seconds=60.0,
        cooldown_frames=1_800,
        confirmed_min_confidence=0.8,
        insufficient_evidence_max_level=AlertLevel.ADVISORY,
        prior_cooldown=prior_cooldown,
        prior_emergency_delivery=prior_emergency_delivery,
    )


def _decision(request: AlertPolicyRequest, *, suppressed: bool = False) -> AlertDecision:
    return AlertDecision(
        alert_id=request.expected_alert_id,
        case_id=request.case_id,
        level=AlertLevel.EMERGENCY,
        recipients=("emergency-response", "safety-officer", "zone-safety-review"),
        policy_rule_ids=("m5-alert-policy-v1",),
        suppressed_by_cooldown=suppressed,
        merged_into_alert_id=SHA_A if suppressed else None,
    )


def _outbox(request: AlertPolicyRequest, decision: AlertDecision) -> AlertOutboxItem:
    return AlertOutboxItem(
        run_id=request.run_id,
        case_id=request.case_id,
        case_authority_sha256=request.case_authority_sha256,
        policy_request_id=request.request_id,
        manifest_id=request.manifest_id,
        alert=decision,
        priority=AlertOutboxPriority.CRITICAL,
        idempotency_key=decision.alert_id,
    )


def test_additive_request_binds_exact_fps_cooldown_tracker_epoch_and_demo_repeat_mode() -> None:
    request = _request(prior_cooldown=_cooldown())

    assert request.cooldown_frames == 1_800
    assert request.repeat_history_mode == "DISABLED_UNTRUSTED_DEMO"
    assert request.cross_day_repeat_count == 0
    assert request.expected_alert_id != request.request_id
    assert request.request_id == request.model_validate_json(request.model_dump_json()).request_id

    payload = request.model_dump(mode="json")
    payload.pop("request_id")
    payload["cooldown_frames"] = 1_799
    with pytest.raises(ValidationError, match="cooldown_frames"):
        AlertPolicyRequest.model_validate(payload)

    payload = request.model_dump(mode="json")
    payload.pop("request_id")
    payload["fps_num"] = 60
    payload["fps_den"] = 2
    payload["cooldown_frames"] = 1_800
    with pytest.raises(ValidationError, match="lowest terms"):
        AlertPolicyRequest.model_validate(payload)

    payload = request.model_dump(mode="json")
    payload.pop("request_id")
    payload["primary_track_ref"] = "cam-02:epoch-01:burner-01"
    with pytest.raises(ValidationError, match="camera"):
        AlertPolicyRequest.model_validate(payload)


def test_immediate_safety_authority_requires_an_exact_accepted_delivery() -> None:
    authority = _emergency_delivery()
    assert authority.incident.adjudicated is False
    assert authority.delivery_receipt.accepted is True

    payload = authority.model_dump(mode="json")
    payload.pop("authority_id")
    payload["delivery_receipt"]["idempotency_key"] = "wrong"
    with pytest.raises(ValidationError, match="idempotency"):
        ImmediateSafetyDeliveryAuthority.model_validate(payload)

    payload = authority.model_dump(mode="json")
    payload.pop("authority_id")
    payload["delivery_receipt"]["accepted"] = False
    with pytest.raises(ValidationError, match="accepted"):
        ImmediateSafetyDeliveryAuthority.model_validate(payload)

    request = _request(prior_emergency_delivery=authority)
    payload = request.model_dump(mode="json")
    payload.pop("request_id")
    payload["zone_id"] = "another-zone"
    with pytest.raises(ValidationError, match="emergency delivery"):
        AlertPolicyRequest.model_validate(payload)


def test_authority_requires_outbox_exactly_when_decision_is_deliverable() -> None:
    request = _request()
    decision = _decision(request)
    outbox = _outbox(request, decision)
    authority = AlertPolicyAuthority(
        request=request,
        disposition=AlertPolicyDisposition.ENQUEUE,
        policy_rule_ids=decision.policy_rule_ids,
        decision=decision,
        cooldown_write=AlertCooldownAuthority(
            key=_cooldown_key(),
            stream_id=request.stream_id,
            source_alert_id=decision.alert_id,
            source_trigger_frame=request.trigger_frame,
            cooldown_frames=request.cooldown_frames,
            cooldown_until_frame_exclusive=(request.trigger_frame + request.cooldown_frames),
        ),
        outbox_item=outbox,
        target_case_status=CaseStatus.CLOSED,
        final_decision=request.verdict_decision,
    )

    assert authority.outbox_item == outbox
    assert (
        authority.authority_id
        == authority.model_validate_json(authority.model_dump_json()).authority_id
    )

    payload = authority.model_dump(mode="json")
    payload.pop("authority_id")
    payload["outbox_item"] = None
    with pytest.raises(ValidationError, match="deliverable"):
        AlertPolicyAuthority.model_validate(payload)

    suppressed = _decision(request, suppressed=True)
    suppressed_authority = AlertPolicyAuthority(
        request=request,
        disposition=AlertPolicyDisposition.SUPPRESSED_MERGED,
        policy_rule_ids=suppressed.policy_rule_ids,
        decision=suppressed,
        cooldown_write=None,
        outbox_item=None,
        final_decision=request.verdict_decision,
    )
    payload = suppressed_authority.model_dump(mode="json")
    payload.pop("authority_id")
    payload["outbox_item"] = outbox.model_dump(mode="json")
    with pytest.raises(ValidationError, match="suppressed"):
        AlertPolicyAuthority.model_validate(payload)


def test_not_established_has_an_explicit_close_without_alert_disposition() -> None:
    request = _request().model_copy(
        update={
            "verdict_decision": VerdictDecision.NOT_ESTABLISHED,
            "recommended_alert_level": AlertLevel.ADVISORY,
        }
    )
    authority = AlertPolicyAuthority(
        request=request,
        disposition=AlertPolicyDisposition.CLOSE_NO_ALERT,
        policy_rule_ids=("m5-alert-policy-v1", "not-established-close-no-alert-v1"),
        final_decision=VerdictDecision.NOT_ESTABLISHED,
    )

    assert authority.decision is None
    assert authority.outbox_item is None
    assert authority.cooldown_write is None


def test_outbox_and_dispatch_contracts_fix_idempotency_to_alert_id() -> None:
    request = _request()
    decision = _decision(request)
    outbox = _outbox(request, decision)
    attempt = AlertDispatchAttempt(
        outbox_id=outbox.outbox_id,
        alert_id=decision.alert_id,
        case_id=request.case_id,
        attempt_number=1,
        fence=1,
        lease_owner_sha256=SHA_D,
        started_at=STARTED_AT,
        lease_expires_at=STARTED_AT + timedelta(minutes=1),
        channel_capability=_channel_capability(),
        idempotency_key=decision.alert_id,
    )
    receipt = AlertDispatchReceipt(
        attempt_id=attempt.attempt_id,
        outbox_id=outbox.outbox_id,
        alert_id=decision.alert_id,
        case_id=request.case_id,
        attempt_number=1,
        fence=attempt.fence,
        lease_owner_sha256=attempt.lease_owner_sha256,
        started_at=attempt.started_at,
        lease_expires_at=attempt.lease_expires_at,
        channel_capability=attempt.channel_capability,
        idempotency_key=decision.alert_id,
        disposition=AlertDispatchDisposition.SUCCEEDED,
        continuation=AlertDispatchContinuation.CLOSED,
        delivery_receipt=DeliveryReceipt(
            alert_id=decision.alert_id,
            channel="fake-alert-channel",
            idempotency_key=decision.alert_id,
            accepted=True,
            provider_receipt_ref="provider-01",
        ),
    )

    assert outbox.idempotency_key == decision.alert_id
    assert attempt.idempotency_key == decision.alert_id
    assert receipt.idempotency_key == decision.alert_id

    for source, model in (
        (outbox.model_dump(mode="json"), AlertOutboxItem),
        (attempt.model_dump(mode="json"), AlertDispatchAttempt),
        (receipt.model_dump(mode="json"), AlertDispatchReceipt),
    ):
        payload = deepcopy(source)
        payload.pop(
            {
                AlertOutboxItem: "outbox_id",
                AlertDispatchAttempt: "attempt_id",
                AlertDispatchReceipt: "receipt_id",
            }[model]
        )
        payload["idempotency_key"] = "wrong"
        with pytest.raises(ValidationError, match="idempotency"):
            model.model_validate(payload)


def test_retryable_dispatch_receipt_requires_a_typed_failure_and_no_false_success() -> None:
    request = _request()
    decision = _decision(request)
    outbox = _outbox(request, decision)
    attempt = AlertDispatchAttempt(
        outbox_id=outbox.outbox_id,
        alert_id=decision.alert_id,
        case_id=request.case_id,
        attempt_number=2,
        fence=2,
        lease_owner_sha256=SHA_D,
        started_at=STARTED_AT,
        lease_expires_at=STARTED_AT + timedelta(minutes=1),
        channel_capability=_channel_capability(),
        idempotency_key=decision.alert_id,
    )
    failure = AlertDispatchReceipt(
        attempt_id=attempt.attempt_id,
        outbox_id=outbox.outbox_id,
        alert_id=decision.alert_id,
        case_id=request.case_id,
        attempt_number=attempt.attempt_number,
        fence=attempt.fence,
        lease_owner_sha256=attempt.lease_owner_sha256,
        started_at=attempt.started_at,
        lease_expires_at=attempt.lease_expires_at,
        channel_capability=attempt.channel_capability,
        idempotency_key=decision.alert_id,
        disposition=AlertDispatchDisposition.RETRYABLE_FAILURE,
        continuation=AlertDispatchContinuation.RETRY_ALLOWED,
        failure_code=AlertDispatchFailureCode.CHANNEL_REJECTED,
        delivery_receipt=DeliveryReceipt(
            alert_id=decision.alert_id,
            channel="fake-alert-channel",
            idempotency_key=decision.alert_id,
            accepted=False,
        ),
    )
    assert failure.failure_code == AlertDispatchFailureCode.CHANNEL_REJECTED

    payload = failure.model_dump(mode="json")
    payload.pop("receipt_id")
    payload["failure_code"] = None
    with pytest.raises(ValidationError, match="failure"):
        AlertDispatchReceipt.model_validate(payload)

    payload = failure.model_dump(mode="json")
    payload.pop("receipt_id")
    payload["delivery_receipt"]["accepted"] = True
    with pytest.raises(ValidationError, match="non-success"):
        AlertDispatchReceipt.model_validate(payload)


def test_unknown_delivery_retry_authority_requires_exact_provider_idempotency() -> None:
    request = _request()
    decision = _decision(request)
    outbox = _outbox(request, decision)
    exact = AlertDispatchAttempt(
        outbox_id=outbox.outbox_id,
        alert_id=decision.alert_id,
        case_id=request.case_id,
        attempt_number=1,
        fence=1,
        lease_owner_sha256=SHA_D,
        started_at=STARTED_AT,
        lease_expires_at=STARTED_AT + timedelta(minutes=1),
        channel_capability=_channel_capability(),
        idempotency_key=decision.alert_id,
    )
    retry_safe = AlertDispatchReceipt(
        attempt_id=exact.attempt_id,
        outbox_id=exact.outbox_id,
        alert_id=exact.alert_id,
        case_id=exact.case_id,
        attempt_number=exact.attempt_number,
        fence=exact.fence,
        lease_owner_sha256=exact.lease_owner_sha256,
        started_at=exact.started_at,
        lease_expires_at=exact.lease_expires_at,
        channel_capability=exact.channel_capability,
        idempotency_key=exact.idempotency_key,
        disposition=AlertDispatchDisposition.UNKNOWN_DELIVERY,
        continuation=AlertDispatchContinuation.RETRY_ALLOWED,
        failure_code=AlertDispatchFailureCode.CHANNEL_EXCEPTION,
    )
    assert retry_safe.continuation == AlertDispatchContinuation.RETRY_ALLOWED

    non_idempotent = exact.model_copy(
        update={"channel_capability": _channel_capability(AlertChannelIdempotencyGuarantee.NONE)}
    )
    attention = AlertDispatchReceipt(
        attempt_id=non_idempotent.attempt_id,
        outbox_id=non_idempotent.outbox_id,
        alert_id=non_idempotent.alert_id,
        case_id=non_idempotent.case_id,
        attempt_number=non_idempotent.attempt_number,
        fence=non_idempotent.fence,
        lease_owner_sha256=non_idempotent.lease_owner_sha256,
        started_at=non_idempotent.started_at,
        lease_expires_at=non_idempotent.lease_expires_at,
        channel_capability=non_idempotent.channel_capability,
        idempotency_key=non_idempotent.idempotency_key,
        disposition=AlertDispatchDisposition.UNKNOWN_DELIVERY,
        continuation=AlertDispatchContinuation.ATTENTION_REQUIRED,
        failure_code=AlertDispatchFailureCode.LEASE_EXPIRED,
    )
    assert attention.continuation == AlertDispatchContinuation.ATTENTION_REQUIRED

    payload = attention.model_dump(mode="json")
    payload.pop("receipt_id")
    payload["continuation"] = AlertDispatchContinuation.RETRY_ALLOWED.value
    with pytest.raises(ValidationError, match="continuation"):
        AlertDispatchReceipt.model_validate(payload)


def test_third_dispatch_attempt_cannot_authorize_another_retry() -> None:
    request = _request()
    decision = _decision(request)
    outbox = _outbox(request, decision)
    attempt = AlertDispatchAttempt(
        outbox_id=outbox.outbox_id,
        alert_id=decision.alert_id,
        case_id=request.case_id,
        attempt_number=3,
        fence=3,
        lease_owner_sha256=SHA_D,
        started_at=STARTED_AT,
        lease_expires_at=STARTED_AT + timedelta(minutes=1),
        channel_capability=_channel_capability(),
        idempotency_key=decision.alert_id,
    )
    payload = {
        "attempt_id": attempt.attempt_id,
        "outbox_id": attempt.outbox_id,
        "alert_id": attempt.alert_id,
        "case_id": attempt.case_id,
        "attempt_number": attempt.attempt_number,
        "fence": attempt.fence,
        "lease_owner_sha256": attempt.lease_owner_sha256,
        "started_at": attempt.started_at,
        "lease_expires_at": attempt.lease_expires_at,
        "channel_capability": attempt.channel_capability,
        "idempotency_key": attempt.idempotency_key,
        "disposition": AlertDispatchDisposition.RETRYABLE_FAILURE,
        "continuation": AlertDispatchContinuation.RETRY_ALLOWED,
        "failure_code": AlertDispatchFailureCode.CHANNEL_REJECTED,
    }
    with pytest.raises(ValidationError, match="continuation"):
        AlertDispatchReceipt.model_validate(payload)


def test_frozen_m0_m4_alert_decision_wire_shape_is_unchanged() -> None:
    assert set(AlertDecision.model_fields) == {
        "alert_id",
        "case_id",
        "level",
        "recipients",
        "policy_rule_ids",
        "suppressed_by_cooldown",
        "merged_into_alert_id",
        "human_review_required",
        "rescinded",
    }
