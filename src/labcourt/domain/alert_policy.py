"""Pure deterministic M5 policy for adjudicated Case alerts."""

from __future__ import annotations

from typing import NoReturn

from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertOutboxItem,
    AlertOutboxPriority,
    AlertPolicyAuthority,
    AlertPolicyDisposition,
    AlertPolicyFailureCode,
    AlertPolicyRequest,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import AlertLevel, CaseStatus, RiskLevel, VerdictDecision
from labcourt.contracts.manifests import RunManifest, StreamManifest
from labcourt.domain.canonical import sha256_hex
from labcourt.domain.timebase import seconds_to_frames

POLICY_BASE_RULE = "m5-alert-policy-v1"
REPEAT_DISABLED_RULE = "demo-cross-day-repeat-disabled-v1"
FRAME_COOLDOWN_RULE = "frame-track-cooldown-v1"
HARD_SIGNAL_MERGE_RULE = "prior-hard-signal-delivery-merge-v1"
INSUFFICIENT_RULE = "insufficient-evidence-advisory-v1"
CONFIDENCE_GATE_RULE = "confirmed-confidence-gate-v1"
NOT_ESTABLISHED_RULE = "not-established-close-no-alert-v1"
ESTABLISHED_RULE = "established-alert-v1"
EMERGENCY_CAP_RULE = "emergency-requires-hard-high-risk-v1"

_RECIPIENTS = {
    AlertLevel.ADVISORY: ("zone-safety-review",),
    AlertLevel.CONFIRMED: ("safety-officer", "zone-safety-review"),
    AlertLevel.EMERGENCY: (
        "emergency-response",
        "safety-officer",
        "zone-safety-review",
    ),
}
_PRIORITIES = {
    AlertLevel.ADVISORY: AlertOutboxPriority.NORMAL,
    AlertLevel.CONFIRMED: AlertOutboxPriority.HIGH,
    AlertLevel.EMERGENCY: AlertOutboxPriority.CRITICAL,
}


class AlertPolicyError(RuntimeError):
    """Controlled failure before a close-and-enqueue intent exists."""

    def __init__(self, reason_code: AlertPolicyFailureCode) -> None:
        if not isinstance(reason_code, AlertPolicyFailureCode):
            raise TypeError("reason_code must be an AlertPolicyFailureCode")
        self.reason_code = reason_code
        super().__init__(f"alert policy failed: {reason_code.value}")


def _fail(reason_code: AlertPolicyFailureCode) -> NoReturn:
    raise AlertPolicyError(reason_code)


def _stream_for(case: Case, manifest: RunManifest) -> StreamManifest:
    matches = tuple(
        stream
        for stream in manifest.streams
        if (stream.camera_id, stream.stream_id) == (case.event.camera_id, case.event.stream_id)
    )
    if len(matches) != 1:
        _fail(AlertPolicyFailureCode.STREAM_AUTHORITY_MISMATCH)
    return matches[0]


def _request_from_authority(
    case: Case,
    config: AppConfig,
    manifest: RunManifest,
    *,
    prior_cooldown: AlertCooldownAuthority | None,
    prior_emergency_delivery: ImmediateSafetyDeliveryAuthority | None,
) -> AlertPolicyRequest:
    if case.status != CaseStatus.READY_FOR_ALERT_POLICY:
        _fail(AlertPolicyFailureCode.INVALID_CASE_STATE)
    if not case.verdicts or not case.procedural_reviews:
        _fail(AlertPolicyFailureCode.REVIEW_AUTHORITY_MISMATCH)
    verdict = case.verdicts[-1]
    review = case.procedural_reviews[-1]
    if (
        not review.passed
        or review.reviewed_verdict_id != verdict.verdict_id
        or review.reviewed_verdict_version != verdict.version
        or review.reviewed_verdict_sha256 != verdict.verdict_sha256
        or verdict.violation_type != case.event.violation_type
    ):
        _fail(AlertPolicyFailureCode.REVIEW_AUTHORITY_MISMATCH)
    if manifest.manifest_id != case.manifest_id:
        _fail(AlertPolicyFailureCode.MANIFEST_AUTHORITY_MISMATCH)
    if manifest.config_sha256 != config.config_sha256:
        _fail(AlertPolicyFailureCode.CONFIG_AUTHORITY_MISMATCH)
    if case.event.rule_version != config.rule_version:
        _fail(AlertPolicyFailureCode.CONFIG_AUTHORITY_MISMATCH)

    zones = tuple(zone for zone in config.zones if zone.zone_id == case.event.zone_id)
    if len(zones) != 1 or zones[0].camera_id != case.event.camera_id:
        _fail(AlertPolicyFailureCode.ZONE_AUTHORITY_MISMATCH)
    stream = _stream_for(case, manifest)
    observation_sha256 = (
        sha256_hex(
            [
                "alert-observation-sufficiency",
                1,
                verdict.observation_sufficiency.model_dump(mode="json"),
            ]
        )
        if verdict.observation_sufficiency is not None
        else None
    )
    return AlertPolicyRequest(
        run_id=case.run_id,
        case_id=case.case_id,
        case_authority_sha256=sha256_hex(["alert-case-authority", 1, case.model_dump(mode="json")]),
        source_case_status=case.status,
        config_sha256=config.config_sha256,
        manifest_id=manifest.manifest_id,
        camera_id=case.event.camera_id,
        stream_id=case.event.stream_id,
        stream_authority_sha256=sha256_hex(
            ["alert-stream-authority", 1, stream.model_dump(mode="json")]
        ),
        fps_num=stream.fps_num,
        fps_den=stream.fps_den,
        zone_id=case.event.zone_id,
        zone_risk=zones[0].risk_level,
        violation_type=case.event.violation_type,
        primary_track_ref=case.event.primary_track_ref,
        trigger_frame=case.event.trigger_frame,
        hard_rule=case.event.hard_rule,
        verdict_id=verdict.verdict_id,
        verdict_version=verdict.version,
        verdict_sha256=verdict.verdict_sha256,
        verdict_decision=verdict.decision,
        verdict_confidence=verdict.confidence,
        recommended_alert_level=verdict.recommended_alert_level,
        procedural_review_id=review.review_id,
        procedural_review_version=review.version,
        procedural_review_passed=review.passed,
        observation_sufficiency_sha256=observation_sha256,
        cooldown_seconds=config.alerts.cooldown_seconds,
        cooldown_frames=seconds_to_frames(
            config.alerts.cooldown_seconds,
            stream.fps_num,
            stream.fps_den,
        ),
        confirmed_min_confidence=config.alerts.confirmed_min_confidence,
        insufficient_evidence_max_level=config.alerts.insufficient_evidence_max_level,
        prior_cooldown=prior_cooldown,
        prior_emergency_delivery=prior_emergency_delivery,
    )


def _level_and_rules(request: AlertPolicyRequest) -> tuple[AlertLevel, bool, set[str]]:
    rules = {
        POLICY_BASE_RULE,
        REPEAT_DISABLED_RULE,
        f"zone-risk-{request.zone_risk.value.lower()}-v1",
    }
    if request.verdict_decision == VerdictDecision.INSUFFICIENT_EVIDENCE:
        rules.add(INSUFFICIENT_RULE)
        return AlertLevel.ADVISORY, True, rules
    rules.add(ESTABLISHED_RULE)
    level = request.recommended_alert_level
    human_review_required = False
    if (
        level in {AlertLevel.CONFIRMED, AlertLevel.EMERGENCY}
        and request.verdict_confidence < request.confirmed_min_confidence
    ):
        rules.add(CONFIDENCE_GATE_RULE)
        return AlertLevel.ADVISORY, True, rules
    if level == AlertLevel.EMERGENCY and (
        not request.hard_rule or request.zone_risk != RiskLevel.HIGH
    ):
        rules.add(EMERGENCY_CAP_RULE)
        level = AlertLevel.CONFIRMED
    return level, human_review_required, rules


def evaluate_alert_policy(request: AlertPolicyRequest) -> AlertPolicyAuthority:
    """Evaluate an already reconstructed immutable L5 authority request."""

    if not isinstance(request, AlertPolicyRequest):
        _fail(AlertPolicyFailureCode.INVALID_ARGUMENT)
    if request.verdict_decision == VerdictDecision.NOT_ESTABLISHED:
        no_alert_rules = tuple(
            sorted(
                {
                    POLICY_BASE_RULE,
                    REPEAT_DISABLED_RULE,
                    NOT_ESTABLISHED_RULE,
                    f"zone-risk-{request.zone_risk.value.lower()}-v1",
                }
            )
        )
        return AlertPolicyAuthority(
            request=request,
            disposition=AlertPolicyDisposition.CLOSE_NO_ALERT,
            policy_rule_ids=no_alert_rules,
            final_decision=request.verdict_decision,
        )
    level, human_review_required, rules = _level_and_rules(request)
    expected_key = (
        AlertCooldownKey(
            zone_id=request.zone_id,
            violation_type=request.violation_type,
            track_ref=request.primary_track_ref,
        )
        if request.primary_track_ref is not None
        else None
    )

    merged_into: str | None = None
    if request.prior_emergency_delivery is not None:
        merged_into = request.prior_emergency_delivery.incident.incident_id
        rules.add(HARD_SIGNAL_MERGE_RULE)
    elif expected_key is not None and request.prior_cooldown is not None:
        prior = request.prior_cooldown
        if prior.key == expected_key:
            if prior.stream_id != request.stream_id:
                _fail(AlertPolicyFailureCode.STREAM_AUTHORITY_MISMATCH)
            if request.trigger_frame < prior.source_trigger_frame:
                _fail(AlertPolicyFailureCode.COOLDOWN_FRAME_REGRESSION)
            if request.trigger_frame < prior.cooldown_until_frame_exclusive:
                merged_into = prior.source_alert_id
                rules.add(FRAME_COOLDOWN_RULE)

    suppressed = merged_into is not None
    decision = AlertDecision(
        alert_id=request.expected_alert_id,
        case_id=request.case_id,
        level=level,
        recipients=_RECIPIENTS[level],
        policy_rule_ids=tuple(sorted(rules)),
        suppressed_by_cooldown=suppressed,
        merged_into_alert_id=merged_into,
        human_review_required=human_review_required,
    )
    if suppressed:
        return AlertPolicyAuthority(
            request=request,
            disposition=AlertPolicyDisposition.SUPPRESSED_MERGED,
            policy_rule_ids=decision.policy_rule_ids,
            decision=decision,
            final_decision=request.verdict_decision,
        )

    cooldown_write = (
        AlertCooldownAuthority(
            key=expected_key,
            stream_id=request.stream_id,
            source_alert_id=decision.alert_id,
            source_trigger_frame=request.trigger_frame,
            cooldown_frames=request.cooldown_frames,
            cooldown_until_frame_exclusive=(request.trigger_frame + request.cooldown_frames),
        )
        if expected_key is not None
        else None
    )
    outbox = AlertOutboxItem(
        run_id=request.run_id,
        case_id=request.case_id,
        case_authority_sha256=request.case_authority_sha256,
        policy_request_id=request.request_id,
        manifest_id=request.manifest_id,
        alert=decision,
        priority=_PRIORITIES[level],
        idempotency_key=decision.alert_id,
    )
    return AlertPolicyAuthority(
        request=request,
        disposition=AlertPolicyDisposition.ENQUEUE,
        policy_rule_ids=decision.policy_rule_ids,
        decision=decision,
        cooldown_write=cooldown_write,
        outbox_item=outbox,
        final_decision=request.verdict_decision,
    )


def plan_case_alert(
    case: Case,
    config: AppConfig,
    manifest: RunManifest,
    *,
    prior_cooldown: AlertCooldownAuthority | None = None,
    prior_emergency_delivery: ImmediateSafetyDeliveryAuthority | None = None,
) -> AlertPolicyAuthority:
    """Verify current Case/L5/config roots, then return a pure atomic commit intent."""

    if (
        not isinstance(case, Case)
        or not isinstance(config, AppConfig)
        or not isinstance(manifest, RunManifest)
    ):
        _fail(AlertPolicyFailureCode.INVALID_ARGUMENT)
    if prior_cooldown is not None and not isinstance(prior_cooldown, AlertCooldownAuthority):
        _fail(AlertPolicyFailureCode.INVALID_ARGUMENT)
    if prior_emergency_delivery is not None and not isinstance(
        prior_emergency_delivery, ImmediateSafetyDeliveryAuthority
    ):
        _fail(AlertPolicyFailureCode.INVALID_ARGUMENT)
    try:
        request = _request_from_authority(
            case,
            config,
            manifest,
            prior_cooldown=prior_cooldown,
            prior_emergency_delivery=prior_emergency_delivery,
        )
    except ValueError:
        reason = (
            AlertPolicyFailureCode.EMERGENCY_DELIVERY_AUTHORITY_MISMATCH
            if prior_emergency_delivery is not None
            else AlertPolicyFailureCode.INVALID_ARGUMENT
        )
        raise AlertPolicyError(reason) from None
    return evaluate_alert_policy(request)


__all__ = [
    "CONFIDENCE_GATE_RULE",
    "FRAME_COOLDOWN_RULE",
    "HARD_SIGNAL_MERGE_RULE",
    "INSUFFICIENT_RULE",
    "REPEAT_DISABLED_RULE",
    "AlertPolicyError",
    "evaluate_alert_policy",
    "plan_case_alert",
]
