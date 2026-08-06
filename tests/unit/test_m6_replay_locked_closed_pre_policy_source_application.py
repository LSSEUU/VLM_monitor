from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPrePolicySourceError,
    M6ReplayLockedClosedPrePolicySourceErrorCode,
    build_m6_replay_locked_closed_policy_pre_policy_source,
)
from labcourt.application.m6_replay_locked_policy_source import (
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertOutboxItem,
    AlertPolicyAuthority,
    AlertPolicyRequest,
)
from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.domain.m6_semantic_projection import M6VerifiedProjectionContext
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
)
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
)
from tests.unit.test_m6_replay_locked_candidate_observation import _runtime
from tests.unit.test_m6_replay_locked_policy_source import (
    _closed_case,
    _closing_audit,
    _document,
    _observation,
    _sha,
)


def _policy_for_ready(ready):  # type: ignore[no-untyped-def]
    template = _observation().source_alert_policy
    verdict = ready.verdicts[-1]
    review = ready.procedural_reviews[-1]
    request = AlertPolicyRequest.model_validate(
        template.request.model_copy(
            update={
                "run_id": ready.run_id,
                "case_id": ready.case_id,
                "case_authority_sha256": sha256_hex(
                    ["alert-case-authority", 1, ready.model_dump(mode="json")]
                ),
                "manifest_id": ready.manifest_id,
                "camera_id": ready.event.camera_id,
                "stream_id": ready.event.stream_id,
                "zone_id": ready.event.zone_id,
                "violation_type": ready.event.violation_type,
                "primary_track_ref": ready.event.primary_track_ref,
                "trigger_frame": ready.event.trigger_frame,
                "hard_rule": ready.event.hard_rule,
                "verdict_id": verdict.verdict_id,
                "verdict_version": verdict.version,
                "verdict_sha256": verdict.verdict_sha256,
                "verdict_decision": verdict.decision,
                "verdict_confidence": verdict.confidence,
                "recommended_alert_level": verdict.recommended_alert_level,
                "procedural_review_id": review.review_id,
                "procedural_review_version": review.version,
                "procedural_review_passed": True,
                "observation_sufficiency_sha256": None,
                "prior_cooldown": None,
                "prior_emergency_delivery": None,
            }
        ).model_dump(mode="json", exclude_computed_fields=True)
    )
    assert template.decision is not None
    assert template.outbox_item is not None
    assert request.primary_track_ref is not None
    decision = AlertDecision(
        alert_id=request.expected_alert_id,
        case_id=ready.case_id,
        level=request.recommended_alert_level,
        recipients=template.decision.recipients,
        policy_rule_ids=template.policy_rule_ids,
    )
    cooldown = AlertCooldownAuthority(
        key=AlertCooldownKey(
            zone_id=request.zone_id,
            violation_type=request.violation_type,
            track_ref=request.primary_track_ref,
        ),
        stream_id=request.stream_id,
        source_alert_id=decision.alert_id,
        source_trigger_frame=request.trigger_frame,
        cooldown_frames=request.cooldown_frames,
        cooldown_until_frame_exclusive=(request.trigger_frame + request.cooldown_frames),
    )
    outbox = AlertOutboxItem(
        run_id=request.run_id,
        case_id=request.case_id,
        case_authority_sha256=request.case_authority_sha256,
        policy_request_id=request.request_id,
        manifest_id=request.manifest_id,
        alert=decision,
        priority=template.outbox_item.priority,
        idempotency_key=decision.alert_id,
    )
    return AlertPolicyAuthority(
        request=request,
        disposition=template.disposition,
        policy_rule_ids=template.policy_rule_ids,
        decision=decision,
        cooldown_write=cooldown,
        outbox_item=outbox,
        final_decision=request.verdict_decision,
    )


def _facts():  # type: ignore[no-untyped-def]
    source = _runtime().source
    ready = source.projection_context.case
    policy = _policy_for_ready(ready)
    closed = _closed_case(ready, policy)
    ready_revision = source.closure.source_case_revision
    assert ready_revision is not None
    report = M5ArtifactValidationReport(
        run_id=ready.run_id,
        manifest_id=ready.manifest_id,
        config_sha256=policy.request.config_sha256,
        authority_root_sha256=_sha("closed-pre-policy-m5-root"),
    )
    report_document = _document(report)
    closed_document = _document(closed)
    closure = M6ReplayInputClosureAuthority.model_validate(
        source.closure.model_copy(
            update={
                "source_case_revision": ready_revision + 1,
                "source_case_document_sha256": hashlib.sha256(
                    closed_document.encode("utf-8")
                ).hexdigest(),
                "source_validation_report_id": report.report_id,
                "source_validation_report_document_sha256": hashlib.sha256(
                    report_document.encode("utf-8")
                ).hexdigest(),
            }
        ).model_dump(mode="json", exclude_computed_fields=True)
    )
    audit = _closing_audit(
        ready,
        closed,
        policy,
        sequence=ready_revision + 1,
    )
    observation = M6ReplayLockedAlertPolicySourceObservation(
        source_identity_sha256=source.source_identity_sha256,
        replay_input_closure=closure,
        replay_input_closure_canonical_document=_document(closure),
        source_validation_report=report,
        source_validation_report_canonical_document=report_document,
        source_m5_authority_root_sha256=report.authority_root_sha256,
        source_ready_case_revision=ready_revision,
        source_ready_case=ready,
        source_ready_case_canonical_document=_document(ready),
        source_closed_case_revision=ready_revision + 1,
        source_closed_case=closed,
        source_closed_case_canonical_document=closed_document,
        source_alert_policy=policy,
        source_alert_policy_canonical_document=_document(policy),
        closing_audit_entry=audit,
        closing_audit_entry_canonical_document=_document(audit),
        cooldown_eligible_history_rows=(),
    )
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)
    cut_document = canonical_json(cut.model_dump(mode="json"))
    cut_payload = cut_document.encode("utf-8")
    binding = M6ReplayLockedClosedPolicySourceBindingAuthority(
        source_catalog_entry_id=_sha("closed-pre-policy-catalog-entry"),
        sample_id=closure.sample_id,
        execution_entry_id=_sha("closed-pre-policy-execution-entry"),
        replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
        pre_policy_route=_runtime().pending.route,
        source_config_sha256=cut.source_config_sha256,
        policy_causal_cut_authority_id=cut.policy_causal_cut_authority_id,
        policy_causal_cut_content_sha256=hashlib.sha256(cut_payload).hexdigest(),
        policy_causal_cut_size_bytes=len(cut_payload),
        cooldown_causal_head=cut.cooldown_causal_head,
        emergency_causal_basis=cut.emergency_causal_basis,
    )
    context = source.projection_context
    closed_context = M6VerifiedProjectionContext(
        case=closed,
        perception=context.perception,
        historical_source_run_id=context.historical_source_run_id,
        historical_source_case_id=context.historical_source_case_id,
        historical_source_manifest_id=context.historical_source_manifest_id,
        model_reference_authority=context.model_reference_authority,
        procedural_gate_authority=context.procedural_gate_authority,
        model_responses=context.model_responses,
        retrieval_cycles=context.retrieval_cycles,
        acquisitions=context.acquisitions,
    )
    return source, closure, cut, binding, closed_context


def _rebind_to_catalog_closure(
    closure: M6ReplayInputClosureAuthority,
    cut: object,
    binding: M6ReplayLockedClosedPolicySourceBindingAuthority,
):  # type: ignore[no-untyped-def]
    cut_payload = cut.model_dump(  # type: ignore[attr-defined]
        mode="json",
        exclude_computed_fields=True,
    )
    cut_payload.update(
        {
            "replay_input_closure_authority_id": (closure.replay_input_closure_authority_id),
            "replay_input_closure_document_sha256": (closure.replay_input_closure_document_sha256),
        }
    )
    rebound_cut = type(cut).model_validate(cut_payload)
    cut_document = canonical_json(rebound_cut.model_dump(mode="json"))
    cut_payload_bytes = cut_document.encode("utf-8")
    binding_payload = binding.model_dump(mode="json", exclude_computed_fields=True)
    binding_payload.update(
        {
            "replay_input_closure_authority_id": (closure.replay_input_closure_authority_id),
            "replay_input_closure_document_sha256": (closure.replay_input_closure_document_sha256),
            "policy_causal_cut_authority_id": rebound_cut.policy_causal_cut_authority_id,
            "policy_causal_cut_content_sha256": hashlib.sha256(cut_payload_bytes).hexdigest(),
            "policy_causal_cut_size_bytes": len(cut_payload_bytes),
        }
    )
    rebound_binding = M6ReplayLockedClosedPolicySourceBindingAuthority.model_validate(
        binding_payload
    )
    return rebound_cut, rebound_binding


def test_builder_proves_the_closed_cut_then_returns_only_ready_facts() -> None:
    source, closure, cut, binding, closed_context = _facts()

    observed = build_m6_replay_locked_closed_policy_pre_policy_source(
        source_binding=binding,
        policy_causal_cut=cut,
        catalog_closure=closure,
        closed_projection_context=closed_context,
    )

    assert type(observed) is M6ReplayLockedClosedPolicyFastPrePolicySource
    assert observed.projection_context.case == source.projection_context.case
    assert observed.source_snapshot.case_status == source.source_snapshot.case_status
    assert not hasattr(observed, "source_alert_policy")
    assert not hasattr(observed, "source_closed_case")
    assert not hasattr(observed, "policy_causal_cut")


def test_builder_rejects_a_context_that_did_not_project_the_committed_close() -> None:
    source, closure, cut, binding, _closed_context = _facts()

    with pytest.raises(M6ReplayLockedClosedPrePolicySourceError) as raised:
        build_m6_replay_locked_closed_policy_pre_policy_source(
            source_binding=binding,
            policy_causal_cut=cut,
            catalog_closure=closure,
            closed_projection_context=source.projection_context,
        )

    assert raised.value.code == (
        M6ReplayLockedClosedPrePolicySourceErrorCode.CLOSED_PROJECTION_MISMATCH
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_case_revision", 3),
        ("source_case_document_sha256", _sha("foreign-closed-case-document")),
        ("source_validation_report_id", _sha("foreign-validation-report")),
        (
            "source_validation_report_document_sha256",
            _sha("foreign-validation-report-document"),
        ),
    ),
)
def test_builder_rejects_canonical_catalog_terminal_identity_outside_the_cut(
    field: str,
    value: object,
) -> None:
    _, closure, cut, binding, closed_context = _facts()
    foreign_closure = M6ReplayInputClosureAuthority.model_validate(
        {
            **closure.model_dump(mode="json", exclude_computed_fields=True),
            field: value,
        }
    )
    rebound_cut, rebound_binding = _rebind_to_catalog_closure(
        foreign_closure,
        cut,
        binding,
    )

    with pytest.raises(M6ReplayLockedClosedPrePolicySourceError) as raised:
        build_m6_replay_locked_closed_policy_pre_policy_source(
            source_binding=rebound_binding,
            policy_causal_cut=rebound_cut,
            catalog_closure=foreign_closure,
            closed_projection_context=closed_context,
        )

    assert raised.value.code == (M6ReplayLockedClosedPrePolicySourceErrorCode.CAUSAL_CUT_MISMATCH)
