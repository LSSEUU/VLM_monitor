from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from labcourt.config_loader import load_config
from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertPolicyAuthority,
    AlertPolicyDisposition,
)
from labcourt.contracts.audit import AuditEntry, AuditEntryDraft
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
)
from labcourt.contracts.m6_replay_locked_policy import (
    M6ReplayLockedAlertPolicyCausalCutAuthority,
    M6ReplayLockedCooldownCausalBasis,
    M6ReplayLockedCooldownCausalHead,
    M6ReplayLockedCooldownHistoryEntry,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.alert_policy import plan_case_alert
from tests.unit.test_m5_alert_policy import ROOT, _manifest_with_stream, _ready_case


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_sha256(value: object) -> str:
    document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _closed_case(ready: Case, policy: AlertPolicyAuthority) -> Case:
    decision = policy.decision
    alert_id = decision.alert_id if decision is not None else "NONE"
    object_ref = ready.case_id if decision is None else decision.alert_id
    alerts = ready.alerts if decision is None else (*ready.alerts, decision)
    payload = ready.model_dump(mode="json", exclude_computed_fields=True)
    payload.update(
        {
            "status": CaseStatus.CLOSED.value,
            "alerts": [item.model_dump(mode="json") for item in alerts],
            "final_decision": policy.final_decision.value,
            "timeline": [
                *(item.model_dump(mode="json") for item in ready.timeline),
                TimelineEntry(
                    sequence=len(ready.timeline),
                    action=AuditAction.CASE_CLOSED.value,
                    stage="ALERT_POLICY",
                    object_ref=object_ref,
                    details={
                        "alert_id": alert_id,
                        "disposition": policy.disposition.value,
                        "status": CaseStatus.CLOSED.value,
                    },
                ).model_dump(mode="json"),
            ],
        }
    )
    return Case.model_validate(payload)


def _closing_audit(
    ready: Case,
    closed: Case,
    policy: AlertPolicyAuthority,
    *,
    sequence: int = 7,
) -> AuditEntry:
    object_ref = (
        ArtifactRef(kind=ArtifactKind.CASE, artifact_id=ready.case_id)
        if policy.decision is None
        else ArtifactRef(kind=ArtifactKind.ALERT, artifact_id=policy.decision.alert_id)
    )
    return AuditEntryDraft(
        run_id=ready.run_id,
        sequence=sequence,
        actor=AuditActorRole.SYSTEM.value,
        action=AuditAction.CASE_CLOSED,
        object_ref=object_ref,
        before_sha256=_document_sha256(ready),
        after_sha256=_document_sha256(closed),
        manifest_id=ready.manifest_id,
        recorded_at="2026-08-04T09:10:11.120000Z",
        prev_entry_hash=_sha("prior-audit-entry"),
    ).seal()


def _cut(
    *,
    prior_cooldown: AlertCooldownAuthority | None = None,
    prior_cooldown_revision: int = 0,
) -> M6ReplayLockedAlertPolicyCausalCutAuthority:
    manifest = _manifest_with_stream()
    config = load_config(ROOT / "configs/demo.yaml")
    ready = _ready_case(manifest)
    policy = plan_case_alert(
        ready,
        config,
        manifest,
        prior_cooldown=prior_cooldown,
    )
    closed = _closed_case(ready, policy)
    if ready.event.primary_track_ref is None:
        basis = M6ReplayLockedCooldownCausalBasis.UNTRACKED
        key = None
    else:
        basis = (
            M6ReplayLockedCooldownCausalBasis.EMPTY_HISTORY
            if prior_cooldown is None
            else M6ReplayLockedCooldownCausalBasis.EXACT_PRIOR
        )
        key = AlertCooldownKey(
            zone_id=ready.event.zone_id,
            violation_type=ready.event.violation_type,
            track_ref=ready.event.primary_track_ref,
        )
    audit = _closing_audit(ready, closed, policy)
    history = (
        ()
        if prior_cooldown is None
        else (
            M6ReplayLockedCooldownHistoryEntry(
                revision=prior_cooldown_revision,
                writer_close_audit_sequence=audit.sequence - 1,
                writer_close_audit_entry_hash=_sha("prior-close-audit"),
                writer_alert_policy_authority_id=_sha("prior-alert-policy"),
                authority=prior_cooldown,
            ),
        )
    )
    return M6ReplayLockedAlertPolicyCausalCutAuthority(
        source_identity_sha256=_sha("source-snapshot"),
        sample_id="closed-policy-sample",
        replay_input_closure_authority_id=_sha("closure-authority"),
        replay_input_closure_document_sha256=_sha("closure-document"),
        source_validation_report_id=_sha("m5-validation-report"),
        source_validation_report_document_sha256=_sha("m5-validation-report-document"),
        source_m5_authority_root_sha256=_sha("m5-authority-root"),
        source_config_sha256=config.config_sha256,
        source_ready_case_revision=6,
        source_ready_case=ready,
        source_closed_case_revision=7,
        source_closed_case=closed,
        source_alert_policy=policy,
        closing_audit_entry=audit,
        cooldown_causal_head=M6ReplayLockedCooldownCausalHead(
            source_run_id=ready.run_id,
            basis=basis,
            source_close_audit_sequence=audit.sequence,
            source_close_audit_entry_hash=audit.entry_hash,
            key=key,
            prior_revision=prior_cooldown_revision,
            prior_authority=prior_cooldown,
            eligible_history=history,
        ),
    )


def test_policy_cut_round_trips_and_rejects_derived_claim_tampering() -> None:
    cut = _cut()

    assert cut.source_ready_case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert cut.source_closed_case.status == CaseStatus.CLOSED
    assert cut.source_alert_policy.disposition == AlertPolicyDisposition.ENQUEUE
    assert cut.cooldown_causal_head.basis == (M6ReplayLockedCooldownCausalBasis.EMPTY_HISTORY)
    assert (
        M6ReplayLockedAlertPolicyCausalCutAuthority.model_validate(cut.model_dump(mode="json"))
        == cut
    )

    payload = cut.model_dump(mode="json")
    payload["policy_causal_cut_authority_id"] = "f" * 64
    with pytest.raises(ValidationError, match="policy_causal_cut_authority_id"):
        M6ReplayLockedAlertPolicyCausalCutAuthority.model_validate(payload)


def test_policy_cut_rejects_nonadjacent_or_rewritten_case_transition() -> None:
    cut = _cut()

    with pytest.raises(ValidationError, match="adjacent"):
        cut.model_copy(update={"source_closed_case_revision": 8})

    rewritten = cut.source_closed_case.model_copy(
        update={"usage": cut.source_closed_case.usage.model_copy(update={"retries": 1})}
    )
    with pytest.raises(ValidationError, match="exact alert-policy successor"):
        cut.model_copy(update={"source_closed_case": rewritten})


def test_policy_cut_rejects_foreign_policy_scope_or_closing_audit() -> None:
    cut = _cut()

    with pytest.raises(ValidationError, match="policy source scope"):
        cut.model_copy(update={"source_config_sha256": _sha("foreign-config")})

    foreign_audit = _closing_audit(
        cut.source_ready_case,
        cut.source_closed_case,
        cut.source_alert_policy,
        sequence=8,
    )
    with pytest.raises(ValidationError, match="closing audit"):
        cut.model_copy(update={"closing_audit_entry": foreign_audit})


def test_cooldown_head_distinguishes_untracked_empty_and_exact_prior() -> None:
    cut = _cut()
    key = cut.cooldown_causal_head.key
    assert key is not None

    prior = AlertCooldownAuthority(
        key=key,
        stream_id=cut.source_alert_policy.request.stream_id,
        source_alert_id=_sha("prior-alert"),
        source_trigger_frame=0,
        cooldown_frames=1,
        cooldown_until_frame_exclusive=1,
    )
    exact = _cut(prior_cooldown=prior, prior_cooldown_revision=1)
    assert exact.cooldown_causal_head.basis == M6ReplayLockedCooldownCausalBasis.EXACT_PRIOR
    assert exact.source_alert_policy.request.prior_cooldown == prior

    with pytest.raises(ValidationError, match="EXACT_PRIOR"):
        M6ReplayLockedCooldownCausalHead(
            source_run_id=cut.source_ready_case.run_id,
            basis=M6ReplayLockedCooldownCausalBasis.EXACT_PRIOR,
            source_close_audit_sequence=7,
            source_close_audit_entry_hash=_sha("close-audit"),
            key=key,
            prior_revision=0,
            prior_authority=None,
            eligible_history=(),
        )

    with pytest.raises(ValidationError, match="EMPTY_HISTORY"):
        M6ReplayLockedCooldownCausalHead(
            source_run_id=cut.source_ready_case.run_id,
            basis=M6ReplayLockedCooldownCausalBasis.EMPTY_HISTORY,
            source_close_audit_sequence=7,
            source_close_audit_entry_hash=_sha("close-audit"),
            key=key,
            prior_revision=1,
            prior_authority=prior,
            eligible_history=(
                M6ReplayLockedCooldownHistoryEntry(
                    revision=1,
                    writer_close_audit_sequence=6,
                    writer_close_audit_entry_hash=_sha("prior-close-audit"),
                    writer_alert_policy_authority_id=_sha("prior-alert-policy"),
                    authority=prior,
                ),
            ),
        )
