from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from pydantic import BaseModel

import labcourt.application.m6_replay_locked_policy_source as subject
from labcourt.config_loader import load_config
from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertCooldownKey,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationArea,
    M5ArtifactValidationIssue,
    M5ArtifactValidationIssueCode,
    M5ArtifactValidationReport,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedFrameInput,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.m6_replay_locked_policy import (
    MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES,
    M6ReplayLockedCooldownCausalBasis,
)
from labcourt.domain.alert_policy import plan_case_alert
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
    M6ReplayLockedCooldownHistoryRowObservation,
)
from tests.contract.test_m6_replay_locked_alert_policy_contracts import (
    _closed_case,
    _closing_audit,
)
from tests.unit.test_m5_alert_policy import ROOT, _manifest_with_stream, _ready_case


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document(value: BaseModel) -> str:
    document: str = canonical_json(value.model_dump(mode="json"))
    return document


def _cooldown(
    key: AlertCooldownKey,
    stream_id: str,
    revision: int,
) -> AlertCooldownAuthority:
    return AlertCooldownAuthority(
        key=key,
        stream_id=stream_id,
        source_alert_id=_sha(f"history-alert-{revision}"),
        source_trigger_frame=revision - 1,
        cooldown_frames=1,
        cooldown_until_frame_exclusive=revision,
    )


def _observation(
    *,
    history_count: int = 0,
) -> M6ReplayLockedAlertPolicySourceObservation:
    manifest = _manifest_with_stream()
    config = load_config(ROOT / "configs/demo.yaml")
    ready = _ready_case(manifest)
    assert ready.event.primary_track_ref is not None
    key = AlertCooldownKey(
        zone_id=ready.event.zone_id,
        violation_type=ready.event.violation_type,
        track_ref=ready.event.primary_track_ref,
    )
    authorities = tuple(
        _cooldown(key, ready.event.stream_id, revision) for revision in range(1, history_count + 1)
    )
    prior = authorities[-1] if authorities else None
    policy = plan_case_alert(
        ready,
        config,
        manifest,
        prior_cooldown=prior,
    )
    closed = _closed_case(ready, policy)
    audit = _closing_audit(ready, closed, policy, sequence=7)
    root = _sha("passing-m5-authority-root")
    report = M5ArtifactValidationReport(
        run_id=ready.run_id,
        manifest_id=ready.manifest_id,
        config_sha256=config.config_sha256,
        authority_root_sha256=root,
    )
    report_document = _document(report)
    closed_document = _document(closed)
    closure = M6ReplayInputClosureAuthority(
        sample_id="policy-source-sample",
        source_run_id=closed.run_id,
        source_case_id=closed.case_id,
        source_case_revision=7,
        source_case_document_sha256=_sha(closed_document),
        source_manifest_id=closed.manifest_id,
        source_manifest_document_sha256=_sha("source-manifest-document"),
        input_authority_id=_sha("input-authority"),
        input_authority_document_sha256=_sha("input-authority-document"),
        source_validation_report_id=report.report_id,
        source_validation_report_document_sha256=_sha(report_document),
        frames=(
            M6LockedFrameInput(
                frame_id="camera-main:stream-main:100",
                document_sha256=_sha("frame-document"),
                content_sha256=_sha("frame-content"),
            ),
        ),
    )
    source_identity = _sha("immutable-policy-source-snapshot")
    history = tuple(
        M6ReplayLockedCooldownHistoryRowObservation(
            source_identity_sha256=source_identity,
            revision=revision,
            writer_close_audit_sequence=audit.sequence - history_count + revision - 1,
            writer_close_audit_entry_hash=_sha(f"writer-close-audit-{revision}"),
            writer_alert_policy_authority_id=_sha(f"writer-policy-{revision}"),
            authority=authority,
            authority_canonical_document=_document(authority),
        )
        for revision, authority in enumerate(authorities, start=1)
    )
    return M6ReplayLockedAlertPolicySourceObservation(
        source_identity_sha256=source_identity,
        replay_input_closure=closure,
        replay_input_closure_canonical_document=_document(closure),
        source_validation_report=report,
        source_validation_report_canonical_document=report_document,
        source_m5_authority_root_sha256=root,
        source_ready_case_revision=6,
        source_ready_case=ready,
        source_ready_case_canonical_document=_document(ready),
        source_closed_case_revision=7,
        source_closed_case=closed,
        source_closed_case_canonical_document=closed_document,
        source_alert_policy=policy,
        source_alert_policy_canonical_document=_document(policy),
        closing_audit_entry=audit,
        closing_audit_entry_canonical_document=_document(audit),
        cooldown_eligible_history_rows=history,
    )


def _assert_failure(
    code: subject.M6ReplayLockedPolicySourceBuildErrorCode,
    observation: object,
) -> subject.M6ReplayLockedPolicySourceBuildError:
    with pytest.raises(subject.M6ReplayLockedPolicySourceBuildError) as raised:
        subject.build_m6_replay_locked_alert_policy_causal_cut(
            observation=observation,
        )
    assert raised.value.code == code
    return raised.value


def test_builds_exact_policy_cut_from_one_passing_source_snapshot() -> None:
    observation = _observation()

    cut = subject.build_m6_replay_locked_alert_policy_causal_cut(
        observation=observation,
    )

    assert cut.source_identity_sha256 == observation.source_identity_sha256
    assert cut.sample_id == observation.replay_input_closure.sample_id
    assert cut.source_m5_authority_root_sha256 == (observation.source_m5_authority_root_sha256)
    assert cut.source_ready_case_revision == 6
    assert cut.source_closed_case_revision == 7
    assert cut.source_alert_policy == observation.source_alert_policy
    assert cut.closing_audit_entry == observation.closing_audit_entry
    assert cut.policy_causal_cut_authority_id


def test_tracked_policy_with_empty_history_seals_an_explicit_empty_head() -> None:
    cut = subject.build_m6_replay_locked_alert_policy_causal_cut(
        observation=_observation(),
    )

    head = cut.cooldown_causal_head
    assert head.basis == M6ReplayLockedCooldownCausalBasis.EMPTY_HISTORY
    assert head.key is not None
    assert head.prior_revision == 0
    assert head.prior_authority is None
    assert head.eligible_count == 0
    assert head.eligible_inventory_root_sha256 == sha256_hex(
        ["m6-replay-locked-cooldown-eligible-inventory", 1, []]
    )


def test_exact_prior_seals_every_contiguous_eligible_history_row() -> None:
    observation = _observation(history_count=2)

    cut = subject.build_m6_replay_locked_alert_policy_causal_cut(
        observation=observation,
    )

    head = cut.cooldown_causal_head
    assert head.basis == M6ReplayLockedCooldownCausalBasis.EXACT_PRIOR
    assert head.prior_revision == 2
    assert head.prior_authority == observation.cooldown_eligible_history_rows[-1].authority
    assert tuple(item.revision for item in head.eligible_history) == (1, 2)
    assert head.eligible_count == 2
    assert head.eligible_inventory_root_sha256 == sha256_hex(
        [
            "m6-replay-locked-cooldown-eligible-inventory",
            1,
            [item.history_entry_id for item in head.eligible_history],
        ]
    )


def test_rejects_any_noncanonical_or_tampered_source_document() -> None:
    observation = _observation()

    _assert_failure(
        subject.M6ReplayLockedPolicySourceBuildErrorCode.DOCUMENT_INVALID,
        replace(
            observation,
            source_closed_case_canonical_document=(
                observation.source_closed_case_canonical_document + " "
            ),
        ),
    )


def test_rejects_foreign_snapshot_rows_and_foreign_source_scope() -> None:
    observation = _observation(history_count=1)
    row = observation.cooldown_eligible_history_rows[0]
    foreign_row = replace(row, source_identity_sha256=_sha("foreign-snapshot"))
    _assert_failure(
        subject.M6ReplayLockedPolicySourceBuildErrorCode.SNAPSHOT_IDENTITY_MISMATCH,
        replace(observation, cooldown_eligible_history_rows=(foreign_row,)),
    )

    foreign_closure = observation.replay_input_closure.model_copy(
        update={"source_case_revision": 8}
    )
    _assert_failure(
        subject.M6ReplayLockedPolicySourceBuildErrorCode.SOURCE_SCOPE_MISMATCH,
        replace(
            observation,
            replay_input_closure=foreign_closure,
            replay_input_closure_canonical_document=_document(foreign_closure),
        ),
    )


def test_rejects_omitted_or_disordered_cooldown_history() -> None:
    observation = _observation(history_count=2)
    for row_order in ((1,), (0,), (1, 0)):
        rows = tuple(observation.cooldown_eligible_history_rows[index] for index in row_order)
        _assert_failure(
            subject.M6ReplayLockedPolicySourceBuildErrorCode.COOLDOWN_HISTORY_MISMATCH,
            replace(observation, cooldown_eligible_history_rows=rows),
        )


def test_rejects_a_non_passing_m5_report_before_scope_publication() -> None:
    observation = _observation()
    issue = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED,
        area=M5ArtifactValidationArea.BUDGET,
        reason_code="policy-source-budget-exceeded",
        limit=1,
        observed=2,
    )
    report = M5ArtifactValidationReport(
        run_id=observation.source_validation_report.run_id,
        manifest_id=observation.source_validation_report.manifest_id,
        config_sha256=observation.source_validation_report.config_sha256,
        authority_root_sha256=observation.source_m5_authority_root_sha256,
        issues=(issue,),
    )
    assert not report.passed

    _assert_failure(
        subject.M6ReplayLockedPolicySourceBuildErrorCode.SOURCE_VALIDATION_FAILED,
        replace(
            observation,
            source_validation_report=report,
            source_validation_report_canonical_document=_document(report),
        ),
    )


def test_enforces_the_shared_64_mib_input_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES == 64 * 1024 * 1024
    monkeypatch.setattr(subject, "MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES", 1)

    _assert_failure(
        subject.M6ReplayLockedPolicySourceBuildErrorCode.DOCUMENT_TOO_LARGE,
        _observation(),
    )


def test_public_failures_are_typed_and_carry_no_authority_payload() -> None:
    observation = _observation()
    secret = "SECRET C:\\people\\alice.json"
    error = _assert_failure(
        subject.M6ReplayLockedPolicySourceBuildErrorCode.DOCUMENT_INVALID,
        replace(observation, source_alert_policy_canonical_document=secret),
    )

    assert error.args == ("M6 locked policy source build failed: DOCUMENT_INVALID",)
    assert vars(error) == {"code": error.code}
    assert not hasattr(error, "payload")
    assert error.__cause__ is None
    assert error.__suppress_context__
    assert "SECRET" not in str(error)
    assert "alice.json" not in str(error)
