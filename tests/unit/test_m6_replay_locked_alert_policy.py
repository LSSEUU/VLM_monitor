from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_replay_locked_alert_policy import (
    M6ReplayLockedAlertPolicyError,
    M6ReplayLockedAlertPolicyErrorCode,
    build_m6_replay_locked_closed_policy_candidate,
)
from labcourt.config_loader import load_config
from labcourt.contracts.alert_policy import AlertCooldownAuthority
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import M6ReplayLockedExecutionRoute
from labcourt.contracts.m6_replay_locked_policy import (
    M6ReplayLockedAlertPolicyCausalCutAuthority,
)
from tests.contract.test_m6_replay_locked_alert_policy_contracts import _cut
from tests.unit.test_m5_alert_policy import ROOT, _manifest_with_stream


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _source_binding(
    cut: M6ReplayLockedAlertPolicyCausalCutAuthority,
) -> M6ReplayLockedClosedPolicySourceBindingAuthority:
    document = canonical_json(cut.model_dump(mode="json"))
    return M6ReplayLockedClosedPolicySourceBindingAuthority(
        source_catalog_entry_id=_sha("catalog-entry"),
        sample_id=cut.sample_id,
        execution_entry_id=_sha("execution-entry"),
        replay_input_closure_authority_id=(cut.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(cut.replay_input_closure_document_sha256),
        pre_policy_route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
        source_config_sha256=cut.source_config_sha256,
        policy_causal_cut_authority_id=cut.policy_causal_cut_authority_id,
        policy_causal_cut_content_sha256=hashlib.sha256(document.encode("utf-8")).hexdigest(),
        policy_causal_cut_size_bytes=len(document.encode("utf-8")),
        cooldown_causal_head=cut.cooldown_causal_head,
    )


def test_policy_continuation_rebuilds_exact_closed_candidate_offline() -> None:
    cut = _cut()
    config = load_config(ROOT / "configs/demo.yaml")
    manifest = _manifest_with_stream()

    result = build_m6_replay_locked_closed_policy_candidate(
        ready_case=cut.source_ready_case,
        source_binding=_source_binding(cut),
        locked_config=config,
        locked_manifest=manifest,
    )

    assert result.ready_case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert result.closed_case == cut.source_closed_case
    assert result.alert_policy == cut.source_alert_policy
    assert result.source_binding_authority_id == _source_binding(cut).source_binding_authority_id
    assert result.policy_causal_cut_authority_id == cut.policy_causal_cut_authority_id
    assert canonical_json(result.closed_case.model_dump(mode="json")) == (
        result.canonical_closed_case_document
    )


def test_policy_continuation_rejects_a_non_ready_case() -> None:
    cut = _cut()

    with pytest.raises(M6ReplayLockedAlertPolicyError) as captured:
        build_m6_replay_locked_closed_policy_candidate(
            ready_case=cut.source_closed_case,
            source_binding=_source_binding(cut),
            locked_config=load_config(ROOT / "configs/demo.yaml"),
            locked_manifest=_manifest_with_stream(),
        )

    assert captured.value.code == M6ReplayLockedAlertPolicyErrorCode.PRE_POLICY_CASE_REJECTED
    assert not hasattr(captured.value, "ready_case")


def test_policy_continuation_consumes_the_exact_prior_cooldown() -> None:
    base = _cut()
    key = base.cooldown_causal_head.key
    assert key is not None
    prior = AlertCooldownAuthority(
        key=key,
        stream_id=base.source_alert_policy.request.stream_id,
        source_alert_id="a" * 64,
        source_trigger_frame=0,
        cooldown_frames=10_000,
        cooldown_until_frame_exclusive=10_000,
    )
    cut = _cut(prior_cooldown=prior, prior_cooldown_revision=1)

    result = build_m6_replay_locked_closed_policy_candidate(
        ready_case=cut.source_ready_case,
        source_binding=_source_binding(cut),
        locked_config=load_config(ROOT / "configs/demo.yaml"),
        locked_manifest=_manifest_with_stream(),
    )

    assert result.alert_policy.request.prior_cooldown == prior
    assert result.alert_policy == cut.source_alert_policy
    assert result.closed_case == cut.source_closed_case


def test_policy_continuation_rejects_a_config_outside_the_causal_cut() -> None:
    cut = _cut()
    config = load_config(ROOT / "configs/demo.yaml")
    foreign_config = config.model_copy(
        update={
            "alerts": config.alerts.model_copy(
                update={"cooldown_seconds": config.alerts.cooldown_seconds + 1.0}
            )
        }
    )

    with pytest.raises(M6ReplayLockedAlertPolicyError) as captured:
        build_m6_replay_locked_closed_policy_candidate(
            ready_case=cut.source_ready_case,
            source_binding=_source_binding(cut),
            locked_config=foreign_config,
            locked_manifest=_manifest_with_stream(),
        )

    assert captured.value.code == M6ReplayLockedAlertPolicyErrorCode.SOURCE_BINDING_MISMATCH
