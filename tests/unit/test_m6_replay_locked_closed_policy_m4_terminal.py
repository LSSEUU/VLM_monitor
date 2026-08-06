from __future__ import annotations

import hashlib

import pytest

import tests.unit.test_m4_hearing_domain as hearing_fixture
from labcourt.application.m6_replay_locked_closed_policy_execution import (
    build_m6_replay_locked_closed_policy_execution_scope,
    build_m6_replay_locked_closed_policy_pending_commitment,
)
from labcourt.application.m6_replay_locked_closed_pre_policy_source import (
    build_m6_replay_locked_closed_policy_pre_policy_source,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    M6ReplayLockedM4TerminalError,
    M6ReplayLockedM4TerminalErrorCode,
    build_m6_replay_locked_closed_policy_m4_pre_policy_candidate,
)
from labcourt.application.m6_replay_locked_policy_source import (
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus, VerdictDecision
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
)
from labcourt.domain.m6_semantic_projection import M6VerifiedProjectionContext
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyM4PrePolicySource,
)
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
)
from tests.unit.test_m6_replay_locked_closed_pre_policy_source_application import (
    _policy_for_ready,
)
from tests.unit.test_m6_replay_locked_execution import _route_inputs
from tests.unit.test_m6_replay_locked_m4_terminal import _execution
from tests.unit.test_m6_replay_locked_policy_source import (
    _closed_case,
    _closing_audit,
    _document,
    _sha,
)


def _closed_execution(
    monkeypatch: pytest.MonkeyPatch,
):  # type: ignore[no-untyped-def]
    original_payloads = hearing_fixture._payloads

    def gate_passed_payloads(**values: object):  # type: ignore[no-untyped-def]
        values["decision"] = VerdictDecision.NOT_ESTABLISHED
        return original_payloads(**values)  # type: ignore[arg-type]

    monkeypatch.setattr(hearing_fixture, "_payloads", gate_passed_payloads)
    template_scope, _template_pending, terminal = _execution(monkeypatch)
    ready = terminal.projection_context.case
    assert ready.status is CaseStatus.READY_FOR_ALERT_POLICY
    assert ready.procedural_reviews[-1].passed is True
    policy = _policy_for_ready(ready)
    closed = _closed_case(ready, policy)
    report = M5ArtifactValidationReport(
        run_id=ready.run_id,
        manifest_id=ready.manifest_id,
        config_sha256=policy.request.config_sha256,
        authority_root_sha256=_sha("m4-closed-policy-m5-root"),
    )
    closed_document = _document(closed)
    report_document = _document(report)
    ready_revision = terminal.closure.source_case_revision
    assert ready_revision is not None
    closure = M6ReplayInputClosureAuthority.model_validate(
        terminal.closure.model_copy(
            update={
                "sample_id": _sha("m4-closed-policy-sample"),
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
    closing_audit = _closing_audit(
        ready,
        closed,
        policy,
        sequence=ready_revision + 1,
    )
    observation = M6ReplayLockedAlertPolicySourceObservation(
        source_identity_sha256=terminal.source_identity_sha256,
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
        closing_audit_entry=closing_audit,
        closing_audit_entry_canonical_document=_document(closing_audit),
        cooldown_eligible_history_rows=(),
    )
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)
    pre_policy_scope, stored = _route_inputs(closure, template_scope)
    component = M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2(
        version=pre_policy_scope.execution_component.version,
        code_commit=pre_policy_scope.execution_component.code_commit,
        pre_policy_component_authority_id=(
            pre_policy_scope.execution_component.component_authority_id
        ),
        supported_pre_policy_routes=(pre_policy_scope.execution_component.supported_routes),
    )
    scope = build_m6_replay_locked_closed_policy_execution_scope(
        pre_policy_execution_scope=pre_policy_scope,
        execution_component=component,
    )
    pending = build_m6_replay_locked_closed_policy_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=stored,
        policy_causal_cut=cut,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    ready_context = terminal.projection_context
    closed_context = M6VerifiedProjectionContext(
        case=closed,
        perception=ready_context.perception,
        historical_source_run_id=ready_context.historical_source_run_id,
        historical_source_case_id=ready_context.historical_source_case_id,
        historical_source_manifest_id=ready_context.historical_source_manifest_id,
        model_reference_authority=ready_context.model_reference_authority,
        procedural_gate_authority=ready_context.procedural_gate_authority,
        model_responses=ready_context.model_responses,
        retrieval_cycles=ready_context.retrieval_cycles,
        acquisitions=ready_context.acquisitions,
    )
    safe_source = build_m6_replay_locked_closed_policy_pre_policy_source(
        source_binding=pending.source_binding,
        policy_causal_cut=cut,
        catalog_closure=closure,
        closed_projection_context=closed_context,
        hearing_record=terminal.hearing_record,
        hearing_verdict_binding=terminal.hearing_verdict_binding,
        gate_current_closure_receipt=terminal.gate_current_closure_receipt,
    )
    assert type(safe_source) is M6ReplayLockedClosedPolicyM4PrePolicySource
    return scope, pending, safe_source


def test_v2_m4_builder_replays_ready_predecessor_without_rewriting_closed_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, safe_source = _closed_execution(monkeypatch)

    candidate = build_m6_replay_locked_closed_policy_m4_pre_policy_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=safe_source,
    )

    assert candidate.case.status is CaseStatus.READY_FOR_ALERT_POLICY
    assert candidate.case.run_id == scope.candidate_run_id
    assert candidate.candidate_snapshot.stage_roots == safe_source.source_snapshot.stage_roots
    assert candidate.candidate_snapshot.semantic_case_hash == (
        safe_source.source_snapshot.semantic_case_hash
    )
    assert safe_source.catalog_closure.source_case_revision == (
        safe_source.source_ready_case_revision + 1
    )
    assert (
        safe_source.catalog_closure.source_case_document_sha256
        != hashlib.sha256(
            canonical_json(safe_source.projection_context.case.model_dump(mode="json")).encode(
                "utf-8"
            )
        ).hexdigest()
    )


def test_v2_m4_builder_rejects_a_safe_source_from_another_pending_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, safe_source = _closed_execution(monkeypatch)
    foreign = object.__new__(M6ReplayLockedClosedPolicyM4PrePolicySource)
    for name in (
        "source_identity_sha256",
        "source_binding",
        "catalog_closure",
        "source_ready_case_revision",
        "projection_context",
        "hearing_record",
        "hearing_verdict_binding",
        "gate_current_closure_receipt",
        "source_snapshot",
    ):
        object.__setattr__(foreign, name, getattr(safe_source, name))
    object.__setattr__(
        foreign,
        "source_binding",
        safe_source.source_binding.model_copy(update={"source_catalog_entry_id": "f" * 64}),
    )

    with pytest.raises(M6ReplayLockedM4TerminalError) as raised:
        build_m6_replay_locked_closed_policy_m4_pre_policy_candidate(
            execution_scope=scope,
            pending_commitment=pending,
            source=foreign,
        )

    assert raised.value.code is M6ReplayLockedM4TerminalErrorCode.SCOPE_MISMATCH
