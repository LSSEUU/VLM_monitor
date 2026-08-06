from __future__ import annotations

from dataclasses import replace

import pytest

from labcourt.application.m6_replay_locked_closed_policy_execution import (
    build_m6_replay_locked_closed_policy_execution_scope,
    build_m6_replay_locked_closed_policy_pending_commitment,
)
from labcourt.application.m6_replay_locked_closed_pre_policy_source import (
    build_m6_replay_locked_closed_policy_pre_policy_source,
)
from labcourt.application.m6_replay_locked_fast_terminal import (
    M6ReplayLockedFastTerminalError,
    M6ReplayLockedFastTerminalErrorCode,
    build_m6_replay_locked_closed_policy_fast_pre_policy_candidate,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
)
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
)
from tests.unit.test_m6_replay_locked_candidate_observation import _runtime
from tests.unit.test_m6_replay_locked_closed_pre_policy_source_application import (
    _facts as _closed_source_facts,
)
from tests.unit.test_m6_replay_locked_execution import _route_inputs


def _execution():  # type: ignore[no-untyped-def]
    source, closure, cut, _binding, closed_context = _closed_source_facts()
    pre_policy_scope, stored = _route_inputs(closure, _runtime().scope)
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
    safe_source = build_m6_replay_locked_closed_policy_pre_policy_source(
        source_binding=pending.source_binding,
        policy_causal_cut=cut,
        catalog_closure=closure,
        closed_projection_context=closed_context,
    )
    assert type(safe_source) is M6ReplayLockedClosedPolicyFastPrePolicySource
    return source, closure, scope, pending, safe_source


def test_v2_fast_builder_replays_ready_predecessor_without_rewriting_closed_closure() -> None:
    source, closure, scope, pending, safe_source = _execution()

    candidate = build_m6_replay_locked_closed_policy_fast_pre_policy_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=safe_source,
    )

    assert candidate.case.status is CaseStatus.READY_FOR_ALERT_POLICY
    assert candidate.case.run_id == scope.candidate_run_id
    assert candidate.candidate_snapshot.stage_roots == source.source_snapshot.stage_roots
    assert candidate.source_snapshot == safe_source.source_snapshot
    assert closure.source_case_revision == safe_source.source_ready_case_revision + 1
    assert closure.source_case_document_sha256 != (
        safe_source.source_snapshot.source_case_document_sha256
    )


def test_v2_fast_builder_rejects_a_safe_source_from_another_pending_cut() -> None:
    _source, _closure, scope, pending, safe_source = _execution()
    foreign_binding = pending.source_binding.model_copy(
        update={"source_catalog_entry_id": "f" * 64}
    )
    foreign_source = replace(safe_source, source_binding=foreign_binding)

    with pytest.raises(M6ReplayLockedFastTerminalError) as raised:
        build_m6_replay_locked_closed_policy_fast_pre_policy_candidate(
            execution_scope=scope,
            pending_commitment=pending,
            source=foreign_source,
        )

    assert raised.value.code is M6ReplayLockedFastTerminalErrorCode.SCOPE_MISMATCH
