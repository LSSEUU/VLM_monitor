from __future__ import annotations

from dataclasses import asdict

import pytest

from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.domain.m6_semantic_projection import build_m6_case_replay_snapshot
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
)
from tests.unit.test_m6_replay_locked_candidate_observation import _runtime
from tests.unit.test_m6_replay_locked_closed_policy_execution import (
    _terminal_facts,
)
from tests.unit.test_m6_replay_locked_policy_source import _sha


def _source():  # type: ignore[no-untyped-def]
    existing = _runtime().source
    ready_revision = existing.closure.source_case_revision
    assert ready_revision is not None
    closed_closure = M6ReplayInputClosureAuthority.model_validate(
        existing.closure.model_copy(
            update={
                "source_case_revision": ready_revision + 1,
                "source_case_document_sha256": _sha("closed-successor"),
            }
        ).model_dump(mode="json", exclude_computed_fields=True)
    )
    base_binding = _terminal_facts()[3].source_binding
    binding = M6ReplayLockedClosedPolicySourceBindingAuthority(
        source_catalog_entry_id=_sha("catalog-entry"),
        sample_id=closed_closure.sample_id,
        execution_entry_id=_sha("execution-entry"),
        replay_input_closure_authority_id=(closed_closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(closed_closure.replay_input_closure_document_sha256),
        pre_policy_route=base_binding.pre_policy_route,
        source_config_sha256=base_binding.source_config_sha256,
        policy_causal_cut_authority_id=_sha("policy-cut"),
        policy_causal_cut_content_sha256=_sha("policy-cut-document"),
        policy_causal_cut_size_bytes=1,
        cooldown_causal_head=base_binding.cooldown_causal_head,
        emergency_causal_basis=base_binding.emergency_causal_basis,
    )
    snapshot = build_m6_case_replay_snapshot(
        context=existing.projection_context,
        sample_id=closed_closure.sample_id,
        source_case_revision=ready_revision,
    )
    return existing, closed_closure, binding, snapshot, ready_revision


def test_fast_source_exposes_only_the_committed_ready_predecessor() -> None:
    existing, closure, binding, snapshot, revision = _source()

    source = M6ReplayLockedClosedPolicyFastPrePolicySource(
        source_identity_sha256=existing.source_identity_sha256,
        source_binding=binding,
        catalog_closure=closure,
        source_ready_case_revision=revision,
        projection_context=existing.projection_context,
        source_snapshot=snapshot,
    )

    document = asdict(source)
    assert source.catalog_closure.source_case_revision == revision + 1
    assert source.source_snapshot.source_case_revision == revision
    assert "source_alert_policy" not in document
    assert "source_closed_case" not in document
    assert "policy_causal_cut" not in document


def test_fast_source_rejects_a_ready_body_used_as_the_catalog_terminal() -> None:
    existing, _closure, binding, snapshot, revision = _source()

    with pytest.raises(ValueError, match="cross-grafted"):
        M6ReplayLockedClosedPolicyFastPrePolicySource(
            source_identity_sha256=existing.source_identity_sha256,
            source_binding=binding,
            catalog_closure=existing.closure,
            source_ready_case_revision=revision,
            projection_context=existing.projection_context,
            source_snapshot=snapshot,
        )
