from __future__ import annotations

import dataclasses

import pytest

from labcourt.contracts.canonical import canonical_json
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateObservation,
    M6ReplayLockedClosedCandidateWrite,
    M6ReplayLockedStoredClosedCandidate,
)
from tests.contract.test_m6_replay_locked_closed_policy_execution_contracts import (
    _closed_terminal,
)


def _authorities():  # type: ignore[no-untyped-def]
    seal = _closed_terminal()
    record = seal.sample_executions[0]
    candidate = record.closed_candidate_binding
    pending = record.pending_commitment
    policy_document = canonical_json(candidate.candidate_alert_policy.model_dump(mode="json"))
    case_document = canonical_json(candidate.closed_candidate_case.model_dump(mode="json"))
    write = M6ReplayLockedClosedCandidateWrite(
        transient_ready_case=candidate.transient_ready_case,
        candidate_alert_policy=candidate.candidate_alert_policy,
        closed_candidate_case=candidate.closed_candidate_case,
        canonical_alert_policy_document=policy_document,
        canonical_closed_case_document=case_document,
    )
    stored = M6ReplayLockedStoredClosedCandidate(
        candidate_run_id=candidate.candidate_run_id,
        execution_scope_authority_id=record.execution_scope_authority_id,
        pre_policy_execution_scope_authority_id=(pending.pre_policy_execution_scope_authority_id),
        ledger_sequence=record.ledger_sequence,
        sample_id=record.sample_id,
        execution_entry_id=record.execution_entry_id,
        source_catalog_entry_id=pending.source_catalog_entry_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        pre_policy_pending_commitment_authority_id=(
            pending.pre_policy_pending_commitment.pending_commitment_authority_id
        ),
        source_binding_authority_id=pending.source_binding_authority_id,
        policy_causal_cut_authority_id=pending.policy_causal_cut_authority_id,
        locked_config_sha256=pending.locked_config_sha256,
        pre_policy_route=pending.pre_policy_route,
        candidate_alert_policy=candidate.candidate_alert_policy,
        canonical_alert_policy_document=policy_document,
        candidate_alert_policy_document_sha256=(candidate.candidate_alert_policy_content_sha256),
        candidate_alert_policy_size_bytes=candidate.candidate_alert_policy_size_bytes,
        closed_candidate_case=candidate.closed_candidate_case,
        canonical_closed_case_document=case_document,
        closed_candidate_case_document_sha256=(candidate.closed_candidate_case_content_sha256),
        closed_candidate_case_size_bytes=candidate.closed_candidate_case_size_bytes,
        case_audit_sequence=candidate.persisted_candidate_case.case_audit_sequence,
        case_audit_entry_hash=candidate.persisted_candidate_case.case_audit_entry_hash,
    )
    observation = M6ReplayLockedClosedCandidateObservation(
        closed_candidate_binding=candidate,
        candidate_snapshot=record.candidate_snapshot,
    )
    return write, stored, observation


def test_closed_candidate_port_keeps_only_policy_and_closed_documents_durable() -> None:
    write, stored, observation = _authorities()

    assert write.closed_candidate_case == stored.closed_candidate_case
    assert observation.closed_candidate_binding.closed_candidate_case == (
        stored.closed_candidate_case
    )
    stored_fields = {field.name for field in dataclasses.fields(stored)}
    assert "transient_ready_case" not in stored_fields
    assert "canonical_ready_case_document" not in stored_fields


def test_closed_candidate_write_rejects_a_ready_body_as_the_persisted_case() -> None:
    write, _, _ = _authorities()

    with pytest.raises(ValueError, match="bindings differ"):
        M6ReplayLockedClosedCandidateWrite(
            transient_ready_case=write.transient_ready_case,
            candidate_alert_policy=write.candidate_alert_policy,
            closed_candidate_case=write.transient_ready_case,
            canonical_alert_policy_document=write.canonical_alert_policy_document,
            canonical_closed_case_document=canonical_json(
                write.transient_ready_case.model_dump(mode="json")
            ),
        )


def test_stored_closed_candidate_rejects_physical_policy_drift() -> None:
    _, stored, _ = _authorities()

    with pytest.raises(ValueError, match="bindings differ"):
        dataclasses.replace(
            stored,
            candidate_alert_policy_document_sha256="f" * 64,
        )
