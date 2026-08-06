from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_replay_locked_closed_policy_execution_scope_store import (
    M6ReplayLockedClosedPolicyExecutionScopePublisher,
    ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore,
)
from labcourt.adapters.storage.m6_replay_locked_closed_policy_ledger import (
    FilesystemM6ReplayLockedClosedPolicyLedgerRepository,
)
from labcourt.application.m6_replay_locked_closed_policy_execution import (
    build_m6_replay_locked_closed_policy_execution_seal,
    build_m6_replay_locked_closed_policy_sample_record,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.ports.m6_replay_locked_closed_policy_ledger import (
    M6ReplayLockedClosedPolicyLedgerError,
    M6ReplayLockedClosedPolicyLedgerFailureCode,
    M6ReplayLockedClosedPolicyLedgerStatus,
)
from tests.unit.test_m6_replay_locked_closed_policy_execution import _terminal_facts

_PRIMARY_ROOT = "m6-replay-locked-closed-policy-executions"
_WITNESS_ROOT = "m6-replay-locked-closed-policy-execution-witnesses"


def _document(value: object) -> str:
    return canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]


@lru_cache(maxsize=1)
def _terminal():  # type: ignore[no-untyped-def]
    scope, stored, cut, pending, proof, observation, head = _terminal_facts()
    record = build_m6_replay_locked_closed_policy_sample_record(
        execution_scope=scope,
        stored_source_catalog=stored,
        pending_commitment=pending,
        source_determinism=proof,
        policy_causal_cut=cut,
        candidate_observation=observation,
    )
    seal = build_m6_replay_locked_closed_policy_execution_seal(
        execution_scope=scope,
        sample_records=(record,),
        candidate_audit_head=head,
    )
    return scope, pending, record, seal


def _repository(
    root: Path,
    scope: object,
    *,
    fault_injector: object = None,
) -> FilesystemM6ReplayLockedClosedPolicyLedgerRepository:
    M6ReplayLockedClosedPolicyExecutionScopePublisher(root).publish(
        scope,  # type: ignore[arg-type]
        _document(scope),
    )
    return FilesystemM6ReplayLockedClosedPolicyLedgerRepository(
        root,
        scope_provider=ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore(root),
        fault_injector=fault_injector,  # type: ignore[arg-type]
    )


def _artifact_state(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(root.rglob("*.json"))
        if ".staging" not in path.parts
    }


def _replica_base(root: Path, replica: str, scope: object) -> Path:
    return (
        root
        / replica
        / scope.candidate_run_id  # type: ignore[attr-defined]
        / scope.execution_scope_authority_id  # type: ignore[attr-defined]
    )


def _persist_terminal_state(
    repository: FilesystemM6ReplayLockedClosedPolicyLedgerRepository,
    scope: object,
    pending: object,
    record: object,
    seal: object,
):  # type: ignore[no-untyped-def]
    repository.persist_pending(  # type: ignore[arg-type]
        scope,
        pending,
        _document(pending),
    )
    repository.append_record(  # type: ignore[arg-type]
        scope,
        record,
        _document(record),
    )
    return repository.seal(  # type: ignore[arg-type]
        scope,
        seal,
        _document(seal),
    )


def _different_record(record: object):  # type: ignore[no-untyped-def]
    binding = record.closed_candidate_binding  # type: ignore[attr-defined]
    persisted = binding.persisted_candidate_case.model_copy(
        update={"case_audit_entry_hash": "f" * 64}
    )
    binding_payload = binding.model_dump(mode="json", exclude_computed_fields=True)
    binding_payload["persisted_candidate_case"] = persisted.model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    different_binding = type(binding).model_validate(binding_payload)
    record_payload = record.model_dump(  # type: ignore[attr-defined]
        mode="json",
        exclude_computed_fields=True,
    )
    record_payload["closed_candidate_binding"] = different_binding.model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    return type(record).model_validate(record_payload)


def test_ledger_persists_and_recovers_every_v2_pending_record_seal_state(
    tmp_path: Path,
) -> None:
    scope, pending, record, seal = _terminal()
    repository = _repository(tmp_path, scope)

    initial = repository.resume(scope)
    after_pending = repository.persist_pending(scope, pending, _document(pending))
    restarted_pending = _repository(tmp_path, scope).resume(scope)
    after_record = repository.append_record(scope, record, _document(record))
    restarted_record = _repository(tmp_path, scope).resume(scope)
    after_seal = repository.seal(scope, seal, _document(seal))
    restarted_seal = _repository(tmp_path, scope).resume(scope)

    assert initial.status == M6ReplayLockedClosedPolicyLedgerStatus.READY_FOR_PENDING
    assert initial.pending_commitments == ()
    assert initial.sample_records == ()
    assert initial.execution_seal is None
    assert after_pending == restarted_pending
    assert after_pending.status == M6ReplayLockedClosedPolicyLedgerStatus.PENDING
    assert after_pending.pending_commitments == (pending,)
    assert after_record == restarted_record
    assert after_record.status == M6ReplayLockedClosedPolicyLedgerStatus.READY_TO_SEAL
    assert after_record.sample_records == (record,)
    assert after_seal == restarted_seal
    assert after_seal.status == M6ReplayLockedClosedPolicyLedgerStatus.SEALED
    assert after_seal.execution_seal == seal
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


def test_every_exact_v2_retry_is_a_zero_write_idempotent_readback(
    tmp_path: Path,
) -> None:
    scope, pending, record, seal = _terminal()
    repository = _repository(tmp_path, scope)

    first_pending = repository.persist_pending(scope, pending, _document(pending))
    pending_files = _artifact_state(tmp_path)
    assert repository.persist_pending(scope, pending, _document(pending)) == first_pending
    assert _artifact_state(tmp_path) == pending_files

    first_record = repository.append_record(scope, record, _document(record))
    record_files = _artifact_state(tmp_path)
    assert repository.append_record(scope, record, _document(record)) == first_record
    assert _artifact_state(tmp_path) == record_files

    first_seal = repository.seal(scope, seal, _document(seal))
    seal_files = _artifact_state(tmp_path)
    assert repository.seal(scope, seal, _document(seal)) == first_seal
    assert _artifact_state(tmp_path) == seal_files
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


@pytest.mark.parametrize("phase", ["after_staging", "before_commit"])
def test_precommit_fault_is_invisible_and_exact_retry_recovers(
    tmp_path: Path,
    phase: str,
) -> None:
    scope, pending, _, _ = _terminal()

    def fault(observed: str) -> None:
        if observed == phase:
            raise RuntimeError("secret C:/alice")

    with pytest.raises(M6ReplayLockedClosedPolicyLedgerError) as raised:
        _repository(tmp_path, scope, fault_injector=fault).persist_pending(
            scope,
            pending,
            _document(pending),
        )
    assert raised.value.reason_code == (
        M6ReplayLockedClosedPolicyLedgerFailureCode.STORAGE_REJECTED
    )
    assert _repository(tmp_path, scope).resume(scope).status == (
        M6ReplayLockedClosedPolicyLedgerStatus.READY_FOR_PENDING
    )

    recovered = _repository(tmp_path, scope).persist_pending(
        scope,
        pending,
        _document(pending),
    )
    assert recovered.status == M6ReplayLockedClosedPolicyLedgerStatus.PENDING
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


def test_after_commit_fault_recovers_only_after_full_redundant_readback(
    tmp_path: Path,
) -> None:
    scope, pending, _, _ = _terminal()

    def fault(phase: str) -> None:
        if phase == "after_commit":
            raise RuntimeError("secret C:/alice")

    recovered = _repository(
        tmp_path,
        scope,
        fault_injector=fault,
    ).persist_pending(scope, pending, _document(pending))

    assert recovered.status == M6ReplayLockedClosedPolicyLedgerStatus.PENDING
    assert recovered.pending_commitments == (pending,)
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


@pytest.mark.parametrize("replica", [_PRIMARY_ROOT, _WITNESS_ROOT])
def test_loss_of_either_complete_replica_recovers_the_terminal_chain(
    tmp_path: Path,
    replica: str,
) -> None:
    scope, pending, record, seal = _terminal()
    repository = _repository(tmp_path, scope)
    sealed = _persist_terminal_state(repository, scope, pending, record, seal)
    replica_base = _replica_base(tmp_path, replica, scope)

    for path in tuple(replica_base.rglob("*.json")):
        path.unlink()

    assert repository.resume(scope) == sealed


@pytest.mark.parametrize("replica", [_PRIMARY_ROOT, _WITNESS_ROOT])
def test_tamper_in_either_replica_is_a_typed_failure(
    tmp_path: Path,
    replica: str,
) -> None:
    scope, pending, _, _ = _terminal()
    repository = _repository(tmp_path, scope)
    repository.persist_pending(scope, pending, _document(pending))
    artifact = _replica_base(tmp_path, replica, scope) / "pending" / "000000.json"
    artifact.write_text(artifact.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(M6ReplayLockedClosedPolicyLedgerError) as raised:
        repository.resume(scope)

    assert raised.value.reason_code == (
        M6ReplayLockedClosedPolicyLedgerFailureCode.DOCUMENT_INVALID
    )
    assert raised.value.__suppress_context__ is True


def test_record_before_pending_and_seal_before_terminal_record_are_rejected(
    tmp_path: Path,
) -> None:
    scope, pending, record, seal = _terminal()
    repository = _repository(tmp_path, scope)

    with pytest.raises(M6ReplayLockedClosedPolicyLedgerError) as record_error:
        repository.append_record(scope, record, _document(record))
    assert record_error.value.reason_code == (
        M6ReplayLockedClosedPolicyLedgerFailureCode.CHAIN_MISMATCH
    )

    repository.persist_pending(scope, pending, _document(pending))
    with pytest.raises(M6ReplayLockedClosedPolicyLedgerError) as seal_error:
        repository.seal(scope, seal, _document(seal))
    assert seal_error.value.reason_code == (
        M6ReplayLockedClosedPolicyLedgerFailureCode.CHAIN_MISMATCH
    )
    assert repository.resume(scope).status == M6ReplayLockedClosedPolicyLedgerStatus.PENDING


def test_conflicting_v2_pending_and_record_never_overwrite_committed_slots(
    tmp_path: Path,
) -> None:
    scope, pending, record, _ = _terminal()
    repository = _repository(tmp_path, scope)
    after_pending = repository.persist_pending(scope, pending, _document(pending))
    foreign_pending = pending.model_copy(update={"execution_scope_authority_id": "f" * 64})

    with pytest.raises(M6ReplayLockedClosedPolicyLedgerError) as pending_error:
        repository.persist_pending(scope, foreign_pending, _document(foreign_pending))
    assert pending_error.value.reason_code == (
        M6ReplayLockedClosedPolicyLedgerFailureCode.PENDING_CONFLICT
    )
    assert repository.resume(scope) == after_pending

    after_record = repository.append_record(scope, record, _document(record))
    foreign_record = _different_record(record)
    with pytest.raises(M6ReplayLockedClosedPolicyLedgerError) as record_error:
        repository.append_record(scope, foreign_record, _document(foreign_record))
    assert record_error.value.reason_code == (
        M6ReplayLockedClosedPolicyLedgerFailureCode.RECORD_CONFLICT
    )
    assert repository.resume(scope) == after_record
