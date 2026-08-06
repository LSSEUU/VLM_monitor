from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from labcourt.adapters.storage.m6_replay_locked_execution_scope_store import (
    M6ReplayLockedExecutionScopePublisher,
    ReadonlyM6ReplayLockedExecutionScopeStore,
)
from labcourt.adapters.storage.m6_replay_locked_ledger import (
    FilesystemM6ReplayLockedLedgerRepository,
)
from labcourt.application.m6_replay_locked_execution import (
    build_m6_replay_locked_execution_seal,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.ports.m6_replay_locked_ledger import (
    M6ReplayLockedLedgerError,
    M6ReplayLockedLedgerFailureCode,
    M6ReplayLockedLedgerStatus,
)
from tests.unit.test_m6_replay_locked_execution import _facts


def _document(value: object) -> str:
    return canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]


def _seal():  # type: ignore[no-untyped-def]
    scope, stored, _, _, _, record, head = _facts()
    seal = build_m6_replay_locked_execution_seal(
        execution_scope=scope,
        stored_source_catalog=stored,
        sample_records=(record,),
        candidate_audit_head=head,
    )
    return scope, record.pending_commitment, record, seal


def _repository(
    root: Path,
    scope: object,
    *,
    fault_injector: object = None,
) -> FilesystemM6ReplayLockedLedgerRepository:
    M6ReplayLockedExecutionScopePublisher(root).publish(scope, _document(scope))  # type: ignore[arg-type]
    return FilesystemM6ReplayLockedLedgerRepository(
        root,
        scope_provider=ReadonlyM6ReplayLockedExecutionScopeStore(root),
        fault_injector=fault_injector,  # type: ignore[arg-type]
    )


def test_ledger_persists_and_recovers_every_pending_record_seal_state(
    tmp_path: Path,
) -> None:
    scope, pending, record, seal = _seal()
    repository = _repository(tmp_path, scope)

    initial = repository.resume(scope)
    after_pending = repository.persist_pending(scope, pending, _document(pending))
    restarted_pending = _repository(tmp_path, scope).resume(scope)
    after_record = repository.append_record(scope, record, _document(record))
    restarted_record = _repository(tmp_path, scope).resume(scope)
    after_seal = repository.seal(scope, seal, _document(seal))
    restarted_seal = _repository(tmp_path, scope).resume(scope)

    assert initial.status == M6ReplayLockedLedgerStatus.READY_FOR_PENDING
    assert after_pending == restarted_pending
    assert after_pending.status == M6ReplayLockedLedgerStatus.PENDING
    assert after_record == restarted_record
    assert after_record.status == M6ReplayLockedLedgerStatus.READY_TO_SEAL
    assert after_seal == restarted_seal
    assert after_seal.status == M6ReplayLockedLedgerStatus.SEALED
    assert after_seal.execution_seal == seal
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


def test_every_exact_retry_is_idempotent_and_does_not_leave_staging(tmp_path: Path) -> None:
    scope, pending, record, seal = _seal()
    repository = _repository(tmp_path, scope)

    first_pending = repository.persist_pending(scope, pending, _document(pending))
    assert repository.persist_pending(scope, pending, _document(pending)) == first_pending
    first_record = repository.append_record(scope, record, _document(record))
    assert repository.append_record(scope, record, _document(record)) == first_record
    first_seal = repository.seal(scope, seal, _document(seal))
    assert repository.seal(scope, seal, _document(seal)) == first_seal
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


def test_ledger_rejects_record_before_pending_and_seal_before_complete(
    tmp_path: Path,
) -> None:
    scope, pending, record, seal = _seal()
    repository = _repository(tmp_path, scope)

    with pytest.raises(M6ReplayLockedLedgerError) as record_error:
        repository.append_record(scope, record, _document(record))
    assert record_error.value.reason_code == M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH

    repository.persist_pending(scope, pending, _document(pending))
    with pytest.raises(M6ReplayLockedLedgerError) as seal_error:
        repository.seal(scope, seal, _document(seal))
    assert seal_error.value.reason_code == M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH


def test_conflicting_pending_never_overwrites_the_committed_intent(tmp_path: Path) -> None:
    scope, pending, _, _ = _seal()
    repository = _repository(tmp_path, scope)
    original = repository.persist_pending(scope, pending, _document(pending))
    foreign = pending.model_copy(update={"source_catalog_entry_id": "f" * 64})

    with pytest.raises(M6ReplayLockedLedgerError) as raised:
        repository.persist_pending(scope, foreign, _document(foreign))

    assert raised.value.reason_code == M6ReplayLockedLedgerFailureCode.PENDING_CONFLICT
    assert repository.resume(scope) == original


@pytest.mark.parametrize("phase", ["after_staging", "before_commit"])
def test_precommit_fault_is_invisible_and_exact_retry_recovers(
    tmp_path: Path,
    phase: str,
) -> None:
    scope, pending, _, _ = _seal()

    def fault(observed: str) -> None:
        if observed == phase:
            raise RuntimeError("secret C:/alice")

    with pytest.raises(M6ReplayLockedLedgerError) as raised:
        _repository(
            tmp_path,
            scope,
            fault_injector=fault,
        ).persist_pending(scope, pending, _document(pending))
    assert raised.value.reason_code == M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED
    assert _repository(tmp_path, scope).resume(scope).status == (
        M6ReplayLockedLedgerStatus.READY_FOR_PENDING
    )

    recovered = _repository(tmp_path, scope).persist_pending(
        scope,
        pending,
        _document(pending),
    )
    assert recovered.status == M6ReplayLockedLedgerStatus.PENDING
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


def test_lost_commit_receipt_is_recovered_by_full_resume(tmp_path: Path) -> None:
    scope, pending, _, _ = _seal()

    def fault(phase: str) -> None:
        if phase == "after_commit":
            raise RuntimeError("secret C:/alice")

    recovered = _repository(
        tmp_path,
        scope,
        fault_injector=fault,
    ).persist_pending(scope, pending, _document(pending))

    assert recovered.status == M6ReplayLockedLedgerStatus.PENDING
    assert recovered.pending_commitments == (pending,)


def test_concurrent_exact_pending_publication_is_idempotent(tmp_path: Path) -> None:
    scope, pending, _, _ = _seal()
    barrier = Barrier(2)

    def publish() -> object:
        def fault(phase: str) -> None:
            if phase == "after_staging":
                barrier.wait(timeout=5)

        return _repository(
            tmp_path,
            scope,
            fault_injector=fault,
        ).persist_pending(scope, pending, _document(pending))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _: publish(), range(2)))

    assert results[0] == results[1]
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


@pytest.mark.parametrize("output_root", ["", "bad\x00root"])
def test_invalid_output_root_is_a_typed_payload_free_failure(output_root: str) -> None:
    class UnusedScopeProvider:
        def load(self, _candidate_run_id: str, _scope_id: str) -> object:
            raise AssertionError("invalid output root must fail first")

    with pytest.raises(M6ReplayLockedLedgerError) as raised:
        FilesystemM6ReplayLockedLedgerRepository(
            output_root,
            scope_provider=UnusedScopeProvider(),
        )

    assert raised.value.reason_code == M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT
    assert raised.value.__suppress_context__ is True


def test_unpublished_scope_is_rejected_before_any_ledger_write(tmp_path: Path) -> None:
    scope, _, _, _ = _seal()
    repository = FilesystemM6ReplayLockedLedgerRepository(
        tmp_path,
        scope_provider=ReadonlyM6ReplayLockedExecutionScopeStore(tmp_path),
    )

    with pytest.raises(M6ReplayLockedLedgerError) as raised:
        repository.resume(scope)

    assert raised.value.reason_code == M6ReplayLockedLedgerFailureCode.SCOPE_NOT_FOUND
    assert not (tmp_path / "m6-replay-locked-executions").exists()
    assert not (tmp_path / "m6-replay-locked-execution-witnesses").exists()


def test_foreign_pending_is_rejected_before_primary_or_witness_write(
    tmp_path: Path,
) -> None:
    scope, pending, _, _ = _seal()
    repository = _repository(tmp_path, scope)
    foreign = pending.model_copy(update={"source_catalog_entry_id": "f" * 64})

    with pytest.raises(M6ReplayLockedLedgerError) as raised:
        repository.persist_pending(scope, foreign, _document(foreign))

    assert raised.value.reason_code == M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH
    assert repository.resume(scope).status == M6ReplayLockedLedgerStatus.READY_FOR_PENDING
    assert not (tmp_path / "m6-replay-locked-executions").exists()
    assert not (tmp_path / "m6-replay-locked-execution-witnesses").exists()


def test_foreign_record_is_rejected_before_primary_or_witness_write(
    tmp_path: Path,
) -> None:
    scope, pending, record, _ = _seal()
    repository = _repository(tmp_path, scope)
    repository.persist_pending(scope, pending, _document(pending))
    foreign_snapshot = record.candidate_snapshot.model_copy(update={"manifest_id": "f" * 64})
    foreign_proof = record.source_determinism.model_copy(
        update={
            "first_semantic_case_hash": foreign_snapshot.semantic_case_hash,
            "second_semantic_case_hash": foreign_snapshot.semantic_case_hash,
        }
    )
    foreign = type(record).model_validate(
        {
            **record.model_dump(mode="json", exclude_computed_fields=True),
            "candidate_manifest_id": "f" * 64,
            "candidate_snapshot": foreign_snapshot.model_dump(mode="json"),
            "source_determinism": foreign_proof.model_dump(mode="json"),
        }
    )

    with pytest.raises(M6ReplayLockedLedgerError) as raised:
        repository.append_record(scope, foreign, _document(foreign))

    assert raised.value.reason_code == M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH
    assert repository.resume(scope).status == M6ReplayLockedLedgerStatus.PENDING
    records = tmp_path / "m6-replay-locked-executions" / scope.candidate_run_id
    witnesses = tmp_path / "m6-replay-locked-execution-witnesses" / scope.candidate_run_id
    assert not tuple(records.rglob("records/*.json"))
    assert not tuple(witnesses.rglob("records/*.json"))


def test_primary_tail_and_seal_deletion_cannot_regress_witnessed_state(
    tmp_path: Path,
) -> None:
    scope, pending, record, seal = _seal()
    repository = _repository(tmp_path, scope)
    repository.persist_pending(scope, pending, _document(pending))
    repository.append_record(scope, record, _document(record))
    sealed = repository.seal(scope, seal, _document(seal))
    base = (
        tmp_path
        / "m6-replay-locked-executions"
        / scope.candidate_run_id
        / scope.execution_scope_authority_id
    )

    (base / "seal.json").unlink()
    assert repository.resume(scope) == sealed
    (base / "records" / "000000.json").unlink()
    assert repository.resume(scope) == sealed
    (base / "pending" / "000000.json").unlink()
    assert repository.resume(scope) == sealed
