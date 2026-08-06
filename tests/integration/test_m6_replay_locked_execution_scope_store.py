from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from labcourt.adapters.storage.m6_replay_locked_execution_scope_store import (
    M6ReplayLockedExecutionScopePublisher,
    ReadonlyM6ReplayLockedExecutionScopeStore,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.application.m6_replay_locked_execution_scope import (
    build_m6_replay_locked_execution_scope,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionComponentAuthority,
)
from labcourt.ports.m6_replay_locked_execution_scope import (
    M6ReplayLockedExecutionScopeFailureCode,
    M6ReplayLockedExecutionScopeStoreError,
)
from tests.unit.test_m6_replay_locked_execution_scope import _inputs


def _scope(**updates: object):  # type: ignore[no-untyped-def]
    inputs = _inputs()
    inputs.update(updates)
    return build_m6_replay_locked_execution_scope(**inputs)


def _document(scope: object) -> str:
    return canonical_json(scope.model_dump(mode="json"))  # type: ignore[attr-defined]


def test_scope_publish_is_idempotent_single_run_and_exact_readback(tmp_path: Path) -> None:
    scope = _scope()
    document = _document(scope)
    publisher = M6ReplayLockedExecutionScopePublisher(tmp_path)

    first = publisher.publish(scope, document)
    second = publisher.publish(scope, document)
    stored = ReadonlyM6ReplayLockedExecutionScopeStore(tmp_path).load(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert first == second == stored
    assert stored.scope == scope
    assert stored.canonical_document == document
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


@pytest.mark.parametrize("phase", ["after_staging", "before_commit"])
def test_precommit_fault_is_not_visible_and_exact_retry_recovers(
    tmp_path: Path,
    phase: str,
) -> None:
    scope = _scope()
    document = _document(scope)

    def fault(observed: str) -> None:
        if observed == phase:
            raise RuntimeError("secret C:/alice")

    with pytest.raises(M6ReplayLockedExecutionScopeStoreError):
        M6ReplayLockedExecutionScopePublisher(tmp_path, fault_injector=fault).publish(
            scope,
            document,
        )
    with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as missing:
        ReadonlyM6ReplayLockedExecutionScopeStore(tmp_path).load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert missing.value.reason_code == M6ReplayLockedExecutionScopeFailureCode.SCOPE_NOT_FOUND

    recovered = M6ReplayLockedExecutionScopePublisher(tmp_path).publish(scope, document)
    assert recovered.scope == scope
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


def test_lost_commit_receipt_recovers_only_after_full_readback(tmp_path: Path) -> None:
    scope = _scope()

    def fault(phase: str) -> None:
        if phase == "after_commit":
            raise RuntimeError("secret C:/alice")

    stored = M6ReplayLockedExecutionScopePublisher(
        tmp_path,
        fault_injector=fault,
    ).publish(scope, _document(scope))

    assert stored.scope == scope
    assert (
        ReadonlyM6ReplayLockedExecutionScopeStore(tmp_path)
        .load(scope.candidate_run_id, scope.execution_scope_authority_id)
        .scope
        == scope
    )


def test_same_candidate_run_rejects_different_scope_without_overwrite(tmp_path: Path) -> None:
    first = _scope()
    inputs = _inputs()
    component = inputs["execution_component"]
    assert isinstance(component, M6ReplayLockedExecutionComponentAuthority)
    second = _scope(execution_component=component.model_copy(update={"version": "0.1.1"}))
    assert first.candidate_run_id == second.candidate_run_id
    assert first.execution_scope_authority_id != second.execution_scope_authority_id
    publisher = M6ReplayLockedExecutionScopePublisher(tmp_path)
    original = publisher.publish(first, _document(first))

    with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as conflict:
        publisher.publish(second, _document(second))

    assert conflict.value.reason_code == M6ReplayLockedExecutionScopeFailureCode.SCOPE_CONFLICT
    assert (
        ReadonlyM6ReplayLockedExecutionScopeStore(tmp_path).load(
            first.candidate_run_id,
            first.execution_scope_authority_id,
        )
        == original
    )


def test_store_rejects_noncanonical_document_tamper_and_size_overflow(tmp_path: Path) -> None:
    scope = _scope()
    document = _document(scope)
    publisher = M6ReplayLockedExecutionScopePublisher(tmp_path)

    with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as noncanonical:
        publisher.publish(scope, document + " ")
    assert noncanonical.value.reason_code == (
        M6ReplayLockedExecutionScopeFailureCode.DOCUMENT_INVALID
    )

    with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as oversized:
        M6ReplayLockedExecutionScopePublisher(tmp_path, max_document_bytes=1).publish(
            scope,
            document,
        )
    assert oversized.value.reason_code == (
        M6ReplayLockedExecutionScopeFailureCode.DOCUMENT_TOO_LARGE
    )

    stored = publisher.publish(scope, document)
    scope_file = next(path for path in tmp_path.rglob("scope.json") if ".staging" not in path.parts)
    scope_file.write_text(stored.canonical_document + " ", encoding="utf-8")
    with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as tampered:
        ReadonlyM6ReplayLockedExecutionScopeStore(tmp_path).load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert tampered.value.reason_code == M6ReplayLockedExecutionScopeFailureCode.IDENTITY_MISMATCH


def test_linked_store_root_is_rejected_without_writing_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable in this environment")
    scope = _scope()

    with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as raised:
        M6ReplayLockedExecutionScopePublisher(linked).publish(scope, _document(scope))

    assert raised.value.reason_code == M6ReplayLockedExecutionScopeFailureCode.STORAGE_REJECTED
    assert not tuple(target.iterdir())


@pytest.mark.parametrize("output_root", ["", "bad\x00root"])
def test_invalid_output_root_is_a_payload_free_typed_failure(output_root: str) -> None:
    with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as raised:
        M6ReplayLockedExecutionScopePublisher(output_root)

    assert raised.value.reason_code == M6ReplayLockedExecutionScopeFailureCode.INVALID_ARGUMENT
    assert raised.value.__suppress_context__ is True
    assert "root" not in str(raised.value).lower()


def test_missing_output_root_is_rejected_without_creating_it(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as raised:
        M6ReplayLockedExecutionScopePublisher(missing)

    assert raised.value.reason_code == M6ReplayLockedExecutionScopeFailureCode.STORAGE_REJECTED
    assert not missing.exists()


def test_symlink_ancestor_does_not_create_a_missing_store_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable in this environment")
    missing_leaf = linked / "missing"

    with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as raised:
        M6ReplayLockedExecutionScopePublisher(missing_leaf)

    assert raised.value.reason_code == M6ReplayLockedExecutionScopeFailureCode.STORAGE_REJECTED
    assert not (target / "missing").exists()


def test_concurrent_exact_publish_is_idempotent_not_a_conflict(tmp_path: Path) -> None:
    scope = _scope()
    document = _document(scope)
    barrier = Barrier(2)

    def publisher() -> object:
        def fault(phase: str) -> None:
            if phase == "after_staging":
                barrier.wait(timeout=5)

        return M6ReplayLockedExecutionScopePublisher(
            tmp_path,
            fault_injector=fault,
        ).publish(scope, document)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _: publisher(), range(2)))

    assert results[0] == results[1]
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


def test_unknown_commit_outcome_is_typed_and_exact_retry_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _scope()
    document = _document(scope)

    def fail_commit(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise OSError("secret C:/alice")

    with monkeypatch.context() as isolated:
        isolated.setattr(SecureWorkspace, "publish_staged", fail_commit)
        with pytest.raises(M6ReplayLockedExecutionScopeStoreError) as raised:
            M6ReplayLockedExecutionScopePublisher(tmp_path).publish(scope, document)

    assert raised.value.reason_code == (
        M6ReplayLockedExecutionScopeFailureCode.COMMIT_OUTCOME_UNKNOWN
    )
    assert raised.value.__suppress_context__ is True
    recovered = M6ReplayLockedExecutionScopePublisher(tmp_path).publish(scope, document)
    assert recovered.scope == scope
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())
