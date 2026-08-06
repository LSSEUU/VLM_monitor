"""Secure append-only file ledger for M6 locked Pending/Record/Seal facts."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import MAX_M6_REGRESSION_CASES
from labcourt.contracts.m6_replay_locked_execution import (
    MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedExecutionSealAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
    M6ReplayLockedSampleExecutionRecord,
)
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    PathBoundaryViolation,
)
from labcourt.ports.m6_replay_locked_execution_scope import (
    M6ReplayLockedExecutionScopeFailureCode,
    M6ReplayLockedExecutionScopeProvider,
    M6ReplayLockedExecutionScopeStoreError,
    M6StoredReplayLockedExecutionScope,
)
from labcourt.ports.m6_replay_locked_ledger import (
    M6ReplayLockedExecutionResume,
    M6ReplayLockedLedgerError,
    M6ReplayLockedLedgerFailureCode,
    M6ReplayLockedLedgerStatus,
)

from .secure_workspace import SecureWorkspace

M6ReplayLockedLedgerFaultInjector = Callable[[str], None]
_ModelT = TypeVar("_ModelT", bound=BaseModel)
_STORE_ROOT = "m6-replay-locked-executions"
_WITNESS_ROOT = "m6-replay-locked-execution-witnesses"
_MAX_OUTPUT_ROOT_UTF8_BYTES = 32_768
_STAGING_READ_TIMEOUT_SECONDS = 1.0
_STAGING_READ_RETRY_SECONDS = 0.005
DEFAULT_M6_REPLAY_LOCKED_LEDGER_MAX_ENTRY_COUNT = 4_096


def _error(code: M6ReplayLockedLedgerFailureCode) -> M6ReplayLockedLedgerError:
    return M6ReplayLockedLedgerError(code)


def _fail(code: M6ReplayLockedLedgerFailureCode) -> NoReturn:
    raise _error(code) from None


def _controlled_output_root(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)
    try:
        raw = str(value)
        if (
            not raw
            or "\x00" in raw
            or len(raw.encode("utf-8", errors="strict")) > _MAX_OUTPUT_ROOT_UTF8_BYTES
        ):
            _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)
        return Path(raw).absolute()
    except M6ReplayLockedLedgerError:
        raise
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)


def _preflight_output_root(root: Path, max_document_bytes: int) -> None:
    try:
        with SecureWorkspace(root, max_document_bytes):
            pass
    except Exception:
        raise _error(M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED) from None


def _canonical_model(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)
    return controlled


def _canonical_payload(
    value: object,
    expected: type[_ModelT],
    canonical_document: object,
    max_document_bytes: int,
) -> tuple[_ModelT, bytes]:
    controlled = _canonical_model(value, expected)
    if not isinstance(canonical_document, str) or not canonical_document:
        _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_INVALID)
    try:
        payload = canonical_document.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_INVALID)
    if len(payload) > max_document_bytes:
        _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_TOO_LARGE)
    if canonical_document != canonical_json(controlled.model_dump(mode="json")):
        _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_INVALID)
    return controlled, payload


def _model_size(value: BaseModel) -> int:
    try:
        return len(canonical_json(value.model_dump(mode="json")).encode("utf-8"))
    except (AttributeError, TypeError, ValueError, UnicodeError):
        _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_INVALID)


def _base(scope: M6ReplayLockedExecutionScopeAuthority) -> str:
    return f"{_STORE_ROOT}/{scope.candidate_run_id}/{scope.execution_scope_authority_id}"


def _pending_relative(scope: M6ReplayLockedExecutionScopeAuthority, sequence: int) -> str:
    return f"{_base(scope)}/pending/{sequence:06d}.json"


def _record_relative(scope: M6ReplayLockedExecutionScopeAuthority, sequence: int) -> str:
    return f"{_base(scope)}/records/{sequence:06d}.json"


def _seal_relative(scope: M6ReplayLockedExecutionScopeAuthority) -> str:
    return f"{_base(scope)}/seal.json"


def _witness_base(scope: M6ReplayLockedExecutionScopeAuthority) -> str:
    return f"{_WITNESS_ROOT}/{scope.candidate_run_id}/{scope.execution_scope_authority_id}"


def _pending_witness_relative(
    scope: M6ReplayLockedExecutionScopeAuthority,
    sequence: int,
) -> str:
    return f"{_witness_base(scope)}/pending/{sequence:06d}.json"


def _record_witness_relative(
    scope: M6ReplayLockedExecutionScopeAuthority,
    sequence: int,
) -> str:
    return f"{_witness_base(scope)}/records/{sequence:06d}.json"


def _seal_witness_relative(scope: M6ReplayLockedExecutionScopeAuthority) -> str:
    return f"{_witness_base(scope)}/seal.json"


def _staged_relative(
    scope: M6ReplayLockedExecutionScopeAuthority,
    label: str,
) -> str:
    return (
        f".staging/{_STORE_ROOT}/{scope.candidate_run_id}/"
        f"{scope.execution_scope_authority_id}/{label}.json"
    )


class FilesystemM6ReplayLockedLedgerRepository:
    """One immutable document per Pending, Record, and terminal Seal."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        scope_provider: M6ReplayLockedExecutionScopeProvider,
        fault_injector: M6ReplayLockedLedgerFaultInjector | None = None,
        max_document_bytes: int = MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        max_entry_count: int = DEFAULT_M6_REPLAY_LOCKED_LEDGER_MAX_ENTRY_COUNT,
    ) -> None:
        if (
            not isinstance(max_document_bytes, int)
            or isinstance(max_document_bytes, bool)
            or max_document_bytes <= 0
            or max_document_bytes > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
        ):
            _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)
        if fault_injector is not None and not callable(fault_injector):
            _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)
        if (
            not isinstance(max_entry_count, int)
            or isinstance(max_entry_count, bool)
            or max_entry_count <= 0
            or max_entry_count > MAX_M6_REGRESSION_CASES
        ):
            _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)
        if not callable(getattr(scope_provider, "load", None)):
            _fail(M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT)
        self._output_root = _controlled_output_root(output_root)
        self._max_document_bytes = max_document_bytes
        self._fault_injector = fault_injector
        self._scope_provider = scope_provider
        self._max_entry_count = max_entry_count
        self._max_prefix_bytes = max_document_bytes // 3
        _preflight_output_root(self._output_root, self._max_document_bytes)

    def _controlled_scope(
        self,
        value: object,
    ) -> M6ReplayLockedExecutionScopeAuthority:
        scope = _canonical_model(value, M6ReplayLockedExecutionScopeAuthority)
        try:
            observed = self._scope_provider.load(
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
            )
        except M6ReplayLockedExecutionScopeStoreError as error:
            if error.reason_code == M6ReplayLockedExecutionScopeFailureCode.SCOPE_NOT_FOUND:
                code = M6ReplayLockedLedgerFailureCode.SCOPE_NOT_FOUND
            elif error.reason_code == M6ReplayLockedExecutionScopeFailureCode.DOCUMENT_TOO_LARGE:
                code = M6ReplayLockedLedgerFailureCode.DOCUMENT_TOO_LARGE
            elif error.reason_code == M6ReplayLockedExecutionScopeFailureCode.STORAGE_REJECTED:
                code = M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED
            else:
                code = M6ReplayLockedLedgerFailureCode.SCOPE_CONFLICT
            raise _error(code) from None
        except Exception:
            raise _error(M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED) from None
        if type(observed) is not M6StoredReplayLockedExecutionScope:
            _fail(M6ReplayLockedLedgerFailureCode.SCOPE_CONFLICT)
        try:
            stored = M6StoredReplayLockedExecutionScope(
                scope=observed.scope,
                canonical_document=observed.canonical_document,
                content_sha256=observed.content_sha256,
                size_bytes=observed.size_bytes,
            )
        except (AttributeError, TypeError, ValueError):
            _fail(M6ReplayLockedLedgerFailureCode.SCOPE_CONFLICT)
        if stored.scope != scope:
            _fail(M6ReplayLockedLedgerFailureCode.SCOPE_CONFLICT)
        if len(scope.execution_dataset.entries) > self._max_entry_count:
            _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_TOO_LARGE)
        return scope

    def _require_resume_budget(self, state: M6ReplayLockedExecutionResume) -> None:
        prefix_bytes = _model_size(state.execution_scope)
        prefix_bytes += sum(_model_size(item) for item in state.pending_commitments)
        prefix_bytes += sum(_model_size(item) for item in state.sample_records)
        if prefix_bytes > self._max_prefix_bytes:
            _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_TOO_LARGE)

    def resume(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
    ) -> M6ReplayLockedExecutionResume:
        scope = self._controlled_scope(execution_scope)
        try:
            with SecureWorkspace(self._output_root, self._max_document_bytes) as workspace:
                pending = tuple(
                    self._read_redundant(
                        workspace,
                        _pending_relative(scope, index),
                        _pending_witness_relative(scope, index),
                        M6ReplayLockedPendingSampleCommitmentAuthority,
                    )
                    for index in range(len(scope.execution_dataset.entries))
                )
                records = tuple(
                    self._read_redundant(
                        workspace,
                        _record_relative(scope, index),
                        _record_witness_relative(scope, index),
                        M6ReplayLockedSampleExecutionRecord,
                    )
                    for index in range(len(scope.execution_dataset.entries))
                )
                seal = self._read_redundant(
                    workspace,
                    _seal_relative(scope),
                    _seal_witness_relative(scope),
                    M6ReplayLockedExecutionSealAuthority,
                )
        except M6ReplayLockedLedgerError:
            raise
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_TOO_LARGE":
                code = M6ReplayLockedLedgerFailureCode.DOCUMENT_TOO_LARGE
            else:
                code = M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED
            raise _error(code) from None
        except BudgetExceeded:
            raise _error(M6ReplayLockedLedgerFailureCode.DOCUMENT_TOO_LARGE) from None
        except ArtifactIntegrityViolation:
            raise _error(M6ReplayLockedLedgerFailureCode.DOCUMENT_INVALID) from None
        except Exception:
            raise _error(M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED) from None

        present_pending = self._require_prefix(pending)
        present_records = self._require_prefix(records)
        try:
            state = M6ReplayLockedExecutionResume(
                execution_scope=scope,
                pending_commitments=present_pending,
                sample_records=present_records,
                execution_seal=seal,
            )
        except (TypeError, ValueError):
            raise _error(M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH) from None
        self._require_resume_budget(state)
        return state

    def persist_pending(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        canonical_document: str,
    ) -> M6ReplayLockedExecutionResume:
        scope = self._controlled_scope(execution_scope)
        pending, payload = _canonical_payload(
            pending_commitment,
            M6ReplayLockedPendingSampleCommitmentAuthority,
            canonical_document,
            self._max_document_bytes,
        )
        state = self.resume(scope)
        sequence = pending.ledger_sequence
        if sequence < len(state.pending_commitments):
            if state.pending_commitments[sequence] == pending:
                return state
            _fail(M6ReplayLockedLedgerFailureCode.PENDING_CONFLICT)
        if state.status == M6ReplayLockedLedgerStatus.SEALED:
            _fail(M6ReplayLockedLedgerFailureCode.EXECUTION_SEALED)
        if (
            state.status != M6ReplayLockedLedgerStatus.READY_FOR_PENDING
            or sequence != state.next_ledger_sequence
            or pending.previous_ledger_entry_hash != state.ledger_head_hash
        ):
            _fail(M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH)
        try:
            tentative = M6ReplayLockedExecutionResume(
                execution_scope=scope,
                pending_commitments=(*state.pending_commitments, pending),
                sample_records=state.sample_records,
            )
        except (TypeError, ValueError):
            _fail(M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH)
        self._require_resume_budget(tentative)
        return self._publish_and_resume(
            scope,
            pending,
            payload,
            final_relative=_pending_relative(scope, sequence),
            witness_relative=_pending_witness_relative(scope, sequence),
            staged_label=f"pending-{sequence:06d}-{pending.pending_commitment_authority_id}",
            conflict_code=M6ReplayLockedLedgerFailureCode.PENDING_CONFLICT,
        )

    def append_record(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        sample_record: M6ReplayLockedSampleExecutionRecord,
        canonical_document: str,
    ) -> M6ReplayLockedExecutionResume:
        scope = self._controlled_scope(execution_scope)
        record, payload = _canonical_payload(
            sample_record,
            M6ReplayLockedSampleExecutionRecord,
            canonical_document,
            self._max_document_bytes,
        )
        state = self.resume(scope)
        sequence = record.ledger_sequence
        if sequence < len(state.sample_records):
            if state.sample_records[sequence] == record:
                return state
            _fail(M6ReplayLockedLedgerFailureCode.RECORD_CONFLICT)
        if state.status == M6ReplayLockedLedgerStatus.SEALED:
            _fail(M6ReplayLockedLedgerFailureCode.EXECUTION_SEALED)
        if (
            state.status != M6ReplayLockedLedgerStatus.PENDING
            or sequence != state.next_ledger_sequence
            or state.pending_commitments[-1] != record.pending_commitment
            or record.previous_ledger_entry_hash != state.ledger_head_hash
        ):
            _fail(M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH)
        try:
            tentative = M6ReplayLockedExecutionResume(
                execution_scope=scope,
                pending_commitments=state.pending_commitments,
                sample_records=(*state.sample_records, record),
            )
        except (TypeError, ValueError):
            _fail(M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH)
        self._require_resume_budget(tentative)
        return self._publish_and_resume(
            scope,
            record,
            payload,
            final_relative=_record_relative(scope, sequence),
            witness_relative=_record_witness_relative(scope, sequence),
            staged_label=f"record-{sequence:06d}-{record.sample_execution_record_id}",
            conflict_code=M6ReplayLockedLedgerFailureCode.RECORD_CONFLICT,
        )

    def seal(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        execution_seal: M6ReplayLockedExecutionSealAuthority,
        canonical_document: str,
    ) -> M6ReplayLockedExecutionResume:
        scope = self._controlled_scope(execution_scope)
        seal, payload = _canonical_payload(
            execution_seal,
            M6ReplayLockedExecutionSealAuthority,
            canonical_document,
            self._max_document_bytes,
        )
        state = self.resume(scope)
        if state.execution_seal is not None:
            if state.execution_seal == seal:
                return state
            _fail(M6ReplayLockedLedgerFailureCode.SEAL_CONFLICT)
        if (
            state.status != M6ReplayLockedLedgerStatus.READY_TO_SEAL
            or seal.execution_scope != scope
            or seal.sample_executions != state.sample_records
        ):
            _fail(M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH)
        try:
            M6ReplayLockedExecutionResume(
                execution_scope=scope,
                pending_commitments=state.pending_commitments,
                sample_records=state.sample_records,
                execution_seal=seal,
            )
        except (TypeError, ValueError):
            _fail(M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH)
        return self._publish_and_resume(
            scope,
            seal,
            payload,
            final_relative=_seal_relative(scope),
            witness_relative=_seal_witness_relative(scope),
            staged_label=f"seal-{seal.execution_seal_authority_id}",
            conflict_code=M6ReplayLockedLedgerFailureCode.SEAL_CONFLICT,
        )

    def _publish_and_resume(
        self,
        scope: M6ReplayLockedExecutionScopeAuthority,
        expected: BaseModel,
        payload: bytes,
        *,
        final_relative: str,
        witness_relative: str,
        staged_label: str,
        conflict_code: M6ReplayLockedLedgerFailureCode,
    ) -> M6ReplayLockedExecutionResume:
        staged_witness = _staged_relative(scope, f"{staged_label}-witness")
        staged_final = _staged_relative(scope, f"{staged_label}-primary")
        expected_sha256 = hashlib.sha256(payload).hexdigest()
        commit_attempted = False
        try:
            with SecureWorkspace(self._output_root, self._max_document_bytes) as workspace:
                self._ensure_directories(workspace, scope)
                self._create_or_verify(
                    workspace,
                    staged_witness,
                    payload,
                    expected_sha256,
                )
                self._create_or_verify(
                    workspace,
                    staged_final,
                    payload,
                    expected_sha256,
                )
                self._fault("after_staging")
                self._fault("before_commit")
                commit_attempted = True
                workspace.publish_staged(
                    staged_witness,
                    witness_relative,
                    expected_sha256,
                    remove_source_if_existing_equal=True,
                )
                workspace.publish_staged(
                    staged_final,
                    final_relative,
                    expected_sha256,
                    remove_source_if_existing_equal=True,
                )
                self._fault("after_commit")
        except Exception as error:
            recovered = self._recover_expected(scope, expected)
            if recovered is not None:
                return recovered
            if isinstance(error, M6ReplayLockedLedgerError):
                raise
            if isinstance(error, ArtifactConflict):
                code = conflict_code
            elif commit_attempted:
                code = M6ReplayLockedLedgerFailureCode.COMMIT_OUTCOME_UNKNOWN
            elif isinstance(error, PathBoundaryViolation) and error.reason_code == "FILE_TOO_LARGE":
                code = M6ReplayLockedLedgerFailureCode.DOCUMENT_TOO_LARGE
            else:
                code = M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED
            raise _error(code) from None
        recovered = self._recover_expected(scope, expected)
        if recovered is None:
            _fail(M6ReplayLockedLedgerFailureCode.COMMIT_OUTCOME_UNKNOWN)
        return recovered

    def _recover_expected(
        self,
        scope: M6ReplayLockedExecutionScopeAuthority,
        expected: BaseModel,
    ) -> M6ReplayLockedExecutionResume | None:
        deadline = time.monotonic() + _STAGING_READ_TIMEOUT_SECONDS
        while True:
            try:
                state = self.resume(scope)
            except M6ReplayLockedLedgerError:
                state = None
            if state is not None and self._state_contains(state, expected):
                return state
            if time.monotonic() >= deadline:
                return None
            time.sleep(_STAGING_READ_RETRY_SECONDS)

    @staticmethod
    def _state_contains(
        state: M6ReplayLockedExecutionResume,
        expected: BaseModel,
    ) -> bool:
        if isinstance(expected, M6ReplayLockedPendingSampleCommitmentAuthority):
            sequence = expected.ledger_sequence
            return (
                sequence < len(state.pending_commitments)
                and state.pending_commitments[sequence] == expected
            )
        if isinstance(expected, M6ReplayLockedSampleExecutionRecord):
            sequence = expected.ledger_sequence
            return (
                sequence < len(state.sample_records) and state.sample_records[sequence] == expected
            )
        if isinstance(expected, M6ReplayLockedExecutionSealAuthority):
            return state.execution_seal == expected
        return False

    @staticmethod
    def _require_prefix(values: tuple[_ModelT | None, ...]) -> tuple[_ModelT, ...]:
        present: list[_ModelT] = []
        missing = False
        for value in values:
            if value is None:
                missing = True
            elif missing:
                _fail(M6ReplayLockedLedgerFailureCode.CHAIN_MISMATCH)
            else:
                present.append(value)
        return tuple(present)

    def _read_optional(
        self,
        workspace: SecureWorkspace,
        relative: str,
        expected: type[_ModelT],
    ) -> _ModelT | None:
        try:
            first = workspace.read_verified(
                relative,
                max_bytes=self._max_document_bytes,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                return None
            raise
        second = workspace.read_verified(
            relative,
            first.sha256,
            max_bytes=first.size_bytes,
        )
        if second.bytes != first.bytes:
            _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_INVALID)
        try:
            document = first.bytes.decode("utf-8", errors="strict")
            value = expected.model_validate_json(first.bytes)
            if canonical_json(value.model_dump(mode="json")) != document:
                _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_INVALID)
            return value
        except M6ReplayLockedLedgerError:
            raise
        except (UnicodeDecodeError, TypeError, ValueError, ValidationError):
            raise _error(M6ReplayLockedLedgerFailureCode.DOCUMENT_INVALID) from None

    def _read_redundant(
        self,
        workspace: SecureWorkspace,
        primary_relative: str,
        witness_relative: str,
        expected: type[_ModelT],
    ) -> _ModelT | None:
        primary = self._read_optional(workspace, primary_relative, expected)
        witness = self._read_optional(workspace, witness_relative, expected)
        if primary is not None and witness is not None and primary != witness:
            _fail(M6ReplayLockedLedgerFailureCode.DOCUMENT_INVALID)
        return primary if primary is not None else witness

    @staticmethod
    def _ensure_directories(
        workspace: SecureWorkspace,
        scope: M6ReplayLockedExecutionScopeAuthority,
    ) -> None:
        base = _base(scope)
        witness_base = _witness_base(scope)
        staging_base = (
            f".staging/{_STORE_ROOT}/{scope.candidate_run_id}/{scope.execution_scope_authority_id}"
        )
        for directory in (
            ".staging",
            f".staging/{_STORE_ROOT}",
            f".staging/{_STORE_ROOT}/{scope.candidate_run_id}",
            staging_base,
            _STORE_ROOT,
            f"{_STORE_ROOT}/{scope.candidate_run_id}",
            base,
            f"{base}/pending",
            f"{base}/records",
            _WITNESS_ROOT,
            f"{_WITNESS_ROOT}/{scope.candidate_run_id}",
            witness_base,
            f"{witness_base}/pending",
            f"{witness_base}/records",
        ):
            workspace.ensure_private_directory(directory)

    @staticmethod
    def _create_or_verify(
        workspace: SecureWorkspace,
        relative: str,
        payload: bytes,
        expected_sha256: str,
    ) -> None:
        try:
            observed = workspace.create_new(relative, payload, expected_sha256)
        except ArtifactConflict:
            deadline = time.monotonic() + _STAGING_READ_TIMEOUT_SECONDS
            while True:
                try:
                    observed = workspace.read_verified(
                        relative,
                        expected_sha256,
                        max_bytes=len(payload),
                    )
                    break
                except ArtifactIntegrityViolation:
                    if time.monotonic() >= deadline:
                        _fail(M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED)
                    time.sleep(_STAGING_READ_RETRY_SECONDS)
                except PathBoundaryViolation as error:
                    if error.reason_code == "WINDOWS_OPEN_32" and time.monotonic() < deadline:
                        time.sleep(_STAGING_READ_RETRY_SECONDS)
                        continue
                    raise
        if observed.bytes != payload or observed.size_bytes != len(payload):
            _fail(M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED)

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)


__all__ = [
    "DEFAULT_M6_REPLAY_LOCKED_LEDGER_MAX_ENTRY_COUNT",
    "FilesystemM6ReplayLockedLedgerRepository",
    "M6ReplayLockedLedgerFaultInjector",
]
