"""Immutable publication of one additive CLOSED-policy execution scope."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import (
    MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
)
from labcourt.contracts.references import require_portable_run_id
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    PathBoundaryViolation,
)
from labcourt.ports.m6_replay_locked_closed_policy_execution_scope import (
    M6ReplayLockedClosedPolicyExecutionScopeFailureCode,
    M6ReplayLockedClosedPolicyExecutionScopeStoreError,
    M6StoredReplayLockedClosedPolicyExecutionScope,
)

from .secure_workspace import SecureWorkspace

M6ReplayLockedClosedPolicyExecutionScopeFaultInjector = Callable[[str], None]
_STORE_ROOT = "m6-replay-locked-closed-policy-execution-scopes"
_MAX_OUTPUT_ROOT_UTF8_BYTES = 32_768
_STAGING_READ_TIMEOUT_SECONDS = 1.0
_STAGING_READ_RETRY_SECONDS = 0.005

_FailureCode = M6ReplayLockedClosedPolicyExecutionScopeFailureCode


def _error(code: _FailureCode) -> M6ReplayLockedClosedPolicyExecutionScopeStoreError:
    return M6ReplayLockedClosedPolicyExecutionScopeStoreError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _require_run_id(value: object) -> str:
    try:
        if not isinstance(value, str):
            raise TypeError
        return require_portable_run_id(value, "M6 CLOSED-policy scope candidate run_id")
    except (TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)


def _require_sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    return value


def _controlled_output_root(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        raw = str(value)
        if (
            not raw
            or "\x00" in raw
            or len(raw.encode("utf-8", errors="strict")) > _MAX_OUTPUT_ROOT_UTF8_BYTES
        ):
            _fail(_FailureCode.INVALID_ARGUMENT)
        return Path(raw).absolute()
    except M6ReplayLockedClosedPolicyExecutionScopeStoreError:
        raise
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)


def _preflight_output_root(root: Path, max_document_bytes: int) -> None:
    try:
        with SecureWorkspace(root, max_document_bytes):
            pass
    except Exception:
        raise _error(_FailureCode.STORAGE_REJECTED) from None


def _final_relative(candidate_run_id: str) -> str:
    return f"{_STORE_ROOT}/{candidate_run_id}/scope.json"


def _staged_relative(candidate_run_id: str, scope_id: str) -> str:
    return f".staging/{_STORE_ROOT}/{candidate_run_id}/{scope_id}.json"


def _canonical_stored(
    scope: object,
    canonical_document: object,
    *,
    max_document_bytes: int,
) -> M6StoredReplayLockedClosedPolicyExecutionScope:
    if (
        type(scope) is not M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2
        or not isinstance(canonical_document, str)
        or not canonical_document
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        payload = canonical_document.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail(_FailureCode.DOCUMENT_INVALID)
    if len(payload) > max_document_bytes:
        _fail(_FailureCode.DOCUMENT_TOO_LARGE)
    try:
        controlled = M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2.model_validate(
            scope.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.DOCUMENT_INVALID)
    if controlled != scope or canonical_document != canonical_json(
        controlled.model_dump(mode="json")
    ):
        _fail(_FailureCode.DOCUMENT_INVALID)
    try:
        return M6StoredReplayLockedClosedPolicyExecutionScope(
            scope=controlled,
            canonical_document=canonical_document,
            content_sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
    except (TypeError, ValueError):
        _fail(_FailureCode.DOCUMENT_INVALID)


class ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore:
    def __init__(
        self,
        output_root: str | Path,
        *,
        max_document_bytes: int = MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
    ) -> None:
        if (
            not isinstance(max_document_bytes, int)
            or isinstance(max_document_bytes, bool)
            or max_document_bytes <= 0
            or max_document_bytes > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
        ):
            _fail(_FailureCode.INVALID_ARGUMENT)
        self._output_root = _controlled_output_root(output_root)
        self._max_document_bytes = max_document_bytes
        _preflight_output_root(self._output_root, self._max_document_bytes)

    def load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6StoredReplayLockedClosedPolicyExecutionScope:
        run_id = _require_run_id(candidate_run_id)
        scope_id = _require_sha256(execution_scope_authority_id)
        relative = _final_relative(run_id)
        try:
            with SecureWorkspace(self._output_root, self._max_document_bytes) as workspace:
                first = workspace.read_verified(
                    relative,
                    max_bytes=self._max_document_bytes,
                )
                second = workspace.read_verified(
                    relative,
                    first.sha256,
                    max_bytes=first.size_bytes,
                )
                if second.bytes != first.bytes:
                    _fail(_FailureCode.IDENTITY_MISMATCH)
        except M6ReplayLockedClosedPolicyExecutionScopeStoreError:
            raise
        except PathBoundaryViolation as exc:
            if exc.reason_code == "FILE_MISSING":
                code = _FailureCode.SCOPE_NOT_FOUND
            elif exc.reason_code == "FILE_TOO_LARGE":
                code = _FailureCode.DOCUMENT_TOO_LARGE
            else:
                code = _FailureCode.STORAGE_REJECTED
            raise _error(code) from None
        except ArtifactIntegrityViolation:
            raise _error(_FailureCode.IDENTITY_MISMATCH) from None
        except BudgetExceeded:
            raise _error(_FailureCode.DOCUMENT_TOO_LARGE) from None
        except Exception:
            raise _error(_FailureCode.STORAGE_REJECTED) from None

        try:
            document = first.bytes.decode("utf-8", errors="strict")
            scope = M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2.model_validate_json(
                first.bytes
            )
            if (
                scope.candidate_run_id != run_id
                or scope.execution_scope_authority_id != scope_id
                or canonical_json(scope.model_dump(mode="json")) != document
            ):
                _fail(_FailureCode.IDENTITY_MISMATCH)
            return M6StoredReplayLockedClosedPolicyExecutionScope(
                scope=scope,
                canonical_document=document,
                content_sha256=first.sha256,
                size_bytes=first.size_bytes,
            )
        except M6ReplayLockedClosedPolicyExecutionScopeStoreError:
            raise
        except (UnicodeDecodeError, TypeError, ValueError, ValidationError):
            raise _error(_FailureCode.DOCUMENT_INVALID) from None


class M6ReplayLockedClosedPolicyExecutionScopePublisher:
    def __init__(
        self,
        output_root: str | Path,
        *,
        fault_injector: M6ReplayLockedClosedPolicyExecutionScopeFaultInjector | None = None,
        max_document_bytes: int = MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
    ) -> None:
        if (
            not isinstance(max_document_bytes, int)
            or isinstance(max_document_bytes, bool)
            or max_document_bytes <= 0
            or max_document_bytes > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
        ):
            _fail(_FailureCode.INVALID_ARGUMENT)
        if fault_injector is not None and not callable(fault_injector):
            _fail(_FailureCode.INVALID_ARGUMENT)
        self._output_root = _controlled_output_root(output_root)
        self._fault_injector = fault_injector
        self._max_document_bytes = max_document_bytes
        _preflight_output_root(self._output_root, self._max_document_bytes)

    def publish(
        self,
        scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        canonical_document: str,
    ) -> M6StoredReplayLockedClosedPolicyExecutionScope:
        stored = _canonical_stored(
            scope,
            canonical_document,
            max_document_bytes=self._max_document_bytes,
        )
        run_id = stored.scope.candidate_run_id
        scope_id = stored.scope.execution_scope_authority_id
        staged = _staged_relative(run_id, scope_id)
        final = _final_relative(run_id)
        payload = stored.canonical_document.encode("utf-8")
        commit_attempted = False
        try:
            with SecureWorkspace(self._output_root, self._max_document_bytes) as workspace:
                self._ensure_directories(workspace, run_id)
                self._create_or_verify(workspace, staged, payload, stored.content_sha256)
                self._fault("after_staging")
                self._fault("before_commit")
                commit_attempted = True
                workspace.publish_staged(
                    staged,
                    final,
                    stored.content_sha256,
                    remove_source_if_existing_equal=True,
                )
                self._fault("after_commit")
        except Exception as exc:
            recovered = self._recover_exact(stored)
            if (
                recovered is None
                and commit_attempted
                and isinstance(exc, PathBoundaryViolation)
                and exc.reason_code
                in {
                    "SOURCE_OR_PARENT_MISSING",
                    "WINDOWS_OPEN_32",
                    "WINDOWS_OPEN_33",
                }
            ):
                recovered = self._recover_exact_until(stored)
            if recovered is not None:
                return recovered
            if isinstance(exc, M6ReplayLockedClosedPolicyExecutionScopeStoreError):
                raise
            if isinstance(exc, ArtifactConflict):
                code = _FailureCode.SCOPE_CONFLICT
            elif commit_attempted:
                code = _FailureCode.COMMIT_OUTCOME_UNKNOWN
            elif isinstance(exc, PathBoundaryViolation) and exc.reason_code == "FILE_TOO_LARGE":
                code = _FailureCode.DOCUMENT_TOO_LARGE
            else:
                code = _FailureCode.STORAGE_REJECTED
            raise _error(code) from None
        return stored

    @staticmethod
    def _ensure_directories(workspace: SecureWorkspace, candidate_run_id: str) -> None:
        for directory in (
            ".staging",
            f".staging/{_STORE_ROOT}",
            f".staging/{_STORE_ROOT}/{candidate_run_id}",
            _STORE_ROOT,
            f"{_STORE_ROOT}/{candidate_run_id}",
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
                        _fail(_FailureCode.STORAGE_REJECTED)
                    time.sleep(_STAGING_READ_RETRY_SECONDS)
                except PathBoundaryViolation as error:
                    if error.reason_code == "WINDOWS_OPEN_32" and time.monotonic() < deadline:
                        time.sleep(_STAGING_READ_RETRY_SECONDS)
                        continue
                    raise
        if observed.bytes != payload or observed.size_bytes != len(payload):
            _fail(_FailureCode.SCOPE_CONFLICT)

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)

    def _recover_exact(
        self,
        expected: M6StoredReplayLockedClosedPolicyExecutionScope,
    ) -> M6StoredReplayLockedClosedPolicyExecutionScope | None:
        try:
            observed = ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore(
                self._output_root,
                max_document_bytes=self._max_document_bytes,
            ).load(
                expected.scope.candidate_run_id,
                expected.scope.execution_scope_authority_id,
            )
        except M6ReplayLockedClosedPolicyExecutionScopeStoreError:
            return None
        return observed if observed == expected else None

    def _recover_exact_until(
        self,
        expected: M6StoredReplayLockedClosedPolicyExecutionScope,
    ) -> M6StoredReplayLockedClosedPolicyExecutionScope | None:
        deadline = time.monotonic() + _STAGING_READ_TIMEOUT_SECONDS
        while True:
            recovered = self._recover_exact(expected)
            if recovered is not None or time.monotonic() >= deadline:
                return recovered
            time.sleep(_STAGING_READ_RETRY_SECONDS)


__all__ = [
    "M6ReplayLockedClosedPolicyExecutionScopeFaultInjector",
    "M6ReplayLockedClosedPolicyExecutionScopePublisher",
    "ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore",
]
