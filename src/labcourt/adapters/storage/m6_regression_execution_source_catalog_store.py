"""Immutable local publication and exact loading of the blinded M6 catalog."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
)
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    PathBoundaryViolation,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES,
    M6RegressionExecutionSourceCatalogError,
    M6RegressionExecutionSourceCatalogFailureCode,
    M6StoredRegressionExecutionSourceCatalog,
)

from .secure_workspace import SecureWorkspace

M6RegressionExecutionSourceCatalogFaultInjector = Callable[[str], None]
_STORE_ROOT = "m6-regression-execution-source-catalogs"


def _error(
    code: M6RegressionExecutionSourceCatalogFailureCode,
) -> M6RegressionExecutionSourceCatalogError:
    return M6RegressionExecutionSourceCatalogError(code)


def _fail(code: M6RegressionExecutionSourceCatalogFailureCode) -> NoReturn:
    raise _error(code)


def _require_sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(M6RegressionExecutionSourceCatalogFailureCode.INVALID_ARGUMENT)
    return value


def _final_relative(authority_id: str, document_sha256: str) -> str:
    return f"{_STORE_ROOT}/{authority_id}/{document_sha256}.json"


def _staged_relative(authority_id: str, document_sha256: str) -> str:
    return f".staging/{_STORE_ROOT}/{authority_id}/{document_sha256}.json"


def _canonical_stored(
    catalog: object,
    canonical_document: object,
    *,
    max_document_bytes: int,
) -> M6StoredRegressionExecutionSourceCatalog:
    if (
        type(catalog) is not M6RegressionExecutionSourceCatalogAuthority
        or not isinstance(canonical_document, str)
        or not canonical_document
    ):
        _fail(M6RegressionExecutionSourceCatalogFailureCode.INVALID_ARGUMENT)
    payload = canonical_document.encode("utf-8")
    if len(payload) > max_document_bytes:
        _fail(M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE)
    try:
        controlled = M6RegressionExecutionSourceCatalogAuthority.model_validate(
            catalog.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_INVALID)
    if controlled != catalog or canonical_document != canonical_json(
        controlled.model_dump(mode="json")
    ):
        _fail(M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_INVALID)
    content_sha256 = hashlib.sha256(payload).hexdigest()
    try:
        return M6StoredRegressionExecutionSourceCatalog(
            source_catalog=controlled,
            canonical_document=canonical_document,
            content_sha256=content_sha256,
            size_bytes=len(payload),
        )
    except (TypeError, ValueError):
        _fail(M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_INVALID)


class ReadonlyM6RegressionExecutionSourceCatalogStore:
    """Load exactly one catalog from the two identities fixed in a run scope."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        max_document_bytes: int = MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES,
    ) -> None:
        if (
            not isinstance(max_document_bytes, int)
            or isinstance(max_document_bytes, bool)
            or max_document_bytes <= 0
            or max_document_bytes > MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES
        ):
            raise ValueError("max_document_bytes is outside the source-catalog budget")
        self._output_root = Path(output_root).absolute()
        self._max_document_bytes = max_document_bytes

    def load(
        self,
        source_catalog_authority_id: str,
        source_catalog_document_sha256: str,
    ) -> M6StoredRegressionExecutionSourceCatalog:
        authority_id = _require_sha256(source_catalog_authority_id)
        document_sha256 = _require_sha256(source_catalog_document_sha256)
        relative = _final_relative(authority_id, document_sha256)
        try:
            with SecureWorkspace(
                self._output_root,
                self._max_document_bytes,
            ) as workspace:
                first = workspace.read_verified(
                    relative,
                    document_sha256,
                    max_bytes=self._max_document_bytes,
                )
                second = workspace.read_verified(
                    relative,
                    first.sha256,
                    max_bytes=first.size_bytes,
                )
                if second.bytes != first.bytes:
                    _fail(M6RegressionExecutionSourceCatalogFailureCode.IDENTITY_MISMATCH)
        except M6RegressionExecutionSourceCatalogError:
            raise
        except PathBoundaryViolation as exc:
            if exc.reason_code == "FILE_MISSING":
                code = M6RegressionExecutionSourceCatalogFailureCode.CATALOG_NOT_FOUND
            elif exc.reason_code == "FILE_TOO_LARGE":
                code = M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE
            else:
                code = M6RegressionExecutionSourceCatalogFailureCode.STORAGE_REJECTED
            raise _error(code) from exc
        except ArtifactIntegrityViolation as exc:
            raise _error(M6RegressionExecutionSourceCatalogFailureCode.IDENTITY_MISMATCH) from exc
        except BudgetExceeded as exc:
            raise _error(M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE) from exc
        except Exception as exc:
            raise _error(M6RegressionExecutionSourceCatalogFailureCode.STORAGE_REJECTED) from exc

        try:
            document = first.bytes.decode("utf-8")
            catalog = M6RegressionExecutionSourceCatalogAuthority.model_validate_json(first.bytes)
            if (
                catalog.source_catalog_authority_id != authority_id
                or first.sha256 != document_sha256
            ):
                _fail(M6RegressionExecutionSourceCatalogFailureCode.IDENTITY_MISMATCH)
            if canonical_json(catalog.model_dump(mode="json")) != document:
                _fail(M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_INVALID)
            return M6StoredRegressionExecutionSourceCatalog(
                source_catalog=catalog,
                canonical_document=document,
                content_sha256=first.sha256,
                size_bytes=first.size_bytes,
            )
        except M6RegressionExecutionSourceCatalogError:
            raise
        except (UnicodeDecodeError, TypeError, ValueError, ValidationError) as exc:
            raise _error(M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_INVALID) from exc


class M6RegressionExecutionSourceCatalogPublisher:
    """Atomically publish one content-addressed catalog before execution begins."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        fault_injector: M6RegressionExecutionSourceCatalogFaultInjector | None = None,
        max_document_bytes: int = MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES,
    ) -> None:
        if (
            not isinstance(max_document_bytes, int)
            or isinstance(max_document_bytes, bool)
            or max_document_bytes <= 0
            or max_document_bytes > MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES
        ):
            raise ValueError("max_document_bytes is outside the source-catalog budget")
        self._output_root = Path(output_root).absolute()
        self._fault_injector = fault_injector
        self._max_document_bytes = max_document_bytes
        try:
            self._output_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise _error(M6RegressionExecutionSourceCatalogFailureCode.STORAGE_REJECTED) from exc

    def publish(
        self,
        catalog: M6RegressionExecutionSourceCatalogAuthority,
        canonical_document: str,
    ) -> M6StoredRegressionExecutionSourceCatalog:
        stored = _canonical_stored(
            catalog,
            canonical_document,
            max_document_bytes=self._max_document_bytes,
        )
        authority_id = stored.source_catalog.source_catalog_authority_id
        document_sha256 = stored.content_sha256
        staged = _staged_relative(authority_id, document_sha256)
        final = _final_relative(authority_id, document_sha256)
        payload = stored.canonical_document.encode("utf-8")
        commit_attempted = False
        try:
            with SecureWorkspace(
                self._output_root,
                self._max_document_bytes,
            ) as workspace:
                self._ensure_directories(workspace, authority_id)
                self._create_or_verify(workspace, staged, payload, document_sha256)
                self._fault("after_staging")
                self._fault("before_commit")
                commit_attempted = True
                workspace.publish_staged(staged, final, document_sha256)
                self._fault("after_commit")
        except Exception as exc:
            recovered = self._recover_exact(stored)
            if recovered is not None:
                return recovered
            if isinstance(exc, M6RegressionExecutionSourceCatalogError):
                raise
            if isinstance(exc, ArtifactConflict):
                code = M6RegressionExecutionSourceCatalogFailureCode.CATALOG_CONFLICT
            elif commit_attempted:
                code = M6RegressionExecutionSourceCatalogFailureCode.COMMIT_OUTCOME_UNKNOWN
            elif isinstance(exc, PathBoundaryViolation) and exc.reason_code == "FILE_TOO_LARGE":
                code = M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE
            else:
                code = M6RegressionExecutionSourceCatalogFailureCode.STORAGE_REJECTED
            raise _error(code) from exc
        return stored

    @staticmethod
    def _ensure_directories(workspace: SecureWorkspace, authority_id: str) -> None:
        directories = (
            ".staging",
            f".staging/{_STORE_ROOT}",
            f".staging/{_STORE_ROOT}/{authority_id}",
            _STORE_ROOT,
            f"{_STORE_ROOT}/{authority_id}",
        )
        for directory in directories:
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
            try:
                observed = workspace.read_verified(
                    relative,
                    expected_sha256,
                    max_bytes=len(payload),
                )
            except Exception:
                _fail(M6RegressionExecutionSourceCatalogFailureCode.CATALOG_CONFLICT)
        if observed.bytes != payload or observed.size_bytes != len(payload):
            _fail(M6RegressionExecutionSourceCatalogFailureCode.CATALOG_CONFLICT)

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)

    def _recover_exact(
        self,
        expected: M6StoredRegressionExecutionSourceCatalog,
    ) -> M6StoredRegressionExecutionSourceCatalog | None:
        try:
            observed = ReadonlyM6RegressionExecutionSourceCatalogStore(
                self._output_root,
                max_document_bytes=self._max_document_bytes,
            ).load(
                expected.source_catalog.source_catalog_authority_id,
                expected.content_sha256,
            )
        except M6RegressionExecutionSourceCatalogError:
            return None
        return observed if observed == expected else None


__all__ = [
    "M6RegressionExecutionSourceCatalogFaultInjector",
    "M6RegressionExecutionSourceCatalogPublisher",
    "ReadonlyM6RegressionExecutionSourceCatalogStore",
]
