"""Bind one blinded M6 execution source catalog to its durable run scope."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_regression_execution_source_catalog import (
    MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6RegressionExecutionSourceCatalogBindingErrorCode(StrEnum):
    """Closed, payload-free failures for the candidate catalog trust join."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    SCOPE_BINDING_MISMATCH = "SCOPE_BINDING_MISMATCH"
    ENTRY_CLOSURE_MISMATCH = "ENTRY_CLOSURE_MISMATCH"


class M6RegressionExecutionSourceCatalogBindingError(LabCourtError):
    """The catalog could not be proven to be the scope's complete input closure."""

    def __init__(
        self,
        code: M6RegressionExecutionSourceCatalogBindingErrorCode,
    ) -> None:
        if not isinstance(code, M6RegressionExecutionSourceCatalogBindingErrorCode):
            raise TypeError("code must be an M6RegressionExecutionSourceCatalogBindingErrorCode")
        self.code = code
        super().__init__(f"M6 execution source catalog binding failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6BoundRegressionExecutionSourceCatalog:
    """Canonical catalog proven against one immutable execution start cut."""

    execution_scope_authority_id: str
    execution_dataset_snapshot_id: str
    execution_source_catalog: M6RegressionExecutionSourceCatalogAuthority
    execution_source_catalog_document: str
    execution_source_catalog_content_sha256: str
    execution_source_catalog_size_bytes: int


def _fail(code: M6RegressionExecutionSourceCatalogBindingErrorCode) -> NoReturn:
    raise M6RegressionExecutionSourceCatalogBindingError(code)


def _canonical_model(value: object, expected: type[_ModelT]) -> _ModelT:
    if not isinstance(value, expected):
        _fail(M6RegressionExecutionSourceCatalogBindingErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6RegressionExecutionSourceCatalogBindingErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6RegressionExecutionSourceCatalogBindingErrorCode.INVALID_ARGUMENT)
    return controlled


def bind_m6_regression_execution_source_catalog(
    *,
    execution_scope: object,
    execution_source_catalog: object,
    execution_source_catalog_document: object,
) -> M6BoundRegressionExecutionSourceCatalog:
    """Require the catalog and scope datasets to be exact, bidirectional peers."""

    scope = _canonical_model(execution_scope, M6UpgradeExecutionScopeAuthority)
    catalog = _canonical_model(
        execution_source_catalog,
        M6RegressionExecutionSourceCatalogAuthority,
    )
    if not isinstance(execution_source_catalog_document, str):
        _fail(M6RegressionExecutionSourceCatalogBindingErrorCode.INVALID_ARGUMENT)
    document = execution_source_catalog_document
    payload = document.encode("utf-8")
    if len(payload) > MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES:
        _fail(M6RegressionExecutionSourceCatalogBindingErrorCode.DOCUMENT_TOO_LARGE)
    if document != canonical_json(catalog.model_dump(mode="json")):
        _fail(M6RegressionExecutionSourceCatalogBindingErrorCode.DOCUMENT_INVALID)
    content_sha256 = hashlib.sha256(payload).hexdigest()

    dataset = scope.execution_dataset
    if (
        dataset.baseline_manifest_id != catalog.baseline_manifest_id
        or dataset.source_catalog_authority_id != catalog.source_catalog_authority_id
        or dataset.source_catalog_document_sha256 != content_sha256
        or dataset.entry_count != catalog.entry_count
        or catalog.source_inventory_item_count != dataset.entry_count
    ):
        _fail(M6RegressionExecutionSourceCatalogBindingErrorCode.SCOPE_BINDING_MISMATCH)

    for execution_entry, catalog_entry in zip(
        dataset.entries,
        catalog.entries,
        strict=True,
    ):
        closure = catalog_entry.replay_input_closure
        if (
            execution_entry.sample_id != catalog_entry.sample_id
            or execution_entry.input_authority_id != catalog_entry.input_authority_id
            or execution_entry.input_authority_document_sha256
            != catalog_entry.input_authority_document_sha256
            or execution_entry.replay_input_closure_authority_id
            != closure.replay_input_closure_authority_id
            or execution_entry.replay_input_closure_document_sha256
            != closure.replay_input_closure_document_sha256
        ):
            _fail(M6RegressionExecutionSourceCatalogBindingErrorCode.ENTRY_CLOSURE_MISMATCH)

    return M6BoundRegressionExecutionSourceCatalog(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        execution_source_catalog=catalog,
        execution_source_catalog_document=document,
        execution_source_catalog_content_sha256=content_sha256,
        execution_source_catalog_size_bytes=len(payload),
    )


__all__ = [
    "MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES",
    "M6BoundRegressionExecutionSourceCatalog",
    "M6RegressionExecutionSourceCatalogBindingError",
    "M6RegressionExecutionSourceCatalogBindingErrorCode",
    "bind_m6_regression_execution_source_catalog",
]
