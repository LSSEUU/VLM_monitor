"""Durable publication and exact loading boundary for the M6 source catalog."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
)
from labcourt.exceptions import ContractViolation

MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES = 256 * 1024 * 1024


class M6RegressionExecutionSourceCatalogFailureCode(StrEnum):
    """Controlled failures without catalog payloads or physical host details."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    CATALOG_NOT_FOUND = "CATALOG_NOT_FOUND"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    CATALOG_CONFLICT = "CATALOG_CONFLICT"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6RegressionExecutionSourceCatalogError(ContractViolation):
    """Typed, payload-free failure at the durable source-catalog boundary."""

    def __init__(
        self,
        reason_code: M6RegressionExecutionSourceCatalogFailureCode,
    ) -> None:
        if not isinstance(reason_code, M6RegressionExecutionSourceCatalogFailureCode):
            raise TypeError("reason_code must be an M6RegressionExecutionSourceCatalogFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 regression execution source catalog failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class M6StoredRegressionExecutionSourceCatalog:
    """One canonical, content-verified candidate-safe source catalog."""

    source_catalog: M6RegressionExecutionSourceCatalogAuthority
    canonical_document: str
    content_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if type(self.source_catalog) is not M6RegressionExecutionSourceCatalogAuthority:
            raise TypeError("source_catalog must be an exact typed M6 source catalog")
        try:
            controlled = M6RegressionExecutionSourceCatalogAuthority.model_validate(
                self.source_catalog.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
        except (AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise ValueError("source_catalog must be canonical") from exc
        if controlled != self.source_catalog:
            raise ValueError("source_catalog must be canonical")
        expected_document = canonical_json(controlled.model_dump(mode="json"))
        if not isinstance(self.canonical_document, str) or not self.canonical_document:
            raise TypeError("canonical_document must be non-empty text")
        if self.canonical_document != expected_document:
            raise ValueError("canonical_document differs from the typed source catalog")
        payload = self.canonical_document.encode("utf-8")
        if len(payload) > MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES:
            raise ValueError("canonical_document exceeds the source-catalog byte budget")
        expected_sha256 = hashlib.sha256(payload).hexdigest()
        if self.content_sha256 != expected_sha256:
            raise ValueError("content_sha256 differs from the canonical document")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes <= 0
            or self.size_bytes != len(payload)
        ):
            raise ValueError("size_bytes differs from the canonical document")


@runtime_checkable
class M6RegressionExecutionSourceCatalogPublisher(Protocol):
    """Publish one canonical catalog before its execution scope is committed."""

    def publish(
        self,
        catalog: M6RegressionExecutionSourceCatalogAuthority,
        canonical_document: str,
    ) -> M6StoredRegressionExecutionSourceCatalog: ...


@runtime_checkable
class M6RegressionExecutionSourceCatalogProvider(Protocol):
    """Load one catalog by both identities without scanning for alternatives."""

    def load(
        self,
        source_catalog_authority_id: str,
        source_catalog_document_sha256: str,
    ) -> M6StoredRegressionExecutionSourceCatalog: ...


__all__ = [
    "MAX_M6_REGRESSION_EXECUTION_SOURCE_CATALOG_BYTES",
    "M6RegressionExecutionSourceCatalogError",
    "M6RegressionExecutionSourceCatalogFailureCode",
    "M6RegressionExecutionSourceCatalogProvider",
    "M6RegressionExecutionSourceCatalogPublisher",
    "M6StoredRegressionExecutionSourceCatalog",
]
