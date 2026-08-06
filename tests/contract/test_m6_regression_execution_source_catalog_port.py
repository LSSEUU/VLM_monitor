from __future__ import annotations

import hashlib
import inspect
from dataclasses import FrozenInstanceError

import pytest

from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
)
from labcourt.ports import (
    M6RegressionExecutionSourceCatalogError,
    M6RegressionExecutionSourceCatalogFailureCode,
    M6RegressionExecutionSourceCatalogProvider,
    M6RegressionExecutionSourceCatalogPublisher,
    M6StoredRegressionExecutionSourceCatalog,
)
from tests.contract.test_m6_regression_dataset_authority_contracts import _bundle


class _StructuralSourceCatalogPublisher:
    def publish(
        self,
        catalog: M6RegressionExecutionSourceCatalogAuthority,
        canonical_document: str,
    ) -> M6StoredRegressionExecutionSourceCatalog:
        del catalog, canonical_document
        raise AssertionError("structural port check must not invoke the publisher")


class _StructuralSourceCatalogProvider:
    def load(
        self,
        source_catalog_authority_id: str,
        source_catalog_document_sha256: str,
    ) -> M6StoredRegressionExecutionSourceCatalog:
        del source_catalog_authority_id, source_catalog_document_sha256
        raise AssertionError("structural port check must not invoke the provider")


class _MissingSourceCatalogBoundary:
    pass


def _stored() -> M6StoredRegressionExecutionSourceCatalog:
    bundle = _bundle()
    document = bundle.execution_source_catalog_document
    payload = document.encode("utf-8")
    return M6StoredRegressionExecutionSourceCatalog(
        source_catalog=bundle.execution_source_catalog,
        canonical_document=document,
        content_sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
    )


def test_source_catalog_publication_and_load_signatures_are_stable() -> None:
    publish = M6RegressionExecutionSourceCatalogPublisher.publish
    assert tuple(inspect.signature(publish).parameters) == (
        "self",
        "catalog",
        "canonical_document",
    )
    assert inspect.get_annotations(publish, eval_str=True) == {
        "catalog": M6RegressionExecutionSourceCatalogAuthority,
        "canonical_document": str,
        "return": M6StoredRegressionExecutionSourceCatalog,
    }

    load = M6RegressionExecutionSourceCatalogProvider.load
    assert tuple(inspect.signature(load).parameters) == (
        "self",
        "source_catalog_authority_id",
        "source_catalog_document_sha256",
    )
    assert inspect.get_annotations(load, eval_str=True) == {
        "source_catalog_authority_id": str,
        "source_catalog_document_sha256": str,
        "return": M6StoredRegressionExecutionSourceCatalog,
    }


def test_source_catalog_boundaries_are_runtime_checkable_by_structure() -> None:
    assert isinstance(
        _StructuralSourceCatalogPublisher(),
        M6RegressionExecutionSourceCatalogPublisher,
    )
    assert isinstance(
        _StructuralSourceCatalogProvider(),
        M6RegressionExecutionSourceCatalogProvider,
    )
    assert not isinstance(
        _MissingSourceCatalogBoundary(),
        M6RegressionExecutionSourceCatalogPublisher,
    )
    assert not isinstance(
        _MissingSourceCatalogBoundary(),
        M6RegressionExecutionSourceCatalogProvider,
    )


def test_source_catalog_failure_codes_are_stable_and_payload_free() -> None:
    assert {item.value for item in M6RegressionExecutionSourceCatalogFailureCode} == {
        "INVALID_ARGUMENT",
        "CATALOG_NOT_FOUND",
        "DOCUMENT_TOO_LARGE",
        "DOCUMENT_INVALID",
        "IDENTITY_MISMATCH",
        "CATALOG_CONFLICT",
        "COMMIT_OUTCOME_UNKNOWN",
        "STORAGE_REJECTED",
    }
    error = M6RegressionExecutionSourceCatalogError(
        M6RegressionExecutionSourceCatalogFailureCode.IDENTITY_MISMATCH
    )
    assert error.args == ("M6 regression execution source catalog failed: IDENTITY_MISMATCH",)
    assert vars(error) == {"reason_code": error.reason_code}
    assert not hasattr(error, "payload")

    with pytest.raises(TypeError, match="reason_code"):
        M6RegressionExecutionSourceCatalogError(  # type: ignore[arg-type]
            "IDENTITY_MISMATCH"
        )


def test_stored_source_catalog_is_frozen_and_binds_exact_canonical_bytes() -> None:
    stored = _stored()
    assert stored.source_catalog.source_catalog_authority_id
    assert stored.size_bytes == len(stored.canonical_document.encode("utf-8"))
    assert (
        stored.content_sha256
        == hashlib.sha256(stored.canonical_document.encode("utf-8")).hexdigest()
    )

    with pytest.raises(FrozenInstanceError):
        stored.size_bytes = 1  # type: ignore[misc]
    with pytest.raises(ValueError, match="typed source catalog"):
        M6StoredRegressionExecutionSourceCatalog(
            source_catalog=stored.source_catalog,
            canonical_document=stored.canonical_document + " ",
            content_sha256=stored.content_sha256,
            size_bytes=stored.size_bytes + 1,
        )
    with pytest.raises(ValueError, match="content_sha256"):
        M6StoredRegressionExecutionSourceCatalog(
            source_catalog=stored.source_catalog,
            canonical_document=stored.canonical_document,
            content_sha256="f" * 64,
            size_bytes=stored.size_bytes,
        )
    with pytest.raises(ValueError, match="size_bytes"):
        M6StoredRegressionExecutionSourceCatalog(
            source_catalog=stored.source_catalog,
            canonical_document=stored.canonical_document,
            content_sha256=stored.content_sha256,
            size_bytes=stored.size_bytes + 1,
        )
