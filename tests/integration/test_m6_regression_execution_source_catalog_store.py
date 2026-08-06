from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_regression_execution_source_catalog_store import (
    M6RegressionExecutionSourceCatalogPublisher,
    ReadonlyM6RegressionExecutionSourceCatalogStore,
)
from labcourt.application.m6_regression_source_catalog import (
    M6RegressionSourceCatalogBundle,
    build_m6_regression_source_catalog,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogError,
    M6RegressionExecutionSourceCatalogFailureCode,
    M6StoredRegressionExecutionSourceCatalog,
)
from tests.unit.test_m6_regression_source_catalog import _sealed_source


def _catalog(sample_seed: str = "opaque-sample") -> M6RegressionSourceCatalogBundle:
    scope, source = _sealed_source(sample_seed)
    return build_m6_regression_source_catalog(
        run_scopes=(scope,),
        sealed_sources=(source,),
    )


def _expected(bundle: M6RegressionSourceCatalogBundle) -> M6StoredRegressionExecutionSourceCatalog:
    document = bundle.execution_source_catalog_document
    payload = document.encode("utf-8")
    return M6StoredRegressionExecutionSourceCatalog(
        source_catalog=bundle.execution_source_catalog,
        canonical_document=document,
        content_sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
    )


def _load(
    root: Path,
    bundle: M6RegressionSourceCatalogBundle,
) -> M6StoredRegressionExecutionSourceCatalog:
    return ReadonlyM6RegressionExecutionSourceCatalogStore(root).load(
        bundle.execution_source_catalog.source_catalog_authority_id,
        bundle.execution_source_catalog_content_sha256,
    )


def _final_catalog_path(root: Path) -> Path:
    final_files = tuple(
        path for path in root.rglob("*.json") if ".staging" not in path.relative_to(root).parts
    )
    assert len(final_files) == 1
    return final_files[0]


def _path_for_identities(
    root: Path,
    published_path: Path,
    *,
    source_authority_id: str,
    target_authority_id: str,
    source_document_sha256: str,
    target_document_sha256: str,
) -> Path:
    relative = published_path.relative_to(root)
    replaced = tuple(
        part.replace(source_authority_id, target_authority_id).replace(
            source_document_sha256,
            target_document_sha256,
        )
        for part in relative.parts
    )
    return root.joinpath(*replaced)


def _write_identity_alias(
    root: Path,
    published_path: Path,
    payload: bytes,
    *,
    source_authority_id: str,
    target_authority_id: str,
    source_document_sha256: str,
    target_document_sha256: str,
) -> Path:
    target = _path_for_identities(
        root,
        published_path,
        source_authority_id=source_authority_id,
        target_authority_id=target_authority_id,
        source_document_sha256=source_document_sha256,
        target_document_sha256=target_document_sha256,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return target


def test_publishes_exactly_once_and_loads_by_both_catalog_identities(
    tmp_path: Path,
) -> None:
    bundle = _catalog()
    expected = _expected(bundle)
    publisher = M6RegressionExecutionSourceCatalogPublisher(tmp_path)

    first = publisher.publish(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_document,
    )
    second = publisher.publish(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_document,
    )

    assert first == second == expected
    assert _load(tmp_path, bundle) == expected
    assert _final_catalog_path(tmp_path).read_text(encoding="utf-8") == (
        bundle.execution_source_catalog_document
    )


@pytest.mark.parametrize("phase", ("after_staging", "before_commit"))
def test_fault_before_commit_is_not_loadable_and_exact_retry_succeeds(
    tmp_path: Path,
    phase: str,
) -> None:
    bundle = _catalog()

    def fault(observed: str) -> None:
        if observed == phase:
            raise RuntimeError(f"fault:{phase}")

    with pytest.raises(M6RegressionExecutionSourceCatalogError):
        M6RegressionExecutionSourceCatalogPublisher(
            tmp_path,
            fault_injector=fault,
        ).publish(
            bundle.execution_source_catalog,
            bundle.execution_source_catalog_document,
        )
    with pytest.raises(M6RegressionExecutionSourceCatalogError) as missing:
        _load(tmp_path, bundle)
    assert missing.value.reason_code == (
        M6RegressionExecutionSourceCatalogFailureCode.CATALOG_NOT_FOUND
    )

    assert M6RegressionExecutionSourceCatalogPublisher(tmp_path).publish(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_document,
    ) == _expected(bundle)
    assert _load(tmp_path, bundle) == _expected(bundle)


def test_after_commit_lost_receipt_recovers_only_the_exact_catalog(
    tmp_path: Path,
) -> None:
    bundle = _catalog()

    def fault(phase: str) -> None:
        if phase == "after_commit":
            raise RuntimeError("simulated lost catalog commit receipt")

    observed = M6RegressionExecutionSourceCatalogPublisher(
        tmp_path,
        fault_injector=fault,
    ).publish(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_document,
    )

    assert observed == _expected(bundle)
    assert _load(tmp_path, bundle) == observed


def test_conflicting_final_target_is_never_overwritten(tmp_path: Path) -> None:
    bundle = _catalog()
    publisher = M6RegressionExecutionSourceCatalogPublisher(tmp_path)
    publisher.publish(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_document,
    )
    final_path = _final_catalog_path(tmp_path)
    conflicting_bytes = b'{"conflicting":true}'
    final_path.write_bytes(conflicting_bytes)

    with pytest.raises(M6RegressionExecutionSourceCatalogError) as conflict:
        publisher.publish(
            bundle.execution_source_catalog,
            bundle.execution_source_catalog_document,
        )
    assert conflict.value.reason_code == (
        M6RegressionExecutionSourceCatalogFailureCode.CATALOG_CONFLICT
    )
    assert final_path.read_bytes() == conflicting_bytes


def test_reader_rejects_physical_tamper_and_noncanonical_json(tmp_path: Path) -> None:
    bundle = _catalog()
    publisher = M6RegressionExecutionSourceCatalogPublisher(tmp_path)
    publisher.publish(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_document,
    )
    final_path = _final_catalog_path(tmp_path)
    final_path.write_bytes(b"{}")

    with pytest.raises(M6RegressionExecutionSourceCatalogError) as tampered:
        _load(tmp_path, bundle)
    assert tampered.value.reason_code == (
        M6RegressionExecutionSourceCatalogFailureCode.IDENTITY_MISMATCH
    )

    other_root = tmp_path / "noncanonical"
    publisher = M6RegressionExecutionSourceCatalogPublisher(other_root)
    publisher.publish(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_document,
    )
    final_path = _final_catalog_path(other_root)
    noncanonical = (bundle.execution_source_catalog_document + " ").encode("utf-8")
    noncanonical_sha256 = hashlib.sha256(noncanonical).hexdigest()
    authority_id = bundle.execution_source_catalog.source_catalog_authority_id
    _write_identity_alias(
        other_root,
        final_path,
        noncanonical,
        source_authority_id=authority_id,
        target_authority_id=authority_id,
        source_document_sha256=bundle.execution_source_catalog_content_sha256,
        target_document_sha256=noncanonical_sha256,
    )

    with pytest.raises(M6RegressionExecutionSourceCatalogError) as invalid:
        ReadonlyM6RegressionExecutionSourceCatalogStore(other_root).load(
            authority_id,
            noncanonical_sha256,
        )
    assert invalid.value.reason_code == (
        M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_INVALID
    )


def test_reader_rejects_requested_hash_and_authority_grafts(tmp_path: Path) -> None:
    bundle = _catalog()
    publisher = M6RegressionExecutionSourceCatalogPublisher(tmp_path)
    publisher.publish(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_document,
    )
    final_path = _final_catalog_path(tmp_path)
    payload = final_path.read_bytes()
    authority_id = bundle.execution_source_catalog.source_catalog_authority_id
    document_sha256 = bundle.execution_source_catalog_content_sha256

    wrong_document_sha256 = "f" * 64
    _write_identity_alias(
        tmp_path,
        final_path,
        payload,
        source_authority_id=authority_id,
        target_authority_id=authority_id,
        source_document_sha256=document_sha256,
        target_document_sha256=wrong_document_sha256,
    )
    with pytest.raises(M6RegressionExecutionSourceCatalogError) as hash_graft:
        ReadonlyM6RegressionExecutionSourceCatalogStore(tmp_path).load(
            authority_id,
            wrong_document_sha256,
        )
    assert hash_graft.value.reason_code == (
        M6RegressionExecutionSourceCatalogFailureCode.IDENTITY_MISMATCH
    )

    wrong_authority_id = "e" * 64
    _write_identity_alias(
        tmp_path,
        final_path,
        payload,
        source_authority_id=authority_id,
        target_authority_id=wrong_authority_id,
        source_document_sha256=document_sha256,
        target_document_sha256=document_sha256,
    )
    with pytest.raises(M6RegressionExecutionSourceCatalogError) as authority_graft:
        ReadonlyM6RegressionExecutionSourceCatalogStore(tmp_path).load(
            wrong_authority_id,
            document_sha256,
        )
    assert authority_graft.value.reason_code == (
        M6RegressionExecutionSourceCatalogFailureCode.IDENTITY_MISMATCH
    )


def test_reader_reports_missing_and_never_scans_for_another_catalog(
    tmp_path: Path,
) -> None:
    published = _catalog()
    missing = _catalog("other-opaque-sample")
    assert published.execution_source_catalog.source_catalog_authority_id != (
        missing.execution_source_catalog.source_catalog_authority_id
    )
    M6RegressionExecutionSourceCatalogPublisher(tmp_path).publish(
        published.execution_source_catalog,
        published.execution_source_catalog_document,
    )

    with pytest.raises(M6RegressionExecutionSourceCatalogError) as absent:
        _load(tmp_path, missing)
    assert absent.value.reason_code == (
        M6RegressionExecutionSourceCatalogFailureCode.CATALOG_NOT_FOUND
    )


def test_reader_and_publisher_enforce_budget_before_accepting_document(
    tmp_path: Path,
) -> None:
    bundle = _catalog()
    with pytest.raises(M6RegressionExecutionSourceCatalogError) as publish_too_large:
        M6RegressionExecutionSourceCatalogPublisher(
            tmp_path,
            max_document_bytes=1,
        ).publish(
            bundle.execution_source_catalog,
            bundle.execution_source_catalog_document,
        )
    assert publish_too_large.value.reason_code == (
        M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE
    )

    M6RegressionExecutionSourceCatalogPublisher(tmp_path).publish(
        bundle.execution_source_catalog,
        bundle.execution_source_catalog_document,
    )
    with pytest.raises(M6RegressionExecutionSourceCatalogError) as load_too_large:
        ReadonlyM6RegressionExecutionSourceCatalogStore(
            tmp_path,
            max_document_bytes=1,
        ).load(
            bundle.execution_source_catalog.source_catalog_authority_id,
            bundle.execution_source_catalog_content_sha256,
        )
    assert load_too_large.value.reason_code == (
        M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE
    )
