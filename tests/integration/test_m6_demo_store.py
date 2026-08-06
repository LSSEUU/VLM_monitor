from __future__ import annotations

import hashlib
import traceback
from collections.abc import Callable
from dataclasses import fields
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_demo_store import (
    M6OfflineDemoPublicationResult,
    M6OfflineDemoPublisher,
    M6OfflineDemoStoreError,
    M6OfflineDemoStoreErrorCode,
    M6StoredOfflineDemoBundle,
    ReadonlyM6OfflineDemoStore,
)
from labcourt.adapters.storage.m6_regression_execution_source_catalog_store import (
    M6RegressionExecutionSourceCatalogPublisher,
    ReadonlyM6RegressionExecutionSourceCatalogStore,
)
from labcourt.adapters.storage.m6_replay_locked_closed_policy_regression_store import (
    M6ReplayLockedClosedPolicyRegressionPublisher,
)
from labcourt.adapters.storage.m6_static_report_store import (
    M6PrivacySafeStaticReportPublisher,
)
from labcourt.application.m6_demo import (
    M6OfflineDemoPublicationBundle,
    M6OfflineDemoScenarioResultDocument,
    build_m6_offline_demo_publication,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_demo import M6OfflineDemoScenarioResultAuthorityV1
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogProvider,
)
from tests.integration.test_m6_static_report_store import _provider_for
from tests.unit.test_m6_demo import (
    _publication,
    _result_documents,
    _static_report_bundle,
    _static_report_publication_seal,
    _static_report_publication_seal_document,
)
from tests.unit.test_m6_demo_publication import _demo_publication_bundle


class _CatalogProviderProbe:
    def __init__(
        self,
        delegate: ReadonlyM6RegressionExecutionSourceCatalogStore,
        *,
        mutate_once: Callable[[], None] | None = None,
    ) -> None:
        self._delegate = delegate
        self._mutate_once = mutate_once
        self.calls: list[tuple[str, str]] = []

    def load(
        self,
        source_catalog_authority_id: str,
        source_catalog_document_sha256: str,
    ) -> object:
        self.calls.append((source_catalog_authority_id, source_catalog_document_sha256))
        if self._mutate_once is not None:
            mutate = self._mutate_once
            self._mutate_once = None
            mutate()
        return self._delegate.load(
            source_catalog_authority_id,
            source_catalog_document_sha256,
        )


def _catalog_provider(
    root: Path,
) -> ReadonlyM6RegressionExecutionSourceCatalogStore:
    stored = _publication().report_bundle.stored_source_catalog
    published = M6RegressionExecutionSourceCatalogPublisher(root).publish(
        stored.source_catalog,
        stored.canonical_document,
    )
    assert published == stored
    return ReadonlyM6RegressionExecutionSourceCatalogStore(root)


def _prepare_upstream(
    tmp_path: Path,
) -> tuple[Path, ReadonlyM6RegressionExecutionSourceCatalogStore]:
    root = tmp_path / "offline-demo"
    provider = _catalog_provider(tmp_path / "catalogs")
    M6ReplayLockedClosedPolicyRegressionPublisher(
        root,
        source_catalog_provider=provider,
    ).publish(_publication())
    M6PrivacySafeStaticReportPublisher(
        root,
        evidence_provider=_provider_for(),
    ).publish(_publication(), _static_report_bundle())
    return root, provider


def _path(root: Path, relative_path: str) -> Path:
    return root / _publication().seal.candidate_run_id / Path(*relative_path.split("/"))


def _publisher(
    root: Path,
    provider: M6RegressionExecutionSourceCatalogProvider,
    *,
    fault_injector=None,  # type: ignore[no-untyped-def]
) -> M6OfflineDemoPublisher:
    return M6OfflineDemoPublisher(
        root,
        source_catalog_provider=provider,
        fault_injector=fault_injector,
    )


def _reader(
    root: Path,
    provider: M6RegressionExecutionSourceCatalogProvider,
) -> ReadonlyM6OfflineDemoStore:
    return ReadonlyM6OfflineDemoStore(
        root,
        source_catalog_provider=provider,
    )


def _conflicting_bundle() -> M6OfflineDemoPublicationBundle:
    documents = list(_result_documents())
    first = documents[0].result
    changed = M6OfflineDemoScenarioResultAuthorityV1(
        scenario_name=first.scenario_name,
        verification_target=("tests/e2e/test_m6_demo_scenarios.py::test_presence_true_positive_v2"),
    )
    documents[0] = M6OfflineDemoScenarioResultDocument(
        result=changed,
        canonical_document=canonical_json(changed.model_dump(mode="json")),
    )
    return build_m6_offline_demo_publication(
        _publication(),
        _static_report_bundle(),
        _static_report_publication_seal(),
        _static_report_publication_seal_document(),
        tuple(documents),
    )


def test_demo_store_api_is_small_typed_and_payload_free() -> None:
    assert tuple(field.name for field in fields(M6OfflineDemoPublicationResult)) == (
        "seal_id",
        "index_path",
        "manifest_path",
        "seal_path",
        "scenario_paths",
    )
    assert tuple(field.name for field in fields(M6StoredOfflineDemoBundle)) == (
        "publication_bundle",
    )
    assert {
        M6OfflineDemoStoreErrorCode.INVALID_ARGUMENT,
        M6OfflineDemoStoreErrorCode.UPSTREAM_MISSING,
        M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT,
        M6OfflineDemoStoreErrorCode.COMMIT_MISSING,
    }.issubset(set(M6OfflineDemoStoreErrorCode))

    error = M6OfflineDemoStoreError(M6OfflineDemoStoreErrorCode.COMMIT_MISSING)
    assert vars(error) == {"code": M6OfflineDemoStoreErrorCode.COMMIT_MISSING}
    with pytest.raises(TypeError, match="M6OfflineDemoStoreErrorCode"):
        M6OfflineDemoStoreError("COMMIT_MISSING")  # type: ignore[arg-type]


def test_publish_exact_retry_and_reader_round_trip_every_sealed_byte(
    tmp_path: Path,
) -> None:
    root, provider = _prepare_upstream(tmp_path)
    bundle = _demo_publication_bundle()
    publisher = _publisher(root, provider)

    first = publisher.publish(bundle)
    second = publisher.publish(bundle)
    stored = _reader(root, provider).load(bundle.seal.candidate_run_id)

    assert type(first) is M6OfflineDemoPublicationResult
    assert first == second
    assert type(stored) is M6StoredOfflineDemoBundle
    assert stored.publication_bundle == bundle
    assert first.seal_id == bundle.seal.seal_id
    assert first.index_path == _path(root, bundle.seal.landing_relative_path)
    assert first.manifest_path == _path(root, bundle.seal.manifest_relative_path)
    assert first.seal_path == _path(root, bundle.seal.seal_relative_path)
    assert first.scenario_paths == tuple(
        _path(root, receipt.artifact_relative_path)
        for receipt in bundle.manifest_bundle.manifest.scenario_receipts
    )
    assert first.index_path.read_text(encoding="utf-8") == bundle.landing_document
    assert first.manifest_path.read_text(encoding="utf-8") == (
        bundle.manifest_bundle.manifest_document
    )
    assert first.seal_path.read_text(encoding="utf-8") == bundle.seal_document
    manifest_payload = first.manifest_path.read_bytes()
    landing_payload = first.index_path.read_bytes()
    assert hashlib.sha256(manifest_payload).hexdigest() == (
        bundle.seal.demo_manifest_content_sha256
    )
    assert len(manifest_payload) == bundle.seal.demo_manifest_size_bytes
    assert hashlib.sha256(landing_payload).hexdigest() == bundle.seal.landing_content_sha256
    assert len(landing_payload) == bundle.seal.landing_size_bytes
    for path, document, receipt in zip(
        first.scenario_paths,
        bundle.scenario_result_documents,
        bundle.manifest_bundle.manifest.scenario_receipts,
        strict=True,
    ):
        payload = path.read_bytes()
        assert payload == document.canonical_document.encode("utf-8")
        assert len(payload) == receipt.artifact_size_bytes
        assert receipt.artifact_content_sha256 == hashlib.sha256(payload).hexdigest()


def test_fault_before_index_commit_is_invisible_and_exact_retry_succeeds(
    tmp_path: Path,
) -> None:
    root, provider = _prepare_upstream(tmp_path)
    bundle = _demo_publication_bundle()

    def fault(phase: str) -> None:
        if phase == "before_commit":
            raise RuntimeError("simulated failure before demo index commit")

    with pytest.raises(M6OfflineDemoStoreError) as failed:
        _publisher(root, provider, fault_injector=fault).publish(bundle)

    assert failed.value.code is M6OfflineDemoStoreErrorCode.COMMIT_PUBLICATION_FAILED
    assert not _path(root, bundle.seal.landing_relative_path).exists()
    with pytest.raises(M6OfflineDemoStoreError) as missing:
        _reader(root, provider).load(bundle.seal.candidate_run_id)
    assert missing.value.code is M6OfflineDemoStoreErrorCode.COMMIT_MISSING

    recovered = _publisher(root, provider).publish(bundle)
    assert recovered.index_path.is_file()
    assert _reader(root, provider).load(bundle.seal.candidate_run_id).publication_bundle == bundle


def test_fixed_run_conflict_never_overwrites_committed_demo(
    tmp_path: Path,
) -> None:
    root, provider = _prepare_upstream(tmp_path)
    first_bundle = _demo_publication_bundle()
    first = _publisher(root, provider).publish(first_bundle)
    original = {path: path.read_bytes() for path in (*first.scenario_paths, first.manifest_path)}
    conflicting_bundle = _conflicting_bundle()

    with pytest.raises(M6OfflineDemoStoreError) as conflict:
        _publisher(root, provider).publish(conflicting_bundle)

    assert conflict.value.code is M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT
    assert _reader(root, provider).load(first_bundle.seal.candidate_run_id).publication_bundle == (
        first_bundle
    )
    assert all(path.read_bytes() == payload for path, payload in original.items())
    assert not _path(root, conflicting_bundle.seal.manifest_relative_path).exists()


def test_publisher_requires_closed_and_static_publications_under_its_own_root(
    tmp_path: Path,
) -> None:
    upstream_root, provider = _prepare_upstream(tmp_path)
    empty_root = tmp_path / "foreign-demo-root"
    bundle = _demo_publication_bundle()

    with pytest.raises(M6OfflineDemoStoreError) as missing:
        _publisher(empty_root, provider).publish(bundle)

    assert upstream_root != empty_root
    assert missing.value.code is M6OfflineDemoStoreErrorCode.UPSTREAM_MISSING
    assert not _path(empty_root, bundle.seal.landing_relative_path).exists()


@pytest.mark.parametrize("upstream_commit", ["regression.json", "index.html"])
def test_reader_revalidates_both_same_root_upstream_commit_points(
    tmp_path: Path,
    upstream_commit: str,
) -> None:
    root, provider = _prepare_upstream(tmp_path)
    bundle = _demo_publication_bundle()
    published = _publisher(root, provider).publish(bundle)

    _path(root, upstream_commit).unlink()

    assert published.index_path.is_file()
    with pytest.raises(M6OfflineDemoStoreError) as missing:
        _reader(root, provider).load(bundle.seal.candidate_run_id)
    assert missing.value.code is M6OfflineDemoStoreErrorCode.UPSTREAM_MISSING


def test_partial_first_bundle_blocks_foreign_bundle_without_poisoning_exact_retry(
    tmp_path: Path,
) -> None:
    root, provider = _prepare_upstream(tmp_path)
    first_bundle = _demo_publication_bundle()
    foreign_bundle = _conflicting_bundle()

    def fault(phase: str) -> None:
        if phase == "before_commit":
            raise RuntimeError("leave one exact partial demo publication")

    with pytest.raises(M6OfflineDemoStoreError):
        _publisher(root, provider, fault_injector=fault).publish(first_bundle)
    assert not _path(root, first_bundle.seal.landing_relative_path).exists()

    with pytest.raises(M6OfflineDemoStoreError) as conflict:
        _publisher(root, provider).publish(foreign_bundle)
    assert conflict.value.code is M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT
    assert not _path(root, foreign_bundle.seal.manifest_relative_path).exists()

    recovered = _publisher(root, provider).publish(first_bundle)
    assert recovered.index_path.is_file()
    assert _reader(root, provider).load(first_bundle.seal.candidate_run_id).publication_bundle == (
        first_bundle
    )


@pytest.mark.parametrize("upstream_commit", ["regression.json", "index.html"])
def test_before_commit_upstream_loss_never_leaves_a_demo_success_marker(
    tmp_path: Path,
    upstream_commit: str,
) -> None:
    root, provider = _prepare_upstream(tmp_path)
    bundle = _demo_publication_bundle()

    def remove_upstream(phase: str) -> None:
        if phase == "before_commit":
            _path(root, upstream_commit).unlink()

    with pytest.raises(M6OfflineDemoStoreError) as rejected:
        _publisher(root, provider, fault_injector=remove_upstream).publish(bundle)

    assert rejected.value.code is M6OfflineDemoStoreErrorCode.UPSTREAM_MISSING
    assert not _path(root, bundle.seal.landing_relative_path).exists()


def test_reader_rejects_sealed_total_budget_before_any_scenario_or_upstream_read(
    tmp_path: Path,
) -> None:
    root, provider = _prepare_upstream(tmp_path)
    bundle = _demo_publication_bundle()
    published = _publisher(root, provider).publish(bundle)
    published.scenario_paths[0].unlink()
    probe = _CatalogProviderProbe(provider)

    with pytest.raises(M6OfflineDemoStoreError) as rejected:
        ReadonlyM6OfflineDemoStore(
            root,
            source_catalog_provider=probe,
            max_bundle_bytes=1,
        ).load(bundle.seal.candidate_run_id)

    assert rejected.value.code is M6OfflineDemoStoreErrorCode.BUDGET_EXCEEDED
    assert probe.calls == []


def test_reader_tamper_failure_has_no_path_or_authority_traceback_payload(
    tmp_path: Path,
) -> None:
    root, provider = _prepare_upstream(tmp_path)
    bundle = _demo_publication_bundle()
    published = _publisher(root, provider).publish(bundle)
    receipt = bundle.manifest_bundle.manifest.scenario_receipts[0]
    published.scenario_paths[0].write_bytes(published.scenario_paths[0].read_bytes() + b" ")

    with pytest.raises(M6OfflineDemoStoreError) as rejected:
        _reader(root, provider).load(bundle.seal.candidate_run_id)

    error = rejected.value
    rendered = "".join(traceback.format_exception(error))
    assert error.code is M6OfflineDemoStoreErrorCode.SCENARIO_INVALID
    assert error.__cause__ is None
    assert error.__context__ is None
    assert bundle.seal.candidate_run_id not in rendered
    assert receipt.artifact_relative_path not in rendered


def test_reader_rechecks_demo_snapshots_after_upstream_provider_side_effect(
    tmp_path: Path,
) -> None:
    root, provider = _prepare_upstream(tmp_path)
    bundle = _demo_publication_bundle()
    published = _publisher(root, provider).publish(bundle)

    def mutate_commit() -> None:
        published.index_path.write_bytes(published.index_path.read_bytes() + b" ")

    probe = _CatalogProviderProbe(provider, mutate_once=mutate_commit)
    with pytest.raises(M6OfflineDemoStoreError) as rejected:
        _reader(root, probe).load(bundle.seal.candidate_run_id)

    assert probe.calls
    assert rejected.value.code is M6OfflineDemoStoreErrorCode.STORAGE_BOUNDARY_FAILURE
