from __future__ import annotations

from dataclasses import replace
from functools import lru_cache
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_regression_execution_source_catalog_store import (
    M6RegressionExecutionSourceCatalogPublisher,
    ReadonlyM6RegressionExecutionSourceCatalogStore,
)
from labcourt.adapters.storage.m6_replay_locked_closed_policy_regression_store import (
    M6ReplayLockedClosedPolicyRegressionPublicationResult,
    M6ReplayLockedClosedPolicyRegressionPublisher,
    M6ReplayLockedClosedPolicyRegressionStoreError,
    M6ReplayLockedClosedPolicyRegressionStoreErrorCode,
    M6StoredReplayLockedClosedPolicyRegressionBundle,
    ReadonlyM6ReplayLockedClosedPolicyRegressionStore,
)
from labcourt.application.m6_replay_locked_closed_policy_publication import (
    build_m6_replay_locked_closed_policy_publication_bundle,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogError,
    M6RegressionExecutionSourceCatalogFailureCode,
)
from tests.integration.test_m6_regression_execution_source_catalog_store import (
    _catalog as _catalog_bundle,
)
from tests.integration.test_m6_regression_execution_source_catalog_store import (
    _expected as _expected_catalog,
)
from tests.integration.test_m6_regression_store import _publication as _v1_publication
from tests.unit.test_m6_replay_locked_closed_policy_regression import _assemble, _facts


class _RecordingProvider:
    def __init__(self, delegate: object) -> None:
        self.delegate = delegate
        self.calls: list[tuple[str, str]] = []

    def load(
        self,
        source_catalog_authority_id: str,
        source_catalog_document_sha256: str,
    ) -> object:
        self.calls.append(
            (
                source_catalog_authority_id,
                source_catalog_document_sha256,
            )
        )
        return self.delegate.load(  # type: ignore[attr-defined, no-any-return]
            source_catalog_authority_id,
            source_catalog_document_sha256,
        )


class _StaticProvider:
    def __init__(self, value: object) -> None:
        self.value = value
        self.calls: list[tuple[str, str]] = []

    def load(
        self,
        source_catalog_authority_id: str,
        source_catalog_document_sha256: str,
    ) -> object:
        self.calls.append(
            (
                source_catalog_authority_id,
                source_catalog_document_sha256,
            )
        )
        return self.value


class _FailingProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def load(
        self,
        source_catalog_authority_id: str,
        source_catalog_document_sha256: str,
    ) -> object:
        self.calls.append(
            (
                source_catalog_authority_id,
                source_catalog_document_sha256,
            )
        )
        raise M6RegressionExecutionSourceCatalogError(
            M6RegressionExecutionSourceCatalogFailureCode.CATALOG_NOT_FOUND
        )


@lru_cache(maxsize=1)
def _publication():  # type: ignore[no-untyped-def]
    return build_m6_replay_locked_closed_policy_publication_bundle(_assemble(_facts()))


@lru_cache(maxsize=1)
def _conflicting_publication():  # type: ignore[no-untyped-def]
    facts = _facts()
    dataset = facts.dataset.model_copy(
        update={
            "eligibility_policy_authority_id": "1" * 64,
            "eligibility_policy_document_sha256": "2" * 64,
        }
    )
    return build_m6_replay_locked_closed_policy_publication_bundle(
        _assemble(replace(facts, dataset=dataset))
    )


@lru_cache(maxsize=1)
def _foreign_catalog():  # type: ignore[no-untyped-def]
    return _expected_catalog(_catalog_bundle("closed-store-foreign-catalog"))


def _catalog_identity() -> tuple[str, str]:
    stored = _publication().report_bundle.stored_source_catalog
    return (
        stored.source_catalog.source_catalog_authority_id,
        stored.content_sha256,
    )


def _publish_catalog(catalog_root: Path):  # type: ignore[no-untyped-def]
    stored = _publication().report_bundle.stored_source_catalog
    published = M6RegressionExecutionSourceCatalogPublisher(catalog_root).publish(
        stored.source_catalog,
        stored.canonical_document,
    )
    assert published == stored
    return ReadonlyM6RegressionExecutionSourceCatalogStore(catalog_root)


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "catalogs", tmp_path / "closed-regressions"


def _publish(tmp_path: Path):  # type: ignore[no-untyped-def]
    catalog_root, report_root = _roots(tmp_path)
    provider = _publish_catalog(catalog_root)
    result = M6ReplayLockedClosedPolicyRegressionPublisher(
        report_root,
        source_catalog_provider=provider,
    ).publish(_publication())
    return catalog_root, report_root, provider, result


def _load(report_root: Path, provider: object):  # type: ignore[no-untyped-def]
    return ReadonlyM6ReplayLockedClosedPolicyRegressionStore(
        report_root,
        source_catalog_provider=provider,
    ).load(_publication().seal.candidate_run_id)


def test_store_api_is_additive_and_v1_types_remain_separate() -> None:
    assert M6ReplayLockedClosedPolicyRegressionPublisher is not None
    assert ReadonlyM6ReplayLockedClosedPolicyRegressionStore is not None
    assert M6ReplayLockedClosedPolicyRegressionStoreError is not None
    assert M6ReplayLockedClosedPolicyRegressionStoreErrorCode is not None
    assert M6ReplayLockedClosedPolicyRegressionPublicationResult is not None
    assert M6StoredReplayLockedClosedPolicyRegressionBundle is not None


def test_publishes_idempotently_and_round_trips_from_report_commit_point(
    tmp_path: Path,
) -> None:
    publication = _publication()
    catalog_root, report_root = _roots(tmp_path)
    durable_provider = _publish_catalog(catalog_root)
    publish_provider = _RecordingProvider(durable_provider)
    publisher = M6ReplayLockedClosedPolicyRegressionPublisher(
        report_root,
        source_catalog_provider=publish_provider,
    )

    first = publisher.publish(publication)
    second = publisher.publish(publication)
    read_provider = _RecordingProvider(durable_provider)
    stored = _load(report_root, read_provider)

    assert first == second
    assert type(first) is M6ReplayLockedClosedPolicyRegressionPublicationResult
    assert first.seal_id == publication.seal.seal_id
    assert first.report_path == (
        report_root / publication.seal.candidate_run_id / "regression.json"
    )
    assert first.seal_path == (
        report_root / publication.seal.candidate_run_id / Path(publication.seal.seal_relative_path)
    )
    expected_dependencies = tuple(
        report_root / publication.seal.candidate_run_id / Path(entry.relative_path)
        for entry in publication.seal.entries
        if entry.relative_path != "regression.json"
    )
    assert first.dependency_paths == expected_dependencies
    assert len(first.dependency_paths) == 3
    assert first.report_path.is_file()
    assert first.seal_path.is_file()
    assert all(path.is_file() for path in first.dependency_paths)
    assert type(stored) is M6StoredReplayLockedClosedPolicyRegressionBundle
    assert stored.report_bundle == publication.report_bundle
    assert stored.seal == publication.seal
    assert stored.seal_document == publication.seal_document
    assert stored.to_publication_bundle() == publication
    assert set(publish_provider.calls) == {_catalog_identity()}
    assert read_provider.calls == [_catalog_identity()]
    assert not tuple(path for path in (report_root / ".staging").rglob("*") if path.is_file())


def test_catalog_remains_an_external_dual_identity_authority_not_a_fifth_document(
    tmp_path: Path,
) -> None:
    catalog_root, report_root, _provider, result = _publish(tmp_path)
    final_report_files = tuple(
        path
        for path in report_root.rglob("*.json")
        if ".staging" not in path.relative_to(report_root).parts
    )
    final_catalog_files = tuple(
        path
        for path in catalog_root.rglob("*.json")
        if ".staging" not in path.relative_to(catalog_root).parts
    )

    assert len(result.dependency_paths) == 3
    assert set(final_report_files) == {
        result.report_path,
        result.seal_path,
        *result.dependency_paths,
    }
    assert len(final_report_files) == 5
    assert len(final_catalog_files) == 1
    assert final_catalog_files[0].is_relative_to(catalog_root)
    assert not final_catalog_files[0].is_relative_to(report_root)


@pytest.mark.parametrize(
    "phase",
    (
        "after_staging",
        "after_dependency:COMMAND",
        "after_dependency:EVALUATOR_DATASET",
        "after_dependency:CLOSED_POLICY_EXECUTION_SEAL",
        "after_seal",
        "before_commit",
    ),
)
def test_faults_before_report_commit_are_not_visible_and_exact_retry_succeeds(
    tmp_path: Path,
    phase: str,
) -> None:
    publication = _publication()
    catalog_root, report_root = _roots(tmp_path)
    provider = _publish_catalog(catalog_root)

    def fault(observed: str) -> None:
        if observed == phase:
            raise RuntimeError(f"fault:{phase}")

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError):
        M6ReplayLockedClosedPolicyRegressionPublisher(
            report_root,
            source_catalog_provider=provider,
            fault_injector=fault,
        ).publish(publication)

    report_path = report_root / publication.seal.candidate_run_id / "regression.json"
    assert not report_path.exists()
    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as missing:
        _load(report_root, provider)
    assert missing.value.code is (M6ReplayLockedClosedPolicyRegressionStoreErrorCode.COMMIT_MISSING)

    recovered = M6ReplayLockedClosedPolicyRegressionPublisher(
        report_root,
        source_catalog_provider=provider,
    ).publish(publication)
    assert recovered.report_path.is_file()
    assert _load(report_root, provider).to_publication_bundle() == publication


def test_lost_report_commit_receipt_recovers_only_after_catalog_backed_readback(
    tmp_path: Path,
) -> None:
    publication = _publication()
    catalog_root, report_root = _roots(tmp_path)
    durable_provider = _publish_catalog(catalog_root)
    provider = _RecordingProvider(durable_provider)

    def fault(phase: str) -> None:
        if phase == "after_commit":
            raise RuntimeError("simulated lost report commit receipt")

    result = M6ReplayLockedClosedPolicyRegressionPublisher(
        report_root,
        source_catalog_provider=provider,
        fault_injector=fault,
    ).publish(publication)

    assert result.report_path.is_file()
    assert len(provider.calls) >= 2
    assert set(provider.calls) == {_catalog_identity()}
    assert _load(report_root, durable_provider).to_publication_bundle() == publication


def test_fixed_candidate_run_rejects_a_different_report_without_overwrite(
    tmp_path: Path,
) -> None:
    first = _publication()
    conflicting = _conflicting_publication()
    assert first.seal.candidate_run_id == conflicting.seal.candidate_run_id
    assert first.seal.report_id != conflicting.seal.report_id
    catalog_root, report_root = _roots(tmp_path)
    provider = _publish_catalog(catalog_root)
    publisher = M6ReplayLockedClosedPolicyRegressionPublisher(
        report_root,
        source_catalog_provider=provider,
    )
    published = publisher.publish(first)
    original = published.report_path.read_bytes()

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as conflict:
        publisher.publish(conflicting)

    assert conflict.value.code is (
        M6ReplayLockedClosedPolicyRegressionStoreErrorCode.COMMIT_CONFLICT
    )
    assert published.report_path.read_bytes() == original
    assert _load(report_root, provider).seal == first.seal


def test_reader_rejects_extra_seal_inventory(tmp_path: Path) -> None:
    _catalog_root, report_root, provider, result = _publish(tmp_path)
    extra = result.seal_path.parent / "extra.json"
    extra.write_text("{}", encoding="utf-8")

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as raised:
        _load(report_root, provider)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionStoreErrorCode.INVENTORY_INVALID
    )


def test_reader_rejects_dependency_physical_tamper(tmp_path: Path) -> None:
    _catalog_root, report_root, provider, result = _publish(tmp_path)
    result.dependency_paths[0].write_bytes(b"{}")

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as raised:
        _load(report_root, provider)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
    )


@pytest.mark.parametrize(
    ("target", "expected_code"),
    (
        ("report", M6ReplayLockedClosedPolicyRegressionStoreErrorCode.REPORT_INVALID),
        ("seal", M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SEAL_INVALID),
    ),
)
def test_reader_rejects_noncanonical_commit_and_seal_documents(
    tmp_path: Path,
    target: str,
    expected_code: M6ReplayLockedClosedPolicyRegressionStoreErrorCode,
) -> None:
    _catalog_root, report_root, provider, result = _publish(tmp_path)
    path = result.report_path if target == "report" else result.seal_path
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as raised:
        _load(report_root, provider)

    assert raised.value.code is expected_code


def test_reader_maps_durable_catalog_physical_tamper_to_typed_failure(
    tmp_path: Path,
) -> None:
    catalog_root, report_root, provider, _result = _publish(tmp_path)
    catalog_files = tuple(
        path
        for path in catalog_root.rglob("*.json")
        if ".staging" not in path.relative_to(catalog_root).parts
    )
    assert len(catalog_files) == 1
    catalog_files[0].write_bytes(b"{}")

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as raised:
        _load(report_root, provider)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SOURCE_CATALOG_LOAD_FAILED
    )
    assert not hasattr(raised.value, "source_catalog")


@pytest.mark.parametrize(
    ("provider_factory", "expected_code"),
    (
        (
            _FailingProvider,
            M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SOURCE_CATALOG_LOAD_FAILED,
        ),
        (
            lambda: _StaticProvider(object()),
            M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SOURCE_CATALOG_LOAD_FAILED,
        ),
        (
            lambda: _StaticProvider(_foreign_catalog()),
            M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SOURCE_CATALOG_MISMATCH,
        ),
    ),
)
def test_publisher_maps_catalog_provider_failure_and_mismatch_without_fallback(
    tmp_path: Path,
    provider_factory,  # type: ignore[no-untyped-def]
    expected_code: M6ReplayLockedClosedPolicyRegressionStoreErrorCode,
) -> None:
    provider = provider_factory()

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as raised:
        M6ReplayLockedClosedPolicyRegressionPublisher(
            tmp_path,
            source_catalog_provider=provider,
        ).publish(_publication())

    assert raised.value.code is expected_code
    assert provider.calls == [_catalog_identity()]
    assert not hasattr(raised.value, "source_catalog")


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("source_catalog_authority_id", "3" * 64),
        ("source_catalog_document_sha256", "4" * 64),
    ),
)
def test_reader_loads_catalog_by_both_seal_identities_and_rejects_grafts(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    _catalog_root, report_root, _provider, result = _publish(tmp_path)
    payload = _publication().seal.model_dump(mode="json", exclude_computed_fields=True)
    payload[field] = replacement
    forged = M6ReplayLockedClosedPolicyPublicationSealAuthorityV2.model_validate(payload)
    result.seal_path.write_text(
        canonical_json(forged.model_dump(mode="json")),
        encoding="utf-8",
    )
    provider = _StaticProvider(_publication().report_bundle.stored_source_catalog)

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as raised:
        _load(report_root, provider)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SOURCE_CATALOG_MISMATCH
    )
    assert provider.calls == [
        (
            forged.source_catalog_authority_id,
            forged.source_catalog_document_sha256,
        )
    ]


def test_budget_rejection_happens_before_catalog_provider_access(
    tmp_path: Path,
) -> None:
    publication = _publication()
    catalog_root, report_root = _roots(tmp_path)
    durable_provider = _publish_catalog(catalog_root)
    publish_provider = _RecordingProvider(durable_provider)

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as publish:
        M6ReplayLockedClosedPolicyRegressionPublisher(
            report_root,
            source_catalog_provider=publish_provider,
            max_document_bytes=1,
        ).publish(publication)
    assert publish.value.code is (M6ReplayLockedClosedPolicyRegressionStoreErrorCode.BUNDLE_INVALID)
    assert publish_provider.calls == []

    M6ReplayLockedClosedPolicyRegressionPublisher(
        report_root,
        source_catalog_provider=durable_provider,
    ).publish(publication)
    read_provider = _RecordingProvider(durable_provider)
    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as load:
        ReadonlyM6ReplayLockedClosedPolicyRegressionStore(
            report_root,
            source_catalog_provider=read_provider,
            max_document_bytes=1,
        ).load(publication.seal.candidate_run_id)
    assert load.value.code is (
        M6ReplayLockedClosedPolicyRegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
    )
    assert read_provider.calls == []


def test_publisher_rejects_v1_publication_before_catalog_access(tmp_path: Path) -> None:
    provider = _StaticProvider(_publication().report_bundle.stored_source_catalog)

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as raised:
        M6ReplayLockedClosedPolicyRegressionPublisher(
            tmp_path,
            source_catalog_provider=provider,
        ).publish(_v1_publication())

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionStoreErrorCode.INVALID_ARGUMENT
    )
    assert provider.calls == []


@pytest.mark.parametrize("candidate_run_id", [None, "", "../foreign-run"])
def test_reader_rejects_invalid_run_ids_without_catalog_access(
    tmp_path: Path,
    candidate_run_id: object,
) -> None:
    provider = _StaticProvider(_publication().report_bundle.stored_source_catalog)

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionStoreError) as raised:
        ReadonlyM6ReplayLockedClosedPolicyRegressionStore(
            tmp_path,
            source_catalog_provider=provider,
        ).load(candidate_run_id)

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionStoreErrorCode.INVALID_ARGUMENT
    )
    assert provider.calls == []
