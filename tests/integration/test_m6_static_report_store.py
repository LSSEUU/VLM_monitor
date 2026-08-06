from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_static_report_store import (
    M6PrivacyProcessedEvidenceProvider,
    M6PrivacySafeStaticReportPublicationResult,
    M6PrivacySafeStaticReportPublisher,
    M6PrivacySafeStaticReportStoreError,
    M6PrivacySafeStaticReportStoreErrorCode,
    M6StoredPrivacyProcessedEvidence,
    M6StoredPrivacySafeStaticReportBundle,
    ReadonlyM6PrivacySafeStaticReportStore,
)
from labcourt.application.m6_static_report import (
    M6PrivacySafeStaticReportBundle,
    build_m6_privacy_safe_static_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_static_report import (
    M6StaticReportEvidenceDisposition,
    M6StaticReportEvidenceItem,
)
from tests.unit.test_m6_replay_locked_closed_policy_publication import _publication
from tests.unit.test_m6_static_report import _bundle, _evidence_items

_PRIVACY_PAYLOAD = b"privacy-processed-evidence"


class _EvidenceProvider:
    def __init__(
        self,
        values: dict[tuple[str, str], object],
        *,
        failure: Exception | None = None,
    ) -> None:
        self.values = values
        self.failure = failure
        self.calls: list[tuple[str, str]] = []

    def load(self, artifact_relative_path: str, content_sha256: str) -> object:
        key = artifact_relative_path, content_sha256
        self.calls.append(key)
        if self.failure is not None:
            raise self.failure
        if key not in self.values:
            raise RuntimeError("privacy evidence unavailable")
        return self.values[key]


def _stored_evidence(
    item: M6StaticReportEvidenceItem,
    payload: bytes = _PRIVACY_PAYLOAD,
) -> M6StoredPrivacyProcessedEvidence:
    assert item.artifact_relative_path is not None
    assert item.artifact_content_sha256 is not None
    return M6StoredPrivacyProcessedEvidence(
        artifact_relative_path=item.artifact_relative_path,
        content_sha256=item.artifact_content_sha256,
        content_bytes=payload,
    )


def _provider_for(
    bundle: M6PrivacySafeStaticReportBundle | None = None,
) -> _EvidenceProvider:
    selected = _bundle() if bundle is None else bundle
    values: dict[tuple[str, str], object] = {}
    for item in selected.manifest.evidence_items:
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE:
            stored = _stored_evidence(item)
            values[(stored.artifact_relative_path, stored.content_sha256)] = stored
    return _EvidenceProvider(values)


def _path(root: Path, relative_path: str) -> Path:
    return root / _publication().seal.candidate_run_id / Path(*relative_path.split("/"))


def _publish(
    root: Path,
    provider: object,
    *,
    fault_injector=None,  # type: ignore[no-untyped-def]
) -> M6PrivacySafeStaticReportPublicationResult:
    return M6PrivacySafeStaticReportPublisher(
        root,
        evidence_provider=provider,
        fault_injector=fault_injector,
    ).publish(_publication(), _bundle())


def _load(root: Path) -> M6StoredPrivacySafeStaticReportBundle:
    return ReadonlyM6PrivacySafeStaticReportStore(root).load(_publication().seal.candidate_run_id)


def test_store_api_and_typed_error_codes_are_additive() -> None:
    assert M6PrivacyProcessedEvidenceProvider is not None
    assert tuple(M6PrivacySafeStaticReportStoreErrorCode) == (
        M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT,
        M6PrivacySafeStaticReportStoreErrorCode.BUNDLE_INVALID,
        M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_LOAD_FAILED,
        M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_INVALID,
        M6PrivacySafeStaticReportStoreErrorCode.STAGING_CONFLICT,
        M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_PUBLICATION_FAILED,
        M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_PUBLICATION_FAILED,
        M6PrivacySafeStaticReportStoreErrorCode.SEAL_PUBLICATION_FAILED,
        M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT,
        M6PrivacySafeStaticReportStoreErrorCode.COMMIT_OUTCOME_UNKNOWN,
        M6PrivacySafeStaticReportStoreErrorCode.COMMIT_MISSING,
        M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_INVALID,
        M6PrivacySafeStaticReportStoreErrorCode.SEAL_INVALID,
        M6PrivacySafeStaticReportStoreErrorCode.HTML_INVALID,
        M6PrivacySafeStaticReportStoreErrorCode.INVENTORY_INVALID,
        M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED,
        M6PrivacySafeStaticReportStoreErrorCode.STORAGE_BOUNDARY_FAILURE,
    )


def test_publish_is_idempotent_and_round_trips_from_index_commit_point(
    tmp_path: Path,
) -> None:
    root = tmp_path / "static-reports"
    provider = _provider_for()
    publisher = M6PrivacySafeStaticReportPublisher(
        root,
        evidence_provider=provider,
    )

    first = publisher.publish(_publication(), _bundle())
    second = publisher.publish(_publication(), _bundle())
    stored = _load(root)
    expected_evidence = tuple(
        _path(root, item.artifact_relative_path)
        for item in _bundle().manifest.evidence_items
        if item.artifact_relative_path is not None
    )

    assert first == second
    assert type(first) is M6PrivacySafeStaticReportPublicationResult
    assert first.seal_id == stored.seal.seal_id
    assert first.index_path == _path(root, "index.html")
    assert first.manifest_path == _path(root, stored.seal.manifest_relative_path)
    assert first.seal_path == _path(root, "m6-static-report/seal.json")
    assert first.evidence_paths == expected_evidence
    assert first.index_path.read_bytes() == _bundle().html_document.encode("utf-8")
    assert first.manifest_path.read_text(encoding="utf-8") == canonical_json(
        _bundle().manifest.model_dump(mode="json")
    )
    assert first.seal_path.read_text(encoding="utf-8") == stored.seal_document
    assert all(path.read_bytes() == _PRIVACY_PAYLOAD for path in first.evidence_paths)
    assert type(stored) is M6StoredPrivacySafeStaticReportBundle
    assert stored.static_report_bundle == _bundle()
    assert stored.seal.candidate_run_id == _publication().seal.candidate_run_id
    assert stored.seal.report_id == _publication().report_bundle.report.report_id
    assert stored.seal.regression_publication_seal_id == _publication().seal.seal_id
    assert stored.seal.static_report_manifest_id == _bundle().manifest.manifest_id
    assert stored.seal.evidence_inventory_root_sha256 == (
        _bundle().manifest.evidence_inventory_root_sha256
    )
    assert stored.seal_document == canonical_json(stored.seal.model_dump(mode="json"))
    staging_files = tuple(path for path in (root / ".staging").rglob("*") if path.is_file())
    assert staging_files == (
        root
        / ".staging"
        / _publication().seal.candidate_run_id
        / "m6-static-report"
        / ".publish.lock",
    )
    assert staging_files[0].read_bytes() == (b"labcourt-m6-static-report-publish-lock-v1\n")


def test_available_media_is_loaded_by_exact_dual_identity_and_copied_safely(
    tmp_path: Path,
) -> None:
    root = tmp_path / "static-reports"
    provider = _provider_for()
    available = next(
        item
        for item in _bundle().manifest.evidence_items
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
    )

    result = _publish(root, provider)

    assert provider.calls == [(available.artifact_relative_path, available.artifact_content_sha256)]
    assert result.evidence_paths == (_path(root, available.artifact_relative_path),)
    assert result.evidence_paths[0].read_bytes() == _PRIVACY_PAYLOAD


def test_purged_and_not_published_evidence_never_call_the_media_provider(
    tmp_path: Path,
) -> None:
    evidence: list[M6StaticReportEvidenceItem] = []
    for index, sample_id in enumerate(item.sample_id for item in _bundle().manifest.evidence_items):
        if index == 0:
            evidence.append(
                M6StaticReportEvidenceItem(
                    sample_id=sample_id,
                    disposition=M6StaticReportEvidenceDisposition.RETENTION_PURGED,
                    deletion_audit_id="deletion-audit-no-provider",
                    retention_reason_code="retention-window-expired",
                )
            )
        else:
            evidence.append(
                M6StaticReportEvidenceItem(
                    sample_id=sample_id,
                    disposition=M6StaticReportEvidenceDisposition.NOT_PUBLISHED,
                )
            )
    static_bundle = build_m6_privacy_safe_static_report(
        _publication(), tuple(sorted(evidence, key=lambda item: item.sample_id))
    )
    provider = _EvidenceProvider({})
    root = tmp_path / "static-reports"

    result = M6PrivacySafeStaticReportPublisher(
        root,
        evidence_provider=provider,
    ).publish(_publication(), static_bundle)

    assert provider.calls == []
    assert result.evidence_paths == ()
    assert _load(root).static_report_bundle == static_bundle
    assert not (root / _publication().seal.candidate_run_id / "privacy-media").exists()


@pytest.mark.parametrize(
    "phase",
    (
        "after_staging",
        f"after_evidence:{_evidence_items()[0].sample_id}",
        "after_manifest",
        "after_seal",
        "before_commit",
    ),
)
def test_faults_before_index_commit_are_not_visible_and_retry_succeeds(
    tmp_path: Path,
    phase: str,
) -> None:
    root = tmp_path / "static-reports"
    provider = _provider_for()

    def fault(observed: str) -> None:
        if observed == phase:
            raise RuntimeError(f"fault:{phase}")

    with pytest.raises(M6PrivacySafeStaticReportStoreError):
        _publish(root, provider, fault_injector=fault)

    assert not _path(root, "index.html").exists()
    with pytest.raises(M6PrivacySafeStaticReportStoreError) as missing:
        _load(root)
    assert missing.value.code is M6PrivacySafeStaticReportStoreErrorCode.COMMIT_MISSING

    recovered = _publish(root, provider)
    assert recovered.index_path.is_file()
    assert _load(root).static_report_bundle == _bundle()


def test_lost_index_commit_receipt_returns_success_only_after_full_readback(
    tmp_path: Path,
) -> None:
    root = tmp_path / "static-reports"

    def fault(phase: str) -> None:
        if phase == "after_commit":
            raise RuntimeError("simulated lost index commit receipt")

    result = _publish(root, _provider_for(), fault_injector=fault)

    assert result.index_path.is_file()
    assert _load(root).static_report_bundle == _bundle()


def test_closed_regression_artifacts_remain_external_links_not_copied_documents(
    tmp_path: Path,
) -> None:
    root = tmp_path / "static-reports"

    result = _publish(root, _provider_for())
    published_files = {
        path.relative_to(root / _publication().seal.candidate_run_id).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and ".staging" not in path.relative_to(root).parts
        and path.name != ".m6-static-report.publish.lock"
    }
    expected_files = {
        "index.html",
        result.manifest_path.relative_to(root / _publication().seal.candidate_run_id).as_posix(),
        "m6-static-report/seal.json",
        *(
            path.relative_to(root / _publication().seal.candidate_run_id).as_posix()
            for path in result.evidence_paths
        ),
    }

    assert published_files == expected_files
    assert "regression.json" not in published_files
    assert not any(path.startswith("m6-regression/documents/") for path in published_files)
    assert _publication().seal.seal_relative_path not in published_files


@pytest.mark.parametrize("value", [None, {}, object()])
def test_publisher_rejects_untyped_regression_publications_before_provider_access(
    tmp_path: Path,
    value: object,
) -> None:
    provider = _provider_for()

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        M6PrivacySafeStaticReportPublisher(
            tmp_path,
            evidence_provider=provider,
        ).publish(value, _bundle())

    assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT
    assert provider.calls == []


@pytest.mark.parametrize("value", [None, {}, object()])
def test_publisher_rejects_untyped_static_bundles_before_provider_access(
    tmp_path: Path,
    value: object,
) -> None:
    provider = _provider_for()

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        M6PrivacySafeStaticReportPublisher(
            tmp_path,
            evidence_provider=provider,
        ).publish(_publication(), value)

    assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT
    assert provider.calls == []


def test_publisher_rebuild_rejects_forged_static_bundles_before_provider_access(
    tmp_path: Path,
) -> None:
    provider = _provider_for()
    bundle = _bundle()
    changed_document = bundle.html_document + " "
    for index, forged in enumerate(
        (
            replace(bundle, manifest=object()),
            replace(bundle, html_document=changed_document),
            replace(bundle, html_content_sha256="0" * 64),
            replace(
                bundle,
                html_document=changed_document,
                html_content_sha256=hashlib.sha256(changed_document.encode("utf-8")).hexdigest(),
            ),
        )
    ):
        with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
            M6PrivacySafeStaticReportPublisher(
                tmp_path / str(index),
                evidence_provider=provider,
            ).publish(_publication(), forged)
        assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.BUNDLE_INVALID

    assert provider.calls == []


def test_publisher_rebuild_rejects_tampered_regression_publication(
    tmp_path: Path,
) -> None:
    provider = _provider_for()
    publication = _publication()
    forged = replace(publication, seal_document=publication.seal_document + " ")

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        M6PrivacySafeStaticReportPublisher(
            tmp_path,
            evidence_provider=provider,
        ).publish(forged, _bundle())

    assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.BUNDLE_INVALID
    assert provider.calls == []


def test_provider_exception_is_typed_payload_free_and_never_commits(
    tmp_path: Path,
) -> None:
    provider = _EvidenceProvider({}, failure=RuntimeError("provider secret"))

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        _publish(tmp_path, provider)

    assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_LOAD_FAILED
    assert vars(raised.value) == {
        "code": M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_LOAD_FAILED
    }
    assert raised.value.__cause__ is None
    assert len(provider.calls) == 1
    assert not _path(tmp_path, "index.html").exists()
    assert "provider secret" not in str(raised.value)


def test_provider_return_must_match_path_hash_and_actual_bytes(
    tmp_path: Path,
) -> None:
    available = next(
        item
        for item in _bundle().manifest.evidence_items
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
    )
    expected = _stored_evidence(available)
    key = expected.artifact_relative_path, expected.content_sha256
    cases = (
        ("untyped", object(), M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_LOAD_FAILED),
        (
            "path",
            replace(expected, artifact_relative_path="privacy-media/foreign.webp"),
            M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_INVALID,
        ),
        (
            "hash",
            replace(expected, content_sha256="0" * 64),
            M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_INVALID,
        ),
        (
            "bytes",
            replace(expected, content_bytes=b"tampered-privacy-evidence"),
            M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_INVALID,
        ),
    )

    for label, returned, expected_code in cases:
        provider = _EvidenceProvider({key: returned})
        root = tmp_path / label
        with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
            _publish(root, provider)
        assert raised.value.code is expected_code
        assert provider.calls == [key]
        assert not _path(root, "index.html").exists()


def _conflicting_static_bundle() -> tuple[M6PrivacySafeStaticReportBundle, bytes]:
    changed_payload = b"changed-privacy-processed-evidence"
    changed_hash = hashlib.sha256(changed_payload).hexdigest()
    evidence = list(_bundle().manifest.evidence_items)
    available_index = next(
        index
        for index, item in enumerate(evidence)
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
    )
    original = evidence[available_index]
    evidence[available_index] = M6StaticReportEvidenceItem(
        sample_id=original.sample_id,
        disposition=M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE,
        artifact_relative_path=f"privacy-media/{original.sample_id}-changed.avif",
        artifact_content_sha256=changed_hash,
    )
    return (
        build_m6_privacy_safe_static_report(
            _publication(), tuple(sorted(evidence, key=lambda item: item.sample_id))
        ),
        changed_payload,
    )


def test_fixed_candidate_run_rejects_different_static_report_without_orphans(
    tmp_path: Path,
) -> None:
    root = tmp_path / "static-reports"
    first_bundle = _bundle()
    conflicting, changed_payload = _conflicting_static_bundle()
    first_provider = _provider_for(first_bundle)
    first_result = M6PrivacySafeStaticReportPublisher(
        root,
        evidence_provider=first_provider,
    ).publish(_publication(), first_bundle)
    original_index = first_result.index_path.read_bytes()
    available = next(
        item
        for item in conflicting.manifest.evidence_items
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
    )
    changed = _stored_evidence(available, changed_payload)
    conflicting_provider = _EvidenceProvider(
        {(changed.artifact_relative_path, changed.content_sha256): changed}
    )

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        M6PrivacySafeStaticReportPublisher(
            root,
            evidence_provider=conflicting_provider,
        ).publish(_publication(), conflicting)

    assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT
    assert first_result.index_path.read_bytes() == original_index
    assert _load(root).static_report_bundle == first_bundle
    assert not _path(root, available.artifact_relative_path).exists()


class _ConcurrentEvidenceProvider(_EvidenceProvider):
    def __init__(
        self,
        values: dict[tuple[str, str], object],
    ) -> None:
        super().__init__(values)
        self._calls_lock = threading.Lock()

    def load(self, artifact_relative_path: str, content_sha256: str) -> object:
        key = artifact_relative_path, content_sha256
        with self._calls_lock:
            self.calls.append(key)
        if key not in self.values:
            raise RuntimeError("privacy evidence unavailable")
        return self.values[key]


def _publish_outcome(
    publisher: M6PrivacySafeStaticReportPublisher,
    bundle: M6PrivacySafeStaticReportBundle,
) -> M6PrivacySafeStaticReportPublicationResult | M6PrivacySafeStaticReportStoreError:
    try:
        return publisher.publish(_publication(), bundle)
    except M6PrivacySafeStaticReportStoreError as exc:
        return exc


def _publish_after_start(
    start: threading.Barrier,
    publisher: M6PrivacySafeStaticReportPublisher,
    bundle: M6PrivacySafeStaticReportBundle,
) -> M6PrivacySafeStaticReportPublicationResult | M6PrivacySafeStaticReportStoreError:
    start.wait(timeout=20)
    return _publish_outcome(publisher, bundle)


def test_concurrent_different_bundles_have_one_exact_winner_without_loser_orphans(
    tmp_path: Path,
) -> None:
    root = tmp_path / "static-reports"
    first_bundle = _bundle()
    second_bundle, second_payload = _conflicting_static_bundle()
    first_available = next(
        item
        for item in first_bundle.manifest.evidence_items
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
    )
    second_available = next(
        item
        for item in second_bundle.manifest.evidence_items
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
    )
    first_stored = _stored_evidence(first_available)
    second_stored = _stored_evidence(second_available, second_payload)
    provider = _ConcurrentEvidenceProvider(
        {
            (first_stored.artifact_relative_path, first_stored.content_sha256): (first_stored),
            (second_stored.artifact_relative_path, second_stored.content_sha256): (second_stored),
        }
    )
    publishers = (
        M6PrivacySafeStaticReportPublisher(root, evidence_provider=provider),
        M6PrivacySafeStaticReportPublisher(root, evidence_provider=provider),
    )

    start = threading.Barrier(3)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(_publish_after_start, start, publishers[0], first_bundle),
            executor.submit(_publish_after_start, start, publishers[1], second_bundle),
        )
        start.wait(timeout=20)
        outcomes = tuple(future.result(timeout=30) for future in futures)

    successes = tuple(
        outcome
        for outcome in outcomes
        if type(outcome) is M6PrivacySafeStaticReportPublicationResult
    )
    failures = tuple(
        outcome for outcome in outcomes if type(outcome) is M6PrivacySafeStaticReportStoreError
    )
    assert len(successes) == 1
    assert len(failures) == 1
    assert failures[0].code is M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT
    assert len(provider.calls) == 1

    result = successes[0]
    stored = _load(root)
    assert result.seal_id == stored.seal.seal_id
    assert stored.static_report_bundle in (first_bundle, second_bundle)
    winner = stored.static_report_bundle
    loser = second_bundle if winner == first_bundle else first_bundle
    winner_available = next(
        item
        for item in winner.manifest.evidence_items
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
    )
    assert provider.calls == [
        (
            winner_available.artifact_relative_path,
            winner_available.artifact_content_sha256,
        )
    ]

    manifests = tuple(
        path for path in _path(root, "m6-static-report/manifests").iterdir() if path.is_file()
    )
    media = tuple(path for path in _path(root, "privacy-media").rglob("*") if path.is_file())
    assert manifests == (result.manifest_path,)
    assert set(media) == set(result.evidence_paths)

    loser_manifest_payload = canonical_json(loser.manifest.model_dump(mode="json")).encode("utf-8")
    loser_manifest_path = _path(
        root,
        f"m6-static-report/manifests/{hashlib.sha256(loser_manifest_payload).hexdigest()}.json",
    )
    assert not loser_manifest_path.exists()
    for item in loser.manifest.evidence_items:
        if item.artifact_relative_path is None:
            continue
        if item.artifact_relative_path not in {
            winner_item.artifact_relative_path for winner_item in winner.manifest.evidence_items
        }:
            assert not _path(root, item.artifact_relative_path).exists()

    staging_files = tuple(path for path in (root / ".staging").rglob("*") if path.is_file())
    assert all(path.name == ".publish.lock" for path in staging_files)


def test_partial_first_writer_blocks_different_writer_before_provider_and_exact_retry_wins(
    tmp_path: Path,
) -> None:
    root = tmp_path / "static-reports"
    first_bundle = _bundle()
    second_bundle, second_payload = _conflicting_static_bundle()
    first_provider = _provider_for(first_bundle)

    def fail_after_manifest(phase: str) -> None:
        if phase == "after_manifest":
            raise RuntimeError("first writer stopped after manifest")

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as first_failure:
        M6PrivacySafeStaticReportPublisher(
            root,
            evidence_provider=first_provider,
            fault_injector=fail_after_manifest,
        ).publish(_publication(), first_bundle)
    assert first_failure.value.code is (
        M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_PUBLICATION_FAILED
    )
    assert not _path(root, "index.html").exists()

    second_available = next(
        item
        for item in second_bundle.manifest.evidence_items
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
    )
    second_stored = _stored_evidence(second_available, second_payload)
    second_provider = _EvidenceProvider(
        {(second_stored.artifact_relative_path, second_stored.content_sha256): second_stored}
    )
    with pytest.raises(M6PrivacySafeStaticReportStoreError) as conflict:
        M6PrivacySafeStaticReportPublisher(
            root,
            evidence_provider=second_provider,
        ).publish(_publication(), second_bundle)
    assert conflict.value.code is M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT
    assert second_provider.calls == []
    assert not _path(root, second_available.artifact_relative_path).exists()

    recovered = M6PrivacySafeStaticReportPublisher(
        root,
        evidence_provider=first_provider,
    ).publish(_publication(), first_bundle)
    stored = _load(root)
    assert recovered.seal_id == stored.seal.seal_id
    assert stored.static_report_bundle == first_bundle
    assert tuple(
        path for path in _path(root, "m6-static-report/manifests").iterdir() if path.is_file()
    ) == (recovered.manifest_path,)
    assert set(path for path in _path(root, "privacy-media").rglob("*") if path.is_file()) == set(
        recovered.evidence_paths
    )


@pytest.mark.parametrize(
    ("target", "expected_code"),
    (
        ("manifest", M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_INVALID),
        ("seal", M6PrivacySafeStaticReportStoreErrorCode.SEAL_INVALID),
        ("html", M6PrivacySafeStaticReportStoreErrorCode.HTML_INVALID),
        ("evidence", M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_INVALID),
    ),
)
def test_reader_rejects_tampered_and_noncanonical_publication_bytes(
    tmp_path: Path,
    target: str,
    expected_code: M6PrivacySafeStaticReportStoreErrorCode,
) -> None:
    root = tmp_path / "static-reports"
    result = _publish(root, _provider_for())
    paths = {
        "manifest": result.manifest_path,
        "seal": result.seal_path,
        "html": result.index_path,
        "evidence": result.evidence_paths[0],
    }
    paths[target].write_bytes(paths[target].read_bytes() + b" ")

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        _load(root)

    assert raised.value.code is expected_code


@pytest.mark.parametrize(
    ("target", "expected_code"),
    (
        ("index", M6PrivacySafeStaticReportStoreErrorCode.COMMIT_MISSING),
        ("manifest", M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_INVALID),
        ("seal", M6PrivacySafeStaticReportStoreErrorCode.SEAL_INVALID),
        ("evidence", M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_INVALID),
    ),
)
def test_reader_rejects_missing_committed_dependencies(
    tmp_path: Path,
    target: str,
    expected_code: M6PrivacySafeStaticReportStoreErrorCode,
) -> None:
    root = tmp_path / "static-reports"
    result = _publish(root, _provider_for())
    paths = {
        "index": result.index_path,
        "manifest": result.manifest_path,
        "seal": result.seal_path,
        "evidence": result.evidence_paths[0],
    }
    paths[target].unlink()

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        _load(root)

    assert raised.value.code is expected_code


@pytest.mark.parametrize(
    "relative_path",
    (
        "m6-static-report/extra.json",
        "m6-static-report/manifests/extra.json",
        "privacy-media/unsealed.png",
    ),
)
def test_reader_rejects_extra_static_or_privacy_media_inventory(
    tmp_path: Path,
    relative_path: str,
) -> None:
    root = tmp_path / "static-reports"
    _publish(root, _provider_for())
    extra = _path(root, relative_path)
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_bytes(b"unsealed-content")

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        _load(root)

    assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.INVENTORY_INVALID


@pytest.mark.parametrize("candidate_run_id", [None, "", "../foreign-run", object()])
def test_reader_rejects_uncontrolled_candidate_run_ids(
    tmp_path: Path,
    candidate_run_id: object,
) -> None:
    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        ReadonlyM6PrivacySafeStaticReportStore(tmp_path).load(candidate_run_id)

    assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize(
    "limits",
    (
        {"max_manifest_bytes": 1},
        {"max_html_bytes": 1},
        {"max_evidence_bytes": 1},
    ),
)
def test_publisher_fails_closed_on_explicit_document_budgets(
    tmp_path: Path,
    limits: dict[str, int],
) -> None:
    provider = _provider_for()

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        M6PrivacySafeStaticReportPublisher(
            tmp_path,
            evidence_provider=provider,
            **limits,
        ).publish(_publication(), _bundle())

    assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED
    assert not _path(tmp_path, "index.html").exists()
    if "max_evidence_bytes" not in limits:
        assert provider.calls == []


@pytest.mark.parametrize(
    "limits",
    (
        {"max_manifest_bytes": 1},
        {"max_html_bytes": 1},
        {"max_evidence_bytes": 1},
    ),
)
def test_reader_fails_closed_on_explicit_document_budgets(
    tmp_path: Path,
    limits: dict[str, int],
) -> None:
    root = tmp_path / "static-reports"
    _publish(root, _provider_for())

    with pytest.raises(M6PrivacySafeStaticReportStoreError) as raised:
        ReadonlyM6PrivacySafeStaticReportStore(root, **limits).load(
            _publication().seal.candidate_run_id
        )

    assert raised.value.code is M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED


@pytest.mark.parametrize("value", [0, -1, True, False, 1.5, "1"])
def test_store_budget_configuration_requires_positive_integers(
    tmp_path: Path,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="max_html_bytes"):
        M6PrivacySafeStaticReportPublisher(
            tmp_path,
            evidence_provider=_provider_for(),
            max_html_bytes=value,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="max_html_bytes"):
        ReadonlyM6PrivacySafeStaticReportStore(
            tmp_path,
            max_html_bytes=value,  # type: ignore[arg-type]
        )


def test_store_rejects_untyped_provider_and_error_requires_typed_code(
    tmp_path: Path,
) -> None:
    with pytest.raises(M6PrivacySafeStaticReportStoreError) as provider:
        M6PrivacySafeStaticReportPublisher(tmp_path, evidence_provider=object())
    assert provider.value.code is M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT

    with pytest.raises(TypeError, match="static report store error code"):
        M6PrivacySafeStaticReportStoreError("INVALID_ARGUMENT")  # type: ignore[arg-type]

    error = M6PrivacySafeStaticReportStoreError(
        M6PrivacySafeStaticReportStoreErrorCode.STORAGE_BOUNDARY_FAILURE
    )
    assert vars(error) == {"code": M6PrivacySafeStaticReportStoreErrorCode.STORAGE_BOUNDARY_FAILURE}
