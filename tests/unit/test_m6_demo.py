from __future__ import annotations

import hashlib
from dataclasses import fields, replace
from functools import lru_cache

import pytest

from labcourt.application.m6_demo import (
    M6OfflineDemoBuildError,
    M6OfflineDemoBuildErrorCode,
    M6OfflineDemoManifestBundle,
    M6OfflineDemoScenarioResultDocument,
    build_m6_offline_demo_manifest,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_demo import (
    M6OfflineDemoScenarioName,
    M6OfflineDemoScenarioResultAuthorityV1,
)
from labcourt.contracts.m6_static_report_publication import (
    M6PrivacySafeStaticReportPublicationSealAuthorityV1,
)
from tests.contract.test_m6_demo_contracts import _result
from tests.unit.test_m6_replay_locked_closed_policy_publication import _publication
from tests.unit.test_m6_static_report import _bundle as _static_report_bundle


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _static_report_publication_seal() -> M6PrivacySafeStaticReportPublicationSealAuthorityV1:
    publication = _publication()
    static_bundle = _static_report_bundle()
    manifest_document = canonical_json(static_bundle.manifest.model_dump(mode="json"))
    manifest_payload = manifest_document.encode("utf-8")
    html_payload = static_bundle.html_document.encode("utf-8")
    seal = M6PrivacySafeStaticReportPublicationSealAuthorityV1(
        candidate_run_id=publication.seal.candidate_run_id,
        report_id=publication.report_bundle.report.report_id,
        regression_publication_seal_id=publication.seal.seal_id,
        static_report_manifest_id=static_bundle.manifest.manifest_id,
        static_report_manifest_content_sha256=hashlib.sha256(manifest_payload).hexdigest(),
        static_report_manifest_size_bytes=len(manifest_payload),
        html_content_sha256=hashlib.sha256(html_payload).hexdigest(),
        html_size_bytes=len(html_payload),
        evidence_inventory_root_sha256=(static_bundle.manifest.evidence_inventory_root_sha256),
    )
    return seal


def _static_report_publication_seal_document() -> str:
    return canonical_json(_static_report_publication_seal().model_dump(mode="json"))


def _result_document(
    name: M6OfflineDemoScenarioName,
) -> M6OfflineDemoScenarioResultDocument:
    result = _result(name)
    return M6OfflineDemoScenarioResultDocument(
        result=result,
        canonical_document=canonical_json(result.model_dump(mode="json")),
    )


def _result_documents() -> tuple[M6OfflineDemoScenarioResultDocument, ...]:
    return tuple(_result_document(name) for name in M6OfflineDemoScenarioName)


@lru_cache(maxsize=1)
def _demo_bundle() -> M6OfflineDemoManifestBundle:
    return build_m6_offline_demo_manifest(
        _publication(),
        _static_report_bundle(),
        _static_report_publication_seal(),
        _static_report_publication_seal_document(),
        _result_documents(),
    )


def test_demo_builder_api_is_small_typed_and_payload_free() -> None:
    assert tuple(field.name for field in fields(M6OfflineDemoScenarioResultDocument)) == (
        "result",
        "canonical_document",
    )
    assert tuple(field.name for field in fields(M6OfflineDemoManifestBundle)) == (
        "manifest",
        "manifest_document",
    )
    assert tuple(M6OfflineDemoBuildErrorCode) == (
        M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT,
        M6OfflineDemoBuildErrorCode.REGRESSION_PUBLICATION_INVALID,
        M6OfflineDemoBuildErrorCode.STATIC_REPORT_BUNDLE_INVALID,
        M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID,
        M6OfflineDemoBuildErrorCode.UPSTREAM_BINDING_MISMATCH,
        M6OfflineDemoBuildErrorCode.MANIFEST_INVARIANT_VIOLATION,
    )

    error = M6OfflineDemoBuildError(M6OfflineDemoBuildErrorCode.MANIFEST_INVARIANT_VIOLATION)
    assert vars(error) == {"code": M6OfflineDemoBuildErrorCode.MANIFEST_INVARIANT_VIOLATION}
    with pytest.raises(TypeError, match="M6OfflineDemoBuildErrorCode"):
        M6OfflineDemoBuildError("INVALID_ARGUMENT")  # type: ignore[arg-type]


def test_builder_binds_exact_closed_static_and_scenario_authorities() -> None:
    publication = _publication()
    static_seal = _static_report_publication_seal()
    bundle = _demo_bundle()

    assert type(bundle) is M6OfflineDemoManifestBundle
    assert bundle.manifest.candidate_run_id == publication.seal.candidate_run_id
    assert bundle.manifest.closed_regression_report_id == (
        publication.report_bundle.report.report_id
    )
    assert bundle.manifest.closed_regression_publication_seal_id == (publication.seal.seal_id)
    assert bundle.manifest.static_report_publication_seal_id == (static_seal.seal_id)
    assert bundle.manifest.static_report_index_content_sha256 == (static_seal.html_content_sha256)
    assert bundle.manifest.classification == "SYNTHETIC_PRECOMPUTED_FAKE"
    assert bundle.manifest.network_used is False
    assert bundle.manifest.gpu_used is False
    assert bundle.manifest.provider_called is False
    assert tuple(item.scenario_name for item in bundle.manifest.scenario_receipts) == tuple(
        M6OfflineDemoScenarioName
    )
    assert bundle.manifest_document == canonical_json(bundle.manifest.model_dump(mode="json"))


def test_builder_derives_each_receipt_from_exact_canonical_result_bytes() -> None:
    bundle = _demo_bundle()
    documents = _result_documents()

    assert len(bundle.manifest.scenario_receipts) == len(documents) == 16
    for receipt, item in zip(
        bundle.manifest.scenario_receipts,
        documents,
        strict=True,
    ):
        payload = item.canonical_document.encode("utf-8")
        assert receipt.scenario_name is item.result.scenario_name
        assert receipt.artifact_content_sha256 == hashlib.sha256(payload).hexdigest()
        assert receipt.artifact_size_bytes == len(payload)


def test_builder_is_exactly_retryable() -> None:
    first = build_m6_offline_demo_manifest(
        _publication(),
        _static_report_bundle(),
        _static_report_publication_seal(),
        _static_report_publication_seal_document(),
        _result_documents(),
    )
    second = build_m6_offline_demo_manifest(
        _publication(),
        _static_report_bundle(),
        _static_report_publication_seal(),
        _static_report_publication_seal_document(),
        _result_documents(),
    )

    assert first == second


@pytest.mark.parametrize("value", [None, {}, object()])
def test_builder_rejects_untyped_regression_publications(value: object) -> None:
    with pytest.raises(M6OfflineDemoBuildError) as raised:
        build_m6_offline_demo_manifest(
            value,
            _static_report_bundle(),
            _static_report_publication_seal(),
            _static_report_publication_seal_document(),
            _result_documents(),
        )

    assert raised.value.code is M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT
    assert vars(raised.value) == {"code": M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT}


@pytest.mark.parametrize("value", [None, {}, object()])
def test_builder_rejects_untyped_static_report_bundles(value: object) -> None:
    with pytest.raises(M6OfflineDemoBuildError) as raised:
        build_m6_offline_demo_manifest(
            _publication(),
            value,
            _static_report_publication_seal(),
            _static_report_publication_seal_document(),
            _result_documents(),
        )

    assert raised.value.code is M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("value", [None, {}, object()])
def test_builder_rejects_untyped_static_publication_seals(value: object) -> None:
    with pytest.raises(M6OfflineDemoBuildError) as raised:
        build_m6_offline_demo_manifest(
            _publication(),
            _static_report_bundle(),
            value,
            _static_report_publication_seal_document(),
            _result_documents(),
        )

    assert raised.value.code is M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("value", [None, b"", {}, object()])
def test_builder_rejects_untyped_static_publication_seal_documents(
    value: object,
) -> None:
    with pytest.raises(M6OfflineDemoBuildError) as raised:
        build_m6_offline_demo_manifest(
            _publication(),
            _static_report_bundle(),
            _static_report_publication_seal(),
            value,
            _result_documents(),
        )

    assert raised.value.code is M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("value", [None, [], {}, object()])
def test_builder_rejects_untyped_scenario_document_inventories(value: object) -> None:
    with pytest.raises(M6OfflineDemoBuildError) as raised:
        build_m6_offline_demo_manifest(
            _publication(),
            _static_report_bundle(),
            _static_report_publication_seal(),
            _static_report_publication_seal_document(),
            value,
        )

    assert raised.value.code is M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("field", ["report_bundle", "seal", "seal_document"])
def test_builder_rebuild_rejects_forged_closed_publication(field: str) -> None:
    publication = _publication()
    replacement: object = object()
    if field == "seal_document":
        replacement = publication.seal_document + " "
    forged = replace(publication, **{field: replacement})

    with pytest.raises(M6OfflineDemoBuildError) as raised:
        build_m6_offline_demo_manifest(
            forged,
            _static_report_bundle(),
            _static_report_publication_seal(),
            _static_report_publication_seal_document(),
            _result_documents(),
        )

    assert raised.value.code is (M6OfflineDemoBuildErrorCode.REGRESSION_PUBLICATION_INVALID)


def test_builder_rebuild_rejects_forged_static_report_documents() -> None:
    static_bundle = _static_report_bundle()
    seal = _static_report_publication_seal()
    seal_document = _static_report_publication_seal_document()
    forged_static = replace(
        static_bundle,
        html_document=static_bundle.html_document + " ",
    )
    for bundle, document in (
        (forged_static, seal_document),
        (static_bundle, seal_document + " "),
    ):
        with pytest.raises(M6OfflineDemoBuildError) as raised:
            build_m6_offline_demo_manifest(
                _publication(),
                bundle,
                seal,
                document,
                _result_documents(),
            )
        assert raised.value.code is (M6OfflineDemoBuildErrorCode.STATIC_REPORT_BUNDLE_INVALID)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("candidate_run_id", "foreign-candidate-run"),
        ("report_id", "1" * 64),
        ("regression_publication_seal_id", "2" * 64),
        ("static_report_manifest_id", "3" * 64),
        ("html_content_sha256", "4" * 64),
    ),
)
def test_builder_rejects_validly_serialized_upstream_binding_grafts(
    field: str,
    replacement: object,
) -> None:
    forged_seal = _static_report_publication_seal().model_copy(update={field: replacement})
    forged_document = canonical_json(forged_seal.model_dump(mode="json"))

    with pytest.raises(M6OfflineDemoBuildError) as raised:
        build_m6_offline_demo_manifest(
            _publication(),
            _static_report_bundle(),
            forged_seal,
            forged_document,
            _result_documents(),
        )

    assert raised.value.code is M6OfflineDemoBuildErrorCode.UPSTREAM_BINDING_MISMATCH


def test_builder_rejects_missing_extra_duplicate_and_unordered_scenarios() -> None:
    documents = _result_documents()
    invalid = (
        documents[:-1],
        (*documents, documents[0]),
        (*documents[:-1], documents[0]),
        tuple(reversed(documents)),
    )

    for inventory in invalid:
        with pytest.raises(M6OfflineDemoBuildError) as raised:
            build_m6_offline_demo_manifest(
                _publication(),
                _static_report_bundle(),
                _static_report_publication_seal(),
                _static_report_publication_seal_document(),
                inventory,
            )
        assert raised.value.code is M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID


def test_builder_rejects_untyped_noncanonical_and_cross_scenario_grafts() -> None:
    documents = list(_result_documents())
    first = documents[0]
    second = documents[1]
    cases = (
        object(),
        replace(first, canonical_document=first.canonical_document + " "),
        replace(first, canonical_document="{}"),
        replace(first, canonical_document=second.canonical_document),
        replace(first, result=object()),
    )

    for replacement in cases:
        inventory = list(documents)
        inventory[0] = replacement  # type: ignore[assignment]
        with pytest.raises(M6OfflineDemoBuildError) as raised:
            build_m6_offline_demo_manifest(
                _publication(),
                _static_report_bundle(),
                _static_report_publication_seal(),
                _static_report_publication_seal_document(),
                tuple(inventory),
            )
        assert raised.value.code is M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID


def test_builder_rejects_canonical_serialized_result_id_forgery() -> None:
    documents = list(_result_documents())
    first = documents[0]
    payload = first.result.model_dump(mode="json")
    payload["result_id"] = "0" * 64
    documents[0] = replace(first, canonical_document=canonical_json(payload))

    with pytest.raises(M6OfflineDemoBuildError) as raised:
        build_m6_offline_demo_manifest(
            _publication(),
            _static_report_bundle(),
            _static_report_publication_seal(),
            _static_report_publication_seal_document(),
            tuple(documents),
        )

    assert raised.value.code is M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID


def test_builder_accepts_a_different_valid_canonical_pytest_node_and_rehashes_it() -> None:
    documents = list(_result_documents())
    first = documents[0].result
    changed = M6OfflineDemoScenarioResultAuthorityV1(
        scenario_name=first.scenario_name,
        verification_target=("tests/e2e/test_m6_demo_scenarios.py::test_presence_true_positive_v2"),
    )
    changed_document = canonical_json(changed.model_dump(mode="json"))
    documents[0] = M6OfflineDemoScenarioResultDocument(
        result=changed,
        canonical_document=changed_document,
    )

    bundle = build_m6_offline_demo_manifest(
        _publication(),
        _static_report_bundle(),
        _static_report_publication_seal(),
        _static_report_publication_seal_document(),
        tuple(documents),
    )

    first_receipt = bundle.manifest.scenario_receipts[0]
    assert first_receipt.artifact_content_sha256 == _sha256(changed_document)
    assert first_receipt.artifact_size_bytes == len(changed_document.encode("utf-8"))
    assert bundle.manifest.demo_manifest_id != _demo_bundle().manifest.demo_manifest_id
