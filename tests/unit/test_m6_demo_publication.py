from __future__ import annotations

import hashlib
from dataclasses import fields
from functools import lru_cache

from labcourt.application.m6_demo import (
    M6OfflineDemoPublicationBundle,
    build_m6_offline_demo_publication,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_demo import M6OfflineDemoScenarioName
from tests.unit.test_m6_demo import (
    _demo_bundle,
    _publication,
    _result_documents,
    _static_report_bundle,
    _static_report_publication_seal,
    _static_report_publication_seal_document,
)


@lru_cache(maxsize=1)
def _demo_publication_bundle() -> M6OfflineDemoPublicationBundle:
    return build_m6_offline_demo_publication(
        _publication(),
        _static_report_bundle(),
        _static_report_publication_seal(),
        _static_report_publication_seal_document(),
        _result_documents(),
    )


def test_demo_publication_bundle_api_is_exact_and_small() -> None:
    assert tuple(field.name for field in fields(M6OfflineDemoPublicationBundle)) == (
        "manifest_bundle",
        "scenario_result_documents",
        "landing_document",
        "seal",
        "seal_document",
    )


def test_demo_publication_binds_a_safe_deterministic_landing_and_all_documents() -> None:
    bundle = _demo_publication_bundle()
    manifest_payload = bundle.manifest_bundle.manifest_document.encode("utf-8")
    landing_payload = bundle.landing_document.encode("utf-8")

    assert bundle.manifest_bundle == _demo_bundle()
    assert bundle.scenario_result_documents == _result_documents()
    assert bundle.landing_document.startswith("<!doctype html>")
    assert "SYNTHETIC_PRECOMPUTED_FAKE" in bundle.landing_document
    assert 'href="../index.html"' in bundle.landing_document
    assert 'href="../regression.json"' in bundle.landing_document
    assert "<script" not in bundle.landing_document.casefold()
    assert "http://" not in bundle.landing_document.casefold()
    assert "https://" not in bundle.landing_document.casefold()
    for name in M6OfflineDemoScenarioName:
        assert f'href="scenarios/{name.value}/result.json"' in bundle.landing_document

    assert bundle.seal.candidate_run_id == bundle.manifest_bundle.manifest.candidate_run_id
    assert bundle.seal.demo_manifest_id == bundle.manifest_bundle.manifest.demo_manifest_id
    assert bundle.seal.demo_manifest_content_sha256 == hashlib.sha256(manifest_payload).hexdigest()
    assert bundle.seal.demo_manifest_size_bytes == len(manifest_payload)
    assert bundle.seal.landing_content_sha256 == hashlib.sha256(landing_payload).hexdigest()
    assert bundle.seal.landing_size_bytes == len(landing_payload)
    assert bundle.seal.scenario_inventory_root_sha256 == (
        bundle.manifest_bundle.manifest.scenario_inventory_root_sha256
    )
    assert bundle.seal_document == canonical_json(bundle.seal.model_dump(mode="json"))


def test_demo_publication_build_is_exactly_retryable() -> None:
    first = build_m6_offline_demo_publication(
        _publication(),
        _static_report_bundle(),
        _static_report_publication_seal(),
        _static_report_publication_seal_document(),
        _result_documents(),
    )
    second = build_m6_offline_demo_publication(
        _publication(),
        _static_report_bundle(),
        _static_report_publication_seal(),
        _static_report_publication_seal_document(),
        _result_documents(),
    )

    assert first == second


def test_demo_landing_has_dark_responsive_reduced_motion_and_keyboard_contracts() -> None:
    document = _demo_publication_bundle().landing_document

    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in document
    assert '<meta name="color-scheme" content="dark">' in document
    assert "a:focus-visible" in document
    assert "min-height: 44px" in document
    assert "@media (max-width: 470px)" in document
    assert "@media (max-width: 680px)" in document
    assert "@media (prefers-reduced-motion: reduce)" in document
    assert ".scenario-card:hover { transform: none; }" in document
