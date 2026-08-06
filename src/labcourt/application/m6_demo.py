"""Build the deterministic manifest for the complete offline M6 demo."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from html import escape as escape_html
from string import Template
from typing import NoReturn

from pydantic import ValidationError

from labcourt.application._m6_demo_template import M6_OFFLINE_DEMO_TEMPLATE
from labcourt.application.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationBuildError,
    M6ReplayLockedClosedPolicyPublicationBundle,
    build_m6_replay_locked_closed_policy_publication_bundle,
)
from labcourt.application.m6_static_report import (
    M6PrivacySafeStaticReportBundle,
    M6StaticReportBuildError,
    build_m6_privacy_safe_static_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_demo import (
    M6OfflineDemoManifestAuthorityV1,
    M6OfflineDemoScenarioArtifactReceiptV1,
    M6OfflineDemoScenarioName,
    M6OfflineDemoScenarioResultAuthorityV1,
)
from labcourt.contracts.m6_demo_publication import (
    M6OfflineDemoPublicationSealAuthorityV1,
)
from labcourt.contracts.m6_static_report_publication import (
    M6PrivacySafeStaticReportPublicationSealAuthorityV1,
)
from labcourt.exceptions import LabCourtError


class M6OfflineDemoBuildErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    REGRESSION_PUBLICATION_INVALID = "REGRESSION_PUBLICATION_INVALID"
    STATIC_REPORT_BUNDLE_INVALID = "STATIC_REPORT_BUNDLE_INVALID"
    SCENARIO_RESULTS_INVALID = "SCENARIO_RESULTS_INVALID"
    UPSTREAM_BINDING_MISMATCH = "UPSTREAM_BINDING_MISMATCH"
    MANIFEST_INVARIANT_VIOLATION = "MANIFEST_INVARIANT_VIOLATION"


class M6OfflineDemoBuildError(LabCourtError):
    def __init__(self, code: M6OfflineDemoBuildErrorCode) -> None:
        if not isinstance(code, M6OfflineDemoBuildErrorCode):
            raise TypeError("code must be an M6OfflineDemoBuildErrorCode")
        self.code = code
        super().__init__(f"M6 offline demo build failed: {code.value}")


class M6OfflineDemoPublicationBuildErrorCode(StrEnum):
    DEMO_MANIFEST_INVALID = "DEMO_MANIFEST_INVALID"
    RENDER_FAILED = "RENDER_FAILED"
    PUBLICATION_INVARIANT_VIOLATION = "PUBLICATION_INVARIANT_VIOLATION"


class M6OfflineDemoPublicationBuildError(LabCourtError):
    def __init__(self, code: M6OfflineDemoPublicationBuildErrorCode) -> None:
        if not isinstance(code, M6OfflineDemoPublicationBuildErrorCode):
            raise TypeError("code must be an M6OfflineDemoPublicationBuildErrorCode")
        self.code = code
        super().__init__(f"M6 offline demo publication build failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6OfflineDemoScenarioResultDocument:
    result: M6OfflineDemoScenarioResultAuthorityV1
    canonical_document: str


@dataclass(frozen=True, slots=True)
class M6OfflineDemoManifestBundle:
    manifest: M6OfflineDemoManifestAuthorityV1
    manifest_document: str


@dataclass(frozen=True, slots=True)
class M6OfflineDemoPublicationBundle:
    manifest_bundle: M6OfflineDemoManifestBundle
    scenario_result_documents: tuple[M6OfflineDemoScenarioResultDocument, ...]
    landing_document: str
    seal: M6OfflineDemoPublicationSealAuthorityV1
    seal_document: str


def _fail(code: M6OfflineDemoBuildErrorCode) -> NoReturn:
    raise M6OfflineDemoBuildError(code)


def _controlled_regression_publication(
    value: object,
) -> M6ReplayLockedClosedPolicyPublicationBundle:
    if type(value) is not M6ReplayLockedClosedPolicyPublicationBundle:
        _fail(M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT)
    assert isinstance(value, M6ReplayLockedClosedPolicyPublicationBundle)
    try:
        rebuilt = build_m6_replay_locked_closed_policy_publication_bundle(value.report_bundle)
    except (
        M6ReplayLockedClosedPolicyPublicationBuildError,
        AttributeError,
        TypeError,
        ValueError,
    ):
        _fail(M6OfflineDemoBuildErrorCode.REGRESSION_PUBLICATION_INVALID)
    if rebuilt != value:
        _fail(M6OfflineDemoBuildErrorCode.REGRESSION_PUBLICATION_INVALID)
    return rebuilt


def _controlled_static_report(
    value: object,
    publication: M6ReplayLockedClosedPolicyPublicationBundle,
) -> M6PrivacySafeStaticReportBundle:
    if type(value) is not M6PrivacySafeStaticReportBundle:
        _fail(M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT)
    assert isinstance(value, M6PrivacySafeStaticReportBundle)
    try:
        rebuilt = build_m6_privacy_safe_static_report(
            publication,
            value.manifest.evidence_items,
        )
    except (M6StaticReportBuildError, AttributeError, TypeError, ValueError):
        _fail(M6OfflineDemoBuildErrorCode.STATIC_REPORT_BUNDLE_INVALID)
    if rebuilt != value:
        _fail(M6OfflineDemoBuildErrorCode.STATIC_REPORT_BUNDLE_INVALID)
    return rebuilt


def _controlled_static_publication_seal(
    seal_value: object,
    document_value: object,
) -> M6PrivacySafeStaticReportPublicationSealAuthorityV1:
    if type(seal_value) is not M6PrivacySafeStaticReportPublicationSealAuthorityV1:
        _fail(M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT)
    if type(document_value) is not str:
        _fail(M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT)
    assert isinstance(seal_value, M6PrivacySafeStaticReportPublicationSealAuthorityV1)
    assert isinstance(document_value, str)
    try:
        rebuilt = M6PrivacySafeStaticReportPublicationSealAuthorityV1.model_validate_json(
            document_value
        )
        rebuilt_document = canonical_json(rebuilt.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError):
        _fail(M6OfflineDemoBuildErrorCode.STATIC_REPORT_BUNDLE_INVALID)
    if rebuilt != seal_value or rebuilt_document != document_value:
        _fail(M6OfflineDemoBuildErrorCode.STATIC_REPORT_BUNDLE_INVALID)
    return rebuilt


def _controlled_scenario_results(
    value: object,
) -> tuple[M6OfflineDemoScenarioResultDocument, ...]:
    if not isinstance(value, tuple):
        _fail(M6OfflineDemoBuildErrorCode.INVALID_ARGUMENT)
    if tuple(
        item.result.scenario_name
        for item in value
        if type(item) is M6OfflineDemoScenarioResultDocument
        and type(item.result) is M6OfflineDemoScenarioResultAuthorityV1
    ) != tuple(M6OfflineDemoScenarioName):
        _fail(M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID)

    controlled: list[M6OfflineDemoScenarioResultDocument] = []
    try:
        for item in value:
            if type(item) is not M6OfflineDemoScenarioResultDocument:
                _fail(M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID)
            if type(item.result) is not M6OfflineDemoScenarioResultAuthorityV1:
                _fail(M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID)
            if type(item.canonical_document) is not str:
                _fail(M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID)
            rebuilt = M6OfflineDemoScenarioResultAuthorityV1.model_validate_json(
                item.canonical_document
            )
            rebuilt_document = canonical_json(rebuilt.model_dump(mode="json"))
            if rebuilt != item.result or rebuilt_document != item.canonical_document:
                _fail(M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID)
            controlled.append(
                M6OfflineDemoScenarioResultDocument(
                    result=rebuilt,
                    canonical_document=rebuilt_document,
                )
            )
    except M6OfflineDemoBuildError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6OfflineDemoBuildErrorCode.SCENARIO_RESULTS_INVALID)
    return tuple(controlled)


def _verify_upstream_bindings(
    publication: M6ReplayLockedClosedPolicyPublicationBundle,
    static_report: M6PrivacySafeStaticReportBundle,
    static_seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1,
) -> None:
    manifest_document = canonical_json(static_report.manifest.model_dump(mode="json"))
    manifest_payload = manifest_document.encode("utf-8")
    html_payload = static_report.html_document.encode("utf-8")
    expected = (
        (static_seal.candidate_run_id, publication.seal.candidate_run_id),
        (static_seal.report_id, publication.report_bundle.report.report_id),
        (static_seal.regression_publication_seal_id, publication.seal.seal_id),
        (static_seal.static_report_manifest_id, static_report.manifest.manifest_id),
        (
            static_seal.static_report_manifest_content_sha256,
            hashlib.sha256(manifest_payload).hexdigest(),
        ),
        (static_seal.static_report_manifest_size_bytes, len(manifest_payload)),
        (static_seal.html_content_sha256, hashlib.sha256(html_payload).hexdigest()),
        (static_seal.html_size_bytes, len(html_payload)),
        (
            static_seal.evidence_inventory_root_sha256,
            static_report.manifest.evidence_inventory_root_sha256,
        ),
    )
    if any(actual != wanted for actual, wanted in expected):
        _fail(M6OfflineDemoBuildErrorCode.UPSTREAM_BINDING_MISMATCH)


def build_m6_offline_demo_manifest(
    regression_publication_bundle: object,
    static_report_bundle: object,
    static_report_publication_seal: object,
    static_report_publication_seal_document: object,
    scenario_result_documents: object,
) -> M6OfflineDemoManifestBundle:
    publication = _controlled_regression_publication(regression_publication_bundle)
    static_report = _controlled_static_report(static_report_bundle, publication)
    static_seal = _controlled_static_publication_seal(
        static_report_publication_seal,
        static_report_publication_seal_document,
    )
    results = _controlled_scenario_results(scenario_result_documents)
    _verify_upstream_bindings(publication, static_report, static_seal)

    try:
        receipts = tuple(
            M6OfflineDemoScenarioArtifactReceiptV1(
                scenario_name=item.result.scenario_name,
                artifact_content_sha256=hashlib.sha256(
                    item.canonical_document.encode("utf-8")
                ).hexdigest(),
                artifact_size_bytes=len(item.canonical_document.encode("utf-8")),
            )
            for item in results
        )
        manifest = M6OfflineDemoManifestAuthorityV1(
            candidate_run_id=publication.seal.candidate_run_id,
            closed_regression_report_id=publication.report_bundle.report.report_id,
            closed_regression_publication_seal_id=publication.seal.seal_id,
            static_report_publication_seal_id=static_seal.seal_id,
            static_report_index_content_sha256=static_seal.html_content_sha256,
            scenario_receipts=receipts,
        )
        document = canonical_json(manifest.model_dump(mode="json"))
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError) as exc:
        raise M6OfflineDemoBuildError(
            M6OfflineDemoBuildErrorCode.MANIFEST_INVARIANT_VIOLATION
        ) from exc
    return M6OfflineDemoManifestBundle(
        manifest=manifest,
        manifest_document=document,
    )


def _render_demo_landing(
    manifest_bundle: M6OfflineDemoManifestBundle,
    results: tuple[M6OfflineDemoScenarioResultDocument, ...],
) -> str:
    manifest = manifest_bundle.manifest
    manifest_sha256 = hashlib.sha256(manifest_bundle.manifest_document.encode("utf-8")).hexdigest()
    scenario_cards: list[str] = []
    for index, item in enumerate(results, start=1):
        label = escape_html(item.result.scenario_name.value.replace("_", " ").title())
        verification_target = escape_html(item.result.verification_target)
        scenario_href = escape_html(
            f"scenarios/{item.result.scenario_name.value}/result.json",
            quote=True,
        )
        scenario_cards.append(
            f"""        <article class="scenario-card">
          <span class="scenario-index">{index:02d}</span>
          <span class="pass">PASSED</span>
          <h3>{label}</h3>
          <p><code>{verification_target}</code></p>
          <a href="{scenario_href}">Open signed result <span aria-hidden="true">&nbsp;→</span></a>
        </article>"""
        )
    return Template(M6_OFFLINE_DEMO_TEMPLATE).substitute(
        scenario_count=escape_html(str(manifest.scenario_count)),
        scenario_cards="\n".join(scenario_cards),
        manifest_href=escape_html(f"manifests/{manifest_sha256}.json", quote=True),
        candidate_run_id=escape_html(manifest.candidate_run_id),
        demo_manifest_id=escape_html(manifest.demo_manifest_id),
        report_id=escape_html(manifest.closed_regression_report_id),
        static_seal_id=escape_html(manifest.static_report_publication_seal_id),
        classification=escape_html(manifest.classification),
    )


def build_m6_offline_demo_publication(
    regression_publication_bundle: object,
    static_report_bundle: object,
    static_report_publication_seal: object,
    static_report_publication_seal_document: object,
    scenario_result_documents: object,
) -> M6OfflineDemoPublicationBundle:
    try:
        manifest_bundle = build_m6_offline_demo_manifest(
            regression_publication_bundle,
            static_report_bundle,
            static_report_publication_seal,
            static_report_publication_seal_document,
            scenario_result_documents,
        )
        results = _controlled_scenario_results(scenario_result_documents)
    except M6OfflineDemoBuildError as exc:
        raise M6OfflineDemoPublicationBuildError(
            M6OfflineDemoPublicationBuildErrorCode.DEMO_MANIFEST_INVALID
        ) from exc

    try:
        landing_document = _render_demo_landing(manifest_bundle, results)
        landing_payload = landing_document.encode("utf-8", errors="strict")
    except (KeyError, TypeError, UnicodeError, ValueError) as exc:
        raise M6OfflineDemoPublicationBuildError(
            M6OfflineDemoPublicationBuildErrorCode.RENDER_FAILED
        ) from exc

    try:
        manifest_payload = manifest_bundle.manifest_document.encode("utf-8")
        seal = M6OfflineDemoPublicationSealAuthorityV1(
            candidate_run_id=manifest_bundle.manifest.candidate_run_id,
            demo_manifest_id=manifest_bundle.manifest.demo_manifest_id,
            demo_manifest_content_sha256=hashlib.sha256(manifest_payload).hexdigest(),
            demo_manifest_size_bytes=len(manifest_payload),
            landing_content_sha256=hashlib.sha256(landing_payload).hexdigest(),
            landing_size_bytes=len(landing_payload),
            scenario_inventory_root_sha256=(
                manifest_bundle.manifest.scenario_inventory_root_sha256
            ),
        )
        seal_document = canonical_json(seal.model_dump(mode="json"))
    except (AttributeError, TypeError, UnicodeError, ValueError, ValidationError) as exc:
        raise M6OfflineDemoPublicationBuildError(
            M6OfflineDemoPublicationBuildErrorCode.PUBLICATION_INVARIANT_VIOLATION
        ) from exc
    return M6OfflineDemoPublicationBundle(
        manifest_bundle=manifest_bundle,
        scenario_result_documents=results,
        landing_document=landing_document,
        seal=seal,
        seal_document=seal_document,
    )


__all__ = [
    "M6OfflineDemoBuildError",
    "M6OfflineDemoBuildErrorCode",
    "M6OfflineDemoManifestBundle",
    "M6OfflineDemoPublicationBuildError",
    "M6OfflineDemoPublicationBuildErrorCode",
    "M6OfflineDemoPublicationBundle",
    "M6OfflineDemoScenarioResultDocument",
    "build_m6_offline_demo_manifest",
    "build_m6_offline_demo_publication",
]
