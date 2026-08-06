from __future__ import annotations

import hashlib
import re
from dataclasses import fields, replace
from functools import lru_cache
from html import escape
from html.parser import HTMLParser

import pytest
from labcourt.application.m6_static_report import (
    M6PrivacySafeStaticReportBundle,
    M6StaticReportBuildError,
    M6StaticReportBuildErrorCode,
    build_m6_privacy_safe_static_report,
)

from labcourt.contracts.m6_static_report import (
    M6StaticReportEvidenceDisposition,
    M6StaticReportEvidenceItem,
)
from tests.unit.test_m6_replay_locked_closed_policy_publication import _publication


class _ReportHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.declarations: list[str] = []
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.text: list[str] = []
        self.rows: list[dict[str, object]] = []
        self.headings: list[tuple[int, str]] = []
        self._row: dict[str, object] | None = None
        self._heading_level: int | None = None
        self._heading_text: list[str] = []

    def handle_decl(self, decl: str) -> None:
        self.declarations.append(decl)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        self.tags.append((tag, attributes))
        if tag == "tr":
            self._row = {"text": [], "images": [], "headers": []}
        elif tag == "img" and self._row is not None:
            images = self._row["images"]
            assert isinstance(images, list)
            images.append(attributes)
        elif tag == "th" and self._row is not None:
            headers = self._row["headers"]
            assert isinstance(headers, list)
            headers.append(attributes)
        if re.fullmatch(r"h[1-6]", tag):
            self._heading_level = int(tag[1])
            self._heading_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "tr" and self._row is not None:
            self.rows.append(self._row)
            self._row = None
        if self._heading_level is not None and tag == f"h{self._heading_level}":
            self.headings.append(
                (self._heading_level, " ".join("".join(self._heading_text).split()))
            )
            self._heading_level = None
            self._heading_text = []

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._row is not None:
            row_text = self._row["text"]
            assert isinstance(row_text, list)
            row_text.append(data)
        if self._heading_level is not None:
            self._heading_text.append(data)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sample_ids() -> tuple[str, ...]:
    return tuple(result.sample_id for result in _publication().report_bundle.report.results)


def _evidence_items() -> tuple[M6StaticReportEvidenceItem, ...]:
    first, second = _sample_ids()
    return tuple(
        sorted(
            (
                M6StaticReportEvidenceItem(
                    sample_id=first,
                    disposition=(M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE),
                    artifact_relative_path=(f"privacy-media/{first}-privacy&processed.webp"),
                    artifact_content_sha256=_sha256("privacy-processed-evidence"),
                ),
                M6StaticReportEvidenceItem(
                    sample_id=second,
                    disposition=M6StaticReportEvidenceDisposition.RETENTION_PURGED,
                    deletion_audit_id="deletion-audit-static-report-1",
                    retention_reason_code="retention-window-expired",
                ),
            ),
            key=lambda item: item.sample_id,
        )
    )


@lru_cache(maxsize=1)
def _bundle() -> M6PrivacySafeStaticReportBundle:
    return build_m6_privacy_safe_static_report(_publication(), _evidence_items())


def _parsed(document: str | None = None) -> _ReportHTMLParser:
    parser = _ReportHTMLParser()
    parser.feed(_bundle().html_document if document is None else document)
    parser.close()
    return parser


def _row_for_sample(parser: _ReportHTMLParser, sample_id: str) -> dict[str, object]:
    matches = [row for row in parser.rows if sample_id in _row_text(row)]
    assert len(matches) == 1
    return matches[0]


def _row_text(row: dict[str, object]) -> str:
    value = row["text"]
    assert isinstance(value, list)
    return " ".join("".join(value).split())


def test_static_report_bundle_has_the_exact_public_contract() -> None:
    assert tuple(field.name for field in fields(M6PrivacySafeStaticReportBundle)) == (
        "manifest",
        "html_document",
        "html_content_sha256",
    )
    assert tuple(M6StaticReportBuildErrorCode) == (
        M6StaticReportBuildErrorCode.INVALID_ARGUMENT,
        M6StaticReportBuildErrorCode.PUBLICATION_BUNDLE_INVALID,
        M6StaticReportBuildErrorCode.EVIDENCE_INVENTORY_INVALID,
        M6StaticReportBuildErrorCode.MANIFEST_INVARIANT_VIOLATION,
        M6StaticReportBuildErrorCode.RENDER_FAILED,
    )


def test_builder_binds_the_exact_closed_publication_and_evidence_inventory() -> None:
    publication = _publication()
    bundle = _bundle()

    assert type(bundle) is M6PrivacySafeStaticReportBundle
    assert bundle.manifest.report_id == publication.report_bundle.report.report_id
    assert bundle.manifest.publication_seal_id == publication.seal.seal_id
    assert bundle.manifest.candidate_run_id == publication.seal.candidate_run_id
    assert bundle.manifest.evidence_items == _evidence_items()
    assert tuple(item.sample_id for item in bundle.manifest.evidence_items) == tuple(
        sorted(_sample_ids())
    )
    assert bundle.manifest.classification == "SYNTHETIC_PRECOMPUTED_FAKE"
    assert bundle.manifest.raw_media_included is False
    assert bundle.manifest.hidden_reasoning_included is False
    assert bundle.manifest.external_resources_included is False


def test_builder_canonicalizes_input_order_and_is_exactly_retryable() -> None:
    publication = _publication()
    evidence = _evidence_items()

    first = build_m6_privacy_safe_static_report(publication, tuple(reversed(evidence)))
    second = build_m6_privacy_safe_static_report(publication, evidence)

    assert first == second
    assert first.manifest.evidence_items == evidence


def test_html_hash_commits_the_exact_utf8_document() -> None:
    bundle = _bundle()

    assert (
        bundle.html_content_sha256
        == hashlib.sha256(bundle.html_document.encode("utf-8")).hexdigest()
    )


@pytest.mark.parametrize("value", [None, {}, object()])
def test_builder_rejects_untyped_publication_inputs_without_payloads(value: object) -> None:
    with pytest.raises(M6StaticReportBuildError) as raised:
        build_m6_privacy_safe_static_report(value, _evidence_items())

    assert raised.value.code is M6StaticReportBuildErrorCode.INVALID_ARGUMENT
    assert vars(raised.value) == {"code": M6StaticReportBuildErrorCode.INVALID_ARGUMENT}


@pytest.mark.parametrize("field", ["report_bundle", "seal", "seal_document"])
def test_builder_rebuild_rejects_tampered_closed_publication(field: str) -> None:
    publication = _publication()
    replacement: object = object()
    if field == "seal_document":
        replacement = publication.seal_document + " "
    forged = replace(publication, **{field: replacement})

    with pytest.raises(M6StaticReportBuildError) as raised:
        build_m6_privacy_safe_static_report(forged, _evidence_items())

    assert raised.value.code is M6StaticReportBuildErrorCode.PUBLICATION_BUNDLE_INVALID
    assert vars(raised.value) == {"code": M6StaticReportBuildErrorCode.PUBLICATION_BUNDLE_INVALID}


def test_builder_requires_an_exact_sample_bijection() -> None:
    publication = _publication()
    evidence = _evidence_items()
    foreign = evidence[0].model_copy(update={"sample_id": "foreign-sample"})
    cases: tuple[object, ...] = (
        evidence[:-1],
        (evidence[0], evidence[0]),
        (evidence[0], foreign),
        (evidence[0], object()),
        {item.sample_id: item for item in evidence},
    )

    for inventory in cases:
        with pytest.raises(M6StaticReportBuildError) as raised:
            build_m6_privacy_safe_static_report(publication, inventory)
        assert raised.value.code is (M6StaticReportBuildErrorCode.EVIDENCE_INVENTORY_INVALID)
        assert vars(raised.value) == {
            "code": M6StaticReportBuildErrorCode.EVIDENCE_INVENTORY_INVALID
        }


def test_build_error_requires_a_typed_code_and_carries_no_input_payload() -> None:
    with pytest.raises(TypeError, match="M6StaticReportBuildErrorCode"):
        M6StaticReportBuildError("INVALID_ARGUMENT")  # type: ignore[arg-type]

    error = M6StaticReportBuildError(M6StaticReportBuildErrorCode.RENDER_FAILED)
    assert vars(error) == {"code": M6StaticReportBuildErrorCode.RENDER_FAILED}


def test_renderer_is_one_standalone_offline_html_document() -> None:
    bundle = _bundle()
    parser = _parsed()
    tags = [tag for tag, _ in parser.tags]

    assert [declaration.casefold() for declaration in parser.declarations] == ["doctype html"]
    assert parser.tags[0][0] == "html"
    assert parser.tags[0][1].get("lang")
    assert tags.count("html") == 1
    assert tags.count("head") == 1
    assert tags.count("body") == 1
    assert "style" in tags
    assert "link" not in tags
    assert "script" not in tags
    assert "iframe" not in tags
    assert "object" not in tags
    assert "embed" not in tags
    assert "http://" not in bundle.html_document.casefold()
    assert "https://" not in bundle.html_document.casefold()
    assert "@import" not in bundle.html_document.casefold()
    assert "url(" not in bundle.html_document.casefold()

    for _, attributes in parser.tags:
        for name in ("href", "src"):
            target = attributes.get(name)
            if target is None or target.startswith("#"):
                continue
            assert not target.startswith(("/", "//"))
            assert ":" not in target.split("/", maxsplit=1)[0]


def test_renderer_exposes_only_controlled_publication_artifact_links() -> None:
    publication = _publication()
    parser = _parsed()
    hrefs = {
        attributes["href"]
        for tag, attributes in parser.tags
        if tag == "a"
        and attributes.get("href") is not None
        and not attributes["href"].startswith("#")
    }
    expected = {entry.relative_path for entry in publication.seal.entries}
    expected.add(publication.seal.seal_relative_path)

    assert hrefs == expected


def test_renderer_has_semantic_navigation_headings_and_evidence_table() -> None:
    parser = _parsed()
    tags = [tag for tag, _ in parser.tags]
    skip_links = [
        attributes
        for tag, attributes in parser.tags
        if tag == "a" and attributes.get("href") == "#main-content"
    ]
    mains = [
        attributes
        for tag, attributes in parser.tags
        if tag == "main" and attributes.get("id") == "main-content"
    ]

    assert len(skip_links) == 1
    assert len(mains) == 1
    assert tags.count("h1") == 1
    assert tags.count("table") >= 1
    assert tags.count("caption") >= 1
    assert parser.headings[0][0] == 1
    assert any(level == 2 for level, _ in parser.headings)
    assert all(
        next_level <= level + 1
        for (level, _), (next_level, _) in zip(parser.headings, parser.headings[1:], strict=False)
    )
    headers = [attributes for tag, attributes in parser.tags if tag == "th"]
    assert headers
    assert all(attributes.get("scope") in {"col", "row"} for attributes in headers)


def test_renderer_has_visible_classification_and_non_color_status_labels() -> None:
    parser = _parsed()
    document_text = " ".join("".join(parser.text).split())

    assert "SYNTHETIC_PRECOMPUTED_FAKE" in document_text
    assert "synthetic" in document_text.casefold()
    assert "precomputed" in document_text.casefold()
    assert "fake" in document_text.casefold()
    for item in _evidence_items():
        row = _row_for_sample(parser, item.sample_id)
        assert item.disposition.value in _row_text(row)


def test_available_evidence_uses_exact_escaped_relative_src_and_stable_alt() -> None:
    parser = _parsed()
    available = next(
        item
        for item in _evidence_items()
        if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
    )
    row = _row_for_sample(parser, available.sample_id)
    images = row["images"]

    assert isinstance(images, list)
    assert len(images) == 1
    image = images[0]
    assert isinstance(image, dict)
    assert image.get("src") == available.artifact_relative_path
    assert image.get("alt") == (f"Privacy-processed evidence for sample {available.sample_id}")
    assert available.artifact_relative_path is not None
    assert escape(available.artifact_relative_path, quote=True) in _bundle().html_document
    assert available.artifact_relative_path not in _bundle().html_document


def test_retention_purged_row_is_text_only_and_shows_deletion_authority() -> None:
    parser = _parsed()
    purged = next(
        item
        for item in _evidence_items()
        if item.disposition is M6StaticReportEvidenceDisposition.RETENTION_PURGED
    )
    row = _row_for_sample(parser, purged.sample_id)
    text = _row_text(row)

    assert row["images"] == []
    assert purged.disposition.value in text
    assert purged.deletion_audit_id is not None
    assert purged.retention_reason_code is not None
    assert purged.deletion_audit_id in text
    assert purged.retention_reason_code in text


def test_not_published_row_is_text_only_and_never_gets_an_image_src() -> None:
    evidence = list(_evidence_items())
    purged_index = next(
        index
        for index, item in enumerate(evidence)
        if item.disposition is M6StaticReportEvidenceDisposition.RETENTION_PURGED
    )
    sample_id = evidence[purged_index].sample_id
    evidence[purged_index] = M6StaticReportEvidenceItem(
        sample_id=sample_id,
        disposition=M6StaticReportEvidenceDisposition.NOT_PUBLISHED,
    )
    bundle = build_m6_privacy_safe_static_report(
        _publication(), tuple(sorted(evidence, key=lambda item: item.sample_id))
    )
    parser = _parsed(bundle.html_document)
    row = _row_for_sample(parser, sample_id)

    assert row["images"] == []
    assert M6StaticReportEvidenceDisposition.NOT_PUBLISHED.value in _row_text(row)


def test_renderer_does_not_embed_raw_authority_documents_or_hidden_reasoning() -> None:
    publication = _publication()
    document = _bundle().html_document
    raw_documents = (
        publication.report_bundle.command_document,
        publication.report_bundle.evaluator_dataset_document,
        publication.report_bundle.execution_seal_document,
        publication.report_bundle.report_document,
        publication.seal_document,
    )

    assert "<pre" not in document.casefold()
    assert all(raw_document not in document for raw_document in raw_documents)


def test_renderer_supports_375px_accessibility_and_reduced_motion() -> None:
    document = _bundle().html_document
    parser = _parsed()
    metas = [attributes for tag, attributes in parser.tags if tag == "meta"]

    assert any(
        meta.get("name") == "viewport"
        and meta.get("content") == "width=device-width, initial-scale=1"
        for meta in metas
    )
    assert re.search(
        r"@media\s*\([^)]*max-width\s*:\s*375px[^)]*\)",
        document,
        re.IGNORECASE,
    )
    assert re.search(
        r"@media\s*\([^)]*prefers-reduced-motion\s*:\s*reduce[^)]*\)",
        document,
        re.IGNORECASE,
    )
    assert ":focus-visible" in document
    assert re.search(r"font-size\s*:\s*(?:16px|1rem|100%)", document)
    assert "overflow-wrap" in document
    assert "max-width: 100%" in document
