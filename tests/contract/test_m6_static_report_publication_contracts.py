from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from labcourt.contracts.m6_static_report_publication import (
    MAX_M6_PRIVACY_SAFE_STATIC_REPORT_HTML_BYTES,
    MAX_M6_PRIVACY_SAFE_STATIC_REPORT_MANIFEST_BYTES,
    M6PrivacySafeStaticReportPublicationSealAuthorityV1,
)
from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_static_report import (
    M6PrivacySafeStaticReportManifestAuthorityV1,
)
from labcourt.schema_export import expected_schema_files
from tests.contract.test_m6_static_report_contracts import _manifest


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _manifest_identity() -> tuple[
    M6PrivacySafeStaticReportManifestAuthorityV1,
    str,
    str,
    int,
]:
    manifest = _manifest()
    document = canonical_json(manifest.model_dump(mode="json"))
    payload = document.encode("utf-8")
    return manifest, document, hashlib.sha256(payload).hexdigest(), len(payload)


def _seal() -> M6PrivacySafeStaticReportPublicationSealAuthorityV1:
    manifest, _document, content_sha256, size_bytes = _manifest_identity()
    html = '<!doctype html><html lang="en"><body>report</body></html>\n'
    return M6PrivacySafeStaticReportPublicationSealAuthorityV1(
        candidate_run_id=manifest.candidate_run_id,
        report_id=manifest.report_id,
        regression_publication_seal_id=manifest.publication_seal_id,
        static_report_manifest_id=manifest.manifest_id,
        static_report_manifest_content_sha256=content_sha256,
        static_report_manifest_size_bytes=size_bytes,
        html_content_sha256=_sha256(html),
        html_size_bytes=len(html.encode("utf-8")),
        evidence_inventory_root_sha256=manifest.evidence_inventory_root_sha256,
    )


def test_publication_seal_has_fixed_version_and_commit_paths() -> None:
    seal = _seal()

    assert seal.schema_version == ("m6-privacy-safe-static-report-publication-seal-authority-v1")
    assert seal.html_relative_path == "index.html"
    assert seal.manifest_relative_path == (
        f"m6-static-report/manifests/{seal.static_report_manifest_content_sha256}.json"
    )
    assert seal.seal_relative_path == "m6-static-report/seal.json"
    assert not seal.html_relative_path.startswith(("/", "../"))
    assert not seal.manifest_relative_path.startswith(("/", "../"))
    assert not seal.seal_relative_path.startswith(("/", "../"))


def test_publication_seal_binds_manifest_html_and_evidence_inventory() -> None:
    manifest, _document, manifest_sha256, manifest_size = _manifest_identity()
    seal = _seal()

    assert seal.report_id == manifest.report_id
    assert seal.candidate_run_id == manifest.candidate_run_id
    assert seal.regression_publication_seal_id == manifest.publication_seal_id
    assert seal.static_report_manifest_id == manifest.manifest_id
    assert seal.static_report_manifest_content_sha256 == manifest_sha256
    assert seal.static_report_manifest_size_bytes == manifest_size
    assert seal.evidence_inventory_root_sha256 == (manifest.evidence_inventory_root_sha256)
    assert len(seal.html_content_sha256) == 64
    assert seal.html_size_bytes > 0


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("candidate_run_id", "foreign-candidate-run"),
        ("report_id", "1" * 64),
        ("regression_publication_seal_id", "7" * 64),
        ("static_report_manifest_id", "2" * 64),
        ("static_report_manifest_content_sha256", "3" * 64),
        ("static_report_manifest_size_bytes", 1),
        ("html_content_sha256", "4" * 64),
        ("html_size_bytes", 1),
        ("evidence_inventory_root_sha256", "5" * 64),
    ),
)
def test_seal_id_commits_every_publication_identity(
    field: str,
    replacement: object,
) -> None:
    seal = _seal()

    forged = seal.model_copy(update={field: replacement})

    assert forged.seal_id != seal.seal_id, field


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("static_report_manifest_size_bytes", 0),
        ("static_report_manifest_size_bytes", -1),
        ("static_report_manifest_size_bytes", True),
        (
            "static_report_manifest_size_bytes",
            MAX_M6_PRIVACY_SAFE_STATIC_REPORT_MANIFEST_BYTES + 1,
        ),
        ("html_size_bytes", 0),
        ("html_size_bytes", -1),
        ("html_size_bytes", True),
        ("html_size_bytes", MAX_M6_PRIVACY_SAFE_STATIC_REPORT_HTML_BYTES + 1),
    ),
)
def test_publication_sizes_are_strict_positive_and_bounded(
    field: str,
    value: object,
) -> None:
    payload = _seal().model_dump(mode="json", exclude_computed_fields=True)
    payload[field] = value

    with pytest.raises(ValidationError):
        M6PrivacySafeStaticReportPublicationSealAuthorityV1.model_validate(payload)


@pytest.mark.parametrize(
    "claim",
    ("html_relative_path", "manifest_relative_path", "seal_relative_path", "seal_id"),
)
def test_publication_seal_rejects_serialized_computed_claim_tampering(claim: str) -> None:
    payload = _seal().model_dump(mode="json")
    payload[claim] = "0" * 64 if claim == "seal_id" else "foreign/path.json"

    with pytest.raises(ValidationError):
        M6PrivacySafeStaticReportPublicationSealAuthorityV1.model_validate(payload)


def test_manifest_path_is_content_addressed_by_canonical_manifest_bytes() -> None:
    seal = _seal()
    changed = seal.model_copy(update={"static_report_manifest_content_sha256": "6" * 64})

    assert changed.manifest_relative_path == (f"m6-static-report/manifests/{'6' * 64}.json")
    assert changed.manifest_relative_path != seal.manifest_relative_path
    assert changed.seal_id != seal.seal_id


def test_static_report_publication_schema_accepts_canonical_wire_document() -> None:
    filename = "m6-privacy-safe-static-report-publication-seal-authority-v1.schema.json"
    schema = json.loads(expected_schema_files()[filename])
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_seal().model_dump(mode="json"))
