from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m6_static_report import (
    M6PrivacySafeStaticReportManifestAuthorityV1,
    M6StaticReportEvidenceDisposition,
    M6StaticReportEvidenceItem,
)
from labcourt.schema_export import expected_schema_files


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _available(
    sample_id: str = "sample-available",
    path: str = "privacy-media/sample-available.webp",
) -> M6StaticReportEvidenceItem:
    return M6StaticReportEvidenceItem(
        sample_id=sample_id,
        disposition=M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE,
        artifact_relative_path=path,
        artifact_content_sha256=_sha256(f"privacy-evidence:{sample_id}"),
    )


def _purged(sample_id: str = "sample-purged") -> M6StaticReportEvidenceItem:
    return M6StaticReportEvidenceItem(
        sample_id=sample_id,
        disposition=M6StaticReportEvidenceDisposition.RETENTION_PURGED,
        deletion_audit_id="deletion-audit-1",
        retention_reason_code="retention-expired",
    )


def _not_published(sample_id: str = "sample-not-published") -> M6StaticReportEvidenceItem:
    return M6StaticReportEvidenceItem(
        sample_id=sample_id,
        disposition=M6StaticReportEvidenceDisposition.NOT_PUBLISHED,
    )


def _manifest() -> M6PrivacySafeStaticReportManifestAuthorityV1:
    return M6PrivacySafeStaticReportManifestAuthorityV1(
        report_id=_sha256("report"),
        publication_seal_id=_sha256("publication-seal"),
        candidate_run_id="candidate-run",
        evidence_items=(_available(), _not_published(), _purged()),
    )


def test_evidence_dispositions_are_exact_and_additive() -> None:
    assert tuple(M6StaticReportEvidenceDisposition) == (
        M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE,
        M6StaticReportEvidenceDisposition.RETENTION_PURGED,
        M6StaticReportEvidenceDisposition.NOT_PUBLISHED,
    )


def test_evidence_item_enforces_three_disjoint_privacy_states() -> None:
    available = _available()
    purged = _purged()
    not_published = _not_published()

    assert available.artifact_relative_path == "privacy-media/sample-available.webp"
    assert available.artifact_content_sha256 is not None
    assert available.deletion_audit_id is None
    assert available.retention_reason_code is None
    assert purged.artifact_relative_path is None
    assert purged.artifact_content_sha256 is None
    assert purged.deletion_audit_id == "deletion-audit-1"
    assert purged.retention_reason_code == "retention-expired"
    assert not_published.artifact_relative_path is None
    assert not_published.artifact_content_sha256 is None
    assert not_published.deletion_audit_id is None
    assert not_published.retention_reason_code is None


@pytest.mark.parametrize(
    "payload",
    (
        {
            "sample_id": "available-missing-path",
            "disposition": "PRIVACY_PROCESSED_AVAILABLE",
            "artifact_content_sha256": "0" * 64,
        },
        {
            "sample_id": "available-missing-hash",
            "disposition": "PRIVACY_PROCESSED_AVAILABLE",
            "artifact_relative_path": "privacy-media/available.png",
        },
        {
            "sample_id": "available-with-deletion",
            "disposition": "PRIVACY_PROCESSED_AVAILABLE",
            "artifact_relative_path": "privacy-media/available.png",
            "artifact_content_sha256": "0" * 64,
            "deletion_audit_id": "foreign-delete",
            "retention_reason_code": "foreign-reason",
        },
        {
            "sample_id": "purged-missing-audit",
            "disposition": "RETENTION_PURGED",
            "retention_reason_code": "retention-expired",
        },
        {
            "sample_id": "purged-missing-reason",
            "disposition": "RETENTION_PURGED",
            "deletion_audit_id": "deletion-audit-1",
        },
        {
            "sample_id": "purged-with-artifact",
            "disposition": "RETENTION_PURGED",
            "artifact_relative_path": "privacy-media/purged.png",
            "artifact_content_sha256": "0" * 64,
            "deletion_audit_id": "deletion-audit-1",
            "retention_reason_code": "retention-expired",
        },
        {
            "sample_id": "not-published-with-artifact",
            "disposition": "NOT_PUBLISHED",
            "artifact_relative_path": "privacy-media/not-published.png",
            "artifact_content_sha256": "0" * 64,
        },
        {
            "sample_id": "not-published-with-deletion",
            "disposition": "NOT_PUBLISHED",
            "deletion_audit_id": "deletion-audit-1",
            "retention_reason_code": "retention-expired",
        },
    ),
)
def test_evidence_item_rejects_cross_state_field_grafts(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        M6StaticReportEvidenceItem.model_validate(payload)


@pytest.mark.parametrize(
    "path",
    (
        "../raw.png",
        "/absolute/raw.png",
        "C:/raw.png",
        "//server/raw.png",
        "https://example.test/raw.png",
        "privacy-media\\raw.png",
        "evidence/raw.png",
        "privacy-media/raw.jpg",
        "privacy-media/raw.svg",
        "privacy-media/raw.PNG",
    ),
)
def test_available_evidence_requires_safe_privacy_media_raster_path(path: str) -> None:
    with pytest.raises(ValidationError):
        _available(path=path)


def test_available_evidence_accepts_only_supported_privacy_processed_formats() -> None:
    for suffix in ("png", "webp", "avif"):
        assert _available(path=f"privacy-media/evidence.{suffix}").artifact_relative_path == (
            f"privacy-media/evidence.{suffix}"
        )


@pytest.mark.parametrize(
    "path",
    (
        "privacy-media/CON.webp",
        "privacy-media/con.png",
        "privacy-media/AUX.processed.avif",
        "privacy-media/LPT1.webp",
        "privacy-media/evidence?.webp",
        "privacy-media/evidence<.png",
        "privacy-media/evidence\x1f.webp",
        "privacy-media/evidence\x7f.webp",
        "privacy-media/evidence\x85.webp",
        "privacy-media/evidence\ud800.webp",
    ),
)
def test_available_evidence_rejects_nonportable_windows_and_unicode_paths(
    path: str,
) -> None:
    with pytest.raises(ValidationError):
        _available(path=path)


@pytest.mark.parametrize(
    ("first_path", "second_path"),
    (
        ("privacy-media/Evidence.webp", "privacy-media/evidence.webp"),
        ("privacy-media/\uff21.webp", "privacy-media/A.webp"),
        (
            "privacy-media/folder.webp",
            "privacy-media/folder.webp/nested.png",
        ),
    ),
)
def test_manifest_available_paths_are_nfkc_casefold_unique_and_prefix_free(
    first_path: str,
    second_path: str,
) -> None:
    manifest = _manifest()

    with pytest.raises(ValidationError, match=r"portable|unique|prefix-free"):
        M6PrivacySafeStaticReportManifestAuthorityV1(
            report_id=manifest.report_id,
            publication_seal_id=manifest.publication_seal_id,
            candidate_run_id=manifest.candidate_run_id,
            evidence_items=(
                _available("sample-a", first_path),
                _available("sample-b", second_path),
            ),
        )


def test_manifest_is_fixed_to_offline_synthetic_privacy_safe_classification() -> None:
    manifest = _manifest()

    assert manifest.schema_version == ("m6-privacy-safe-static-report-manifest-authority-v1")
    assert manifest.classification == "SYNTHETIC_PRECOMPUTED_FAKE"
    assert manifest.raw_media_included is False
    assert manifest.hidden_reasoning_included is False
    assert manifest.external_resources_included is False
    assert manifest.evidence_item_count == 3
    assert tuple(item.sample_id for item in manifest.evidence_items) == (
        "sample-available",
        "sample-not-published",
        "sample-purged",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("classification", "REAL_PRODUCTION"),
        ("raw_media_included", True),
        ("hidden_reasoning_included", True),
        ("external_resources_included", True),
    ),
)
def test_manifest_rejects_any_unsafe_classification_or_capability(
    field: str,
    value: object,
) -> None:
    payload = _manifest().model_dump(mode="json", exclude_computed_fields=True)
    payload[field] = value

    with pytest.raises(ValidationError):
        M6PrivacySafeStaticReportManifestAuthorityV1.model_validate(payload)


def test_manifest_requires_unique_canonical_evidence_order() -> None:
    manifest = _manifest()
    unordered = manifest.model_dump(mode="json", exclude_computed_fields=True)
    unordered["evidence_items"] = list(reversed(unordered["evidence_items"]))
    with pytest.raises(ValidationError, match=r"canonical|ordered"):
        M6PrivacySafeStaticReportManifestAuthorityV1.model_validate(unordered)

    duplicate = manifest.model_dump(mode="json", exclude_computed_fields=True)
    duplicate["evidence_items"][-1] = duplicate["evidence_items"][0]
    with pytest.raises(ValidationError, match=r"unique|exact"):
        M6PrivacySafeStaticReportManifestAuthorityV1.model_validate(duplicate)


def test_evidence_and_manifest_reject_serialized_computed_claim_tampering() -> None:
    evidence = _available()
    evidence_payload = evidence.model_dump(mode="json")
    evidence_payload["evidence_item_id"] = "0" * 64
    with pytest.raises(ValidationError):
        M6StaticReportEvidenceItem.model_validate(evidence_payload)

    manifest = _manifest()
    for claim, replacement in {
        "evidence_item_count": 99,
        "evidence_inventory_root_sha256": "0" * 64,
        "manifest_id": "0" * 64,
    }.items():
        payload = manifest.model_dump(mode="json")
        payload[claim] = replacement
        with pytest.raises(ValidationError):
            M6PrivacySafeStaticReportManifestAuthorityV1.model_validate(payload)


def test_manifest_id_commits_report_publication_run_and_evidence_inventory() -> None:
    manifest = _manifest()
    for field, replacement in {
        "report_id": "1" * 64,
        "publication_seal_id": "2" * 64,
        "candidate_run_id": "foreign-candidate-run",
    }.items():
        forged = manifest.model_copy(update={field: replacement})
        assert forged.manifest_id != manifest.manifest_id, field

    changed_evidence = _available(path="privacy-media/changed.avif")
    forged_inventory = M6PrivacySafeStaticReportManifestAuthorityV1(
        report_id=manifest.report_id,
        publication_seal_id=manifest.publication_seal_id,
        candidate_run_id=manifest.candidate_run_id,
        evidence_items=(changed_evidence, _not_published(), _purged()),
    )
    assert forged_inventory.evidence_inventory_root_sha256 != (
        manifest.evidence_inventory_root_sha256
    )
    assert forged_inventory.manifest_id != manifest.manifest_id


def test_static_report_manifest_schema_accepts_canonical_wire_document() -> None:
    filename = "m6-privacy-safe-static-report-manifest-authority-v1.schema.json"
    schema = json.loads(expected_schema_files()[filename])
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_manifest().model_dump(mode="json"))
