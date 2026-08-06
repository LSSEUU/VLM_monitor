from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_demo_publication import (
    MAX_M6_OFFLINE_DEMO_LANDING_BYTES,
    MAX_M6_OFFLINE_DEMO_MANIFEST_BYTES,
    M6OfflineDemoPublicationSealAuthorityV1,
)
from labcourt.schema_export import expected_schema_files
from tests.contract.test_m6_demo_contracts import _manifest


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _seal() -> M6OfflineDemoPublicationSealAuthorityV1:
    manifest = _manifest()
    manifest_payload = canonical_json(manifest.model_dump(mode="json")).encode("utf-8")
    landing_payload = b"<!doctype html><title>LabCourt M6 offline demo</title>"
    return M6OfflineDemoPublicationSealAuthorityV1(
        candidate_run_id=manifest.candidate_run_id,
        demo_manifest_id=manifest.demo_manifest_id,
        demo_manifest_content_sha256=_sha256(manifest_payload),
        demo_manifest_size_bytes=len(manifest_payload),
        landing_content_sha256=_sha256(landing_payload),
        landing_size_bytes=len(landing_payload),
        scenario_inventory_root_sha256=manifest.scenario_inventory_root_sha256,
    )


def test_demo_publication_seal_binds_manifest_landing_and_scenario_inventory() -> None:
    seal = _seal()

    assert seal.schema_version == "m6-offline-demo-publication-seal-authority-v1"
    assert seal.candidate_run_id == _manifest().candidate_run_id
    assert seal.demo_manifest_id == _manifest().demo_manifest_id
    assert seal.scenario_inventory_root_sha256 == (_manifest().scenario_inventory_root_sha256)
    assert seal.landing_relative_path == "demo/index.html"
    assert seal.manifest_relative_path == (
        f"demo/manifests/{seal.demo_manifest_content_sha256}.json"
    )
    assert seal.seal_relative_path == "demo/seal.json"
    assert len(seal.seal_id) == 64


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("candidate_run_id", "other-offline-demo"),
        ("demo_manifest_id", "1" * 64),
        ("demo_manifest_content_sha256", "2" * 64),
        ("demo_manifest_size_bytes", 1),
        ("landing_content_sha256", "3" * 64),
        ("landing_size_bytes", 1),
        ("scenario_inventory_root_sha256", "4" * 64),
    ),
)
def test_demo_publication_seal_id_commits_every_publication_root(
    field: str,
    replacement: object,
) -> None:
    seal = _seal()

    assert seal.model_copy(update={field: replacement}).seal_id != seal.seal_id


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("demo_manifest_size_bytes", 0),
        ("demo_manifest_size_bytes", True),
        ("demo_manifest_size_bytes", MAX_M6_OFFLINE_DEMO_MANIFEST_BYTES + 1),
        ("landing_size_bytes", 0),
        ("landing_size_bytes", True),
        ("landing_size_bytes", MAX_M6_OFFLINE_DEMO_LANDING_BYTES + 1),
    ),
)
def test_demo_publication_sizes_are_strict_positive_and_bounded(
    field: str,
    replacement: object,
) -> None:
    payload = _seal().model_dump(mode="json", exclude_computed_fields=True)
    payload[field] = replacement

    with pytest.raises(ValidationError):
        M6OfflineDemoPublicationSealAuthorityV1.model_validate(payload)


@pytest.mark.parametrize(
    "claim",
    ("landing_relative_path", "manifest_relative_path", "seal_relative_path", "seal_id"),
)
def test_demo_publication_rejects_serialized_computed_claim_tampering(claim: str) -> None:
    payload = _seal().model_dump(mode="json")
    payload[claim] = "0" * 64 if claim == "seal_id" else "../forged"

    with pytest.raises(ValidationError):
        M6OfflineDemoPublicationSealAuthorityV1.model_validate(payload)


def test_demo_publication_schema_accepts_the_canonical_wire_document() -> None:
    filename = "m6-offline-demo-publication-seal-authority-v1.schema.json"
    schema = json.loads(expected_schema_files()[filename])

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_seal().model_dump(mode="json"))
