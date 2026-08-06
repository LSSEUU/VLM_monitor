from __future__ import annotations

import hashlib
import json
from functools import lru_cache

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.application.m6_replay_locked_closed_policy_publication import (
    build_m6_replay_locked_closed_policy_publication_bundle,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_publication import (
    M6RegressionPublicationDocumentKind,
)
from labcourt.contracts.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationDocumentEntry,
    M6ReplayLockedClosedPolicyPublicationDocumentKind,
    M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
)
from labcourt.schema_export import expected_schema_files
from tests.unit.test_m6_replay_locked_closed_policy_regression import _assemble, _facts


def _sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _publication():  # type: ignore[no-untyped-def]
    return build_m6_replay_locked_closed_policy_publication_bundle(_assemble(_facts()))


def test_closed_policy_publication_v2_is_additive_and_has_exact_document_kinds() -> None:
    assert tuple(M6ReplayLockedClosedPolicyPublicationDocumentKind) == (
        M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND,
        M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET,
        M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL,
        M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT,
    )
    assert tuple(M6RegressionPublicationDocumentKind) == (
        M6RegressionPublicationDocumentKind.COMMAND,
        M6RegressionPublicationDocumentKind.EVALUATOR_DATASET,
        M6RegressionPublicationDocumentKind.CANDIDATE_OUTPUT_INVENTORY,
        M6RegressionPublicationDocumentKind.REGRESSION_REPORT,
    )
    assert (
        M6ReplayLockedClosedPolicyPublicationDocumentKind is not M6RegressionPublicationDocumentKind
    )


def test_seal_v2_binds_closed_scope_catalog_and_all_four_physical_documents() -> None:
    publication = _publication()
    bundle = publication.report_bundle
    seal = publication.seal
    scope = bundle.execution_seal.execution_scope
    entries = {entry.kind: entry for entry in seal.entries}
    documents = {
        M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND: (bundle.command_document),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET: (
            bundle.evaluator_dataset_document
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL: (
            bundle.execution_seal_document
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT: (
            bundle.report_document
        ),
    }
    artifact_ids = {
        M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND: scope.command_id,
        M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET: (
            bundle.evaluator_dataset.dataset_snapshot_id
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL: (
            bundle.execution_seal.execution_seal_authority_id
        ),
        M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT: (
            bundle.report.report_id
        ),
    }

    assert seal.schema_version == ("m6-replay-locked-closed-policy-publication-seal-authority-v2")
    assert seal.candidate_run_id == scope.candidate_run_id
    assert seal.candidate_manifest_id == scope.candidate_manifest_id
    assert seal.source_catalog_authority_id == (
        bundle.stored_source_catalog.source_catalog.source_catalog_authority_id
    )
    assert seal.source_catalog_document_sha256 == bundle.stored_source_catalog.content_sha256
    assert seal.command_id == scope.command_id
    assert seal.execution_dataset_snapshot_id == scope.execution_dataset_snapshot_id
    assert seal.evaluator_dataset_snapshot_id == bundle.evaluator_dataset.dataset_snapshot_id
    assert seal.closed_policy_execution_seal_authority_id == (
        bundle.execution_seal.execution_seal_authority_id
    )
    assert seal.report_id == bundle.report.report_id
    assert set(entries) == set(M6ReplayLockedClosedPolicyPublicationDocumentKind)
    for kind, document in documents.items():
        entry = entries[kind]
        assert entry.artifact_id == artifact_ids[kind]
        assert entry.content_sha256 == _sha256(document)
        assert entry.size_bytes == len(document.encode("utf-8"))

    report_entry = entries[M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT]
    assert report_entry.relative_path == "regression.json"
    assert all(
        entry.relative_path != "regression.json"
        for kind, entry in entries.items()
        if kind is not M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT
    )
    assert publication.seal_document == canonical_json(seal.model_dump(mode="json"))


def test_source_catalog_is_scope_authority_not_a_fifth_publication_document() -> None:
    publication = _publication()
    catalog = publication.report_bundle.stored_source_catalog

    assert len(publication.seal.entries) == 4
    assert catalog.source_catalog.source_catalog_authority_id not in {
        entry.artifact_id for entry in publication.seal.entries
    }
    assert catalog.content_sha256 not in {
        entry.content_sha256 for entry in publication.seal.entries
    }
    assert "SOURCE_CATALOG" not in {
        kind.value for kind in M6ReplayLockedClosedPolicyPublicationDocumentKind
    }


def test_seal_v2_rejects_serialized_computed_claim_tampering() -> None:
    payload = _publication().seal.model_dump(mode="json")
    replacements = {
        "document_inventory_root_sha256": "0" * 64,
        "seal_id": "0" * 64,
        "seal_relative_path": "foreign/seal.json",
    }

    for claim, replacement in replacements.items():
        forged = dict(payload)
        forged[claim] = replacement
        with pytest.raises(ValidationError, match="derived CLOSED-policy publication"):
            M6ReplayLockedClosedPolicyPublicationSealAuthorityV2.model_validate(forged)


def test_entry_rejects_serialized_physical_identity_claim_tampering() -> None:
    entry = _publication().seal.entries[0]
    payload = entry.model_dump(mode="json")

    for claim, replacement in {
        "relative_path": "foreign.json",
        "entry_id": "0" * 64,
    }.items():
        forged = dict(payload)
        forged[claim] = replacement
        with pytest.raises(ValidationError, match="derived CLOSED-policy publication"):
            M6ReplayLockedClosedPolicyPublicationDocumentEntry.model_validate(forged)


def test_seal_v2_rejects_artifact_grafts_and_noncanonical_inventory() -> None:
    seal = _publication().seal
    payload = seal.model_dump(mode="json", exclude_computed_fields=True)
    entries = list(payload["entries"])
    entries[0] = dict(entries[0])
    entries[0]["artifact_id"] = "1" * 64
    payload["entries"] = entries

    with pytest.raises(ValidationError, match="entry conflicts with seal scope"):
        M6ReplayLockedClosedPolicyPublicationSealAuthorityV2.model_validate(payload)

    unordered = seal.model_dump(mode="json", exclude_computed_fields=True)
    unordered["entries"] = list(reversed(unordered["entries"]))
    with pytest.raises(ValidationError, match="canonical and ordered"):
        M6ReplayLockedClosedPolicyPublicationSealAuthorityV2.model_validate(unordered)

    duplicate = seal.model_dump(mode="json", exclude_computed_fields=True)
    duplicate["entries"][-1] = duplicate["entries"][0]
    with pytest.raises(ValidationError):
        M6ReplayLockedClosedPolicyPublicationSealAuthorityV2.model_validate(duplicate)


def test_seal_id_commits_every_explicit_scope_and_physical_inventory_binding() -> None:
    seal = _publication().seal
    replacements = {
        "candidate_run_id": "foreign-candidate-run",
        "candidate_manifest_id": "0" * 64,
        "source_catalog_authority_id": "0" * 64,
        "source_catalog_document_sha256": "0" * 64,
        "command_id": "0" * 64,
        "execution_dataset_snapshot_id": "0" * 64,
        "evaluator_dataset_snapshot_id": "0" * 64,
        "closed_policy_execution_seal_authority_id": "0" * 64,
        "report_id": "0" * 64,
    }
    entry_kinds = {
        "command_id": M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND,
        "evaluator_dataset_snapshot_id": (
            M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET
        ),
        "closed_policy_execution_seal_authority_id": (
            M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL
        ),
        "report_id": M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT,
    }

    for field, replacement in replacements.items():
        payload = seal.model_dump(mode="json", exclude_computed_fields=True)
        payload[field] = replacement
        if field in entry_kinds:
            entry = next(item for item in payload["entries"] if item["kind"] == entry_kinds[field])
            entry["artifact_id"] = replacement
        forged = M6ReplayLockedClosedPolicyPublicationSealAuthorityV2.model_validate(payload)
        assert forged.seal_id != seal.seal_id, field

    physical_payload = seal.model_dump(mode="json", exclude_computed_fields=True)
    physical_payload["entries"][0]["content_sha256"] = "0" * 64
    forged_inventory = M6ReplayLockedClosedPolicyPublicationSealAuthorityV2.model_validate(
        physical_payload
    )
    assert forged_inventory.document_inventory_root_sha256 != (seal.document_inventory_root_sha256)
    assert forged_inventory.seal_id != seal.seal_id


def test_seal_v2_schema_accepts_the_canonical_wire_document() -> None:
    filename = "m6-replay-locked-closed-policy-publication-seal-authority-v2.schema.json"
    schema = json.loads(expected_schema_files()[filename])
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_publication().seal.model_dump(mode="json"))
