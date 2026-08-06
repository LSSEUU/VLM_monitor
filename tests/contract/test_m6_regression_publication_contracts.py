from __future__ import annotations

import json
from dataclasses import replace

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.application.m6_regression_publication import (
    M6RegressionPublicationBuildError,
    M6RegressionPublicationBuildErrorCode,
    build_m6_regression_publication_bundle,
)
from labcourt.application.m6_upgrade_regression import (
    assemble_m6_upgrade_regression_report,
)
from labcourt.contracts.m6_regression_publication import (
    M6RegressionPublicationDocumentKind,
    M6RegressionPublicationSeal,
)
from labcourt.schema_export import expected_schema_files
from tests.unit.test_m6_upgrade_regression import _inputs, _v3_inputs


def _publication():  # type: ignore[no-untyped-def]
    report_bundle = assemble_m6_upgrade_regression_report(**_inputs())
    return build_m6_regression_publication_bundle(report_bundle)


def test_publication_seal_binds_exact_documents_and_fixed_commit_path() -> None:
    publication = _publication()
    seal = publication.seal
    entries = {item.kind: item for item in seal.entries}

    assert entries[M6RegressionPublicationDocumentKind.REGRESSION_REPORT].relative_path == (
        "regression.json"
    )
    assert seal.seal_relative_path == f"m6-regression/seals/{seal.report_id}/seal.json"
    assert seal.candidate_run_id == (
        publication.report_bundle.candidate_output_inventory.candidate_run_cut.candidate_run_id
    )
    assert all(publication.document_for(entry.kind).encode("utf-8") for entry in seal.entries)


def test_publication_seal_rejects_computed_claim_and_scope_tampering() -> None:
    publication = _publication()
    payload = publication.seal.model_dump(mode="json")
    payload["document_inventory_root_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="document_inventory_root_sha256"):
        M6RegressionPublicationSeal.model_validate(payload)

    entries = list(publication.seal.entries)
    entries[0] = entries[0].model_copy(update={"artifact_id": "1" * 64})
    with pytest.raises(ValidationError, match="entry conflicts with seal scope"):
        publication.seal.model_copy(update={"entries": tuple(entries)})


def test_publication_builder_rejects_a_tampered_report_bundle() -> None:
    publication = _publication()
    forged = replace(
        publication.report_bundle,
        report_document=publication.report_bundle.report_document + " ",
    )
    with pytest.raises(M6RegressionPublicationBuildError) as invalid:
        build_m6_regression_publication_bundle(forged)
    assert invalid.value.code == M6RegressionPublicationBuildErrorCode.REPORT_BUNDLE_INVALID


def test_publication_seal_schema_accepts_the_canonical_wire_document() -> None:
    seal = _publication().seal
    schema = json.loads(expected_schema_files()["m6-regression-publication-seal.schema.json"])
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(seal.model_dump(mode="json"))


def test_publication_seal_binds_terminal_v3_inventory_without_downgrade() -> None:
    report_bundle = assemble_m6_upgrade_regression_report(**_v3_inputs())

    publication = build_m6_regression_publication_bundle(report_bundle)

    assert report_bundle.candidate_output_inventory.schema_version == (
        "m6-upgrade-candidate-output-inventory-authority-v3"
    )
    assert publication.seal.candidate_output_inventory_authority_id == (
        report_bundle.candidate_output_inventory.candidate_output_inventory_authority_id
    )
