from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.application.m6_regression_source_catalog import (
    build_m6_regression_source_catalog,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
    M6RegressionSourceInventoryCutAuthority,
    M6RegressionSourceInventoryItem,
)
from labcourt.schema_export import expected_schema_files
from tests.unit.test_m6_regression_source_catalog import _sealed_source


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bundle():  # type: ignore[no-untyped-def]
    scope, source = _sealed_source()
    return build_m6_regression_source_catalog(
        run_scopes=(scope,),
        sealed_sources=(source,),
    )


def test_source_cut_and_catalog_computed_claims_round_trip_and_reject_tamper() -> None:
    bundle = _bundle()
    cut_payload = bundle.source_inventory_cut.model_dump(mode="json")
    catalog_payload = bundle.execution_source_catalog.model_dump(mode="json")
    assert M6RegressionSourceInventoryCutAuthority.model_validate(cut_payload) == (
        bundle.source_inventory_cut
    )
    assert M6RegressionExecutionSourceCatalogAuthority.model_validate(catalog_payload) == (
        bundle.execution_source_catalog
    )

    for claim, forged in (
        ("source_item_count", 99),
        ("source_inventory_root_sha256", "f" * 64),
        ("source_inventory_cut_authority_id", "f" * 64),
    ):
        attacked = dict(cut_payload)
        attacked[claim] = forged
        with pytest.raises(ValidationError, match=claim):
            M6RegressionSourceInventoryCutAuthority.model_validate(attacked)

    for claim, forged in (
        ("entry_count", 99),
        ("catalog_inventory_root_sha256", "f" * 64),
        ("source_catalog_authority_id", "f" * 64),
    ):
        attacked = dict(catalog_payload)
        attacked[claim] = forged
        with pytest.raises(ValidationError, match=claim):
            M6RegressionExecutionSourceCatalogAuthority.model_validate(attacked)


def test_source_cut_rejects_duplicate_reordered_and_forged_inventory() -> None:
    source_cut = _bundle().source_inventory_cut
    first = source_cut.items[0]
    second = first.model_copy(
        update={
            "sample_id": _sha("second-opaque-sample"),
            "source_case_id": "case-other",
            "source_case_document_sha256": _sha("case-other-document"),
            "source_seal_id": _sha("seal-other"),
            "source_seal_content_sha256": _sha("seal-other-content"),
            "input_authority_id": _sha("input-other"),
            "input_authority_document_sha256": _sha("input-other-document"),
            "input_authority_content_sha256": _sha("input-other-content"),
            "replay_input_closure_authority_id": _sha("closure-other"),
            "replay_input_closure_document_sha256": _sha("closure-other-document"),
            "replay_input_closure_content_sha256": _sha("closure-other-content"),
        }
    )
    ordered = tuple(sorted((first, second), key=lambda item: item.sample_id))
    run_cut = source_cut.run_cuts[0].model_copy(
        update={
            "source_item_count": 2,
            "source_scope_root_sha256": sha256_hex(
                [
                    "m6-regression-source-run-scope",
                    1,
                    first.source_run_id,
                    [item.source_scope_key for item in ordered],
                ]
            ),
        }
    )
    valid = source_cut.model_copy(update={"run_cuts": (run_cut,), "items": ordered})
    assert valid.source_item_count == 2

    with pytest.raises(ValidationError, match="sample_ids"):
        valid.model_copy(update={"items": tuple(reversed(ordered))})
    with pytest.raises(ValidationError, match="source Cases"):
        duplicate_case = second.model_copy(
            update={
                "source_case_id": first.source_case_id,
                "source_case_document_sha256": first.source_case_document_sha256,
            }
        )
        duplicated = tuple(sorted((first, duplicate_case), key=lambda item: item.sample_id))
        duplicated_cut = run_cut.model_copy(
            update={
                "source_scope_root_sha256": sha256_hex(
                    [
                        "m6-regression-source-run-scope",
                        1,
                        first.source_run_id,
                        [item.source_scope_key for item in duplicated],
                    ]
                )
            }
        )
        source_cut.model_copy(update={"run_cuts": (duplicated_cut,), "items": duplicated})


def test_candidate_catalog_forbids_evaluator_fields_and_closure_hash_forgery() -> None:
    catalog = _bundle().execution_source_catalog
    payload = catalog.model_dump(mode="json")
    attacked_entry = dict(payload["entries"][0])
    attacked_entry["memberships"] = ["GOLD"]
    payload["entries"] = [attacked_entry]
    with pytest.raises(ValidationError, match="Extra inputs"):
        M6RegressionExecutionSourceCatalogAuthority.model_validate(payload)

    entry = catalog.entries[0]
    with pytest.raises(ValidationError, match="closure binding differs"):
        entry.model_copy(update={"replay_input_closure_content_sha256": "f" * 64})
    with pytest.raises(ValidationError, match="source inventory root differs"):
        catalog.model_copy(update={"source_inventory_root_sha256": "f" * 64})


def test_publication_sample_ids_are_label_free_fixed_width_tokens() -> None:
    item = _bundle().source_inventory_cut.items[0]
    payload = item.model_dump(mode="json", exclude_computed_fields=True)
    payload["sample_id"] = "gold-001"
    with pytest.raises(ValidationError, match="opaque lowercase SHA-256"):
        M6RegressionSourceInventoryItem.model_validate(payload)


def test_source_cut_rejects_item_from_another_authority_or_audit_snapshot() -> None:
    source_cut = _bundle().source_inventory_cut
    item = source_cut.items[0]
    foreign_item = item.model_copy(
        update={
            "sealed_source_m5_authority_root_sha256": _sha("foreign-m5-root"),
            "sealed_audit_head_hash": _sha("foreign-audit-head"),
        }
    )

    with pytest.raises(ValidationError, match="different snapshots"):
        source_cut.model_copy(update={"items": (foreign_item,)})


def test_two_dataset_authority_schemas_validate_complete_documents() -> None:
    bundle = _bundle()
    artifacts = {
        "m6-regression-source-inventory-cut": bundle.source_inventory_cut,
        "m6-regression-execution-source-catalog": bundle.execution_source_catalog,
    }
    schemas = expected_schema_files()
    for name, artifact in artifacts.items():
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))
