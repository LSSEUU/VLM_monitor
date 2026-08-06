"""Derive paired evaluator and blinded execution datasets from M6 selection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import (
    M6BaselineAuthorityKind,
    M6RegressionDatasetEntry,
    M6RegressionDatasetSnapshot,
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
)
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
    M6RegressionSourceInventoryCutAuthority,
)
from labcourt.contracts.m6_regression_selection import (
    M6RegressionEligibilityPolicyAuthority,
    M6RegressionSelectionDisposition,
    M6RegressionSelectionInventoryAuthority,
)
from labcourt.exceptions import LabCourtError

_ModelT = TypeVar("_ModelT", bound=BaseModel)

MAX_M6_REGRESSION_ASSEMBLY_DOCUMENT_BYTES = 256 * 1024 * 1024
MAX_M6_REGRESSION_ASSEMBLY_INPUT_BYTES = 512 * 1024 * 1024


class M6RegressionDatasetAssemblyErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    SOURCE_CATALOG_MISMATCH = "SOURCE_CATALOG_MISMATCH"
    SELECTION_INVENTORY_MISMATCH = "SELECTION_INVENTORY_MISMATCH"
    PENDING_APPEAL_BLOCKS_DATASET = "PENDING_APPEAL_BLOCKS_DATASET"
    STABILITY_SET_EMPTY = "STABILITY_SET_EMPTY"
    GOLD_SET_EMPTY = "GOLD_SET_EMPTY"
    CHALLENGE_SET_EMPTY = "CHALLENGE_SET_EMPTY"
    DATASET_INVARIANT_VIOLATION = "DATASET_INVARIANT_VIOLATION"


class M6RegressionDatasetAssemblyError(LabCourtError):
    """The selected evaluator scope could not become paired dataset artifacts."""

    def __init__(self, code: M6RegressionDatasetAssemblyErrorCode) -> None:
        if not isinstance(code, M6RegressionDatasetAssemblyErrorCode):
            raise TypeError("code must be an M6RegressionDatasetAssemblyErrorCode")
        self.code = code
        super().__init__(f"M6 regression dataset assembly failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6RegressionDatasetBundle:
    execution_dataset: M6RegressionExecutionDatasetSnapshot
    evaluator_dataset: M6RegressionDatasetSnapshot
    execution_dataset_document: str
    execution_dataset_content_sha256: str
    evaluator_dataset_document: str
    evaluator_dataset_content_sha256: str


def _fail(code: M6RegressionDatasetAssemblyErrorCode) -> NoReturn:
    raise M6RegressionDatasetAssemblyError(code)


def _canonical_model(
    value: object,
    expected: type[_ModelT],
    mismatch: M6RegressionDatasetAssemblyErrorCode,
) -> _ModelT:
    if not isinstance(value, expected):
        _fail(M6RegressionDatasetAssemblyErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(mismatch)
    if controlled != value:
        _fail(mismatch)
    return controlled


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _require_document(value: BaseModel, document: object) -> tuple[str, str]:
    if not isinstance(document, str):
        _fail(M6RegressionDatasetAssemblyErrorCode.DOCUMENT_INVALID)
    payload = document.encode("utf-8")
    if len(payload) > MAX_M6_REGRESSION_ASSEMBLY_DOCUMENT_BYTES:
        _fail(M6RegressionDatasetAssemblyErrorCode.DOCUMENT_TOO_LARGE)
    if document != _document(value):
        _fail(M6RegressionDatasetAssemblyErrorCode.DOCUMENT_INVALID)
    return document, hashlib.sha256(payload).hexdigest()


def assemble_m6_regression_dataset(
    *,
    source_inventory_cut: object,
    source_inventory_cut_document: object,
    execution_source_catalog: object,
    execution_source_catalog_document: object,
    eligibility_policy: object,
    eligibility_policy_document: object,
    selection_inventory: object,
    selection_inventory_document: object,
) -> M6RegressionDatasetBundle:
    """Produce both views in one loop so evaluator fields never enter candidate input."""

    cut = _canonical_model(
        source_inventory_cut,
        M6RegressionSourceInventoryCutAuthority,
        M6RegressionDatasetAssemblyErrorCode.SOURCE_CATALOG_MISMATCH,
    )
    catalog = _canonical_model(
        execution_source_catalog,
        M6RegressionExecutionSourceCatalogAuthority,
        M6RegressionDatasetAssemblyErrorCode.SOURCE_CATALOG_MISMATCH,
    )
    policy = _canonical_model(
        eligibility_policy,
        M6RegressionEligibilityPolicyAuthority,
        M6RegressionDatasetAssemblyErrorCode.SELECTION_INVENTORY_MISMATCH,
    )
    selection = _canonical_model(
        selection_inventory,
        M6RegressionSelectionInventoryAuthority,
        M6RegressionDatasetAssemblyErrorCode.SELECTION_INVENTORY_MISMATCH,
    )
    cut_document, cut_content_sha256 = _require_document(cut, source_inventory_cut_document)
    catalog_document, catalog_content_sha256 = _require_document(
        catalog,
        execution_source_catalog_document,
    )
    policy_document, policy_content_sha256 = _require_document(
        policy,
        eligibility_policy_document,
    )
    selection_document, selection_content_sha256 = _require_document(
        selection,
        selection_inventory_document,
    )
    if (
        sum(
            len(document.encode("utf-8"))
            for document in (
                cut_document,
                catalog_document,
                policy_document,
                selection_document,
            )
        )
        > MAX_M6_REGRESSION_ASSEMBLY_INPUT_BYTES
    ):
        _fail(M6RegressionDatasetAssemblyErrorCode.DOCUMENT_TOO_LARGE)
    if (
        catalog.baseline_manifest_id != cut.baseline_manifest_id
        or catalog.source_inventory_cut_authority_id != cut.source_inventory_cut_authority_id
        or catalog.source_inventory_cut_content_sha256 != cut_content_sha256
        or catalog.source_inventory_item_count != cut.source_item_count
        or catalog.source_inventory_root_sha256 != cut.source_inventory_root_sha256
        or tuple(item.sample_id for item in catalog.entries)
        != tuple(item.sample_id for item in cut.items)
    ):
        _fail(M6RegressionDatasetAssemblyErrorCode.SOURCE_CATALOG_MISMATCH)
    for item, catalog_entry in zip(cut.items, catalog.entries, strict=True):
        if (
            catalog_entry.source_item_id != item.source_item_id
            or catalog_entry.sample_id != item.sample_id
            or catalog_entry.source_seal_id != item.source_seal_id
            or catalog_entry.source_seal_content_sha256 != item.source_seal_content_sha256
            or catalog_entry.source_seal_size_bytes != item.source_seal_size_bytes
            or catalog_entry.input_authority_id != item.input_authority_id
            or catalog_entry.input_authority_document_sha256 != item.input_authority_document_sha256
            or catalog_entry.input_authority_content_sha256 != item.input_authority_content_sha256
            or catalog_entry.input_authority_size_bytes != item.input_authority_size_bytes
            or catalog_entry.replay_input_closure.replay_input_closure_authority_id
            != item.replay_input_closure_authority_id
            or catalog_entry.replay_input_closure.replay_input_closure_document_sha256
            != item.replay_input_closure_document_sha256
            or catalog_entry.replay_input_closure_content_sha256
            != item.replay_input_closure_content_sha256
            or catalog_entry.replay_input_closure_size_bytes != item.replay_input_closure_size_bytes
        ):
            _fail(M6RegressionDatasetAssemblyErrorCode.SOURCE_CATALOG_MISMATCH)
    if (
        selection.baseline_manifest_id != cut.baseline_manifest_id
        or selection.source_inventory_cut_authority_id != cut.source_inventory_cut_authority_id
        or selection.source_inventory_cut_content_sha256 != cut_content_sha256
        or selection.source_inventory_item_count != cut.source_item_count
        or selection.source_inventory_root_sha256 != cut.source_inventory_root_sha256
        or selection.eligibility_policy != policy
        or selection.eligibility_policy_content_sha256 != policy_content_sha256
        or tuple(item.source_item for item in selection.receipts) != cut.items
    ):
        _fail(M6RegressionDatasetAssemblyErrorCode.SELECTION_INVENTORY_MISMATCH)
    if selection.blocked_count:
        _fail(M6RegressionDatasetAssemblyErrorCode.PENDING_APPEAL_BLOCKS_DATASET)
    if not selection.stability_count:
        _fail(M6RegressionDatasetAssemblyErrorCode.STABILITY_SET_EMPTY)
    if not selection.gold_count:
        _fail(M6RegressionDatasetAssemblyErrorCode.GOLD_SET_EMPTY)
    if not selection.challenge_count:
        _fail(M6RegressionDatasetAssemblyErrorCode.CHALLENGE_SET_EMPTY)

    execution_entries: list[M6RegressionExecutionEntry] = []
    evaluator_entries: list[M6RegressionDatasetEntry] = []
    for catalog_entry, receipt in zip(catalog.entries, selection.receipts, strict=True):
        item = receipt.source_item
        closure = catalog_entry.replay_input_closure
        execution_entries.append(
            M6RegressionExecutionEntry(
                sample_id=item.sample_id,
                input_authority_id=item.input_authority_id,
                input_authority_document_sha256=item.input_authority_document_sha256,
                replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
                replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
            )
        )
        gold_authority = receipt.appeal_gold_authority
        evaluator_entries.append(
            M6RegressionDatasetEntry(
                sample_id=item.sample_id,
                input_authority_id=item.input_authority_id,
                input_authority_document_sha256=item.input_authority_document_sha256,
                replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
                replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
                baseline_authority_kind=(
                    M6BaselineAuthorityKind.MACHINE_TERMINAL_CASE
                    if receipt.selection_disposition
                    == M6RegressionSelectionDisposition.SELECTED_STABILITY
                    else M6BaselineAuthorityKind.PRE_APPEAL_CLOSED_CASE
                ),
                baseline_authority_id=receipt.baseline_snapshot.snapshot_id,
                baseline_authority_document_sha256=(receipt.baseline_snapshot_content_sha256),
                baseline_snapshot=receipt.baseline_snapshot,
                memberships=receipt.memberships,
                gold_truth=(gold_authority.gold_truth if gold_authority is not None else None),
                challenge_kinds=receipt.challenge_kinds,
            )
        )
    try:
        execution_dataset = M6RegressionExecutionDatasetSnapshot(
            baseline_manifest_id=cut.baseline_manifest_id,
            source_catalog_authority_id=catalog.source_catalog_authority_id,
            source_catalog_document_sha256=catalog_content_sha256,
            entries=tuple(execution_entries),
        )
        evaluator_dataset = M6RegressionDatasetSnapshot(
            baseline_manifest_id=cut.baseline_manifest_id,
            execution_dataset=execution_dataset,
            source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
            source_inventory_cut_document_sha256=cut_content_sha256,
            source_inventory_item_count=cut.source_item_count,
            source_inventory_root_sha256=cut.source_inventory_root_sha256,
            eligibility_policy_authority_id=policy.eligibility_policy_authority_id,
            eligibility_policy_document_sha256=policy_content_sha256,
            selection_inventory_authority_id=(selection.selection_inventory_authority_id),
            selection_inventory_document_sha256=selection_content_sha256,
            selection_receipt_count=selection.receipt_count,
            selection_inventory_root_sha256=(selection.selection_inventory_root_sha256),
            entries=tuple(evaluator_entries),
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6RegressionDatasetAssemblyErrorCode.DATASET_INVARIANT_VIOLATION)
    execution_document = _document(execution_dataset)
    evaluator_document = _document(evaluator_dataset)
    if any(
        len(document.encode("utf-8")) > MAX_M6_REGRESSION_ASSEMBLY_DOCUMENT_BYTES
        for document in (execution_document, evaluator_document)
    ):
        _fail(M6RegressionDatasetAssemblyErrorCode.DOCUMENT_TOO_LARGE)
    del cut_document, catalog_document, policy_document, selection_document
    return M6RegressionDatasetBundle(
        execution_dataset=execution_dataset,
        evaluator_dataset=evaluator_dataset,
        execution_dataset_document=execution_document,
        execution_dataset_content_sha256=hashlib.sha256(
            execution_document.encode("utf-8")
        ).hexdigest(),
        evaluator_dataset_document=evaluator_document,
        evaluator_dataset_content_sha256=hashlib.sha256(
            evaluator_document.encode("utf-8")
        ).hexdigest(),
    )


__all__ = [
    "MAX_M6_REGRESSION_ASSEMBLY_DOCUMENT_BYTES",
    "MAX_M6_REGRESSION_ASSEMBLY_INPUT_BYTES",
    "M6RegressionDatasetAssemblyError",
    "M6RegressionDatasetAssemblyErrorCode",
    "M6RegressionDatasetBundle",
    "assemble_m6_regression_dataset",
]
