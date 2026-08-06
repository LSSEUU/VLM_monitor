"""Assemble one CLOSED-policy replay Seal into the frozen M6 report contract."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus, ReproducibilityMode
from labcourt.contracts.m6_regression import (
    M6RegressionCaseResult,
    M6RegressionDatasetSnapshot,
    M6RegressionReport,
)
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)

MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_DOCUMENT_BYTES = 256 * 1024 * 1024
MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_INPUT_BYTES = 768 * 1024 * 1024

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    MODE_NOT_REPLAY_LOCKED = "MODE_NOT_REPLAY_LOCKED"
    SOURCE_CATALOG_MISMATCH = "SOURCE_CATALOG_MISMATCH"
    COMMAND_DATASET_MISMATCH = "COMMAND_DATASET_MISMATCH"
    EXECUTION_SEAL_MISMATCH = "EXECUTION_SEAL_MISMATCH"
    BASELINE_SOURCE_MISMATCH = "BASELINE_SOURCE_MISMATCH"
    REPORT_INVARIANT_VIOLATION = "REPORT_INVARIANT_VIOLATION"


class M6ReplayLockedClosedPolicyRegressionAssemblyError(LabCourtError):
    """The exact CLOSED replay inventory could not become a regression report."""

    def __init__(
        self,
        code: M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode,
    ) -> None:
        if not isinstance(code, M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode):
            raise TypeError("code must be an M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode")
        self.code = code
        super().__init__(f"M6 replay-locked CLOSED-policy regression assembly failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedPolicyRegressionReportBundle:
    """Canonical report inputs retained beside the derived report bytes."""

    report: M6RegressionReport
    report_document: str
    report_content_sha256: str
    command_document: str
    command_content_sha256: str
    evaluator_dataset: M6RegressionDatasetSnapshot
    evaluator_dataset_document: str
    evaluator_dataset_content_sha256: str
    stored_source_catalog: M6StoredRegressionExecutionSourceCatalog
    execution_seal: M6ReplayLockedClosedPolicyExecutionSealAuthorityV2
    execution_seal_document: str
    execution_seal_content_sha256: str


def _fail(
    code: M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode,
) -> NoReturn:
    raise M6ReplayLockedClosedPolicyRegressionAssemblyError(code)


def _canonical_model(
    value: object,
    expected: type[_ModelT],
    code: M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode,
) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(code)
    if controlled != value:
        _fail(code)
    return controlled


def _controlled_catalog(
    value: object,
) -> M6StoredRegressionExecutionSourceCatalog:
    if type(value) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.INVALID_ARGUMENT)
    assert isinstance(value, M6StoredRegressionExecutionSourceCatalog)
    try:
        return M6StoredRegressionExecutionSourceCatalog(
            source_catalog=type(value.source_catalog).model_validate(
                value.source_catalog.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            ),
            canonical_document=value.canonical_document,
            content_sha256=value.content_sha256,
            size_bytes=value.size_bytes,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.SOURCE_CATALOG_MISMATCH)


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _require_document(
    value: BaseModel,
    document: object,
) -> tuple[str, str, int]:
    if not isinstance(document, str):
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.DOCUMENT_INVALID)
    try:
        payload = document.encode("utf-8")
    except UnicodeEncodeError:
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.DOCUMENT_INVALID)
    if len(payload) > MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_DOCUMENT_BYTES:
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.DOCUMENT_TOO_LARGE)
    if document != _document(value):
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.DOCUMENT_INVALID)
    return document, hashlib.sha256(payload).hexdigest(), len(payload)


def _require_catalog_dataset_join(
    stored: M6StoredRegressionExecutionSourceCatalog,
    dataset: M6RegressionDatasetSnapshot,
) -> None:
    catalog = stored.source_catalog
    execution = dataset.execution_dataset
    if (
        execution.source_catalog_authority_id != catalog.source_catalog_authority_id
        or execution.source_catalog_document_sha256 != stored.content_sha256
        or execution.baseline_manifest_id != catalog.baseline_manifest_id
        or dataset.baseline_manifest_id != catalog.baseline_manifest_id
        or dataset.source_inventory_cut_authority_id != catalog.source_inventory_cut_authority_id
        or dataset.source_inventory_cut_document_sha256
        != catalog.source_inventory_cut_content_sha256
        or dataset.source_inventory_item_count != catalog.source_inventory_item_count
        or dataset.source_inventory_root_sha256 != catalog.source_inventory_root_sha256
        or len(dataset.entries) != len(catalog.entries)
    ):
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.SOURCE_CATALOG_MISMATCH)
    for catalog_entry, evaluator_entry, execution_entry in zip(
        catalog.entries,
        dataset.entries,
        execution.entries,
        strict=True,
    ):
        closure = catalog_entry.replay_input_closure
        expected = (
            catalog_entry.sample_id,
            catalog_entry.input_authority_id,
            catalog_entry.input_authority_document_sha256,
            closure.replay_input_closure_authority_id,
            closure.replay_input_closure_document_sha256,
        )
        if expected != (
            evaluator_entry.sample_id,
            evaluator_entry.input_authority_id,
            evaluator_entry.input_authority_document_sha256,
            evaluator_entry.replay_input_closure_authority_id,
            evaluator_entry.replay_input_closure_document_sha256,
        ) or expected != (
            execution_entry.sample_id,
            execution_entry.input_authority_id,
            execution_entry.input_authority_document_sha256,
            execution_entry.replay_input_closure_authority_id,
            execution_entry.replay_input_closure_document_sha256,
        ):
            _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.SOURCE_CATALOG_MISMATCH)


def _require_seal_scope_join(
    stored: M6StoredRegressionExecutionSourceCatalog,
    dataset: M6RegressionDatasetSnapshot,
    seal: M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
) -> None:
    catalog = stored.source_catalog
    scope = seal.execution_scope
    pre_policy_scope = scope.pre_policy_execution_scope
    command = pre_policy_scope.command
    if command.mode != ReproducibilityMode.REPLAY_LOCKED:
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.MODE_NOT_REPLAY_LOCKED)
    if (
        command.execution_dataset_snapshot_id
        != dataset.execution_dataset.execution_dataset_snapshot_id
        or command.baseline_manifest_id != dataset.baseline_manifest_id
        or command.candidate_manifest_id != dataset.baseline_manifest_id
        or command.policy_authority.config_sha256 != scope.locked_config_sha256
        or pre_policy_scope.execution_dataset != dataset.execution_dataset
    ):
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.COMMAND_DATASET_MISMATCH)
    expected_source_runs = tuple(
        sorted({entry.replay_input_closure.source_run_id for entry in catalog.entries})
    )
    if (
        pre_policy_scope.source_catalog_content_sha256 != stored.content_sha256
        or pre_policy_scope.source_catalog_size_bytes != stored.size_bytes
        or pre_policy_scope.source_catalog_entry_count != len(catalog.entries)
        or pre_policy_scope.source_catalog_entry_ids
        != tuple(entry.catalog_entry_id for entry in catalog.entries)
        or pre_policy_scope.source_run_ids != expected_source_runs
        or len(seal.sample_executions) != len(dataset.entries)
        or seal.execution_receipt_count != len(dataset.entries)
    ):
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.EXECUTION_SEAL_MISMATCH)


def _results_from_same_source(
    stored: M6StoredRegressionExecutionSourceCatalog,
    dataset: M6RegressionDatasetSnapshot,
    seal: M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
) -> tuple[M6RegressionCaseResult, ...]:
    results: list[M6RegressionCaseResult] = []
    for catalog_entry, evaluator_entry, record in zip(
        stored.source_catalog.entries,
        dataset.entries,
        seal.sample_executions,
        strict=True,
    ):
        closure = catalog_entry.replay_input_closure
        baseline = evaluator_entry.baseline_snapshot
        if (
            record.execution_entry != dataset.execution_dataset.entries[record.ledger_sequence]
            or record.execution_entry.sample_id != catalog_entry.sample_id
            or record.replay_input_closure != closure
        ):
            _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.EXECUTION_SEAL_MISMATCH)
        if (
            baseline is None
            or baseline.case_status != CaseStatus.CLOSED
            or closure.source_case_id is None
            or closure.source_case_revision is None
            or closure.source_case_document_sha256 is None
            or baseline.sample_id != closure.sample_id
            or baseline.source_run_id != closure.source_run_id
            or baseline.source_case_id != closure.source_case_id
            or baseline.source_case_revision != closure.source_case_revision
            or baseline.source_case_document_sha256 != closure.source_case_document_sha256
            or baseline.manifest_id != closure.source_manifest_id
            or baseline.snapshot_id != record.source_snapshot_id
            or baseline.semantic_case_hash != record.source_semantic_case_hash
            or baseline.final_decision != record.policy_causal_cut.source_closed_case.final_decision
        ):
            _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.BASELINE_SOURCE_MISMATCH)
        results.append(
            M6RegressionCaseResult(
                entry_id=evaluator_entry.entry_id,
                sample_id=evaluator_entry.sample_id,
                baseline_snapshot=baseline,
                candidate_snapshot=record.candidate_snapshot,
            )
        )
    return tuple(results)


def assemble_m6_replay_locked_closed_policy_regression_report(
    *,
    stored_source_catalog: object,
    evaluator_dataset: object,
    evaluator_dataset_document: object,
    execution_seal: object,
    execution_seal_document: object,
) -> M6ReplayLockedClosedPolicyRegressionReportBundle:
    """Build a report only after catalog, evaluator truth, and CLOSED Seal join."""

    stored = _controlled_catalog(stored_source_catalog)
    dataset = _canonical_model(
        evaluator_dataset,
        M6RegressionDatasetSnapshot,
        M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.COMMAND_DATASET_MISMATCH,
    )
    seal = _canonical_model(
        execution_seal,
        M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
        M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.EXECUTION_SEAL_MISMATCH,
    )
    controlled_dataset_document, dataset_content_sha256, dataset_size = _require_document(
        dataset,
        evaluator_dataset_document,
    )
    controlled_seal_document, seal_content_sha256, seal_size = _require_document(
        seal,
        execution_seal_document,
    )
    if (
        stored.size_bytes + dataset_size + seal_size
        > MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_INPUT_BYTES
    ):
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.DOCUMENT_TOO_LARGE)

    _require_catalog_dataset_join(stored, dataset)
    _require_seal_scope_join(stored, dataset, seal)
    results = _results_from_same_source(stored, dataset, seal)
    command = seal.execution_scope.pre_policy_execution_scope.command
    try:
        report = M6RegressionReport(
            command=command,
            dataset=dataset,
            results=results,
            execution_receipts=seal.execution_receipts,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.REPORT_INVARIANT_VIOLATION)
    report_document = _document(report)
    report_payload = report_document.encode("utf-8")
    if len(report_payload) > MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_DOCUMENT_BYTES:
        _fail(M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.DOCUMENT_TOO_LARGE)
    command_document = _document(command)
    command_payload = command_document.encode("utf-8")
    return M6ReplayLockedClosedPolicyRegressionReportBundle(
        report=report,
        report_document=report_document,
        report_content_sha256=hashlib.sha256(report_payload).hexdigest(),
        command_document=command_document,
        command_content_sha256=hashlib.sha256(command_payload).hexdigest(),
        evaluator_dataset=dataset,
        evaluator_dataset_document=controlled_dataset_document,
        evaluator_dataset_content_sha256=dataset_content_sha256,
        stored_source_catalog=stored,
        execution_seal=seal,
        execution_seal_document=controlled_seal_document,
        execution_seal_content_sha256=seal_content_sha256,
    )


__all__ = [
    "MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_DOCUMENT_BYTES",
    "MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_INPUT_BYTES",
    "M6ReplayLockedClosedPolicyRegressionAssemblyError",
    "M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode",
    "M6ReplayLockedClosedPolicyRegressionReportBundle",
    "assemble_m6_replay_locked_closed_policy_regression_report",
]
