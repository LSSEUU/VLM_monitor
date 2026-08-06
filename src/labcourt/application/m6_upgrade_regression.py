"""Derive the frozen M6 report from one complete upgrade output inventory."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.m6_regression import (
    M6RegressionCaseResult,
    M6RegressionDatasetSnapshot,
    M6RegressionReport,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthority,
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.exceptions import LabCourtError

MAX_M6_UPGRADE_REGRESSION_DOCUMENT_BYTES = 256 * 1024 * 1024
MAX_M6_UPGRADE_REGRESSION_INPUT_BYTES = 512 * 1024 * 1024

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6UpgradeRegressionAssemblyErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    MODE_NOT_UPGRADE_REGRESSION = "MODE_NOT_UPGRADE_REGRESSION"
    COMMAND_DATASET_MISMATCH = "COMMAND_DATASET_MISMATCH"
    CANDIDATE_OUTPUT_MISMATCH = "CANDIDATE_OUTPUT_MISMATCH"
    REPORT_INVARIANT_VIOLATION = "REPORT_INVARIANT_VIOLATION"


class M6UpgradeRegressionAssemblyError(LabCourtError):
    """The exact upgrade execution could not become a regression report."""

    def __init__(self, code: M6UpgradeRegressionAssemblyErrorCode) -> None:
        if not isinstance(code, M6UpgradeRegressionAssemblyErrorCode):
            raise TypeError("code must be an M6UpgradeRegressionAssemblyErrorCode")
        self.code = code
        super().__init__(f"M6 upgrade regression assembly failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6UpgradeRegressionReportBundle:
    report: M6RegressionReport
    report_document: str
    report_content_sha256: str
    command_document: str
    command_content_sha256: str
    dataset_document: str
    dataset_content_sha256: str
    candidate_output_inventory: M6UpgradeCandidateOutputInventoryAuthorityV3
    candidate_output_inventory_document: str
    candidate_output_inventory_content_sha256: str


def _fail(code: M6UpgradeRegressionAssemblyErrorCode) -> NoReturn:
    raise M6UpgradeRegressionAssemblyError(code)


def _canonical_model(
    value: object,
    expected: type[_ModelT],
    code: M6UpgradeRegressionAssemblyErrorCode,
) -> _ModelT:
    if not isinstance(value, expected):
        _fail(M6UpgradeRegressionAssemblyErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(code)
    if controlled != value:
        _fail(code)
    return controlled


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _canonical_candidate_output_inventory(
    value: object,
) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
    if not isinstance(value, M6UpgradeCandidateOutputInventoryAuthorityV3):
        if isinstance(value, M6UpgradeCandidateOutputInventoryAuthority):
            _fail(M6UpgradeRegressionAssemblyErrorCode.CANDIDATE_OUTPUT_MISMATCH)
        _fail(M6UpgradeRegressionAssemblyErrorCode.INVALID_ARGUMENT)
    return _canonical_model(
        value,
        M6UpgradeCandidateOutputInventoryAuthorityV3,
        M6UpgradeRegressionAssemblyErrorCode.CANDIDATE_OUTPUT_MISMATCH,
    )


def _require_document(value: BaseModel, document: object) -> tuple[str, str, int]:
    if not isinstance(document, str):
        _fail(M6UpgradeRegressionAssemblyErrorCode.DOCUMENT_INVALID)
    payload = document.encode("utf-8")
    if len(payload) > MAX_M6_UPGRADE_REGRESSION_DOCUMENT_BYTES:
        _fail(M6UpgradeRegressionAssemblyErrorCode.DOCUMENT_TOO_LARGE)
    if document != _document(value):
        _fail(M6UpgradeRegressionAssemblyErrorCode.DOCUMENT_INVALID)
    return document, hashlib.sha256(payload).hexdigest(), len(payload)


def assemble_m6_upgrade_regression_report(
    *,
    command: object,
    command_document: object,
    dataset: object,
    dataset_document: object,
    candidate_output_inventory: object,
    candidate_output_inventory_document: object,
) -> M6UpgradeRegressionReportBundle:
    """Build results, receipts, aggregates, and gates without caller-supplied claims."""

    controlled_command = _canonical_model(
        command,
        M6RegressionRunCommand,
        M6UpgradeRegressionAssemblyErrorCode.COMMAND_DATASET_MISMATCH,
    )
    controlled_dataset = _canonical_model(
        dataset,
        M6RegressionDatasetSnapshot,
        M6UpgradeRegressionAssemblyErrorCode.COMMAND_DATASET_MISMATCH,
    )
    outputs = _canonical_candidate_output_inventory(candidate_output_inventory)
    controlled_command_document, command_content_sha256, command_size = _require_document(
        controlled_command,
        command_document,
    )
    controlled_dataset_document, dataset_content_sha256, dataset_size = _require_document(
        controlled_dataset,
        dataset_document,
    )
    controlled_output_document, output_content_sha256, output_size = _require_document(
        outputs,
        candidate_output_inventory_document,
    )
    if command_size + dataset_size + output_size > MAX_M6_UPGRADE_REGRESSION_INPUT_BYTES:
        _fail(M6UpgradeRegressionAssemblyErrorCode.DOCUMENT_TOO_LARGE)
    if controlled_command.mode != ReproducibilityMode.UPGRADE_REGRESSION:
        _fail(M6UpgradeRegressionAssemblyErrorCode.MODE_NOT_UPGRADE_REGRESSION)
    if (
        controlled_command.execution_dataset_snapshot_id
        != controlled_dataset.execution_dataset.execution_dataset_snapshot_id
        or controlled_command.baseline_manifest_id != controlled_dataset.baseline_manifest_id
    ):
        _fail(M6UpgradeRegressionAssemblyErrorCode.COMMAND_DATASET_MISMATCH)
    if (
        outputs.command != controlled_command
        or outputs.execution_dataset != controlled_dataset.execution_dataset
    ):
        _fail(M6UpgradeRegressionAssemblyErrorCode.CANDIDATE_OUTPUT_MISMATCH)

    results: list[M6RegressionCaseResult] = []
    receipts = []
    try:
        for entry, output in zip(
            controlled_dataset.entries,
            outputs.outputs,
            strict=True,
        ):
            if (
                entry.sample_id != output.sample_id
                or entry.input_authority_id != output.execution_entry.input_authority_id
                or entry.input_authority_document_sha256
                != output.execution_entry.input_authority_document_sha256
                or entry.replay_input_closure_authority_id
                != output.execution_entry.replay_input_closure_authority_id
                or entry.replay_input_closure_document_sha256
                != output.execution_entry.replay_input_closure_document_sha256
            ):
                _fail(M6UpgradeRegressionAssemblyErrorCode.CANDIDATE_OUTPUT_MISMATCH)
            results.append(
                M6RegressionCaseResult(
                    entry_id=entry.entry_id,
                    sample_id=entry.sample_id,
                    baseline_snapshot=entry.baseline_snapshot,
                    candidate_snapshot=output.candidate_snapshot,
                )
            )
            receipts.append(output.execution_receipt)
        report = M6RegressionReport(
            command=controlled_command,
            dataset=controlled_dataset,
            results=tuple(results),
            execution_receipts=tuple(receipts),
        )
    except M6UpgradeRegressionAssemblyError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6UpgradeRegressionAssemblyErrorCode.REPORT_INVARIANT_VIOLATION)
    report_document = _document(report)
    report_payload = report_document.encode("utf-8")
    if len(report_payload) > MAX_M6_UPGRADE_REGRESSION_DOCUMENT_BYTES:
        _fail(M6UpgradeRegressionAssemblyErrorCode.DOCUMENT_TOO_LARGE)
    return M6UpgradeRegressionReportBundle(
        report=report,
        report_document=report_document,
        report_content_sha256=hashlib.sha256(report_payload).hexdigest(),
        command_document=controlled_command_document,
        command_content_sha256=command_content_sha256,
        dataset_document=controlled_dataset_document,
        dataset_content_sha256=dataset_content_sha256,
        candidate_output_inventory=outputs,
        candidate_output_inventory_document=controlled_output_document,
        candidate_output_inventory_content_sha256=output_content_sha256,
    )


__all__ = [
    "MAX_M6_UPGRADE_REGRESSION_DOCUMENT_BYTES",
    "MAX_M6_UPGRADE_REGRESSION_INPUT_BYTES",
    "M6UpgradeRegressionAssemblyError",
    "M6UpgradeRegressionAssemblyErrorCode",
    "M6UpgradeRegressionReportBundle",
    "assemble_m6_upgrade_regression_report",
]
