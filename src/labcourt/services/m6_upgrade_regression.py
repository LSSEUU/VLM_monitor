"""Run one protocol-V3 candidate and atomically publish its M6 regression report."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.adapters.storage.m6_regression_store import (
    MAX_M6_REGRESSION_PUBLICATION_SEAL_BYTES,
    M6RegressionPublicationResult,
    M6RegressionPublisher,
    M6StoredRegressionBundle,
    ReadonlyM6RegressionStore,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.application.m6_regression_publication import (
    M6RegressionPublicationBundle,
    build_m6_regression_publication_bundle,
)
from labcourt.application.m6_upgrade_regression import (
    MAX_M6_UPGRADE_REGRESSION_DOCUMENT_BYTES,
    M6UpgradeRegressionReportBundle,
    assemble_m6_upgrade_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6RegressionDatasetSnapshot
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.contracts.m6_regression_publication import (
    MAX_M6_REGRESSION_PUBLICATION_DOCUMENT_BYTES,
)
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeExecutionScopeAuthority
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_upgrade_candidate_coordinator import (
    M6UpgradeCandidateCoordinatorV3,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_MAX_OUTPUT_ROOT_UTF8_BYTES = 32_768


class M6UpgradeRegressionRunErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    DATASET_INVALID = "DATASET_INVALID"
    DATASET_DOCUMENT_INVALID = "DATASET_DOCUMENT_INVALID"
    DATASET_DOCUMENT_TOO_LARGE = "DATASET_DOCUMENT_TOO_LARGE"
    DATASET_SCOPE_MISMATCH = "DATASET_SCOPE_MISMATCH"
    CANDIDATE_EXECUTION_REJECTED = "CANDIDATE_EXECUTION_REJECTED"
    CANDIDATE_SCOPE_MISMATCH = "CANDIDATE_SCOPE_MISMATCH"
    REPORT_ASSEMBLY_REJECTED = "REPORT_ASSEMBLY_REJECTED"
    PUBLICATION_BUILD_REJECTED = "PUBLICATION_BUILD_REJECTED"
    PUBLICATION_REJECTED = "PUBLICATION_REJECTED"
    READBACK_REJECTED = "READBACK_REJECTED"
    READBACK_MISMATCH = "READBACK_MISMATCH"


class M6UpgradeRegressionRunError(LabCourtError):
    """Payload-free failure at the run-level regression composition boundary."""

    def __init__(self, code: M6UpgradeRegressionRunErrorCode) -> None:
        if not isinstance(code, M6UpgradeRegressionRunErrorCode):
            raise TypeError("code must be an M6 upgrade regression run error code")
        self.code = code
        super().__init__(f"M6 upgrade regression run failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6UpgradeRegressionRunResult:
    report_bundle: M6UpgradeRegressionReportBundle
    publication_bundle: M6RegressionPublicationBundle
    publication_result: M6RegressionPublicationResult
    stored_bundle: M6StoredRegressionBundle


def _fail(code: M6UpgradeRegressionRunErrorCode) -> NoReturn:
    raise M6UpgradeRegressionRunError(code)


def _canonical_model(
    value: object,
    expected: type[_ModelT],
    code: M6UpgradeRegressionRunErrorCode,
) -> _ModelT:
    if type(value) is not expected:
        _fail(code)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(code)
    if controlled != value:
        _fail(code)
    return controlled


def _canonical_document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _controlled_dataset_document(value: object, dataset: M6RegressionDatasetSnapshot) -> str:
    if not isinstance(value, str):
        _fail(M6UpgradeRegressionRunErrorCode.DATASET_DOCUMENT_INVALID)
    try:
        payload = value.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail(M6UpgradeRegressionRunErrorCode.DATASET_DOCUMENT_INVALID)
    if len(payload) > MAX_M6_UPGRADE_REGRESSION_DOCUMENT_BYTES:
        _fail(M6UpgradeRegressionRunErrorCode.DATASET_DOCUMENT_TOO_LARGE)
    if value != _canonical_document(dataset):
        _fail(M6UpgradeRegressionRunErrorCode.DATASET_DOCUMENT_INVALID)
    return value


def _controlled_output_root(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        _fail(M6UpgradeRegressionRunErrorCode.INVALID_ARGUMENT)
    try:
        raw = str(value)
        if (
            not raw
            or "\x00" in raw
            or len(raw.encode("utf-8", errors="strict")) > _MAX_OUTPUT_ROOT_UTF8_BYTES
        ):
            _fail(M6UpgradeRegressionRunErrorCode.INVALID_ARGUMENT)
        return Path(raw).absolute()
    except M6UpgradeRegressionRunError:
        raise
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        _fail(M6UpgradeRegressionRunErrorCode.INVALID_ARGUMENT)


def run_m6_upgrade_regression_v3(
    *,
    execution_scope: object,
    evaluator_dataset: object,
    evaluator_dataset_document: object,
    coordinator: object,
    output_root: str | Path,
) -> M6UpgradeRegressionRunResult:
    """Execute, evaluate, publish, and read back one exact protocol-V3 run."""

    scope = _canonical_model(
        execution_scope,
        M6UpgradeExecutionScopeAuthority,
        M6UpgradeRegressionRunErrorCode.INVALID_ARGUMENT,
    )
    dataset = _canonical_model(
        evaluator_dataset,
        M6RegressionDatasetSnapshot,
        M6UpgradeRegressionRunErrorCode.DATASET_INVALID,
    )
    if (
        dataset.execution_dataset != scope.execution_dataset
        or scope.command.execution_dataset_snapshot_id
        != dataset.execution_dataset.execution_dataset_snapshot_id
        or scope.command.baseline_manifest_id != dataset.baseline_manifest_id
        or scope.command.candidate_manifest_id != scope.candidate_manifest.manifest_id
    ):
        _fail(M6UpgradeRegressionRunErrorCode.DATASET_SCOPE_MISMATCH)
    dataset_document = _controlled_dataset_document(evaluator_dataset_document, dataset)
    if not isinstance(coordinator, M6UpgradeCandidateCoordinatorV3):
        _fail(M6UpgradeRegressionRunErrorCode.INVALID_ARGUMENT)
    controlled_output_root = _controlled_output_root(output_root)
    try:
        publisher = M6RegressionPublisher(controlled_output_root)
        with SecureWorkspace(
            controlled_output_root,
            max(
                MAX_M6_REGRESSION_PUBLICATION_DOCUMENT_BYTES,
                MAX_M6_REGRESSION_PUBLICATION_SEAL_BYTES,
            ),
        ):
            pass
        readonly_store = ReadonlyM6RegressionStore(controlled_output_root)
    except Exception:
        raise M6UpgradeRegressionRunError(
            M6UpgradeRegressionRunErrorCode.PUBLICATION_REJECTED
        ) from None

    try:
        returned_inventory = coordinator.run_to_terminal(scope)
    except Exception:
        raise M6UpgradeRegressionRunError(
            M6UpgradeRegressionRunErrorCode.CANDIDATE_EXECUTION_REJECTED
        ) from None
    inventory = _canonical_model(
        returned_inventory,
        M6UpgradeCandidateOutputInventoryAuthorityV3,
        M6UpgradeRegressionRunErrorCode.CANDIDATE_EXECUTION_REJECTED,
    )
    if inventory.execution_ledger.execution_scope != scope:
        _fail(M6UpgradeRegressionRunErrorCode.CANDIDATE_SCOPE_MISMATCH)

    try:
        report_bundle = assemble_m6_upgrade_regression_report(
            command=scope.command,
            command_document=_canonical_document(scope.command),
            dataset=dataset,
            dataset_document=dataset_document,
            candidate_output_inventory=inventory,
            candidate_output_inventory_document=_canonical_document(inventory),
        )
    except Exception:
        raise M6UpgradeRegressionRunError(
            M6UpgradeRegressionRunErrorCode.REPORT_ASSEMBLY_REJECTED
        ) from None
    try:
        publication_bundle = build_m6_regression_publication_bundle(report_bundle)
    except Exception:
        raise M6UpgradeRegressionRunError(
            M6UpgradeRegressionRunErrorCode.PUBLICATION_BUILD_REJECTED
        ) from None
    try:
        publication_result = publisher.publish(publication_bundle)
    except Exception:
        raise M6UpgradeRegressionRunError(
            M6UpgradeRegressionRunErrorCode.PUBLICATION_REJECTED
        ) from None
    try:
        stored_bundle = readonly_store.load(scope.candidate_run_id)
    except Exception:
        raise M6UpgradeRegressionRunError(
            M6UpgradeRegressionRunErrorCode.READBACK_REJECTED
        ) from None
    try:
        rebuilt_stored_bundle = stored_bundle.to_report_bundle()
    except Exception:
        raise M6UpgradeRegressionRunError(
            M6UpgradeRegressionRunErrorCode.READBACK_REJECTED
        ) from None
    if (
        rebuilt_stored_bundle != report_bundle
        or stored_bundle.seal != publication_bundle.seal
        or stored_bundle.seal_document != publication_bundle.seal_document
    ):
        _fail(M6UpgradeRegressionRunErrorCode.READBACK_MISMATCH)
    return M6UpgradeRegressionRunResult(
        report_bundle=report_bundle,
        publication_bundle=publication_bundle,
        publication_result=publication_result,
        stored_bundle=stored_bundle,
    )


__all__ = [
    "M6UpgradeRegressionRunError",
    "M6UpgradeRegressionRunErrorCode",
    "M6UpgradeRegressionRunResult",
    "run_m6_upgrade_regression_v3",
]
