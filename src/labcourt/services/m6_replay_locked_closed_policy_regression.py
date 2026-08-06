"""Execute and atomically publish one replay-locked CLOSED-policy report."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.adapters.storage.m6_replay_locked_closed_policy_regression_store import (
    MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_PUBLICATION_SEAL_BYTES,
    M6ReplayLockedClosedPolicyRegressionPublicationResult,
    M6ReplayLockedClosedPolicyRegressionPublisher,
    M6StoredReplayLockedClosedPolicyRegressionBundle,
    ReadonlyM6ReplayLockedClosedPolicyRegressionStore,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.application.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationBundle,
    build_m6_replay_locked_closed_policy_publication_bundle,
)
from labcourt.application.m6_replay_locked_closed_policy_regression import (
    MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_DOCUMENT_BYTES,
    M6ReplayLockedClosedPolicyRegressionReportBundle,
    assemble_m6_replay_locked_closed_policy_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6RegressionDatasetSnapshot
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_closed_policy_publication import (
    MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_DOCUMENT_BYTES,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogProvider,
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_closed_policy_coordinator import (
    M6ReplayLockedClosedPolicyCoordinator,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_MAX_OUTPUT_ROOT_UTF8_BYTES = 32_768


class M6ReplayLockedClosedPolicyRegressionRunErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_CATALOG_INVALID = "SOURCE_CATALOG_INVALID"
    SOURCE_CATALOG_LOAD_REJECTED = "SOURCE_CATALOG_LOAD_REJECTED"
    SOURCE_CATALOG_MISMATCH = "SOURCE_CATALOG_MISMATCH"
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


class M6ReplayLockedClosedPolicyRegressionRunError(LabCourtError):
    """Payload-free failure at the CLOSED-policy run composition boundary."""

    def __init__(
        self,
        code: M6ReplayLockedClosedPolicyRegressionRunErrorCode,
    ) -> None:
        if not isinstance(code, M6ReplayLockedClosedPolicyRegressionRunErrorCode):
            raise TypeError("code must be an M6 CLOSED-policy regression run error code")
        self.code = code
        super().__init__(f"M6 CLOSED-policy regression run failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedPolicyRegressionRunResult:
    execution_seal: M6ReplayLockedClosedPolicyExecutionSealAuthorityV2
    report_bundle: M6ReplayLockedClosedPolicyRegressionReportBundle
    publication_bundle: M6ReplayLockedClosedPolicyPublicationBundle
    publication_result: M6ReplayLockedClosedPolicyRegressionPublicationResult
    stored_bundle: M6StoredReplayLockedClosedPolicyRegressionBundle


def _fail(code: M6ReplayLockedClosedPolicyRegressionRunErrorCode) -> NoReturn:
    raise M6ReplayLockedClosedPolicyRegressionRunError(code)


def _canonical_model(
    value: object,
    expected: type[_ModelT],
    code: M6ReplayLockedClosedPolicyRegressionRunErrorCode,
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


def _controlled_catalog(
    value: object,
) -> M6StoredRegressionExecutionSourceCatalog:
    if type(value) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_INVALID)
    assert isinstance(value, M6StoredRegressionExecutionSourceCatalog)
    try:
        controlled = M6StoredRegressionExecutionSourceCatalog(
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
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_INVALID)
    if controlled != value:
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_INVALID)
    return controlled


def _canonical_document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _controlled_dataset_document(
    value: object,
    dataset: M6RegressionDatasetSnapshot,
) -> str:
    if not isinstance(value, str):
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_DOCUMENT_INVALID)
    try:
        payload = value.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_DOCUMENT_INVALID)
    if len(payload) > MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_DOCUMENT_BYTES:
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_DOCUMENT_TOO_LARGE)
    if value != _canonical_document(dataset):
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_DOCUMENT_INVALID)
    return value


def _controlled_output_root(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT)
    try:
        raw = str(value)
        if (
            not raw
            or "\x00" in raw
            or len(raw.encode("utf-8", errors="strict")) > _MAX_OUTPUT_ROOT_UTF8_BYTES
        ):
            _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT)
        return Path(raw).absolute()
    except M6ReplayLockedClosedPolicyRegressionRunError:
        raise
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT)


def _require_start_cut_join(
    scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    stored: M6StoredRegressionExecutionSourceCatalog,
    dataset: M6RegressionDatasetSnapshot,
) -> None:
    pre_policy = scope.pre_policy_execution_scope
    scoped_execution = pre_policy.execution_dataset
    catalog = stored.source_catalog
    if (
        scoped_execution.source_catalog_authority_id != catalog.source_catalog_authority_id
        or scoped_execution.source_catalog_document_sha256 != stored.content_sha256
        or scoped_execution.baseline_manifest_id != catalog.baseline_manifest_id
        or scoped_execution.entry_count != catalog.entry_count
        or catalog.source_inventory_item_count != scoped_execution.entry_count
        or any(
            execution_entry.sample_id != catalog_entry.sample_id
            or execution_entry.input_authority_id != catalog_entry.input_authority_id
            or execution_entry.input_authority_document_sha256
            != catalog_entry.input_authority_document_sha256
            or execution_entry.replay_input_closure_authority_id
            != catalog_entry.replay_input_closure.replay_input_closure_authority_id
            or execution_entry.replay_input_closure_document_sha256
            != catalog_entry.replay_input_closure.replay_input_closure_document_sha256
            for execution_entry, catalog_entry in zip(
                scoped_execution.entries,
                catalog.entries,
                strict=True,
            )
        )
    ):
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_MISMATCH)
    execution = dataset.execution_dataset
    if (
        scoped_execution != execution
        or pre_policy.command.execution_dataset_snapshot_id
        != execution.execution_dataset_snapshot_id
        or pre_policy.command.baseline_manifest_id != dataset.baseline_manifest_id
        or dataset.baseline_manifest_id != catalog.baseline_manifest_id
        or dataset.source_inventory_cut_authority_id != catalog.source_inventory_cut_authority_id
        or dataset.source_inventory_cut_document_sha256
        != catalog.source_inventory_cut_content_sha256
        or dataset.source_inventory_item_count != catalog.source_inventory_item_count
        or dataset.source_inventory_root_sha256 != catalog.source_inventory_root_sha256
        or len(dataset.entries) != len(catalog.entries)
    ):
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_SCOPE_MISMATCH)


def _load_durable_catalog(
    provider: M6RegressionExecutionSourceCatalogProvider,
    stored: M6StoredRegressionExecutionSourceCatalog,
) -> None:
    try:
        loaded = provider.load(
            stored.source_catalog.source_catalog_authority_id,
            stored.content_sha256,
        )
    except Exception:
        raise M6ReplayLockedClosedPolicyRegressionRunError(
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_LOAD_REJECTED
        ) from None
    if type(loaded) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_LOAD_REJECTED)
    if loaded != stored:
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.SOURCE_CATALOG_MISMATCH)


def run_m6_replay_locked_closed_policy_regression_v2(
    *,
    execution_scope: object,
    stored_source_catalog: object,
    evaluator_dataset: object,
    evaluator_dataset_document: object,
    coordinator: object,
    source_catalog_provider: object,
    output_root: str | Path,
) -> M6ReplayLockedClosedPolicyRegressionRunResult:
    """Execute, evaluate, publish, and read back one CLOSED-policy run."""

    scope = _canonical_model(
        execution_scope,
        M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT,
    )
    stored = _controlled_catalog(stored_source_catalog)
    dataset = _canonical_model(
        evaluator_dataset,
        M6RegressionDatasetSnapshot,
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.DATASET_INVALID,
    )
    dataset_document = _controlled_dataset_document(
        evaluator_dataset_document,
        dataset,
    )
    if not isinstance(coordinator, M6ReplayLockedClosedPolicyCoordinator):
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT)
    if not isinstance(
        source_catalog_provider,
        M6RegressionExecutionSourceCatalogProvider,
    ):
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.INVALID_ARGUMENT)
    _require_start_cut_join(scope, stored, dataset)
    _load_durable_catalog(source_catalog_provider, stored)
    controlled_output_root = _controlled_output_root(output_root)
    try:
        publisher = M6ReplayLockedClosedPolicyRegressionPublisher(
            controlled_output_root,
            source_catalog_provider=source_catalog_provider,
        )
        with SecureWorkspace(
            controlled_output_root,
            max(
                MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_DOCUMENT_BYTES,
                MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_PUBLICATION_SEAL_BYTES,
            ),
        ):
            pass
        readonly_store = ReadonlyM6ReplayLockedClosedPolicyRegressionStore(
            controlled_output_root,
            source_catalog_provider=source_catalog_provider,
        )
    except Exception:
        raise M6ReplayLockedClosedPolicyRegressionRunError(
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.PUBLICATION_REJECTED
        ) from None

    try:
        returned_seal = coordinator.run_to_terminal(scope, stored)
    except Exception:
        raise M6ReplayLockedClosedPolicyRegressionRunError(
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.CANDIDATE_EXECUTION_REJECTED
        ) from None
    seal = _canonical_model(
        returned_seal,
        M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
        M6ReplayLockedClosedPolicyRegressionRunErrorCode.CANDIDATE_EXECUTION_REJECTED,
    )
    if seal.execution_scope != scope:
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.CANDIDATE_SCOPE_MISMATCH)

    try:
        report_bundle = assemble_m6_replay_locked_closed_policy_regression_report(
            stored_source_catalog=stored,
            evaluator_dataset=dataset,
            evaluator_dataset_document=dataset_document,
            execution_seal=seal,
            execution_seal_document=_canonical_document(seal),
        )
    except Exception:
        raise M6ReplayLockedClosedPolicyRegressionRunError(
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.REPORT_ASSEMBLY_REJECTED
        ) from None
    try:
        publication_bundle = build_m6_replay_locked_closed_policy_publication_bundle(report_bundle)
    except Exception:
        raise M6ReplayLockedClosedPolicyRegressionRunError(
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.PUBLICATION_BUILD_REJECTED
        ) from None
    try:
        publication_result = publisher.publish(publication_bundle)
    except Exception:
        raise M6ReplayLockedClosedPolicyRegressionRunError(
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.PUBLICATION_REJECTED
        ) from None
    try:
        stored_bundle = readonly_store.load(scope.candidate_run_id)
        rebuilt_publication = stored_bundle.to_publication_bundle()
    except Exception:
        raise M6ReplayLockedClosedPolicyRegressionRunError(
            M6ReplayLockedClosedPolicyRegressionRunErrorCode.READBACK_REJECTED
        ) from None
    if (
        stored_bundle.report_bundle != report_bundle
        or stored_bundle.seal != publication_bundle.seal
        or stored_bundle.seal_document != publication_bundle.seal_document
        or rebuilt_publication != publication_bundle
    ):
        _fail(M6ReplayLockedClosedPolicyRegressionRunErrorCode.READBACK_MISMATCH)
    return M6ReplayLockedClosedPolicyRegressionRunResult(
        execution_seal=seal,
        report_bundle=report_bundle,
        publication_bundle=publication_bundle,
        publication_result=publication_result,
        stored_bundle=stored_bundle,
    )


__all__ = [
    "M6ReplayLockedClosedPolicyRegressionRunError",
    "M6ReplayLockedClosedPolicyRegressionRunErrorCode",
    "M6ReplayLockedClosedPolicyRegressionRunResult",
    "run_m6_replay_locked_closed_policy_regression_v2",
]
