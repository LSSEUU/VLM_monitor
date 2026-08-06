"""Immutable publication and exact readback for CLOSED-policy M6 reports."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationBuildError,
    M6ReplayLockedClosedPolicyPublicationBundle,
    build_m6_replay_locked_closed_policy_publication_bundle,
)
from labcourt.application.m6_replay_locked_closed_policy_regression import (
    M6ReplayLockedClosedPolicyRegressionAssemblyError,
    M6ReplayLockedClosedPolicyRegressionReportBundle,
    assemble_m6_replay_locked_closed_policy_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import (
    M6RegressionDatasetSnapshot,
    M6RegressionReport,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_closed_policy_publication import (
    MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_BUNDLE_BYTES,
    MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_DOCUMENT_BYTES,
    M6ReplayLockedClosedPolicyPublicationDocumentEntry,
    M6ReplayLockedClosedPolicyPublicationDocumentKind,
    M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    LabCourtError,
    PathBoundaryViolation,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogProvider,
    M6StoredRegressionExecutionSourceCatalog,
)

from .secure_workspace import SecureWorkspace

MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_PUBLICATION_SEAL_BYTES = 1024 * 1024
_MAX_SEAL_DIRECTORY_ITEMS = 2
_MAX_NAME_BYTES = 512
M6ReplayLockedClosedPolicyRegressionStoreFaultInjector = Callable[[str], None]
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedClosedPolicyRegressionStoreErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    BUNDLE_INVALID = "BUNDLE_INVALID"
    SOURCE_CATALOG_LOAD_FAILED = "SOURCE_CATALOG_LOAD_FAILED"
    SOURCE_CATALOG_MISMATCH = "SOURCE_CATALOG_MISMATCH"
    STAGING_CONFLICT = "STAGING_CONFLICT"
    DEPENDENCY_PUBLICATION_FAILED = "DEPENDENCY_PUBLICATION_FAILED"
    SEAL_PUBLICATION_FAILED = "SEAL_PUBLICATION_FAILED"
    COMMIT_CONFLICT = "COMMIT_CONFLICT"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    COMMIT_MISSING = "COMMIT_MISSING"
    REPORT_INVALID = "REPORT_INVALID"
    SEAL_INVALID = "SEAL_INVALID"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INVENTORY_INVALID = "INVENTORY_INVALID"
    STORAGE_BOUNDARY_FAILURE = "STORAGE_BOUNDARY_FAILURE"


class M6ReplayLockedClosedPolicyRegressionStoreError(LabCourtError):
    """Payload-free failure at the CLOSED-policy report storage boundary."""

    def __init__(
        self,
        code: M6ReplayLockedClosedPolicyRegressionStoreErrorCode,
    ) -> None:
        if not isinstance(code, M6ReplayLockedClosedPolicyRegressionStoreErrorCode):
            raise TypeError("code must be an M6 CLOSED-policy regression store error code")
        self.code = code
        super().__init__(f"M6 CLOSED-policy regression store failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedPolicyRegressionPublicationResult:
    seal_id: str
    report_path: Path
    seal_path: Path
    dependency_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class M6StoredReplayLockedClosedPolicyRegressionBundle:
    report_bundle: M6ReplayLockedClosedPolicyRegressionReportBundle
    seal: M6ReplayLockedClosedPolicyPublicationSealAuthorityV2
    seal_document: str

    def to_publication_bundle(
        self,
    ) -> M6ReplayLockedClosedPolicyPublicationBundle:
        return build_m6_replay_locked_closed_policy_publication_bundle(self.report_bundle)


def _fail(
    code: M6ReplayLockedClosedPolicyRegressionStoreErrorCode,
) -> NoReturn:
    raise M6ReplayLockedClosedPolicyRegressionStoreError(code)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_model_document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _parse_canonical(
    payload: bytes,
    model_type: type[_ModelT],
    code: M6ReplayLockedClosedPolicyRegressionStoreErrorCode,
) -> tuple[_ModelT, str]:
    try:
        document = payload.decode("utf-8")
        value = model_type.model_validate_json(payload)
        if _canonical_model_document(value) != document:
            _fail(code)
        return value, document
    except M6ReplayLockedClosedPolicyRegressionStoreError:
        raise
    except (UnicodeDecodeError, TypeError, ValueError, ValidationError):
        _fail(code)


def _root_relative(candidate_run_id: str) -> str:
    return candidate_run_id


def _entry_final_relative(
    candidate_run_id: str,
    entry: M6ReplayLockedClosedPolicyPublicationDocumentEntry,
) -> str:
    return f"{_root_relative(candidate_run_id)}/{entry.relative_path}"


def _seal_final_relative(
    seal: M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
) -> str:
    return f"{_root_relative(seal.candidate_run_id)}/{seal.seal_relative_path}"


def _report_final_relative(candidate_run_id: str) -> str:
    return f"{_root_relative(candidate_run_id)}/regression.json"


def _entry_by_kind(
    seal: M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
) -> dict[
    M6ReplayLockedClosedPolicyPublicationDocumentKind,
    M6ReplayLockedClosedPolicyPublicationDocumentEntry,
]:
    return {item.kind: item for item in seal.entries}


def _validate_provider(
    provider: object,
) -> M6RegressionExecutionSourceCatalogProvider:
    if not isinstance(provider, M6RegressionExecutionSourceCatalogProvider):
        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.INVALID_ARGUMENT)
    return provider


def _load_source_catalog(
    provider: M6RegressionExecutionSourceCatalogProvider,
    authority_id: str,
    document_sha256: str,
) -> M6StoredRegressionExecutionSourceCatalog:
    try:
        stored = provider.load(authority_id, document_sha256)
    except Exception:
        raise M6ReplayLockedClosedPolicyRegressionStoreError(
            M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SOURCE_CATALOG_LOAD_FAILED
        ) from None
    if type(stored) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SOURCE_CATALOG_LOAD_FAILED)
    assert isinstance(stored, M6StoredRegressionExecutionSourceCatalog)
    if (
        stored.source_catalog.source_catalog_authority_id != authority_id
        or stored.content_sha256 != document_sha256
    ):
        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SOURCE_CATALOG_MISMATCH)
    return stored


def _validate_bundle(
    bundle: object,
) -> M6ReplayLockedClosedPolicyPublicationBundle:
    if type(bundle) is not M6ReplayLockedClosedPolicyPublicationBundle:
        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.INVALID_ARGUMENT)
    assert isinstance(bundle, M6ReplayLockedClosedPolicyPublicationBundle)
    try:
        rebuilt = build_m6_replay_locked_closed_policy_publication_bundle(bundle.report_bundle)
    except M6ReplayLockedClosedPolicyPublicationBuildError as exc:
        raise M6ReplayLockedClosedPolicyRegressionStoreError(
            M6ReplayLockedClosedPolicyRegressionStoreErrorCode.BUNDLE_INVALID
        ) from exc
    if rebuilt != bundle:
        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.BUNDLE_INVALID)
    for entry in rebuilt.seal.entries:
        payload = rebuilt.document_for(entry.kind).encode("utf-8")
        if entry.content_sha256 != _sha256(payload) or entry.size_bytes != len(payload):
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.BUNDLE_INVALID)
    if _canonical_model_document(rebuilt.seal) != rebuilt.seal_document:
        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.BUNDLE_INVALID)
    return rebuilt


class ReadonlyM6ReplayLockedClosedPolicyRegressionStore:
    """Load the report commit point, then verify its exact external catalog."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
        max_document_bytes: int = (MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_DOCUMENT_BYTES),
        max_bundle_bytes: int = (MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_BUNDLE_BYTES),
    ) -> None:
        for value, label in (
            (max_document_bytes, "max_document_bytes"),
            (max_bundle_bytes, "max_bundle_bytes"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        self._output_root = Path(output_root).absolute()
        self._source_catalog_provider = _validate_provider(source_catalog_provider)
        self._max_document_bytes = max_document_bytes
        self._max_bundle_bytes = max_bundle_bytes

    def load(
        self,
        candidate_run_id: object,
    ) -> M6StoredReplayLockedClosedPolicyRegressionBundle:
        if not isinstance(candidate_run_id, str):
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.INVALID_ARGUMENT)
        try:
            controlled_run_id = require_reference_token(
                candidate_run_id,
                "M6 CLOSED-policy regression candidate run_id",
            )
        except (TypeError, ValueError):
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.INVALID_ARGUMENT)
        workspace_limit = max(
            self._max_document_bytes,
            MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_PUBLICATION_SEAL_BYTES,
        )
        report_relative = _report_final_relative(controlled_run_id)
        try:
            with SecureWorkspace(self._output_root, workspace_limit) as workspace:
                try:
                    first_report = workspace.read_verified(
                        report_relative,
                        max_bytes=self._max_document_bytes,
                    )
                except PathBoundaryViolation as exc:
                    if exc.reason_code == "FILE_MISSING":
                        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.COMMIT_MISSING)
                    raise
                report, report_document = _parse_canonical(
                    first_report.bytes,
                    M6RegressionReport,
                    M6ReplayLockedClosedPolicyRegressionStoreErrorCode.REPORT_INVALID,
                )
                candidate_run_ids = {
                    receipt.candidate_run_id for receipt in report.execution_receipts
                }
                if candidate_run_ids != {controlled_run_id}:
                    _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.REPORT_INVALID)
                seal_directory = (
                    f"{controlled_run_id}/m6-regression/closed-policy-seals/{report.report_id}"
                )
                self._require_exact_seal_inventory(workspace, seal_directory)
                seal_relative = f"{seal_directory}/seal.json"
                first_seal = workspace.read_verified(
                    seal_relative,
                    max_bytes=(
                        MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_PUBLICATION_SEAL_BYTES
                    ),
                )
                seal, seal_document = _parse_canonical(
                    first_seal.bytes,
                    M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
                    M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SEAL_INVALID,
                )
                if (
                    seal.candidate_run_id != controlled_run_id
                    or seal.report_id != report.report_id
                    or seal.command_id != report.command.command_id
                    or seal.execution_dataset_snapshot_id
                    != report.dataset.execution_dataset.execution_dataset_snapshot_id
                    or seal.evaluator_dataset_snapshot_id != report.dataset.dataset_snapshot_id
                    or seal.candidate_manifest_id != report.command.candidate_manifest_id
                    or seal.seal_relative_path
                    != (f"m6-regression/closed-policy-seals/{report.report_id}/seal.json")
                ):
                    _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SEAL_INVALID)
                if sum(item.size_bytes for item in seal.entries) > self._max_bundle_bytes:
                    _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID)
                entries = _entry_by_kind(seal)
                report_entry = entries[
                    M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT
                ]
                if (
                    report_entry.content_sha256 != first_report.sha256
                    or report_entry.size_bytes != first_report.size_bytes
                    or report_entry.relative_path != "regression.json"
                ):
                    _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.REPORT_INVALID)
                documents: dict[
                    M6ReplayLockedClosedPolicyPublicationDocumentKind,
                    str,
                ] = {
                    M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT: (
                        report_document
                    )
                }
                for entry in seal.entries:
                    if (
                        entry.kind
                        == M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT
                    ):
                        continue
                    if entry.size_bytes > self._max_document_bytes:
                        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID)
                    observed = workspace.read_verified(
                        _entry_final_relative(controlled_run_id, entry),
                        entry.content_sha256,
                        max_bytes=entry.size_bytes,
                    )
                    if observed.size_bytes != entry.size_bytes:
                        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID)
                    try:
                        documents[entry.kind] = observed.bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID)
                second_seal = workspace.read_verified(
                    seal_relative,
                    first_seal.sha256,
                    max_bytes=first_seal.size_bytes,
                )
                second_report = workspace.read_verified(
                    report_relative,
                    first_report.sha256,
                    max_bytes=first_report.size_bytes,
                )
                if (
                    second_seal.bytes != first_seal.bytes
                    or second_report.bytes != first_report.bytes
                ):
                    _fail(
                        M6ReplayLockedClosedPolicyRegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
                    )
                self._require_exact_seal_inventory(workspace, seal_directory)
        except M6ReplayLockedClosedPolicyRegressionStoreError:
            raise
        except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation) as exc:
            raise M6ReplayLockedClosedPolicyRegressionStoreError(
                M6ReplayLockedClosedPolicyRegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from exc

        command, command_document = _parse_canonical(
            documents[M6ReplayLockedClosedPolicyPublicationDocumentKind.COMMAND].encode("utf-8"),
            M6RegressionRunCommand,
            M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID,
        )
        dataset, dataset_document = _parse_canonical(
            documents[M6ReplayLockedClosedPolicyPublicationDocumentKind.EVALUATOR_DATASET].encode(
                "utf-8"
            ),
            M6RegressionDatasetSnapshot,
            M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID,
        )
        execution_seal, execution_seal_document = _parse_canonical(
            documents[
                M6ReplayLockedClosedPolicyPublicationDocumentKind.CLOSED_POLICY_EXECUTION_SEAL
            ].encode("utf-8"),
            M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
            M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID,
        )
        stored_catalog = _load_source_catalog(
            self._source_catalog_provider,
            seal.source_catalog_authority_id,
            seal.source_catalog_document_sha256,
        )
        try:
            rebuilt_report = assemble_m6_replay_locked_closed_policy_regression_report(
                stored_source_catalog=stored_catalog,
                evaluator_dataset=dataset,
                evaluator_dataset_document=dataset_document,
                execution_seal=execution_seal,
                execution_seal_document=execution_seal_document,
            )
            rebuilt_publication = build_m6_replay_locked_closed_policy_publication_bundle(
                rebuilt_report
            )
        except (
            M6ReplayLockedClosedPolicyRegressionAssemblyError,
            M6ReplayLockedClosedPolicyPublicationBuildError,
        ) as exc:
            raise M6ReplayLockedClosedPolicyRegressionStoreError(
                M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID
            ) from exc
        if (
            rebuilt_report.report != report
            or rebuilt_report.report_document != report_document
            or rebuilt_report.command_document != command_document
            or rebuilt_publication.seal != seal
            or rebuilt_publication.seal_document != seal_document
        ):
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID)
        if command != report.command:
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DOCUMENT_INVALID)
        return M6StoredReplayLockedClosedPolicyRegressionBundle(
            report_bundle=rebuilt_report,
            seal=seal,
            seal_document=seal_document,
        )

    @staticmethod
    def _require_exact_seal_inventory(
        workspace: SecureWorkspace,
        seal_directory: str,
    ) -> None:
        try:
            hints = workspace.list_m6_replay_locked_closed_policy_seal_directory(
                seal_directory,
                _MAX_SEAL_DIRECTORY_ITEMS,
                _MAX_NAME_BYTES,
            )
        except PathBoundaryViolation as exc:
            if exc.reason_code == "DIRECTORY_MISSING":
                _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SEAL_INVALID)
            raise
        if len(hints) != 1 or hints[0].name != "seal.json":
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.INVENTORY_INVALID)


class M6ReplayLockedClosedPolicyRegressionPublisher:
    """Publish dependencies and V2 seal before the fixed report commit point."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
        fault_injector: (M6ReplayLockedClosedPolicyRegressionStoreFaultInjector | None) = None,
        max_document_bytes: int = (MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_DOCUMENT_BYTES),
        max_bundle_bytes: int = (MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_PUBLICATION_BUNDLE_BYTES),
    ) -> None:
        for value, label in (
            (max_document_bytes, "max_document_bytes"),
            (max_bundle_bytes, "max_bundle_bytes"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        self._output_root = Path(output_root).absolute()
        self._source_catalog_provider = _validate_provider(source_catalog_provider)
        self._fault_injector = fault_injector
        self._max_document_bytes = max_document_bytes
        self._max_bundle_bytes = max_bundle_bytes
        try:
            self._output_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise M6ReplayLockedClosedPolicyRegressionStoreError(
                M6ReplayLockedClosedPolicyRegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from None

    def publish(
        self,
        bundle: object,
    ) -> M6ReplayLockedClosedPolicyRegressionPublicationResult:
        controlled = _validate_bundle(bundle)
        if (
            any(item.size_bytes > self._max_document_bytes for item in controlled.seal.entries)
            or sum(item.size_bytes for item in controlled.seal.entries) > self._max_bundle_bytes
        ):
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.BUNDLE_INVALID)
        seal_payload = controlled.seal_document.encode("utf-8")
        if len(seal_payload) > MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_PUBLICATION_SEAL_BYTES:
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.BUNDLE_INVALID)
        stored_catalog = _load_source_catalog(
            self._source_catalog_provider,
            controlled.seal.source_catalog_authority_id,
            controlled.seal.source_catalog_document_sha256,
        )
        if stored_catalog != controlled.report_bundle.stored_source_catalog:
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SOURCE_CATALOG_MISMATCH)
        documents = {
            item.kind: controlled.document_for(item.kind).encode("utf-8")
            for item in controlled.seal.entries
        }
        stage_root = (
            f".staging/{controlled.seal.candidate_run_id}/m6-regression/"
            f"closed-policy/{controlled.seal.seal_id}"
        )
        commit_attempted = False
        seal_published = False
        try:
            with SecureWorkspace(
                self._output_root,
                max(
                    self._max_document_bytes,
                    MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_PUBLICATION_SEAL_BYTES,
                ),
            ) as workspace:
                self._ensure_directories(workspace, controlled.seal, stage_root)
                for entry in controlled.seal.entries:
                    self._create_or_verify(
                        workspace,
                        f"{stage_root}/{entry.relative_path}",
                        documents[entry.kind],
                    )
                staged_seal = f"{stage_root}/{controlled.seal.seal_relative_path}"
                self._create_or_verify(workspace, staged_seal, seal_payload)
                self._fault("after_staging")
                for entry in controlled.seal.entries:
                    if (
                        entry.kind
                        == M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT
                    ):
                        continue
                    workspace.publish_staged(
                        f"{stage_root}/{entry.relative_path}",
                        _entry_final_relative(controlled.seal.candidate_run_id, entry),
                        entry.content_sha256,
                        remove_source_if_existing_equal=True,
                    )
                    self._fault(f"after_dependency:{entry.kind.value}")
                workspace.publish_staged(
                    staged_seal,
                    _seal_final_relative(controlled.seal),
                    _sha256(seal_payload),
                    remove_source_if_existing_equal=True,
                )
                seal_published = True
                self._fault("after_seal")
                self._fault("before_commit")
                commit_attempted = True
                report_entry = _entry_by_kind(controlled.seal)[
                    M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT
                ]
                workspace.publish_staged(
                    f"{stage_root}/{report_entry.relative_path}",
                    _report_final_relative(controlled.seal.candidate_run_id),
                    report_entry.content_sha256,
                    remove_source_if_existing_equal=True,
                )
                self._fault("after_commit")
        except Exception as exc:
            recovered = self._recover_exact(controlled)
            if recovered is not None:
                return recovered
            if isinstance(exc, M6ReplayLockedClosedPolicyRegressionStoreError):
                raise
            if isinstance(exc, ArtifactConflict):
                code = (
                    M6ReplayLockedClosedPolicyRegressionStoreErrorCode.COMMIT_CONFLICT
                    if commit_attempted
                    else M6ReplayLockedClosedPolicyRegressionStoreErrorCode.STAGING_CONFLICT
                )
            elif commit_attempted:
                code = M6ReplayLockedClosedPolicyRegressionStoreErrorCode.COMMIT_OUTCOME_UNKNOWN
            elif seal_published:
                code = M6ReplayLockedClosedPolicyRegressionStoreErrorCode.SEAL_PUBLICATION_FAILED
            elif isinstance(
                exc,
                (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation),
            ):
                code = M6ReplayLockedClosedPolicyRegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            else:
                code = (
                    M6ReplayLockedClosedPolicyRegressionStoreErrorCode.DEPENDENCY_PUBLICATION_FAILED
                )
            raise M6ReplayLockedClosedPolicyRegressionStoreError(code) from exc
        recovered = self._recover_exact(controlled)
        if recovered is None:
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.COMMIT_OUTCOME_UNKNOWN)
        return recovered

    def _recover_exact(
        self,
        bundle: M6ReplayLockedClosedPolicyPublicationBundle,
    ) -> M6ReplayLockedClosedPolicyRegressionPublicationResult | None:
        try:
            stored = ReadonlyM6ReplayLockedClosedPolicyRegressionStore(
                self._output_root,
                source_catalog_provider=self._source_catalog_provider,
                max_document_bytes=self._max_document_bytes,
                max_bundle_bytes=self._max_bundle_bytes,
            ).load(bundle.seal.candidate_run_id)
            rebuilt = stored.to_publication_bundle()
        except (
            M6ReplayLockedClosedPolicyRegressionStoreError,
            M6ReplayLockedClosedPolicyPublicationBuildError,
        ):
            return None
        if rebuilt != bundle:
            return None
        return self._result(bundle.seal)

    @staticmethod
    def _ensure_directories(
        workspace: SecureWorkspace,
        seal: M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
        stage_root: str,
    ) -> None:
        root = _root_relative(seal.candidate_run_id)
        directories = {
            ".staging",
            f".staging/{seal.candidate_run_id}",
            f".staging/{seal.candidate_run_id}/m6-regression",
            f".staging/{seal.candidate_run_id}/m6-regression/closed-policy",
            stage_root,
            root,
            f"{root}/m6-regression",
            f"{root}/m6-regression/documents",
            f"{root}/m6-regression/closed-policy-seals",
            f"{root}/m6-regression/closed-policy-seals/{seal.report_id}",
            f"{stage_root}/m6-regression",
            f"{stage_root}/m6-regression/documents",
            f"{stage_root}/m6-regression/closed-policy-seals",
            f"{stage_root}/m6-regression/closed-policy-seals/{seal.report_id}",
            *(
                f"{root}/{entry.relative_path.rsplit('/', maxsplit=1)[0]}"
                for entry in seal.entries
                if "/" in entry.relative_path
            ),
            *(
                f"{stage_root}/{entry.relative_path.rsplit('/', maxsplit=1)[0]}"
                for entry in seal.entries
                if "/" in entry.relative_path
            ),
        }
        for directory in sorted(
            directories,
            key=lambda item: (item.count("/"), item),
        ):
            workspace.ensure_private_directory(directory)

    @staticmethod
    def _create_or_verify(
        workspace: SecureWorkspace,
        relative_path: str,
        payload: bytes,
    ) -> None:
        expected = _sha256(payload)
        try:
            observed = workspace.create_new(relative_path, payload, expected)
        except ArtifactConflict:
            try:
                observed = workspace.read_verified(
                    relative_path,
                    expected,
                    max_bytes=len(payload),
                )
            except (ArtifactIntegrityViolation, PathBoundaryViolation):
                _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.STAGING_CONFLICT)
        if observed.bytes != payload:
            _fail(M6ReplayLockedClosedPolicyRegressionStoreErrorCode.STAGING_CONFLICT)

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)

    def _result(
        self,
        seal: M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
    ) -> M6ReplayLockedClosedPolicyRegressionPublicationResult:
        dependencies = tuple(
            self._output_root / Path(_entry_final_relative(seal.candidate_run_id, entry))
            for entry in seal.entries
            if (entry.kind != M6ReplayLockedClosedPolicyPublicationDocumentKind.REGRESSION_REPORT)
        )
        return M6ReplayLockedClosedPolicyRegressionPublicationResult(
            seal_id=seal.seal_id,
            report_path=self._output_root / Path(_report_final_relative(seal.candidate_run_id)),
            seal_path=self._output_root / Path(_seal_final_relative(seal)),
            dependency_paths=dependencies,
        )


__all__ = [
    "MAX_M6_REPLAY_LOCKED_CLOSED_POLICY_REGRESSION_PUBLICATION_SEAL_BYTES",
    "M6ReplayLockedClosedPolicyRegressionPublicationResult",
    "M6ReplayLockedClosedPolicyRegressionPublisher",
    "M6ReplayLockedClosedPolicyRegressionStoreError",
    "M6ReplayLockedClosedPolicyRegressionStoreErrorCode",
    "M6ReplayLockedClosedPolicyRegressionStoreFaultInjector",
    "M6StoredReplayLockedClosedPolicyRegressionBundle",
    "ReadonlyM6ReplayLockedClosedPolicyRegressionStore",
]
