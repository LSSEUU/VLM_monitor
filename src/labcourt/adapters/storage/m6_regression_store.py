"""Secure immutable publication and readback of M6 regression bundles."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_regression_publication import (
    M6RegressionPublicationBuildError,
    M6RegressionPublicationBundle,
    build_m6_regression_publication_bundle,
)
from labcourt.application.m6_upgrade_regression import (
    M6UpgradeRegressionAssemblyError,
    M6UpgradeRegressionReportBundle,
    assemble_m6_upgrade_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import (
    M6RegressionDatasetSnapshot,
    M6RegressionReport,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.contracts.m6_regression_publication import (
    MAX_M6_REGRESSION_PUBLICATION_BUNDLE_BYTES,
    MAX_M6_REGRESSION_PUBLICATION_DOCUMENT_BYTES,
    M6RegressionPublicationDocumentEntry,
    M6RegressionPublicationDocumentKind,
    M6RegressionPublicationSeal,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    LabCourtError,
    PathBoundaryViolation,
)

from .secure_workspace import SecureWorkspace

MAX_M6_REGRESSION_PUBLICATION_SEAL_BYTES = 1024 * 1024
_MAX_SEAL_DIRECTORY_ITEMS = 2
_MAX_NAME_BYTES = 512
M6RegressionStoreFaultInjector = Callable[[str], None]
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6RegressionStoreErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    BUNDLE_INVALID = "BUNDLE_INVALID"
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


class M6RegressionStoreError(LabCourtError):
    def __init__(self, code: M6RegressionStoreErrorCode) -> None:
        if not isinstance(code, M6RegressionStoreErrorCode):
            raise TypeError("code must be an M6RegressionStoreErrorCode")
        self.code = code
        super().__init__(f"M6 regression store failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6RegressionPublicationResult:
    seal_id: str
    report_path: Path
    seal_path: Path
    dependency_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class M6StoredRegressionBundle:
    command: M6RegressionRunCommand
    dataset: M6RegressionDatasetSnapshot
    candidate_output_inventory: M6UpgradeCandidateOutputInventoryAuthorityV3
    report: M6RegressionReport
    seal: M6RegressionPublicationSeal
    command_document: str
    dataset_document: str
    candidate_output_inventory_document: str
    report_document: str
    seal_document: str

    def to_report_bundle(self) -> M6UpgradeRegressionReportBundle:
        return assemble_m6_upgrade_regression_report(
            command=self.command,
            command_document=self.command_document,
            dataset=self.dataset,
            dataset_document=self.dataset_document,
            candidate_output_inventory=self.candidate_output_inventory,
            candidate_output_inventory_document=self.candidate_output_inventory_document,
        )


def _fail(code: M6RegressionStoreErrorCode) -> NoReturn:
    raise M6RegressionStoreError(code)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_model_document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _parse_canonical(
    payload: bytes,
    model_type: type[_ModelT],
    code: M6RegressionStoreErrorCode,
) -> tuple[_ModelT, str]:
    try:
        document = payload.decode("utf-8")
        value = model_type.model_validate_json(payload)
        if _canonical_model_document(value) != document:
            _fail(code)
        return value, document
    except M6RegressionStoreError:
        raise
    except (UnicodeDecodeError, TypeError, ValueError, ValidationError):
        _fail(code)


def _root_relative(candidate_run_id: str) -> str:
    return candidate_run_id


def _entry_final_relative(
    candidate_run_id: str,
    entry: M6RegressionPublicationDocumentEntry,
) -> str:
    return f"{_root_relative(candidate_run_id)}/{entry.relative_path}"


def _seal_final_relative(seal: M6RegressionPublicationSeal) -> str:
    return f"{_root_relative(seal.candidate_run_id)}/{seal.seal_relative_path}"


def _report_final_relative(candidate_run_id: str) -> str:
    return f"{_root_relative(candidate_run_id)}/regression.json"


def _entry_by_kind(
    seal: M6RegressionPublicationSeal,
) -> dict[M6RegressionPublicationDocumentKind, M6RegressionPublicationDocumentEntry]:
    return {item.kind: item for item in seal.entries}


def _validate_bundle(bundle: object) -> M6RegressionPublicationBundle:
    if not isinstance(bundle, M6RegressionPublicationBundle):
        _fail(M6RegressionStoreErrorCode.INVALID_ARGUMENT)
    try:
        rebuilt = build_m6_regression_publication_bundle(bundle.report_bundle)
    except M6RegressionPublicationBuildError as exc:
        raise M6RegressionStoreError(M6RegressionStoreErrorCode.BUNDLE_INVALID) from exc
    if rebuilt != bundle:
        _fail(M6RegressionStoreErrorCode.BUNDLE_INVALID)
    for entry in rebuilt.seal.entries:
        payload = rebuilt.document_for(entry.kind).encode("utf-8")
        if entry.content_sha256 != _sha256(payload) or entry.size_bytes != len(payload):
            _fail(M6RegressionStoreErrorCode.BUNDLE_INVALID)
    if _canonical_model_document(rebuilt.seal) != rebuilt.seal_document:
        _fail(M6RegressionStoreErrorCode.BUNDLE_INVALID)
    return rebuilt


class ReadonlyM6RegressionStore:
    """Read from the final report commit point, then verify every dependency."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        max_document_bytes: int = MAX_M6_REGRESSION_PUBLICATION_DOCUMENT_BYTES,
        max_bundle_bytes: int = MAX_M6_REGRESSION_PUBLICATION_BUNDLE_BYTES,
    ) -> None:
        for value, label in (
            (max_document_bytes, "max_document_bytes"),
            (max_bundle_bytes, "max_bundle_bytes"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        self._output_root = Path(output_root).absolute()
        self._max_document_bytes = max_document_bytes
        self._max_bundle_bytes = max_bundle_bytes

    def load(self, candidate_run_id: object) -> M6StoredRegressionBundle:
        if not isinstance(candidate_run_id, str):
            _fail(M6RegressionStoreErrorCode.INVALID_ARGUMENT)
        try:
            controlled_run_id = require_reference_token(
                candidate_run_id,
                "M6 regression candidate run_id",
            )
        except (TypeError, ValueError):
            _fail(M6RegressionStoreErrorCode.INVALID_ARGUMENT)
        workspace_limit = max(
            self._max_document_bytes,
            MAX_M6_REGRESSION_PUBLICATION_SEAL_BYTES,
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
                        _fail(M6RegressionStoreErrorCode.COMMIT_MISSING)
                    raise
                report, report_document = _parse_canonical(
                    first_report.bytes,
                    M6RegressionReport,
                    M6RegressionStoreErrorCode.REPORT_INVALID,
                )
                candidate_run_ids = {
                    receipt.candidate_run_id for receipt in report.execution_receipts
                }
                if candidate_run_ids != {controlled_run_id}:
                    _fail(M6RegressionStoreErrorCode.REPORT_INVALID)
                seal_directory = f"{controlled_run_id}/m6-regression/seals/{report.report_id}"
                self._require_exact_seal_inventory(workspace, seal_directory)
                seal_relative = f"{seal_directory}/seal.json"
                first_seal = workspace.read_verified(
                    seal_relative,
                    max_bytes=MAX_M6_REGRESSION_PUBLICATION_SEAL_BYTES,
                )
                seal, seal_document = _parse_canonical(
                    first_seal.bytes,
                    M6RegressionPublicationSeal,
                    M6RegressionStoreErrorCode.SEAL_INVALID,
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
                    != f"m6-regression/seals/{report.report_id}/seal.json"
                ):
                    _fail(M6RegressionStoreErrorCode.SEAL_INVALID)
                if sum(item.size_bytes for item in seal.entries) > self._max_bundle_bytes:
                    _fail(M6RegressionStoreErrorCode.DOCUMENT_INVALID)
                entries = _entry_by_kind(seal)
                report_entry = entries[M6RegressionPublicationDocumentKind.REGRESSION_REPORT]
                if (
                    report_entry.content_sha256 != first_report.sha256
                    or report_entry.size_bytes != first_report.size_bytes
                    or report_entry.relative_path != "regression.json"
                ):
                    _fail(M6RegressionStoreErrorCode.REPORT_INVALID)
                documents: dict[M6RegressionPublicationDocumentKind, str] = {
                    M6RegressionPublicationDocumentKind.REGRESSION_REPORT: report_document
                }
                for entry in seal.entries:
                    if entry.kind == M6RegressionPublicationDocumentKind.REGRESSION_REPORT:
                        continue
                    if entry.size_bytes > self._max_document_bytes:
                        _fail(M6RegressionStoreErrorCode.DOCUMENT_INVALID)
                    observed = workspace.read_verified(
                        _entry_final_relative(controlled_run_id, entry),
                        entry.content_sha256,
                        max_bytes=entry.size_bytes,
                    )
                    if observed.size_bytes != entry.size_bytes:
                        _fail(M6RegressionStoreErrorCode.DOCUMENT_INVALID)
                    try:
                        documents[entry.kind] = observed.bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        _fail(M6RegressionStoreErrorCode.DOCUMENT_INVALID)
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
                    _fail(M6RegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE)
                self._require_exact_seal_inventory(workspace, seal_directory)
        except M6RegressionStoreError:
            raise
        except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation) as exc:
            raise M6RegressionStoreError(
                M6RegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from exc

        command, command_document = _parse_canonical(
            documents[M6RegressionPublicationDocumentKind.COMMAND].encode("utf-8"),
            M6RegressionRunCommand,
            M6RegressionStoreErrorCode.DOCUMENT_INVALID,
        )
        dataset, dataset_document = _parse_canonical(
            documents[M6RegressionPublicationDocumentKind.EVALUATOR_DATASET].encode("utf-8"),
            M6RegressionDatasetSnapshot,
            M6RegressionStoreErrorCode.DOCUMENT_INVALID,
        )
        outputs, output_document = _parse_canonical(
            documents[M6RegressionPublicationDocumentKind.CANDIDATE_OUTPUT_INVENTORY].encode(
                "utf-8"
            ),
            M6UpgradeCandidateOutputInventoryAuthorityV3,
            M6RegressionStoreErrorCode.DOCUMENT_INVALID,
        )
        try:
            rebuilt_report = assemble_m6_upgrade_regression_report(
                command=command,
                command_document=command_document,
                dataset=dataset,
                dataset_document=dataset_document,
                candidate_output_inventory=outputs,
                candidate_output_inventory_document=output_document,
            )
            rebuilt_publication = build_m6_regression_publication_bundle(rebuilt_report)
        except (M6UpgradeRegressionAssemblyError, M6RegressionPublicationBuildError) as exc:
            raise M6RegressionStoreError(M6RegressionStoreErrorCode.DOCUMENT_INVALID) from exc
        if (
            rebuilt_report.report != report
            or rebuilt_report.report_document != report_document
            or rebuilt_publication.seal != seal
            or rebuilt_publication.seal_document != seal_document
        ):
            _fail(M6RegressionStoreErrorCode.DOCUMENT_INVALID)
        return M6StoredRegressionBundle(
            command=command,
            dataset=dataset,
            candidate_output_inventory=outputs,
            report=report,
            seal=seal,
            command_document=command_document,
            dataset_document=dataset_document,
            candidate_output_inventory_document=output_document,
            report_document=report_document,
            seal_document=seal_document,
        )

    @staticmethod
    def _require_exact_seal_inventory(
        workspace: SecureWorkspace,
        seal_directory: str,
    ) -> None:
        try:
            hints = workspace.list_m6_regression_seal_directory(
                seal_directory,
                _MAX_SEAL_DIRECTORY_ITEMS,
                _MAX_NAME_BYTES,
            )
        except PathBoundaryViolation as exc:
            if exc.reason_code == "DIRECTORY_MISSING":
                _fail(M6RegressionStoreErrorCode.SEAL_INVALID)
            raise
        if len(hints) != 1 or hints[0].name != "seal.json":
            _fail(M6RegressionStoreErrorCode.INVENTORY_INVALID)


class M6RegressionPublisher:
    """Publish dependencies and seal first; publish the report last without overwrite."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        fault_injector: M6RegressionStoreFaultInjector | None = None,
        max_document_bytes: int = MAX_M6_REGRESSION_PUBLICATION_DOCUMENT_BYTES,
        max_bundle_bytes: int = MAX_M6_REGRESSION_PUBLICATION_BUNDLE_BYTES,
    ) -> None:
        self._output_root = Path(output_root).absolute()
        self._fault_injector = fault_injector
        self._max_document_bytes = max_document_bytes
        self._max_bundle_bytes = max_bundle_bytes
        try:
            self._output_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise M6RegressionStoreError(
                M6RegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from None

    def publish(self, bundle: object) -> M6RegressionPublicationResult:
        controlled = _validate_bundle(bundle)
        if (
            any(item.size_bytes > self._max_document_bytes for item in controlled.seal.entries)
            or sum(item.size_bytes for item in controlled.seal.entries) > self._max_bundle_bytes
        ):
            _fail(M6RegressionStoreErrorCode.BUNDLE_INVALID)
        seal_payload = controlled.seal_document.encode("utf-8")
        if len(seal_payload) > MAX_M6_REGRESSION_PUBLICATION_SEAL_BYTES:
            _fail(M6RegressionStoreErrorCode.BUNDLE_INVALID)
        documents = {
            item.kind: controlled.document_for(item.kind).encode("utf-8")
            for item in controlled.seal.entries
        }
        stage_root = (
            f".staging/{controlled.seal.candidate_run_id}/m6-regression/{controlled.seal.seal_id}"
        )
        commit_attempted = False
        seal_published = False
        try:
            with SecureWorkspace(
                self._output_root,
                max(self._max_document_bytes, MAX_M6_REGRESSION_PUBLICATION_SEAL_BYTES),
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
                    if entry.kind == M6RegressionPublicationDocumentKind.REGRESSION_REPORT:
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
                    M6RegressionPublicationDocumentKind.REGRESSION_REPORT
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
            if isinstance(exc, M6RegressionStoreError):
                raise
            if isinstance(exc, ArtifactConflict):
                code = (
                    M6RegressionStoreErrorCode.COMMIT_CONFLICT
                    if commit_attempted
                    else M6RegressionStoreErrorCode.STAGING_CONFLICT
                )
            elif commit_attempted:
                code = M6RegressionStoreErrorCode.COMMIT_OUTCOME_UNKNOWN
            elif seal_published:
                code = M6RegressionStoreErrorCode.SEAL_PUBLICATION_FAILED
            elif isinstance(
                exc,
                (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation),
            ):
                code = M6RegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            else:
                code = M6RegressionStoreErrorCode.DEPENDENCY_PUBLICATION_FAILED
            raise M6RegressionStoreError(code) from exc
        recovered = self._recover_exact(controlled)
        if recovered is None:
            _fail(M6RegressionStoreErrorCode.COMMIT_OUTCOME_UNKNOWN)
        return recovered

    def _recover_exact(
        self,
        bundle: M6RegressionPublicationBundle,
    ) -> M6RegressionPublicationResult | None:
        try:
            stored = ReadonlyM6RegressionStore(
                self._output_root,
                max_document_bytes=self._max_document_bytes,
                max_bundle_bytes=self._max_bundle_bytes,
            ).load(bundle.seal.candidate_run_id)
        except M6RegressionStoreError:
            return None
        if (
            stored.seal != bundle.seal
            or stored.seal_document != bundle.seal_document
            or stored.command_document != bundle.report_bundle.command_document
            or stored.dataset_document != bundle.report_bundle.dataset_document
            or stored.candidate_output_inventory_document
            != bundle.report_bundle.candidate_output_inventory_document
            or stored.report_document != bundle.report_bundle.report_document
        ):
            return None
        return self._result(bundle.seal)

    @staticmethod
    def _ensure_directories(
        workspace: SecureWorkspace,
        seal: M6RegressionPublicationSeal,
        stage_root: str,
    ) -> None:
        root = _root_relative(seal.candidate_run_id)
        directories = {
            ".staging",
            f".staging/{seal.candidate_run_id}",
            f".staging/{seal.candidate_run_id}/m6-regression",
            stage_root,
            root,
            f"{root}/m6-regression",
            f"{root}/m6-regression/documents",
            f"{root}/m6-regression/seals",
            f"{root}/m6-regression/seals/{seal.report_id}",
            f"{stage_root}/m6-regression",
            f"{stage_root}/m6-regression/documents",
            f"{stage_root}/m6-regression/seals",
            f"{stage_root}/m6-regression/seals/{seal.report_id}",
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
        for directory in sorted(directories, key=lambda item: (item.count("/"), item)):
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
                _fail(M6RegressionStoreErrorCode.STAGING_CONFLICT)
        if observed.bytes != payload:
            _fail(M6RegressionStoreErrorCode.STAGING_CONFLICT)

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)

    def _result(self, seal: M6RegressionPublicationSeal) -> M6RegressionPublicationResult:
        dependencies = tuple(
            self._output_root / Path(_entry_final_relative(seal.candidate_run_id, entry))
            for entry in seal.entries
            if entry.kind != M6RegressionPublicationDocumentKind.REGRESSION_REPORT
        )
        return M6RegressionPublicationResult(
            seal_id=seal.seal_id,
            report_path=self._output_root / Path(_report_final_relative(seal.candidate_run_id)),
            seal_path=self._output_root / Path(_seal_final_relative(seal)),
            dependency_paths=dependencies,
        )


__all__ = [
    "MAX_M6_REGRESSION_PUBLICATION_SEAL_BYTES",
    "M6RegressionPublicationResult",
    "M6RegressionPublisher",
    "M6RegressionStoreError",
    "M6RegressionStoreErrorCode",
    "M6StoredRegressionBundle",
    "ReadonlyM6RegressionStore",
]
