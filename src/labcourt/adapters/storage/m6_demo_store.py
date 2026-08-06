"""Atomic publication and exact readback for the complete offline M6 demo."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.adapters.storage.m6_replay_locked_closed_policy_regression_store import (
    M6ReplayLockedClosedPolicyRegressionStoreError,
    M6ReplayLockedClosedPolicyRegressionStoreErrorCode,
    ReadonlyM6ReplayLockedClosedPolicyRegressionStore,
)
from labcourt.adapters.storage.m6_static_report_store import (
    M6PrivacySafeStaticReportStoreError,
    M6PrivacySafeStaticReportStoreErrorCode,
    M6StoredPrivacySafeStaticReportBundle,
    ReadonlyM6PrivacySafeStaticReportStore,
)
from labcourt.application.m6_demo import (
    M6OfflineDemoPublicationBuildError,
    M6OfflineDemoPublicationBundle,
    M6OfflineDemoScenarioResultDocument,
    build_m6_offline_demo_publication,
)
from labcourt.application.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationBundle,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_demo import (
    MAX_M6_OFFLINE_DEMO_SCENARIO_ARTIFACT_BYTES,
    M6OfflineDemoManifestAuthorityV1,
    M6OfflineDemoScenarioResultAuthorityV1,
)
from labcourt.contracts.m6_demo_publication import (
    MAX_M6_OFFLINE_DEMO_LANDING_BYTES,
    MAX_M6_OFFLINE_DEMO_MANIFEST_BYTES,
    M6OfflineDemoPublicationSealAuthorityV1,
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
)

from .secure_workspace import SecureFileSnapshot, SecureWorkspace

MAX_M6_OFFLINE_DEMO_PUBLICATION_SEAL_BYTES = 1024 * 1024
MAX_M6_OFFLINE_DEMO_BUNDLE_BYTES = 512 * 1024 * 1024
_MAX_INVENTORY_NAME_BYTES = 4096
M6OfflineDemoStoreFaultInjector = Callable[[str], None]
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6OfflineDemoStoreErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    BUNDLE_INVALID = "BUNDLE_INVALID"
    UPSTREAM_MISSING = "UPSTREAM_MISSING"
    UPSTREAM_INVALID = "UPSTREAM_INVALID"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    STAGING_CONFLICT = "STAGING_CONFLICT"
    DEPENDENCY_PUBLICATION_FAILED = "DEPENDENCY_PUBLICATION_FAILED"
    SEAL_PUBLICATION_FAILED = "SEAL_PUBLICATION_FAILED"
    COMMIT_PUBLICATION_FAILED = "COMMIT_PUBLICATION_FAILED"
    COMMIT_CONFLICT = "COMMIT_CONFLICT"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    COMMIT_MISSING = "COMMIT_MISSING"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    SEAL_INVALID = "SEAL_INVALID"
    LANDING_INVALID = "LANDING_INVALID"
    SCENARIO_INVALID = "SCENARIO_INVALID"
    INVENTORY_INVALID = "INVENTORY_INVALID"
    STORAGE_BOUNDARY_FAILURE = "STORAGE_BOUNDARY_FAILURE"


class M6OfflineDemoStoreError(LabCourtError):
    """Payload-free failure at the offline-demo publication boundary."""

    def __init__(self, code: M6OfflineDemoStoreErrorCode) -> None:
        if not isinstance(code, M6OfflineDemoStoreErrorCode):
            raise TypeError("code must be an M6OfflineDemoStoreErrorCode")
        self.code = code
        super().__init__(f"M6 offline demo store failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6OfflineDemoPublicationResult:
    seal_id: str
    index_path: Path
    manifest_path: Path
    seal_path: Path
    scenario_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class M6StoredOfflineDemoBundle:
    publication_bundle: M6OfflineDemoPublicationBundle


def _fail(code: M6OfflineDemoStoreErrorCode) -> NoReturn:
    raise M6OfflineDemoStoreError(code)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_model_document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _parse_canonical(
    snapshot: SecureFileSnapshot,
    model_type: type[_ModelT],
    code: M6OfflineDemoStoreErrorCode,
) -> tuple[_ModelT, str]:
    try:
        document = snapshot.bytes.decode("utf-8")
        value = model_type.model_validate_json(snapshot.bytes)
        if _canonical_model_document(value) != document:
            _fail(code)
        return value, document
    except M6OfflineDemoStoreError:
        raise
    except (UnicodeDecodeError, TypeError, ValueError, ValidationError):
        _fail(code)


def _positive_budget(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _provider(value: object) -> M6RegressionExecutionSourceCatalogProvider:
    if not isinstance(value, M6RegressionExecutionSourceCatalogProvider):
        _fail(M6OfflineDemoStoreErrorCode.INVALID_ARGUMENT)
    return value


def _final_relative(run_id: str, relative_path: str) -> str:
    return f"{run_id}/{relative_path}"


def _load_upstreams(
    output_root: Path,
    source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
    run_id: str,
) -> tuple[
    M6ReplayLockedClosedPolicyPublicationBundle,
    M6StoredPrivacySafeStaticReportBundle,
]:
    try:
        closed = ReadonlyM6ReplayLockedClosedPolicyRegressionStore(
            output_root,
            source_catalog_provider=source_catalog_provider,
        ).load(run_id)
    except M6ReplayLockedClosedPolicyRegressionStoreError as exc:
        if exc.code is M6ReplayLockedClosedPolicyRegressionStoreErrorCode.COMMIT_MISSING:
            _fail(M6OfflineDemoStoreErrorCode.UPSTREAM_MISSING)
        raise M6OfflineDemoStoreError(M6OfflineDemoStoreErrorCode.UPSTREAM_INVALID) from exc
    try:
        static = ReadonlyM6PrivacySafeStaticReportStore(output_root).load(run_id)
    except M6PrivacySafeStaticReportStoreError as exc:
        if exc.code is M6PrivacySafeStaticReportStoreErrorCode.COMMIT_MISSING:
            _fail(M6OfflineDemoStoreErrorCode.UPSTREAM_MISSING)
        raise M6OfflineDemoStoreError(M6OfflineDemoStoreErrorCode.UPSTREAM_INVALID) from exc
    return closed.to_publication_bundle(), static


def _rebuild_publication(
    output_root: Path,
    source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
    value: object,
) -> M6OfflineDemoPublicationBundle:
    if type(value) is not M6OfflineDemoPublicationBundle:
        _fail(M6OfflineDemoStoreErrorCode.INVALID_ARGUMENT)
    assert isinstance(value, M6OfflineDemoPublicationBundle)
    try:
        run_id = require_reference_token(
            value.seal.candidate_run_id,
            "M6 offline demo candidate run_id",
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6OfflineDemoStoreErrorCode.BUNDLE_INVALID)
    regression, static = _load_upstreams(output_root, source_catalog_provider, run_id)
    try:
        rebuilt = build_m6_offline_demo_publication(
            regression,
            static.static_report_bundle,
            static.seal,
            static.seal_document,
            value.scenario_result_documents,
        )
    except (AttributeError, TypeError, ValueError, M6OfflineDemoPublicationBuildError) as exc:
        raise M6OfflineDemoStoreError(M6OfflineDemoStoreErrorCode.BUNDLE_INVALID) from exc
    if rebuilt != value:
        _fail(M6OfflineDemoStoreErrorCode.BUNDLE_INVALID)
    return rebuilt


class ReadonlyM6OfflineDemoStore:
    """Load ``demo/index.html`` as commit point and verify every sealed byte."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
        max_manifest_bytes: int = MAX_M6_OFFLINE_DEMO_MANIFEST_BYTES,
        max_index_bytes: int = MAX_M6_OFFLINE_DEMO_LANDING_BYTES,
        max_scenario_bytes: int = MAX_M6_OFFLINE_DEMO_SCENARIO_ARTIFACT_BYTES,
        max_bundle_bytes: int = MAX_M6_OFFLINE_DEMO_BUNDLE_BYTES,
    ) -> None:
        self._output_root = Path(output_root).absolute()
        self._source_catalog_provider = _provider(source_catalog_provider)
        self._max_manifest_bytes = _positive_budget(max_manifest_bytes, "max_manifest_bytes")
        self._max_index_bytes = _positive_budget(max_index_bytes, "max_index_bytes")
        self._max_scenario_bytes = _positive_budget(max_scenario_bytes, "max_scenario_bytes")
        self._max_bundle_bytes = _positive_budget(max_bundle_bytes, "max_bundle_bytes")

    def load(self, candidate_run_id: object) -> M6StoredOfflineDemoBundle:
        code: M6OfflineDemoStoreErrorCode | None = None
        try:
            return self._load_impl(candidate_run_id)
        except M6OfflineDemoStoreError as exc:
            code = exc.code
        assert code is not None
        raise M6OfflineDemoStoreError(code) from None

    def _load_impl(self, candidate_run_id: object) -> M6StoredOfflineDemoBundle:
        if not isinstance(candidate_run_id, str):
            _fail(M6OfflineDemoStoreErrorCode.INVALID_ARGUMENT)
        try:
            run_id = require_reference_token(candidate_run_id, "M6 offline demo run_id")
        except (TypeError, ValueError):
            _fail(M6OfflineDemoStoreErrorCode.INVALID_ARGUMENT)

        index_relative = _final_relative(run_id, "demo/index.html")
        seal_relative = _final_relative(run_id, "demo/seal.json")
        workspace_limit = max(
            self._max_manifest_bytes,
            self._max_index_bytes,
            self._max_scenario_bytes,
            MAX_M6_OFFLINE_DEMO_PUBLICATION_SEAL_BYTES,
        )
        try:
            with SecureWorkspace(self._output_root, workspace_limit) as workspace:
                first_index = self._read_commit(workspace, index_relative)
                first_seal = workspace.read_verified(
                    seal_relative,
                    max_bytes=MAX_M6_OFFLINE_DEMO_PUBLICATION_SEAL_BYTES,
                )
                seal, seal_document = _parse_canonical(
                    first_seal,
                    M6OfflineDemoPublicationSealAuthorityV1,
                    M6OfflineDemoStoreErrorCode.SEAL_INVALID,
                )
                self._validate_seal_shape(seal, run_id, first_index)
                first_manifest = workspace.read_verified(
                    _final_relative(run_id, seal.manifest_relative_path),
                    seal.demo_manifest_content_sha256,
                    max_bytes=min(seal.demo_manifest_size_bytes, self._max_manifest_bytes),
                )
                if first_manifest.size_bytes != seal.demo_manifest_size_bytes:
                    _fail(M6OfflineDemoStoreErrorCode.MANIFEST_INVALID)
                manifest, manifest_document = _parse_canonical(
                    first_manifest,
                    M6OfflineDemoManifestAuthorityV1,
                    M6OfflineDemoStoreErrorCode.MANIFEST_INVALID,
                )
                if (
                    manifest.candidate_run_id != run_id
                    or manifest.demo_manifest_id != seal.demo_manifest_id
                    or manifest.scenario_inventory_root_sha256
                    != seal.scenario_inventory_root_sha256
                ):
                    _fail(M6OfflineDemoStoreErrorCode.MANIFEST_INVALID)
                sealed_total_size = (
                    first_index.size_bytes
                    + first_seal.size_bytes
                    + first_manifest.size_bytes
                    + sum(receipt.artifact_size_bytes for receipt in manifest.scenario_receipts)
                )
                if sealed_total_size > self._max_bundle_bytes:
                    _fail(M6OfflineDemoStoreErrorCode.BUDGET_EXCEEDED)
                scenario_documents, scenario_snapshots = self._read_scenarios(
                    workspace,
                    run_id,
                    manifest,
                )
                self._require_exact_inventory(workspace, run_id, seal, manifest)
                self._repeat_read(
                    workspace,
                    first_index,
                    first_seal,
                    first_manifest,
                    scenario_snapshots,
                )
                try:
                    landing_document = first_index.bytes.decode("utf-8")
                except UnicodeDecodeError:
                    _fail(M6OfflineDemoStoreErrorCode.LANDING_INVALID)
        except M6OfflineDemoStoreError:
            raise
        except BudgetExceeded:
            _fail(M6OfflineDemoStoreErrorCode.BUDGET_EXCEEDED)
        except (ArtifactIntegrityViolation, PathBoundaryViolation, ValueError):
            _fail(M6OfflineDemoStoreErrorCode.STORAGE_BOUNDARY_FAILURE)

        regression, static = _load_upstreams(
            self._output_root,
            self._source_catalog_provider,
            run_id,
        )
        try:
            rebuilt = build_m6_offline_demo_publication(
                regression,
                static.static_report_bundle,
                static.seal,
                static.seal_document,
                scenario_documents,
            )
        except M6OfflineDemoPublicationBuildError as exc:
            raise M6OfflineDemoStoreError(M6OfflineDemoStoreErrorCode.MANIFEST_INVALID) from exc
        if rebuilt.manifest_bundle.manifest_document != manifest_document:
            _fail(M6OfflineDemoStoreErrorCode.MANIFEST_INVALID)
        if rebuilt.landing_document != landing_document:
            _fail(M6OfflineDemoStoreErrorCode.LANDING_INVALID)
        if rebuilt.seal != seal or rebuilt.seal_document != seal_document:
            _fail(M6OfflineDemoStoreErrorCode.SEAL_INVALID)
        try:
            with SecureWorkspace(self._output_root, workspace_limit) as workspace:
                self._repeat_read(
                    workspace,
                    first_index,
                    first_seal,
                    first_manifest,
                    scenario_snapshots,
                )
                self._require_exact_inventory(workspace, run_id, seal, manifest)
        except M6OfflineDemoStoreError:
            raise
        except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation, ValueError):
            _fail(M6OfflineDemoStoreErrorCode.STORAGE_BOUNDARY_FAILURE)
        return M6StoredOfflineDemoBundle(publication_bundle=rebuilt)

    def _read_commit(
        self,
        workspace: SecureWorkspace,
        relative_path: str,
    ) -> SecureFileSnapshot:
        try:
            return workspace.read_verified(relative_path, max_bytes=self._max_index_bytes)
        except PathBoundaryViolation as exc:
            if exc.reason_code == "FILE_MISSING":
                _fail(M6OfflineDemoStoreErrorCode.COMMIT_MISSING)
            if exc.reason_code == "FILE_TOO_LARGE":
                _fail(M6OfflineDemoStoreErrorCode.BUDGET_EXCEEDED)
            raise

    def _validate_seal_shape(
        self,
        seal: M6OfflineDemoPublicationSealAuthorityV1,
        run_id: str,
        index: SecureFileSnapshot,
    ) -> None:
        if (
            seal.candidate_run_id != run_id
            or seal.landing_relative_path != "demo/index.html"
            or seal.seal_relative_path != "demo/seal.json"
        ):
            _fail(M6OfflineDemoStoreErrorCode.SEAL_INVALID)
        if (
            seal.landing_size_bytes > self._max_index_bytes
            or seal.demo_manifest_size_bytes > self._max_manifest_bytes
        ):
            _fail(M6OfflineDemoStoreErrorCode.BUDGET_EXCEEDED)
        if (
            index.sha256 != seal.landing_content_sha256
            or index.size_bytes != seal.landing_size_bytes
        ):
            _fail(M6OfflineDemoStoreErrorCode.LANDING_INVALID)

    def _read_scenarios(
        self,
        workspace: SecureWorkspace,
        run_id: str,
        manifest: M6OfflineDemoManifestAuthorityV1,
    ) -> tuple[
        tuple[M6OfflineDemoScenarioResultDocument, ...],
        tuple[SecureFileSnapshot, ...],
    ]:
        documents: list[M6OfflineDemoScenarioResultDocument] = []
        snapshots: list[SecureFileSnapshot] = []
        for receipt in manifest.scenario_receipts:
            if receipt.artifact_size_bytes > self._max_scenario_bytes:
                _fail(M6OfflineDemoStoreErrorCode.BUDGET_EXCEEDED)
            try:
                snapshot = workspace.read_verified(
                    _final_relative(run_id, receipt.artifact_relative_path),
                    receipt.artifact_content_sha256,
                    max_bytes=receipt.artifact_size_bytes,
                )
            except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation):
                _fail(M6OfflineDemoStoreErrorCode.SCENARIO_INVALID)
            if snapshot.size_bytes != receipt.artifact_size_bytes:
                _fail(M6OfflineDemoStoreErrorCode.SCENARIO_INVALID)
            result, document = _parse_canonical(
                snapshot,
                M6OfflineDemoScenarioResultAuthorityV1,
                M6OfflineDemoStoreErrorCode.SCENARIO_INVALID,
            )
            if result.scenario_name is not receipt.scenario_name:
                _fail(M6OfflineDemoStoreErrorCode.SCENARIO_INVALID)
            documents.append(
                M6OfflineDemoScenarioResultDocument(
                    result=result,
                    canonical_document=document,
                )
            )
            snapshots.append(snapshot)
        return tuple(documents), tuple(snapshots)

    @staticmethod
    def _repeat_read(
        workspace: SecureWorkspace,
        index: SecureFileSnapshot,
        seal: SecureFileSnapshot,
        manifest: SecureFileSnapshot,
        scenarios: tuple[SecureFileSnapshot, ...],
    ) -> None:
        for snapshot in (index, seal, manifest, *scenarios):
            observed = workspace.read_verified(
                snapshot.relative_path,
                snapshot.sha256,
                max_bytes=snapshot.size_bytes,
            )
            if observed.bytes != snapshot.bytes:
                _fail(M6OfflineDemoStoreErrorCode.STORAGE_BOUNDARY_FAILURE)

    @staticmethod
    def _require_exact_inventory(
        workspace: SecureWorkspace,
        run_id: str,
        seal: M6OfflineDemoPublicationSealAuthorityV1,
        manifest: M6OfflineDemoManifestAuthorityV1,
    ) -> None:
        expected: dict[str, set[str]] = {
            f"{run_id}/demo": {"index.html", "manifests", "scenarios", "seal.json"},
            f"{run_id}/demo/manifests": {f"{seal.demo_manifest_content_sha256}.json"},
            f"{run_id}/demo/scenarios": {
                receipt.scenario_name.value for receipt in manifest.scenario_receipts
            },
        }
        for receipt in manifest.scenario_receipts:
            expected[f"{run_id}/demo/scenarios/{receipt.scenario_name.value}"] = {"result.json"}
        for directory, names in expected.items():
            try:
                hints = workspace.list_m6_offline_demo_directory(
                    directory,
                    len(names) + 1,
                    _MAX_INVENTORY_NAME_BYTES,
                )
            except (BudgetExceeded, PathBoundaryViolation, ValueError):
                _fail(M6OfflineDemoStoreErrorCode.INVENTORY_INVALID)
            observed = {hint.name for hint in hints if hint.name is not None}
            if len(observed) != len(hints) or observed != names:
                _fail(M6OfflineDemoStoreErrorCode.INVENTORY_INVALID)


class M6OfflineDemoPublisher:
    """Publish dependencies first and make ``demo/index.html`` the commit point."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
        fault_injector: M6OfflineDemoStoreFaultInjector | None = None,
        max_manifest_bytes: int = MAX_M6_OFFLINE_DEMO_MANIFEST_BYTES,
        max_index_bytes: int = MAX_M6_OFFLINE_DEMO_LANDING_BYTES,
        max_scenario_bytes: int = MAX_M6_OFFLINE_DEMO_SCENARIO_ARTIFACT_BYTES,
        max_bundle_bytes: int = MAX_M6_OFFLINE_DEMO_BUNDLE_BYTES,
    ) -> None:
        self._output_root = Path(output_root).absolute()
        self._source_catalog_provider = _provider(source_catalog_provider)
        if fault_injector is not None and not callable(fault_injector):
            _fail(M6OfflineDemoStoreErrorCode.INVALID_ARGUMENT)
        self._fault_injector = fault_injector
        self._max_manifest_bytes = _positive_budget(max_manifest_bytes, "max_manifest_bytes")
        self._max_index_bytes = _positive_budget(max_index_bytes, "max_index_bytes")
        self._max_scenario_bytes = _positive_budget(max_scenario_bytes, "max_scenario_bytes")
        self._max_bundle_bytes = _positive_budget(max_bundle_bytes, "max_bundle_bytes")
        try:
            self._output_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            _fail(M6OfflineDemoStoreErrorCode.STORAGE_BOUNDARY_FAILURE)

    def publish(self, bundle: object) -> M6OfflineDemoPublicationResult:
        code: M6OfflineDemoStoreErrorCode | None = None
        try:
            return self._publish_impl(bundle)
        except M6OfflineDemoStoreError as exc:
            code = exc.code
        assert code is not None
        raise M6OfflineDemoStoreError(code) from None

    def _publish_impl(self, bundle: object) -> M6OfflineDemoPublicationResult:
        controlled = _rebuild_publication(
            self._output_root,
            self._source_catalog_provider,
            bundle,
        )
        payloads = self._payloads(controlled)
        self._enforce_budgets(controlled, payloads)
        run_id = controlled.seal.candidate_run_id
        workspace_limit = max(
            self._max_manifest_bytes,
            self._max_index_bytes,
            self._max_scenario_bytes,
            MAX_M6_OFFLINE_DEMO_PUBLICATION_SEAL_BYTES,
        )
        try:
            with SecureWorkspace(self._output_root, workspace_limit) as workspace:
                self._ensure_lock_directory(workspace, run_id)
                with workspace.m6_offline_demo_publish_lock(run_id):
                    existing = self._load_existing(run_id)
                    if existing is not None:
                        if existing.publication_bundle == controlled:
                            return self._result(controlled)
                        _fail(M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT)
                    self._require_compatible_partial_publication(
                        workspace,
                        controlled,
                        payloads,
                    )
                    return self._publish_locked(workspace, controlled, payloads)
        except M6OfflineDemoStoreError as exc:
            if exc.code is M6OfflineDemoStoreErrorCode.COMMIT_OUTCOME_UNKNOWN:
                recovered = self._recover_exact(controlled)
                if recovered is not None:
                    return recovered
            raise
        except BudgetExceeded:
            _fail(M6OfflineDemoStoreErrorCode.BUDGET_EXCEEDED)
        except (ArtifactConflict, ArtifactIntegrityViolation, PathBoundaryViolation):
            recovered = self._recover_exact(controlled)
            if recovered is not None:
                return recovered
            _fail(M6OfflineDemoStoreErrorCode.STORAGE_BOUNDARY_FAILURE)

    @staticmethod
    def _payloads(bundle: M6OfflineDemoPublicationBundle) -> dict[str, bytes]:
        payloads = {
            bundle.seal.landing_relative_path: bundle.landing_document.encode("utf-8"),
            bundle.seal.manifest_relative_path: (
                bundle.manifest_bundle.manifest_document.encode("utf-8")
            ),
            bundle.seal.seal_relative_path: bundle.seal_document.encode("utf-8"),
        }
        payloads.update(
            {
                receipt.artifact_relative_path: document.canonical_document.encode("utf-8")
                for receipt, document in zip(
                    bundle.manifest_bundle.manifest.scenario_receipts,
                    bundle.scenario_result_documents,
                    strict=True,
                )
            }
        )
        return payloads

    def _enforce_budgets(
        self,
        bundle: M6OfflineDemoPublicationBundle,
        payloads: dict[str, bytes],
    ) -> None:
        if (
            bundle.seal.demo_manifest_size_bytes > self._max_manifest_bytes
            or bundle.seal.landing_size_bytes > self._max_index_bytes
            or any(
                item.artifact_size_bytes > self._max_scenario_bytes
                for item in bundle.manifest_bundle.manifest.scenario_receipts
            )
            or len(bundle.seal_document.encode("utf-8"))
            > MAX_M6_OFFLINE_DEMO_PUBLICATION_SEAL_BYTES
            or sum(len(payload) for payload in payloads.values()) > self._max_bundle_bytes
        ):
            _fail(M6OfflineDemoStoreErrorCode.BUDGET_EXCEEDED)

    @staticmethod
    def _ensure_lock_directory(workspace: SecureWorkspace, run_id: str) -> None:
        workspace.ensure_private_directory(".staging")
        workspace.ensure_private_directory(f".staging/{run_id}")
        workspace.ensure_private_directory(f".staging/{run_id}/m6-offline-demo")

    def _publish_locked(
        self,
        workspace: SecureWorkspace,
        bundle: M6OfflineDemoPublicationBundle,
        payloads: dict[str, bytes],
    ) -> M6OfflineDemoPublicationResult:
        run_id = bundle.seal.candidate_run_id
        stage_root = f".staging/{run_id}/m6-offline-demo/pending"
        phase = "staging"
        commit_attempted = False
        try:
            self._ensure_directories(workspace, bundle, stage_root)
            for relative_path, payload in payloads.items():
                self._create_or_verify(
                    workspace,
                    f"{stage_root}/{relative_path}",
                    payload,
                )
            self._fault("after_staging")

            phase = "dependencies"
            for receipt in bundle.manifest_bundle.manifest.scenario_receipts:
                self._publish_one(
                    workspace,
                    stage_root,
                    run_id,
                    receipt.artifact_relative_path,
                    payloads[receipt.artifact_relative_path],
                )
                self._fault(f"after_scenario:{receipt.scenario_name.value}")
            self._publish_one(
                workspace,
                stage_root,
                run_id,
                bundle.seal.manifest_relative_path,
                payloads[bundle.seal.manifest_relative_path],
            )
            self._fault("after_manifest")

            phase = "seal"
            self._publish_one(
                workspace,
                stage_root,
                run_id,
                bundle.seal.seal_relative_path,
                payloads[bundle.seal.seal_relative_path],
            )
            self._fault("after_seal")

            phase = "commit"
            self._fault("before_commit")
            if (
                _rebuild_publication(
                    self._output_root,
                    self._source_catalog_provider,
                    bundle,
                )
                != bundle
            ):
                _fail(M6OfflineDemoStoreErrorCode.BUNDLE_INVALID)
            commit_attempted = True
            self._publish_one(
                workspace,
                stage_root,
                run_id,
                bundle.seal.landing_relative_path,
                payloads[bundle.seal.landing_relative_path],
            )
            self._fault("after_commit")
        except Exception as exc:
            recovered = self._recover_exact(bundle)
            if recovered is not None:
                return recovered
            if isinstance(exc, M6OfflineDemoStoreError):
                raise
            if isinstance(exc, BudgetExceeded):
                code = M6OfflineDemoStoreErrorCode.BUDGET_EXCEEDED
            elif isinstance(exc, ArtifactConflict) and commit_attempted:
                code = M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT
            elif commit_attempted:
                code = M6OfflineDemoStoreErrorCode.COMMIT_OUTCOME_UNKNOWN
            elif phase == "staging":
                code = M6OfflineDemoStoreErrorCode.STAGING_CONFLICT
            elif phase == "seal":
                code = M6OfflineDemoStoreErrorCode.SEAL_PUBLICATION_FAILED
            elif phase == "commit":
                code = M6OfflineDemoStoreErrorCode.COMMIT_PUBLICATION_FAILED
            else:
                code = M6OfflineDemoStoreErrorCode.DEPENDENCY_PUBLICATION_FAILED
            raise M6OfflineDemoStoreError(code) from None
        recovered = self._recover_exact(bundle)
        if recovered is None:
            _fail(M6OfflineDemoStoreErrorCode.COMMIT_OUTCOME_UNKNOWN)
        return recovered

    @staticmethod
    def _require_compatible_partial_publication(
        workspace: SecureWorkspace,
        bundle: M6OfflineDemoPublicationBundle,
        payloads: dict[str, bytes],
    ) -> None:
        run_id = bundle.seal.candidate_run_id
        manifest = bundle.manifest_bundle.manifest
        expected_directories: dict[str, set[str]] = {
            f"{run_id}/demo": {"manifests", "scenarios", "seal.json"},
            f"{run_id}/demo/manifests": {f"{bundle.seal.demo_manifest_content_sha256}.json"},
            f"{run_id}/demo/scenarios": {
                receipt.scenario_name.value for receipt in manifest.scenario_receipts
            },
        }
        for receipt in manifest.scenario_receipts:
            expected_directories[f"{run_id}/demo/scenarios/{receipt.scenario_name.value}"] = {
                "result.json"
            }
        for directory, allowed_names in expected_directories.items():
            try:
                hints = workspace.list_m6_offline_demo_directory(
                    directory,
                    len(allowed_names) + 1,
                    _MAX_INVENTORY_NAME_BYTES,
                )
            except PathBoundaryViolation as exc:
                if exc.reason_code == "DIRECTORY_MISSING":
                    continue
                _fail(M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT)
            except (BudgetExceeded, ValueError):
                _fail(M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT)
            observed = {hint.name for hint in hints if hint.name is not None}
            if len(observed) != len(hints) or not observed.issubset(allowed_names):
                _fail(M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT)

        stage_root = f".staging/{run_id}/m6-offline-demo/pending"
        for relative_path, payload in payloads.items():
            for candidate in (
                f"{stage_root}/{relative_path}",
                _final_relative(run_id, relative_path),
            ):
                if relative_path == bundle.seal.landing_relative_path and candidate.startswith(
                    f"{run_id}/"
                ):
                    continue
                try:
                    snapshot = workspace.read_verified(
                        candidate,
                        _sha256(payload),
                        max_bytes=len(payload),
                    )
                    if snapshot.bytes != payload:
                        _fail(M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT)
                except PathBoundaryViolation as exc:
                    if exc.reason_code == "FILE_MISSING":
                        continue
                    _fail(M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT)
                except (ArtifactIntegrityViolation, BudgetExceeded, ValueError):
                    _fail(M6OfflineDemoStoreErrorCode.COMMIT_CONFLICT)

    @staticmethod
    def _publish_one(
        workspace: SecureWorkspace,
        stage_root: str,
        run_id: str,
        relative_path: str,
        payload: bytes,
    ) -> None:
        workspace.publish_staged(
            f"{stage_root}/{relative_path}",
            _final_relative(run_id, relative_path),
            _sha256(payload),
            remove_source_if_existing_equal=True,
        )

    @staticmethod
    def _ensure_directories(
        workspace: SecureWorkspace,
        bundle: M6OfflineDemoPublicationBundle,
        stage_root: str,
    ) -> None:
        run_id = bundle.seal.candidate_run_id
        for directory in (
            f".staging/{run_id}/m6-offline-demo",
            stage_root,
            f"{stage_root}/demo",
            f"{stage_root}/demo/manifests",
            f"{stage_root}/demo/scenarios",
            run_id,
            f"{run_id}/demo",
            f"{run_id}/demo/manifests",
            f"{run_id}/demo/scenarios",
        ):
            workspace.ensure_private_directory(directory)
        for receipt in bundle.manifest_bundle.manifest.scenario_receipts:
            name = receipt.scenario_name.value
            workspace.ensure_private_directory(f"{stage_root}/demo/scenarios/{name}")
            workspace.ensure_private_directory(f"{run_id}/demo/scenarios/{name}")

    @staticmethod
    def _create_or_verify(
        workspace: SecureWorkspace,
        relative_path: str,
        payload: bytes,
    ) -> None:
        digest = _sha256(payload)
        try:
            workspace.create_new(relative_path, payload, digest)
        except ArtifactConflict:
            existing = workspace.read_verified(
                relative_path,
                digest,
                max_bytes=len(payload),
            )
            if existing.bytes != payload:
                raise

    def _load_existing(self, run_id: str) -> M6StoredOfflineDemoBundle | None:
        try:
            return ReadonlyM6OfflineDemoStore(
                self._output_root,
                source_catalog_provider=self._source_catalog_provider,
                max_manifest_bytes=self._max_manifest_bytes,
                max_index_bytes=self._max_index_bytes,
                max_scenario_bytes=self._max_scenario_bytes,
                max_bundle_bytes=self._max_bundle_bytes,
            ).load(run_id)
        except M6OfflineDemoStoreError as exc:
            if exc.code is M6OfflineDemoStoreErrorCode.COMMIT_MISSING:
                return None
            raise

    def _recover_exact(
        self,
        bundle: M6OfflineDemoPublicationBundle,
    ) -> M6OfflineDemoPublicationResult | None:
        try:
            stored = ReadonlyM6OfflineDemoStore(
                self._output_root,
                source_catalog_provider=self._source_catalog_provider,
                max_manifest_bytes=self._max_manifest_bytes,
                max_index_bytes=self._max_index_bytes,
                max_scenario_bytes=self._max_scenario_bytes,
                max_bundle_bytes=self._max_bundle_bytes,
            ).load(bundle.seal.candidate_run_id)
        except M6OfflineDemoStoreError:
            return None
        if stored.publication_bundle != bundle:
            return None
        return self._result(bundle)

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)

    def _result(
        self,
        bundle: M6OfflineDemoPublicationBundle,
    ) -> M6OfflineDemoPublicationResult:
        run_root = self._output_root / bundle.seal.candidate_run_id
        return M6OfflineDemoPublicationResult(
            seal_id=bundle.seal.seal_id,
            index_path=run_root / Path(*bundle.seal.landing_relative_path.split("/")),
            manifest_path=run_root / Path(*bundle.seal.manifest_relative_path.split("/")),
            seal_path=run_root / Path(*bundle.seal.seal_relative_path.split("/")),
            scenario_paths=tuple(
                run_root / Path(*receipt.artifact_relative_path.split("/"))
                for receipt in bundle.manifest_bundle.manifest.scenario_receipts
            ),
        )


__all__ = [
    "MAX_M6_OFFLINE_DEMO_BUNDLE_BYTES",
    "MAX_M6_OFFLINE_DEMO_PUBLICATION_SEAL_BYTES",
    "M6OfflineDemoPublicationResult",
    "M6OfflineDemoPublisher",
    "M6OfflineDemoStoreError",
    "M6OfflineDemoStoreErrorCode",
    "M6StoredOfflineDemoBundle",
    "ReadonlyM6OfflineDemoStore",
]
