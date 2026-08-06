"""Atomic publication and exact readback for privacy-safe M6 static reports."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationBuildError,
    M6ReplayLockedClosedPolicyPublicationBundle,
    build_m6_replay_locked_closed_policy_publication_bundle,
)
from labcourt.application.m6_static_report import (
    M6PrivacySafeStaticReportBundle,
    M6StaticReportBuildError,
    build_m6_privacy_safe_static_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_static_report import (
    M6PrivacySafeStaticReportManifestAuthorityV1,
    M6StaticReportEvidenceDisposition,
    M6StaticReportEvidenceItem,
)
from labcourt.contracts.m6_static_report_publication import (
    MAX_M6_PRIVACY_SAFE_STATIC_REPORT_HTML_BYTES,
    MAX_M6_PRIVACY_SAFE_STATIC_REPORT_MANIFEST_BYTES,
    M6PrivacySafeStaticReportPublicationSealAuthorityV1,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    LabCourtError,
    PathBoundaryViolation,
)

from .secure_workspace import SecureFileSnapshot, SecureWorkspace

MAX_M6_PRIVACY_SAFE_STATIC_REPORT_PUBLICATION_SEAL_BYTES = 1024 * 1024
MAX_M6_PRIVACY_SAFE_STATIC_REPORT_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_M6_PRIVACY_SAFE_STATIC_REPORT_TOTAL_EVIDENCE_BYTES = 512 * 1024 * 1024
_MAX_INVENTORY_NAME_BYTES = 4096
M6PrivacySafeStaticReportStoreFaultInjector = Callable[[str], None]
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6PrivacySafeStaticReportStoreErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    BUNDLE_INVALID = "BUNDLE_INVALID"
    EVIDENCE_LOAD_FAILED = "EVIDENCE_LOAD_FAILED"
    EVIDENCE_INVALID = "EVIDENCE_INVALID"
    STAGING_CONFLICT = "STAGING_CONFLICT"
    EVIDENCE_PUBLICATION_FAILED = "EVIDENCE_PUBLICATION_FAILED"
    MANIFEST_PUBLICATION_FAILED = "MANIFEST_PUBLICATION_FAILED"
    SEAL_PUBLICATION_FAILED = "SEAL_PUBLICATION_FAILED"
    COMMIT_CONFLICT = "COMMIT_CONFLICT"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    COMMIT_MISSING = "COMMIT_MISSING"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    SEAL_INVALID = "SEAL_INVALID"
    HTML_INVALID = "HTML_INVALID"
    INVENTORY_INVALID = "INVENTORY_INVALID"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    STORAGE_BOUNDARY_FAILURE = "STORAGE_BOUNDARY_FAILURE"


class M6PrivacySafeStaticReportStoreError(LabCourtError):
    """Payload-free failure at the static-report publication boundary."""

    def __init__(self, code: M6PrivacySafeStaticReportStoreErrorCode) -> None:
        if not isinstance(code, M6PrivacySafeStaticReportStoreErrorCode):
            raise TypeError("code must be an M6 static report store error code")
        self.code = code
        super().__init__(f"M6 static report store failed: {code.value}")


@runtime_checkable
class M6PrivacyProcessedEvidenceProvider(Protocol):
    """Load one already privacy-processed raster by its exact dual identity."""

    def load(self, artifact_relative_path: str, content_sha256: str) -> object: ...


@dataclass(frozen=True, slots=True)
class M6StoredPrivacyProcessedEvidence:
    artifact_relative_path: str
    content_sha256: str
    content_bytes: bytes


@dataclass(frozen=True, slots=True)
class M6PrivacySafeStaticReportPublicationResult:
    seal_id: str
    index_path: Path
    manifest_path: Path
    seal_path: Path
    evidence_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class M6StoredPrivacySafeStaticReportBundle:
    static_report_bundle: M6PrivacySafeStaticReportBundle
    seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1
    seal_document: str


def _fail(code: M6PrivacySafeStaticReportStoreErrorCode) -> NoReturn:
    raise M6PrivacySafeStaticReportStoreError(code)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_model_document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _parse_canonical(
    payload: bytes,
    model_type: type[_ModelT],
    code: M6PrivacySafeStaticReportStoreErrorCode,
) -> tuple[_ModelT, str]:
    try:
        document = payload.decode("utf-8")
        value = model_type.model_validate_json(payload)
        if _canonical_model_document(value) != document:
            _fail(code)
        return value, document
    except M6PrivacySafeStaticReportStoreError:
        raise
    except (UnicodeDecodeError, TypeError, ValueError, ValidationError):
        _fail(code)


def _validate_positive_budget(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _validate_provider(value: object) -> M6PrivacyProcessedEvidenceProvider:
    if not isinstance(value, M6PrivacyProcessedEvidenceProvider):
        _fail(M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT)
    return value


def _controlled_publication(
    value: object,
) -> M6ReplayLockedClosedPolicyPublicationBundle:
    if type(value) is not M6ReplayLockedClosedPolicyPublicationBundle:
        _fail(M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT)
    assert isinstance(value, M6ReplayLockedClosedPolicyPublicationBundle)
    try:
        rebuilt = build_m6_replay_locked_closed_policy_publication_bundle(value.report_bundle)
    except (
        AttributeError,
        TypeError,
        ValueError,
        M6ReplayLockedClosedPolicyPublicationBuildError,
    ) as exc:
        raise M6PrivacySafeStaticReportStoreError(
            M6PrivacySafeStaticReportStoreErrorCode.BUNDLE_INVALID
        ) from exc
    if rebuilt != value:
        _fail(M6PrivacySafeStaticReportStoreErrorCode.BUNDLE_INVALID)
    return rebuilt


def _controlled_static_bundle(
    publication: M6ReplayLockedClosedPolicyPublicationBundle,
    value: object,
) -> M6PrivacySafeStaticReportBundle:
    if type(value) is not M6PrivacySafeStaticReportBundle:
        _fail(M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT)
    assert isinstance(value, M6PrivacySafeStaticReportBundle)
    if type(value.manifest) is not M6PrivacySafeStaticReportManifestAuthorityV1:
        _fail(M6PrivacySafeStaticReportStoreErrorCode.BUNDLE_INVALID)
    try:
        rebuilt = build_m6_privacy_safe_static_report(
            publication,
            value.manifest.evidence_items,
        )
    except (AttributeError, TypeError, ValueError, M6StaticReportBuildError) as exc:
        raise M6PrivacySafeStaticReportStoreError(
            M6PrivacySafeStaticReportStoreErrorCode.BUNDLE_INVALID
        ) from exc
    if rebuilt != value:
        _fail(M6PrivacySafeStaticReportStoreErrorCode.BUNDLE_INVALID)
    return rebuilt


def _root_relative(candidate_run_id: str) -> str:
    return candidate_run_id


def _final_relative(candidate_run_id: str, relative_path: str) -> str:
    return f"{_root_relative(candidate_run_id)}/{relative_path}"


def _load_evidence(
    provider: M6PrivacyProcessedEvidenceProvider,
    item: M6StaticReportEvidenceItem,
) -> M6StoredPrivacyProcessedEvidence:
    assert item.artifact_relative_path is not None
    assert item.artifact_content_sha256 is not None
    try:
        value = provider.load(item.artifact_relative_path, item.artifact_content_sha256)
    except Exception:
        raise M6PrivacySafeStaticReportStoreError(
            M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_LOAD_FAILED
        ) from None
    if type(value) is not M6StoredPrivacyProcessedEvidence:
        _fail(M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_LOAD_FAILED)
    assert isinstance(value, M6StoredPrivacyProcessedEvidence)
    if (
        value.artifact_relative_path != item.artifact_relative_path
        or value.content_sha256 != item.artifact_content_sha256
        or type(value.content_bytes) is not bytes
        or _sha256(value.content_bytes) != item.artifact_content_sha256
    ):
        _fail(M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_INVALID)
    return value


def _build_publication_seal(
    publication: M6ReplayLockedClosedPolicyPublicationBundle,
    static_bundle: M6PrivacySafeStaticReportBundle,
    manifest_payload: bytes,
    html_payload: bytes,
) -> M6PrivacySafeStaticReportPublicationSealAuthorityV1:
    return M6PrivacySafeStaticReportPublicationSealAuthorityV1(
        candidate_run_id=publication.seal.candidate_run_id,
        report_id=publication.report_bundle.report.report_id,
        regression_publication_seal_id=publication.seal.seal_id,
        static_report_manifest_id=static_bundle.manifest.manifest_id,
        static_report_manifest_content_sha256=_sha256(manifest_payload),
        static_report_manifest_size_bytes=len(manifest_payload),
        html_content_sha256=_sha256(html_payload),
        html_size_bytes=len(html_payload),
        evidence_inventory_root_sha256=(static_bundle.manifest.evidence_inventory_root_sha256),
    )


class ReadonlyM6PrivacySafeStaticReportStore:
    """Load ``index.html`` as commit point and verify its complete static bundle."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        max_manifest_bytes: int = MAX_M6_PRIVACY_SAFE_STATIC_REPORT_MANIFEST_BYTES,
        max_html_bytes: int = MAX_M6_PRIVACY_SAFE_STATIC_REPORT_HTML_BYTES,
        max_evidence_bytes: int = MAX_M6_PRIVACY_SAFE_STATIC_REPORT_EVIDENCE_BYTES,
    ) -> None:
        self._output_root = Path(output_root).absolute()
        self._max_manifest_bytes = _validate_positive_budget(
            max_manifest_bytes, "max_manifest_bytes"
        )
        self._max_html_bytes = _validate_positive_budget(max_html_bytes, "max_html_bytes")
        self._max_evidence_bytes = _validate_positive_budget(
            max_evidence_bytes, "max_evidence_bytes"
        )

    def load(self, candidate_run_id: object) -> M6StoredPrivacySafeStaticReportBundle:
        if not isinstance(candidate_run_id, str):
            _fail(M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT)
        try:
            controlled_run_id = require_reference_token(
                candidate_run_id,
                "M6 static report candidate run_id",
            )
        except (TypeError, ValueError):
            _fail(M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT)

        workspace_limit = max(
            self._max_manifest_bytes,
            self._max_html_bytes,
            self._max_evidence_bytes,
            MAX_M6_PRIVACY_SAFE_STATIC_REPORT_PUBLICATION_SEAL_BYTES,
        )
        index_relative = _final_relative(controlled_run_id, "index.html")
        seal_relative = _final_relative(controlled_run_id, "m6-static-report/seal.json")
        try:
            with SecureWorkspace(self._output_root, workspace_limit) as workspace:
                first_index = self._read_commit(workspace, index_relative)
                seal, seal_document, first_seal = self._read_seal(
                    workspace,
                    seal_relative,
                )
                if (
                    seal.candidate_run_id != controlled_run_id
                    or seal.html_relative_path != "index.html"
                    or seal.seal_relative_path != "m6-static-report/seal.json"
                ):
                    _fail(M6PrivacySafeStaticReportStoreErrorCode.SEAL_INVALID)
                if (
                    seal.html_size_bytes > self._max_html_bytes
                    or seal.static_report_manifest_size_bytes > self._max_manifest_bytes
                ):
                    _fail(M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED)
                if (
                    first_index.sha256 != seal.html_content_sha256
                    or first_index.size_bytes != seal.html_size_bytes
                ):
                    _fail(M6PrivacySafeStaticReportStoreErrorCode.HTML_INVALID)
                try:
                    html_document = first_index.bytes.decode("utf-8")
                except UnicodeDecodeError:
                    _fail(M6PrivacySafeStaticReportStoreErrorCode.HTML_INVALID)

                manifest_relative = _final_relative(
                    controlled_run_id,
                    seal.manifest_relative_path,
                )
                manifest, manifest_document, first_manifest = self._read_manifest(
                    workspace,
                    manifest_relative,
                    seal,
                )
                if (
                    manifest.candidate_run_id != controlled_run_id
                    or manifest.report_id != seal.report_id
                    or manifest.publication_seal_id != seal.regression_publication_seal_id
                    or manifest.manifest_id != seal.static_report_manifest_id
                    or manifest.evidence_inventory_root_sha256
                    != seal.evidence_inventory_root_sha256
                ):
                    _fail(M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_INVALID)
                evidence_snapshots = self._read_evidence(
                    workspace,
                    controlled_run_id,
                    manifest,
                )
                self._require_exact_inventory(workspace, controlled_run_id, seal, manifest)

                second_manifest = workspace.read_verified(
                    manifest_relative,
                    first_manifest.sha256,
                    max_bytes=first_manifest.size_bytes,
                )
                second_seal = workspace.read_verified(
                    seal_relative,
                    first_seal.sha256,
                    max_bytes=first_seal.size_bytes,
                )
                second_index = workspace.read_verified(
                    index_relative,
                    first_index.sha256,
                    max_bytes=first_index.size_bytes,
                )
                if (
                    second_manifest.bytes != first_manifest.bytes
                    or second_seal.bytes != first_seal.bytes
                    or second_index.bytes != first_index.bytes
                ):
                    _fail(M6PrivacySafeStaticReportStoreErrorCode.STORAGE_BOUNDARY_FAILURE)
                for relative_path, expected_payload in evidence_snapshots:
                    observed = workspace.read_verified(
                        relative_path,
                        _sha256(expected_payload),
                        max_bytes=len(expected_payload),
                    )
                    if observed.bytes != expected_payload:
                        _fail(M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_INVALID)
                self._require_exact_inventory(workspace, controlled_run_id, seal, manifest)
        except M6PrivacySafeStaticReportStoreError:
            raise
        except BudgetExceeded as exc:
            raise M6PrivacySafeStaticReportStoreError(
                M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED
            ) from exc
        except (ArtifactIntegrityViolation, PathBoundaryViolation, ValueError) as exc:
            raise M6PrivacySafeStaticReportStoreError(
                M6PrivacySafeStaticReportStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from exc

        static_bundle = M6PrivacySafeStaticReportBundle(
            manifest=manifest,
            html_document=html_document,
            html_content_sha256=seal.html_content_sha256,
        )
        if manifest_document != _canonical_model_document(static_bundle.manifest):
            _fail(M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_INVALID)
        return M6StoredPrivacySafeStaticReportBundle(
            static_report_bundle=static_bundle,
            seal=seal,
            seal_document=seal_document,
        )

    def _read_commit(
        self,
        workspace: SecureWorkspace,
        relative_path: str,
    ) -> SecureFileSnapshot:
        try:
            return workspace.read_verified(relative_path, max_bytes=self._max_html_bytes)
        except PathBoundaryViolation as exc:
            if exc.reason_code == "FILE_MISSING":
                _fail(M6PrivacySafeStaticReportStoreErrorCode.COMMIT_MISSING)
            if exc.reason_code == "FILE_TOO_LARGE":
                _fail(M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED)
            raise

    @staticmethod
    def _read_seal(
        workspace: SecureWorkspace,
        relative_path: str,
    ) -> tuple[
        M6PrivacySafeStaticReportPublicationSealAuthorityV1,
        str,
        SecureFileSnapshot,
    ]:
        try:
            snapshot = workspace.read_verified(
                relative_path,
                max_bytes=MAX_M6_PRIVACY_SAFE_STATIC_REPORT_PUBLICATION_SEAL_BYTES,
            )
        except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation) as exc:
            raise M6PrivacySafeStaticReportStoreError(
                M6PrivacySafeStaticReportStoreErrorCode.SEAL_INVALID
            ) from exc
        seal, document = _parse_canonical(
            snapshot.bytes,
            M6PrivacySafeStaticReportPublicationSealAuthorityV1,
            M6PrivacySafeStaticReportStoreErrorCode.SEAL_INVALID,
        )
        return seal, document, snapshot

    def _read_manifest(
        self,
        workspace: SecureWorkspace,
        relative_path: str,
        seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1,
    ) -> tuple[
        M6PrivacySafeStaticReportManifestAuthorityV1,
        str,
        SecureFileSnapshot,
    ]:
        try:
            snapshot = workspace.read_verified(
                relative_path,
                seal.static_report_manifest_content_sha256,
                max_bytes=seal.static_report_manifest_size_bytes,
            )
        except (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation) as exc:
            raise M6PrivacySafeStaticReportStoreError(
                M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_INVALID
            ) from exc
        if snapshot.size_bytes != seal.static_report_manifest_size_bytes:
            _fail(M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_INVALID)
        manifest, document = _parse_canonical(
            snapshot.bytes,
            M6PrivacySafeStaticReportManifestAuthorityV1,
            M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_INVALID,
        )
        return manifest, document, snapshot

    def _read_evidence(
        self,
        workspace: SecureWorkspace,
        candidate_run_id: str,
        manifest: M6PrivacySafeStaticReportManifestAuthorityV1,
    ) -> tuple[tuple[str, bytes], ...]:
        snapshots: list[tuple[str, bytes]] = []
        total_bytes = 0
        for item in manifest.evidence_items:
            if (
                item.disposition
                is not M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
            ):
                continue
            assert item.artifact_relative_path is not None
            assert item.artifact_content_sha256 is not None
            relative_path = _final_relative(candidate_run_id, item.artifact_relative_path)
            try:
                snapshot = workspace.read_verified(
                    relative_path,
                    item.artifact_content_sha256,
                    max_bytes=self._max_evidence_bytes,
                )
            except BudgetExceeded as exc:
                raise M6PrivacySafeStaticReportStoreError(
                    M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED
                ) from exc
            except (ArtifactIntegrityViolation, PathBoundaryViolation) as exc:
                if isinstance(exc, PathBoundaryViolation) and exc.reason_code == "FILE_TOO_LARGE":
                    raise M6PrivacySafeStaticReportStoreError(
                        M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED
                    ) from exc
                raise M6PrivacySafeStaticReportStoreError(
                    M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_INVALID
                ) from exc
            total_bytes += snapshot.size_bytes
            if total_bytes > MAX_M6_PRIVACY_SAFE_STATIC_REPORT_TOTAL_EVIDENCE_BYTES:
                _fail(M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED)
            snapshots.append((relative_path, snapshot.bytes))
        return tuple(snapshots)

    @staticmethod
    def _require_exact_inventory(
        workspace: SecureWorkspace,
        candidate_run_id: str,
        seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1,
        manifest: M6PrivacySafeStaticReportManifestAuthorityV1,
    ) -> None:
        expected: dict[str, set[str]] = {
            f"{candidate_run_id}/m6-static-report": {"manifests", "seal.json"},
            f"{candidate_run_id}/m6-static-report/manifests": {
                f"{seal.static_report_manifest_content_sha256}.json"
            },
        }
        available_paths = tuple(
            item.artifact_relative_path
            for item in manifest.evidence_items
            if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
        )
        for relative_path in available_paths:
            assert relative_path is not None
            parts = relative_path.split("/")
            for index, child in enumerate(parts[1:], start=1):
                parent = f"{candidate_run_id}/{'/'.join(parts[:index])}"
                expected.setdefault(parent, set()).add(child)
        if not available_paths:
            expected[f"{candidate_run_id}/privacy-media"] = set()

        for directory, names in expected.items():
            try:
                hints = workspace.list_m6_static_report_directory(
                    directory,
                    len(names) + 1,
                    _MAX_INVENTORY_NAME_BYTES,
                )
            except PathBoundaryViolation as exc:
                if (
                    directory == f"{candidate_run_id}/privacy-media"
                    and not names
                    and exc.reason_code == "DIRECTORY_MISSING"
                ):
                    continue
                _fail(M6PrivacySafeStaticReportStoreErrorCode.INVENTORY_INVALID)
            except (BudgetExceeded, ValueError):
                _fail(M6PrivacySafeStaticReportStoreErrorCode.INVENTORY_INVALID)
            observed = {hint.name for hint in hints if hint.name is not None}
            if len(observed) != len(hints) or observed != names:
                _fail(M6PrivacySafeStaticReportStoreErrorCode.INVENTORY_INVALID)


class M6PrivacySafeStaticReportPublisher:
    """Publish dependencies first and make ``index.html`` the final commit point."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        evidence_provider: M6PrivacyProcessedEvidenceProvider,
        fault_injector: M6PrivacySafeStaticReportStoreFaultInjector | None = None,
        max_manifest_bytes: int = MAX_M6_PRIVACY_SAFE_STATIC_REPORT_MANIFEST_BYTES,
        max_html_bytes: int = MAX_M6_PRIVACY_SAFE_STATIC_REPORT_HTML_BYTES,
        max_evidence_bytes: int = MAX_M6_PRIVACY_SAFE_STATIC_REPORT_EVIDENCE_BYTES,
    ) -> None:
        self._output_root = Path(output_root).absolute()
        self._evidence_provider = _validate_provider(evidence_provider)
        if fault_injector is not None and not callable(fault_injector):
            _fail(M6PrivacySafeStaticReportStoreErrorCode.INVALID_ARGUMENT)
        self._fault_injector = fault_injector
        self._max_manifest_bytes = _validate_positive_budget(
            max_manifest_bytes, "max_manifest_bytes"
        )
        self._max_html_bytes = _validate_positive_budget(max_html_bytes, "max_html_bytes")
        self._max_evidence_bytes = _validate_positive_budget(
            max_evidence_bytes, "max_evidence_bytes"
        )
        try:
            self._output_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            _fail(M6PrivacySafeStaticReportStoreErrorCode.STORAGE_BOUNDARY_FAILURE)

    def publish(
        self,
        regression_publication_bundle: object,
        static_report_bundle: object,
    ) -> M6PrivacySafeStaticReportPublicationResult:
        publication = _controlled_publication(regression_publication_bundle)
        static_bundle = _controlled_static_bundle(publication, static_report_bundle)
        manifest_payload = _canonical_model_document(static_bundle.manifest).encode("utf-8")
        try:
            html_payload = static_bundle.html_document.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise M6PrivacySafeStaticReportStoreError(
                M6PrivacySafeStaticReportStoreErrorCode.BUNDLE_INVALID
            ) from exc
        if len(manifest_payload) > min(
            self._max_manifest_bytes,
            MAX_M6_PRIVACY_SAFE_STATIC_REPORT_MANIFEST_BYTES,
        ) or len(html_payload) > min(
            self._max_html_bytes,
            MAX_M6_PRIVACY_SAFE_STATIC_REPORT_HTML_BYTES,
        ):
            _fail(M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED)
        seal = _build_publication_seal(
            publication,
            static_bundle,
            manifest_payload,
            html_payload,
        )
        seal_document = _canonical_model_document(seal)
        seal_payload = seal_document.encode("utf-8")
        if len(seal_payload) > MAX_M6_PRIVACY_SAFE_STATIC_REPORT_PUBLICATION_SEAL_BYTES:
            _fail(M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED)

        workspace_limit = max(
            self._max_manifest_bytes,
            self._max_html_bytes,
            self._max_evidence_bytes,
            MAX_M6_PRIVACY_SAFE_STATIC_REPORT_PUBLICATION_SEAL_BYTES,
        )
        try:
            with SecureWorkspace(self._output_root, workspace_limit) as workspace:
                workspace.ensure_private_directory(".staging")
                workspace.ensure_private_directory(f".staging/{seal.candidate_run_id}")
                workspace.ensure_private_directory(
                    f".staging/{seal.candidate_run_id}/m6-static-report"
                )
                workspace.ensure_private_directory(seal.candidate_run_id)
                with workspace.m6_static_report_publish_lock(seal.candidate_run_id):
                    existing = self._preflight_locked(
                        workspace,
                        static_bundle,
                        seal,
                        manifest_payload,
                        seal_payload,
                    )
                    if existing is not None:
                        return existing
                evidence = self._load_all_evidence(static_bundle.manifest)
                with workspace.m6_static_report_publish_lock(seal.candidate_run_id):
                    existing = self._preflight_locked(
                        workspace,
                        static_bundle,
                        seal,
                        manifest_payload,
                        seal_payload,
                    )
                    if existing is not None:
                        return existing
                    return self._publish_locked(
                        workspace=workspace,
                        static_bundle=static_bundle,
                        seal=seal,
                        manifest_payload=manifest_payload,
                        html_payload=html_payload,
                        seal_payload=seal_payload,
                        evidence=evidence,
                    )
        except M6PrivacySafeStaticReportStoreError as exc:
            if exc.code is M6PrivacySafeStaticReportStoreErrorCode.COMMIT_OUTCOME_UNKNOWN:
                recovered = self._recover_exact(static_bundle, seal)
                if recovered is not None:
                    return recovered
            raise
        except (
            ArtifactConflict,
            ArtifactIntegrityViolation,
            BudgetExceeded,
            PathBoundaryViolation,
        ):
            recovered = self._recover_exact(static_bundle, seal)
            if recovered is not None:
                return recovered
            raise M6PrivacySafeStaticReportStoreError(
                M6PrivacySafeStaticReportStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from None

    def _publish_locked(
        self,
        *,
        workspace: SecureWorkspace,
        static_bundle: M6PrivacySafeStaticReportBundle,
        seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1,
        manifest_payload: bytes,
        html_payload: bytes,
        seal_payload: bytes,
        evidence: tuple[tuple[M6StaticReportEvidenceItem, M6StoredPrivacyProcessedEvidence], ...],
    ) -> M6PrivacySafeStaticReportPublicationResult:
        stage_root = f".staging/{seal.candidate_run_id}/m6-static-report/pending"
        commit_attempted = False
        phase = "staging"
        try:
            self._ensure_directories(workspace, seal, static_bundle.manifest, stage_root)
            self._create_or_verify(
                workspace,
                f"{stage_root}/{seal.html_relative_path}",
                html_payload,
            )
            self._create_or_verify(
                workspace,
                f"{stage_root}/{seal.manifest_relative_path}",
                manifest_payload,
            )
            self._create_or_verify(
                workspace,
                f"{stage_root}/{seal.seal_relative_path}",
                seal_payload,
            )
            for item, stored in evidence:
                assert item.artifact_relative_path is not None
                self._create_or_verify(
                    workspace,
                    f"{stage_root}/{item.artifact_relative_path}",
                    stored.content_bytes,
                )
            self._fault("after_staging")

            phase = "evidence"
            for item, stored in evidence:
                assert item.artifact_relative_path is not None
                workspace.publish_staged(
                    f"{stage_root}/{item.artifact_relative_path}",
                    _final_relative(
                        seal.candidate_run_id,
                        item.artifact_relative_path,
                    ),
                    stored.content_sha256,
                    remove_source_if_existing_equal=True,
                )
                self._fault(f"after_evidence:{item.sample_id}")

            phase = "manifest"
            workspace.publish_staged(
                f"{stage_root}/{seal.manifest_relative_path}",
                _final_relative(seal.candidate_run_id, seal.manifest_relative_path),
                seal.static_report_manifest_content_sha256,
                remove_source_if_existing_equal=True,
            )
            self._fault("after_manifest")

            phase = "seal"
            workspace.publish_staged(
                f"{stage_root}/{seal.seal_relative_path}",
                _final_relative(seal.candidate_run_id, seal.seal_relative_path),
                _sha256(seal_payload),
                remove_source_if_existing_equal=True,
            )
            self._fault("after_seal")

            phase = "commit"
            self._fault("before_commit")
            commit_attempted = True
            workspace.publish_staged(
                f"{stage_root}/{seal.html_relative_path}",
                _final_relative(seal.candidate_run_id, seal.html_relative_path),
                seal.html_content_sha256,
                remove_source_if_existing_equal=True,
            )
            self._fault("after_commit")
        except Exception as exc:
            recovered = self._recover_exact(static_bundle, seal)
            if recovered is not None:
                return recovered
            if isinstance(exc, M6PrivacySafeStaticReportStoreError):
                raise
            if isinstance(exc, BudgetExceeded):
                code = M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED
            elif isinstance(exc, ArtifactConflict) and commit_attempted:
                code = M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT
            elif commit_attempted:
                code = M6PrivacySafeStaticReportStoreErrorCode.COMMIT_OUTCOME_UNKNOWN
            elif phase == "staging":
                code = M6PrivacySafeStaticReportStoreErrorCode.STAGING_CONFLICT
            elif phase == "evidence":
                code = M6PrivacySafeStaticReportStoreErrorCode.EVIDENCE_PUBLICATION_FAILED
            elif phase == "manifest":
                code = M6PrivacySafeStaticReportStoreErrorCode.MANIFEST_PUBLICATION_FAILED
            elif phase == "seal":
                code = M6PrivacySafeStaticReportStoreErrorCode.SEAL_PUBLICATION_FAILED
            elif isinstance(exc, (ArtifactIntegrityViolation, PathBoundaryViolation)):
                code = M6PrivacySafeStaticReportStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            else:
                code = M6PrivacySafeStaticReportStoreErrorCode.COMMIT_OUTCOME_UNKNOWN
            raise M6PrivacySafeStaticReportStoreError(code) from None

        recovered = self._recover_exact(static_bundle, seal)
        if recovered is None:
            _fail(M6PrivacySafeStaticReportStoreErrorCode.COMMIT_OUTCOME_UNKNOWN)
        return recovered

    def _preflight_locked(
        self,
        workspace: SecureWorkspace,
        static_bundle: M6PrivacySafeStaticReportBundle,
        seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1,
        manifest_payload: bytes,
        seal_payload: bytes,
    ) -> M6PrivacySafeStaticReportPublicationResult | None:
        existing = self._load_existing(seal.candidate_run_id)
        if existing is not None:
            if existing.static_report_bundle == static_bundle and existing.seal == seal:
                return self._result(seal, static_bundle.manifest)
            _fail(M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT)
        self._require_compatible_partial_publication(
            workspace,
            seal,
            static_bundle.manifest,
            manifest_payload,
            seal_payload,
        )
        return None

    def _load_existing(
        self,
        candidate_run_id: str,
    ) -> M6StoredPrivacySafeStaticReportBundle | None:
        try:
            return ReadonlyM6PrivacySafeStaticReportStore(
                self._output_root,
                max_manifest_bytes=self._max_manifest_bytes,
                max_html_bytes=self._max_html_bytes,
                max_evidence_bytes=self._max_evidence_bytes,
            ).load(candidate_run_id)
        except M6PrivacySafeStaticReportStoreError as exc:
            if exc.code is M6PrivacySafeStaticReportStoreErrorCode.COMMIT_MISSING:
                return None
            raise

    def _require_compatible_partial_publication(
        self,
        workspace: SecureWorkspace,
        seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1,
        manifest: M6PrivacySafeStaticReportManifestAuthorityV1,
        manifest_payload: bytes,
        seal_payload: bytes,
    ) -> None:
        expected: dict[str, set[str]] = {
            f"{seal.candidate_run_id}/m6-static-report": {"manifests", "seal.json"},
            f"{seal.candidate_run_id}/m6-static-report/manifests": {
                f"{seal.static_report_manifest_content_sha256}.json"
            },
        }
        available = tuple(
            item
            for item in manifest.evidence_items
            if item.disposition is M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
        )
        for item in available:
            assert item.artifact_relative_path is not None
            parts = item.artifact_relative_path.split("/")
            for index, child in enumerate(parts[1:], start=1):
                parent = f"{seal.candidate_run_id}/{'/'.join(parts[:index])}"
                expected.setdefault(parent, set()).add(child)
        if not available:
            expected[f"{seal.candidate_run_id}/privacy-media"] = set()

        for directory, allowed_names in expected.items():
            try:
                hints = workspace.list_m6_static_report_directory(
                    directory,
                    len(allowed_names) + 1,
                    _MAX_INVENTORY_NAME_BYTES,
                )
            except PathBoundaryViolation as exc:
                if exc.reason_code == "DIRECTORY_MISSING":
                    continue
                _fail(M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT)
            except (BudgetExceeded, ValueError):
                _fail(M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT)
            observed = {hint.name for hint in hints if hint.name is not None}
            if len(observed) != len(hints) or not observed.issubset(allowed_names):
                _fail(M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT)

        expected_files: list[tuple[str, str, int]] = [
            (
                _final_relative(seal.candidate_run_id, seal.manifest_relative_path),
                seal.static_report_manifest_content_sha256,
                len(manifest_payload),
            ),
            (
                _final_relative(seal.candidate_run_id, seal.seal_relative_path),
                _sha256(seal_payload),
                len(seal_payload),
            ),
            (
                (
                    f".staging/{seal.candidate_run_id}/m6-static-report/"
                    f"pending/{seal.html_relative_path}"
                ),
                seal.html_content_sha256,
                seal.html_size_bytes,
            ),
            (
                (
                    f".staging/{seal.candidate_run_id}/m6-static-report/"
                    f"pending/{seal.seal_relative_path}"
                ),
                _sha256(seal_payload),
                len(seal_payload),
            ),
        ]
        for item in available:
            assert item.artifact_relative_path is not None
            assert item.artifact_content_sha256 is not None
            expected_files.append(
                (
                    _final_relative(
                        seal.candidate_run_id,
                        item.artifact_relative_path,
                    ),
                    item.artifact_content_sha256,
                    self._max_evidence_bytes,
                )
            )
        for relative_path, expected_sha256, max_bytes in expected_files:
            try:
                workspace.read_verified(
                    relative_path,
                    expected_sha256,
                    max_bytes=max_bytes,
                )
            except PathBoundaryViolation as exc:
                if exc.reason_code == "FILE_MISSING":
                    continue
                _fail(M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT)
            except (ArtifactIntegrityViolation, BudgetExceeded, ValueError):
                _fail(M6PrivacySafeStaticReportStoreErrorCode.COMMIT_CONFLICT)

    def _load_all_evidence(
        self,
        manifest: M6PrivacySafeStaticReportManifestAuthorityV1,
    ) -> tuple[tuple[M6StaticReportEvidenceItem, M6StoredPrivacyProcessedEvidence], ...]:
        loaded: list[tuple[M6StaticReportEvidenceItem, M6StoredPrivacyProcessedEvidence]] = []
        total_bytes = 0
        for item in manifest.evidence_items:
            if (
                item.disposition
                is not M6StaticReportEvidenceDisposition.PRIVACY_PROCESSED_AVAILABLE
            ):
                continue
            stored = _load_evidence(self._evidence_provider, item)
            if len(stored.content_bytes) > self._max_evidence_bytes:
                _fail(M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED)
            total_bytes += len(stored.content_bytes)
            if total_bytes > MAX_M6_PRIVACY_SAFE_STATIC_REPORT_TOTAL_EVIDENCE_BYTES:
                _fail(M6PrivacySafeStaticReportStoreErrorCode.BUDGET_EXCEEDED)
            loaded.append((item, stored))
        return tuple(loaded)

    @staticmethod
    def _ensure_directories(
        workspace: SecureWorkspace,
        seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1,
        manifest: M6PrivacySafeStaticReportManifestAuthorityV1,
        stage_root: str,
    ) -> None:
        root = _root_relative(seal.candidate_run_id)
        file_paths = {
            seal.html_relative_path,
            seal.manifest_relative_path,
            seal.seal_relative_path,
            *(
                item.artifact_relative_path
                for item in manifest.evidence_items
                if item.artifact_relative_path is not None
            ),
        }
        directories = {
            ".staging",
            f".staging/{seal.candidate_run_id}",
            f".staging/{seal.candidate_run_id}/m6-static-report",
            stage_root,
            root,
        }
        for relative_path in file_paths:
            parent_parts = relative_path.split("/")[:-1]
            for index in range(1, len(parent_parts) + 1):
                parent = "/".join(parent_parts[:index])
                directories.add(f"{root}/{parent}")
                directories.add(f"{stage_root}/{parent}")
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
                _fail(M6PrivacySafeStaticReportStoreErrorCode.STAGING_CONFLICT)
        if observed.bytes != payload:
            _fail(M6PrivacySafeStaticReportStoreErrorCode.STAGING_CONFLICT)

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)

    def _recover_exact(
        self,
        static_bundle: M6PrivacySafeStaticReportBundle,
        seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1,
    ) -> M6PrivacySafeStaticReportPublicationResult | None:
        try:
            stored = ReadonlyM6PrivacySafeStaticReportStore(
                self._output_root,
                max_manifest_bytes=self._max_manifest_bytes,
                max_html_bytes=self._max_html_bytes,
                max_evidence_bytes=self._max_evidence_bytes,
            ).load(seal.candidate_run_id)
        except M6PrivacySafeStaticReportStoreError:
            return None
        if stored.static_report_bundle != static_bundle or stored.seal != seal:
            return None
        return self._result(seal, static_bundle.manifest)

    def _result(
        self,
        seal: M6PrivacySafeStaticReportPublicationSealAuthorityV1,
        manifest: M6PrivacySafeStaticReportManifestAuthorityV1,
    ) -> M6PrivacySafeStaticReportPublicationResult:
        evidence_paths = tuple(
            self._output_root
            / Path(
                _final_relative(
                    seal.candidate_run_id,
                    item.artifact_relative_path,
                )
            )
            for item in manifest.evidence_items
            if item.artifact_relative_path is not None
        )
        return M6PrivacySafeStaticReportPublicationResult(
            seal_id=seal.seal_id,
            index_path=self._output_root
            / Path(_final_relative(seal.candidate_run_id, seal.html_relative_path)),
            manifest_path=self._output_root
            / Path(_final_relative(seal.candidate_run_id, seal.manifest_relative_path)),
            seal_path=self._output_root
            / Path(_final_relative(seal.candidate_run_id, seal.seal_relative_path)),
            evidence_paths=evidence_paths,
        )


__all__ = [
    "MAX_M6_PRIVACY_SAFE_STATIC_REPORT_EVIDENCE_BYTES",
    "MAX_M6_PRIVACY_SAFE_STATIC_REPORT_PUBLICATION_SEAL_BYTES",
    "MAX_M6_PRIVACY_SAFE_STATIC_REPORT_TOTAL_EVIDENCE_BYTES",
    "M6PrivacyProcessedEvidenceProvider",
    "M6PrivacySafeStaticReportPublicationResult",
    "M6PrivacySafeStaticReportPublisher",
    "M6PrivacySafeStaticReportStoreError",
    "M6PrivacySafeStaticReportStoreErrorCode",
    "M6PrivacySafeStaticReportStoreFaultInjector",
    "M6StoredPrivacyProcessedEvidence",
    "M6StoredPrivacySafeStaticReportBundle",
    "ReadonlyM6PrivacySafeStaticReportStore",
]
