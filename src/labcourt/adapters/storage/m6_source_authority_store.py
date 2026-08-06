"""Secure immutable publication and readback of M6 source authority bundles."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_source_authority import (
    M6SourceAuthorityError,
    assemble_m6_validated_source_authority,
)
from labcourt.application.m6_source_authority_builder import M6SealedSourceBundle
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_source_authority import M6ReplayInputAuthority
from labcourt.contracts.m6_source_authority_store import (
    MAX_M6_SOURCE_AUTHORITY_BUNDLE_BYTES,
    MAX_M6_SOURCE_AUTHORITY_DOCUMENT_BYTES,
    M6SourceAuthorityDocumentEntry,
    M6SourceAuthorityDocumentKind,
    M6SourceAuthoritySeal,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    LabCourtError,
    PathBoundaryViolation,
)
from labcourt.ports.m6_source_authority import M6SourceAuthoritySnapshot

from .secure_workspace import SecureWorkspace

MAX_M6_SOURCE_AUTHORITY_SEAL_BYTES = 1024 * 1024
_MAX_SEAL_DIRECTORY_ITEMS = 2
_MAX_NAME_BYTES = 512
M6SourceAuthorityStoreFaultInjector = Callable[[str], None]
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6SourceAuthorityStoreErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    BUNDLE_INVALID = "BUNDLE_INVALID"
    STAGING_CONFLICT = "STAGING_CONFLICT"
    DEPENDENCY_PUBLICATION_FAILED = "DEPENDENCY_PUBLICATION_FAILED"
    COMMIT_CONFLICT = "COMMIT_CONFLICT"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    SEAL_MISSING = "SEAL_MISSING"
    SEAL_INVALID = "SEAL_INVALID"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INVENTORY_INVALID = "INVENTORY_INVALID"
    STORAGE_BOUNDARY_FAILURE = "STORAGE_BOUNDARY_FAILURE"


class M6SourceAuthorityStoreError(LabCourtError):
    """An M6 source authority bundle could not be published or read exactly."""

    def __init__(self, code: M6SourceAuthorityStoreErrorCode) -> None:
        if not isinstance(code, M6SourceAuthorityStoreErrorCode):
            raise TypeError("code must be an M6SourceAuthorityStoreErrorCode")
        self.code = code
        super().__init__(f"M6 source authority store failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6SourceAuthorityPublicationResult:
    seal_id: str
    seal_path: Path
    document_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class M6StoredSourceAuthorityBundle:
    replay_input_closure: M6ReplayInputClosureAuthority
    replay_input_authority: M6ReplayInputAuthority
    source_validation_report: M5ArtifactValidationReport
    source_case: Case
    source_manifest: RunManifest
    seal: M6SourceAuthoritySeal
    replay_input_closure_document: str
    replay_input_authority_document: str
    source_validation_report_document: str
    source_case_document: str
    source_manifest_document: str

    def to_source_snapshot(self, source_identity_sha256: str) -> M6SourceAuthoritySnapshot:
        return M6SourceAuthoritySnapshot(
            source_identity_sha256=source_identity_sha256,
            input_authority_canonical_document=self.replay_input_authority_document,
            source_validation_report_canonical_document=self.source_validation_report_document,
            source_case_canonical_document=self.source_case_document,
            source_case_document_sha256=self.seal.source_case_document_sha256,
            source_manifest_canonical_document=self.source_manifest_document,
            source_manifest_document_sha256=self.seal.source_manifest_document_sha256,
            source_m4_authority_root_sha256=self.seal.source_m4_authority_root_sha256,
            source_m5_authority_root_sha256=self.seal.source_m5_authority_root_sha256,
            audit_head_sequence=self.seal.audit_head_sequence,
            audit_head_hash=self.seal.audit_head_hash,
        )


def _fail(code: M6SourceAuthorityStoreErrorCode) -> NoReturn:
    raise M6SourceAuthorityStoreError(code)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_model_document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _parse_canonical(
    payload: bytes,
    model_type: type[_ModelT],
    code: M6SourceAuthorityStoreErrorCode,
) -> tuple[_ModelT, str]:
    try:
        document = payload.decode("utf-8")
        value = model_type.model_validate_json(payload)
        if _canonical_model_document(value) != document:
            _fail(code)
        return value, document
    except M6SourceAuthorityStoreError:
        raise
    except (UnicodeDecodeError, TypeError, ValueError, ValidationError):
        _fail(code)


def _canonical_config(value: object) -> AppConfig:
    if not isinstance(value, AppConfig):
        _fail(M6SourceAuthorityStoreErrorCode.INVALID_ARGUMENT)
    try:
        controlled = AppConfig.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SourceAuthorityStoreErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6SourceAuthorityStoreErrorCode.INVALID_ARGUMENT)
    return controlled


def _entry_by_kind(
    seal: M6SourceAuthoritySeal,
) -> dict[M6SourceAuthorityDocumentKind, M6SourceAuthorityDocumentEntry]:
    return {item.kind: item for item in seal.entries}


def _root_relative(run_id: str) -> str:
    return f"{run_id}/m6-source-authorities"


def _document_final_relative(
    run_id: str,
    entry: M6SourceAuthorityDocumentEntry,
) -> str:
    return f"{_root_relative(run_id)}/{entry.relative_path}"


def _seal_final_relative(seal: M6SourceAuthoritySeal) -> str:
    return f"{_root_relative(seal.source_run_id)}/{seal.seal_relative_path}"


def _validate_bundle(
    bundle: object,
    config: object,
) -> tuple[M6SealedSourceBundle, AppConfig]:
    if not isinstance(bundle, M6SealedSourceBundle):
        _fail(M6SourceAuthorityStoreErrorCode.INVALID_ARGUMENT)
    controlled_config = _canonical_config(config)
    models_and_documents: tuple[tuple[BaseModel, str], ...] = (
        (bundle.replay_input_closure, bundle.replay_input_closure_document),
        (bundle.replay_input_authority, bundle.replay_input_authority_document),
        (bundle.source_validation_report, bundle.source_validation_report_document),
        (bundle.source_case, bundle.source_case_document),
        (bundle.source_manifest, bundle.source_manifest_document),
    )
    if any(
        _canonical_model_document(model) != document for model, document in models_and_documents
    ):
        _fail(M6SourceAuthorityStoreErrorCode.BUNDLE_INVALID)
    try:
        seal = M6SourceAuthoritySeal.model_validate(bundle.seal.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SourceAuthorityStoreErrorCode.BUNDLE_INVALID)
    if seal != bundle.seal:
        _fail(M6SourceAuthorityStoreErrorCode.BUNDLE_INVALID)
    documents = {
        M6SourceAuthorityDocumentKind.REPLAY_INPUT_CLOSURE: (bundle.replay_input_closure_document),
        M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY: (
            bundle.replay_input_authority_document
        ),
        M6SourceAuthorityDocumentKind.SOURCE_VALIDATION_REPORT: (
            bundle.source_validation_report_document
        ),
        M6SourceAuthorityDocumentKind.SOURCE_CASE: bundle.source_case_document,
        M6SourceAuthorityDocumentKind.SOURCE_MANIFEST: bundle.source_manifest_document,
    }
    for entry in seal.entries:
        payload = documents[entry.kind].encode("utf-8")
        if entry.content_sha256 != _sha256(payload) or entry.size_bytes != len(payload):
            _fail(M6SourceAuthorityStoreErrorCode.BUNDLE_INVALID)
    snapshot = M6SourceAuthoritySnapshot(
        source_identity_sha256=sha256_hex(
            ["m6-source-authority-publication-validation", 1, seal.seal_id]
        ),
        input_authority_canonical_document=bundle.replay_input_authority_document,
        source_validation_report_canonical_document=(bundle.source_validation_report_document),
        source_case_canonical_document=bundle.source_case_document,
        source_case_document_sha256=seal.source_case_document_sha256,
        source_manifest_canonical_document=bundle.source_manifest_document,
        source_manifest_document_sha256=seal.source_manifest_document_sha256,
        source_m4_authority_root_sha256=seal.source_m4_authority_root_sha256,
        source_m5_authority_root_sha256=seal.source_m5_authority_root_sha256,
        audit_head_sequence=seal.audit_head_sequence,
        audit_head_hash=seal.audit_head_hash,
    )
    try:
        assemble_m6_validated_source_authority(
            closure=bundle.replay_input_closure,
            snapshot=snapshot,
            config=controlled_config,
        )
    except M6SourceAuthorityError as exc:
        raise M6SourceAuthorityStoreError(M6SourceAuthorityStoreErrorCode.BUNDLE_INVALID) from exc
    return bundle, controlled_config


class ReadonlyM6SourceAuthorityStore:
    """Resolve a bundle only from a typed replay closure and fixed safe paths."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        max_document_bytes: int = MAX_M6_SOURCE_AUTHORITY_DOCUMENT_BYTES,
        max_bundle_bytes: int = MAX_M6_SOURCE_AUTHORITY_BUNDLE_BYTES,
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

    def load(self, closure: object) -> M6StoredSourceAuthorityBundle:
        if not isinstance(closure, M6ReplayInputClosureAuthority):
            _fail(M6SourceAuthorityStoreErrorCode.INVALID_ARGUMENT)
        try:
            controlled_closure = M6ReplayInputClosureAuthority.model_validate(
                closure.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            _fail(M6SourceAuthorityStoreErrorCode.INVALID_ARGUMENT)
        if controlled_closure != closure:
            _fail(M6SourceAuthorityStoreErrorCode.INVALID_ARGUMENT)
        seal_directory = (
            f"{_root_relative(closure.source_run_id)}/seals/"
            f"{closure.replay_input_closure_authority_id}"
        )
        seal_relative = f"{seal_directory}/seal.json"
        workspace_limit = max(self._max_document_bytes, MAX_M6_SOURCE_AUTHORITY_SEAL_BYTES)
        try:
            with SecureWorkspace(self._output_root, workspace_limit) as workspace:
                self._require_exact_seal_inventory(workspace, seal_directory)
                first = workspace.read_verified(
                    seal_relative,
                    max_bytes=MAX_M6_SOURCE_AUTHORITY_SEAL_BYTES,
                )
                seal, _ = _parse_canonical(
                    first.bytes,
                    M6SourceAuthoritySeal,
                    M6SourceAuthorityStoreErrorCode.SEAL_INVALID,
                )
                if (
                    seal.source_run_id != closure.source_run_id
                    or seal.replay_input_closure_authority_id
                    != closure.replay_input_closure_authority_id
                    or seal.replay_input_closure_document_sha256
                    != closure.replay_input_closure_document_sha256
                    or seal.seal_relative_path
                    != f"seals/{closure.replay_input_closure_authority_id}/seal.json"
                ):
                    _fail(M6SourceAuthorityStoreErrorCode.SEAL_INVALID)
                if sum(item.size_bytes for item in seal.entries) > self._max_bundle_bytes:
                    _fail(M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID)
                documents: dict[M6SourceAuthorityDocumentKind, str] = {}
                for entry in seal.entries:
                    if entry.size_bytes > self._max_document_bytes:
                        _fail(M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID)
                    observed = workspace.read_verified(
                        _document_final_relative(seal.source_run_id, entry),
                        entry.content_sha256,
                        max_bytes=entry.size_bytes,
                    )
                    if observed.size_bytes != entry.size_bytes:
                        _fail(M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID)
                    try:
                        documents[entry.kind] = observed.bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        _fail(M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID)
                second = workspace.read_verified(
                    seal_relative,
                    first.sha256,
                    max_bytes=first.size_bytes,
                )
                if second.bytes != first.bytes:
                    _fail(M6SourceAuthorityStoreErrorCode.SEAL_INVALID)
                self._require_exact_seal_inventory(workspace, seal_directory)
        except M6SourceAuthorityStoreError:
            raise
        except PathBoundaryViolation as exc:
            code = (
                M6SourceAuthorityStoreErrorCode.SEAL_MISSING
                if exc.reason_code in {"FILE_MISSING", "DIRECTORY_MISSING"}
                else M6SourceAuthorityStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            )
            raise M6SourceAuthorityStoreError(code) from exc
        except (ArtifactIntegrityViolation, BudgetExceeded) as exc:
            raise M6SourceAuthorityStoreError(
                M6SourceAuthorityStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from exc

        entries = _entry_by_kind(seal)
        parsed_closure, closure_document = _parse_canonical(
            documents[M6SourceAuthorityDocumentKind.REPLAY_INPUT_CLOSURE].encode("utf-8"),
            M6ReplayInputClosureAuthority,
            M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID,
        )
        input_authority, authority_document = _parse_canonical(
            documents[M6SourceAuthorityDocumentKind.REPLAY_INPUT_AUTHORITY].encode("utf-8"),
            M6ReplayInputAuthority,
            M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID,
        )
        report, report_document = _parse_canonical(
            documents[M6SourceAuthorityDocumentKind.SOURCE_VALIDATION_REPORT].encode("utf-8"),
            M5ArtifactValidationReport,
            M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID,
        )
        source_case, case_document = _parse_canonical(
            documents[M6SourceAuthorityDocumentKind.SOURCE_CASE].encode("utf-8"),
            Case,
            M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID,
        )
        source_manifest, manifest_document = _parse_canonical(
            documents[M6SourceAuthorityDocumentKind.SOURCE_MANIFEST].encode("utf-8"),
            RunManifest,
            M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID,
        )
        if parsed_closure != closure:
            _fail(M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID)
        physical_declared_kinds = {
            M6SourceAuthorityDocumentKind.SOURCE_VALIDATION_REPORT,
            M6SourceAuthorityDocumentKind.SOURCE_CASE,
            M6SourceAuthorityDocumentKind.SOURCE_MANIFEST,
        }
        if any(
            entries[kind].content_sha256 != entries[kind].declared_document_sha256
            for kind in physical_declared_kinds
        ):
            _fail(M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID)
        if (
            input_authority.input_authority_id != seal.replay_input_authority_id
            or input_authority.input_authority_document_sha256
            != seal.replay_input_authority_document_sha256
            or report.report_id != seal.source_validation_report_id
            or source_case.case_id != seal.source_case_id
            or source_manifest.manifest_id != seal.source_manifest_id
            or input_authority.source_case_document_sha256 != seal.source_case_document_sha256
            or input_authority.source_manifest_document_sha256
            != seal.source_manifest_document_sha256
            or input_authority.source_validation_report_document_sha256
            != seal.source_validation_report_document_sha256
        ):
            _fail(M6SourceAuthorityStoreErrorCode.DOCUMENT_INVALID)
        return M6StoredSourceAuthorityBundle(
            replay_input_closure=parsed_closure,
            replay_input_authority=input_authority,
            source_validation_report=report,
            source_case=source_case,
            source_manifest=source_manifest,
            seal=seal,
            replay_input_closure_document=closure_document,
            replay_input_authority_document=authority_document,
            source_validation_report_document=report_document,
            source_case_document=case_document,
            source_manifest_document=manifest_document,
        )

    @staticmethod
    def _require_exact_seal_inventory(
        workspace: SecureWorkspace,
        seal_directory: str,
    ) -> None:
        hints = workspace.list_m6_source_authority_seal_directory(
            seal_directory,
            _MAX_SEAL_DIRECTORY_ITEMS,
            _MAX_NAME_BYTES,
        )
        if not hints:
            _fail(M6SourceAuthorityStoreErrorCode.SEAL_MISSING)
        if len(hints) != 1 or hints[0].name != "seal.json":
            _fail(M6SourceAuthorityStoreErrorCode.INVENTORY_INVALID)


class M6SourceAuthorityPublisher:
    """Publish dependencies first and the immutable seal as the sole commit point."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        fault_injector: M6SourceAuthorityStoreFaultInjector | None = None,
        max_document_bytes: int = MAX_M6_SOURCE_AUTHORITY_DOCUMENT_BYTES,
        max_bundle_bytes: int = MAX_M6_SOURCE_AUTHORITY_BUNDLE_BYTES,
    ) -> None:
        self._output_root = Path(output_root).absolute()
        self._fault_injector = fault_injector
        self._max_document_bytes = max_document_bytes
        self._max_bundle_bytes = max_bundle_bytes
        try:
            self._output_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise M6SourceAuthorityStoreError(
                M6SourceAuthorityStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from None

    def publish(
        self,
        bundle: object,
        *,
        config: object,
    ) -> M6SourceAuthorityPublicationResult:
        controlled, _ = _validate_bundle(bundle, config)
        if (
            any(item.size_bytes > self._max_document_bytes for item in controlled.seal.entries)
            or sum(item.size_bytes for item in controlled.seal.entries) > self._max_bundle_bytes
        ):
            _fail(M6SourceAuthorityStoreErrorCode.BUNDLE_INVALID)
        seal_payload = controlled.seal_document.encode("utf-8")
        if len(seal_payload) > MAX_M6_SOURCE_AUTHORITY_SEAL_BYTES:
            _fail(M6SourceAuthorityStoreErrorCode.BUNDLE_INVALID)
        documents = {
            item.kind: controlled.document_for(item.kind).encode("utf-8")
            for item in controlled.seal.entries
        }
        stage_root = (
            f".staging/{controlled.seal.source_run_id}/m6-source-authorities/"
            f"{controlled.seal.seal_id}"
        )
        commit_attempted = False
        try:
            with SecureWorkspace(
                self._output_root,
                max(self._max_document_bytes, MAX_M6_SOURCE_AUTHORITY_SEAL_BYTES),
            ) as workspace:
                self._ensure_directories(workspace, controlled.seal, stage_root)
                for entry in controlled.seal.entries:
                    staged = f"{stage_root}/{entry.relative_path}"
                    self._create_or_verify(workspace, staged, documents[entry.kind])
                staged_seal = f"{stage_root}/{controlled.seal.seal_relative_path}"
                self._create_or_verify(workspace, staged_seal, seal_payload)
                self._fault("after_staging")
                for entry in controlled.seal.entries:
                    workspace.publish_staged(
                        f"{stage_root}/{entry.relative_path}",
                        _document_final_relative(controlled.seal.source_run_id, entry),
                        entry.content_sha256,
                    )
                    self._fault(f"after_dependency:{entry.kind.value}")
                self._fault("before_commit")
                commit_attempted = True
                workspace.publish_staged(
                    staged_seal,
                    _seal_final_relative(controlled.seal),
                    _sha256(seal_payload),
                )
                self._fault("after_commit")
        except Exception as exc:
            recovered = self._recover_exact(controlled)
            if recovered is not None:
                return recovered
            if isinstance(exc, M6SourceAuthorityStoreError):
                raise
            if isinstance(exc, ArtifactConflict):
                code = (
                    M6SourceAuthorityStoreErrorCode.COMMIT_CONFLICT
                    if commit_attempted
                    else M6SourceAuthorityStoreErrorCode.STAGING_CONFLICT
                )
            elif commit_attempted:
                code = M6SourceAuthorityStoreErrorCode.COMMIT_OUTCOME_UNKNOWN
            elif isinstance(
                exc,
                (ArtifactIntegrityViolation, BudgetExceeded, PathBoundaryViolation),
            ):
                code = M6SourceAuthorityStoreErrorCode.STORAGE_BOUNDARY_FAILURE
            else:
                code = M6SourceAuthorityStoreErrorCode.DEPENDENCY_PUBLICATION_FAILED
            raise M6SourceAuthorityStoreError(code) from exc
        recovered = self._recover_exact(controlled)
        if recovered is None:
            _fail(M6SourceAuthorityStoreErrorCode.COMMIT_OUTCOME_UNKNOWN)
        return recovered

    def _recover_exact(
        self,
        bundle: M6SealedSourceBundle,
    ) -> M6SourceAuthorityPublicationResult | None:
        try:
            stored = ReadonlyM6SourceAuthorityStore(
                self._output_root,
                max_document_bytes=self._max_document_bytes,
                max_bundle_bytes=self._max_bundle_bytes,
            ).load(bundle.replay_input_closure)
        except M6SourceAuthorityStoreError:
            return None
        if (
            stored.seal != bundle.seal
            or stored.replay_input_closure_document != bundle.replay_input_closure_document
            or stored.replay_input_authority_document != bundle.replay_input_authority_document
            or stored.source_validation_report_document != bundle.source_validation_report_document
            or stored.source_case_document != bundle.source_case_document
            or stored.source_manifest_document != bundle.source_manifest_document
        ):
            return None
        return self._result(bundle.seal)

    @staticmethod
    def _ensure_directories(
        workspace: SecureWorkspace,
        seal: M6SourceAuthoritySeal,
        stage_root: str,
    ) -> None:
        root = _root_relative(seal.source_run_id)
        directories = {
            ".staging",
            f".staging/{seal.source_run_id}",
            f".staging/{seal.source_run_id}/m6-source-authorities",
            stage_root,
            seal.source_run_id,
            root,
            f"{root}/documents",
            f"{root}/seals",
            f"{root}/seals/{seal.replay_input_closure_authority_id}",
            f"{stage_root}/documents",
            f"{stage_root}/seals",
            f"{stage_root}/seals/{seal.replay_input_closure_authority_id}",
            *(f"{root}/{entry.relative_path.rsplit('/', maxsplit=1)[0]}" for entry in seal.entries),
            *(
                f"{stage_root}/{entry.relative_path.rsplit('/', maxsplit=1)[0]}"
                for entry in seal.entries
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
            observed = workspace.read_verified(
                relative_path,
                expected,
                max_bytes=len(payload),
            )
        if observed.bytes != payload:
            _fail(M6SourceAuthorityStoreErrorCode.STAGING_CONFLICT)

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)

    def _result(self, seal: M6SourceAuthoritySeal) -> M6SourceAuthorityPublicationResult:
        return M6SourceAuthorityPublicationResult(
            seal_id=seal.seal_id,
            seal_path=self._output_root / Path(_seal_final_relative(seal)),
            document_paths=tuple(
                self._output_root / Path(_document_final_relative(seal.source_run_id, item))
                for item in seal.entries
            ),
        )


__all__ = [
    "MAX_M6_SOURCE_AUTHORITY_SEAL_BYTES",
    "M6SourceAuthorityPublicationResult",
    "M6SourceAuthorityPublisher",
    "M6SourceAuthorityStoreError",
    "M6SourceAuthorityStoreErrorCode",
    "M6StoredSourceAuthorityBundle",
    "ReadonlyM6SourceAuthorityStore",
]
